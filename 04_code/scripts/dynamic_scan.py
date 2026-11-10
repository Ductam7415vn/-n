# -*- coding: utf-8 -*-
"""
Quét động có kiểm soát cho apiscan: dùng bản đồ endpoint tĩnh dẫn đường cho OWASP ZAP, rồi gộp kết quả ZAP
(và tuỳ chọn MobSF) với báo cáo tĩnh thành một báo cáo hợp nhất.

CHỈ dùng trên máy chủ mình có quyền kiểm thử (InsecureBankv2 chạy cục bộ, hoặc app có văn bản cho phép).
Cổng an toàn:
  * Mục tiêu phải phân giải về địa chỉ loopback/mạng riêng; ngược lại phải truyền --authorization <tệp văn bản
    cho phép>, SHA-256 của tệp được ghi vào báo cáo.
  * Chỉ endpoint cùng host với mục tiêu mới được gửi tới ZAP; URL tới host khác trong bản đồ endpoint bị bỏ qua.
  * Quét chủ động (ascan) chỉ giới hạn trong URL của mục tiêu.

ZAP chạy cục bộ, ví dụ:
    docker run -d --name zap -p 127.0.0.1:8090:8090 zaproxy/zap-stable \\
        zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.key=<khoá> \\
        -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
"""
from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import os
import re
import socket
import time
import urllib.parse
import urllib.request

RISK_TO_SEVERITY = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
SEV_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}

API_TOP10 = {
    "API1": "Broken Object Level Authorization",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization",
    "API7": "Server Side Request Forgery",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
}
# Ánh xạ CWE của cảnh báo ZAP → OWASP API Security Top 10 – 2023. Bản 2023 không còn mục Injection riêng;
# đồ án quy ước xếp lỗi chèn mã (SQLi, XSS, command injection) vào API8.
CWE_TO_API = {
    639: "API1", 284: "API1",
    287: "API2", 306: "API2", 307: "API2", 384: "API2", 521: "API2", 522: "API2", 613: "API2", 798: "API2",
    213: "API3", 915: "API3",
    400: "API4", 770: "API4", 799: "API4",
    285: "API5", 862: "API5", 863: "API5",
    918: "API7",
    16: "API8", 22: "API8", 78: "API8", 79: "API8", 89: "API8", 94: "API8", 200: "API8", 209: "API8",
    264: "API8", 319: "API8", 352: "API8", 497: "API8", 525: "API8", 548: "API8", 565: "API8", 614: "API8",
    693: "API8", 942: "API8", 943: "API8", 1004: "API8", 1021: "API8", 1275: "API8",
    1059: "API9",
}


class DynamicError(Exception):
    pass


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_private_host(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise DynamicError(f"không phân giải được host {host}") from exc
    addrs = {ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos}
    return bool(addrs) and all(a.is_loopback or a.is_private for a in addrs)


def check_target(target: str, authorization: str | None) -> dict:
    """Áp cổng an toàn; trả thông tin ủy quyền để ghi vào báo cáo."""
    parts = urllib.parse.urlsplit(target)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise DynamicError(f"--target phải là URL http(s) đầy đủ, nhận được: {target}")
    if authorization:
        if not os.path.isfile(authorization):
            raise DynamicError(f"không thấy tệp ủy quyền {authorization}")
        return {"mode": "authorization", "file": os.path.abspath(authorization),
                "sha256": sha256_file(authorization)}
    if not is_private_host(parts.hostname):
        raise DynamicError(f"{parts.hostname} không phải địa chỉ cục bộ/mạng riêng — chỉ quét khi có văn bản "
                           f"cho phép của chủ hệ thống (--authorization <tệp>)")
    return {"mode": "private-network"}


def seed_urls(endpoints: list[str], target: str) -> tuple[list[str], list[str]]:
    """Ghép endpoint tĩnh vào mục tiêu. Trả (URL sẽ gửi ZAP, endpoint bị bỏ vì thuộc host khác)."""
    base = urllib.parse.urlsplit(target)
    root = target.rstrip("/")
    seeds, skipped = [], []
    for ep in endpoints:
        if ep.startswith("/"):
            seeds.append(root + ep)
            continue
        u = urllib.parse.urlsplit(ep)
        if u.scheme in ("http", "https") and u.hostname == base.hostname and (u.port or None) == (base.port or None):
            seeds.append(ep)
        else:
            skipped.append(ep)
    return sorted(set(seeds)), skipped


def parse_seed_file(path: str, target: str) -> list[dict]:
    """Tệp yêu cầu mẫu, mỗi dòng: `METHOD /path [body]` (body dạng form). Dòng trống và dòng # bị bỏ qua."""
    reqs = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 2)
            if len(parts) < 2 or parts[0].upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                raise DynamicError(f"{path}:{n}: cần dạng 'METHOD /path [body]'")
            method, path_part = parts[0].upper(), parts[1]
            if not path_part.startswith("/"):
                raise DynamicError(f"{path}:{n}: đường dẫn phải bắt đầu bằng '/' (luôn gửi tới --target)")
            reqs.append({"method": method, "url": target.rstrip("/") + path_part,
                         "body": parts[2] if len(parts) == 3 else ""})
    return reqs


NUMERIC_PARAM = re.compile(r"(?i)(amount|acc|account|id|num|number|count|page|limit|offset|size|qty|price)$")


def placeholder(name: str) -> str:
    return "1" if NUMERIC_PARAM.search(name) else "apiscan"


def auto_requests(extracted: list[dict], target: str) -> list[dict]:
    """Sinh yêu cầu mẫu từ report.json["requests"]: tham số path → giá trị giả, query vào URL, form vào body.

    Giá trị tham số không có trong mã tĩnh nên dùng giá trị giả; ZAP tự thay bằng payload khi active scan.
    """
    root = target.rstrip("/")
    out = []
    for r in extracted:
        path = re.sub(r"\{([^}/]+)\}", lambda m: placeholder(m.group(1)), r["path"])
        query = [(p["name"], placeholder(p["name"])) for p in r["params"] if p["in"] == "query"]
        form = [(p["name"], placeholder(p["name"])) for p in r["params"] if p["in"] in ("form", "multipart")]
        url = root + urllib.parse.quote(path, safe="/%")
        if query:
            url += "?" + urllib.parse.urlencode(query)
        req = {"method": r["method"], "url": url, "body": urllib.parse.urlencode(form), "origin": "static"}
        if r.get("body") == "json" and not form:
            req.update(body="{}", content_type="application/json")
        out.append(req)
    return out


def combine_requests(auto: list[dict], manual: list[dict]) -> list[dict]:
    """Yêu cầu trong tệp --seed-requests thay yêu cầu tự sinh cùng (phương thức, đường dẫn)."""
    def key(r):
        return r["method"], urllib.parse.urlsplit(r["url"]).path
    manual_keys = {key(r) for r in manual}
    return [r for r in auto if key(r) not in manual_keys] + manual


def raw_request(req: dict) -> str:
    u = urllib.parse.urlsplit(req["url"])
    lines = [f"{req['method']} {req['url']} HTTP/1.1", f"Host: {u.netloc}"]
    if req["body"]:
        lines += [f"Content-Type: {req.get('content_type', 'application/x-www-form-urlencoded')}",
                  f"Content-Length: {len(req['body'].encode())}"]
    return "\r\n".join(lines) + "\r\n\r\n" + req["body"]


class Zap:
    def __init__(self, base: str, key: str, timeout: float = 60):
        self.base, self.key, self.timeout = base.rstrip("/"), key, timeout

    def call(self, kind: str, component: str, name: str, **params) -> dict:
        params["apikey"] = self.key
        url = f"{self.base}/JSON/{component}/{kind}/{name}/?{urllib.parse.urlencode(params)}"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except OSError as exc:
            raise DynamicError(f"ZAP {component}/{name}: {exc}") from exc

    def wait(self, component: str, scan_id: str, poll: float, limit: float) -> None:
        deadline = time.monotonic() + limit
        while int(self.call("view", component, "status", scanId=scan_id)["status"]) < 100:
            if time.monotonic() > deadline:
                self.call("action", component, "stop", scanId=scan_id)
                raise DynamicError(f"{component} quá {limit:.0f} s — đã dừng")
            time.sleep(poll)


def run_zap(zap: Zap, target: str, seeds: list[str], requests: list[dict], poll: float = 2,
            spider_limit: float = 600, ascan_limit: float = 3600) -> list[dict]:
    zap.call("action", "context", "newContext", contextName="apiscan")
    zap.call("action", "context", "includeInContext", contextName="apiscan",
             regex=urllib.parse.urljoin(target, "/").rstrip("/") + ".*")
    for url in seeds:
        zap.call("action", "core", "accessUrl", url=url, followRedirects="false")
    for req in requests:
        zap.call("action", "core", "sendRequest", request=raw_request(req), followRedirects="false")
    sid = zap.call("action", "spider", "scan", url=target, contextName="apiscan", recurse="true")["scan"]
    zap.wait("spider", sid, poll, spider_limit)
    aid = zap.call("action", "ascan", "scan", url=target, contextName="apiscan", recurse="true",
                   inScopeOnly="false")["scan"]
    zap.wait("ascan", aid, poll, ascan_limit)
    return zap.call("view", "core", "alerts", baseurl=target, start="0", count="10000")["alerts"]


def normalize_zap(alerts: list[dict], target: str, seeds: list[str]) -> list[dict]:
    """Gộp cảnh báo ZAP theo (plugin, đường dẫn) và gắn nhãn OWASP API 2023."""
    seed_paths = {urllib.parse.urlsplit(s).path for s in seeds}
    host = urllib.parse.urlsplit(target).hostname
    grouped: dict[tuple, dict] = {}
    for a in alerts:
        u = urllib.parse.urlsplit(a.get("url", ""))
        if u.hostname != host:
            continue
        try:
            cwe = int(a.get("cweid") or -1)
        except ValueError:
            cwe = -1
        api = CWE_TO_API.get(cwe)
        key = (a.get("pluginId"), u.path, a.get("param", ""))
        g = grouped.setdefault(key, {
            "source": "zap", "rule_id": f"ZAP-{a.get('pluginId')}", "title": a.get("alert") or a.get("name", ""),
            "severity": RISK_TO_SEVERITY.get(a.get("risk"), "info"), "confidence": a.get("confidence", ""),
            "owasp_api": api or "", "cwe": cwe if cwe > 0 else None, "path": u.path, "param": a.get("param", ""),
            "evidence": (a.get("evidence") or a.get("attack") or "")[:200], "method": a.get("method", ""),
            "seeded_from_static": u.path in seed_paths, "count": 0})
        g["count"] += 1
    return sorted(grouped.values(), key=lambda x: (-SEV_RANK[x["severity"]], x["path"], x["rule_id"]))


def load_mobsf(path: str, scope: list[str]) -> list[dict]:
    import compare_mobsf
    with open(path, encoding="utf-8") as f:
        report = json.load(f)
    units = compare_mobsf.mobsf_units(report, scope)
    return [{"source": "mobsf", "rule_id": u["rule"], "title": u["title"], "severity": u["severity"],
             "location": u["location"], "kind": u["source"]}
            for u in units if u["severity"] in ("high", "warning") and u["in_scope"]]


def merged_html(static: dict, dynamic: list[dict], mobsf: list[dict] | None, meta: dict) -> str:
    e = html.escape

    def badge(s):
        c = {"high": "#b42318", "medium": "#b54708", "warning": "#b54708", "low": "#175cd3"}.get(s, "#475467")
        return f'<span style="background:{c};color:#fff;padding:1px 8px;border-radius:10px;font-size:12px">{e(s)}</span>'

    dyn_rows = "".join(
        f"<tr><td>{badge(d['severity'])}<br><span class='m'>tin cậy ZAP: {e(d['confidence'])}</span></td>"
        f"<td>{e(d['title'])}<br><span class='m'>{e(d['owasp_api'] + ' — ' + API_TOP10.get(d['owasp_api'], '')) if d['owasp_api'] else 'chưa ánh xạ'}"
        f"{' · CWE-' + str(d['cwe']) if d['cwe'] else ''}</span></td>"
        f"<td class='m'>{e(d['method'])} {e(d['path'])}{' · ' + e(d['param']) if d['param'] else ''}"
        f"<br>{'từ bản đồ endpoint tĩnh' if d['seeded_from_static'] else 'ZAP tự tìm'} · {d['count']} lần</td>"
        f"<td class='m'>{e(d['evidence'])}</td></tr>"
        for d in dynamic)
    st_rows = "".join(
        f"<tr><td>{badge(i['severity'])}<br><span class='m'>tin cậy: {e(i['confidence'])}</span></td>"
        f"<td>{e(i['title'])}<br><span class='m'>{e(i['owasp'])} · {e(i['rule_id'])}</span></td>"
        f"<td class='m'>{e(i['location'])}</td><td class='m'>{e((i.get('evidence') or '')[:120])}</td></tr>"
        for i in sorted(static["issues"], key=lambda i: -SEV_RANK.get(i["severity"], 0)))
    mob_box = ""
    if mobsf is not None:
        mob_rows = "".join(f"<tr><td>{badge(m['severity'])}</td><td>{e(m['title'])}<br><span class='m'>{e(m['rule_id'])}"
                           f"</span></td><td class='m'>{e(m['location'])}</td></tr>" for m in mobsf)
        mob_box = (f"<h2>MobSF — phân tích tĩnh, mức high/warning trong phạm vi mã ({len(mobsf)})</h2>"
                   f"<table><tr><th>Mức</th><th>Cảnh báo</th><th>Vị trí</th></tr>{mob_rows}</table>")
    auth = meta["authorization"]
    auth_text = (f"văn bản cho phép {e(os.path.basename(auth['file']))} (SHA-256 {e(auth['sha256'][:16])}…)"
                 if auth["mode"] == "authorization" else "mục tiêu trong mạng cục bộ/riêng")
    return f"""<!doctype html><html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>apiscan — báo cáo hợp nhất {e(static['meta'].get('app', ''))}</title>
<style>body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f7f8fa;color:#1a2233;margin:0}}
.w{{max-width:1100px;margin:0 auto;padding:24px}}h1{{font-size:21px;margin:0 0 4px}}h2{{font-size:16px;margin:24px 0 8px}}
.s{{color:#667;font-size:14px;margin-bottom:14px}}table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e4e7ec}}
th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid #eef0f3;vertical-align:top;font-size:13px}}th{{background:#eef2f7}}
.m{{font-family:monospace;font-size:12px;color:#475467}}.foot{{color:#98a2b3;font-size:12px;margin-top:16px}}</style></head>
<body><div class="w"><h1>Báo cáo hợp nhất tĩnh + động — {e(static['meta'].get('app', '—'))}</h1>
<div class="s">Mục tiêu {e(meta['target'])} · {e(meta['time'])} · cơ sở quét: {auth_text}<br>
{len(static['issues'])} cảnh báo tĩnh · {len(dynamic)} cảnh báo động · {meta['seeds']} URL dẫn đường từ bản đồ endpoint
{f" · {len(meta['skipped_endpoints'])} endpoint khác host bị bỏ qua" if meta['skipped_endpoints'] else ""}</div>
<h2>Quét động — OWASP ZAP, gắn nhãn OWASP API Security Top 10 – 2023 ({len(dynamic)})</h2>
<table><tr><th>Mức</th><th>Cảnh báo</th><th>Endpoint</th><th>Bằng chứng</th></tr>{dyn_rows}</table>
<h2>Phân tích tĩnh — apiscan ({len(static['issues'])})</h2>
<table><tr><th>Mức</th><th>Cảnh báo</th><th>Vị trí</th><th>Bằng chứng</th></tr>{st_rows}</table>
{mob_box}
<p class="foot">Cảnh báo ZAP là kết quả kiểm thử tự động, cần xác minh thủ công. Ánh xạ CWE → OWASP API 2023 là gần đúng.</p>
</div></body></html>"""
