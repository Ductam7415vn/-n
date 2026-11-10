#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apiscan — phát hiện dấu hiệu lỗ hổng bảo mật trong tệp APK Android bằng phân tích tĩnh (chỉ đọc).

Một lệnh từ APK tới báo cáo:
    python3 apiscan.py scan app.apk                      # báo cáo vào ./apiscan-report/<package>/
    python3 apiscan.py scan app.apk -o out/ --min-confidence medium
    python3 apiscan.py scan app.apk --app-pkg com.example.app --app-pkg com.example.lib
    python3 apiscan.py scan app.apk --config apiscan.yml  # tắt luật, bỏ qua cảnh báo đã xác nhận
    python3 apiscan.py batch apks/ -o out/                # nhiều APK → out/index.html tổng hợp
    python3 apiscan.py baseline out/app/report.json -o apiscan.yml
    python3 apiscan.py dynamic out/app/report.json --target http://127.0.0.1:8888 --zap-key <khoá>

Các bước: tính SHA-256 → giải nén bằng apktool + dịch ngược bằng JADX vào thư mục làm việc (dùng lại nếu
đã có cho cùng SHA-256) → tự suy phạm vi mã của app từ Manifest → chạy bộ luật của static_scan → ghi
report.json + report.html.

Công cụ chỉ đọc tệp: không cài, không chạy ứng dụng, không gửi yêu cầu tới máy chủ của ứng dụng.
Cần có `apktool` và `jadx` trong PATH.
"""
import argparse
import csv
import datetime
import glob
import hashlib
import html
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apiscan_config  # noqa: E402
import dynamic_scan  # noqa: E402
import static_scan  # noqa: E402

__version__ = "1.0.0"
DONE_MARKER = ".apiscan-done"


class ScanError(Exception):
    pass


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def require_tool(name: str) -> str:
    exe = shutil.which(name)
    if not exe:
        raise ScanError(f"không tìm thấy '{name}' trong PATH (macOS: brew install {name})")
    return exe


def decompile(apk: str, work: str, force: bool) -> tuple[str, str]:
    """Giải nén APK vào work/apktool và work/jadx; bỏ qua nếu đã làm xong cho cùng APK."""
    apktool_dir, jadx_dir = os.path.join(work, "apktool"), os.path.join(work, "jadx")
    marker = os.path.join(work, DONE_MARKER)
    if os.path.exists(marker) and not force:
        print(f"Dùng lại kết quả giải nén: {work}")
        return apktool_dir, jadx_dir
    os.makedirs(work, exist_ok=True)
    print("Đang giải nén bằng apktool…")
    proc = subprocess.run([require_tool("apktool"), "d", "-f", "-o", apktool_dir, apk],
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if proc.returncode:
        raise ScanError(f"apktool không giải nén được.\n{proc.stderr[-2000:]}")
    print("Đang dịch ngược bằng JADX (có thể mất vài phút)…")
    # JADX trả mã lỗi khác 0 khi một số phương thức không dịch được — vẫn dùng được nếu đã có mã nguồn.
    proc = subprocess.run([require_tool("jadx"), "--no-res", "-d", jadx_dir, apk],
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if not os.path.isdir(os.path.join(jadx_dir, "sources")):
        raise ScanError(f"JADX không tạo được mã nguồn.\n{proc.stderr[-2000:]}")
    if proc.returncode:
        print("  (JADX báo một số phương thức không dịch được — bình thường với app lớn)")
    open(marker, "w").close()
    return apktool_dir, jadx_dir


def scan_apk(apk: str, a, cfg: dict, out: str | None) -> dict:
    """Quét một APK, ghi report.json + report.html; trả kết quả của static_scan.analyze kèm đường dẫn báo cáo."""
    apk = os.path.abspath(apk)
    if not os.path.isfile(apk):
        raise ScanError(f"không thấy tệp {apk}")
    digest = sha256_of(apk)
    print(f"APK: {apk}\nSHA-256: {digest}")
    work = os.path.join(os.path.abspath(a.work_dir), digest[:16])
    apktool_dir, jadx_dir = decompile(apk, work, a.force_decompile)

    pkgs = [x.strip() for v in a.app_pkg for x in v.split(",") if x.strip()] or cfg["app_pkg"]
    started = time.perf_counter()
    result = static_scan.analyze(apktool_dir, jadx_dir, pkgs, a.min_confidence or cfg["min_confidence"] or "low",
                                 cfg["disable"], cfg["suppress"], a.export_rules)
    result["meta"].update({"apk": os.path.basename(apk), "apk_sha256": digest,
                           "analysis_seconds": round(time.perf_counter() - started, 2)})
    if a.config:
        result["meta"]["config"] = os.path.abspath(a.config)

    out = out or os.path.join("apiscan-report", result["meta"]["app"])
    os.makedirs(out, exist_ok=True)
    result["out_json"], result["out_html"] = os.path.join(out, "report.json"), os.path.join(out, "report.html")
    static_scan.write_reports(result, result["out_json"], result["out_html"])
    return result


def load_cfg(a) -> dict:
    try:
        return apiscan_config.load_config(a.config) if a.config else apiscan_config.parse_config(None)
    except apiscan_config.ConfigError as exc:
        raise ScanError(f"cấu hình: {exc}") from exc


def cmd_scan(a) -> int:
    result = scan_apk(a.apk, a, load_cfg(a), a.output)
    print()
    static_scan.print_summary(result)
    print(f"\nBáo cáo: {result['out_html']}\nJSON:    {result['out_json']}")
    return 0


def collect_apks(paths: list[str]) -> list[str]:
    found = []
    for p in paths:
        if os.path.isdir(p):
            found += glob.glob(os.path.join(p, "*.apk"))
        elif os.path.isfile(p):
            found.append(p)
        else:
            raise ScanError(f"không thấy {p}")
    return sorted({os.path.abspath(x) for x in found})


def summary_row(result: dict, report_dir: str) -> dict:
    from collections import Counter
    issues = result["issues"]
    conf, sev = Counter(i.confidence for i in issues), Counter(i.severity for i in issues)
    return {"apk": result["meta"]["apk"], "app": result["meta"]["app"], "sha256": result["meta"]["apk_sha256"],
            "status": "ok", "issues": len(issues),
            "conf_high": conf["high"], "conf_medium": conf["medium"], "conf_low": conf["low"],
            "sev_high": sev["high"], "hidden": result["hidden"], "suppressed": len(result["suppressed"]),
            "endpoints": len(result["endpoints"]), "attack_surface": len(result["attack_surface"]),
            "seconds": result["meta"]["analysis_seconds"],
            "rules": dict(sorted(Counter(i.rule_id for i in issues).items())),
            "owasp": dict(sorted(Counter(i.owasp for i in issues).items())),
            "report": os.path.relpath(result["out_html"], report_dir)}


CSV_FIELDS = ("apk", "app", "sha256", "status", "issues", "conf_high", "conf_medium", "conf_low", "sev_high",
              "hidden", "suppressed", "endpoints", "attack_surface", "seconds", "report", "error")


def cmd_batch(a) -> int:
    cfg = load_cfg(a)
    apks = collect_apks(a.apks)
    if not apks:
        raise ScanError("không có tệp .apk nào để quét")
    if cfg["app_pkg"] and len(apks) > 1:
        raise ScanError("app_pkg trong cấu hình chỉ dùng được khi quét một APK — bỏ đi để mỗi app tự suy phạm vi")
    out = os.path.abspath(a.output)
    os.makedirs(out, exist_ok=True)
    rows, used = [], set()
    for n, apk in enumerate(apks, 1):
        print(f"\n[{n}/{len(apks)}] {os.path.basename(apk)}")
        name = os.path.splitext(os.path.basename(apk))[0]
        if name in used:
            name = f"{name}-{n}"
        used.add(name)
        try:
            result = scan_apk(apk, a, cfg, os.path.join(out, name))
        except (ScanError, OSError) as exc:
            print(f"  LỖI: {exc}")
            rows.append({"apk": os.path.basename(apk), "app": "?", "status": "error", "error": str(exc)})
            continue
        rows.append(summary_row(result, out))
        print(f"  {rows[-1]['issues']} cảnh báo · {rows[-1]['endpoints']} endpoint · {rows[-1]['seconds']} s")

    meta = {"time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            "min_confidence": a.min_confidence or cfg["min_confidence"] or "low",
            "config": os.path.abspath(a.config) if a.config else None}
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "apps": rows}, f, ensure_ascii=False, indent=2)
    with open(os.path.join(out, "summary.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(out, "index.html"), "w", encoding="utf-8") as f:
        f.write(batch_html(rows, meta))
    failed = sum(r["status"] != "ok" for r in rows)
    print(f"\nĐã quét {len(rows) - failed}/{len(rows)} APK. Tổng hợp: {os.path.join(out, 'index.html')}")
    return 1 if failed else 0


def batch_html(rows: list[dict], meta: dict) -> str:
    ok = [r for r in rows if r["status"] == "ok"]
    e = html.escape
    total = sum(r["issues"] for r in ok)
    rules: dict[str, int] = {}
    for r in ok:
        for rule in r["rules"]:
            rules[rule] = rules.get(rule, 0) + 1
    app_rows = "".join(
        f"<tr><td><a href='{e(r['report'])}'>{e(r['app'])}</a><br><span class='m'>{e(r['apk'])}</span></td>"
        f"<td class='n'>{r['issues']}</td><td class='n'>{r['conf_high']}</td><td class='n'>{r['conf_medium']}</td>"
        f"<td class='n'>{r['conf_low']}</td><td class='n'>{r['sev_high']}</td><td class='n'>{r['suppressed']}</td>"
        f"<td class='n'>{r['endpoints']}</td><td class='n'>{r['attack_surface']}</td><td class='n'>{r['seconds']}</td></tr>"
        if r["status"] == "ok" else
        f"<tr class='err'><td>{e(r['apk'])}</td><td colspan='9'>Lỗi: {e(r['error'][:300])}</td></tr>"
        for r in rows)
    rule_rows = "".join(
        f"<tr><td class='m'>{e(rule)}</td><td class='n'>{cnt}/{len(ok)}</td>"
        f"<td><div class='bar' style='width:{100 * cnt / len(ok):.0f}%'></div></td></tr>"
        for rule, cnt in sorted(rules.items(), key=lambda x: (-x[1], x[0])))
    cards = (f"<div class='c'><b>{len(ok)}</b>APK đã quét</div><div class='c'><b>{len(rows) - len(ok)}</b>lỗi</div>"
             f"<div class='c'><b>{total}</b>cảnh báo</div>"
             f"<div class='c'><b>{sum(r['conf_high'] for r in ok)}</b>tin cậy high</div>"
             f"<div class='c'><b>{sum(r['endpoints'] for r in ok)}</b>endpoint</div>")
    return f"""<!doctype html><html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>apiscan — tổng hợp {len(rows)} APK</title>
<style>body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f7f8fa;color:#1a2233;margin:0}}
.w{{max-width:1100px;margin:0 auto;padding:24px}}h1{{font-size:21px;margin:0 0 4px}}h2{{font-size:16px;margin:24px 0 8px}}
.s{{color:#667;font-size:14px;margin-bottom:14px}}.cs{{display:flex;gap:12px;flex-wrap:wrap}}
.c{{background:#fff;border:1px solid #e4e7ec;border-radius:10px;padding:12px 16px;font-size:13px;color:#475467;min-width:120px}}
.c b{{display:block;font-size:24px;color:#1a2233}}.t{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e4e7ec}}
th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid #eef0f3;vertical-align:top;font-size:13px}}
th{{background:#eef2f7}}.n{{text-align:right;font-variant-numeric:tabular-nums}}.m{{font-family:monospace;font-size:12px;color:#475467}}
tr.err td{{background:#fef3f2;color:#b42318}}.bar{{background:#2e6fd8;height:10px;border-radius:5px;min-width:2px}}
.foot{{color:#98a2b3;font-size:12px;margin-top:16px}}</style></head><body><div class="w">
<h1>apiscan — báo cáo tổng hợp</h1>
<div class="s">{len(rows)} APK · ngưỡng tin cậy ≥ {e(meta['min_confidence'])} · {e(meta['time'])}</div>
<div class="cs">{cards}</div>
<h2>Theo ứng dụng</h2><div class="t"><table><tr><th>Ứng dụng</th><th class="n">Cảnh báo</th><th class="n">high</th>
<th class="n">medium</th><th class="n">low</th><th class="n">Mức nghiêm trọng cao</th><th class="n">Đã bỏ qua</th>
<th class="n">Endpoint</th><th class="n">Bề mặt intent</th><th class="n">Giây</th></tr>{app_rows}</table></div>
<h2>Tỉ lệ ứng dụng có cảnh báo theo luật</h2><div class="t"><table><tr><th>Luật</th><th class="n">Số app</th><th style="width:60%"></th></tr>{rule_rows}</table></div>
<p class="foot">Cột high/medium/low là độ tin cậy của cảnh báo. Mọi cảnh báo cần người kiểm tra xác minh theo tệp:dòng trong báo cáo
từng ứng dụng. Công cụ chỉ đọc tệp APK, không gửi yêu cầu mạng tới máy chủ ứng dụng.</p></div></body></html>"""


def cmd_baseline(a) -> int:
    with open(a.report, encoding="utf-8") as f:
        report = json.load(f)
    if any("fingerprint" not in i for i in report.get("issues", [])):
        raise ScanError("báo cáo không có trường fingerprint — quét lại bằng phiên bản apiscan hiện tại")
    text = apiscan_config.baseline_yaml(report)
    if a.output:
        if os.path.exists(a.output) and not a.force:
            raise ScanError(f"{a.output} đã tồn tại (dùng --force để ghi đè)")
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Đã ghi {len(report['issues'])} mục suppress vào {a.output}")
    else:
        sys.stdout.write(text)
    return 0


def cmd_dynamic(a) -> int:
    with open(a.report, encoding="utf-8") as f:
        static = json.load(f)
    try:
        auth = dynamic_scan.check_target(a.target, a.authorization)
        seeds, skipped = dynamic_scan.seed_urls(static.get("endpoints", []), a.target)
        manual = dynamic_scan.parse_seed_file(a.seed_requests, a.target) if a.seed_requests else []
        auto = [] if a.no_auto_requests else dynamic_scan.auto_requests(static.get("requests", []), a.target)
        requests = dynamic_scan.combine_requests(auto, manual)
        if a.zap_json:
            with open(a.zap_json, encoding="utf-8") as f:
                data = json.load(f)
            raw = data["alerts"] if isinstance(data, dict) else data
            print(f"Dùng cảnh báo ZAP có sẵn: {a.zap_json} ({len(raw)} mục)")
        else:
            print(f"ZAP {a.zap}: {len(seeds)} URL từ bản đồ endpoint, {len(requests)} yêu cầu mẫu "
                  f"({sum(r.get('origin') == 'static' for r in requests)} tự trích từ mã) → spider + active scan")
            raw = dynamic_scan.run_zap(dynamic_scan.Zap(a.zap, a.zap_key), a.target, seeds, requests,
                                       ascan_limit=a.max_minutes * 60)
        dynamic = dynamic_scan.normalize_zap(raw, a.target, seeds + [r["url"] for r in requests])
        mobsf = dynamic_scan.load_mobsf(a.mobsf_json, static["meta"].get("scope", [])) if a.mobsf_json else None
    except dynamic_scan.DynamicError as exc:
        raise ScanError(str(exc)) from exc

    meta = {"target": a.target, "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), "authorization": auth,
            "seeds": len(seeds), "seed_requests": len(requests),
            "auto_requests": sum(r.get("origin") == "static" for r in requests), "skipped_endpoints": skipped,
            "static_report": os.path.abspath(a.report)}
    out = a.output or os.path.join(os.path.dirname(os.path.abspath(a.report)), "dynamic")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "merged.json"), "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "static": static["issues"], "dynamic": dynamic, "mobsf": mobsf, "zap_raw": raw},
                  f, ensure_ascii=False, indent=2)
    with open(os.path.join(out, "merged.html"), "w", encoding="utf-8") as f:
        f.write(dynamic_scan.merged_html(static, dynamic, mobsf, meta))
    from collections import Counter
    print(f"Cảnh báo động: {len(dynamic)} | theo mức: {dict(Counter(d['severity'] for d in dynamic))}")
    print(f"Theo OWASP API 2023: {dict(sorted(Counter(d['owasp_api'] or '?' for d in dynamic).items()))}")
    print(f"Báo cáo hợp nhất: {os.path.join(out, 'merged.html')}")
    return 0


def add_scan_options(s, app_pkg: bool = True) -> None:
    s.add_argument("--config", help="Tệp cấu hình YAML: tắt luật, suppression, ngưỡng (xem apiscan_config.py)")
    s.add_argument("--work-dir", default=os.path.join(os.path.expanduser("~"), ".cache", "apiscan"),
                   help="Nơi lưu kết quả giải nén, theo SHA-256 của APK (mặc định ~/.cache/apiscan)")
    if app_pkg:
        s.add_argument("--app-pkg", action="append", default=[],
                       help="Package mã của app (lặp lại được); để trống sẽ tự suy từ Manifest")
    else:
        s.set_defaults(app_pkg=[])
    s.add_argument("--min-confidence", choices=("low", "medium", "high"), default=None,
                   help="Chỉ xuất cảnh báo từ mức tin cậy này trở lên (khuyến nghị: medium)")
    s.add_argument("--force-decompile", action="store_true", help="Giải nén lại kể cả khi đã có")
    s.add_argument("--export-rules", choices=static_scan.EXPORT_RULES, default="v1",
                   help="Bộ luật CFG-EXPORT: v1 (mặc định, dùng trong đánh giá Chương 3) hoặc v2 (thử nghiệm holdout 10)")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="apiscan", description=__doc__.split("\n\n")[0].strip(),
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"apiscan {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="Quét một tệp APK và xuất báo cáo HTML + JSON")
    s.add_argument("apk", help="Đường dẫn tệp .apk")
    s.add_argument("-o", "--output", help="Thư mục báo cáo (mặc định ./apiscan-report/<package>)")
    add_scan_options(s)
    s.set_defaults(func=cmd_scan)
    b = sub.add_parser("batch", help="Quét nhiều APK, xuất báo cáo từng app + index.html/summary.csv tổng hợp")
    b.add_argument("apks", nargs="+", help="Tệp .apk hoặc thư mục chứa .apk")
    b.add_argument("-o", "--output", default="apiscan-batch", help="Thư mục kết quả (mặc định ./apiscan-batch)")
    add_scan_options(b, app_pkg=False)
    b.set_defaults(func=cmd_batch)
    bl = sub.add_parser("baseline", help="Sinh apiscan.yml bỏ qua mọi cảnh báo của một report.json")
    bl.add_argument("report", help="report.json do apiscan scan/batch tạo")
    bl.add_argument("-o", "--output", help="Tệp YAML đầu ra (mặc định in ra màn hình)")
    bl.add_argument("--force", action="store_true", help="Ghi đè tệp đầu ra nếu đã có")
    bl.set_defaults(func=cmd_baseline)
    d = sub.add_parser("dynamic", help="Quét động bằng ZAP (chỉ máy chủ có phép), gộp với báo cáo tĩnh")
    d.add_argument("report", help="report.json của apiscan scan — lấy bản đồ endpoint làm điểm khởi đầu")
    d.add_argument("--target", required=True, help="URL gốc của máy chủ API, vd http://127.0.0.1:8888")
    d.add_argument("--authorization", help="Tệp văn bản cho phép kiểm thử; bắt buộc nếu mục tiêu không phải mạng riêng")
    d.add_argument("--zap", default="http://127.0.0.1:8090", help="Địa chỉ API của ZAP (mặc định 127.0.0.1:8090)")
    d.add_argument("--zap-key", default=os.environ.get("ZAP_API_KEY", ""), help="Khoá API của ZAP (hoặc ZAP_API_KEY)")
    d.add_argument("--zap-json", help="Dùng cảnh báo ZAP đã xuất (core/view/alerts) thay vì gọi ZAP")
    d.add_argument("--seed-requests", help="Tệp yêu cầu mẫu, mỗi dòng 'METHOD /path [body form]'; "
                                           "thay yêu cầu tự trích cùng phương thức + đường dẫn")
    d.add_argument("--no-auto-requests", action="store_true",
                   help="Không tự sinh yêu cầu mẫu từ report.json[\"requests\"] (phương thức + tham số trích từ mã)")
    d.add_argument("--mobsf-json", help="Báo cáo JSON của MobSF để gộp (mobsf_batch.py)")
    d.add_argument("--max-minutes", type=float, default=60, help="Giới hạn thời gian active scan (phút)")
    d.add_argument("-o", "--output", help="Thư mục kết quả (mặc định <thư mục report>/dynamic)")
    d.set_defaults(func=cmd_dynamic)
    a = p.parse_args(argv)
    try:
        return a.func(a)
    except ScanError as exc:
        print(f"Lỗi: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
