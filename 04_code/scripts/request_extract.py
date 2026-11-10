# -*- coding: utf-8 -*-
"""
Trích yêu cầu HTTP (phương thức, đường dẫn, tên tham số) từ mã dịch ngược — CHỈ ĐỌC tệp, không gửi yêu cầu.

Hỗ trợ:
  * Apache HttpClient: `new HttpPost(... + "/path")` kèm `new BasicNameValuePair("ten", ...)` ngay sau đó.
    Các lời tạo HttpX liền nhau (không có tham số xen giữa) dùng chung một danh sách tham số, như
    `/login` và `/devlogin` của InsecureBankv2.
  * Retrofit: `@POST("path")` + tham số `@Field`, `@Query`, `@Path`, `@Header`, `@Part`, `@Body` trên chữ ký hàm.

Kết quả dùng để dẫn đường cho quét động (dynamic_scan.auto_requests); giá trị tham số không trích được từ mã
tĩnh nên chỉ có tên.
"""
from __future__ import annotations

import re
import urllib.parse

HTTP_CTOR = re.compile(r'new\s+Http(Get|Post|Put|Delete|Patch)\s*\(')
NAME_VALUE = re.compile(r'new\s+BasicNameValuePair\(\s*"([^"\\]+)"')
STR_LIT = re.compile(r'"((?:[^"\\]|\\.)*)"')
RETROFIT_VERB = re.compile(r'@(?:retrofit2\.http\.)?(GET|POST|PUT|DELETE|PATCH|HEAD)\(\s*(?:value\s*=\s*)?"([^"]*)"\s*\)')
RETROFIT_PARAM = re.compile(r'@(?:retrofit2\.http\.)?(Field|Query|Path|Header|Part)\(\s*(?:value\s*=\s*)?"([^"]+)"')
RETROFIT_BODY = re.compile(r'@(?:retrofit2\.http\.)?Body\b')
PARAM_KIND = {"Field": "form", "Query": "query", "Path": "path", "Header": "header", "Part": "multipart"}
PAIR_WINDOW = 60


def _ctor_args(line: str, start: int) -> str:
    depth, i = 1, start
    while i < len(line) and depth:
        if line[i] == '"':
            m = STR_LIT.match(line, i)
            i = m.end() if m else i + 1
            continue
        depth += {"(": 1, ")": -1}.get(line[i], 0)
        i += 1
    return line[start:i - 1] if depth == 0 else line[start:]


def path_from_args(args: str) -> tuple[str, list[str]] | None:
    """Đường dẫn (bỏ query) và tên tham số query từ chuỗi literal cuối cùng trông như URL/đường dẫn."""
    for lit in reversed(STR_LIT.findall(args)):
        if "://" in lit:
            u = urllib.parse.urlsplit(lit)
            if not u.netloc:
                continue
            path, query = u.path or "/", u.query
        elif lit.startswith("/") and len(lit) > 1:
            path, _, query = lit.partition("?")
        else:
            continue
        names = [k for k, _ in urllib.parse.parse_qsl(query, keep_blank_values=True)]
        return path, names
    return None


def extract_httpclient(lines: list[str], loc: str) -> list[dict]:
    reqs: list[dict] = []
    group: list[dict] = []
    group_line = -1
    pairs_seen = True
    for i, ln in enumerate(lines, 1):
        for m in HTTP_CTOR.finditer(ln):
            found = path_from_args(_ctor_args(ln, m.end()))
            if not found:
                continue
            path, qnames = found
            req = {"method": m.group(1).upper(), "path": path, "params": [], "body": None,
                   "source": "HttpClient", "location": f"{loc}:{i}"}
            req["params"] += [{"name": n, "in": "query"} for n in qnames]
            if pairs_seen:
                group = []
                pairs_seen = False
            group.append(req)
            group_line = i
            reqs.append(req)
        for m in NAME_VALUE.finditer(ln):
            if not group or i - group_line > PAIR_WINDOW:
                continue
            pairs_seen = True
            for req in group:
                kind = "query" if req["method"] in ("GET", "DELETE") else "form"
                if all(p["name"] != m.group(1) for p in req["params"]):
                    req["params"].append({"name": m.group(1), "in": kind})
    return reqs


def extract_retrofit(lines: list[str], loc: str) -> list[dict]:
    reqs = []
    for i, ln in enumerate(lines):
        m = RETROFIT_VERB.search(ln)
        if not m:
            continue
        sig = []
        for nxt in lines[i + 1:i + 9]:
            sig.append(nxt)
            if ";" in nxt or "{" in nxt:
                break
        sig_text = " ".join(sig)
        raw = m.group(2)
        if "://" in raw:
            raw = urllib.parse.urlsplit(raw).path
        path, _, query = raw.partition("?")
        params = [{"name": k, "in": "query"} for k, _ in urllib.parse.parse_qsl(query, keep_blank_values=True)]
        for pm in RETROFIT_PARAM.finditer(sig_text):
            params.append({"name": pm.group(2), "in": PARAM_KIND[pm.group(1)]})
        reqs.append({"method": m.group(1), "path": "/" + path.lstrip("/"), "params": params,
                     "body": "json" if RETROFIT_BODY.search(sig_text) else None,
                     "source": "Retrofit", "location": f"{loc}:{i + 1}"})
    return reqs


def extract_requests(text: str, loc: str) -> list[dict]:
    if "Http" not in text and "@" not in text:
        return []
    lines = text.splitlines()
    out = []
    if "BasicNameValuePair" in text or HTTP_CTOR.search(text):
        out += extract_httpclient(lines, loc)
    if RETROFIT_VERB.search(text):
        out += extract_retrofit(lines, loc)
    return out


def merge_requests(reqs: list[dict]) -> list[dict]:
    """Gộp theo (phương thức, đường dẫn): hợp tên tham số, giữ mọi vị trí trong mã."""
    merged: dict[tuple, dict] = {}
    for r in reqs:
        key = (r["method"], r["path"])
        g = merged.setdefault(key, {"method": r["method"], "path": r["path"], "params": [], "body": None,
                                    "source": r["source"], "locations": []})
        for p in r["params"]:
            if p not in g["params"]:
                g["params"].append(p)
        g["body"] = g["body"] or r["body"]
        g["locations"].append(r["location"])
    return sorted(merged.values(), key=lambda r: (r["path"], r["method"]))
