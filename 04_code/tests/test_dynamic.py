#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kiểm thử phần quét động của apiscan (dynamic_scan.py) với một ZAP giả chạy trên 127.0.0.1 —
kiểm tra cổng an toàn, cách dẫn đường bằng bản đồ endpoint và cách gộp/gắn nhãn cảnh báo.

Chạy:  python3 -m unittest discover -s 04_code/tests -v
"""
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "scripts")))

import apiscan  # noqa: E402
import dynamic_scan as dyn  # noqa: E402

TARGET = "http://127.0.0.1:8888"
ALERTS = [
    {"pluginId": "40018", "alert": "SQL Injection", "risk": "High", "confidence": "Medium", "cweid": "89",
     "url": TARGET + "/login", "param": "username", "method": "POST", "evidence": "", "attack": "' OR '1'='1"},
    {"pluginId": "40018", "alert": "SQL Injection", "risk": "High", "confidence": "Medium", "cweid": "89",
     "url": TARGET + "/login", "param": "username", "method": "POST", "evidence": "", "attack": "1 OR 1=1"},
    {"pluginId": "10021", "alert": "X-Content-Type-Options Header Missing", "risk": "Low", "confidence": "Medium",
     "cweid": "693", "url": TARGET + "/robots.txt", "param": "", "method": "GET", "evidence": ""},
    {"pluginId": "10099", "alert": "Other host", "risk": "High", "confidence": "Low", "cweid": "200",
     "url": "http://198.51.100.7/x", "param": "", "method": "GET", "evidence": ""},
    {"pluginId": "90001", "alert": "Unmapped", "risk": "Informational", "confidence": "Low", "cweid": "-1",
     "url": TARGET + "/devlogin", "param": "", "method": "GET", "evidence": ""},
]


class FakeZap(BaseHTTPRequestHandler):
    calls: list = []

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        _, _, component, kind, name, _ = u.path.split("/")
        q = dict(urllib.parse.parse_qsl(u.query))
        FakeZap.calls.append((component, kind, name, q))
        if q.get("apikey") != "k":
            self.send_response(403)
            self.end_headers()
            return
        body = {"Result": "OK"}
        if name == "scan":
            body = {"scan": "1"}
        elif name == "status":
            body = {"status": "100"}
        elif name == "alerts":
            body = {"alerts": ALERTS}
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class TestSafetyGate(unittest.TestCase):
    def test_private_targets_allowed(self):
        for t in ("http://127.0.0.1:8888", "http://localhost:5000", "http://192.168.1.20/api", "http://10.0.2.2:8888"):
            with self.subTest(target=t):
                self.assertEqual(dyn.check_target(t, None)["mode"], "private-network")

    def test_public_target_needs_authorization(self):
        with self.assertRaises(dyn.DynamicError):
            dyn.check_target("http://8.8.8.8/", None)
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("Giấy phép kiểm thử")
        try:
            auth = dyn.check_target("http://8.8.8.8/", f.name)
            self.assertEqual(auth["mode"], "authorization")
            self.assertEqual(len(auth["sha256"]), 64)
        finally:
            os.unlink(f.name)

    def test_rejects_non_url(self):
        for t in ("127.0.0.1:8888", "ftp://127.0.0.1/"):
            with self.subTest(target=t), self.assertRaises(dyn.DynamicError):
                dyn.check_target(t, None)


class TestSeeds(unittest.TestCase):
    def test_only_target_host_is_seeded(self):
        seeds, skipped = dyn.seed_urls(["/login", "/login", "http://127.0.0.1:8888/getaccounts",
                                        "https://api.github.com/repos", "http://127.0.0.1:9999/other"], TARGET)
        self.assertEqual(seeds, [TARGET + "/getaccounts", TARGET + "/login"])
        self.assertEqual(skipped, ["https://api.github.com/repos", "http://127.0.0.1:9999/other"])

    def test_seed_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("# mẫu\nPOST /login username=dinesh&password=x\n\nGET /getaccounts\n")
        try:
            reqs = dyn.parse_seed_file(f.name, TARGET)
            self.assertEqual([r["method"] for r in reqs], ["POST", "GET"])
            raw = dyn.raw_request(reqs[0])
            self.assertTrue(raw.startswith("POST http://127.0.0.1:8888/login HTTP/1.1\r\nHost: 127.0.0.1:8888"))
            self.assertTrue(raw.endswith("\r\n\r\nusername=dinesh&password=x"))
            with open(f.name, "w", encoding="utf-8") as g:
                g.write("POST http://evil.example/login a=b\n")
            with self.assertRaises(dyn.DynamicError):
                dyn.parse_seed_file(f.name, TARGET)
        finally:
            os.unlink(f.name)


class TestNormalize(unittest.TestCase):
    def test_group_label_and_filter_host(self):
        out = dyn.normalize_zap(ALERTS, TARGET, [TARGET + "/login"])
        by = {(d["rule_id"], d["path"]): d for d in out}
        self.assertNotIn(("ZAP-10099", "/x"), by)
        sqli = by[("ZAP-40018", "/login")]
        self.assertEqual((sqli["count"], sqli["owasp_api"], sqli["severity"]), (2, "API8", "high"))
        self.assertTrue(sqli["seeded_from_static"])
        self.assertFalse(by[("ZAP-10021", "/robots.txt")]["seeded_from_static"])
        self.assertEqual(by[("ZAP-90001", "/devlogin")]["owasp_api"], "")
        self.assertEqual(out[0]["severity"], "high")


class TestDynamicCommand(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.report = os.path.join(self.tmp.name, "report.json")
        with open(self.report, "w", encoding="utf-8") as f:
            json.dump({"meta": {"app": "com.android.insecurebankv2", "scope": ["com.android.insecurebankv2"]},
                       "issues": [{"rule_id": "NET-HTTP", "owasp": "M5", "title": "URL http", "severity": "medium",
                                   "confidence": "medium", "location": "a/DoLogin.java:3", "evidence": "x"}],
                       "endpoints": ["/login", "/devlogin", "https://api.github.com/x"]}, f)

    def tearDown(self):
        self.tmp.cleanup()

    def args(self, **kw):
        base = dict(report=self.report, target=TARGET, authorization=None, zap="", zap_key="k", zap_json=None,
                    seed_requests=None, no_auto_requests=False, mobsf_json=None, max_minutes=1, output=os.path.join(self.tmp.name, "dyn"))
        base.update(kw)
        return SimpleNamespace(**base)

    def test_against_fake_zap(self):
        server = HTTPServer(("127.0.0.1", 0), FakeZap)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        FakeZap.calls = []
        try:
            code = apiscan.cmd_dynamic(self.args(zap=f"http://127.0.0.1:{server.server_port}"))
        finally:
            server.shutdown()
        self.assertEqual(code, 0)
        names = [(c[0], c[2]) for c in FakeZap.calls]
        accessed = sorted(c[3]["url"] for c in FakeZap.calls if c[2] == "accessUrl")
        self.assertEqual(accessed, [TARGET + "/devlogin", TARGET + "/login"])
        self.assertLess(names.index(("spider", "scan")), names.index(("ascan", "scan")))
        self.assertTrue(all("api.github.com" not in json.dumps(c[3]) for c in FakeZap.calls))
        with open(os.path.join(self.tmp.name, "dyn", "merged.json"), encoding="utf-8") as f:
            merged = json.load(f)
        self.assertEqual(merged["meta"]["skipped_endpoints"], ["https://api.github.com/x"])
        self.assertEqual(len(merged["static"]), 1)
        self.assertIn("SQL Injection", open(os.path.join(self.tmp.name, "dyn", "merged.html"), encoding="utf-8").read())

    def test_offline_zap_json_and_public_target_refused(self):
        zap_json = os.path.join(self.tmp.name, "alerts.json")
        with open(zap_json, "w", encoding="utf-8") as f:
            json.dump({"alerts": ALERTS}, f)
        self.assertEqual(apiscan.cmd_dynamic(self.args(zap_json=zap_json)), 0)
        with self.assertRaises(apiscan.ScanError):
            apiscan.cmd_dynamic(self.args(zap_json=zap_json, target="http://8.8.8.8"))


if __name__ == "__main__":
    unittest.main()
