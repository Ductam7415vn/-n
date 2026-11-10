#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kiểm thử cấu hình YAML, suppression, baseline và lệnh batch của apiscan.

Chạy:  python3 -m unittest discover -s 04_code/tests -v
"""
import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "scripts")))

import apiscan  # noqa: E402
import apiscan_config as cfgmod  # noqa: E402
import static_scan as ss  # noqa: E402
from test_static_scan import _make_app  # noqa: E402

MANIFEST = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo.bank">
<uses-sdk android:targetSdkVersion="22"/>
<application android:allowBackup="true" android:debuggable="true">
<activity android:name="com.demo.bank.Transfer" android:exported="true"/></application></manifest>'''
JAVA = {"com/demo/bank/Login.java": '''package com.demo.bank;
public class Login {
    String key = "This is the super secret key 123";
    void f(String user, String password) {
        Log.d("Login", "account=" + user + ":" + password);
        HttpPost p = new HttpPost("http://" + host + "/devlogin");
    }
}'''}


class TestParseConfig(unittest.TestCase):
    def test_empty_config_is_valid(self):
        cfg = cfgmod.parse_config(None)
        self.assertEqual((cfg["min_confidence"], cfg["disable"], cfg["suppress"]), (None, set(), []))

    def test_full_config(self):
        cfg = cfgmod.parse_config({"min_confidence": "medium", "app_pkg": "com.x",
                                   "rules": {"disable": ["cry-hash"]},
                                   "suppress": [{"rule": "cfg-export", "evidence": "*Main*", "reason": "launcher"}]})
        self.assertEqual(cfg["app_pkg"], ["com.x"])
        self.assertEqual(cfg["disable"], {"CRY-HASH"})
        self.assertEqual(cfg["suppress"][0]["rule"], "CFG-EXPORT")

    def test_rejects_mistakes(self):
        bad = [
            {"min_confidence": "hi"},
            {"supress": []},
            {"rules": {"enable": ["X"]}},
            {"suppress": [{"rule": "NET-HTTP"}]},
            {"suppress": [{"reason": "không có điều kiện khớp"}]},
            {"suppress": [{"rule": "NET-HTTP", "reason": "x", "file": "a"}]},
        ]
        for data in bad:
            with self.subTest(data=data), self.assertRaises(cfgmod.ConfigError):
                cfgmod.parse_config(data)

    def test_load_yaml_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "apiscan.yml")
            with open(path, "w", encoding="utf-8") as f:
                f.write("min_confidence: high\nsuppress:\n  - id: abc\n    reason: đã xác nhận\n")
            cfg = cfgmod.load_config(path)
            self.assertEqual(cfg["min_confidence"], "high")
            self.assertEqual(cfg["suppress"], [{"id": "abc", "reason": "đã xác nhận"}])
            with open(path, "w", encoding="utf-8") as f:
                f.write("suppress: [\n")
            with self.assertRaises(cfgmod.ConfigError):
                cfgmod.load_config(path)


class TestFingerprint(unittest.TestCase):
    def test_stable_across_line_shift(self):
        a = ss.Issue("NET-HTTP", "M5", "t", "medium", "com/x/A.java:10", 'url("http://a")')
        b = ss.Issue("NET-HTTP", "M5", "t", "medium", "com/x/A.java:42", '  url("http://a")\t')
        c = ss.Issue("NET-HTTP", "M5", "t", "medium", "com/x/B.java:10", 'url("http://a")')
        self.assertEqual(cfgmod.fingerprint(a), cfgmod.fingerprint(b))
        self.assertNotEqual(cfgmod.fingerprint(a), cfgmod.fingerprint(c))


class TestSuppressionInAnalyze(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.apk, self.jadx = _make_app(self.tmp.name, MANIFEST, JAVA)
        self.base = ss.analyze(self.apk, self.jadx)

    def tearDown(self):
        self.tmp.cleanup()

    def test_suppress_by_id_rule_and_glob(self):
        target = next(i for i in self.base["issues"] if i.rule_id == "LOG-SENS")
        entries = [{"id": target.fingerprint, "reason": "log chỉ ở bản debug"},
                   {"rule": "CFG-EXPORT", "evidence": "*Transfer*", "reason": "đã kiểm tra"},
                   {"rule": "NET-HTTP", "location": "*/Nothing.java:*", "reason": "không khớp"}]
        result = ss.analyze(self.apk, self.jadx, suppress=entries)
        rules = {i.rule_id for i in result["issues"]}
        self.assertNotIn("LOG-SENS", rules)
        self.assertNotIn("CFG-EXPORT", rules)
        self.assertEqual(len(result["issues"]) + len(result["suppressed"]), len(self.base["issues"]))
        self.assertEqual(result["unmatched_suppressions"], [3])
        self.assertEqual({s["reason"] for s in result["suppressed"]}, {"log chỉ ở bản debug", "đã kiểm tra"})

    def test_disable_rule(self):
        result = ss.analyze(self.apk, self.jadx, disable={"NET-HTTP", "API-HIDDEN"})
        rules = {i.rule_id for i in result["issues"]}
        self.assertFalse({"NET-HTTP", "API-HIDDEN"} & rules)
        self.assertGreater(result["disabled"], 0)

    def test_reports_carry_fingerprint_and_suppressed(self):
        entries = [{"rule": "CFG-DEBUG", "reason": "bản thử nội bộ"}]
        result = ss.analyze(self.apk, self.jadx, suppress=entries)
        out_json, out_html = os.path.join(self.tmp.name, "r.json"), os.path.join(self.tmp.name, "r.html")
        ss.write_reports(result, out_json, out_html)
        with open(out_json, encoding="utf-8") as f:
            data = json.load(f)
        self.assertTrue(all(len(i["fingerprint"]) == 12 for i in data["issues"]))
        self.assertEqual([s["rule_id"] for s in data["suppressed"]], ["CFG-DEBUG"])
        self.assertEqual(data["suppressed"][0]["suppress_reason"], "bản thử nội bộ")
        with open(out_html, encoding="utf-8") as f:
            self.assertIn("Cảnh báo đã bỏ qua theo cấu hình", f.read())

    def test_baseline_suppresses_everything(self):
        data = {"meta": self.base["meta"], "issues": [{"fingerprint": i.fingerprint, "rule_id": i.rule_id,
                                                       "location": i.location} for i in self.base["issues"]]}
        import yaml
        cfg = cfgmod.parse_config(yaml.safe_load(cfgmod.baseline_yaml(data)))
        result = ss.analyze(self.apk, self.jadx, suppress=cfg["suppress"])
        self.assertEqual(result["issues"], [])
        self.assertEqual(result["unmatched_suppressions"], [])


class TestBatch(unittest.TestCase):
    def test_batch_continues_after_failure_and_writes_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk_dir = os.path.join(tmp, "apks")
            os.makedirs(apk_dir)
            good = os.path.join(apk_dir, "demo.apk")
            bad = os.path.join(apk_dir, "broken.apk")
            for path, data in ((good, b"demo-apk"), (bad, b"broken-apk")):
                with open(path, "wb") as f:
                    f.write(data)
            work = os.path.join(tmp, "work")
            digest = apiscan.sha256_of(good)[:16]
            apktool_dir, jadx_dir = _make_app(os.path.join(work, digest), MANIFEST, JAVA)
            self.assertEqual((apktool_dir, jadx_dir),
                             (os.path.join(work, digest, "apktool"), os.path.join(work, digest, "jadx")))
            open(os.path.join(work, digest, apiscan.DONE_MARKER), "w").close()

            original = apiscan.require_tool
            apiscan.require_tool = lambda name: (_ for _ in ()).throw(apiscan.ScanError(f"thiếu {name}"))
            try:
                out = os.path.join(tmp, "out")
                code = apiscan.cmd_batch(SimpleNamespace(apks=[apk_dir], output=out, config=None, work_dir=work, export_rules="v1",
                                                         app_pkg=[], min_confidence=None, force_decompile=False))
            finally:
                apiscan.require_tool = original

            self.assertEqual(code, 1)
            with open(os.path.join(out, "summary.json"), encoding="utf-8") as f:
                rows = {r["apk"]: r for r in json.load(f)["apps"]}
            self.assertEqual(rows["broken.apk"]["status"], "error")
            self.assertEqual(rows["demo.apk"]["status"], "ok")
            self.assertEqual(rows["demo.apk"]["app"], "com.demo.bank")
            self.assertGreater(rows["demo.apk"]["issues"], 0)
            self.assertTrue(os.path.isfile(os.path.join(out, rows["demo.apk"]["report"])))
            for name in ("index.html", "summary.csv"):
                self.assertTrue(os.path.isfile(os.path.join(out, name)))


if __name__ == "__main__":
    unittest.main()
