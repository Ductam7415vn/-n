#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kiểm thử trích yêu cầu HTTP từ mã dịch ngược (request_extract.py) và cách lệnh dynamic dùng chúng làm yêu cầu mẫu.

Ca tích hợp với InsecureBankv2 chỉ chạy khi đã có 04_code/target-app/OUT_IB (không commit vào repo).
Chạy:  python3 -m unittest discover -s 04_code/tests -v
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "scripts")))

import dynamic_scan as dyn  # noqa: E402
import request_extract as rx  # noqa: E402
import static_scan as ss  # noqa: E402

TARGET = "http://127.0.0.1:8888"

DOLOGIN = '''class DoLogin {
    void postData() {
        HttpPost httppost = new HttpPost(DoLogin.this.protocol + DoLogin.this.serverip + ":" + DoLogin.this.serverport + "/login");
        HttpPost httppost2 = new HttpPost(DoLogin.this.protocol + DoLogin.this.serverip + ":" + DoLogin.this.serverport + "/devlogin");
        List<NameValuePair> nameValuePairs = new ArrayList<>(2);
        nameValuePairs.add(new BasicNameValuePair("username", DoLogin.this.username));
        nameValuePairs.add(new BasicNameValuePair("password", DoLogin.this.password));
    }
    void other() {
        HttpGet g = new HttpGet("https://api.example.org/v1/items?page=2&sort=asc");
        HttpPost p = new HttpPost(this.url);
    }
}'''

RETROFIT = '''public interface RestService {
    @POST("data/lists/{id}/entries/batch")
    Call<Resp> addEntries(@Path("id") long j, @Query("csrf_token") String str, @Body Batch batch);

    @FormUrlEncoded
    @retrofit2.http.POST("/api/login")
    Call<Token> login(@Field("user") String u,
                      @Field("pass") String p);

    @GET("v1/page/{title}")
    Object page(@Path("title") String str, @Header("Authorization") String auth);
}'''


class TestHttpClient(unittest.TestCase):
    def setUp(self):
        self.reqs = {(r["method"], r["path"]): r for r in rx.extract_requests(DOLOGIN, "a/DoLogin.java")}

    def test_consecutive_constructors_share_params(self):
        for path in ("/login", "/devlogin"):
            with self.subTest(path=path):
                r = self.reqs[("POST", path)]
                self.assertEqual([(p["name"], p["in"]) for p in r["params"]],
                                 [("username", "form"), ("password", "form")])

    def test_full_url_gives_path_and_query_names(self):
        r = self.reqs[("GET", "/v1/items")]
        self.assertEqual([p["name"] for p in r["params"]], ["page", "sort"])
        self.assertEqual(r["location"], "a/DoLogin.java:10")

    def test_dynamic_url_is_skipped(self):
        self.assertEqual(len(self.reqs), 3)

    def test_pairs_far_from_constructor_are_ignored(self):
        text = 'new HttpPost(base + "/x");\n' + "\n" * 70 + 'new BasicNameValuePair("late", v);'
        self.assertEqual(rx.extract_requests(text, "f")[0]["params"], [])


class TestRetrofit(unittest.TestCase):
    def setUp(self):
        self.reqs = {(r["method"], r["path"]): r for r in rx.extract_requests(RETROFIT, "a/RestService.java")}

    def test_path_query_and_body(self):
        r = self.reqs[("POST", "/data/lists/{id}/entries/batch")]
        self.assertEqual([(p["name"], p["in"]) for p in r["params"]], [("id", "path"), ("csrf_token", "query")])
        self.assertEqual(r["body"], "json")

    def test_multiline_signature_and_qualified_annotation(self):
        r = self.reqs[("POST", "/api/login")]
        self.assertEqual([(p["name"], p["in"]) for p in r["params"]], [("user", "form"), ("pass", "form")])
        self.assertIsNone(r["body"])

    def test_header_param_recorded(self):
        r = self.reqs[("GET", "/v1/page/{title}")]
        self.assertIn({"name": "Authorization", "in": "header"}, r["params"])


class TestMerge(unittest.TestCase):
    def test_same_endpoint_in_two_files(self):
        a = rx.extract_requests('new HttpPost(b + "/login");\nnew BasicNameValuePair("username", u);', "A.java")
        b = rx.extract_requests('new HttpPost(b + "/login");\nnew BasicNameValuePair("otp", o);', "B.java")
        merged = rx.merge_requests(a + b)
        self.assertEqual(len(merged), 1)
        self.assertEqual([p["name"] for p in merged[0]["params"]], ["username", "otp"])
        self.assertEqual(merged[0]["locations"], ["A.java:1", "B.java:1"])


class TestAutoRequests(unittest.TestCase):
    EXTRACTED = [
        {"method": "POST", "path": "/dotransfer", "body": None, "source": "HttpClient", "locations": ["x:1"],
         "params": [{"name": "username", "in": "form"}, {"name": "from_acc", "in": "form"},
                    {"name": "amount", "in": "form"}]},
        {"method": "POST", "path": "/data/lists/{id}/entries", "body": "json", "source": "Retrofit",
         "locations": ["y:2"], "params": [{"name": "id", "in": "path"}, {"name": "csrf_token", "in": "query"},
                                          {"name": "Authorization", "in": "header"}]},
    ]

    def test_form_path_query_and_json(self):
        transfer, lists = sorted(dyn.auto_requests(self.EXTRACTED, TARGET + "/"), key=lambda r: r["url"], reverse=True)
        self.assertEqual(transfer["url"], TARGET + "/dotransfer")
        self.assertEqual(transfer["body"], "username=apiscan&from_acc=1&amount=1")
        self.assertEqual(lists["url"], TARGET + "/data/lists/1/entries?csrf_token=apiscan")
        self.assertEqual((lists["body"], lists["content_type"]), ("{}", "application/json"))
        self.assertIn("Content-Type: application/json", dyn.raw_request(lists))

    def test_manual_seed_overrides_auto(self):
        auto = dyn.auto_requests(self.EXTRACTED, TARGET)
        manual = [{"method": "POST", "url": TARGET + "/dotransfer", "body": "username=dinesh"}]
        combined = dyn.combine_requests(auto, manual)
        self.assertEqual(len(combined), 2)
        self.assertIn(manual[0], combined)
        self.assertNotIn("username=apiscan", " ".join(r["body"] for r in combined))


OUT_IB = os.path.normpath(os.path.join(HERE, "..", "target-app", "OUT_IB"))
IB_SEED_FILE = os.path.normpath(os.path.join(HERE, "..", "dynamic", "ib_seed_requests.txt"))


@unittest.skipUnless(os.path.isdir(OUT_IB), "chưa giải nén InsecureBankv2 vào 04_code/target-app/OUT_IB")
class TestInsecureBankv2Requests(unittest.TestCase):
    def test_matches_hand_written_seed_file(self):
        """Phương thức, đường dẫn và tên tham số tự trích khớp tệp yêu cầu mẫu viết tay từ mã dịch ngược."""
        result = ss.analyze(os.path.join(OUT_IB, "apktool"), os.path.join(OUT_IB, "jadx"))
        auto = {(r["method"], r["path"]): [p["name"] for p in r["params"]] for r in result["requests"]}
        manual = {}
        for r in dyn.parse_seed_file(IB_SEED_FILE, TARGET):
            path = r["url"][len(TARGET):]
            manual[(r["method"], path)] = [kv.split("=")[0] for kv in r["body"].split("&")]
        self.assertEqual(auto, manual)


if __name__ == "__main__":
    unittest.main()
