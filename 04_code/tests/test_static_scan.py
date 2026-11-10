#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kiểm thử hồi quy cho bộ luật của apiscan (static_scan.py).

Mỗi ca lấy từ một tình huống thật đã gặp khi đánh giá trên InsecureBankv2 và các app mã nguồn mở
(xem docs/PROGRESS.md): ca "phải bắt" giữ recall, ca "phải bỏ qua" giữ các lần giảm báo nhầm.

Chạy:  python3 -m unittest discover -s 04_code/tests -v
Ca tích hợp với InsecureBankv2 chỉ chạy khi đã có 04_code/target-app/OUT_IB (không commit vào repo).
"""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.normpath(os.path.join(HERE, "..", "scripts"))
sys.path.insert(0, SCRIPTS)

import static_scan as ss  # noqa: E402
import test_groundtruth as gt  # noqa: E402


class TestNetHttp(unittest.TestCase):
    FLAG = [
        'String protocol = "http://";',
        'HttpPost p = new HttpPost("http://" + host + "/login");',
        'URL u = new URL("http://api.myapp.vn/v1/users");',
        'return url.replace("https://", "http://");',
        'return "http://" + strTrim;',
        'Request r = new Request.Builder().url("http://api.x.com/v1/elements").build();',
        'webView.loadUrl("http://intranet.corp/app");',
        'public static final String BASE_URL = "http://backend.example.org/api/";',
    ]
    SKIP = [
        'if (StringsKt__StringsJVMKt.startsWith$default(str, "http://", false, 2, null)) {',
        'return str.startsWith("http://") ? "https://".concat(str.substring(7)) : str;',
        'String s = strArr[1].replace("http://", "https://");',
        'String strG0 = p.g0(p.g0(String.valueOf(x), "http://", BuildConfig.FLAVOR), "https://", BuildConfig.FLAVOR);',
        'xml.setFeature("http://xmlpull.org/v1/doc/features.html#process-namespaces", true);',
        'x.getAttributeValue("http://schemas.android.com/apk/res/android", "name");',
        'Element e = message2.findChild("x", "http://jabber.org/protocol/muc#user");',
        'if (z && "http://jabber.org/protocol/nick".equals(attribute2)) {',
        'return pepManager.delete("http://jabber.org/protocol/nick");',
        'legacyCapabilities.setAttribute("node", "http://conversations.im");',
        'if (attribute.startsWith("http://conversations.im#")) {',
        'super(str, "http://gultsch.de/xmpp/drafts/jingle/transports/ice-udp/option");',
        'statusLine.put("xmlns:stream", "http://etherx.jabber.org/streams");',
        'public static final String NSURI = "http://search.yahoo.com/mrss/";',
        'a.startActivity(new Intent("android.intent.action.VIEW", Uri.parse("http://www.openkeychain.org/")));',
        'Element element2 = new Element("fingerprint", "http://gultsch.de/xmpp/drafts/omemo/dlts-srtp-verification");',
    ]

    def test_flag(self):
        for line in self.FLAG:
            with self.subTest(line=line):
                self.assertTrue(ss.has_cleartext_http(line))

    def test_skip(self):
        for line in self.SKIP:
            with self.subTest(line=line):
                self.assertFalse(ss.has_cleartext_http(line))


class TestLogSens(unittest.TestCase):
    CASES = {
        'Log.d("Successful Login:", ", account=" + DoLogin.this.username + ":" + DoLogin.this.password);': True,
        'Log.i("NavigationHelper", "You unlocked a secret unicorn.");': False,
        'Log.e("Tried to refresh invalid view token!", new Object[0]);': False,
        'Log.v(e, "Authentication exception for new token, permanent error assumed", new Object[0]);': False,
        'Log.d(TAG, "token=" + authState.getAccessToken());': True,
        'Log.d(TAG, "got " + getToken(ctx));': True,
        'Log.w(TAG, "password %s rejected", pwd);': True,
        'Log.d(TAG, "Caller %s signature fingerprint matches %s", callingPackage, strHex);': False,
        'Log.e(TAG, "msg: " + e.getMessage() + " (token refresh)");': False,
        'Log.d(TAG, String.format("secret=%s", k));': True,
        'Log.d(TAG, "a(b) \\"quoted\\" token", x);': False,
    }
    CONFIDENCE = {
        'Log.d("Successful Login:", ", account=" + DoLogin.this.username + ":" + DoLogin.this.password);': "high",
        'Log.d(Config.LOGTAG, "received offer to restart ICE " + distinctCredentials);': "high",
        'Log.d(TAG, "got " + getToken(ctx));': "high",
        'Log.d(TAG, "token=" + x);': "medium",
        'Log.w(TAG, "password: %s", value);': "medium",
        'Log.d(Config.LOGTAG, jid + ": storing hashed token " + tokenMechanism);': "medium",
        'Log.i(MasterCredential.TAG, "Reading XML KeyFile version : " + f2);': "low",
        'Log.d(str4, "Autofill password web type: " + tag4 + " " + x);': "low",
        'Log.d(TAG, "no credentials for \'" + request.url() + "\'");': "low",
        'Log.d(TAG, String.format("skipping backup for %s because password is empty", jid));': "low",
    }

    def test_value_logged(self):
        for line, expected in self.CASES.items():
            with self.subTest(line=line):
                self.assertEqual(ss.logs_sensitive_value(line), expected)

    def test_prefilter_spans_nested_parentheses(self):
        rx = [r for r in ss.CODE_RULES if r[0] == "LOG-SENS"][0][4]
        self.assertTrue(rx.search('Log.d(TAG, getX() + this.password);'))

    def test_confidence(self):
        for line, expected in self.CONFIDENCE.items():
            with self.subTest(line=line):
                self.assertEqual(ss.log_confidence(line), expected)


class TestStorageExternal(unittest.TestCase):
    CASES = {
        'File fileToCheck = new File(Environment.getExternalStorageDirectory(), FILENAME);': True,
        'mWebView.loadUrl("file://" + Environment.getExternalStorageDirectory() + "/Statements_" + this.uname + ".html");': True,
        'String MYFILE = Environment.getExternalStorageDirectory() + "/Statements_" + x + ".html";': True,
        'File f = new File(context.getExternalFilesDir(null), "tokens.json");': True,
        'String p = getExternalCacheDir().getAbsolutePath() + "/dump.db";': True,
        'File d = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), name);': True,
        'externalStorageDirectory = Environment.getExternalStorageDirectory();': False,
        'x = string.contains(Environment.getExternalStorageDirectory().getPath()) ? Environment.getExternalStorageDirectory() : new File(string);': False,
        'this.f4084c0.G("android.permission.READ_EXTERNAL_STORAGE");': False,
        'File externalFilesDir = this.f4932g.getExternalFilesDir("Tusky");': False,
        'if (Environment.getExternalStorageState().equals("mounted")) {': False,
    }

    def test_builds_file_path(self):
        for line, expected in self.CASES.items():
            with self.subTest(line=line):
                self.assertEqual(ss.builds_external_file_path(line), expected)


class TestKeyLiteral(unittest.TestCase):
    SECRET = {
        'String key = "This is the super secret key 123";': True,
        'private static final String PASSWORD = "hunter2";': True,
        'String apiKey = "AIzaSyD8x9Kq0LmN3pQ7rS2tU5vW1xY4zA6bC0d";': True,
        'public static final String CLIENT_SECRET = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";': True,
        'static final String token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";': True,
        'private static final String KEY_UP_ARROW = "up_arrow";': False,
        'public static final String KEY_PASSWORD = "password";': False,
        'private static final String PREF_PROXY_PASSWORD = "prefProxyPassword";': False,
        'private static final String PREF_PASSWORD = "de.danoeh.antennapod.preferences.gpoddernet.password";': False,
        'private static final String GROUP_KEY = "de.danoeh.antennapod.EPISODES";': False,
        'private static final String SCROLL_OFFSET_KEY = "scroll_offset";': False,
        'private static final String OPML_ENTITY_KEY = "antennapod-feeds.opml";': False,
        'public static final String TYPE_INTEGER_PRIMARY_KEY = "INTEGER PRIMARY KEY";': False,
        'private static final String KEYS_FEED = "Feeds.id AS feed_id, Feeds.title";': False,
        'private static final String PREF__PUSH_TOKEN = "pushToken";': False,
        'public static final String ACCOUNT_USES_STANDARD_PASSWORD = "ACCOUNT_USES_STANDARD_PASSWORD";': False,
        'private static final String KEY_FIRST_START_DATE = "KEY_FIRST_HIT_DATE";': False,
    }
    VALUE_CONFIDENCE = {
        "This is the super secret key 123": "medium", "XTMMQGA2YZ4WJUBYY4HK": "high",
        "AIzaSyD8x9Kq0LmN3pQ7rS2tU5vW1xY4zA6bC0d": "high", "9f8e7d6c5b4a39281706f5e4d3c2b1a0": "high",
        "Password": "low", "Private key": "low", "OTP Token": "low", "UTF-8": "low", "NESTED_KEY": "low",
        "cert_fingerprint_sha256": "low", "hunter2": "low",
        "/ocs/v2.php/apps/end_to_end_encryption/api/v1/public-key": "low",
        "/ocs/v2.php/apps/sharing/api/v1/secret": "low",
        "https://api.example.com/v2/token": "low",
        "Zx9Kq0LmN3pQ7rS2/tU5vW1xY4zA6bC0d": "high",
    }

    def test_secret_vs_key_name(self):
        for line, expected in self.SECRET.items():
            with self.subTest(line=line):
                self.assertEqual(ss.is_hardcoded_secret(line), expected)

    def test_value_confidence(self):
        for value, expected in self.VALUE_CONFIDENCE.items():
            with self.subTest(value=value):
                self.assertEqual(ss.secret_value_confidence(value), expected)


class TestKeyHardFlow(unittest.TestCase):
    CASES = {
        "insecurebank_field_through_parameter": ('''public class CryptoClass {
    String key = "This is the super secret key 123";
    public static byte[] aes256decrypt(byte[] ivBytes, byte[] keyBytes, byte[] textBytes) throws Exception {
        SecretKeySpec newKey = new SecretKeySpec(keyBytes, "AES");
        return null;
    }
    public String dec(String theString) throws Exception {
        byte[] keyBytes = this.key.getBytes("UTF-8");
        this.cipherData = aes256decrypt(this.ivBytes, keyBytes, Base64.decode(theString.getBytes("UTF-8"), 0));
        return null;
    }
}''', {4}),
        "literal_direct": ('''class A {
    void f() {
        Key k = new SecretKeySpec("0123456789abcdef".getBytes(StandardCharsets.UTF_8), "AES");
    }
}''', {3}),
        "byte_array_field": ('''class A {
    private static final byte[] K = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    void f() {
        SecretKeySpec s = new SecretKeySpec(K, "AES");
    }
}''', {4}),
        "base64_of_constant": ('''class A {
    static final String SECRET = "c2VjcmV0c2VjcmV0c2VjcmV0";
    void f() {
        byte[] bArr = Base64.decode(SECRET, 0);
        SecretKeySpec s = new SecretKeySpec(bArr, "AES");
    }
}''', {5}),
        "scram_constant_is_hmac_message": ('''class ScramSha1 {
    public static byte[] hmac(byte[] bArr, byte[] bArr2) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "HmacSHA1");
        return null;
    }
    public byte[] clientKey(byte[] saltedPassword) throws Exception {
        return hmac(saltedPassword, "Client Key".getBytes());
    }
}''', set()),
        "runtime_keys": ('''class A {
    void f() {
        SecretKeySpec s = new SecretKeySpec(randomBytes(32), "HmacSHA256");
        SecretKeySpec t = new SecretKeySpec(getKey(str, bArr2), "AES");
    }
}''', set()),
        "pbkdf2": ('''class A {
    public SecretKeys gen(String password, byte[] salt) throws Exception {
        byte[] encoded = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(new PBEKeySpec(password.toCharArray(), salt, 10000, 384)).getEncoded();
        return new SecretKeys(new SecretKeySpec(uk.l0(0, encoded, 16), "AES"), null);
    }
}''', set()),
        "same_name_other_method": ('''class A {
    void g() {
        byte[] bArr = "header".getBytes();
    }
    void f(byte[] bArr) {
        SecretKeySpec s = new SecretKeySpec(bArr, "AES");
    }
}''', set()),
    }

    def test_traced_to_constant(self):
        for name, (src, expected) in self.CASES.items():
            with self.subTest(case=name):
                self.assertEqual(ss.hardcoded_key_lines(src), expected)


class TestCodeAlertConfidence(unittest.TestCase):
    IV_TEXT = 'class A { byte[] ivBytes = {0,0,0}; void f(){ new IvParameterSpec(ivBytes); } }'
    CASES = {
        ("CRY-IV0", 'byte[] ivBytes = {0, 0, 0, 0, 0, 0, 0, 0};', IV_TEXT): "high",
        ("CRY-IV0", 'private static final byte[] ZERO_FIVE = {0, 0, 0, 0, 0};', 'class B { }'): "low",
        ("NET-HTTP", 'url = (i & 4) != 0 ? new URL("http://") : url;', ''): "low",
        ("NET-HTTP", 'String protocol = "http://";', ''): "",
        ("STO-EXT", 'String MYFILE = Environment.getExternalStorageDirectory() + "/Statements_" + u + ".html";', ''): "medium",
        ("STO-EXT", 'File file = new File(context.getExternalFilesDir(null), ".nomedia");', ''): "low",
        ("WEB-IFACE", 'addJavascriptInterface();', ''): "low",
        ("WEB-IFACE", 'webView.addJavascriptInterface(this.bridge, "AndroidBergamot");',
         'webView.loadUrl("file:///android_asset/x/index.html");'): "low",
        ("WEB-IFACE", 'webView.addJavascriptInterface(new NativeInterface(c), "NativeInterface");', 'webView.loadUrl(server);'): "",
        ("CRY-WEAK", 'Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");', ''): "low",
    }

    def test_signals(self):
        for (rid, line, text), expected in self.CASES.items():
            with self.subTest(rule=rid, line=line):
                self.assertEqual(ss.code_alert_confidence(rid, line, text), expected)


class TestNetworkSecurityConfig(unittest.TestCase):
    REF = 'android:networkSecurityConfig="@xml/nsc"'
    CASES = {
        "base_cleartext_and_user_ca": (REF, '<network-security-config><base-config cleartextTrafficPermitted="true"><trust-anchors>'
                                            '<certificates src="system"/><certificates src="user"/></trust-anchors></base-config>'
                                            '</network-security-config>', ["NET-NSC", "NET-TRUST"]),
        "onion_only": (REF, '<network-security-config><base-config cleartextTrafficPermitted="false"/><domain-config '
                            'cleartextTrafficPermitted="true"><domain includeSubdomains="true">onion</domain></domain-config>'
                            '</network-security-config>', []),
        "private_ip_only": (REF, '<network-security-config><domain-config cleartextTrafficPermitted="true"><domain>192.168.1.20'
                                 '</domain></domain-config></network-security-config>', []),
        "public_domain": (REF, '<network-security-config><domain-config cleartextTrafficPermitted="true"><domain>api.example.com'
                               '</domain><domain>localhost</domain></domain-config></network-security-config>', ["NET-NSC"]),
        "user_ca_debug_only": (REF, '<network-security-config><debug-overrides><trust-anchors><certificates src="user"/>'
                                    '</trust-anchors></debug-overrides></network-security-config>', []),
        "not_referenced": ("", '<network-security-config><base-config cleartextTrafficPermitted="true"/></network-security-config>', []),
        "nested_inherits": (REF, '<network-security-config><domain-config cleartextTrafficPermitted="true"><domain>10.0.2.2</domain>'
                                 '<domain-config><domain>cdn.example.org</domain></domain-config></domain-config>'
                                 '</network-security-config>', ["NET-NSC"]),
    }

    def test_scoped_findings(self):
        for name, (attr, nsc, expected) in self.CASES.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmp:
                os.makedirs(os.path.join(tmp, "res", "xml"))
                with open(os.path.join(tmp, "AndroidManifest.xml"), "w", encoding="utf-8") as f:
                    f.write('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="x">'
                            f'<application {attr}/></manifest>')
                with open(os.path.join(tmp, "res", "xml", "nsc.xml"), "w", encoding="utf-8") as f:
                    f.write(nsc)
                issues = ss.scan_nsc(tmp)
                self.assertEqual([i.rule_id for i in issues], expected)
                for i in issues:
                    if "domain-config" in i.evidence:
                        self.assertEqual(i.confidence, "medium")


MANIFEST_EXPORT = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="x"><application>
<activity android:name="x.A" android:exported="true" android:permission="x.P"/>
<activity android:name="x.B" android:exported="true" android:enabled="false"/>
<provider android:name="x.Prov" android:authorities="x"/>
<receiver android:name="x.R"><intent-filter><action android:name="x.INTERNAL"/></intent-filter></receiver>
<receiver android:name="x.R2" android:exported="true"><intent-filter><action android:name="com.other.PING"/></intent-filter></receiver>
<activity android:name="x.D" android:exported="false"><intent-filter><action android:name="android.intent.action.VIEW"/></intent-filter></activity>
</application></manifest>'''


class TestExported(unittest.TestCase):
    def test_implicit_export_by_target_sdk(self):
        expected = {16: ["x.Prov", "x.R"], 30: ["x.R"], 33: []}
        for sdk, names in expected.items():
            with self.subTest(target_sdk=sdk):
                issues, surface = ss.classify_exported(MANIFEST_EXPORT, sdk, {"x.INTERNAL"})
                self.assertEqual([i[1] for i in issues], names)
                self.assertEqual([s["component"] for s in surface], ["x.R2"])

    def test_internal_action_on_launcher_is_marked(self):
        xml = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="x"><application>
<activity android:name="x.Main" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/>
<category android:name="android.intent.category.LAUNCHER"/></intent-filter>
<intent-filter><action android:name="x.OPEN"/></intent-filter></activity></application></manifest>'''
        issues, _ = ss.classify_exported(xml, 34, {"x.OPEN"})
        self.assertEqual(len(issues), 1)
        self.assertTrue(issues[0][4], "component LAUNCHER phải được đánh dấu để hạ độ tin cậy")

    def test_v2_third_party_service_is_alert(self):
        xml = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="x"><application>
<service android:name="x.Api" android:exported="true"><intent-filter><action android:name="x.API_CALL"/></intent-filter></service>
<service android:name="x.Sys" android:exported="true"><intent-filter><action android:name="android.view.InputMethod"/></intent-filter></service>
<receiver android:name="x.Rcv" android:exported="true"><intent-filter><action android:name="x.API_CALL"/></intent-filter></receiver>
</application></manifest>'''
        issues, surface = ss.classify_exported(xml, 34, set())
        self.assertEqual(issues, [])
        issues, surface = ss.classify_exported(xml, 34, set(), "v2")
        self.assertEqual([(i[1], i[5]) for i in issues], [("x.Api", ["x.API_CALL"])])
        self.assertEqual([s["component"] for s in surface], ["x.Sys", "x.Rcv"])

    def test_v2_keeps_medium_when_caller_check_present(self):
        java = {"x/Prov.java": "class Prov { void q() { int u = Binder.getCallingUid(); } }"}
        for rules, expected in (("v1", "low"), ("v2", "medium")):
            with self.subTest(rules=rules):
                it = ss.Issue("CFG-EXPORT", "M8", "t", "high", "AndroidManifest.xml:1", "x.Prov", "")
                with tempfile.TemporaryDirectory() as tmp:
                    _, jadx = _make_app(tmp, "<manifest/>", java)
                    ss.refine_export_confidence([it], jadx, rules)
                ss.assign_confidence([it])
                self.assertEqual(it.confidence, expected)


def _make_app(tmp: str, manifest: str, java: dict[str, str]) -> tuple[str, str]:
    apktool_dir, jadx_dir = os.path.join(tmp, "apktool"), os.path.join(tmp, "jadx")
    os.makedirs(apktool_dir)
    with open(os.path.join(apktool_dir, "AndroidManifest.xml"), "w", encoding="utf-8") as f:
        f.write(manifest)
    for rel_path, src in java.items():
        path = os.path.join(jadx_dir, "sources", rel_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(src)
    return apktool_dir, jadx_dir


class TestScopeInference(unittest.TestCase):
    def test_application_id_suffix(self):
        manifest = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.kunzisoft.keepass.libre">
<application android:name="com.kunzisoft.keepass.app.App">
<activity android:name="com.kunzisoft.keepass.activities.Main"/></application></manifest>'''
        with tempfile.TemporaryDirectory() as tmp:
            apk, jadx = _make_app(tmp, manifest, {
                "com/kunzisoft/keepass/libre/R.java": "class R {}",
                "com/kunzisoft/keepass/app/App.java": "class App {}",
            })
            self.assertEqual(ss.infer_app_packages(apk, jadx), ["com.kunzisoft.keepass"])

    def test_multiple_namespaces_and_libraries(self):
        manifest = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.fsck.k9">
<application android:name="app.k9mail.K9App">
<activity android:name="net.thunderbird.app.MainActivity"><intent-filter>
<action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/>
</intent-filter></activity>
<activity android:name="com.fsck.k9.activity.MessageList"/>
<activity android:name="com.blikoon.qrcodescanner.QrCodeActivity"/>
<activity android:name="net.openid.appauth.RedirectUriReceiverActivity"/>
<activity android:name="androidx.work.impl.Foo"/></application></manifest>'''
        with tempfile.TemporaryDirectory() as tmp:
            apk, jadx = _make_app(tmp, manifest, {
                "com/fsck/k9/activity/MessageList.java": "class MessageList {}",
                "app/k9mail/K9App.java": "class K9App {}",
                "net/thunderbird/app/MainActivity.java": "class MainActivity {}",
                "com/blikoon/qrcodescanner/QrCodeActivity.java": "class QrCodeActivity {}",
                "net/openid/appauth/RedirectUriReceiverActivity.java": "class R {}",
            })
            self.assertEqual(ss.infer_app_packages(apk, jadx), ["app.k9mail", "com.fsck.k9", "net.thunderbird"])


class TestAnalyzeEndToEnd(unittest.TestCase):
    def test_mini_app(self):
        manifest = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo.bank">
<uses-sdk android:targetSdkVersion="22"/>
<application android:allowBackup="true" android:debuggable="true">
<activity android:name="com.demo.bank.Transfer" android:exported="true"/></application></manifest>'''
        java = {"com/demo/bank/Login.java": '''package com.demo.bank;
public class Login {
    String key = "This is the super secret key 123";
    void f(String user, String password) {
        Log.d("Login", "account=" + user + ":" + password);
        HttpPost p = new HttpPost("http://" + host + "/devlogin");
    }
}'''}
        with tempfile.TemporaryDirectory() as tmp:
            apk, jadx = _make_app(tmp, manifest, java)
            result = ss.analyze(apk, jadx)
            rules = {i.rule_id for i in result["issues"]}
            self.assertEqual(result["meta"]["scope"], ["com.demo.bank"])
            self.assertTrue({"CFG-DEBUG", "CFG-BACKUP", "CFG-EXPORT", "CRY-KEYLIT", "LOG-SENS",
                             "NET-HTTP", "API-HIDDEN"} <= rules, rules)
            self.assertTrue(all(i.confidence in ("high", "medium", "low") for i in result["issues"]))
            filtered = ss.analyze(apk, jadx, min_confidence="high")
            self.assertTrue(all(i.confidence == "high" for i in filtered["issues"]))
            self.assertEqual(len(filtered["issues"]) + filtered["hidden"], len(result["issues"]))


OUT_IB = os.path.normpath(os.path.join(HERE, "..", "target-app", "OUT_IB"))
IB_LABELS = os.path.normpath(os.path.join(HERE, "..", "..", "03_benchmark", "ground-truth", "insecurebankv2_labels.json"))


@unittest.skipUnless(os.path.isdir(OUT_IB), "chưa giải nén InsecureBankv2 vào 04_code/target-app/OUT_IB")
class TestInsecureBankv2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = ss.analyze(os.path.join(OUT_IB, "apktool"), os.path.join(OUT_IB, "jadx"))
        cls.issues = [{"rule_id": i.rule_id, "location": i.location, "evidence": i.evidence,
                       "confidence": i.confidence} for i in result["issues"]]

    def test_recall_static_answer_key(self):
        for name, pred in gt.IB_GROUND_TRUTH.items():
            with self.subTest(item=name):
                self.assertTrue(pred(self.issues))

    def test_recall_kept_at_medium_confidence(self):
        medium_up = [i for i in self.issues if i["confidence"] in ("high", "medium")]
        for name, pred in gt.IB_GROUND_TRUTH.items():
            with self.subTest(item=name):
                self.assertTrue(pred(medium_up))

    def test_every_alert_matches_a_true_positive_label(self):
        with open(IB_LABELS, encoding="utf-8") as f:
            labels = json.load(f)["labels"]
        used = set()
        for issue in self.issues:
            lb = gt.match_label(issue, labels, used)
            with self.subTest(issue=issue["location"]):
                self.assertIsNotNone(lb)
                self.assertEqual(lb["label"], "TP")
            if lb is not None:
                used.add(id(lb))


if __name__ == "__main__":
    unittest.main()
