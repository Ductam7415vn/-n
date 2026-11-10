#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
static_scan.py — Trình phân tích cấu hình & chất lượng mã TĨNH cho ứng dụng Android.

Mục đích (phòng thủ, học thuật): đọc một tệp APK đã được giải nén sẵn bằng apktool
(Manifest + smali) và dịch ngược bằng JADX (mã Java), rồi rà soát các DẤU HIỆU bảo mật
đã được tài liệu hoá công khai (OWASP Mobile Top 10 – 2024). Công cụ:

  * CHỈ ĐỌC tệp trên đĩa. Không cài app, không chạy app, không gửi bất kỳ yêu cầu mạng
    nào tới máy chủ của ứng dụng. Đây không phải công cụ tấn công.
  * Mỗi cảnh báo đều kèm tệp:dòng để người kiểm tra tự xác minh (đúng / báo nhầm).
  * Xuất kết quả ra JSON + báo cáo HTML gắn nhãn OWASP.

Dùng cho đồ án: kiểm chứng độ chính xác trên ứng dụng có đáp án (InsecureBankv2),
sau đó áp dụng để phân tích tĩnh ứng dụng mã nguồn mở (đối chiếu được với mã gốc).

Cách dùng:
    # Bước 1 (ngoài script): giải nén APK trước
    #   apktool d -f -o OUT/apktool  app.apk
    #   jadx     -d OUT/jadx         app.apk
    # Bước 2: chạy phân tích
    python3 static_scan.py --apktool OUT/apktool --jadx OUT/jadx \
        --app-pkg com.android.insecurebankv2 \
        --out-json result.json --out-html result.html

Nếu không truyền --app-pkg, script tự đoán gói ứng dụng từ Manifest.
"""
from __future__ import annotations
import argparse
import html
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict, field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apiscan_config  # noqa: E402
import request_extract  # noqa: E402


# --------------------------------------------------------------------------- #
#  Mô hình cảnh báo
# --------------------------------------------------------------------------- #
@dataclass
class Issue:
    rule_id: str          # mã quy tắc nội bộ
    owasp: str            # mã OWASP Mobile 2024
    title: str            # mô tả ngắn
    severity: str         # high / medium / low / info
    location: str         # tệp:dòng hoặc thành phần
    evidence: str = ""    # trích đoạn làm bằng chứng
    note: str = ""        # ghi chú (vd dễ báo nhầm)
    confidence: str = ""  # high / medium / low — độ chắc của bằng chứng, độc lập với severity
    fingerprint: str = ""  # định danh ổn định (không gồm số dòng), dùng cho suppression


OWASP_TITLE = {
    "M1": "Improper Credential Usage",
    "M2": "Inadequate Supply Chain Security",
    "M3": "Insecure Authentication/Authorization",
    "M4": "Insufficient Input/Output Validation",
    "M5": "Insecure Communication",
    "M7": "Insufficient Binary Protections",
    "M8": "Security Misconfiguration",
    "M9": "Insecure Data Storage",
    "M10": "Insufficient Cryptography",
}


# --------------------------------------------------------------------------- #
#  Tiện ích đọc tệp
# --------------------------------------------------------------------------- #
def read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def iter_java(jadx_dir: str, app_pkg: str | list[str] | None):
    """Duyệt các tệp .java trong phạm vi mã của app (một hoặc nhiều package); không có thư mục nào → toàn bộ."""
    root = os.path.join(jadx_dir, "sources")
    if not os.path.isdir(root):
        root = jadx_dir
    pkgs = [app_pkg] if isinstance(app_pkg, str) else list(app_pkg or [])
    subs = [d for d in (os.path.join(root, *p.split(".")) for p in pkgs) if os.path.isdir(d)] or [root]
    for sub in subs:
        for dp, _, files in os.walk(sub):
            for fn in files:
                if fn.endswith(".java"):
                    yield os.path.join(dp, fn)


def rel(path: str, base: str) -> str:
    try:
        return os.path.relpath(path, base)
    except ValueError:
        return path


# --------------------------------------------------------------------------- #
#  1) Phân tích AndroidManifest  (M8, M5)
# --------------------------------------------------------------------------- #
def guess_app_pkg(apktool_dir: str) -> str | None:
    m = re.search(r'package="([^"]+)"', read(os.path.join(apktool_dir, "AndroidManifest.xml")))
    return m.group(1) if m else None


# Namespace của thư viện phổ biến — không coi là mã của app khi suy phạm vi từ component trong Manifest.
LIBRARY_NAMESPACES = (
    "android.", "androidx.", "com.google.", "kotlin.", "kotlinx.", "org.jetbrains.", "com.squareup.", "okhttp3.",
    "retrofit2.", "io.reactivex.", "org.acra.", "com.jakewharton.", "com.canhub.", "net.openid.", "org.unifiedpush.",
    "com.bumptech.", "org.bouncycastle.", "com.facebook.", "com.journeyapps.", "com.mikepenz.", "org.chromium.",
    "io.sentry.", "com.github.", "leakcanary.", "dagger.", "com.firebase.", "j$.", "org.osmdroid.",
)


def _common_prefix(a: list[str], b: list[str]) -> list[str]:
    out = []
    for x, y in zip(a, b):
        if x != y:
            break
        out.append(x)
    return out


def infer_app_packages(apktool_dir: str, jadx_dir: str) -> list[str]:
    """Suy phạm vi mã của app từ Manifest: package (nếu có mã), namespace của lớp Application, và namespace
    của component ngoài thư viện đã biết khi namespace đó có activity LAUNCHER hoặc từ 2 component trở lên.

    package trong Manifest là applicationId — có thể khác namespace mã (vd hậu tố ".libre") hoặc chỉ là một
    trong nhiều namespace của app (K-9 Mail: com.fsck.k9 + app.k9mail + net.thunderbird).
    """
    root = os.path.join(jadx_dir, "sources")
    if not os.path.isdir(root):
        root = jadx_dir
    try:
        man = ET.parse(os.path.join(apktool_dir, "AndroidManifest.xml")).getroot()
    except (ET.ParseError, OSError):
        return []
    pkg = (man.get("package") or "").split(".")
    app = man.find("application")

    def namespace(cls: str) -> str | None:
        if cls.startswith("."):
            cls = ".".join(pkg) + cls
        if "." not in cls or cls.startswith(LIBRARY_NAMESPACES):
            return None
        parts = cls.split(".")[:-1]
        common = _common_prefix(parts, pkg)
        return ".".join(common if len(common) >= 2 else parts[:2])

    cands = {".".join(pkg)} if pkg != [""] else set()
    counts, launchers = {}, set()
    if app is not None:
        if app.get(ANDROID_NS + "name") and namespace(app.get(ANDROID_NS + "name")):
            cands.add(namespace(app.get(ANDROID_NS + "name")))
        for comp in app:
            if comp.tag not in COMPONENT_TAGS:
                continue
            ns_ = namespace(comp.get(ANDROID_NS + "name") or "")
            if not ns_:
                continue
            counts[ns_] = counts.get(ns_, 0) + 1
            for f in comp.findall("intent-filter"):
                acts = {a.get(ANDROID_NS + "name") for a in f.findall("action")}
                cats = {c.get(ANDROID_NS + "name") for c in f.findall("category")}
                if "android.intent.action.MAIN" in acts and cats & LAUNCHER_CATEGORIES:
                    launchers.add(ns_)
    cands |= {n for n, c in counts.items() if c >= 2 or n in launchers}

    def has_code(p: str) -> bool:
        for dp, _, files in os.walk(os.path.join(root, *p.split("."))):
            if any(f.endswith(".java") and f != "R.java" and not f.startswith("R$") for f in files):
                return True
        return False

    kept = sorted(c for c in cands if c and has_code(c))
    return [c for c in kept if not any(c != o and c.startswith(o + ".") for o in kept)]


SENT_ACTION_PAT = re.compile(r'(?:setAction\(|new Intent\()"([^"]+)"')


def collect_sent_actions(jadx_dir: str, app_pkg: str | None) -> set[str]:
    """Các action mà CHÍNH app tự gửi (setAction("x") / new Intent("x")) trong mã của app."""
    sent: set[str] = set()
    for jf in iter_java(jadx_dir, app_pkg):
        sent.update(SENT_ACTION_PAT.findall(read(jf)))
    return sent


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
LAUNCHER_CATEGORIES = {"android.intent.category.LAUNCHER", "android.intent.category.LEANBACK_LAUNCHER",
                       "android.intent.category.HOME"}
COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


EXPORT_RULES = ("v1", "v2")


def classify_exported(xml: str, target_sdk: int | None, sent_actions: set[str], export_rules: str = "v1"):
    """Tách thành phần exported thành (cảnh báo, bề mặt tiếp nhận intent).

    Cảnh báo: exported không có permission mà không có intent-filter (không có lý do để mở),
    hoặc nhận action tuỳ biến mà chính app tự gửi (kênh nội bộ bị mở ra ngoài).
    Bề mặt: exported để nhận intent của hệ thống / intent chuẩn công khai / giao thức của app bên
    thứ ba — có lý do để mở, không tính là lỗ hổng nhưng vẫn liệt kê để rà soát xử lý đầu vào.
    Trước targetSdk 31, thành phần có intent-filter mà không khai báo exported được export ngầm định;
    provider được export ngầm định khi targetSdk < 17.
    export_rules="v2": service không permission nhận action tuỳ biến của app khác cũng là cảnh báo (service chạy
    mã theo lệnh của bất kỳ app nào, khác activity cần người dùng thao tác) — rút ra từ CVE-2026-65995 (OsmAnd).
    """
    found = []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return found
    app = root.find("application")
    if app is None:
        return found
    for comp in app:
        if comp.tag not in COMPONENT_TAGS:
            continue
        attr = lambda k: comp.get(ANDROID_NS + k)
        if attr("enabled") == "false":
            continue
        filters = comp.findall("intent-filter")
        exported = attr("exported")
        if exported is None:
            if comp.tag == "provider":
                implicit = target_sdk is not None and target_sdk < 17
            else:
                implicit = bool(filters) and target_sdk is not None and target_sdk < 31
            if not implicit:
                continue
            how = "ngầm định"
        elif exported == "false":
            continue
        else:
            how = "khai báo"
        if attr("permission") or (comp.tag == "provider" and attr("readPermission") and attr("writePermission")):
            continue
        actions = [a.get(ANDROID_NS + "name") or "" for f in filters for a in f.findall("action")]
        categories = {c.get(ANDROID_NS + "name") for f in filters for c in f.findall("category")}
        found.append((comp.tag, attr("name") or comp.tag, how, actions, categories))

    issues, surface = [], []
    for tag, name, how, actions, categories in found:
        internal = [a for a in actions if a in sent_actions and not a.startswith("android.")]
        custom = [a for a in actions if not a.startswith("android.")]
        if not actions or internal:
            launcher = "android.intent.action.MAIN" in actions and bool(categories & LAUNCHER_CATEGORIES)
            issues.append((tag, name, how, internal, launcher, []))
            continue
        if export_rules == "v2" and tag == "service" and custom:
            issues.append((tag, name, how, [], False, custom))
            continue
        if custom:
            reason = "Nhận action của app bên thứ ba (app không tự gửi action này)"
        elif "android.intent.action.MAIN" in actions and categories & LAUNCHER_CATEGORIES:
            reason = "Điểm vào ứng dụng (MAIN/LAUNCHER) — bắt buộc exported"
        else:
            reason = "Nhận intent hệ thống/chuẩn công khai — cần rà soát xử lý dữ liệu đầu vào"
        surface.append({"component": name, "type": tag, "exported": how,
                        "actions": actions, "reason": reason})
    return issues, surface


def scan_manifest(apktool_dir: str, sent_actions: set[str] | None = None,
                  export_rules: str = "v1") -> tuple[list[Issue], list[dict]]:
    issues: list[Issue] = []
    mpath = os.path.join(apktool_dir, "AndroidManifest.xml")
    xml = read(mpath)
    if not xml:
        return issues, []

    def line_of(substr_regex: str) -> int:
        for i, ln in enumerate(xml.splitlines(), 1):
            if re.search(substr_regex, ln):
                return i
        return 0

    # debuggable
    if re.search(r'android:debuggable="true"', xml):
        issues.append(Issue("CFG-DEBUG", "M8", "Ứng dụng bật cờ debuggable",
                            "high", f"AndroidManifest.xml:{line_of('debuggable=.true.')}",
                            'android:debuggable="true"',
                            "Bản phát hành không được để true."))
    # allowBackup
    if re.search(r'android:allowBackup="true"', xml):
        curated = re.search(r'android:(fullBackupContent|dataExtractionRules|backupAgent)=', xml)
        issues.append(Issue("CFG-BACKUP", "M8", "Cho phép sao lưu dữ liệu ứng dụng",
                            "medium", f"AndroidManifest.xml:{line_of('allowBackup=.true.')}",
                            'android:allowBackup="true"',
                            "Cho phép trích xuất dữ liệu qua adb backup trên máy đã cắm."
                            + (" Có quy tắc backup/backupAgent — cần đọc quy tắc để biết dữ liệu nào bị sao lưu."
                               if curated else ""),
                            "medium" if curated else "high"))
    # cleartext
    if re.search(r'android:usesCleartextTraffic="true"', xml):
        issues.append(Issue("NET-CLEAR", "M5", "Cho phép lưu lượng HTTP không mã hoá",
                            "high", f"AndroidManifest.xml:{line_of('usesCleartextTraffic=.true.')}",
                            'android:usesCleartextTraffic="true"'))
    # targetSdk thấp => cleartext mặc định cho phép (apktool.yml dạng YAML: "targetSdkVersion: 22")
    yml = read(os.path.join(apktool_dir, "apktool.yml"))
    mt = re.search(r'targetSdkVersion:\s*["\']?(\d+)', yml) \
        or re.search(r'targetSdkVersion="(\d+)"', xml)
    target_sdk = int(mt.group(1)) if mt else None
    if target_sdk is not None and target_sdk < 28:
        issues.append(Issue("NET-SDK", "M5",
                            f"targetSdk={target_sdk} (<28): cleartext HTTP được phép mặc định",
                            "medium", "apktool.yml", f"targetSdkVersion={target_sdk}",
                            "Từ Android 9 (SDK 28) cleartext mới bị chặn mặc định."))

    exported, surface = classify_exported(xml, target_sdk, sent_actions or set(), export_rules)
    for tag, comp, how, internal, launcher, third_party in exported:
        line = line_of(f'android:name="{re.escape(comp)}"')
        if third_party:
            note = (f"Service nhận action {', '.join(third_party)} từ bất kỳ app nào mà không yêu cầu permission — "
                    "cần kiểm tra service có xác thực bên gọi không.")
        elif internal:
            note = (f"Nhận action {', '.join(internal)} mà chính app tự gửi — kênh nội bộ, "
                    "app khác cũng gửi được.")
        else:
            note = "Không có intent-filter: không có lý do để app khác gọi trực tiếp."
        if how == "ngầm định":
            note += f" Exported ngầm định do targetSdk={target_sdk}."
        if launcher:
            note += " Thành phần là LAUNCHER (vốn bắt buộc exported)."
        issues.append(Issue("CFG-EXPORT", "M8",
                            f"Thành phần exported không bảo vệ: {comp.split('.')[-1]}",
                            "high", f"AndroidManifest.xml:{line}", comp, note,
                            "low" if launcher else ""))
    for s in surface:
        line = line_of('android:name="' + re.escape(s["component"]) + '"')
        s["location"] = f"AndroidManifest.xml:{line}"
    return issues, surface


# --------------------------------------------------------------------------- #
#  2) network_security_config  (M5)
# --------------------------------------------------------------------------- #
NON_TLS_HOST = re.compile(r'(localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|'
                          r'172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|\[?::1\]?|(.*\.)?(onion|local|localhost|lan|i2p|home\.arpa))',
                          re.I)


def nsc_config_path(apktool_dir: str) -> str | None:
    """Tệp network_security_config mà Manifest thực sự tham chiếu (tệp không được tham chiếu không có hiệu lực)."""
    m = re.search(r'android:networkSecurityConfig="@xml/([\w.]+)"',
                  read(os.path.join(apktool_dir, "AndroidManifest.xml")))
    if not m:
        return None
    path = os.path.join(apktool_dir, "res", "xml", m.group(1) + ".xml")
    return path if os.path.isfile(path) else None


def _trusts_user_ca(cfg) -> bool:
    return any(c.get("src") == "user" for c in cfg.findall("trust-anchors/certificates"))


def scan_nsc(apktool_dir: str) -> list[Issue]:
    """Phân tích network_security_config theo từng phạm vi.

    base-config cho phép cleartext / tin CA người dùng → áp cho mọi kết nối (high). domain-config chỉ áp cho
    domain liệt kê: bỏ qua khi mọi domain là mạng riêng hoặc không cần TLS (.onion, localhost, IP nội bộ),
    còn domain công khai → medium. debug-overrides chỉ có hiệu lực ở bản debuggable → không cảnh báo.
    """
    issues: list[Issue] = []
    path = nsc_config_path(apktool_dir)
    if not path:
        return issues
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return issues
    loc = rel(path, apktool_dir)
    base = root.find("base-config")
    if base is not None and base.get("cleartextTrafficPermitted") == "true":
        issues.append(Issue("NET-NSC", "M5", "network_security_config cho phép cleartext", "medium", loc,
                            'cleartextTrafficPermitted="true"', "base-config: áp cho mọi kết nối."))
    if base is not None and _trusts_user_ca(base):
        issues.append(Issue("NET-TRUST", "M5", "Tin cậy CA do người dùng cài (user trust anchor)", "medium", loc,
                            "user certificates trusted", "base-config: áp cho mọi kết nối."))

    def walk(cfg, inherited_cleartext):
        cleartext = cfg.get("cleartextTrafficPermitted", inherited_cleartext)
        public = [d.text.strip() for d in cfg.findall("domain")
                  if d.text and not NON_TLS_HOST.fullmatch(d.text.strip())]
        if public and cleartext == "true":
            issues.append(Issue("NET-NSC", "M5", "Cho phép cleartext tới domain công khai", "medium", loc,
                                f'cleartextTrafficPermitted="true" (domain-config: {", ".join(public[:5])})',
                                "Chỉ áp cho các domain liệt kê.", "medium"))
        if public and _trusts_user_ca(cfg):
            issues.append(Issue("NET-TRUST", "M5", "Tin cậy CA do người dùng cài cho domain cụ thể", "medium", loc,
                                f'user certificates trusted (domain-config: {", ".join(public[:5])})',
                                "Chỉ áp cho các domain liệt kê.", "medium"))
        for sub in cfg.findall("domain-config"):
            walk(sub, cleartext)

    for cfg in root.findall("domain-config"):
        walk(cfg, base.get("cleartextTrafficPermitted") if base is not None else None)
    return issues


# --------------------------------------------------------------------------- #
#  3) Rà soát mã Java  (M1, M5, M9, M10, M4, API ẩn)
# --------------------------------------------------------------------------- #
# Mỗi quy tắc: (rule_id, owasp, title, severity, regex, note)
CODE_RULES = [
    ("CRY-WEAK", "M10", "Thuật toán/chế độ mã hoá yếu", "high",
     re.compile(r'getInstance\("(DES|DESede|RC4|AES/ECB|.*ECB.*|.*/ECB/.*)"', re.I),
     "ECB/DES/RC4 bị coi là yếu."),
    ("CRY-HASH", "M10", "Hàm băm yếu cho dữ liệu nhạy cảm", "medium",
     re.compile(r'MessageDigest\.getInstance\("(MD5|SHA-1|SHA1)"', re.I),
     "MD5/SHA-1 không nên dùng để băm mật khẩu."),
    ("CRY-IV0", "M10", "IV tĩnh (mảng byte khởi tạo bằng số 0)", "high",
     re.compile(r'(IvParameterSpec\([^)]*\{\s*0\s*,)|'
                r'(byte\[\]\s*\w*[iI][vV]\w*\s*=\s*\{\s*0\s*,\s*0)'),
     "IV cố định làm mất tính ngẫu nhiên của CBC."),
    ("CRY-KEYLIT", "M1", "Khoá/bí mật viết cứng dạng chuỗi", "high",
     re.compile(r'(String|final\s+String)\s+\w*(key|secret|pass|pwd|token)\w*\s*=\s*'
                r'"(?![^"]*[(\[{^$\\])[^"]{4,}"', re.I),
     "Chuỗi bí mật nhúng thẳng trong mã (đã loại regex/PATTERN, SQL và hằng TÊN khoá như KEY_*/PREF_*)."),
    ("CRY-KEYHARD", "M1", "SecretKeySpec dùng khoá bắt nguồn từ hằng viết cứng", "high",
     re.compile(r'SecretKeySpec\('),
     "Byte khoá truy ngược (trong cùng tệp, qua biến/tham số) về literal chuỗi hoặc mảng byte."),
    ("NET-HTTP", "M5", "Chuỗi http:// trong mã (cleartext)", "medium",
     re.compile(r'"http://[^"]*"'),
     "Có thể là endpoint gọi không mã hoá (đã loại URI namespace và mã kiểm tra/nâng cấp http→https)."),
    ("LOG-SENS", "M9", "Ghi log có thể chứa dữ liệu nhạy cảm", "medium",
     re.compile(r'\bLog\.(?:[dveiw]|wtf)\(.*(password|passwd|pwd|token|secret|username|credential)', re.I),
     "Log in ra giá trị nhạy cảm (không tính thông điệp cố định chỉ chứa từ khoá); bản phát hành nên loại bỏ."),
    ("STO-EXT", "M9", "Ghi dữ liệu ra bộ nhớ ngoài", "medium",
     re.compile(r'getExternal(?:Storage|FilesDir|CacheDir)|EXTERNAL_STORAGE'),
     "App tự tạo đường dẫn tệp trong bộ nhớ ngoài — app khác có thể đọc/ghi trên thiết bị cũ."),
    ("STO-PREF-WORLD", "M9", "SharedPreferences chế độ WORLD_READABLE/WRITEABLE", "high",
     re.compile(r'getSharedPreferences\([^,]+,\s*(1|2|MODE_WORLD)'),
     "Mode 1/2 cho app khác đọc/ghi."),
    ("WEB-JS", "M4", "WebView bật JavaScript", "low",
     re.compile(r'setJavaScriptEnabled\(true\)'),
     "Rủi ro khi kết hợp tải nội dung không tin cậy / file://."),
    ("WEB-IFACE", "M4", "WebView addJavascriptInterface", "medium",
     re.compile(r'addJavascriptInterface\('),
     "Có thể cho JS gọi vào mã native."),
    ("API-HIDDEN", "M8", "Dấu hiệu endpoint dev/test/ẩn", "medium",
     re.compile(r'"/(devlogin|dev/|internal/|staging/|test/)[a-z0-9/_\-]*"', re.I),
     "Có thể là endpoint lẽ ra không xuất hiện ở bản phát hành."),
]

# Mẫu khoá công khai dễ gây BÁO NHẦM — chỉ ghi chú, vẫn liệt kê để người xem quyết định
API_KEY_PAT = re.compile(r'"(AIza[0-9A-Za-z_\-]{20,}|AKIA[0-9A-Z]{16}|sk_live_[0-9A-Za-z]{10,}|ghp_[0-9A-Za-z]{20,})"')

URL_PAT = re.compile(r'"https?://([a-zA-Z0-9.\-]+)(?::\d+)?(/[^"]*)?"')
# loại bỏ các URL namespace/schema phổ biến không phải endpoint
URL_IGNORE = re.compile(r'(w3\.org|xmlpull\.org|apache\.org|android\.com|'
                        r'schemas\.android|googleapis\.com/auth|json-schema\.org|example\.com)', re.I)

SENSITIVE_WORD = re.compile(r'password|passwd|pwd|token|secret|username|credential', re.I)
LOG_CALL = re.compile(r'\bLog\.(?:[dveiw]|wtf)\(')
STR_LIT = re.compile(r'"(?:\\.|[^"\\])*"')
LIT_JOINED_TO_VALUE = re.compile(r'"\s*\+\s*[A-Za-z_(]')
FORMAT_PLACEHOLDER = re.compile(r'%[sdx]|\{\}')


def log_call_args(line: str, start: int) -> str:
    """Phần đối số của lời gọi log, khớp ngoặc và bỏ qua ngoặc nằm trong chuỗi."""
    depth, i = 1, start
    while i < len(line) and depth:
        if line[i] == '"':
            m = STR_LIT.match(line, i)
            i = m.end() if m else len(line)
            continue
        depth += {"(": 1, ")": -1}.get(line[i], 0)
        i += 1
    return line[start:i - 1] if depth == 0 else line[start:]


def logs_sensitive_value(line: str) -> bool:
    """Lời gọi log có in ra GIÁ TRỊ nhạy cảm hay chỉ có từ khoá trong thông điệp cố định.

    Tính là nhạy cảm khi biến/biểu thức (ngoài chuỗi literal) mang tên nhạy cảm, hoặc chuỗi chứa
    từ khoá được nối với một giá trị ("token=" + x) hay có placeholder định dạng ("password %s").
    """
    for call in LOG_CALL.finditer(line):
        args = log_call_args(line, call.end())
        if SENSITIVE_WORD.search(STR_LIT.sub('""', args)):
            return True
        for lit in STR_LIT.finditer(args):
            if not SENSITIVE_WORD.search(lit.group(0)):
                continue
            if FORMAT_PLACEHOLDER.search(lit.group(0)) or LIT_JOINED_TO_VALUE.match(args, lit.end() - 1):
                return True
    return False


EXT_DIR = (r'[\w.]*(?:getExternalStorageDirectory\(\)|getExternalStoragePublicDirectory\([^()]*\)|'
           r'getExternal(?:Files|Cache)Dirs?\([^()]*\))(?:\.(?:getPath|getAbsolutePath|toString)\(\))?')
EXT_FILE_PATH = re.compile(rf'new File\(\s*{EXT_DIR}\s*,|{EXT_DIR}\s*\+|\+\s*{EXT_DIR}')


def builds_external_file_path(line: str) -> bool:
    """Dòng ghép thư mục bộ nhớ ngoài với một tên tệp (app tự tạo tệp ở vùng dùng chung).

    Bỏ qua tham chiếu thư mục trơn (gốc cho bộ chọn tệp, so sánh đường dẫn) và chuỗi tên quyền
    *_EXTERNAL_STORAGE. Đường dẫn ghép qua nhiều dòng sẽ bị bỏ sót (cần phân tích luồng dữ liệu).
    """
    return bool(EXT_FILE_PATH.search(line))


STRING_DECL = re.compile(r'String\s+(\w+)\s*=\s*"((?:\\.|[^"\\])*)"')
SQL_FRAGMENT = re.compile(r'\b(PRIMARY KEY|NOT NULL|AUTOINCREMENT|INTEGER|SELECT|FROM|WHERE|AS)\b')
NAME_LIKE_VALUE = re.compile(r'[A-Za-z][A-Za-z0-9_.\-]*')
QUALIFIED_NAME = re.compile(r'[a-z][a-z0-9_]*(\.[A-Za-z0-9_]+){2,}')
KEY_NAME_PREFIX = re.compile(r'(KEY|PREF|EXTRA|ARG|COLUMN|COL)_')
SECRET_WORDS = {"key", "keys", "pass", "password", "passwd", "pwd", "secret", "token", "api"}


def _words(s: str) -> set[str]:
    return {w.lower() for w in re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?![a-z])', s)
            if len(w) >= 3 and w.lower() not in SECRET_WORDS}


def is_key_name_constant(ident: str, value: str) -> bool:
    """Hằng là TÊN khoá (khoá SharedPreferences/Bundle, tên cột DB, câu SQL) chứ không phải bí mật.

    Chỉ áp cho giá trị dạng định danh (không dấu cách, không có dãy ≥3 chữ số) — bí mật dạng câu
    như "This is the super secret key 123" hay chuỗi ngẫu nhiên nhiều số vẫn bị cảnh báo.
    """
    if SQL_FRAGMENT.search(value):
        return True
    if not NAME_LIKE_VALUE.fullmatch(value) or re.search(r'\d{3,}', value):
        return False
    if QUALIFIED_NAME.fullmatch(value) or KEY_NAME_PREFIX.match(ident):
        return True
    ident_flat = re.sub(r'[^a-z0-9]', '', ident.lower())
    value_flat = re.sub(r'[^a-z0-9]', '', value.lower())
    return (any(w in ident_flat for w in _words(value))
            or any(w in value_flat for w in _words(ident)))


def is_hardcoded_secret(line: str) -> bool:
    m = STRING_DECL.search(line)
    return not (m and is_key_name_constant(m.group(1), m.group(2)))


METHOD_HEADER = re.compile(r'^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|private|protected|static|final|'
                           r'synchronized|native|abstract|strictfp)\s+)*[\w$<>\[\],.? ]+\s+([\w$]+)\s*\(([^)]*)\)'
                           r'\s*(?:throws\s+[^{]+)?\{\s*$')
ASSIGNMENT = re.compile(r'(?:^|[;{]\s*|\b(?:final\s+)?[\w$<>\[\].]+\s+)(?:this\.)?([\w$]+)\s*=\s*([^=;][^;]*);')
BYTE_ARRAY_LIT = re.compile(r'(?:new\s+byte\[\]\s*)?\{[\s\d,\-xXa-fA-F()byte]*\}')
CAST_PREFIX = re.compile(r'^(?:\(\s*[\w$.]+(?:\[\])?\s*\)\s*)+')
DERIVE_CALL = re.compile(r'^[\w$.]*?(getBytes|toCharArray|copyOf|copyOfRange|decode\w*|\w*[Hh]ex\w*|\w*Base64\w*)\((.*)\)$')


def split_args(args: str) -> list[str]:
    out, depth, cur, i = [], 0, "", 0
    while i < len(args):
        c = args[i]
        if c == '"':
            m = STR_LIT.match(args, i)
            j = m.end() if m else len(args)
            cur += args[i:j]
            i = j
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += c
        i += 1
    if cur.strip():
        out.append(cur.strip())
    return out


def is_const_expr(expr: str, tainted: set[str]) -> bool:
    """Biểu thức có giá trị bắt nguồn từ hằng viết cứng (literal / biến đã nhiễm)."""
    e = CAST_PREFIX.sub("", expr.strip())
    if STR_LIT.fullmatch(e) and e != '""':
        return True
    if BYTE_ARRAY_LIT.fullmatch(e) and re.search(r'\d', e):
        return True
    ref = re.fullmatch(r'(?:[\w$]+\.)*([\w$]+)', e)
    if ref:
        return ref.group(1) in tainted
    recv = re.fullmatch(r'(.+?)\.(getBytes|toCharArray)\(.*\)', e)
    if recv:
        return is_const_expr(recv.group(1), tainted)
    call = DERIVE_CALL.match(e)
    if call:
        args = split_args(call.group(2))
        return bool(args) and is_const_expr(args[0], tainted)
    return False


def split_methods(lines: list[str]):
    """(tên hàm, danh sách tham số, chỉ số dòng thân hàm) + các dòng ngoài hàm (field)."""
    methods, in_method, i = [], set(), 0
    while i < len(lines):
        m = METHOD_HEADER.match(lines[i])
        if not m:
            i += 1
            continue
        params = [p.split()[-1] for p in split_args(m.group(2)) if p.split()]
        depth, body, j = 0, [], i
        while j < len(lines):
            depth += STR_LIT.sub('""', lines[j]).count("{") - STR_LIT.sub('""', lines[j]).count("}")
            body.append(j)
            if depth <= 0 and j > i:
                break
            j += 1
        methods.append((m.group(1), params, body))
        in_method.update(body)
        i = j + 1
    fields = [k for k in range(len(lines)) if k not in in_method]
    return methods, fields


def hardcoded_key_lines(text: str) -> set[int]:
    """Số dòng (1-based) có SecretKeySpec mà byte khoá truy về hằng viết cứng trong cùng tệp."""
    if "SecretKeySpec(" not in text:
        return set()
    lines = text.splitlines()
    methods, field_lines = split_methods(lines)
    fields: set[str] = set()
    for k in field_lines:
        for m in ASSIGNMENT.finditer(lines[k]):
            if is_const_expr(m.group(2), fields):
                fields.add(m.group(1))
    tainted_params = {name: set() for name, _, _ in methods}
    local: dict[int, set[str]] = {}
    for _ in range(5):
        changed = False
        for idx, (name, params, body) in enumerate(methods):
            env = set(fields) | tainted_params[name]
            grew = True
            while grew:
                grew = False
                for k in body:
                    for m in ASSIGNMENT.finditer(lines[k]):
                        if m.group(1) not in env and is_const_expr(m.group(2), env):
                            env.add(m.group(1))
                            grew = True
            local[idx] = env
            for callee, cparams, _ in methods:
                for k in body:
                    for cm in re.finditer(rf'\b{re.escape(callee)}\(', lines[k]):
                        args = split_args(log_call_args(lines[k], cm.end()))
                        for pos, arg in enumerate(args[:len(cparams)]):
                            if cparams[pos] not in tainted_params[callee] and is_const_expr(arg, env):
                                tainted_params[callee].add(cparams[pos])
                                changed = True
        if not changed:
            break
    hits = set()
    for idx, (_, _, body) in enumerate(methods):
        for k in body:
            for sm in re.finditer(r'SecretKeySpec\(', lines[k]):
                args = split_args(log_call_args(lines[k], sm.end()))
                if args and is_const_expr(args[0], local.get(idx, fields)):
                    hits.add(k + 1)
    return hits


HTTP_LIT = re.compile(r'"http://[^"]*"')
STR_OPS = ('startsWith|endsWith|replace|replaceFirst|replaceAll|contains|equals|equalsIgnoreCase|'
           'indexOf|lastIndexOf|regionMatches|removePrefix|matches')
STR_OP_CALL = re.compile(rf'({STR_OPS})\w*(\$default)?$')
STR_OP_ON_LITERAL = re.compile(rf'\.({STR_OPS})\(')
IDENTIFIER_CALL = re.compile(r'(Child|Feature|Namespace|Attribute|Extension|Element|Tag|Node)', re.I)
SPEC_URI = re.compile(r'#|/(protocol|ns|schemas?|xmlns|dtds?|drafts?)/|\.(dtd|xsd)"', re.I)
NAMESPACE_CONTEXT = re.compile(r'xmlns|"urn:|\b\w*(NSURI|NAMESPACE|XMLNS|SCHEMA)\w*\s*=|\b(NS|NS_\w+|\w+_NS)\s*=', re.I)
BROWSER_INTENT = re.compile(r'android\.intent\.action\.VIEW|ACTION_VIEW')
HTTPS_TO_HTTP = re.compile(r'"https://"\s*,\s*"http://"')


def enclosing_calls(line: str) -> dict[int, str]:
    """Vị trí bắt đầu mỗi literal chuỗi -> tên hàm trực tiếp bao quanh nó ("" nếu không nằm trong lời gọi)."""
    calls, stack, i = {}, [], 0
    while i < len(line):
        c = line[i]
        if c == '"':
            m = STR_LIT.match(line, i)
            if not m:
                break
            calls[i] = stack[-1] if stack else ""
            i = m.end()
            continue
        if c == "(":
            name = re.search(r'([\w$]+)\s*$', line[:i])
            stack.append(name.group(1) if name else "")
        elif c == ")" and stack:
            stack.pop()
        i += 1
    return calls


def has_cleartext_http(line: str) -> bool:
    """Dòng có chuỗi http:// thật sự dùng để kết nối hay không — xét theo NGỮ CẢNH của literal.

    Bỏ qua literal là định danh chứ không phải địa chỉ kết nối: đối số của hàm XML/namespace
    (findChild, hasFeature, setAttribute…) hoặc hàm so sánh chuỗi; URI dạng đặc tả (có #, /protocol/,
    /ns/, .dtd…); hằng namespace / dòng có xmlns, urn:; link mở bằng trình duyệt ngoài (intent VIEW);
    "http://" trơn đi cùng "https://" (chuẩn hoá scheme). Hạ cấp replace("https://", "http://") vẫn giữ.
    """
    if HTTPS_TO_HTTP.search(line):
        return True
    if NAMESPACE_CONTEXT.search(line) or BROWSER_INTENT.search(line):
        return False
    calls = enclosing_calls(line)
    for m in HTTP_LIT.finditer(line):
        lit, call = m.group(0), calls.get(m.start(), "")
        if URL_IGNORE.search(lit) or SPEC_URI.search(lit):
            continue
        if STR_OP_CALL.search(call) or STR_OP_ON_LITERAL.match(line, m.end()):
            continue
        if call and IDENTIFIER_CALL.search(call):
            continue
        if lit == '"http://"' and '"https://"' in line:
            continue
        return True
    return False


def scan_code(jadx_dir: str, app_pkg: str | None,
              requests: list[dict] | None = None) -> tuple[list[Issue], list[str]]:
    """requests (nếu truyền vào) nhận thêm các yêu cầu HTTP trích từ mã, xem request_extract."""
    issues: list[Issue] = []
    endpoints: set[str] = set()
    base = os.path.join(jadx_dir, "sources")
    if not os.path.isdir(base):
        base = jadx_dir

    PATH_LIT = re.compile(r'"(/[a-zA-Z][a-zA-Z0-9/_\-]{1,60})"')
    NET_HINT = re.compile(r'HttpPost|HttpGet|HttpURLConnection|okhttp|Retrofit|@(GET|POST|PUT|DELETE)\b|\.url\(')

    for jf in iter_java(jadx_dir, app_pkg):
        bn = os.path.basename(jf)
        if bn == "R.java" or bn.startswith("R$"):
            continue  # tệp sinh tự động, nhiều nhiễu
        # BuildConfig sinh tự động nhưng hay chứa khoá API — chỉ xét CRY-KEYLIT
        build_config = bn == "BuildConfig.java"
        text = read(jf)
        if not text:
            continue
        loc = rel(jf, base)
        if requests is not None and not build_config:
            requests += request_extract.extract_requests(text, loc)
        lines = text.splitlines()
        file_is_net = bool(NET_HINT.search(text))
        key_hits = hardcoded_key_lines(text)
        for i, ln in enumerate(lines, 1):
            for rid, owasp, title, sev, rx, note in CODE_RULES:
                if build_config and rid != "CRY-KEYLIT":
                    continue
                if rx.search(ln):
                    if rid == "NET-HTTP" and not has_cleartext_http(ln):
                        continue
                    if rid == "LOG-SENS" and not logs_sensitive_value(ln):
                        continue
                    if rid == "STO-EXT" and not builds_external_file_path(ln):
                        continue
                    if rid == "CRY-KEYLIT" and not is_hardcoded_secret(ln):
                        continue
                    if rid == "CRY-KEYHARD" and i not in key_hits:
                        continue
                    issues.append(Issue(rid, owasp, title, sev, f"{loc}:{i}",
                                        ln.strip()[:160], note, code_alert_confidence(rid, ln, text)))
            if build_config:
                continue
            # khoá dịch vụ công khai (ghi chú báo nhầm)
            for km in API_KEY_PAT.finditer(ln):
                issues.append(Issue("KEY-SERVICE", "M1",
                                    "Chuỗi giống API key dịch vụ", "low", f"{loc}:{i}",
                                    km.group(1)[:12] + "…",
                                    "RẤT DỄ BÁO NHẦM: khoá Firebase/Maps thường được phép công khai."))
            # thu thập endpoint cho bản đồ API
            for um in URL_PAT.finditer(ln):
                hostpath = um.group(1) + (um.group(2) or "")
                if not URL_IGNORE.search(um.group(0)):
                    endpoints.add(hostpath[:120])
            # đường dẫn tương đối "/..." trong tệp có gọi mạng
            if file_is_net:
                for pm in PATH_LIT.finditer(ln):
                    endpoints.add(pm.group(1))
    return issues, sorted(endpoints)


# --------------------------------------------------------------------------- #
#  Xuất báo cáo
# --------------------------------------------------------------------------- #
SEV_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}


# Mức tin cậy theo LOẠI BẰNG CHỨNG của luật (đặt trước, không suy từ precision đo được):
#   high   — bằng chứng trực tiếp chứng minh điểm yếu (cờ/cấu hình, giá trị literal, luồng từ hằng).
#   medium — dấu hiệu mạnh nhưng mã có thể có kiểm tra/bối cảnh mà phân tích tĩnh không thấy.
#   low    — bề mặt rủi ro, tự nó chưa phải lỗ hổng (cần thêm điều kiện mới khai thác được).
RULE_CONFIDENCE = {
    "CFG-DEBUG": "high", "NET-CLEAR": "high", "NET-NSC": "high", "NET-TRUST": "high", "NET-SDK": "high",
    "CRY-IV0": "high", "CRY-KEYHARD": "high", "STO-PREF-WORLD": "high",
    "CFG-EXPORT": "medium", "CRY-KEYLIT": "medium", "CRY-WEAK": "medium", "LOG-SENS": "medium",
    "NET-HTTP": "medium", "API-HIDDEN": "medium", "WEB-IFACE": "medium",
    "STO-EXT": "low", "WEB-JS": "low", "CRY-HASH": "low", "KEY-SERVICE": "low",
}
CONF_RANK = {"high": 3, "medium": 2, "low": 1}


SENSITIVE_HEAD = re.compile(r'(password|passwd|pwd|passphrase|token|secret|credentials?)$', re.I)
LITERAL_ENDS_WITH_SECRET_WORD = re.compile(
    r'(password|passwd|pwd|token|secret|credentials?|username)\w*\s*[=:]?\s*[\'"]?\s*(%[sdx])?\s*"$', re.I)
KNOWN_KEY_PREFIX = re.compile(r'(AIza|AKIA|ASIA|ghp_|gho_|ghs_|sk_live_|rk_live_|xox[abp]-|glpat-)')
CHARSETS = {"UTF-8", "UTF8", "UTF-16", "US-ASCII", "ASCII", "ISO-8859-1"}
DATA_FILE_LITERAL = re.compile(r'\.(db|sqlite|html?|txt|json|xml|csv|log|key|pem|p12|bak)"', re.I)
FILE_WRITE_API = re.compile(r'FileWriter|FileOutputStream|BufferedWriter|copyFile|openFileOutput|writeText|writeBytes')
CALLER_CHECK_API = re.compile(r'getCallingPackage|getCallingUid|getCallingPid|checkCallingPermission|'
                              r'checkCallingOrSelfPermission|enforceCallingPermission|enforceCallingOrSelfPermission')


def _camel_words(name: str) -> list[str]:
    return re.findall(r'[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])', name)


def _shannon(value: str) -> float:
    from math import log2
    n = len(value)
    return -sum(c / n * log2(c / n) for c in (value.count(ch) for ch in set(value))) if n else 0.0


def log_confidence(line: str) -> str:
    """high: in ra biến/field/getter có danh từ chính nhạy cảm; medium: chuỗi KẾT THÚC bằng từ khoá rồi
    nối/định dạng giá trị; low: từ khoá chỉ ở tên lớp/TAG hoặc giữa câu."""
    level = "low"
    for call in LOG_CALL.finditer(line):
        args = log_call_args(line, call.end())
        code = STR_LIT.sub('""', args)
        for m in re.finditer(r'(?<![\w$])([A-Za-z_$][\w$]*)', code):
            tok = m.group(1)
            if tok[0].isupper() or tok == "TAG":
                continue
            words = _camel_words(re.sub(r'^(get|is)(?=[A-Z])', '', tok))
            if words and SENSITIVE_HEAD.fullmatch(words[-1].lower()):
                return "high"
        for lit in STR_LIT.finditer(args):
            joined = LIT_JOINED_TO_VALUE.match(args, lit.end() - 1) or FORMAT_PLACEHOLDER.search(lit.group(0))
            if joined and LITERAL_ENDS_WITH_SECRET_WORD.search(lit.group(0)):
                level = "medium"
    return level


def secret_value_confidence(value: str) -> str:
    """Độ giống bí mật của GIÁ TRỊ literal: khoá ngẫu nhiên/tiền tố khoá → high; nhãn chữ, tên định danh,
    bảng mã, đường dẫn/URL, chuỗi ngắn → low; còn lại (passphrase…) → medium."""
    if KNOWN_KEY_PREFIX.match(value):
        return "high"
    if (len(value) < 8 or value.upper() in CHARSETS or value.startswith("/") or "://" in value
            or re.fullmatch(r'[A-Za-z]+(?:[ \-][A-Za-z]+){0,2}', value)
            or re.fullmatch(r'[a-z0-9]+(?:[_.\-][a-z0-9]+)+', value)
            or re.fullmatch(r'[A-Z0-9]+(?:_[A-Z0-9]+)+', value)):
        return "low"
    if (len(value) >= 16 and " " not in value and _shannon(value) >= 3.5
            and re.search(r'\d', value) and re.search(r'[A-Za-z]', value)):
        return "high"
    return "medium"


def code_alert_confidence(rid: str, line: str, text: str) -> str:
    """Độ tin cậy theo tín hiệu của TỪNG cảnh báo trong mã; "" = dùng mặc định của luật."""
    if rid == "LOG-SENS":
        return log_confidence(line)
    if rid == "CRY-KEYLIT":
        m = STRING_DECL.search(line)
        return secret_value_confidence(m.group(2)) if m else ""
    if rid == "CRY-IV0":
        m = re.search(r'byte\[\]\s*([\w$]+)\s*=', line)
        used_as_iv = "ParameterSpec(" in line or (
            m and re.search(rf'(IvParameterSpec|GCMParameterSpec)\([^;]*\b{re.escape(m.group(1))}\b', text))
        return "high" if used_as_iv else "low"
    if rid == "NET-HTTP":
        return "low" if re.search(r'(new URL|Uri\.parse)\(\s*"http://"\s*\)', line) else ""
    if rid == "STO-EXT":
        return "medium" if DATA_FILE_LITERAL.search(line) or FILE_WRITE_API.search(line) else "low"
    if rid == "WEB-IFACE":
        if re.search(r'addJavascriptInterface\(\s*\)', line):
            return "low"
        loads = re.findall(r'loadUrl\(\s*"([^"]*)"', text)
        return "low" if loads and all(u.startswith("file:///android_asset") for u in loads) else ""
    if rid == "CRY-WEAK":
        return "low" if re.search(r'"RSA/ECB/', line) else ""
    return ""


def refine_export_confidence(issues: list[Issue], jadx_dir: str, export_rules: str = "v1") -> None:
    """CFG-EXPORT: đọc mã lớp của component — có kiểm tra danh tính app gọi → low.

    Không hạ mức khi mã chỉ "không đọc intent": màn hình đặc quyền mở thẳng được (bỏ qua đăng nhập) vẫn
    là lỗ hổng dù không nhận dữ liệu (vd DoTransfer của InsecureBankv2).
    """
    root = os.path.join(jadx_dir, "sources")
    if not os.path.isdir(root):
        root = jadx_dir
    for it in issues:
        if it.rule_id != "CFG-EXPORT" or it.confidence:
            continue
        src = read(os.path.join(root, *it.evidence.split("$")[0].split(".")) + ".java")
        if not src:
            continue
        if CALLER_CHECK_API.search(src):
            if export_rules == "v1":
                it.confidence = "low"
            it.note += " Mã có kiểm tra danh tính app gọi."


def assign_confidence(issues: list[Issue]) -> list[Issue]:
    for it in issues:
        if not it.confidence:
            it.confidence = RULE_CONFIDENCE.get(it.rule_id, "medium")
    return issues


def to_html(issues: list[Issue], endpoints: list[str], meta: dict, surface: list[dict] | None = None,
            suppressed: list[dict] | None = None, requests: list[dict] | None = None) -> str:
    by = {}
    for it in issues:
        by.setdefault(it.owasp, []).append(it)

    def badge(s):
        c = {"high": "#b42318", "medium": "#b54708", "low": "#175cd3", "info": "#475467"}.get(s, "#475467")
        return f'<span style="background:{c};color:#fff;padding:1px 8px;border-radius:10px;font-size:12px">{s}</span>'

    rows = []
    for code in sorted(by, key=lambda c: (c != "N/A", c)):
        fs = sorted(by[code], key=lambda x: (-CONF_RANK.get(x.confidence, 0), -SEV_RANK.get(x.severity, 0)))
        rows.append(f'<tr class="g"><td colspan="4"><b>{code}</b> — {html.escape(OWASP_TITLE.get(code, "?"))} ({len(fs)})</td></tr>')
        for it in fs:
            rows.append("<tr>"
                        f"<td>{badge(it.severity)}<br><span style='font-size:11px;color:#475467'>tin cậy: "
                        f"{html.escape(it.confidence)}</span></td>"
                        f"<td>{html.escape(it.title)}</td>"
                        f"<td style='font-family:monospace;font-size:12px'>{html.escape(it.location)}"
                        f"<br><span style='color:#98a2b3' title='id dùng cho suppress trong apiscan.yml'>"
                        f"id {html.escape(it.fingerprint)}</span></td>"
                        f"<td style='font-size:12px;color:#475467'>{html.escape((it.evidence or '')[:90])}"
                        f"{'<br><i>'+html.escape(it.note)+'</i>' if it.note else ''}</td></tr>")
    eps = "".join(f"<li style='font-family:monospace;font-size:12px'>{html.escape(e)}</li>" for e in endpoints[:200])
    surf = "".join(
        f"<tr><td style='font-family:monospace;font-size:12px'>{html.escape(x['component'])}<br>"
        f"<span style='color:#98a2b3'>{html.escape(x['type'])} · exported {html.escape(x['exported'])} · "
        f"{html.escape(x['location'])}</span></td>"
        f"<td style='font-size:12px'>{html.escape(x['reason'])}<br>"
        f"<span style='font-family:monospace;color:#475467'>{html.escape(', '.join(x['actions']))}</span></td></tr>"
        for x in surface or [])
    surf_box = (f'<div class="box"><b>Bề mặt tiếp nhận intent</b> ({len(surface)} thành phần exported có lý do — '
                f'không tính là lỗ hổng, cần rà soát cách xử lý dữ liệu đầu vào)'
                f'<table style="margin-top:8px">{surf}</table></div>') if surface else ""
    req_rows = []
    for r in (requests or [])[:200]:
        params = ", ".join(f"{p['name']} ({p['in']})" for p in r["params"]) or "—"
        more = f" (+{len(r['locations']) - 1})" if len(r["locations"]) > 1 else ""
        req_rows.append(
            f"<tr><td style='font-family:monospace;font-size:12px'>{html.escape(r['method'])} {html.escape(r['path'])}</td>"
            f"<td style='font-family:monospace;font-size:12px'>{html.escape(params)}"
            f"{' · body JSON' if r.get('body') else ''}</td>"
            f"<td style='font-family:monospace;font-size:12px;color:#475467'>{html.escape(r['source'])}<br>"
            f"{html.escape(r['locations'][0])}{more}</td></tr>")
    req_box = (f'<div class="box"><b>Yêu cầu HTTP trích từ mã</b> ({len(requests)} — phương thức + tên tham số, '
               f'dùng dẫn đường cho <code>apiscan dynamic</code>)<table style="margin-top:8px">'
               f'<tr><th>Yêu cầu</th><th>Tham số</th><th>Nguồn</th></tr>{''.join(req_rows)}</table></div>') if requests else ""
    sup_rows = "".join(
        f"<tr><td style='font-family:monospace;font-size:12px'>{html.escape(x['issue'].rule_id)}<br>"
        f"<span style='color:#98a2b3'>id {html.escape(x['issue'].fingerprint)}</span></td>"
        f"<td style='font-family:monospace;font-size:12px'>{html.escape(x['issue'].location)}</td>"
        f"<td style='font-size:12px'>{html.escape(x['reason'])}</td></tr>"
        for x in suppressed or [])
    sup_box = (f'<details class="box"><summary><b>Cảnh báo đã bỏ qua theo cấu hình</b> ({len(suppressed)})</summary>'
               f'<table style="margin-top:8px"><tr><th>Luật</th><th>Vị trí</th><th>Lý do</th></tr>{sup_rows}</table>'
               f'</details>') if suppressed else ""
    return f"""<!doctype html><html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Phân tích tĩnh — {html.escape(meta.get('app',''))}</title>
<style>body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f7f8fa;color:#1a2233;margin:0}}
.w{{max-width:1000px;margin:0 auto;padding:24px}}h1{{font-size:21px;margin:0 0 4px}}.s{{color:#667;font-size:14px;margin-bottom:14px}}
table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e4e7ec;border-radius:10px;overflow:hidden}}
th,td{{text-align:left;padding:8px 11px;border-bottom:1px solid #eef0f3;vertical-align:top}}th{{background:#eef2f7;font-size:13px}}
tr.g td{{background:#f0f4f9}}.box{{background:#fff;border:1px solid #e4e7ec;border-radius:10px;padding:12px 16px;margin:14px 0}}
.foot{{color:#98a2b3;font-size:12px;margin-top:16px}}</style></head><body><div class="w">
<h1>Báo cáo phân tích tĩnh Android — {html.escape(meta.get('app','—'))}</h1>
<div class="s">Phân tích CHỈ ĐỌC tệp APK · {len(issues)} cảnh báo{f" · {len(suppressed)} đã bỏ qua" if suppressed else ""} · {len(endpoints)} endpoint · {html.escape(meta.get('time',''))}</div>
<table><thead><tr><th>Mức / tin cậy</th><th>Cảnh báo</th><th>Vị trí</th><th>Bằng chứng / ghi chú</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
{sup_box}
{surf_box}
<div class="box"><b>Bản đồ endpoint phát hiện trong mã</b> (dùng định hướng kiểm thử có phép; bản thân chưa phải lỗ hổng)<ul>{eps}</ul></div>
{req_box}
<p class="foot">Công cụ dựa trên dấu hiệu tĩnh, có thể báo nhầm — mọi cảnh báo cần người kiểm tra xác minh theo tệp:dòng.
Công cụ không thực hiện tấn công và không gửi yêu cầu mạng tới máy chủ ứng dụng.</p></div></body></html>"""


def analyze(apktool_dir: str, jadx_dir: str, app_pkgs: list[str] | None = None,
            min_confidence: str = "low", disable: set[str] | None = None,
            suppress: list[dict] | None = None, export_rules: str = "v1") -> dict:
    """Chạy toàn bộ phân tích trên APK đã giải nén. app_pkgs rỗng → tự suy phạm vi mã từ Manifest.

    disable: mã luật bị tắt hẳn. suppress: các mục bỏ qua đã kiểm tra bằng apiscan_config.parse_config;
    cảnh báo khớp được chuyển sang result["suppressed"] kèm lý do, không tính vào result["issues"].
    export_rules: "v2" = bộ luật CFG-EXPORT thử nghiệm (holdout đợt 10): không hạ low chỉ vì mã có gọi API kiểm tra
    bên gọi (CVE-2021-43863 có gọi nhưng kiểm tra sai), và service nhận action tuỳ biến là cảnh báo.
    """
    import datetime
    manifest_pkg = guess_app_pkg(apktool_dir)
    scope = app_pkgs or infer_app_packages(apktool_dir, jadx_dir) or ([manifest_pkg] if manifest_pkg else [])
    scan_scope = scope[0] if len(scope) == 1 else scope
    man_issues, surface = scan_manifest(apktool_dir, collect_sent_actions(jadx_dir, scan_scope), export_rules)
    nsc_issues = scan_nsc(apktool_dir)
    raw_requests: list[dict] = []
    code_issues, endpoints = scan_code(jadx_dir, scan_scope, raw_requests)
    refine_export_confidence(man_issues, jadx_dir, export_rules)
    issues = assign_confidence(man_issues + nsc_issues + code_issues)
    for it in issues:
        it.fingerprint = apiscan_config.fingerprint(it)
    disabled = [i for i in issues if i.rule_id in (disable or ())]
    issues = [i for i in issues if i.rule_id not in (disable or ())]
    issues, suppressed, unmatched = apiscan_config.apply_suppressions(issues, suppress or [])
    shown = [i for i in issues if CONF_RANK[i.confidence] >= CONF_RANK[min_confidence]]
    meta = {"app": manifest_pkg or "?", "scope": scope,
            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}
    if min_confidence != "low":
        meta["min_confidence"] = min_confidence
    if disable:
        meta["disabled_rules"] = sorted(disable)
    if export_rules != "v1":
        meta["export_rules"] = export_rules
    return {"meta": meta, "issues": shown, "hidden": len(issues) - len(shown),
            "suppressed": suppressed, "disabled": len(disabled), "unmatched_suppressions": unmatched,
            "attack_surface": surface, "endpoints": endpoints,
            "requests": request_extract.merge_requests(raw_requests)}


def write_reports(result: dict, out_json: str, out_html: str) -> None:
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump({"meta": result["meta"], "issues": [asdict(i) for i in result["issues"]],
                   "suppressed": [dict(asdict(s["issue"]), suppress_reason=s["reason"])
                                  for s in result.get("suppressed", [])],
                   "attack_surface": result["attack_surface"], "endpoints": result["endpoints"],
                   "requests": result.get("requests", [])},
                  f, ensure_ascii=False, indent=2)
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(to_html(result["issues"], result["endpoints"], result["meta"], result["attack_surface"],
                        result.get("suppressed"), result.get("requests")))


def print_summary(result: dict) -> None:
    from collections import Counter
    issues, meta = result["issues"], result["meta"]
    print(f"Gói ứng dụng: {meta['app']}  |  phạm vi mã: {', '.join(meta['scope']) or '(toàn bộ)'}")
    print(f"Tổng cảnh báo: {len(issues)}  |  theo mức: {dict(Counter(i.severity for i in issues))}")
    print(f"Theo độ tin cậy: {dict(Counter(i.confidence for i in issues))}"
          + (f"  (đã lọc --min-confidence {meta['min_confidence']}: {result['hidden']} cảnh báo ẩn)"
             if meta.get("min_confidence") else ""))
    print(f"Theo OWASP: {dict(sorted(Counter(i.owasp for i in issues).items()))}")
    if result.get("suppressed") or result.get("disabled"):
        print(f"Bỏ qua theo cấu hình: {len(result.get('suppressed', []))} cảnh báo suppress, "
              f"{result.get('disabled', 0)} cảnh báo của luật bị tắt")
    for n in result.get("unmatched_suppressions", []):
        print(f"  Cảnh báo: mục suppress[{n}] không khớp cảnh báo nào — có thể đã lỗi thời hoặc gõ sai")
    print(f"Bề mặt tiếp nhận intent (không tính cảnh báo): {len(result['attack_surface'])}")
    print(f"Endpoint phát hiện: {len(result['endpoints'])}  |  yêu cầu HTTP trích từ mã: "
          f"{len(result.get('requests', []))}")


def main(argv=None):
    p = argparse.ArgumentParser(description="Phân tích cấu hình & mã tĩnh Android (chỉ đọc).")
    p.add_argument("--apktool", required=True, help="Thư mục apktool đã giải nén")
    p.add_argument("--jadx", required=True, help="Thư mục JADX đã dịch ngược")
    p.add_argument("--app-pkg", action="append", default=[],
                   help="Package mã của app (lặp lại được); để trống sẽ tự suy từ Manifest")
    p.add_argument("--out-json", default="static_result.json")
    p.add_argument("--out-html", default="static_result.html")
    p.add_argument("--min-confidence", choices=("low", "medium", "high"), default=None,
                   help="Chỉ xuất cảnh báo có độ tin cậy từ mức này trở lên (mặc định: tất cả)")
    p.add_argument("--config", help="Tệp cấu hình YAML (tắt luật, suppression, ngưỡng)")
    a = p.parse_args(argv)
    try:
        cfg = apiscan_config.load_config(a.config) if a.config else apiscan_config.parse_config(None)
    except apiscan_config.ConfigError as exc:
        sys.exit(f"Lỗi cấu hình: {exc}")
    pkgs = [x.strip() for v in a.app_pkg for x in v.split(",") if x.strip()] or cfg["app_pkg"]
    result = analyze(a.apktool, a.jadx, pkgs, a.min_confidence or cfg["min_confidence"] or "low",
                     cfg["disable"], cfg["suppress"])
    write_reports(result, a.out_json, a.out_html)
    print_summary(result)
    print(f"Đã ghi: {a.out_json}, {a.out_html}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
