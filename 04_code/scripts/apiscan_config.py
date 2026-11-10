# -*- coding: utf-8 -*-
"""
Cấu hình YAML và cơ chế bỏ qua cảnh báo (suppression) cho apiscan.

Ví dụ `apiscan.yml`:

    min_confidence: medium
    app_pkg: [com.example.app]
    rules:
      disable: [CRY-HASH]
    suppress:
      - id: 3fa2c1d9e0ab                 # dấu vân tay in trong báo cáo
        reason: "Khoá công khai của Google Play, không phải bí mật"
      - rule: CFG-EXPORT
        evidence: "*.ShareReceiverActivity*"
        reason: "Nhận intent SEND từ app khác — chức năng chính"

Một mục suppress khớp khi MỌI trường đã ghi đều khớp (`location`, `evidence` là glob). Cảnh báo bị bỏ qua
không biến mất: báo cáo vẫn đếm và liệt kê kèm lý do, để người rà soát thấy được đã bỏ qua những gì.
"""
import fnmatch
import hashlib
import re

CONFIDENCE_LEVELS = ("low", "medium", "high")
TOP_KEYS = {"min_confidence", "app_pkg", "rules", "suppress"}
RULES_KEYS = {"disable"}
SUPPRESS_KEYS = {"id", "rule", "location", "evidence", "reason"}
MATCH_KEYS = ("id", "rule", "location", "evidence")
LINE_SUFFIX = re.compile(r":\d+$")


class ConfigError(ValueError):
    pass


def fingerprint(issue) -> str:
    """Định danh ổn định của cảnh báo: bỏ số dòng để không đổi khi mã xung quanh dịch chuyển."""
    loc = LINE_SUFFIX.sub("", issue.location)
    raw = "\x1f".join((issue.rule_id, loc, " ".join(issue.evidence.split())))
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


def _str_list(value, where: str) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(x, str) and x.strip() for x in value):
        raise ConfigError(f"{where}: cần một chuỗi hoặc danh sách chuỗi")
    return [x.strip() for x in value]


def parse_config(data) -> dict:
    """Kiểm tra và chuẩn hoá cấu hình đã đọc từ YAML; báo lỗi rõ ràng thay vì bỏ qua khoá gõ sai."""
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError("tệp cấu hình phải là một mapping YAML")
    unknown = set(data) - TOP_KEYS
    if unknown:
        raise ConfigError(f"khoá không hỗ trợ: {', '.join(sorted(unknown))} (hỗ trợ: {', '.join(sorted(TOP_KEYS))})")

    cfg = {"min_confidence": None, "app_pkg": [], "disable": set(), "suppress": []}
    if "min_confidence" in data:
        if data["min_confidence"] not in CONFIDENCE_LEVELS:
            raise ConfigError(f"min_confidence phải là một trong {', '.join(CONFIDENCE_LEVELS)}")
        cfg["min_confidence"] = data["min_confidence"]
    if "app_pkg" in data:
        cfg["app_pkg"] = _str_list(data["app_pkg"], "app_pkg")

    rules = data.get("rules") or {}
    if not isinstance(rules, dict) or set(rules) - RULES_KEYS:
        raise ConfigError("rules: chỉ hỗ trợ khoá 'disable'")
    if "disable" in rules:
        cfg["disable"] = {r.upper() for r in _str_list(rules["disable"], "rules.disable")}

    entries = data.get("suppress") or []
    if not isinstance(entries, list):
        raise ConfigError("suppress: cần một danh sách")
    for n, e in enumerate(entries, 1):
        where = f"suppress[{n}]"
        if not isinstance(e, dict):
            raise ConfigError(f"{where}: cần một mapping")
        bad = set(e) - SUPPRESS_KEYS
        if bad:
            raise ConfigError(f"{where}: khoá không hỗ trợ: {', '.join(sorted(bad))}")
        if not any(k in e for k in MATCH_KEYS):
            raise ConfigError(f"{where}: cần ít nhất một trong {', '.join(MATCH_KEYS)}")
        if not str(e.get("reason") or "").strip():
            raise ConfigError(f"{where}: cần 'reason' — lý do bỏ qua phải được ghi lại")
        entry = {k: str(e[k]).strip() for k in e}
        if "rule" in entry:
            entry["rule"] = entry["rule"].upper()
        cfg["suppress"].append(entry)
    return cfg


def load_config(path: str) -> dict:
    try:
        import yaml
    except ImportError as exc:
        raise ConfigError("cần PyYAML để đọc tệp cấu hình (pip install pyyaml)") from exc
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except OSError as exc:
        raise ConfigError(f"không đọc được {path}: {exc.strerror}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} không phải YAML hợp lệ: {exc}") from exc
    try:
        return parse_config(data)
    except ConfigError as exc:
        raise ConfigError(f"{path}: {exc}") from exc


def _matches(entry: dict, issue) -> bool:
    if "id" in entry and entry["id"] != issue.fingerprint:
        return False
    if "rule" in entry and entry["rule"] != issue.rule_id:
        return False
    if "location" in entry and not fnmatch.fnmatchcase(issue.location, entry["location"]):
        return False
    if "evidence" in entry and not fnmatch.fnmatchcase(issue.evidence, entry["evidence"]):
        return False
    return True


def apply_suppressions(issues: list, entries: list[dict]) -> tuple[list, list[dict], list[int]]:
    """Tách cảnh báo bị bỏ qua. Trả (giữ lại, [{issue, reason}], số thứ tự các mục không khớp cảnh báo nào)."""
    kept, suppressed, hits = [], [], [0] * len(entries)
    for issue in issues:
        for n, entry in enumerate(entries):
            if _matches(entry, issue):
                hits[n] += 1
                suppressed.append({"issue": issue, "reason": entry["reason"]})
                break
        else:
            kept.append(issue)
    return kept, suppressed, [n + 1 for n, h in enumerate(hits) if not h]


def baseline_yaml(report: dict) -> str:
    """Sinh tệp cấu hình bỏ qua mọi cảnh báo hiện có của một report.json, để chỉ thấy cảnh báo MỚI ở lần sau."""
    lines = ["# Baseline sinh từ báo cáo apiscan — rà từng mục, sửa 'reason' cho đúng thực tế.",
             f"# App: {report['meta'].get('app', '?')}  SHA-256: {report['meta'].get('apk_sha256', '?')}",
             "suppress:"]
    for i in report["issues"]:
        lines.append(f"  - id: {i['fingerprint']}  # {i['rule_id']} {i['location']}")
        lines.append('    reason: "baseline — chưa rà soát"')
    if not report["issues"]:
        lines[-1] = "suppress: []"
    return "\n".join(lines) + "\n"
