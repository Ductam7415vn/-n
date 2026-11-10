#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Đối chứng apiscan với MobSF trên cùng 19 app thật và cùng định nghĩa TP/FP.

Đơn vị cảnh báo của MobSF: mỗi cặp (luật, file) ở phần mã, mỗi mục manifest, mỗi mục network security config và
mỗi mục chứng chỉ; chỉ tính mức high/warning (mức info/secure/good là thông tin, MobSF không xếp là cảnh báo).

Chạy (từ thư mục gốc đồ án):
    python3 04_code/scripts/compare_mobsf.py summary
    python3 04_code/scripts/compare_mobsf.py sample -n 100 --seed 42 > mau.json   # mẫu ngẫu nhiên để gán nhãn
    python3 04_code/scripts/compare_mobsf.py eval 03_benchmark/ground-truth/mobsf_sample_labels.json
"""
import argparse
import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.dirname(__file__))
import test_groundtruth as tg  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RES = os.path.join(ROOT, "03_benchmark", "ket-qua-test")
GT = os.path.join(ROOT, "03_benchmark", "ground-truth")

APPS = [
    ("np", "newpipe", "org.schabi.newpipe_1015"),
    ("tu", "tusky", "com.keylesspalace.tusky_142"),
    ("k9", "k9mail", "com.fsck.k9_39045"),
    ("ap", "antennapod", "de.danoeh.antennapod_3120295"),
    ("nc_scope", "nextcloud", "com.nextcloud.client_350000090"),
    ("cv", "conversations", "eu.siacs.conversations_4218104"),
    ("jf", "jellyfin", "org.jellyfin.mobile_2070399"),
    ("dx", "davx5", "at.bitfire.davdroid_405200005"),
    ("fd", "feeder", "com.nononsenseapps.feeder_4113"),
    ("ag", "aegis", "com.beemdevelopment.aegis_82"),
    ("rr", "redreader", "org.quantumbadger.redreader_118"),
    ("kp", "keepassdx", "com.kunzisoft.keepass.libre_45500"),
    ("bw", "breezyweather", "org.breezyweather_60202"),
    ("gb", "gadgetbridge", "nodomain.freeyourgadget.gadgetbridge_253"),
    ("wp", "wikipedia", "org.wikipedia_50606"),
    ("briar", "briar", "org.briarproject.briar.android_10521"),
    ("mmex", "mmex", "com.money.manager.ex_1118"),
    ("termux", "termux", "com.termux_1002"),
    ("catima", "catima", "me.hackerchick.catima_1004"),
]
ALERT = ("high", "warning")

CODE_RULES_FOR = {
    "CRY-KEYLIT": ("android_hardcoded", "hardcoded_api_key", "android_aes_key"),
    "CRY-KEYHARD": ("android_hardcoded", "hardcoded_api_key", "android_aes_key"),
    "STO-EXT": ("android_read_write_external",),
    "LOG-SENS": ("android_logging",),
    "WEB-IFACE": ("android_webview",),
    "WEB-JS": ("android_webview", "android_webview_allow_file_from_url"),
    "CRY-HASH": ("android_md5", "android_sha1"),
    "NET-HTTP": (),
}


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def in_scope(name, scope):
    return any(name == p or name.startswith(p + ".") for p in scope)


def mobsf_units(report, scope):
    """Mọi mục MobSF báo (kể cả info) dưới dạng danh sách đơn vị phẳng."""
    units = []
    for rule, v in report["code_analysis"]["findings"].items():
        sev = v["metadata"]["severity"]
        for path, lines in v["files"].items():
            cls = path[:-5].replace("/", ".") if path.endswith(".java") else path
            units.append({"source": "code", "rule": rule, "severity": sev, "location": path, "lines": lines,
                          "title": v["metadata"]["description"], "in_scope": in_scope(cls, scope)})
    for f in report["manifest_analysis"]["manifest_findings"]:
        comp = next((c for c in f.get("component", []) if "." in c and " " not in c), "")
        units.append({"source": "manifest", "rule": f["rule"], "severity": f["severity"], "location": comp,
                      "title": f["title"], "in_scope": not comp or in_scope(comp, scope)})
    for f in report["network_security"]["network_findings"]:
        units.append({"source": "network", "rule": "nsc", "severity": f["severity"],
                      "location": ",".join(f.get("scope", [])), "title": f["description"], "in_scope": True})
    for sev, desc, title in report["certificate_analysis"]["certificate_findings"]:
        units.append({"source": "certificate", "rule": title, "severity": sev, "location": "",
                      "title": desc, "in_scope": True})
    return units


def apiscan_tps(key, label_name):
    issues = load_json(os.path.join(RES, "final", f"{key}.json"))["issues"]
    labels = load_json(os.path.join(GT, f"{label_name}_labels.json"))["labels"]
    used, tps = set(), []
    for i in issues:
        lb = tg.match_label(i, labels, used)
        if lb:
            used.add(id(lb))
            if lb["label"] == "TP":
                tps.append(i)
    return issues, tps


def covers(issue, units, report):
    """Mức MobSF báo điểm yếu mà apiscan đã xác nhận là TP: 'alert' (high/warning), 'info', hoặc None."""
    rid, ev = issue["rule_id"], issue.get("evidence", "")
    f = tg.split_location(issue["location"])
    if rid == "CFG-BACKUP":
        hits = [u for u in units if u["rule"] == "app_allowbackup"]
    elif rid == "CFG-EXPORT":
        hits = [u for u in units if u["source"] == "manifest" and u["location"] == ev]
    elif rid == "NET-CLEAR":
        hits = [u for u in units if u["source"] == "manifest" and "usesCleartextTraffic" in u["title"]]
    elif rid == "NET-NSC":
        hits = [u for u in units if u["source"] == "network" and "clear text" in u["title"].lower()]
    elif rid == "NET-TRUST":
        hits = [u for u in units if u["source"] == "network" and "user installed" in u["title"].lower()]
    else:
        rules = CODE_RULES_FOR.get(rid, ())
        hits = [u for u in units if u["source"] == "code" and u["location"] == f and u["rule"] in rules]
        if not hits and rid.startswith("CRY-KEY") and '"' in ev:
            literal = ev.split('"')[1]
            if literal and any(literal in s for s in report.get("secrets", [])):
                return "info"
        if not hits and rid == "NET-HTTP":
            if any(e.get("path") == f and any(x.startswith("http://") for x in e.get("urls", []))
                   for e in report.get("urls", [])):
                return "info"
    if any(u["severity"] in ALERT for u in hits):
        return "alert"
    return "info" if hits else None


def all_alerts():
    for key, label_name, mobsf_name in APPS:
        path = os.path.join(RES, "mobsf", f"{mobsf_name}.json")
        if not os.path.exists(path):
            continue
        scope = load_json(os.path.join(RES, "final", f"{key}.json"))["meta"]["scope"]
        report = load_json(path)
        units = mobsf_units(report, scope)
        yield key, label_name, mobsf_name, report, units


def cmd_summary(_):
    tot = {"rules": 0, "alerts": 0, "scope": 0, "info": 0, "secrets": 0, "api": 0, "api_tp": 0,
           "cov_alert": 0, "cov_info": 0, "sec": []}
    missed = []
    print(f"{'app':<14}{'MobSF rule':>11}{'MobSF đv':>10}{'trong pv':>10}{'info':>7}{'secrets':>9}"
          f"{'apiscan':>9}{'TP':>5}{'MobSF phủ':>11}{'giây':>7}")
    for key, label_name, _, report, units in all_alerts():
        alerts = [u for u in units if u["severity"] in ALERT]
        n_rules = len({(u["source"], u["rule"]) for u in alerts})
        issues, tps = apiscan_tps(key, label_name)
        cov = [covers(i, units, report) for i in tps]
        for i, c in zip(tps, cov):
            if c != "alert":
                missed.append((label_name, i["rule_id"], i["location"], c or "không"))
        row = {"rules": n_rules, "alerts": len(alerts), "scope": sum(u["in_scope"] for u in alerts),
               "info": sum(u["severity"] == "info" for u in units), "secrets": len(report.get("secrets", [])),
               "api": len(issues), "api_tp": len(tps), "cov_alert": cov.count("alert"), "cov_info": cov.count("info")}
        for k, v in row.items():
            tot[k] += v
        sec = report["_apiscan_meta"]["seconds"]
        tot["sec"].append(sec)
        print(f"{label_name:<14}{row['rules']:>11}{row['alerts']:>10}{row['scope']:>10}{row['info']:>7}"
              f"{row['secrets']:>9}{row['api']:>9}{row['api_tp']:>5}{row['cov_alert']:>8}/{row['api_tp']:<2}{sec:>7.0f}")
    secs = sorted(tot["sec"])
    print(f"{'TỔNG':<14}{tot['rules']:>11}{tot['alerts']:>10}{tot['scope']:>10}{tot['info']:>7}{tot['secrets']:>9}"
          f"{tot['api']:>9}{tot['api_tp']:>5}{tot['cov_alert']:>8}/{tot['api_tp']:<2}")
    if secs:
        print(f"Thời gian MobSF/app: trung vị {secs[len(secs) // 2]:.0f} s, lớn nhất {secs[-1]:.0f} s "
              f"(gồm upload + giải nén + phân tích, có cache giải nén nếu đã quét)")
    print(f"TP của apiscan được MobSF báo ở mức high/warning: {tot['cov_alert']}/{tot['api_tp']}; "
          f"chỉ ở mức info/secrets: {tot['cov_info']}")
    print("TP của apiscan MobSF không báo ở mức cảnh báo:")
    for m in missed:
        print("   ", *m)


def cmd_sample(a):
    pool = []
    for _, label_name, _, _, units in all_alerts():
        for u in units:
            if u["severity"] in ALERT:
                pool.append({"app": label_name, **{k: u[k] for k in ("source", "rule", "severity", "location",
                                                                     "title", "in_scope")},
                             **({"lines": u["lines"]} if "lines" in u else {})})
    rnd = random.Random(a.seed)
    sample = rnd.sample(pool, min(a.n, len(pool)))
    json.dump({"pool_size": len(pool), "seed": a.seed, "n": len(sample), "units": sample},
              sys.stdout, ensure_ascii=False, indent=1)


def wilson(k, n, z=1.96):
    if not n:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h


def cmd_eval(a):
    d = load_json(a.labels)
    units = d["units"]
    groups = {"tất cả": units, "trong phạm vi app": [u for u in units if u["in_scope"]],
              "ngoài phạm vi (thư viện)": [u for u in units if not u["in_scope"]]}
    for src in ("code", "manifest", "network", "certificate"):
        groups[f"nguồn {src}"] = [u for u in units if u["source"] == src]
    print(f"Mẫu {len(units)}/{d['pool_size']} đơn vị cảnh báo MobSF (seed {d['seed']})")
    for name, us in groups.items():
        if not us:
            continue
        k = sum(u["label"] == "TP" for u in us)
        strict = sum(u["label"] == "TP" and not u.get("borderline") for u in us)
        lo, hi = wilson(k, len(us))
        print(f"  {name:<26} TP {k:>3}/{len(us):<3} = {k / len(us) * 100:5.1f}%  KTC95% [{lo * 100:.1f}; "
              f"{hi * 100:.1f}]%  chặt {strict / len(us) * 100:.1f}%")
    by_rule = {}
    for u in units:
        r = by_rule.setdefault(u["rule"], [0, 0])
        r[0] += u["label"] == "TP"
        r[1] += 1
    print("Theo luật MobSF (TP/mẫu):")
    for rule, (k, n) in sorted(by_rule.items(), key=lambda x: -x[1][1]):
        print(f"  {rule:<44}{k:>3}/{n}")


def main(argv=None):
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("summary")
    s = sub.add_parser("sample")
    s.add_argument("-n", type=int, default=100)
    s.add_argument("--seed", type=int, default=42)
    e = sub.add_parser("eval")
    e.add_argument("labels")
    a = p.parse_args(argv)
    {"summary": cmd_summary, "sample": cmd_sample, "eval": cmd_eval}[a.cmd](a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
