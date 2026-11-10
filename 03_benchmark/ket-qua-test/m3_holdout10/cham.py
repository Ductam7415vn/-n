#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cham.py — Chấm holdout đợt 10 và số liệu tham khảo của bộ luật CFG-EXPORT v2.

    python3 cham.py holdout                  # 4 app holdout: v1/ v2/
    python3 cham.py tham_khao dev            # 19 app tập phát triển: tham_khao/dev_v1, dev_v2
    python3 cham.py tham_khao cve            # 5 bản lỗi của phép đo CVE: tham_khao/cve_v1, cve_v2

Ghép báo cáo với tệp nhãn theo SHA-256 của APK. Với mỗi cặp v1/v2 in ra: precision từng bản (mọi cảnh báo, ≥ medium,
chặt), cảnh báo đổi tầng tin cậy (thay đổi 1) và cảnh báo chỉ có ở v2 (thay đổi 2) kèm nhãn nếu đã có.
"""
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "04_code", "scripts"))
from test_groundtruth import match_label, split_location  # noqa: E402

GT_DIR = os.path.join(ROOT, "03_benchmark", "ground-truth")
RANK = {"high": 3, "medium": 2, "low": 1}


def labels_by_sha():
    out = {}
    for path in glob.glob(os.path.join(GT_DIR, "*_labels.json")):
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        if d.get("apk_sha256"):
            out[d["apk_sha256"]] = d
    return out


def reports(folder):
    out = {}
    for path in sorted(glob.glob(os.path.join(folder, "*", "report.json"))):
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        out[d["meta"]["apk_sha256"]] = d
    return out


def key(issue):
    return issue["rule_id"], split_location(issue["location"]), issue.get("evidence", "").strip()


def is_tp(lb, strict):
    return lb["label"] == "TP" and not (strict and lb.get("borderline"))


def pct(tp, n):
    return f"{tp / n * 100:.1f}% ({tp}/{n})" if n else "—"


def score(rep, gt):
    """Trả về danh sách (issue, nhãn hoặc None) cho một báo cáo."""
    labels = gt["labels"] if gt else []
    used, rows = set(), []
    for i in rep["issues"]:
        lb = match_label(i, labels, used)
        if lb is not None:
            used.add(id(lb))
        rows.append((i, lb))
    return rows


def summarize(name, rows):
    labeled = [(i, lb) for i, lb in rows if lb]
    med = [(i, lb) for i, lb in labeled if RANK.get(i.get("confidence"), 0) >= 2]
    unl = len(rows) - len(labeled)
    print(f"  {name}: {len(rows)} cảnh báo, chưa nhãn {unl}"
          f" | mọi cảnh báo {pct(sum(is_tp(lb, False) for _, lb in labeled), len(labeled))}"
          f" | chặt {pct(sum(is_tp(lb, True) for _, lb in labeled), len(labeled))}"
          f" | ≥ medium {pct(sum(is_tp(lb, False) for _, lb in med), len(med))}"
          f" | ≥ medium chặt {pct(sum(is_tp(lb, True) for _, lb in med), len(med))}")


def compare(dir_v1, dir_v2):
    gts = labels_by_sha()
    r1, r2 = reports(dir_v1), reports(dir_v2)
    all1, all2, retier, new, gone = [], [], [], [], []
    for sha in sorted(r1, key=lambda s: r1[s]["meta"]["app"]):
        gt = gts.get(sha)
        app = gt["app"] if gt else r1[sha]["meta"]["app"]
        s1, s2 = score(r1[sha], gt), score(r2[sha], gt)
        all1 += s1
        all2 += s2
        m1 = {key(i): (i, lb) for i, lb in s1}
        m2 = {key(i): (i, lb) for i, lb in s2}
        for k, (i, lb) in m2.items():
            if k not in m1:
                new.append((app, i, lb))
            elif m1[k][0].get("confidence") != i.get("confidence"):
                retier.append((app, m1[k][0].get("confidence"), i, lb))
        gone += [(app, i) for k, (i, _) in m1.items() if k not in m2]
    print(f"Số app: {len(r1)}")
    summarize("v1", all1)
    summarize("v2", all2)

    def label_text(lb):
        if not lb:
            return "chưa nhãn"
        return lb["label"] + (" (borderline)" if lb.get("borderline") else "")

    print(f"\nThay đổi 1 — cảnh báo đổi tầng tin cậy: {len(retier)}")
    for app, old, i, lb in retier:
        print(f"  {app}: {i['rule_id']} {i.get('evidence', '')[:70]} | {old} → {i.get('confidence')} | {label_text(lb)}")
    print(f"\nThay đổi 2 — cảnh báo chỉ có ở v2: {len(new)}")
    for app, i, lb in new:
        print(f"  {app}: {i['rule_id']} {i.get('evidence', '')[:70]} | {i.get('confidence')} | {label_text(lb)}")
    if gone:
        print(f"\nCảnh báo có ở v1 nhưng mất ở v2: {len(gone)}")
        for app, i in gone:
            print(f"  {app}: {i['rule_id']} {i.get('evidence', '')[:70]}")


def main():
    if sys.argv[1:] == ["holdout"]:
        compare(os.path.join(HERE, "v1"), os.path.join(HERE, "v2"))
    elif len(sys.argv) == 3 and sys.argv[1] == "tham_khao" and sys.argv[2] in ("dev", "cve"):
        base = os.path.join(HERE, "tham_khao", sys.argv[2])
        compare(base + "_v1", base + "_v2")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
