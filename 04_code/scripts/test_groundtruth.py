#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_groundtruth.py — Bài test tự chấm cho vòng lặp phát triển APIScan.

Khẳng định sau mỗi lần sửa công cụ:
  1) RECALL trên InsecureBankv2 = 100% trên 6 mục tĩnh của đáp án (ràng buộc cứng).
  2) PRECISION trên từng app tính từ NHÃN GÁN TAY (03_benchmark/ground-truth/*_labels.json):
     precision = TP / (TP + FP). Cảnh báo chưa có nhãn được báo riêng và cho ra
     khoảng [cận dưới, cận trên] thay vì đoán.
  3) Không được làm mất cảnh báo đã gán nhãn TP (lọc quá tay).

Cách dùng (sau khi đã chạy static_scan.py tạo các file JSON):
    python3 static_scan.py --apktool OUT_IB/apktool --jadx OUT_IB/jadx \
        --app-pkg com.android.insecurebankv2 --out-json ib.json
    python3 static_scan.py --apktool OUT_NP/apktool --jadx OUT_NP/jadx \
        --app-pkg org.schabi.newpipe --out-json np.json
    python3 test_groundtruth.py --ib-json ib.json --newpipe-json np.json
    # app khác: thêm --eval ketqua.json nhan.json (lặp lại được)

Mã thoát != 0 nếu recall InsecureBankv2 < 100% hoặc mất cảnh báo TP đã gán nhãn.
"""
import argparse
import json
import os
import sys

GT_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "..", "..", "03_benchmark", "ground-truth"))
IB_LABELS = os.path.join(GT_DIR, "insecurebankv2_labels.json")
NP_LABELS = os.path.join(GT_DIR, "newpipe_labels.json")

IB_PKG = "com/android/insecurebankv2/"
IB_EXPORTED = ("PostLogin", "DoTransfer", "ViewStatement", "ChangePassword",
               "TrackUserContentProvider", "MyBroadCastReceiver")


def _at(i, rule_ids, file_part="", evidence_part=""):
    return (i["rule_id"] in rule_ids and file_part in i["location"]
            and evidence_part in i.get("evidence", ""))


# Mỗi mục đáp án là hàm nhận TOÀN BỘ danh sách cảnh báo, để mục nhiều thành phần (V06)
# đòi đủ từng thành phần thay vì chỉ cần một cảnh báo bất kỳ cùng loại.
IB_GROUND_TRUTH = {
    "V01 khoá cứng": lambda xs: any(_at(i, ("CRY-KEYLIT",), "CryptoClass") for i in xs),
    "V02 cleartext": lambda xs: (any(_at(i, ("NET-SDK", "NET-CLEAR")) for i in xs)
                                 and all(any(_at(i, ("NET-HTTP",), IB_PKG + f) for i in xs)
                                         for f in ("DoLogin", "DoTransfer", "ChangePassword"))),
    "V05 mật mã yếu (IV)": lambda xs: any(_at(i, ("CRY-IV0", "CRY-WEAK"), "CryptoClass") for i in xs),
    "V06 exported": lambda xs: all(any(_at(i, ("CFG-EXPORT",), "", "insecurebankv2." + c) for i in xs)
                                   for c in IB_EXPORTED),
    "V07 cửa hậu devlogin": lambda xs: any(_at(i, ("API-HIDDEN",), "DoLogin", "/devlogin") for i in xs),
    "V11 allowBackup": lambda xs: any(_at(i, ("CFG-BACKUP",)) for i in xs),
}
# Đáp án xếp nhóm "Động" nhưng mã nguồn lộ dấu hiệu tĩnh: theo dõi, không bắt buộc.
IB_BONUS = {
    "V04 lưu trữ không an toàn": lambda xs: any(_at(i, ("STO-PREF-WORLD",), "MyBroadCastReceiver") for i in xs),
    "V10 rò rỉ qua log": lambda xs: any(_at(i, ("LOG-SENS",), "DoLogin", "password") for i in xs),
}


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)["issues"]


def split_location(loc):
    f, _, ln = loc.rpartition(":")
    return f if ln.isdigit() else loc


def same_evidence(a, b):
    a, b = a.strip(), b.strip()
    return bool(a and b) and (a.startswith(b) or b.startswith(a))


def match_label(issue, labels, used):
    f = split_location(issue["location"])
    cands = [lb for lb in labels
             if lb["rule_id"] == issue["rule_id"] and lb["file"] == f
             and same_evidence(lb["evidence"], issue.get("evidence", ""))]
    for lb in cands:
        if id(lb) not in used:
            return lb
    return cands[0] if cands else None


def evaluate_precision(name, issues, labels_path):
    with open(labels_path, encoding="utf-8") as f:
        labels = json.load(f)["labels"]
    tp = fp = 0
    unlabeled, used, scored = [], set(), []
    for i in issues:
        lb = match_label(i, labels, used)
        if lb is None:
            unlabeled.append(i)
            continue
        used.add(id(lb))
        scored.append((i.get("confidence", ""), lb["label"]))
        if lb["label"] == "TP":
            tp += 1
        else:
            fp += 1
    lost_tp = [lb for lb in labels if lb["label"] == "TP" and id(lb) not in used]
    gone_fp = sum(1 for lb in labels if lb["label"] == "FP" and id(lb) not in used)

    print(f"\n=== {name} — PRECISION (theo nhãn gán tay) ===")
    print(f"  Tổng cảnh báo: {len(issues)}  |  TP: {tp}  FP: {fp}  chưa gán nhãn: {len(unlabeled)}")
    if gone_fp:
        print(f"  Báo nhầm đã gán nhãn nay không còn xuất hiện: {gone_fp}")
    if tp + fp:
        print(f"  => Precision trên phần đã gán nhãn: {tp / (tp + fp) * 100:.1f}%  ({tp}/{tp + fp})")
    if unlabeled:
        n = len(issues)
        print(f"  => Khoảng precision nếu tính cả phần chưa nhãn: "
              f"{tp / n * 100:.1f}% – {(tp + len(unlabeled)) / n * 100:.1f}%")
        print("  CẦN GÁN NHÃN (thêm vào " + os.path.relpath(labels_path) + "):")
        for i in unlabeled:
            print(f"    - {i['rule_id']} {i['location']} | {i.get('evidence', '')[:90]}")
    for lb in lost_tp:
        print(f"  [MẤT TP] {lb['rule_id']} {lb['file']} | {lb['evidence'][:80]}")
    return lost_tp, tp, fp, len(unlabeled), scored


def print_confidence_breakdown(title, scored):
    """Precision theo từng mức tin cậy và cộng dồn (≥ mức) trên các cảnh báo đã gán nhãn."""
    if not scored or not any(c for c, _ in scored):
        return
    print(f"\n=== {title} — PRECISION THEO ĐỘ TIN CẬY ===")
    print("  mức      | riêng mức            | từ mức này trở lên")
    for level, floor in (("high", 3), ("medium", 2), ("low", 1)):
        rank = {"high": 3, "medium": 2, "low": 1}
        only = [lab for c, lab in scored if c == level]
        upto = [lab for c, lab in scored if rank.get(c, 0) >= floor]
        def fmt(xs):
            t = xs.count("TP")
            return f"{t / len(xs) * 100:5.1f}% ({t}/{len(xs)})" if xs else "   —"
        print(f"  {level:<8} | {fmt(only):<20} | {fmt(upto)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ib-json", required=True)
    ap.add_argument("--ib-labels", default=IB_LABELS)
    ap.add_argument("--newpipe-json")
    ap.add_argument("--newpipe-labels", default=NP_LABELS)
    ap.add_argument("--eval", nargs=2, action="append", default=[], metavar=("RESULT_JSON", "LABELS_JSON"),
                    help="Đo precision cho app khác từ file kết quả + file nhãn")
    a = ap.parse_args()

    ib = load(a.ib_json)
    print("=== InsecureBankv2 — RECALL (ràng buộc cứng = 100%) ===")
    missed = []
    for name, pred in IB_GROUND_TRUTH.items():
        hit = pred(ib)
        print(f"  [{'OK ' if hit else 'MISS'}] {name}")
        if not hit:
            missed.append(name)
    total = len(IB_GROUND_TRUTH)
    print(f"  => Recall tĩnh: {(total - len(missed)) / total * 100:.0f}%  ({total - len(missed)}/{total} mục tĩnh của đáp án)")
    for name, pred in IB_BONUS.items():
        print(f"  [{'+  ' if pred(ib) else '-  '}] (thêm) {name}")

    lost = evaluate_precision("InsecureBankv2", ib, a.ib_labels)[0]
    real_scored = []
    runs = list(a.eval)
    if a.newpipe_json:
        runs.insert(0, (a.newpipe_json, a.newpipe_labels))
    real = []
    for result_json, labels_json in runs:
        with open(labels_json, encoding="utf-8") as f:
            app = json.load(f).get("app", result_json)
        lost_tp, tp, fp, unl, scored = evaluate_precision(app, load(result_json), labels_json)
        lost += lost_tp
        real_scored += scored
        real.append((app, tp, fp, unl))

    if len(real) > 1:
        tp, fp, unl = (sum(r[i] for r in real) for i in (1, 2, 3))
        print(f"\n=== TỔNG {len(real)} APP THẬT ({', '.join(r[0] for r in real)}) ===")
        print(f"  TP: {tp}  FP: {fp}  chưa gán nhãn: {unl}")
        if tp + fp:
            print(f"  => Precision gộp (micro): {tp / (tp + fp) * 100:.1f}%  ({tp}/{tp + fp})")
            per_app = [r[1] / (r[1] + r[2]) for r in real if r[1] + r[2]]
            print(f"  => Precision trung bình theo app (macro): {sum(per_app) / len(per_app) * 100:.1f}%")
    print_confidence_breakdown(f"{len(real)} APP THẬT" if len(real) > 1 else (real[0][0] if real else ""), real_scored)

    failed = False
    if missed:
        print(f"\nFAIL: recall InsecureBankv2 < 100% (thiếu: {missed})")
        failed = True
    if lost:
        print(f"\nFAIL: mất {len(lost)} cảnh báo đã gán nhãn TP (lọc quá tay).")
        failed = True
    if failed:
        return 1
    print("\nPASS: recall InsecureBankv2 = 100%, không mất TP đã gán nhãn.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
