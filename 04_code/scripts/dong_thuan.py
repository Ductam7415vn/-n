#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Đo độ đồng thuận gán nhãn giữa người gán thứ hai và bộ nhãn của đồ án (Cohen's kappa).

    # 1) Tạo phiếu: lấy mẫu cảnh báo (phân tầng TP/FP), kèm đoạn mã ngữ cảnh, ẩn nhãn gốc
    python3 dong_thuan.py make --reports 03_benchmark/ket-qua-test/batch_20apk --work-dir <thư mục giải nén> \\
        --out 03_benchmark/ground-truth/dong_thuan --tp 30 --fp 50
    # 2) Đưa người gán thứ hai: HUONG_DAN.md + phieu_gan_nhan.html + phieu_gan_nhan.csv (KHÔNG đưa dap_an_an.json)
    # 3) Chấm
    python3 dong_thuan.py score --out 03_benchmark/ground-truth/dong_thuan --filled phieu_da_dien.csv

--work-dir là nơi `apiscan` đã giải nén các APK (thư mục con theo 16 ký tự đầu SHA-256), để lấy đoạn mã ngữ cảnh.
"""
import argparse
import csv
import glob
import html
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_groundtruth as gt  # noqa: E402

GT_DIR = os.path.normpath(os.path.join(HERE, "..", "..", "03_benchmark", "ground-truth"))
CONTEXT = 6
FIELDS = ("item", "app", "rule_id", "title", "location", "evidence", "label", "fp_type", "borderline", "reason")


def labels_by_sha() -> dict:
    out = {}
    for path in glob.glob(os.path.join(GT_DIR, "*_labels.json")):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if "apk_sha256" in data and "labels" in data:
            out[data["apk_sha256"]] = (data.get("app", os.path.basename(path)), data["labels"])
    return out


def snippet(work_dir: str, sha: str, location: str) -> str:
    base = os.path.join(work_dir, sha[:16])
    path, _, line = location.rpartition(":")
    if not line.isdigit():
        return ""
    candidates = [os.path.join(base, "apktool", path), os.path.join(base, "jadx", "sources", path)]
    src = next((c for c in candidates if os.path.isfile(c)), None)
    if not src:
        return ""
    with open(src, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    n = int(line)
    lo, hi = max(1, n - CONTEXT), min(len(lines), n + CONTEXT)
    return "\n".join(f"{'>' if i == n else ' '}{i:5d}  {lines[i - 1]}" for i in range(lo, hi + 1))


def cmd_make(a) -> int:
    known = labels_by_sha()
    pool = []
    for rep in sorted(glob.glob(os.path.join(a.reports, "*", "report.json"))):
        with open(rep, encoding="utf-8") as f:
            data = json.load(f)
        sha = data["meta"].get("apk_sha256")
        if sha not in known or data["meta"].get("app") == "com.android.insecurebankv2":
            continue
        app, labels = known[sha]
        used = set()
        for issue in data["issues"]:
            lb = gt.match_label(issue, labels, used)
            if lb is None:
                continue
            used.add(id(lb))
            pool.append({"app": app, "sha": sha, "issue": issue, "label": lb})
    rng = random.Random(a.seed)
    tps = [p for p in pool if p["label"]["label"] == "TP"]
    fps = [p for p in pool if p["label"]["label"] == "FP"]
    if len(tps) < a.tp or len(fps) < a.fp:
        sys.exit(f"Không đủ mẫu: có {len(tps)} TP, {len(fps)} FP")
    sample = rng.sample(tps, a.tp) + rng.sample(fps, a.fp)
    rng.shuffle(sample)

    os.makedirs(a.out, exist_ok=True)
    key, cards = [], []
    with open(os.path.join(a.out, "phieu_gan_nhan.csv"), "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for n, s in enumerate(sample, 1):
            i = s["issue"]
            item = f"M{n:03d}"
            w.writerow({"item": item, "app": s["app"], "rule_id": i["rule_id"], "title": i["title"],
                        "location": i["location"], "evidence": i.get("evidence", "")})
            key.append({"item": item, "app": s["app"], "rule_id": i["rule_id"], "location": i["location"],
                        "confidence": i.get("confidence"), "label": s["label"]["label"],
                        "fp_type": s["label"].get("fp_type", ""), "borderline": bool(s["label"].get("borderline")),
                        "reason": s["label"].get("reason", "")})
            code = snippet(a.work_dir, s["sha"], i["location"]) if a.work_dir else ""
            cards.append(f"<section><h2>{item} · {html.escape(s['app'])} · <code>{html.escape(i['rule_id'])}</code></h2>"
                         f"<p><b>{html.escape(i['title'])}</b><br><code>{html.escape(i['location'])}</code></p>"
                         f"<p class='ev'>{html.escape(i.get('evidence', ''))}</p>"
                         + (f"<pre>{html.escape(code)}</pre>" if code else
                            "<p class='m'>Không có đoạn mã kèm theo — mở APK đã dịch ngược để xem.</p>")
                         + (f"<p class='m'>Ghi chú của công cụ: {html.escape(i['note'])}</p>" if i.get("note") else "")
                         + "</section>")
    with open(os.path.join(a.out, "dap_an_an.json"), "w", encoding="utf-8") as f:
        json.dump({"seed": a.seed, "tp": a.tp, "fp": a.fp, "pool_tp": len(tps), "pool_fp": len(fps), "items": key},
                  f, ensure_ascii=False, indent=2)
    with open(os.path.join(a.out, "phieu_gan_nhan.html"), "w", encoding="utf-8") as f:
        f.write(f"""<!doctype html><html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Phiếu gán nhãn apiscan</title>
<style>body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f7f8fa;color:#1a2233;margin:0}}
main{{max-width:1000px;margin:0 auto;padding:24px}}section{{background:#fff;border:1px solid #e4e7ec;border-radius:10px;
padding:12px 16px;margin:12px 0}}h2{{font-size:16px;margin:0 0 6px}}pre{{background:#0f172a;color:#e2e8f0;padding:10px;
border-radius:8px;overflow-x:auto;font-size:12px}}.ev{{font-family:monospace;font-size:12px;color:#475467}}
.m{{color:#667;font-size:13px}}</style></head><body><main>
<h1>Phiếu gán nhãn độc lập — {len(sample)} cảnh báo</h1>
<p>Đọc <b>HUONG_DAN.md</b> trước. Điền nhãn vào <b>phieu_gan_nhan.csv</b> (cột label, fp_type, borderline, reason).
Thứ tự đã xáo trộn; tỉ lệ TP/FP trong phiếu không phản ánh tỉ lệ thật.</p>
{''.join(cards)}</main></body></html>""")
    print(f"Đã tạo {len(sample)} mục ({a.tp} TP + {a.fp} FP theo nhãn gốc, từ {len(tps)} TP / {len(fps)} FP) → {a.out}")
    return 0


def kappa(pairs: list[tuple[str, str]]) -> float:
    n = len(pairs)
    cats = sorted({x for p in pairs for x in p})
    po = sum(a == b for a, b in pairs) / n
    pe = sum((sum(a == c for a, _ in pairs) / n) * (sum(b == c for _, b in pairs) / n) for c in cats)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def cmd_score(a) -> int:
    with open(os.path.join(a.out, "dap_an_an.json"), encoding="utf-8") as f:
        key = {k["item"]: k for k in json.load(f)["items"]}
    with open(a.filled, encoding="utf-8-sig", newline="") as f:
        filled = {r["item"]: r for r in csv.DictReader(f)}
    pairs, strict, diffs, missing = [], [], [], []
    for item, k in key.items():
        lab = (filled.get(item, {}).get("label") or "").strip().upper()
        if lab not in ("TP", "FP"):
            missing.append(item)
            continue
        pairs.append((k["label"], lab))
        borderline2 = (filled[item].get("borderline") or "").strip().lower() in ("1", "x", "yes", "có", "true")
        strict.append(("FP" if k["borderline"] else k["label"], "FP" if borderline2 else lab))
        if k["label"] != lab:
            diffs.append((item, k, filled[item]))
    if not pairs:
        sys.exit("Chưa có mục nào được điền nhãn TP/FP")
    rng = random.Random(42)
    boots = sorted(kappa([rng.choice(pairs) for _ in pairs]) for _ in range(2000))
    agree = sum(x == y for x, y in pairs)
    print(f"Số mục chấm: {len(pairs)}/{len(key)}" + (f" (thiếu: {', '.join(missing)})" if missing else ""))
    print(f"Đồng ý: {agree}/{len(pairs)} = {agree / len(pairs):.1%}")
    print(f"Cohen's kappa: {kappa(pairs):.3f} (bootstrap 95%: {boots[50]:.3f}–{boots[1949]:.3f})")
    print(f"Kappa chặt (borderline → FP ở cả hai phía): {kappa(strict):.3f}")
    for g in ("TP", "FP"):
        sub = [p for p in pairs if p[0] == g]
        if sub:
            print(f"  Nhãn gốc {g}: người gán 2 đồng ý {sum(x == y for x, y in sub)}/{len(sub)}")
    print("\nBất đồng:")
    for item, k, r in diffs:
        print(f"  {item} {k['app']} {k['rule_id']} {k['location']}: gốc {k['label']} — người 2 {r['label']}"
              f"\n      gốc: {k['reason'][:160]}\n      người 2: {(r.get('reason') or '')[:160]}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0].strip())
    sub = p.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("make")
    m.add_argument("--reports", required=True, help="Thư mục kết quả apiscan batch")
    m.add_argument("--work-dir", help="Thư mục giải nén của apiscan, để kèm đoạn mã")
    m.add_argument("--out", required=True)
    m.add_argument("--tp", type=int, default=30)
    m.add_argument("--fp", type=int, default=50)
    m.add_argument("--seed", type=int, default=42)
    m.set_defaults(func=cmd_make)
    s = sub.add_parser("score")
    s.add_argument("--out", required=True, help="Thư mục chứa dap_an_an.json")
    s.add_argument("--filled", required=True, help="CSV người gán thứ hai đã điền")
    s.set_defaults(func=cmd_score)
    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
