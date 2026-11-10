#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vẽ các hình cho Chương 3. Số liệu lấy từ các lần chạy thật đã commit:
  - holdout từng đợt: test_output*.txt trong 03_benchmark/ket-qua-test/m1_* và m2_holdout*/; đợt 10: m3_holdout10/KET_QUA.md
  - tập phát triển tại thời điểm đóng băng mỗi đợt: docs/PROGRESS.md
  - phân tầng tin cậy 19 app: 03_benchmark/ket-qua-test/final/summary.txt

Chạy: python3 05_bao-cao/hinh/ve_hinh_chuong3.py   (cần matplotlib)
"""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = os.path.dirname(os.path.abspath(__file__))
plt.rcParams.update({"font.family": "Times New Roman", "font.size": 12, "axes.spines.top": False,
                     "axes.spines.right": False, "savefig.dpi": 200, "savefig.bbox": "tight"})
INK, GREY, BLUE, ORANGE, GREEN, RED = "#1f2933", "#9aa5b1", "#2563eb", "#ea580c", "#16a34a", "#dc2626"


def hinh_kien_truc():
    fig, ax = plt.subplots(figsize=(10, 4.6))
    ax.set_xlim(0, 100), ax.set_ylim(0, 46), ax.axis("off")

    def box(x, y, w, h, text, fc="#eef2f7"):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.2",
                                    fc=fc, ec=INK, lw=1))
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=10.5, color=INK, linespacing=1.3)

    def arrow(x1, y1, x2, y2):
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=12, color=INK, lw=1))

    box(1, 19, 11, 8, "Tệp APK\n(+ SHA-256)", "#fff7ed")
    box(17, 30, 15, 8, "apktool\nManifest, res/")
    box(17, 8, 15, 8, "JADX\nmã Java")
    box(37, 19, 15, 8, "Suy phạm vi mã\ncủa ứng dụng")
    box(57, 34, 18, 7, "Phân tích Manifest\n(exported, backup…)")
    box(57, 23.5, 18, 7, "Network security\nconfig (theo phạm vi)")
    box(57, 13, 18, 7, "Bộ luật mã nguồn\n+ lọc theo ngữ cảnh")
    box(57, 2.5, 18, 7, "Bản đồ endpoint\n+ bề mặt intent")
    box(80, 19, 18, 8, "Điểm tin cậy\ntừng cảnh báo\n→ HTML + JSON", "#ecfdf5")
    arrow(12, 24, 17, 33), arrow(12, 22, 17, 12)
    arrow(32, 34, 37, 25), arrow(32, 12, 37, 21)
    for y in (37.5, 27, 16.5, 6):
        arrow(52, 23, 57, y)
        arrow(75, y, 80, 23)
    fig.savefig(os.path.join(OUT, "hinh3_1_kien_truc.png"))
    plt.close(fig)


def hinh_holdout():
    rounds = list(range(1, 11))
    dev_all = [14.3, 35.7, 34.9, 35.0, 41.8, 39.8, 28.1, 16.7, 17.3, 17.2]
    hold_all = [18.2, 5.3, 15.3, 40.0, 31.8, 3.7, 2.8, 25.0, 14.3, 11.8]
    hold_n = [22, 169, 85, 25, 22, 54, 107, 16, 7, 17]
    conf_rounds = [6, 7, 8, 9, 10]
    dev_med = [53.1, 62.9, 39.5, 39.6, 39.1]
    hold_med = [3.8, 7.1, 30.8, 25.0, 15.4]

    fig, (a, b) = plt.subplots(1, 2, figsize=(11, 4.2), gridspec_kw={"width_ratios": [1.6, 1]})
    a.plot(rounds, dev_all, "-o", color=BLUE, label="Tập phát triển (tại thời điểm đóng băng)")
    a.plot(rounds, hold_all, "-s", color=ORANGE, label="Holdout (app mới, đo trước khi sửa luật)")
    a.axhline(50, ls="--", color=GREY, lw=1)
    a.text(10.2, 51, "mục tiêu 50%", fontsize=9, color=GREY, ha="right")
    a.set_xticks(rounds, [f"{r}\n(n={n})" for r, n in zip(rounds, hold_n)], fontsize=10)
    a.set_xlabel("Đợt holdout (n = số cảnh báo holdout)"), a.set_ylabel("Precision (%) — mọi cảnh báo")
    a.set_ylim(0, 70), a.legend(frameon=False, fontsize=9.5, loc="upper left")
    a.set_title("(a) Mọi cảnh báo", fontsize=12)

    b.plot(conf_rounds, dev_med, "-o", color=BLUE)
    b.plot(conf_rounds, hold_med, "-s", color=ORANGE)
    b.axhline(50, ls="--", color=GREY, lw=1)
    b.set_xticks(conf_rounds), b.set_xlabel("Đợt holdout"), b.set_ylabel("Precision (%) — tin cậy ≥ medium")
    b.set_ylim(0, 70), b.set_title("(b) Lọc tin cậy ≥ medium", fontsize=12)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "hinh3_3_holdout.png"))
    plt.close(fig)


def hinh_tang_tin_cay():
    tiers = ["high", "medium", "low"]
    dev_tp, dev_fp = [25, 29, 3], [6, 78, 190]
    hold_tp, hold_fp = [3, 5, 0], [6, 45, 71]
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for ax, tp, fp, title in ((axes[0], dev_tp, dev_fp, "(a) 19 ứng dụng thật — công cụ cuối"),
                              (axes[1], hold_tp, hold_fp, "(b) Gộp holdout đợt 7–9")):
        ax.bar(tiers, tp, color=GREEN, label="TP")
        ax.bar(tiers, fp, bottom=tp, color=GREY, label="FP")
        for x, t, f in zip(tiers, tp, fp):
            ax.text(x, t + f + 2, f"{t}/{t + f}\n({100 * t / (t + f):.1f}%)", ha="center", fontsize=9.5)
        ax.set_title(title, fontsize=12), ax.set_ylabel("Số cảnh báo"), ax.set_xlabel("Tầng tin cậy")
        ax.set_ylim(0, max(t + f for t, f in zip(tp, fp)) * 1.25)
    axes[0].legend(frameon=False)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "hinh3_4_tang_tin_cay.png"))
    plt.close(fig)


if __name__ == "__main__":
    hinh_kien_truc()
    hinh_holdout()
    hinh_tang_tin_cay()
    print("Đã vẽ:", sorted(f for f in os.listdir(OUT) if f.endswith(".png")))
