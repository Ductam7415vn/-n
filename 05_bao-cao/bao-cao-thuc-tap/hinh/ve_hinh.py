#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vẽ hai sơ đồ cho báo cáo thực tập: các giai đoạn công việc và quy trình kiểm tra bảo mật đề xuất.

Chạy: python3 05_bao-cao/bao-cao-thuc-tap/hinh/ve_hinh.py   (cần matplotlib)
"""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = os.path.dirname(os.path.abspath(__file__))
plt.rcParams.update({"font.family": "Times New Roman", "font.size": 12, "savefig.dpi": 200, "savefig.bbox": "tight"})
INK, PALE, WARM, MINT = "#1f2933", "#eef2f7", "#fff7ed", "#ecfdf5"


def canvas(w, h, xmax, ymax):
    fig, ax = plt.subplots(figsize=(w, h))
    ax.set_xlim(0, xmax), ax.set_ylim(0, ymax), ax.axis("off")

    def box(x, y, bw, bh, text, fc=PALE, size=10.5):
        ax.add_patch(FancyBboxPatch((x, y), bw, bh, boxstyle="round,pad=0.4,rounding_size=1.0", fc=fc, ec=INK, lw=1))
        ax.text(x + bw / 2, y + bh / 2, text, ha="center", va="center", fontsize=size, color=INK, linespacing=1.3)

    def arrow(x1, y1, x2, y2):
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=12, color=INK, lw=1))

    return fig, ax, box, arrow


def hinh_giai_doan():
    fig, ax, box, arrow = canvas(10, 3.4, 100, 34)
    top = ["1. Tìm hiểu\nOWASP, MASVS", "2. Dựng\nmôi trường", "3. Phân tích\nthủ công,\nbộ đáp án",
           "4. Xây dựng\napiscan"]
    bot = ["5. Đánh giá trên\nứng dụng thật,\ngiảm báo nhầm", "6. Đối chứng\nvới MobSF", "7. Kiểm thử hồi quy,\ntài liệu,\nbàn giao"]
    for i, t in enumerate(top):
        x = 2 + i * 25
        box(x, 20, 19, 11, t, MINT if i == 3 else PALE)
        if i:
            arrow(x - 5.6, 25.5, x, 25.5)
    for i, t in enumerate(bot):
        x = 77 - i * 25
        box(x, 2, 19, 12, t, WARM if i == 0 else PALE)
        if i:
            arrow(x + 25, 8, x + 19.6, 8)
    arrow(86.5, 19.6, 86.5, 14.4)
    ax.text(84.5, 16.6, "lặp lại theo từng đợt ứng dụng mới (9 đợt)", ha="right", fontsize=9.5, color=INK, style="italic")
    fig.savefig(os.path.join(OUT, "giai_doan_cong_viec.png"))
    plt.close(fig)


def hinh_quy_trinh():
    fig, ax, box, arrow = canvas(10, 3.0, 100, 30)
    box(1, 9, 14, 12, "Tệp APK\nbản phát hành", WARM)
    box(21, 9, 21, 12, "1. Sàng lọc tự động\napiscan (≥ medium)\n+ MobSF bổ sung")
    box(48, 9, 21, 12, "2. Rà soát theo tầng\ntin cậy; đối chiếu\nbản đồ endpoint")
    box(75, 9, 23, 12, "3. Kiểm thử động có\nkiểm soát (chỉ khi\nđược phép)", MINT)
    arrow(15.4, 15, 21, 15), arrow(42.4, 15, 48, 15), arrow(69.4, 15, 75, 15)
    ax.text(58.5, 3.5, "Cảnh báo đã xác nhận là nhầm → ghi lại để bổ sung luật hoặc cấu hình bỏ qua", ha="center",
            fontsize=10, color=INK, style="italic")
    fig.savefig(os.path.join(OUT, "quy_trinh_de_xuat.png"))
    plt.close(fig)


if __name__ == "__main__":
    hinh_giai_doan()
    hinh_quy_trinh()
    print("Đã vẽ 2 hình vào", OUT)
