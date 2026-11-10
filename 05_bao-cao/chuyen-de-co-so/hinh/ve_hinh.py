#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vẽ các hình cho báo cáo chuyên đề cơ sở. Số liệu Hình 3.2 lấy từ ../ket_qua_tim_mau.txt (thuc_nghiem_tim_mau.py).

Chạy: python3 05_bao-cao/chuyen-de-co-so/hinh/ve_hinh.py   (cần matplotlib)
"""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = os.path.dirname(os.path.abspath(__file__))
plt.rcParams.update({"font.family": "Times New Roman", "font.size": 12, "axes.spines.top": False,
                     "axes.spines.right": False, "savefig.dpi": 200, "savefig.bbox": "tight"})
INK, BLUE, ORANGE, GREEN, PALE, WARM, MINT = "#1f2933", "#2563eb", "#ea580c", "#16a34a", "#eef2f7", "#fff7ed", "#ecfdf5"


def canvas(w, h, xmax, ymax):
    fig, ax = plt.subplots(figsize=(w, h))
    ax.set_xlim(0, xmax), ax.set_ylim(0, ymax), ax.axis("off")

    def box(x, y, bw, bh, text, fc=PALE, size=10.5):
        ax.add_patch(FancyBboxPatch((x, y), bw, bh, boxstyle="round,pad=0.4,rounding_size=1.0", fc=fc, ec=INK, lw=1))
        ax.text(x + bw / 2, y + bh / 2, text, ha="center", va="center", fontsize=size, color=INK, linespacing=1.3)

    def arrow(x1, y1, x2, y2, label=None):
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=12, color=INK, lw=1))
        if label:
            ax.text((x1 + x2) / 2, (y1 + y2) / 2 + 1.2, label, ha="center", fontsize=9.5, color=INK, style="italic")

    return fig, ax, box, arrow


def hinh_cau_truc_apk():
    fig, ax, box, _ = canvas(9, 4.4, 100, 48)
    ax.add_patch(FancyBboxPatch((2, 2), 96, 42, boxstyle="round,pad=0.5,rounding_size=1.5", fc="white", ec=INK, lw=1.4))
    ax.text(50, 41, "Tệp APK (định dạng ZIP)", ha="center", fontsize=12, weight="bold", color=INK)
    items = [
        ("AndroidManifest.xml\n(XML nhị phân: gói, quyền,\nthành phần, cấu hình)", WARM),
        ("classes.dex, classes2.dex…\n(bytecode Dalvik của\nmã Java/Kotlin)", WARM),
        ("resources.arsc\n(bảng tài nguyên\nđã biên dịch)", PALE),
        ("res/\n(layout, xml, hình ảnh;\nnetwork security config)", PALE),
        ("assets/\n(tệp thô do\nứng dụng tự đọc)", PALE),
        ("lib/<abi>/\n(thư viện native .so)", PALE),
        ("META-INF/\n(chữ ký v1:\nMANIFEST.MF,\n*.SF, *.RSA)", MINT),
    ]
    xs = [5, 32, 59, 5, 32, 59, 77]
    ys = [23, 23, 23, 5, 5, 5, 23]
    ws = [23, 23, 14, 23, 23, 14, 18]
    for (text, fc), x, y, w in zip(items, xs, ys, ws):
        box(x, y, w, 12, text, fc, 9.5)
    ax.text(86, 12, "Khối chữ ký\nAPK v2/v3\n(trước Central\nDirectory)", ha="center", va="center", fontsize=9.5,
            color=INK, style="italic")
    fig.savefig(os.path.join(OUT, "hinh1_1_cau_truc_apk.png"))
    plt.close(fig)


def hinh_thanh_phan_ipc():
    fig, ax, box, arrow = canvas(9.5, 5, 100, 50)
    ax.set_ylim(-6, 50)
    ax.add_patch(FancyBboxPatch((44, 3), 54, 43, boxstyle="round,pad=0.5,rounding_size=1.5", fc="white", ec=INK, lw=1.2))
    ax.text(71, 42.5, "Ứng dụng B (sandbox, UID riêng)", ha="center", fontsize=11.5, weight="bold", color=INK)
    box(1, 19, 18, 12, "Ứng dụng A\n(UID khác)", WARM)
    box(48, 28, 21, 8, "Activity\n(màn hình)")
    box(74, 28, 21, 8, "Service\n(tác vụ nền)")
    box(48, 7, 21, 8, "BroadcastReceiver\n(nhận sự kiện)")
    box(74, 7, 21, 8, "ContentProvider\n(chia sẻ dữ liệu)")
    arrow(19, 29, 48, 33)
    ax.text(31, 34.5, "startActivity(Intent)", ha="center", fontsize=9.5, color=INK, style="italic")
    arrow(19, 24, 48, 12)
    ax.text(28.5, 19.5, "sendBroadcast", ha="center", fontsize=9.5, color=INK, style="italic")
    ax.annotate("", xy=(74, 9), xytext=(19, 21), arrowprops=dict(arrowstyle="-|>", color=INK, lw=1,
                                                                connectionstyle="arc3,rad=0.3"))
    ax.text(29, 6, "query/insert\n(ContentResolver)", ha="center", fontsize=9.5, color=INK, style="italic")
    ax.text(50, -4.5, "Chỉ thành phần exported mới nhận được lời gọi từ ứng dụng khác; "
                      "permission trên thành phần giới hạn ai được gọi", ha="center", fontsize=10, color=INK)
    fig.savefig(os.path.join(OUT, "hinh1_2_thanh_phan_ipc.png"))
    plt.close(fig)


def hinh_dich_nguoc():
    fig, ax, box, arrow = canvas(10, 4.2, 100, 44)
    box(1, 17, 12, 9, "Tệp APK", WARM)
    box(22, 30, 17, 9, "apktool d\n(giải mã)")
    box(22, 4, 17, 9, "JADX\n(dịch ngược)")
    box(48, 34, 22, 7, "AndroidManifest.xml\n(văn bản)")
    box(48, 23.5, 22, 7, "res/ (XML, values)")
    box(48, 13, 22, 7, "smali/ (mã hợp ngữ\ncủa máy ảo Dalvik)")
    box(48, 2.5, 22, 7, "sources/ (mã Java\ngần đúng)")
    box(79, 17, 20, 10, "Người phân tích /\ncông cụ quét:\nmẫu, cấu hình,\nluồng dữ liệu", MINT)
    arrow(13, 23, 22, 34), arrow(13, 20, 22, 9)
    arrow(39, 36, 48, 37.5), arrow(39, 34, 48, 27), arrow(39, 32, 48, 16.5), arrow(39, 8.5, 48, 6)
    for y in (37.5, 27, 16.5, 6):
        arrow(70, y, 79, 22)
    fig.savefig(os.path.join(OUT, "hinh2_1_dich_nguoc.png"))
    plt.close(fig)


def hinh_quy_trinh():
    fig, ax, box, arrow = canvas(10, 2.6, 100, 26)
    steps = ["1. Thu thập APK\n+ SHA-256", "2. Dịch ngược\n(apktool, JADX)", "3. Rà soát\nManifest, res/",
             "4. Tìm mẫu và\nđọc mã nguồn", "5. Xác nhận, ánh\nxạ OWASP", "6. Đề xuất\nkhắc phục"]
    for i, s in enumerate(steps):
        x = 1 + i * 16.6
        box(x, 7, 13.5, 12, s, MINT if i == 5 else PALE, 10)
        if i:
            arrow(x - 3.1, 13, x, 13)
    fig.savefig(os.path.join(OUT, "hinh3_1_quy_trinh.png"))
    plt.close(fig)


def hinh_tim_mau():
    labels = ["http://", "Cipher.\ngetInstance", "Log.[dievw](", "password\n(không phân\nbiệt hoa thường)",
              "getExternal-\nStorage", "getShared-\nPreferences(…, 1)"]
    app = [3, 2, 1, 70, 4, 1]
    apk = [38, 3, 644, 118, 12, 2]
    fig, ax = plt.subplots(figsize=(9.5, 4))
    x = range(len(labels))
    b1 = ax.bar([i - 0.2 for i in x], app, 0.4, color=BLUE, label="Trong package ứng dụng (14 tệp Java)")
    b2 = ax.bar([i + 0.2 for i in x], apk, 0.4, color=ORANGE, label="Toàn APK (2.992 tệp Java)")
    ax.set_yscale("log")
    ax.set_ylabel("Số dòng khớp (thang log)")
    ax.set_xticks(list(x), labels, fontsize=10)
    for bars in (b1, b2):
        for b in bars:
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() * 1.1, str(int(b.get_height())), ha="center",
                    fontsize=9.5)
    ax.legend(frameon=False, fontsize=10, loc="upper right")
    fig.savefig(os.path.join(OUT, "hinh3_2_tim_mau.png"))
    plt.close(fig)


if __name__ == "__main__":
    hinh_cau_truc_apk()
    hinh_thanh_phan_ipc()
    hinh_dich_nguoc()
    hinh_quy_trinh()
    hinh_tim_mau()
    print("Đã vẽ 5 hình vào", OUT)
