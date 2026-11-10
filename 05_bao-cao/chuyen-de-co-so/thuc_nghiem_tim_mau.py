#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Đếm số dòng/tệp khớp từng mẫu tìm kiếm trong mã JADX của InsecureBankv2, so sánh phạm vi package ứng dụng với toàn APK.

Chạy từ thư mục gốc đồ án sau khi dịch ngược:
    jadx -d 04_code/target-app/OUT_IB/jadx 04_code/target-app/InsecureBankv2.apk
    python3 05_bao-cao/chuyen-de-co-so/thuc_nghiem_tim_mau.py [thư mục sources của JADX]
"""
import os
import re
import sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "04_code/target-app/OUT_IB/jadx/sources"
APP = "com/android/insecurebankv2"
PATTERNS = [r"http://", r"Cipher\.getInstance", r"Log\.[dievw]\(", r"(?i)password", r"getExternalStorage",
            r"getSharedPreferences\([^,]+, *1\)"]


def count(root, pattern):
    rx = re.compile(pattern)
    lines = files = 0
    for d, _, names in os.walk(root):
        for n in names:
            if not n.endswith(".java"):
                continue
            with open(os.path.join(d, n), encoding="utf-8", errors="replace") as f:
                hit = sum(1 for line in f if rx.search(line))
            lines += hit
            files += hit > 0
    return lines, files


def main():
    print(f"{'Mẫu':<36}{'dòng(app)':>10}{'tệp':>6}{'dòng(APK)':>11}{'tệp':>6}")
    for p in PATTERNS:
        a = count(os.path.join(SRC, APP), p)
        b = count(SRC, p)
        print(f"{p:<36}{a[0]:>10}{a[1]:>6}{b[0]:>11}{b[1]:>6}")
    total = sum(n.endswith(".java") for _, _, ns in os.walk(SRC) for n in ns)
    app = sum(n.endswith(".java") for _, _, ns in os.walk(os.path.join(SRC, APP)) for n in ns)
    print(f"Tệp .java toàn APK: {total}; thuộc package ứng dụng: {app}")


if __name__ == "__main__":
    main()
