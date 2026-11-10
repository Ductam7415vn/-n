#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Xuất báo cáo thực tập tốt nghiệp ra .docx theo cấu trúc mẫu báo cáo thực tập của Học viện Kỹ thuật mật mã: bìa có logo và
khung viền → mục lục → danh mục ký hiệu, hình, bảng → nội dung (BaoCaoThucTap.md, lời cảm ơn nằm trong Lời mở đầu) →
trang xác nhận của người hướng dẫn. Dùng lại các hàm dựng trang của xuat_chuyen_de.py.

Chạy (cần pandoc, python-docx, docxcompose):
    python3 05_bao-cao/bao-cao-thuc-tap/xuat_bao_cao_thuc_tap.py   # → BaoCaoThucTap_NguyenDucTam.docx
"""
import os
import sys

from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Cm

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "chuyen-de-co-so"))
import xuat_chuyen_de as base  # noqa: E402

TEN_DE_TAI = "XÂY DỰNG CÔNG CỤ PHÂN TÍCH TĨNH PHÁT HIỆN LỖ HỔNG BẢO MẬT API CHO ỨNG DỤNG ANDROID"

KY_HIEU = [
    ("API", "Application Programming Interface — giao diện lập trình ứng dụng"),
    ("APK", "Android Package — tệp cài đặt ứng dụng Android"),
    ("BOLA", "Broken Object Level Authorization — lỗi phân quyền mức đối tượng"),
    ("CBC", "Cipher Block Chaining — chế độ mã hoá khối móc xích"),
    ("FN", "False Negative — lỗ hổng bị bỏ sót"),
    ("FP", "False Positive — cảnh báo nhầm"),
    ("HTML", "HyperText Markup Language"),
    ("HTTP(S)", "HyperText Transfer Protocol (Secure)"),
    ("IV", "Initialization Vector — vector khởi tạo"),
    ("JSON", "JavaScript Object Notation"),
    ("MASTG", "Mobile Application Security Testing Guide"),
    ("MASVS", "Mobile Application Security Verification Standard"),
    ("MobSF", "Mobile Security Framework"),
    ("OWASP", "Open Worldwide Application Security Project"),
    ("REST", "Representational State Transfer — kiểu kiến trúc API dựa trên HTTP"),
    ("SDK", "Software Development Kit — bộ công cụ phát triển"),
    ("SHA-256", "Secure Hash Algorithm 256-bit"),
    ("TP", "True Positive — cảnh báo đúng"),
    ("URL", "Uniform Resource Locator"),
]


def build_cover(doc):
    p = base.para
    p(doc, "BAN CƠ YẾU CHÍNH PHỦ", 14, bold=True, before=12)
    p(doc, "HỌC VIỆN KỸ THUẬT MẬT MÃ", 14, bold=True)
    p(doc, "¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯", 13, after=14)
    p(doc, after=14).add_run().add_picture(base.LOGO, width=Cm(3.4))
    p(doc, "THỰC TẬP TỐT NGHIỆP", 14, bold=True)
    p(doc, "BÁO CÁO THỰC TẬP TỐT NGHIỆP", 15, bold=True, after=16)
    p(doc, TEN_DE_TAI, 16, bold=True, after=20, line=1.3)
    for t in ("Ngành: An toàn thông tin", "Mã số: 7.48.02.02"):
        q = p(doc, t, 13, align=WD_ALIGN_PARAGRAPH.LEFT)
        q.paragraph_format.left_indent = Cm(9)
    base.label_value(doc, "Sinh viên thực hiện:", ("Nguyễn Đức Tâm", "Mã sinh viên: AT190147", "Lớp: AT19A"))
    base.label_value(doc, "Đơn vị thực tập:", ("Công ty TNHH Công nghệ BetaSoft",))
    base.label_value(doc, "Người quản lý thực tập:", ("Nguyễn Văn Thịnh", "Công ty TNHH Công nghệ BetaSoft"))
    p(doc, "Hà Nội – 2026", 13, bold=True, before=36)


def build_review_page(doc):
    p = base.para
    h = p(doc, "XÁC NHẬN CỦA NGƯỜI HƯỚNG DẪN", 14, bold=True, after=18, line=1.5)
    h.paragraph_format.page_break_before = True
    for _ in range(14):
        p(doc, "." * 118, 12, align=WD_ALIGN_PARAGRAPH.LEFT, line=1.8)
    q = p(doc, "Hà Nội, ngày ...... tháng ...... năm 2026", 13, italic=True, align=WD_ALIGN_PARAGRAPH.RIGHT, before=12)
    q.paragraph_format.right_indent = Cm(1)
    table = doc.add_table(rows=2, cols=2)
    for row, texts, bold, italic in ((0, ("Điểm", "Người hướng dẫn"), True, False),
                                     (1, ("(Bằng số và bằng chữ)", "(Ký và ghi rõ họ tên)"), False, True)):
        for cell, text in zip(table.rows[row].cells, texts):
            cell.text = ""
            r = cell.paragraphs[0].add_run(text)
            r.bold, r.italic = bold, italic
            cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
    base.full_width(table, (Cm(8), Cm(8)))


def main():
    base.SRC = os.path.join(HERE, "BaoCaoThucTap.md")
    base.OUT = os.path.join(HERE, "BaoCaoThucTap_NguyenDucTam.docx")
    base.LOGO = os.path.join(HERE, "hinh", "logo_kma.png")
    base.KY_HIEU = KY_HIEU
    base.LOI_CAM_ON = []
    base.build_cover = build_cover
    base.build_review_page = build_review_page
    return base.main()


if __name__ == "__main__":
    sys.exit(main())
