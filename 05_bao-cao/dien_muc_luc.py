#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Điền sẵn mục lục (kết quả của trường TOC) trong DoAnTotNghiep_NguyenDucTam.docx từ bookmark của bản PDF đã xuất.

Google Docs và một số trình xem không cập nhật trường TOC, nên chỉ thấy dòng nhắc "Update Field". Script giữ nguyên mã
trường (Word vẫn cập nhật lại khi mở vì settings có updateFields) và thay phần kết quả bằng các mục cấp 1–3 kèm số trang
lấy từ PDF do Gotenberg/LibreOffice xuất, nơi số trang vật lý trùng số trang in ở chân trang.

Chạy sau ghep_luan_van.py và bước xuất PDF (cần pypdf):
    python3 05_bao-cao/dien_muc_luc.py
"""
import os
import re
import shutil
import sys
import tempfile
import zipfile
from xml.sax.saxutils import escape

from pypdf import PdfReader

HERE = os.path.dirname(os.path.abspath(__file__))
DOCX = os.path.join(HERE, "DoAnTotNghiep_NguyenDucTam.docx")
PDF = os.path.join(HERE, "DoAnTotNghiep_NguyenDucTam.pdf")
TEXT_WIDTH = 11906 - 1701 - 1134
INDENT = 284
FONT = '<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="Times New Roman"/>'


def outline_entries(pdf_path):
    reader = PdfReader(pdf_path)
    entries = []

    def walk(items, level):
        for item in items:
            if isinstance(item, list):
                walk(item, level + 1)
            elif level <= 2:
                entries.append((level, item["/Title"].strip(), reader.get_destination_page_number(item) + 1))

    walk(reader.outline, 0)
    return entries


def entry_runs(level, title, page):
    bold = "<w:b/>" if level == 0 else ""
    rpr = f"<w:rPr>{FONT}{bold}<w:sz w:val=\"26\"/></w:rPr>"
    return (f"<w:r>{rpr}<w:t xml:space=\"preserve\">{escape(title)}</w:t></w:r>"
            f"<w:r>{rpr}<w:tab/></w:r><w:r>{rpr}<w:t>{page}</w:t></w:r>")


def entry_ppr(level):
    return (f"<w:pPr><w:tabs><w:tab w:val=\"right\" w:leader=\"dot\" w:pos=\"{TEXT_WIDTH}\"/></w:tabs>"
            f"<w:spacing w:before=\"0\" w:after=\"60\" w:line=\"312\" w:lineRule=\"auto\"/>"
            f"<w:ind w:left=\"{level * INDENT}\" w:right=\"567\"/></w:pPr>")


def build_toc(entries, instr_runs):
    paras = []
    last = len(entries) - 1
    for n, (level, title, page) in enumerate(entries):
        head = instr_runs + '<w:r><w:fldChar w:fldCharType="separate"/></w:r>' if n == 0 else ""
        tail = '<w:r><w:fldChar w:fldCharType="end"/></w:r>' if n == last else ""
        paras.append(f"<w:p>{entry_ppr(level)}{head}{entry_runs(level, title, page)}{tail}</w:p>")
    return "".join(paras)


def main():
    entries = outline_entries(PDF)
    if not entries:
        sys.exit("PDF không có bookmark — xuất lại PDF bằng Gotenberg trước.")
    with zipfile.ZipFile(DOCX) as z:
        xml = z.read("word/document.xml").decode("utf-8")
    m = re.search(r'<w:p>(?:(?!</w:p>).)*?<w:instrText[^>]*>TOC [^<]*</w:instrText>.*?</w:p>', xml, re.S)
    if not m:
        sys.exit("Không tìm thấy trường TOC trong document.xml.")
    instr = re.search(r'(<w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText[^>]*>TOC [^<]*</w:instrText></w:r>)',
                      m.group(0))
    xml = xml[:m.start()] + build_toc(entries, instr.group(1)) + xml[m.end():]

    fd, tmp = tempfile.mkstemp(suffix=".docx")
    os.close(fd)
    with zipfile.ZipFile(DOCX) as src, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            data = xml.encode("utf-8") if info.filename == "word/document.xml" else src.read(info.filename)
            dst.writestr(info, data)
    shutil.move(tmp, DOCX)
    print(f"Đã điền {len(entries)} mục vào mục lục: {DOCX}")


if __name__ == "__main__":
    main()
