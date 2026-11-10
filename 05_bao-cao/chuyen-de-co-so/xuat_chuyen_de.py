#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Xuất báo cáo chuyên đề cơ sở ra .docx theo mẫu trình bày của Học viện Kỹ thuật mật mã:
bìa có logo và khung viền đôi → mục lục → danh mục ký hiệu, hình, bảng → nội dung (ChuyenDeCoSo.md) → trang nhận xét
của giảng viên. Khổ A4, Times New Roman 13, giãn dòng 1,5, lề trái 3 cm / phải 2 cm / trên-dưới 2,5 cm.

Chạy (cần pandoc, python-docx, docxcompose):
    python3 05_bao-cao/chuyen-de-co-so/xuat_chuyen_de.py      # → BaoCaoChuyenDeCoSo_NguyenDucTam.docx
Mở bằng Word và chọn "Yes" khi được hỏi cập nhật trường để mục lục điền số trang.
"""
import os
import re
import sys
import tempfile
import zipfile

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt
from docxcompose.composer import Composer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import xuat_docx  # noqa: E402
import sua_ooxml  # noqa: E402

SRC = os.path.join(HERE, "ChuyenDeCoSo.md")
OUT = os.path.join(HERE, "BaoCaoChuyenDeCoSo_NguyenDucTam.docx")
LOGO = os.path.join(HERE, "hinh", "logo_kma.png")

LOAI_BAO_CAO = "BÁO CÁO CHUYÊN ĐỀ CƠ SỞ CHUYÊN NGÀNH"
TEN_DE_TAI = "NGHIÊN CỨU CÔNG CỤ TỰ ĐỘNG PHÁT HIỆN LỖ HỔNG BẢO MẬT API CỦA ỨNG DỤNG ANDROID"
SINH_VIEN = ("Nguyễn Đức Tâm", "Mã sinh viên: AT190147", "Lớp: AT19A")
LOI_CAM_ON = [
    "Em xin chân thành cảm ơn Ban Giám đốc Học viện Kỹ thuật mật mã và các thầy cô trong Khoa An toàn thông tin đã giảng "
    "dạy và trang bị cho em những kiến thức nền tảng về an toàn thông tin, mật mã và phát triển phần mềm, là cơ sở để em "
    "thực hiện chuyên đề này.",
    "Em xin gửi lời cảm ơn sâu sắc tới thầy TS. Phạm Duy Trung, người đã định hướng đề tài, góp ý về phạm vi và cách trình "
    "bày, đồng thời nhắc em luôn kiểm chứng mọi nhận định bằng số liệu từ thực nghiệm thật trong suốt quá trình thực hiện "
    "chuyên đề.",
    "Em cũng xin cảm ơn cộng đồng OWASP và các nhóm phát triển apktool, JADX, MobSF, cùng tác giả ứng dụng InsecureBankv2. "
    "Tài liệu và công cụ mã nguồn mở của họ giúp em có thể học và thực hành phân tích bảo mật ứng dụng Android một cách "
    "hợp pháp và an toàn. Cuối cùng, em xin cảm ơn gia đình và bạn bè đã luôn động viên em.",
    "Do kiến thức và thời gian còn hạn chế, báo cáo không tránh khỏi thiếu sót. Em rất mong nhận được ý kiến góp ý của các "
    "thầy cô để em hoàn thiện kiến thức và tiếp tục hướng nghiên cứu này ở đồ án tốt nghiệp.",
]
HUONG_DAN = ("TS. Phạm Duy Trung", "Khoa An toàn thông tin – Học viện Kỹ thuật mật mã")
NAM = "Hà Nội, 2026"

KY_HIEU = [
    ("API", "Application Programming Interface — giao diện lập trình ứng dụng"),
    ("APK", "Android Package — tệp cài đặt ứng dụng Android"),
    ("ART", "Android Runtime — môi trường thực thi Android"),
    ("AST", "Abstract Syntax Tree — cây cú pháp trừu tượng"),
    ("BOLA", "Broken Object Level Authorization — lỗi phân quyền mức đối tượng"),
    ("CBC", "Cipher Block Chaining — chế độ mã hoá khối móc xích"),
    ("CVE", "Common Vulnerabilities and Exposures — mã định danh lỗ hổng công khai"),
    ("CWE", "Common Weakness Enumeration — danh mục điểm yếu phần mềm"),
    ("DEX", "Dalvik Executable — định dạng bytecode của Android"),
    ("FN", "False Negative — lỗ hổng bị bỏ sót"),
    ("FP", "False Positive — cảnh báo nhầm"),
    ("HTTP(S)", "HyperText Transfer Protocol (Secure)"),
    ("IV", "Initialization Vector — vector khởi tạo"),
    ("MASTG", "Mobile Application Security Testing Guide"),
    ("MASVS", "Mobile Application Security Verification Standard"),
    ("MobSF", "Mobile Security Framework"),
    ("OWASP", "Open Worldwide Application Security Project"),
    ("REST", "Representational State Transfer — kiểu kiến trúc API dựa trên HTTP"),
    ("SDK", "Software Development Kit — bộ công cụ phát triển"),
    ("SHA-256", "Secure Hash Algorithm 256-bit"),
    ("SMS", "Short Message Service — tin nhắn ngắn"),
    ("TP", "True Positive — cảnh báo đúng"),
    ("UID", "User Identifier — mã định danh người dùng Linux"),
    ("URI/URL", "Uniform Resource Identifier/Locator"),
    ("XML", "eXtensible Markup Language"),
]


def para(doc, text="", size=13, bold=False, italic=False, align=WD_ALIGN_PARAGRAPH.CENTER, before=0, after=0,
         line=1.15):
    p = doc.add_paragraph()
    p.alignment = align
    pf = p.paragraph_format
    pf.space_before, pf.space_after, pf.line_spacing = Pt(before), Pt(after), line
    if text:
        r = p.add_run(text)
        r.font.name, r.font.size, r.bold, r.italic = "Times New Roman", Pt(size), bold, italic
    return p


def label_value(doc, label, values, indent=Cm(2.5)):
    p = para(doc, align=WD_ALIGN_PARAGRAPH.LEFT, before=6)
    p.paragraph_format.left_indent = indent
    r = p.add_run(label)
    r.font.name, r.font.size, r.italic = "Times New Roman", Pt(13), True
    for i, v in enumerate(values):
        q = para(doc, align=WD_ALIGN_PARAGRAPH.LEFT)
        q.paragraph_format.left_indent = indent + Cm(1)
        r = q.add_run(v)
        r.font.name, r.font.size, r.bold = "Times New Roman", Pt(13), i == 0


def page_border(section):
    borders = OxmlElement("w:pgBorders")
    borders.set(qn("w:offsetFrom"), "page")
    for side in ("top", "left", "bottom", "right"):
        b = OxmlElement(f"w:{side}")
        b.set(qn("w:val"), "thickThinSmallGap")
        b.set(qn("w:sz"), "24")
        b.set(qn("w:space"), "24")
        b.set(qn("w:color"), "auto")
        borders.append(b)
    sect = section._sectPr
    anchor = sect.find(qn("w:pgMar"))
    anchor.addnext(borders)


def add_field(paragraph, instr):
    r = paragraph.add_run()
    for kind, text in (("begin", None), (None, instr), ("separate", None), (None, ""), ("end", None)):
        if kind:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), kind)
        elif text == instr:
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = instr
        else:
            el = OxmlElement("w:t")
            el.text = text
        r._r.append(el)


def full_width(table, widths):
    table.autofit = False
    tbl_w = table._tbl.tblPr.find(qn("w:tblW"))
    if tbl_w is None:
        tbl_w = OxmlElement("w:tblW")
        table._tbl.tblPr.append(tbl_w)
    tbl_w.set(qn("w:type"), "pct")
    tbl_w.set(qn("w:w"), "5000")
    for row in table.rows:
        for cell, w in zip(row.cells, widths):
            cell.width = w
            for p in cell.paragraphs:
                if p.alignment is None:
                    p.alignment = WD_ALIGN_PARAGRAPH.LEFT


def setup_page(section):
    section.page_width, section.page_height = Cm(21), Cm(29.7)
    section.left_margin, section.right_margin = Cm(3), Cm(2)
    section.top_margin, section.bottom_margin = Cm(2.5), Cm(2.5)


def build_cover(doc):
    para(doc, "BAN CƠ YẾU CHÍNH PHỦ", 14, bold=True, before=12)
    para(doc, "HỌC VIỆN KỸ THUẬT MẬT MÃ", 14, bold=True)
    para(doc, "¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯", 13, after=18)
    p = para(doc, after=18)
    p.add_run().add_picture(LOGO, width=Cm(3.6))
    para(doc, LOAI_BAO_CAO, 15, bold=True, after=18)
    para(doc, TEN_DE_TAI, 16, bold=True, after=24, line=1.3)
    for t in ("Ngành: An toàn thông tin", "Mã số: 7.48.02.02"):
        q = para(doc, t, 13, align=WD_ALIGN_PARAGRAPH.LEFT)
        q.paragraph_format.left_indent = Cm(9)
    label_value(doc, "Sinh viên thực hiện:", SINH_VIEN)
    label_value(doc, "Người hướng dẫn:", HUONG_DAN)
    para(doc, NAM, 13, bold=True, before=60)


def front_heading(doc, text):
    return para(doc, text, 14, bold=True, before=0, after=12, line=1.5)


def caption_list(md, prefix):
    items = re.findall(r"^!\[(%s [^\]]+)\]" % prefix, md, re.M) if prefix == "Hình" else \
        re.findall(r"^\*(%s \d+\.\d+\.[^*]+)\*$" % prefix, md, re.M)
    return list(dict.fromkeys(items))


def build_front(doc, md):
    sec2 = doc.add_section(WD_SECTION.NEW_PAGE)
    setup_page(sec2)
    border = sec2._sectPr.find(qn("w:pgBorders"))
    if border is not None:
        sec2._sectPr.remove(border)
    sec2.footer.is_linked_to_previous = False
    fp = sec2.footer.paragraphs[0]
    fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    add_field(fp, "PAGE")

    front_heading(doc, "MỤC LỤC")
    add_field(para(doc, align=WD_ALIGN_PARAGRAPH.LEFT, line=1.5), 'TOC \\o "1-3" \\h \\z \\u')
    para(doc).add_run().add_break(WD_BREAK.PAGE)

    front_heading(doc, "DANH MỤC KÝ HIỆU VÀ VIẾT TẮT")
    table = doc.add_table(rows=1, cols=2)
    table.style = "Table"
    for cell, text in zip(table.rows[0].cells, ("Ký hiệu", "Ý nghĩa")):
        cell.text = ""
        r = cell.paragraphs[0].add_run(text)
        r.bold, r.font.size = True, Pt(12)
    for k, v in KY_HIEU:
        cells = table.add_row().cells
        for cell, text in zip(cells, (k, v)):
            cell.text = ""
            cell.paragraphs[0].add_run(text).font.size = Pt(12)
    full_width(table, (Cm(3.5), Cm(12.5)))
    para(doc).add_run().add_break(WD_BREAK.PAGE)

    for title, prefix in (("DANH MỤC HÌNH VẼ", "Hình"), ("DANH MỤC BẢNG", "Bảng")):
        front_heading(doc, title)
        for item in caption_list(md, prefix):
            para(doc, item, 13, align=WD_ALIGN_PARAGRAPH.LEFT, after=3, line=1.3)
        para(doc)

    if not LOI_CAM_ON:
        return
    h = front_heading(doc, "LỜI CẢM ƠN")
    h.paragraph_format.page_break_before = True
    for text in LOI_CAM_ON:
        p = para(doc, text, 13, align=WD_ALIGN_PARAGRAPH.JUSTIFY, after=6, line=1.5)
        p.paragraph_format.first_line_indent = Cm(1)
    para(doc, "Hà Nội, ngày ...... tháng ...... năm 2026", 13, italic=True, align=WD_ALIGN_PARAGRAPH.RIGHT, before=12)
    for text in ("SINH VIÊN THỰC HIỆN", "Nguyễn Đức Tâm"):
        q = para(doc, text, 13, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, line=1.5)
        q.paragraph_format.left_indent = Cm(8)


def build_review_page(doc):
    p = para(doc, "NHẬN XÉT CỦA GIẢNG VIÊN HƯỚNG DẪN", 14, bold=True, after=18, line=1.5)
    p.paragraph_format.page_break_before = True
    for _ in range(14):
        para(doc, "." * 118, 12, align=WD_ALIGN_PARAGRAPH.LEFT, line=1.8)
    q = para(doc, "Hà Nội, ngày ...... tháng ...... năm 2026", 13, italic=True, align=WD_ALIGN_PARAGRAPH.RIGHT,
             before=12)
    q.paragraph_format.right_indent = Cm(1)
    table = doc.add_table(rows=2, cols=2)
    for cell, text, b in zip(table.rows[0].cells, ("Điểm", "GIẢNG VIÊN HƯỚNG DẪN"), (True, True)):
        cell.text = ""
        r = cell.paragraphs[0].add_run(text)
        r.bold = b
        cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
    for cell, text in zip(table.rows[1].cells, ("(Bằng số và bằng chữ)", "(Ký và ghi rõ họ tên)")):
        cell.text = ""
        r = cell.paragraphs[0].add_run(text)
        r.italic = True
        cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
    full_width(table, (Cm(8), Cm(8)))


FOOTER_XML = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
              'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
              '<w:p><w:pPr><w:jc w:val="center"/></w:pPr>'
              '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
              '<w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r>'
              '<w:r><w:fldChar w:fldCharType="separate"/></w:r>'
              '<w:r><w:t>1</w:t></w:r>'
              '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>')


def simplify_footers(path, footer_xml=FOOTER_XML):
    """Footer mẫu của python-docx (style Footer không tồn tại, trường PAGE không có giá trị hiển thị) khiến Google Docs
    không mở được tệp; thay bằng footer tối giản như Word ghi."""
    with zipfile.ZipFile(path) as zin:
        items = [(i, zin.read(i.filename)) for i in zin.infolist()]
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zout:
        for info, data in items:
            if re.fullmatch(r"word/footer\d+\.xml", info.filename):
                data = footer_xml.encode("utf-8")
            zout.writestr(info, data)


def main():
    md = open(SRC, encoding="utf-8").read()
    with tempfile.TemporaryDirectory() as tmp:
        body_path = os.path.join(tmp, "body.docx")
        xuat_docx.main(SRC, body_path)
        body = Document(body_path)

        master = Document(body_path)
        body_el = master.element.body
        for el in list(body_el):
            if el.tag != qn("w:sectPr"):
                body_el.remove(el)
        setup_page(master.sections[0])
        page_border(master.sections[0])
        h1 = master.styles["Heading 1"].paragraph_format
        h1.page_break_before = True
        build_cover(master)
        build_front(master, md)

        composer = Composer(master)
        composer.append(body)
        tail = Document(body_path)
        for el in list(tail.element.body):
            if el.tag != qn("w:sectPr"):
                tail.element.body.remove(el)
        build_review_page(tail)
        composer.append(tail)

        settings = composer.doc.settings.element
        upd = OxmlElement("w:updateFields")
        upd.set(qn("w:val"), "true")
        settings.append(upd)
        composer.save(OUT)
    simplify_footers(OUT)
    sua_ooxml.normalize(OUT)
    print("Đã xuất:", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
