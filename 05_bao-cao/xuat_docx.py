#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Xuất một chương Markdown (vd Chuong3.md) sang .docx theo định dạng của các báo cáo tiến độ:
Times New Roman 13, giãn dòng 1,5, tiêu đề đậm màu đen, khổ A4, lề trái 3 cm / phải 2 cm / trên-dưới 2,5 cm.

Chạy:  python3 05_bao-cao/xuat_docx.py 05_bao-cao/Chuong3.md 05_bao-cao/Chuong3_apiscan.docx   (cần pandoc)

Quy ước trong Markdown: dòng in nghiêng "*Bảng x.y. …*" ngay trước bảng thành chú thích bảng; ảnh có alt
"Hình x.y. …" thành hình kèm chú thích (dòng in nghiêng "*Hình …*" ngay sau ảnh bị bỏ để không lặp).
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sua_ooxml  # noqa: E402

TNR = '<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="Times New Roman" w:cs="Times New Roman"/>'
PARAGRAPH_STYLES = {
    "Normal": '<w:pPr><w:spacing w:before="0" w:after="120" w:line="360" w:lineRule="auto"/><w:jc w:val="both"/></w:pPr>'
              f'<w:rPr>{TNR}<w:sz w:val="26"/><w:szCs w:val="26"/></w:rPr>',
    "BodyText": '<w:pPr><w:spacing w:before="0" w:after="120" w:line="360" w:lineRule="auto"/><w:ind w:firstLine="567"/>'
                f'<w:jc w:val="both"/></w:pPr><w:rPr>{TNR}<w:sz w:val="26"/><w:szCs w:val="26"/></w:rPr>',
    "FirstParagraph": '<w:pPr><w:spacing w:before="0" w:after="120" w:line="360" w:lineRule="auto"/><w:ind w:firstLine="567"/>'
                      f'<w:jc w:val="both"/></w:pPr><w:rPr>{TNR}<w:sz w:val="26"/><w:szCs w:val="26"/></w:rPr>',
    "Compact": '<w:pPr><w:spacing w:before="0" w:after="60" w:line="312" w:lineRule="auto"/></w:pPr>'
               f'<w:rPr>{TNR}<w:sz w:val="26"/><w:szCs w:val="26"/></w:rPr>',
    "Heading1": '<w:pPr><w:keepNext/><w:spacing w:before="0" w:after="240" w:line="360" w:lineRule="auto"/><w:jc w:val="center"/>'
                f'<w:outlineLvl w:val="0"/></w:pPr><w:rPr>{TNR}<w:b/><w:bCs/><w:color w:val="000000"/><w:sz w:val="28"/>'
                '<w:szCs w:val="28"/></w:rPr>',
    "Heading2": '<w:pPr><w:keepNext/><w:spacing w:before="240" w:after="120" w:line="360" w:lineRule="auto"/><w:jc w:val="left"/>'
                f'<w:outlineLvl w:val="1"/></w:pPr><w:rPr>{TNR}<w:b/><w:bCs/><w:color w:val="000000"/><w:sz w:val="26"/>'
                '<w:szCs w:val="26"/></w:rPr>',
    "Heading3": '<w:pPr><w:keepNext/><w:spacing w:before="180" w:after="120" w:line="360" w:lineRule="auto"/><w:jc w:val="left"/>'
                f'<w:outlineLvl w:val="2"/></w:pPr><w:rPr>{TNR}<w:b/><w:bCs/><w:i/><w:iCs/><w:color w:val="000000"/>'
                '<w:sz w:val="26"/><w:szCs w:val="26"/></w:rPr>',
    "TableCaption": '<w:pPr><w:keepNext/><w:spacing w:before="120" w:after="60" w:line="276" w:lineRule="auto"/><w:jc w:val="center"/>'
                    f'</w:pPr><w:rPr>{TNR}<w:i/><w:iCs/><w:color w:val="000000"/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr>',
    "ImageCaption": '<w:pPr><w:spacing w:before="60" w:after="200" w:line="276" w:lineRule="auto"/><w:jc w:val="center"/></w:pPr>'
                    f'<w:rPr>{TNR}<w:i/><w:iCs/><w:color w:val="000000"/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr>',
    "CaptionedFigure": '<w:pPr><w:keepNext/><w:spacing w:before="120" w:after="0"/><w:jc w:val="center"/></w:pPr>',
    "Figure": '<w:pPr><w:keepNext/><w:spacing w:before="120" w:after="0"/><w:jc w:val="center"/></w:pPr>',
    "VerbatimChar": '<w:rPr><w:rFonts w:ascii="Courier New" w:hAnsi="Courier New" w:cs="Courier New"/><w:sz w:val="22"/>'
                    '<w:szCs w:val="22"/></w:rPr>',
    "SourceCode": '<w:pPr><w:spacing w:before="60" w:after="120" w:line="240" w:lineRule="auto"/><w:ind w:left="567"/></w:pPr>',
}
PAGE_SETUP = ('<w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1417" w:right="1134" w:bottom="1417" w:left="1701" '
              'w:header="720" w:footer="720" w:gutter="0"/>')
TABLE_BORDERS = ('<w:tblBorders>' + "".join(f'<w:{s} w:val="single" w:sz="4" w:space="0" w:color="000000"/>'
                                            for s in ("top", "left", "bottom", "right", "insideH", "insideV"))
                 + '</w:tblBorders>')


def preprocess(md: str) -> str:
    """Chuyển chú thích bảng/hình sang cú pháp pandoc."""
    md = re.sub(r'(!\[(Hình [^\]]+)\]\([^)]+\))\n\n\*Hình [^\n]*\*\n', r'\1\n', md)
    lines, out, i = md.split("\n"), [], 0
    while i < len(lines):
        m = re.fullmatch(r'\*(Bảng \d+\.\d+\..*)\*', lines[i].strip())
        if m and i + 2 < len(lines) and lines[i + 1] == "" and lines[i + 2].startswith("|"):
            j = i + 2
            while j < len(lines) and lines[j].startswith("|"):
                j += 1
            out += lines[i + 2:j] + ["", f"Table: {m.group(1)}"]
            i = j
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


def set_style(styles: str, sid: str, body: str) -> str:
    pattern = re.compile(rf'(<w:style [^>]*w:styleId="{sid}"[^>]*>)(.*?)(</w:style>)', re.S)
    m = pattern.search(styles)
    if not m:
        return styles.replace("</w:styles>", f'<w:style w:type="paragraph" w:customStyle="1" w:styleId="{sid}">'
                                             f'<w:name w:val="{sid}"/><w:basedOn w:val="Normal"/>{body}</w:style></w:styles>')
    inner = re.sub(r'<w:pPr>.*?</w:pPr>|<w:pPr/>|<w:rPr>.*?</w:rPr>|<w:rPr/>', "", m.group(2), flags=re.S)
    return styles[:m.start()] + m.group(1) + inner + body + m.group(3) + styles[m.end():]


def insert_borders(tbl_pr: str) -> str:
    """Chèn tblBorders đúng thứ tự schema: sau tblInd, trước shd/tblLayout/tblCellMar/tblLook."""
    tbl_pr = re.sub(r'<w:tblBorders>.*?</w:tblBorders>', "", tbl_pr, flags=re.S)
    m = re.search(r'<w:(shd|tblLayout|tblCellMar|tblLook)\b', tbl_pr)
    pos = m.start() if m else len(tbl_pr)
    return tbl_pr[:pos] + TABLE_BORDERS + tbl_pr[pos:]


def build_reference(path: str) -> None:
    subprocess.run(["pandoc", "-o", path, "--print-default-data-file", "reference.docx"], check=True)
    tmp = path + ".dir"
    with zipfile.ZipFile(path) as z:
        z.extractall(tmp)
    sp = os.path.join(tmp, "word", "styles.xml")
    styles = open(sp, encoding="utf-8").read()
    styles = re.sub(r'<w:rFonts [^>]*/>', TNR, styles, count=1)
    for sid, body in PARAGRAPH_STYLES.items():
        styles = set_style(styles, sid, body)
    styles = re.sub(r'(<w:style w:type="table"[^>]*w:styleId="Table"[^>]*>.*?<w:tblPr>)(.*?)(</w:tblPr>)',
                    lambda m: m.group(1) + insert_borders(m.group(2)) + m.group(3), styles, count=1, flags=re.S)
    open(sp, "w", encoding="utf-8").write(styles)
    dp = os.path.join(tmp, "word", "document.xml")
    doc = open(dp, encoding="utf-8").read()
    doc = re.sub(r'<w:pgSz[^>]*/>', '', doc)
    doc = re.sub(r'<w:pgMar[^>]*/>', PAGE_SETUP, doc)
    open(dp, "w", encoding="utf-8").write(doc)
    os.remove(path)
    shutil.make_archive(path, "zip", tmp)
    os.rename(path + ".zip", path)
    shutil.rmtree(tmp)


def postprocess(docx: str) -> None:
    """Bảng: cỡ chữ 11, giãn dòng đơn, rộng toàn trang, không tách một dòng bảng sang hai trang."""
    tmp = docx + ".dir"
    with zipfile.ZipFile(docx) as z:
        z.extractall(tmp)
    dp = os.path.join(tmp, "word", "document.xml")
    doc = open(dp, encoding="utf-8").read()

    def shrink(m):
        t = m.group(0)
        t = re.sub(r'<w:tblW [^>]*/>', '<w:tblW w:w="5000" w:type="pct"/>', t)
        t = t.replace('<w:tr><w:trPr>', '<w:tr><w:trPr><w:cantSplit/>')
        t = re.sub(r'<w:tr>(?!<w:trPr>)', '<w:tr><w:trPr><w:cantSplit/></w:trPr>', t)
        t = re.sub(r'<w:pPr><w:pStyle w:val="Compact" ?/>(<w:spacing [^>]*/>)?',
                   '<w:pPr><w:pStyle w:val="Compact"/><w:spacing w:after="40" w:line="240" w:lineRule="auto"/>', t)
        return re.sub(r'<w:r>(<w:rPr>)?', lambda r: '<w:r><w:rPr><w:sz w:val="22"/><w:szCs w:val="22"/>'
                      if r.group(1) else '<w:r><w:rPr><w:sz w:val="22"/><w:szCs w:val="22"/></w:rPr>', t)
    doc = re.sub(r'<w:tbl>.*?</w:tbl>', shrink, doc, flags=re.S)
    i = doc.rfind("</w:sectPr>")
    if i != -1 and "<w:pgSz" not in doc[doc.rfind("<w:sectPr"):i]:
        doc = doc[:i] + PAGE_SETUP + doc[i:]
    open(dp, "w", encoding="utf-8").write(doc)
    cp = os.path.join(tmp, "[Content_Types].xml")
    types = open(cp, encoding="utf-8").read()
    if 'Extension="png"' not in types:
        types = types.replace("<Default ", '<Default Extension="png" ContentType="image/png"/><Default ', 1)
        open(cp, "w", encoding="utf-8").write(types)
    os.remove(docx)
    shutil.make_archive(docx, "zip", tmp)
    os.rename(docx + ".zip", docx)
    shutil.rmtree(tmp)
    sua_ooxml.normalize(docx)


def main(src: str, dst: str) -> int:
    src, dst = os.path.abspath(src), os.path.abspath(dst)
    with tempfile.TemporaryDirectory() as tmp:
        ref = os.path.join(tmp, "reference.docx")
        build_reference(ref)
        md = os.path.join(tmp, "chapter.md")
        with open(src, encoding="utf-8") as f, open(md, "w", encoding="utf-8") as g:
            g.write(preprocess(f.read()))
        subprocess.run(["pandoc", md, "-f", "markdown", "-o", dst, "--reference-doc", ref,
                        "--resource-path", os.path.dirname(src)], check=True)
    postprocess(dst)
    print("Đã xuất:", dst)
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
