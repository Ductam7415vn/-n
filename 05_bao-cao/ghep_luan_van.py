#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ghép luận văn hoàn chỉnh từ các phần đã viết:
  bìa + phần đầu + Chương 1   ← Báo cáo đợt 1.docx
  Chương 2 + Phụ lục A–D      ← Báo cáo đợt 2.docx (trích dẫn được đánh số lại theo danh mục hợp nhất)
  Chương 3                    ← Chuong3.md (qua xuat_docx.py)
  Kết luận và hướng phát triển ← KetLuan.md (qua xuat_docx.py)
  Tài liệu tham khảo hợp nhất ← danh mục của Báo cáo đợt 1 + REFS_MOI

Chạy (cần pandoc, python-docx, docxcompose):
    python3 05_bao-cao/ghep_luan_van.py            # → 05_bao-cao/DoAnTotNghiep_NguyenDucTam.docx
Mở bằng Word và chọn "Yes" khi được hỏi cập nhật trường để mục lục điền số trang.
"""
import copy
import os
import re
import subprocess
import sys
import tempfile

from docx import Document
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from docx.shared import Cm, Pt
from docxcompose.composer import Composer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sua_ooxml  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "DoAnTotNghiep_NguyenDucTam.docx")

CH2_CITE_MAP = {1: 10, 2: 11, 3: 12, 4: 13, 5: 21, 6: 14, 7: 15, 8: 16, 9: 17, 10: 3, 11: 19, 12: 18, 13: 1, 14: 2,
                15: 22, 16: 6, 17: 23, 18: 24, 19: 4, 20: 25}

REFS_MOI = [
    "[22]. Google. Run apps on the Android Emulator — Android Developers. Online: "
    "https://developer.android.com/studio/run/emulator [Truy cập: 15/9/2026].",
    "[23]. Docker Inc. Docker Desktop for Mac with Apple Silicon — Documentation. Online: "
    "https://docs.docker.com/desktop/setup/install/mac-install/ [Truy cập: 15/9/2026].",
    "[24]. Pallets Projects. Flask — Web Development, One Drop at a Time. Online: https://flask.palletsprojects.com/ "
    "[Truy cập: 15/9/2026].",
    "[25]. Wohlin, C. và cộng sự. Experimentation in Software Engineering. Springer, 2012 — chương về các mối đe doạ "
    "tới tính hợp lệ của nghiên cứu thực nghiệm.",
    "[26]. F-Droid. F-Droid — Free and Open Source Android App Repository. Online: https://f-droid.org/ "
    "[Truy cập: 4/10/2026].",
    "[27]. Wilson, E. B. Probable Inference, the Law of Succession, and Statistical Inference. Journal of the American "
    "Statistical Association, Vol. 22, No. 158, 1927, pp. 209–212.",
    "[28]. Google. Shrink, obfuscate, and optimize your app — Android Developers. Online: "
    "https://developer.android.com/build/shrink-code [Truy cập: 4/10/2026].",
    "[29]. GitHub Security Lab. Advisories. Online: https://securitylab.github.com/advisories/ [Truy cập: 8/11/2026].",
    "[30]. Cohen, J. A Coefficient of Agreement for Nominal Scales. Educational and Psychological Measurement, 20(1), "
    "37–46, 1960.",
]

KY_HIEU_MOI = [
    ("AES", "Advanced Encryption Standard"),
    ("CBC", "Cipher Block Chaining"),
    ("FN", "False Negative"),
    ("FP", "False Positive"),
    ("HTML", "HyperText Markup Language"),
    ("IV", "Initialization Vector"),
    ("KTC", "Confidence Interval (khoảng tin cậy)"),
    ("RQ", "Research Question (câu hỏi nghiên cứu)"),
    ("CLI", "Command Line Interface"),
    ("TN", "True Negative"),
    ("TP", "True Positive"),
    ("XMPP", "Extensible Messaging and Presence Protocol"),
]

HINH_CH3 = [
    "Hình 3.1. Kiến trúc của công cụ apiscan",
    "Hình 3.2. Một phần báo cáo HTML của apiscan trên InsecureBankv2",
    "Hình 3.3. Precision trên tập phát triển (tại thời điểm đóng băng) và trên holdout qua các đợt",
    "Hình 3.4. TP và FP theo tầng tin cậy: (a) 19 ứng dụng thật; (b) gộp holdout đợt 7–9",
]

LOI_CAM_ON = [
    "Em xin bày tỏ lòng biết ơn sâu sắc tới Ban Giám đốc Học viện Kỹ thuật mật mã và các thầy cô trong Khoa An toàn "
    "thông tin đã tận tình giảng dạy, trang bị cho em nền tảng kiến thức chuyên ngành trong suốt những năm học vừa qua.",
    "Em xin gửi lời cảm ơn chân thành và sâu sắc nhất tới thầy TS. Phạm Duy Trung — giảng viên Khoa An toàn thông tin, "
    "Học viện Kỹ thuật mật mã. Thầy đã góp ý để em định lượng hoá khung đánh giá thay vì dừng ở nhận xét định tính, và "
    "đã đồng ý để em chuyển trọng tâm của đồ án sang xây dựng một công cụ có đầu ra dùng được khi kết quả thực nghiệm "
    "ban đầu cho thấy khoảng cách lớn giữa ứng dụng mẫu và ứng dụng thực tế.",
    "Em cũng xin cảm ơn cộng đồng mã nguồn mở OWASP, các nhóm phát triển MobSF, OWASP ZAP, Frida, objection, JADX, "
    "apktool, tác giả Dinesh Shetty và những người đóng góp cho dự án InsecureBankv2, cùng các nhà phát triển của 19 "
    "ứng dụng mã nguồn mở được dùng để đánh giá — mã nguồn công khai của họ là điều kiện để đồ án có thể đánh giá công "
    "cụ trên ứng dụng thực tế. Cuối cùng, em xin cảm ơn gia đình và bạn bè đã luôn động viên em trong suốt quá trình "
    "thực hiện đồ án.",
    "Do năng lực và thời gian còn hạn chế, đồ án chắc chắn không tránh khỏi thiếu sót. Em rất mong nhận được sự chỉ "
    "bảo, góp ý của các thầy cô và hội đồng.",
]

LOI_NOI_DAU = [
    "Ứng dụng Android giao tiếp với máy chủ qua API, và phần lớn rủi ro bảo mật của ứng dụng di động hiện nay nằm ở "
    "lớp giao tiếp đó: lưu và truyền thông tin xác thực không an toàn, cấu hình mạng cho phép kết nối không mã hoá, "
    "thành phần được mở cho ứng dụng khác gọi tới mà không có kiểm soát. Hai bộ tiêu chuẩn OWASP Mobile Top 10 (2024) "
    "và OWASP API Security Top 10 (2023) đã hệ thống hoá các nhóm lỗ hổng này, và nhiều công cụ tự động đã ra đời để "
    "phát hiện chúng. Tuy nhiên, các công cụ phân tích tĩnh thường được kiểm chứng trên ứng dụng có lỗ hổng có chủ "
    "đích; khi áp dụng lên ứng dụng thực tế, chúng sinh nhiều cảnh báo nhưng tỉ lệ cảnh báo đúng thấp, buộc người kiểm "
    "thử phải rà soát thủ công.",
    "Đồ án ban đầu được định hướng như một nghiên cứu so sánh bảy công cụ tự động trên ứng dụng mẫu InsecureBankv2. "
    "Trong quá trình thực nghiệm, một quan sát đã làm thay đổi trọng tâm: cùng một bộ luật phân tích tĩnh cho mọi cảnh "
    "báo đúng trên InsecureBankv2 nhưng chỉ 1/19 cảnh báo đúng trên ứng dụng mã nguồn mở NewPipe. Với sự đồng ý của "
    "giáo viên hướng dẫn, đồ án chuyển sang xây dựng một công cụ phân tích tĩnh có đầu ra dùng được — công cụ apiscan — "
    "và một phương pháp đánh giá công cụ trung thực trên ứng dụng thực tế; phần khảo sát và benchmark công cụ được giữ "
    "lại làm cơ sở lựa chọn kỹ thuật và đối chứng.",
    "Ngoài phần mở đầu và kết luận, đồ án gồm ba chương:",
    "Chương 1 trình bày tổng quan về bảo mật API của ứng dụng Android: kiến trúc giao tiếp, cơ chế bảo vệ tầng vận "
    "chuyển, bề mặt tấn công, hai bộ tiêu chuẩn OWASP, ba phương pháp kiểm tra bảo mật và tổng quan các công cụ tự "
    "động, qua đó xác định khoảng trống nghiên cứu.",
    "Chương 2 phân tích chi tiết ranh giới năng lực của từng công cụ, ứng dụng đích InsecureBankv2 cùng danh sách lỗ "
    "hổng đã biết, môi trường thực nghiệm trên máy Apple Silicon và khung đánh giá gồm ma trận kiểm thử, quy ước gán "
    "nhãn và tiêu chí đo.",
    "Chương 3 trình bày thiết kế và cài đặt công cụ apiscan, các kỹ thuật giảm báo nhầm theo ngữ cảnh, điểm tin cậy "
    "theo từng cảnh báo; đánh giá công cụ trên InsecureBankv2 và 19 ứng dụng mã nguồn mở theo giao thức holdout nhiều "
    "đợt, đối chứng với MobSF và thảo luận các hạn chế.",
    "Mọi thực nghiệm trong đồ án chỉ dùng ứng dụng có lỗ hổng có chủ đích và ứng dụng mã nguồn mở, chỉ phân tích tĩnh "
    "tệp APK, không gửi yêu cầu tới máy chủ của bên thứ ba. Mọi con số đều từ lần chạy thật và có tệp minh chứng đi kèm "
    "mã nguồn của công cụ. Do thời gian thực hiện có hạn và lĩnh vực an toàn ứng dụng di động thay đổi rất nhanh, đồ án "
    "chắc chắn còn nhiều thiếu sót. Em rất mong nhận được sự góp ý của các thầy cô để đồ án được hoàn thiện hơn.",
]

PIPELINE_CU = ("Đối với ba công cụ có giao diện lập trình là MobSF và OWASP ZAP, cùng với công cụ điều phối chung, toàn "
               "bộ quá trình tải tệp, kích hoạt quét, thu kết quả và chuẩn hoá được tự động hoá bằng một kịch bản Python.")
PIPELINE_MOI = ("Đối với ba công cụ có giao diện lập trình là MobSF và OWASP ZAP, cùng với công cụ điều phối chung, toàn "
                "bộ quá trình tải tệp, kích hoạt quét, thu kết quả và chuẩn hoá được thiết kế để tự động hoá bằng một kịch "
                "bản Python; trong thực nghiệm ở Chương 3, phần đã được cài đặt và sử dụng là bộ chạy phân tích tĩnh của "
                "MobSF (mobsf_batch.py).")

KET_LUAN_CH2_CU = "Với thiết kế đã hoàn tất và được mô tả đủ chi tiết để tái lập, Chương 3 sẽ tiến hành thực nghiệm"
KET_LUAN_CH2_MOI = (
    "Khi bắt đầu thực nghiệm, một quan sát đã làm thay đổi trọng tâm của đồ án: cùng một bộ luật phân tích tĩnh cho mọi "
    "cảnh báo đúng trên InsecureBankv2 nhưng chỉ 1/19 cảnh báo đúng trên ứng dụng mã nguồn mở NewPipe. Vì vậy, với sự "
    "đồng ý của giáo viên hướng dẫn, Chương 3 không thực hiện toàn bộ ma trận ba mươi tư trường hợp mà tập trung xây dựng "
    "và đánh giá công cụ phân tích tĩnh apiscan. Các kết quả của chương này được sử dụng tiếp như sau: bộ đáp án mười "
    "hai lỗ hổng, sau khi được hiệu chỉnh ở mục 3.3.1, dùng để đo recall của công cụ; quy ước gán nhãn ở mục 2.5.2 được "
    "mở rộng để gán nhãn cảnh báo trên ứng dụng thật; phân tích ranh giới năng lực ở mục 2.1 là cơ sở lựa chọn kỹ thuật "
    "cho công cụ. Trong bảy công cụ, phần thực nghiệm chỉ chạy nhóm công cụ tĩnh — JADX, apktool và phân tích tĩnh của "
    "MobSF — để đối chứng với apiscan (mục 3.5). Các trường hợp kiểm thử động với Burp Suite, OWASP ZAP và Frida chưa "
    "được thực hiện và được nêu là hướng phát triển ở phần Kết luận.")


def body_elements(doc):
    return [el for el in doc.element.body if el.tag != qn("w:sectPr")]


def text_of(el):
    return "".join(t.text or "" for t in el.iter(qn("w:t")))


def find(doc, pred, start=0):
    els = body_elements(doc)
    for i in range(start, len(els)):
        if pred(text_of(els[i]).strip(), els[i]):
            return i
    raise LookupError("không tìm thấy phần tử cần thiết")


def remove_range(doc, i, j):
    for el in body_elements(doc)[i:j]:
        el.getparent().remove(el)


def set_text(p_el, text):
    runs = p_el.findall(qn("w:r"))
    keep = next((r for r in runs if r.find(qn("w:t")) is not None), runs[0])
    for r in runs:
        if r is not keep:
            p_el.remove(r)
    for t in keep.findall(qn("w:t"))[1:]:
        keep.remove(t)
    t = keep.find(qn("w:t"))
    if t is None:
        t = OxmlElement("w:t")
        keep.append(t)
    t.text = text
    t.set(qn("xml:space"), "preserve")


def replace_paragraphs(doc, first, end, texts):
    """Thay các đoạn [first, end) bằng các đoạn mới có định dạng của đoạn first."""
    els = body_elements(doc)
    template = next(el for el in els[first:end] if el.find(qn("w:r")) is not None and text_of(el).strip())
    anchor = els[end]
    remove_range(doc, first, end)
    for text in texts:
        p = copy.deepcopy(template)
        set_text(p, text)
        anchor.addprevious(p)


def page_break_before(el):
    ppr = el.find(qn("w:pPr"))
    if ppr is None:
        ppr = OxmlElement("w:pPr")
        el.insert(0, ppr)
    pb = OxmlElement("w:pageBreakBefore")
    pos = sum(1 for c in ppr if c.tag in (qn("w:pStyle"), qn("w:keepNext"), qn("w:keepLines")))
    ppr.insert(pos, pb)


def heading_pred(prefix):
    return lambda t, el: t.startswith(prefix) and el.tag == qn("w:p")


def is_ref_entry(t, _):
    return re.match(r"\[\d+\]\.", t) is not None


def build_front_and_ch1(path):
    doc = Document(path)
    els = body_elements(doc)
    for i, el in enumerate(els):
        if text_of(el).strip() == "BÁO CÁO ĐỢT 1":
            set_text(el, "ĐỒ ÁN TỐT NGHIỆP")
            if text_of(els[i + 1]).strip() == "ĐỒ ÁN TỐT NGHIỆP":
                els[i + 1].getparent().remove(els[i + 1])

    d2 = Document(os.path.join(HERE, "Báo cáo đợt 2.docx"))
    table = doc.tables[0]
    rows = {r.cells[0].text.strip(): r.cells[1].text.strip() for r in table.rows[1:]}
    for t in (d2.tables[0],):
        for r in t.rows[1:]:
            rows.setdefault(r.cells[0].text.strip(), r.cells[1].text.strip())
    for k, v in KY_HIEU_MOI:
        rows.setdefault(k, v)
    template = table.rows[1]._tr
    for r in table.rows[1:]:
        table._tbl.remove(r._tr)
    for k in sorted(rows, key=str.upper):
        tr = copy.deepcopy(template)
        tcs = tr.findall(qn("w:tc"))
        set_text(tcs[0].find(qn("w:p")), k)
        set_text(tcs[1].find(qn("w:p")), rows[k])
        table._tbl.append(tr)

    front = []
    for para in d2.paragraphs:
        if para.text.strip() == "LỜI CẢM ƠN":
            break
        front.append(para.text.strip())
    hinh_ch2 = [t for t in front if re.match(r"Hình 2\.\d+\.", t)]
    bang_ch2 = [t for t in front if re.match(r"Bảng 2\.\d+\.", t)]
    ch3_md = open(os.path.join(HERE, "Chuong3.md"), encoding="utf-8").read()
    bang_ch3 = re.findall(r"^\*(Bảng 3\.\d+\..*)\*$", ch3_md, re.M)
    for prefix, extra in (("Hình 1.", hinh_ch2 + HINH_CH3), ("Bảng 1.", bang_ch2 + bang_ch3)):
        els = body_elements(doc)
        last = max(i for i, el in enumerate(els[:80]) if text_of(el).strip().startswith(prefix))
        anchor = els[last]
        for text in reversed(extra):
            p = copy.deepcopy(anchor)
            set_text(p, text)
            anchor.addnext(p)

    i = find(doc, lambda t, el: t == "LỜI CẢM ƠN")
    j = find(doc, lambda t, el: t == "SINH VIÊN THỰC HIỆN ĐỒ ÁN", i)
    k = max(n for n in range(i + 1, j) if text_of(body_elements(doc)[n]).strip())
    replace_paragraphs(doc, i + 1, k + 1, LOI_CAM_ON)

    i = find(doc, lambda t, el: t == "LỜI NÓI ĐẦU")
    j = find(doc, lambda t, el: t == "SINH VIÊN THỰC HIỆN ĐỒ ÁN", i)
    k = max(n for n in range(i + 1, j) if text_of(body_elements(doc)[n]).strip())
    replace_paragraphs(doc, i + 1, k + 1, LOI_NOI_DAU)

    i = find(doc, lambda t, el: t == "Tài liệu tham khảo")
    remove_range(doc, i, len(body_elements(doc)))
    return doc


def build_refs(path):
    doc = Document(path)
    i = find(doc, lambda t, el: t == "Tài liệu tham khảo")
    remove_range(doc, 0, i)
    els = body_elements(doc)
    page_break_before(els[0])
    last = [el for el in els if is_ref_entry(text_of(el).strip(), el)][-1]
    anchor = last
    for text in REFS_MOI:
        p = copy.deepcopy(last)
        set_text(p, text)
        anchor.addnext(p)
        anchor = p
    return doc


def remap_citations(doc):
    def sub(m):
        return f"[{CH2_CITE_MAP[int(m.group(1))]}]"
    for t in doc.element.body.iter(qn("w:t")):
        if t.text and "[" in t.text:
            t.text = re.sub(r"\[(\d+)\]", sub, t.text)


def build_ch2(path):
    doc = Document(path)
    i = find(doc, heading_pred("Chương 2."))
    remove_range(doc, 0, i)
    i = find(doc, lambda t, el: t == "Phụ lục")
    remove_range(doc, i, len(body_elements(doc)))
    page_break_before(body_elements(doc)[0])
    remap_citations(doc)
    n = 0
    for el in body_elements(doc):
        full = text_of(el)
        if PIPELINE_CU in full:
            set_text(el, full.replace(PIPELINE_CU, PIPELINE_MOI))
            n += 1
    if n != 1:
        raise LookupError("không tìm thấy câu mô tả pipeline ở mục 2.5.4")
    i = find(doc, lambda t, el: t.startswith(KET_LUAN_CH2_CU))
    set_text(body_elements(doc)[i], KET_LUAN_CH2_MOI)
    return doc


def build_appendix(path):
    doc = Document(path)
    i = find(doc, lambda t, el: t == "Phụ lục")
    remove_range(doc, 0, i)
    i = find(doc, lambda t, el: t == "Tài liệu tham khảo")
    remove_range(doc, i, len(body_elements(doc)))
    page_break_before(body_elements(doc)[0])
    return doc


def from_markdown(md, tmp):
    out = os.path.join(tmp, os.path.basename(md).replace(".md", ".docx"))
    subprocess.run([sys.executable, os.path.join(HERE, "xuat_docx.py"), md, out], check=True, stdout=subprocess.DEVNULL)
    doc = Document(out)
    page_break_before(body_elements(doc)[0])
    return doc


def fix_styles(doc):
    """Các style Heading, Body Text, Caption của bản gốc là mặc định của Word (Cambria xanh, không thụt dòng); chương
    1–2 định dạng trực tiếp nên không bị ảnh hưởng, còn chương 3 và kết luận dùng style thuần và nhận định nghĩa
    style của bản gốc khi ghép, nên các style này phải đúng định dạng luận văn."""
    spec = {"Heading 1": (28, True, False, True), "Heading 2": (26, True, False, False),
            "Heading 3": (26, True, True, False), "Caption": (24, False, True, True)}
    for name, (size, bold, italic, center) in spec.items():
        st = doc.styles[name]
        f = st.font
        f.name = "Times New Roman"
        f.size = Pt(size / 2)
        f.bold = bold
        f.italic = italic
        rfonts = st.element.rPr.find(qn("w:rFonts"))
        for a in ("w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme"):
            rfonts.attrib.pop(qn(a), None)
        for a in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
            rfonts.set(qn(a), "Times New Roman")
        color = st.element.rPr.find(qn("w:color"))
        if color is not None:
            st.element.rPr.remove(color)
        if center:
            st.paragraph_format.alignment = 1
        st.paragraph_format.space_before = Pt(6)
        st.paragraph_format.space_after = Pt(6)
    body = doc.styles["Body Text"].paragraph_format
    body.first_line_indent = Pt(28.35)
    body.alignment = 3
    body.space_after = Pt(6)


def to_a4(doc):
    """Đổi mọi section sang A4 (giữ lề) và co các bảng có độ rộng cố định vượt vùng chữ mới theo tỉ lệ."""
    for section in doc.sections:
        section.page_width, section.page_height = Cm(21), Cm(29.7)
    sect = doc.sections[-1]
    text_w = int((sect.page_width - sect.left_margin - sect.right_margin) / 635)
    for tbl in doc.element.body.iter(qn("w:tbl")):
        grid = tbl.find(qn("w:tblGrid"))
        cols = grid.findall(qn("w:gridCol")) if grid is not None else []
        total = sum(int(c.get(qn("w:w"))) for c in cols)
        if total <= text_w:
            continue
        ratio = text_w / total
        for c in cols:
            c.set(qn("w:w"), str(int(int(c.get(qn("w:w"))) * ratio)))
        for tcw in tbl.iter(qn("w:tcW")):
            if tcw.get(qn("w:type")) == "dxa":
                tcw.set(qn("w:w"), str(int(int(tcw.get(qn("w:w"))) * ratio)))


def ask_update_fields(doc):
    settings = doc.settings.element
    el = settings.find(qn("w:updateFields"))
    if el is None:
        el = OxmlElement("w:updateFields")
        settings.append(el)
    el.set(qn("w:val"), "true")


def main():
    d1 = os.path.join(HERE, "Báo cáo đợt 1.docx")
    d2 = os.path.join(HERE, "Báo cáo đợt 2.docx")
    with tempfile.TemporaryDirectory() as tmp:
        master = build_front_and_ch1(d1)
        fix_styles(master)
        composer = Composer(master)
        composer.append(build_ch2(d2))
        composer.append(from_markdown(os.path.join(HERE, "Chuong3.md"), tmp))
        composer.append(from_markdown(os.path.join(HERE, "KetLuan.md"), tmp))
        composer.append(build_refs(d1))
        composer.append(build_appendix(d2))
        to_a4(composer.doc)
        ask_update_fields(composer.doc)
        composer.save(OUT)
    sua_ooxml.normalize(OUT)
    print("Đã ghép:", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
