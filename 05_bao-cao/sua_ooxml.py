#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sắp lại thứ tự phần tử con theo lược đồ OOXML cho các thẻ hay bị ghi sai thứ tự (pPr, rPr, sectPr, tblPr, tcPr,
settings) và bỏ phần tử lặp trong các thẻ chỉ cho phép một lần. Word bỏ qua lỗi thứ tự nhưng Google Docs và các trình
đọc khác có thể từ chối mở tệp.

Chạy:  python3 05_bao-cao/sua_ooxml.py tep1.docx [tep2.docx ...]      (chỉ cần thư viện chuẩn)
"""
import os
import shutil
import sys
import tempfile
import zipfile
from xml.dom import minidom

ORDER = {
    "w:pPr": "pStyle keepNext keepLines pageBreakBefore framePr widowControl numPr suppressLineNumbers pBdr shd tabs "
             "suppressAutoHyphens kinsoku wordWrap overflowPunct topLinePunct autoSpaceDE autoSpaceDN bidi "
             "adjustRightInd snapToGrid spacing ind contextualSpacing mirrorIndents suppressOverlap jc textDirection "
             "textAlignment textboxTightWrap outlineLvl divId cnfStyle rPr sectPr pPrChange",
    "w:rPr": "rStyle rFonts b bCs i iCs caps smallCaps strike dstrike outline shadow emboss imprint noProof snapToGrid "
             "vanish webHidden color spacing w kern position sz szCs highlight u effect bdr shd fitText vertAlign rtl "
             "cs em lang eastAsianLayout specVanish oMath",
    "w:sectPr": "headerReference footerReference footnotePr endnotePr type pgSz pgMar paperSrc pgBorders lnNumType "
                "pgNumType cols formProt vAlign noEndnote titlePg textDirection bidi rtlGutter docGrid printerSettings "
                "sectPrChange",
    "w:tblPr": "tblStyle tblpPr tblOverlap bidiVisual tblStyleRowBandSize tblStyleColBandSize tblW jc tblCellSpacing "
               "tblInd tblBorders shd tblLayout tblCellMar tblLook tblCaption tblDescription",
    "w:tcPr": "cnfStyle tcW gridSpan hMerge vMerge tcBorders shd noWrap tcMar textDirection tcFitText vAlign hideMark",
    "w:settings": "writeProtection view zoom removePersonalInformation removeDateAndTime doNotDisplayPageBoundaries "
                  "displayBackgroundShape printPostScriptOverText printFractionalCharacterWidth printFormsData "
                  "embedTrueTypeFonts embedSystemFonts saveSubsetFonts saveFormsData mirrorMargins "
                  "alignBordersAndEdges bordersDoNotSurroundHeader bordersDoNotSurroundFooter gutterAtTop "
                  "hideSpellingErrors hideGrammaticalErrors activeWritingStyle proofState formsDesign attachedTemplate "
                  "linkStyles stylePaneFormatFilter stylePaneSortMethod documentType mailMerge revisionView "
                  "trackRevisions doNotTrackMoves doNotTrackFormatting documentProtection autoFormatOverride "
                  "styleLockTheme styleLockQFSet defaultTabStop autoHyphenation consecutiveHyphenLimit hyphenationZone "
                  "doNotHyphenateCaps showEnvelope summaryLength clickAndTypeStyle defaultTableStyle evenAndOddHeaders "
                  "bookFoldRevPrinting bookFoldPrinting bookFoldPrintingSheets drawingGridHorizontalSpacing "
                  "drawingGridVerticalSpacing displayHorizontalDrawingGridEvery displayVerticalDrawingGridEvery "
                  "doNotUseMarginsForDrawingGridOrigin drawingGridHorizontalOrigin drawingGridVerticalOrigin "
                  "doNotShadeFormData noPunctuationKerning characterSpacingControl printTwoOnOne "
                  "strictFirstAndLastChars noLineBreaksAfter noLineBreaksBefore savePreviewPicture "
                  "doNotValidateAgainstSchema saveInvalidXml ignoreMixedContent alwaysShowPlaceholderText "
                  "doNotDemarcateInvalidXml saveXmlDataOnly useXSLTWhenSaving saveThroughXslt showXMLTags "
                  "alwaysMergeEmptyNamespace updateFields hdrShapeDefaults footnotePr endnotePr compat docVars rsids "
                  "mathPr attachedSchema themeFontLang clrSchemeMapping doNotIncludeSubdocsInStats "
                  "doNotAutoCompressPictures forceUpgrade captions readModeInkLockDown smartTagType schemaLibrary "
                  "shapeDefaults doNotEmbedSmartTags decimalSymbol listSeparator",
}
ORDER = {k: {"w:" + n: i for i, n in enumerate(v.split())} for k, v in ORDER.items()}
REPEATABLE = {"w:headerReference", "w:footerReference", "w:activeWritingStyle", "w:smartTagType", "w:attachedSchema"}
PARTS = ("word/document.xml", "word/styles.xml", "word/settings.xml", "word/numbering.xml")


def fix_element(el, order):
    kids = [c for c in el.childNodes if c.nodeType == c.ELEMENT_NODE]
    seen, keep = set(), []
    for c in kids:
        if c.tagName in seen and c.tagName not in REPEATABLE and c.tagName in order:
            el.removeChild(c)
            continue
        seen.add(c.tagName)
        keep.append(c)
    rank, last = [], -1
    for c in keep:
        last = order.get(c.tagName, last)
        rank.append(last)
    ordered = [c for _, c in sorted(zip(rank, keep), key=lambda x: x[0])]
    if ordered == keep:
        return len(kids) != len(keep)
    for c in keep:
        el.removeChild(c)
    for c in ordered:
        el.appendChild(c)
    return True


def split_field_runs(dom):
    """Tách run chứa nhiều phần của một trường (fldChar/instrText/t) thành mỗi phần một run, như Word vẫn ghi."""
    changed = 0
    for r in list(dom.getElementsByTagName("w:r")):
        kids = [c for c in r.childNodes if c.nodeType == c.ELEMENT_NODE]
        if sum(c.tagName == "w:fldChar" for c in kids) < 2:
            continue
        rpr = next((c for c in kids if c.tagName == "w:rPr"), None)
        parent = r.parentNode
        for c in kids:
            if c is rpr:
                continue
            nr = dom.createElement("w:r")
            if rpr is not None:
                nr.appendChild(rpr.cloneNode(True))
            nr.appendChild(c.cloneNode(True))
            parent.insertBefore(nr, r)
        parent.removeChild(r)
        changed += 1
    return changed


def drop_missing_style_refs(dom):
    """Bỏ basedOn/next/link trỏ tới style không tồn tại trong styles.xml."""
    styles = dom.getElementsByTagName("w:style")
    ids = {s.getAttribute("w:styleId") for s in styles}
    changed = 0
    for s in styles:
        for tag in ("w:basedOn", "w:next", "w:link"):
            for el in list(s.getElementsByTagName(tag)):
                if el.parentNode is s and el.getAttribute("w:val") not in ids:
                    s.removeChild(el)
                    changed += 1
    return changed


def fix_xml(data):
    dom = minidom.parseString(data)
    changed = split_field_runs(dom) + drop_missing_style_refs(dom)
    for tag, order in ORDER.items():
        for el in dom.getElementsByTagName(tag):
            changed += fix_element(el, order)
    return changed, dom.toxml(encoding="UTF-8")


def normalize(path):
    total = 0
    with zipfile.ZipFile(path) as zin:
        items = [(i, zin.read(i.filename)) for i in zin.infolist()]
    fd, tmp = tempfile.mkstemp(suffix=".docx", dir=os.path.dirname(os.path.abspath(path)))
    os.close(fd)
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
        for info, data in items:
            if info.filename in PARTS or (info.filename.startswith(("word/header", "word/footer"))
                                          and info.filename.endswith(".xml")):
                n, data = fix_xml(data)
                total += n
            zout.writestr(info, data)
    shutil.move(tmp, path)
    return total


if __name__ == "__main__":
    for p in sys.argv[1:]:
        print(f"{p}: sửa {normalize(p)} thẻ")
