#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Word（.docx）写入器 —— 只用标准库拼 OOXML。

为什么不用 python-docx：
    skill 的承诺是"Python 侧只用标准库"。报告是要在离线机器上出的，多一个 pip 依赖
    就多一个装不上的理由。docx 本质就是一个装着 XML 的 zip，zipfile 加拼字符串就够了，
    代价是这里每一段 XML 都得自己写对、自己保证能被 Word 打开。

版式照着商用扫描器的报告抄 —— 页面尺寸、页边距、字体、表格边框与填充色都取自
"绿盟 远程安全评估系统"主机报表的源文件，配色见 THEME：
    A4；上下页边距 2.54cm、左右 3.17cm；正文与表格用微软雅黑；
    表格边框 #9ACAE1，表头行填充 #DCEBF0，键列填充 #EAF5F9。
三节结构：封面 / 目录 / 正文。前两节不编页，正文节带页眉横线与页脚页码。

目录用 Word 的 TOC 域，并且 settings.xml 里打开了 updateFields —— 打开文档时会自动
重算页码；万一打开方不更新域，域里缓存的那份纯文字目录也能看，不会出现空白目录。

用法（数据驱动，调用方只描述结构，不管 XML）：

    blocks = [
        {"type": "cover", "org": "…", "title": "…", "subtitle": "…", "foot": [("报告编号", "…")]},
        {"type": "section", "kind": "plain"},
        {"type": "toc", "entries": [("1 评估概述", 1)]},
        {"type": "section", "kind": "plain"},
        {"type": "heading", "text": "1　评估概述", "level": 1},
        {"type": "para", "text": "…"},
        {"type": "caption", "text": "表 1-1　评估范围"},
        {"type": "table", "headers": ["项目", "内容"], "rows": [[cell("项目"), cell("内容")]]},
    ]
    build_docx("/path/report.docx", blocks, title="安全评估报告", author="…")
"""

import os
import zipfile
from xml.sax.saxutils import escape

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

# 取自模板的配色。改这里的时候 HTML 那份（reporter.CSS）要一起改，
# 两份报告出自同一个主题，颜色对不上比风格普通更扎眼。
THEME = {
    "ink": "122347",        # 正文文字（模板的 body color）
    "muted": "5A6B7D",      # 说明文字
    "accent": "1B609A",     # 标题与链接
    "line": "9ACAE1",       # 表格边框
    "fill_head": "DCEBF0",  # 表头行 / 键列填充
    "fill_soft": "EAF5F9",  # 值列与交替行填充
}

FONT_EA = "微软雅黑"
FONT_LATIN = "Microsoft YaHei"

# 字号一律用半磅：10.5pt=21、12pt=24、14pt=28、15.5pt=31、26pt=52
SZ_BODY = 24
SZ_TABLE = 21
SZ_CAPTION = 21
SZ_H1 = 28
SZ_H2 = 24
SZ_CAPTION_BLOCK = 21

# A4 页宽 11906 twip，左右页边距各 1800（3.17cm，跟模板一致）→ 正文可用宽度
PAGE_W = 11906
MARGIN_LR = 1800
CONTENT_W = PAGE_W - MARGIN_LR * 2


def _esc(text):
    return escape(str("" if text is None else text))


def _run(text, size=SZ_BODY, bold=False, color=None, east=FONT_EA, underline=False):
    """一个文本 run。换行要拆成 <w:br/> —— Word 不认字符串里的 \\n。"""
    # 子元素顺序按 OOXML 的序列来（rFonts → b → color → sz/szCs → u）。
    # Word 读的时候比较宽容，WPS 和严格的校验器不一定，顺序错了会整段丢格式。
    props = ['<w:rFonts w:ascii="%s" w:hAnsi="%s" w:eastAsia="%s"/>' % (FONT_LATIN, FONT_LATIN, east)]
    if bold:
        props.append("<w:b/>")
    if color:
        props.append('<w:color w:val="%s"/>' % color)
    props.append('<w:sz w:val="%d"/><w:szCs w:val="%d"/>' % (size, size))
    if underline:
        props.append('<w:u w:val="single"/>')
    body = []
    for index, line in enumerate(str("" if text is None else text).split("\n")):
        if index:
            body.append("<w:br/>")
        if line:
            body.append('<w:t xml:space="preserve">%s</w:t>' % _esc(line))
    return "<w:r><w:rPr>%s</w:rPr>%s</w:r>" % ("".join(props), "".join(body))


def _tab_right(pos=CONTENT_W):
    """右对齐制表位，点线填充 —— 目录的"标题......页码"就是这个做的。"""
    return '<w:tabs><w:tab w:val="right" w:leader="dot" w:pos="%d"/></w:tabs>' % pos


def _para(runs, style=None, align=None, before=0, after=120, line=320, indent_chars=0,
          keep_next=False, shade=None, border_top=False, tabs=False):
    # 顺序同上：pPr 的子元素也得按 schema 的序列排，具体见 _run 上面的说明
    ppr = []
    if style:
        ppr.append('<w:pStyle w:val="%s"/>' % style)
    if keep_next:
        ppr.append("<w:keepNext/>")
    if border_top:
        ppr.append('<w:pBdr><w:top w:val="single" w:sz="6" w:space="6" w:color="%s"/></w:pBdr>'
                   % THEME["line"])
    if shade:
        ppr.append('<w:shd w:val="clear" w:color="auto" w:fill="%s"/>' % shade)
    if tabs:
        ppr.append(_tab_right())
    ppr.append('<w:spacing w:before="%d" w:after="%d" w:line="%d" w:lineRule="auto"/>'
               % (before, after, line))
    if indent_chars:
        ppr.append('<w:ind w:firstLineChars="%d"/>' % indent_chars)
    if align:
        ppr.append('<w:jc w:val="%s"/>' % align)
    return "<w:p><w:pPr>%s</w:pPr>%s</w:p>" % ("".join(ppr), "".join(runs))


def cell(text, bold=False, color=None, align=None, fill=None, size=SZ_TABLE):
    """表格单元格的描述。调用方用它包一下，省得记 fill/align 这些参数名。"""
    return {"text": text, "bold": bold, "color": color, "align": align, "fill": fill, "size": size}


def key_cell(text):
    """键值表的键列：模板里这一列是浅蓝底、加粗。"""
    return cell(text, bold=True, fill=THEME["fill_head"])


def _col_widths(count, ratios):
    if not ratios:
        return [CONTENT_W // count] * count
    total = float(sum(ratios))
    widths = [max(560, int(CONTENT_W * ratio / total)) for ratio in ratios]
    # 把取整误差补到最后一列，别让表格比正文宽出几个 twip
    widths[-1] += CONTENT_W - sum(widths)
    return widths


def _table(headers, rows, ratios=None, header_fill=None):
    count = len(headers)
    widths = _col_widths(count, ratios)
    header_fill = header_fill or THEME["fill_head"]

    def cells(values, header=False):
        out = []
        for index, value in enumerate(values):
            item = value if isinstance(value, dict) else cell(value)
            out.append(
                "<w:tc><w:tcPr>"
                '<w:tcW w:w="%d" w:type="dxa"/>'
                '<w:shd w:val="clear" w:color="auto" w:fill="%s"/>'
                '<w:vAlign w:val="top"/>'
                "</w:tcPr>%s</w:tc>"
                % (widths[index],
                   item.get("fill") or ("auto" if header else THEME["fill_soft"]),
                   _para([_run(item.get("text"), size=item.get("size") or SZ_TABLE,
                               bold=item.get("bold", header),
                               color=item.get("color"))],
                         align=item.get("align"), before=15, after=15, line=260)))
        return "".join(out)

    parts = ['<w:tbl><w:tblPr><w:tblW w:w="%d" w:type="dxa"/>'
             "<w:tblBorders>" % CONTENT_W]
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        parts.append('<w:%s w:val="single" w:sz="4" w:space="0" w:color="%s"/>' % (edge, THEME["line"]))
    parts.append('</w:tblBorders><w:tblLayout w:type="fixed"/></w:tblPr><w:tblGrid>')
    parts.extend('<w:gridCol w:w="%d"/>' % width for width in widths)
    parts.append("</w:tblGrid>")
    if headers:
        # 表头行跨页时重复：报告里的表常常要翻页，翻过去看不到列名等于没表头
        parts.append('<w:tr><w:trPr><w:tblHeader/></w:trPr>%s</w:tr>'
                     % cells([cell(h, bold=True) for h in headers], header=True))
    for row in rows:
        parts.append("<w:tr>%s</w:tr>" % cells(row))
    parts.append("</w:tbl>")
    return "".join(parts)


def _toc_field(entries):
    """"标题……页码" 目录。

    用真的 TOC 域而不是手打一份：页码只有 Word 自己知道。域里同时缓存一份纯文字目录，
    万一打开方没更新域，看到的也是完整的章节列表（只是没有页码），不会是一片空白。
    """
    if not entries:
        return _para([_run("（无目录条目）", color=THEME["muted"], size=SZ_CAPTION)])
    begin = ('<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
             '<w:r><w:instrText xml:space="preserve"> TOC \\o "1-2" \\h \\z \\u </w:instrText></w:r>'
             '<w:r><w:fldChar w:fldCharType="separate"/></w:r>')
    parts = []
    for index, (title, level) in enumerate(entries):
        runs = ([begin] if index == 0 else []) + [
            _run(title, size=SZ_TABLE, bold=level <= 1),
            '<w:r><w:tab/></w:r>',
        ]
        if index == len(entries) - 1:
            runs.append('<w:r><w:fldChar w:fldCharType="end"/></w:r>')
        # 二级条目缩进两格，跟模板的 toc 2 样式一致
        parts.append("<w:p><w:pPr>%s<w:spacing w:before=\"0\" w:after=\"60\" w:line=\"280\" "
                     "w:lineRule=\"auto\"/>%s%s</w:pPr>%s</w:p>"
                     % (_tab_right(),
                        '<w:ind w:leftChars="%d"/>' % (0 if level <= 1 else 200),
                        '<w:rPr><w:sz w:val="%d"/></w:rPr>' % SZ_TABLE,
                        "".join(runs)))
    return "".join(parts)


def _cover(block):
    out = [_para([], before=1200, after=0)]
    out.append(_para([_run(block.get("org", ""), size=SZ_CAPTION, color=THEME["muted"])],
                     align="center", after=420))
    out.append(_para([_run(block.get("title", ""), size=52, bold=True, color=THEME["ink"])],
                     align="center", after=240))
    out.append(_para([_run(block.get("subtitle", ""), size=SZ_H1, color=THEME["ink"])],
                     align="center", after=0))
    # 封面下部：横线 + 报告编号/密级/日期，位置与模板的"报表生成时间"一致
    out.append(_para([], before=5200, after=0))
    foot = block.get("foot") or []
    if foot:
        runs = []
        for index, (key, value) in enumerate(foot):
            if index:
                runs.append(_run("　｜　", size=SZ_CAPTION, color=THEME["muted"]))
            runs.append(_run("%s %s" % (key, value), size=SZ_CAPTION, color=THEME["muted"]))
        out.append(_para(runs, align="center", border_top=True, before=120, after=60))
    return "".join(out)


def _sect(kind, theme_line):
    """节属性。plain = 封面/目录（无页眉页脚）；body = 正文（页眉横线 + 页脚页码）。"""
    page = ('<w:pgSz w:w="%d" w:h="16838"/>'
            '<w:pgMar w:top="1440" w:right="%d" w:bottom="1440" w:left="%d" '
            'w:header="851" w:footer="992" w:gutter="0"/>' % (PAGE_W, MARGIN_LR, MARGIN_LR))
    if kind == "body":
        return ('<w:sectPr><w:headerReference w:type="default" r:id="rId2"/>'
                '<w:footerReference w:type="default" r:id="rId3"/>%s'
                '<w:cols w:space="425"/></w:sectPr>' % page)
    return "<w:sectPr>%s<w:cols w:space=\"425\"/></w:sectPr>" % page


def _section_break(kind):
    """节分隔：sectPr 挂在上一节的最后一个段落上，所以这里输出一个空段落。"""
    return ('<w:p><w:pPr><w:rPr><w:sz w:val="2"/></w:rPr>%s</w:pPr></w:p>' % _sect(kind, None))


def _blocks_to_xml(blocks):
    parts = []
    for block in blocks:
        kind = block.get("type")
        if kind == "cover":
            parts.append(_cover(block))
        elif kind == "section":
            parts.append(_section_break(block.get("kind") or "plain"))
        elif kind == "toc":
            parts.append(_toc_field(block.get("entries") or []))
        elif kind == "heading":
            level = min(3, max(1, int(block.get("level") or 1)))
            size = SZ_H1 if level == 1 else SZ_H2
            parts.append("<w:p><w:pPr><w:pStyle w:val=\"Heading%d\"/><w:keepNext/>"
                         '<w:spacing w:before="%d" w:after="%d" w:line="300" w:lineRule="auto"/>'
                         "<w:rPr><w:sz w:val=\"%d\"/></w:rPr></w:pPr>%s</w:p>"
                         % (level, 300 if level == 1 else 220, 120, size,
                            _run(block.get("text"), size=size, bold=True,
                                 color=THEME["ink"], east=FONT_EA)))
        elif kind == "para":
            parts.append(_para([_run(block.get("text"), size=SZ_BODY,
                                     color=THEME["muted"] if block.get("muted") else THEME["ink"])],
                               indent_chars=200 if block.get("indent") else 0,
                               align=block.get("align"), after=100))
        elif kind == "caption":
            parts.append(_para([_run(block.get("text"), size=SZ_CAPTION, bold=True,
                                     color=THEME["ink"])], before=200, after=60, keep_next=True))
        elif kind == "table":
            parts.append(_table(block.get("headers") or [], block.get("rows") or [],
                                ratios=block.get("ratios"), header_fill=block.get("header_fill")))
            if block.get("note"):
                parts.append(_para([_run(block["note"], size=SZ_CAPTION, color=THEME["muted"])],
                                   before=60, after=160))
        elif kind == "code":
            for line in str(block.get("text") or "").split("\n"):
                parts.append(_para([_run(line, size=SZ_TABLE, color=THEME["ink"])], align="left",
                                   before=0, after=0, line=240, shade=THEME["fill_soft"]))
            parts.append(_para([], after=0))
        elif kind == "pagebreak":
            parts.append(_para(['<w:r><w:br w:type="page"/></w:r>'], after=0))
        elif kind == "spacer":
            parts.append(_para([], after=int(block.get("size") or 120)))
    return "".join(parts)


def _styles():
    head1 = ('<w:pPr><w:keepNext/>'
             '<w:spacing w:before="300" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr>'
             '<w:rPr><w:rFonts w:ascii="%s" w:hAnsi="%s" w:eastAsia="%s"/><w:b/>'
             '<w:color w:val="%s"/><w:sz w:val="%d"/></w:rPr>'
             % (FONT_LATIN, FONT_LATIN, FONT_EA, THEME["ink"], SZ_H1))
    head2 = ('<w:pPr><w:keepNext/>'
             '<w:spacing w:before="240" w:after="100"/><w:outlineLvl w:val="1"/></w:pPr>'
             '<w:rPr><w:rFonts w:ascii="%s" w:hAnsi="%s" w:eastAsia="%s"/><w:b/>'
             '<w:color w:val="%s"/><w:sz w:val="%d"/></w:rPr>'
             % (FONT_LATIN, FONT_LATIN, FONT_EA, THEME["ink"], SZ_H2))
    head3 = ('<w:pPr><w:keepNext/>'
             '<w:spacing w:before="200" w:after="80"/><w:outlineLvl w:val="2"/></w:pPr>'
             '<w:rPr><w:rFonts w:ascii="%s" w:hAnsi="%s" w:eastAsia="%s"/><w:b/>'
             '<w:color w:val="%s"/><w:sz w:val="%d"/></w:rPr>'
             % (FONT_LATIN, FONT_LATIN, FONT_EA, THEME["ink"], SZ_TABLE))
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:styles xmlns:w="%s">'
            "<w:docDefaults><w:rPrDefault><w:rPr>"
            '<w:rFonts w:ascii="%s" w:hAnsi="%s" w:eastAsia="%s"/>'
            '<w:color w:val="%s"/><w:sz w:val="%d"/><w:szCs w:val="%d"/>'
            "</w:rPr></w:rPrDefault>"
            '<w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="320" w:lineRule="auto"/></w:pPr></w:pPrDefault>'
            "</w:docDefaults>"
            '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/>'
            "<w:qFormat/></w:style>"
            '<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/>'
            '<w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>%s</w:style>'
            '<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/>'
            '<w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>%s</w:style>'
            '<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/>'
            '<w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>%s</w:style>'
            "</w:styles>"
            % (W, FONT_LATIN, FONT_LATIN, FONT_EA, THEME["ink"], SZ_BODY, SZ_BODY,
               head1, head2, head3))


def _header():
    """页眉：一条横线。模板的正文页顶部那条线就是页眉的下框线。"""
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:hdr xmlns:w="%s" xmlns:r="%s">'
            '<w:p><w:pPr><w:pBdr><w:bottom w:val="single" w:sz="6" w:space="4" w:color="%s"/>'
            "</w:pBdr></w:pPr></w:p></w:hdr>" % (W, R, THEME["line"]))


def _field(name, size=SZ_CAPTION):
    """PAGE / NUMPAGES 这类域。中间那个 run 是 Word 没更新域之前显示的占位。"""
    run = ('<w:r><w:rPr><w:rFonts w:ascii="%s" w:hAnsi="%s" w:eastAsia="%s"/>'
           '<w:color w:val="%s"/><w:sz w:val="%d"/></w:rPr>%%s</w:r>'
           % (FONT_LATIN, FONT_LATIN, FONT_EA, THEME["muted"], size))
    return "".join([
        run % '<w:fldChar w:fldCharType="begin"/>',
        run % '<w:instrText xml:space="preserve"> %s </w:instrText>' % name,
        run % '<w:fldChar w:fldCharType="separate"/>',
        run % "<w:t>1</w:t>",
        run % '<w:fldChar w:fldCharType="end"/>',
    ])


def _footer():
    """页脚：居中页码。封面与目录用不带页眉页脚的节，所以这里只管正文页。"""
    tail = ('<w:r><w:rPr><w:rFonts w:ascii="%s" w:hAnsi="%s" w:eastAsia="%s"/>'
            '<w:color w:val="%s"/><w:sz w:val="%d"/></w:rPr>'
            '<w:t xml:space="preserve">%s</w:t></w:r>'
            % (FONT_LATIN, FONT_LATIN, FONT_EA, THEME["muted"], SZ_CAPTION, "%s"))
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:ftr xmlns:w="%s" xmlns:r="%s"><w:p><w:pPr><w:jc w:val="center"/></w:pPr>'
            % (W, R)
            + tail % "第 " + _field("PAGE") + tail % " 页　共 " + _field("NUMPAGES") + tail % " 页"
            + "</w:p></w:ftr>")


def _settings():
    """updateFields：打开文档时让 Word 重算目录页码与总页数。"""
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:settings xmlns:w="%s"><w:updateFields w:val="true"/>'
            '<w:compat><w:compatSetting w:name="compatibilityMode" '
            'w:uri="http://schemas.microsoft.com/office/word" w:val="15"/></w:compat>'
            "</w:settings>" % W)


def _document(body):
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:document xmlns:w="%s" xmlns:r="%s"><w:body>%s%s</w:body></w:document>'
            % (W, R, body, _sect("body", None)))


def build_docx(path, blocks, title="", author="", created=""):
    """把 block 列表写成 .docx，返回路径。"""
    core = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            "<dc:title>%s</dc:title><dc:creator>%s</dc:creator><cp:lastModifiedBy>%s</cp:lastModifiedBy>"
            "%s</cp:coreProperties>"
            % (_esc(title), _esc(author), _esc(author),
               '<dcterms:created xsi:type="dcterms:W3CDTF">%s</dcterms:created>' % _esc(created)
               if created else ""))
    content_types = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                     '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                     '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                     '<Default Extension="xml" ContentType="application/xml"/>'
                     '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                     '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
                     '<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>'
                     '<Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>'
                     '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
                     '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
                     "</Types>")
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            "</Relationships>")
    doc_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
                '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/>'
                '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>'
                '<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>'
                "</Relationships>")

    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as package:
        # [Content_Types].xml 放第一个：包规范建议如此，某些解包工具也认这个顺序
        package.writestr("[Content_Types].xml", content_types)
        package.writestr("_rels/.rels", rels)
        package.writestr("docProps/core.xml", core)
        package.writestr("word/document.xml", _document(_blocks_to_xml(blocks)))
        package.writestr("word/styles.xml", _styles())
        package.writestr("word/settings.xml", _settings())
        package.writestr("word/header1.xml", _header())
        package.writestr("word/footer1.xml", _footer())
        package.writestr("word/_rels/document.xml.rels", doc_rels)
    return path
