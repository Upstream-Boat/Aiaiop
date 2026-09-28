#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""报告（reporter）— 产出 Word / HTML / PDF / Markdown / JSON，落在 data/runtime/reports/<run_id>/。

HTML 是主件，按交付出去的报告体例排：封面 → 目录 → 正文（综述信息 / 风险类别 / 风险清单 /
风险详情 / 脆弱凭据 / 参考标准）→ 附录（执行记录 / 审计链 / 原始输出）→ 声明。
章节号、表格样式、配色都对齐商用扫描器的主机报表，见 references/reports.md。

排版上刻意不用渐变、圆角胶囊和图标。这份东西是要打印、盖章、装订交给甲方的，
越像排版软件里出来的越合适；屏幕上的观感让位给纸面。

样式全部内联，不引外部字体、图标和脚本：报告常在离线内网机器上打开，缺一样都难看。
Word 与 HTML 是同一份数据的两个渲染器（Word 走 docx_writer），正文文案抽成了共用常量
（TXT_* 那几个），改一处两处都变 —— 交出去两份报告说法不一样，比少交一份更麻烦。

PDF 由同一份 HTML 转出，不存在"两份报告数字不一样"。
"""

import html
import json
import math
import os
import re
import time

from agents import docx_writer

from core import paths

# 出具单位 —— 与 skill-card.md 第 2 节的归属单位保持一致
ORG = "指尖未来（北京）信息技术有限公司"
CLASSIFICATION = "受控 · 内部资料"
REPORT_VERSION = "V1.0"

# 免责声明同时出现在封面页的责任声明与报告尾部，措辞保持一致
DISCLAIMER = ("本报告仅针对已获书面授权的目标出具，结论基于评估当时采集到的信息，不代表目标在任何时刻的绝对安全状态；未经授权不得向第三方提供。")

# 报告里的固定文案。HTML 和 Word 两份渲染器都从这里取字，
# 免得改一处忘一处，出现"同一轮任务两个格式的说法不一样"。
TXT_CONFIDENTIAL = ("本报告含评估对象的网络结构与服务信息，属受控资料。除评估委托方及其书面授权的第三方外，"
                    "不得复制、转发或以任何形式向其他方披露。报告使用完毕应按本单位涉密载体管理要求归档或销毁。")
TXT_LIABILITY = ("本报告的结论仅基于评估期间采集到的信息作出，不代表目标在任何时刻的绝对安全状态，"
                 "也不能覆盖评估范围之外、以及当时不可观测的隐蔽风险。评估动作均在书面授权范围内执行，"
                 "全过程写入审计链，可依据附录 B 复核。")
TXT_PURPOSE = ("按委托任务对目标开展资产发现与风险排查，确认对外暴露的服务与已知风险，形成可复核的结论，"
               "为后续整改与复测提供依据。")
TXT_SCOPE_NOTE = ("评估严格限定在上述范围内；范围之外的目标未做任何探测。任务中被安全策略拦下的高风险步骤"
                  "见附录 A，未经授权一律未执行。")
TXT_METHOD = ("评估按「判定 → 执行 → 复核 → 报告」四阶段推进。工具原始输出先经规则或模型复核，"
              "只保留输出中能直接看到证据的条目；凭推测成立的项目不予收录，避免把扫描噪声写成风险项。")
TXT_LEVELS = ("报告中的风险按可造成的直接影响定级，不以工具自身的告警级别为准。"
              "同一问题在不同环境下影响不同，处置时请结合业务重要性判断。")
TXT_REMEDIATION = ("建议按上表顺序推进：先改能直接导致失陷或数据泄露的问题，再收敛对外暴露面，"
                   "配置类问题并入版本迭代消化。同一主机上的多项问题合并为一次变更，减少业务中断次数。"
                   "整改完成后请在相同范围内复测，确认问题确已消除；未复测前，本报告的结论仍然有效。")
TXT_NO_FINDINGS_DETAIL = "本次评估未确认可归入本报告的风险项，无需逐条说明。执行过的工具与输出见附录 A、附录 C。"
TXT_NO_FINDINGS_FIX = ("本次评估未确认风险项，无整改条目。建议保持现有暴露面不变更，"
                       "并在下一次评估窗口复测。")
TXT_OUTPUT_HEAD = "下列内容为工具原始输出，仅作核对用，未经整理的输出不代表评估结论。"
TXT_REJECTED_HEAD = ("复核员给出的每一条结论，都由第二个判读源拿同一批原始工具输出重新核对过一遍。"
                     "证据在原始输出里找不到、或者定级没有依据支撑的条目，不进入风险清单，列在下表备查。"
                     "这类条目多来自模型对输出的过度解读，既不表示目标不存在该问题，也不表示排查已经覆盖到。")
TXT_AUDIT_HEAD = ("本轮任务的每一次工具调用与拦截均写入审计链，链上每一行包含前一行的哈希，"
                  "因此事后单独改写某条记录会破坏链的连续性。下表为出报告时对全链重新校验的结果。")

SEV_ORDER = ("critical", "high", "medium", "low", "info")
SEV_LABEL = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示"}

# 标签用（描边+淡底）与分布条用（实色）是两套色：标签要能打印后仍分得清，
# 实色块只出现在分布图上，饱和度可以高一些。
SEV_STYLE = {
    "critical": ("#8f1d1d", "#fbf1f1", "#c98a8a"),
    "high": ("#9a4a06", "#fdf4ea", "#dda86f"),
    "medium": ("#7a6207", "#fbf8e8", "#d6c476"),
    "low": ("#1f4f7a", "#eef5fb", "#9dbdd8"),
    "info": ("#4a5a6d", "#f3f5f7", "#c3ccd6"),
}
# Word 单元格里的档位文字色。与 HTML 标签同源，改一处即可。
SEV_INK = {key: style[0] for key, style in SEV_STYLE.items()}
SEV_BAR = {"critical": "#a32a2a", "high": "#c2691a", "medium": "#b39413",
           "low": "#2b6cab", "info": "#8b98a6"}

SEV_CRITERIA = {
    "critical": "可直接取得系统控制权或读取核心数据，或已确认可远程利用且影响范围不可控。",
    "high": "可被利用取得敏感权限或数据；在缺少其他防护措施时可导致系统失陷。",
    "medium": "需要特定前置条件才可利用，或仅造成有限的信息泄露与配置缺陷。",
    "low": "配置类问题与信息暴露，单独利用价值低，与其他问题组合后可放大影响。",
    "info": "仅作现状记录，不构成直接风险。",
}
SEV_DUE = {
    "critical": "立即处置（24 小时内）",
    "high": "3 个工作日内",
    "medium": "2 周内",
    "low": "随版本迭代",
    "info": "无需处置，留存记录",
}

# 加固建议按工具归类。写在报告里的建议必须是能从工具输出推出来的通用动作，
# 不能替甲方拍板业务改造，所以只到"关闭 / 收敛 / 升级 / 加认证"这一层。
_ADVICE_GROUPS = (
    (("nmap_scan", "masscan_scan", "ping_scan", "network_inspect", "network_survey",
      "ip_usage_report", "service_identify", "os_identify"),
     "确认该端口或服务的业务必要性：非必需的关闭，必需的限定访问来源并纳入变更管理。"),
    (("nikto_scan", "dirb_scan", "waf_detect"),
     "按条目逐项核实：升级 Web 组件到受支持版本，关闭目录浏览与示例页面，"
     "去掉响应头中的版本信息，必要时将后台入口限制到管理网段。"),
    (("nuclei_scan", "poc_runner_sm_por", "vuln_verify", "exploit_search"),
     "按模板或公告对应的修复方案升级受影响组件；暂时无法升级的，先加访问控制或用"
     "虚拟补丁挡住利用路径，修复后在相同范围复测确认。"),
    (("sqlmap_basic", "sqlmap_full"),
     "将拼接式 SQL 改为参数化查询（预编译语句），并对数据库账号按最小权限收敛，"
     "关闭不必要的报错回显。"),
    (("hydra_bruteforce", "hashcat_bruteforce", "passwd_dict_gen"),
     "提高口令复杂度与长度要求，启用登录失败锁定与多因素认证，禁用默认账号与弱口令。"),
    (("smb_enum", "impacket_secretsdump", "impacket_smbexec"),
     "关闭不必要的 SMB 共享与旧版本协议，启用 SMB 签名，限制 445 端口的可达范围。"),
    (("subdomain_enum",),
     "核对子域名的对外发布范围，下线的服务及时撤销解析记录，避免内部系统意外暴露。"),
    (("cve_match_sm_por",),
     "本地 CVE 库按产品名匹配，需先确认实际版本区间再判定影响；确认受影响的纳入补丁管理流程。"),
    (("kerberos_attack", "mimikatz_memory", "lateral_", "persist_install",
      "cleanup_trace", "db_data_extract", "file_extract", "revshell_handler"),
     "该结论涉及凭据或横向可达性，请结合内网分段与权限模型复核，并优先处理凭据轮换。"),
)
DEFAULT_ADVICE = "结合业务影响确认是否需要修复；确定修复的在整改完成后于相同范围复测确认。"


def _esc(text):
    """转义成 HTML。

    注意不要写成 `str(text or "")` —— 那会把 0、0.0、False 这些**假值也变成空字符串**，
    于是「耗时 0.0 秒」在报告里只剩一个 "s"。
    这里只把 None 当作空值。
    """
    if text is None:
        return ""
    return html.escape(str(text))


def _sev_key(severity):
    """严重级归一到五个已知档位。模型偶尔会给出 "moderate" 这类别名。"""
    key = str(severity or "").strip().lower()
    if key in SEV_ORDER:
        return key
    return {"moderate": "medium", "warning": "medium", "severe": "critical",
            "unknown": "info", "": "info"}.get(key, "info")


def _rank(severity):
    return SEV_ORDER.index(_sev_key(severity))


def _tag(severity):
    key = _sev_key(severity)
    fg, bg, border = SEV_STYLE[key]
    return ("<span class='tag' style='color:%s;background:%s;border-color:%s'>%s</span>"
            % (fg, bg, border, SEV_LABEL[key]))


# 交叉验证的结论着色。被推翻的（rejected）不进清单，所以这里只有两档：
# 确认 = 证据能回溯且定级有依据；存疑 = 证据在，但撑不起当前定级。
VERDICT_LABEL = {"confirmed": "确认", "disputed": "存疑"}
VERDICT_STYLE = {"confirmed": ("#1f5130", "#e7f2ea", "#a8cbb8"),
                 "disputed": ("#7a5b00", "#fdf6e1", "#dfca86")}


def _verdict_tag(finding):
    """交叉验证标记。没有 verdict 字段时返回空串 —— 直接调 reporter 的场景没有这一列。"""
    key = str(finding.get("verdict") or "").strip().lower()
    if key not in VERDICT_STYLE:
        return ""
    fg, bg, border = VERDICT_STYLE[key]
    return ("<span class='tag' style='color:%s;background:%s;border-color:%s'>%s</span>"
            % (fg, bg, border, VERDICT_LABEL[key]))


def _has_verdicts(findings):
    return any(str(item.get("verdict") or "").lower() in VERDICT_STYLE for item in findings)


def _verdict_text(review_result):
    """交叉验证那行统计。没跑 verifier（如直接调 reporter）时返回空串。"""
    text = (review_result or {}).get("verdicts")
    if not text:
        return ""
    source = (review_result or {}).get("verdict_source") or "-"
    return "%s（来源：%s）" % (_short(text, 120), source)


def _rejected_of(review_result):
    return (review_result or {}).get("rejected") or []


_USAGE_LABEL = (("backend", "推理后端"), ("model", "模型"), ("prompt_tokens", "输入"),
                ("completion_tokens", "输出"), ("total_tokens", "合计"),
                ("calls", "调用次数"), ("requests", "请求次数"))

# 后端名 → 报告里的写法。表里没有的原样显示英文名，不硬编一个中文出来。
BACKEND_LABEL = {"stepfun": "StepFun 阶跃星辰", "spark-local": "DGX Spark 本机模型",
                 "spark": "DGX Spark 本机模型", "gpustack": "GPUStack 算力集群"}


def _usage_text(usage):
    """把模型用量写成一句话。

    直接把用量字典 json.dumps 进报告太生硬 —— 这一栏是给甲方看的，不是给机器看的。
    """
    if not usage:
        return ""
    if not isinstance(usage, dict):
        return _short(usage, 160)
    bits = []
    for key, label in _USAGE_LABEL:
        value = usage.get(key)
        if value in (None, "", 0):
            continue
        if key == "backend":
            value = BACKEND_LABEL.get(str(value), value)
        unit = "" if key in ("backend", "model", "calls", "requests") else " tokens"
        bits.append("%s %s%s" % (label, value, unit))
    if bits:
        return "　｜　".join(bits)
    # 上游回了全零（拿到了 usage 但没真的计数）时，不能退化成 json 原文 ——
    # 这一栏是给甲方看的，一行机器格式的字典比空着更糟
    if all(usage.get(key) in (None, "", 0) for key, _ in _USAGE_LABEL):
        return ""
    return _short(usage, 160)


def _gpu_text(gpu):
    """算力归因写成一句话。

    峰值单独提出来：空闲时采到的 0% 没有信息量，看的是"推理真的把 GPU 用起来了"。
    """
    if not isinstance(gpu, dict):
        return ""
    text = gpu.get("line") or ""
    peak = gpu.get("peak_utilization_gpu")
    if peak:
        text += "%s推理峰值 %.0f%%" % ("　｜　" if text else "", peak)
    peak_power = gpu.get("peak_power_w")
    if peak_power and peak_power > (gpu.get("last") or {}).get("power_w", 0):
        text += "　｜　峰值功耗 %.1fW" % peak_power
    return text


def _advice(finding):
    title = str(finding.get("title") or "")
    if "未完成" in title:
        # 工具没跑完时套用该工具的加固建议是错的：本轮根本没拿到它的结论
        return "该步骤未跑完，本轮结论未覆盖该工具的检查范围；建议排查原因后在相同范围补测。"
    tool = str(finding.get("tool") or "")
    for tools, advice in _ADVICE_GROUPS:
        if tool in tools or any(tool.startswith(prefix) for prefix in tools if prefix.endswith("_")):
            return advice
    return DEFAULT_ADVICE


def _short(value, limit=140):
    """把参数之类的结构化数据压成一行，太长就截断 —— 表格里塞不下多行 JSON。"""
    if value is None:
        return ""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit] + "…"


def _cell(text, limit=200):
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:limit] + "…"


def _table(caption, headers, rows, note="", widths=None):
    """带表题的表格。

    表题在表上方，这是中文报告的习惯（图题在下、表题在上），顺序搞反了一眼就能看出是程序拼的。
    widths 给"序号""等级"这类窄列定宽：不指定宽度时，几毫米的列头会被挤成竖排两行。
    """
    out = ["<div class='tcap'>%s</div>" % _esc(caption)]
    # 给了列宽就用固定布局：不固定的话 weasyprint 会按内容再分配一次，窄列照样被撑宽
    out.append("<table class='grid%s'>" % (" fixed" if widths else ""))
    if widths:
        out.append("<colgroup>%s</colgroup>"
                   % "".join("<col style='width:%s'>" % _esc(w) if w else "<col>"
                             for w in widths))
    out.append("<thead><tr>%s</tr></thead><tbody>"
               % "".join("<th>%s</th>" % _esc(h) for h in headers))
    if rows:
        out.extend(rows)
    else:
        out.append("<tr><td colspan='%d' class='muted'>无记录</td></tr>" % len(headers))
    out.append("</tbody></table>")
    if note:
        out.append("<p class='muted'>%s</p>" % _esc(note))
    return "\n".join(out)



# ------------------------------------------------------------------ 统计口径

# 评估依据：固定三条，HTML 与 Word 共用
BASIS_ROWS = (
    "评估委托方提供的书面授权，授权范围以本报告第 1.1 节的评估对象为准",
    "sec-assessment 内置规则库：CVE 库、Exploit-DB、nuclei 模板、nmap OUI 表",
    "评估全过程审计链记录，校验方式见附录 B",
)

# 风险值只由"各等级风险条目数"加权得出，权重是扫描器报告里的公开口径：
#   严重 3 / 高危 2 / 中危 1 / 低危 0.5 / 提示 0，上限 10。
# 这套权重能把商用报告里"7 条低危 = 3.5 分"的数字对上，报告里每个数都能倒推。
RISK_WEIGHT = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5, "info": 0.0}

# 分档按商用报告的两级口径来：主机一级（单台机器上所有条目求和）、网络一级（整个评估
# 范围内求和）。两套区间的端点不同，报告里 6.2 / 6.3 两张表就是照这个写的，
# 改这里就得同步改表，不然会出现"分数对不上档位"。
HOST_BANDS = (
    ("非常危险", 7.0, 10.0),
    ("比较危险", 5.0, 7.0),
    ("比较安全", 2.0, 5.0),
    ("非常安全", 0.0, 2.0),
)
RISK_BANDS = (
    ("非常危险", 8.0, 10.0),
    ("比较危险", 5.0, 8.0),
    ("比较安全", 1.0, 5.0),
    ("非常安全", 0.0, 1.0),
)


# ------------------------------------------------------------------ 图表
#
# 报告常常在离线内网机器上打开、并且要直接打印装订，所以图表一律内联：
# 环形图是手写的 SVG（不引图表库），条形图是纯 HTML/CSS（weasyprint 转 PDF 最稳，
# flex/gap 在个别版本上会掉，所以这里用 float 排）。取色沿用正文的风险配色
# （SEV_BAR / BAND_TONE），保证"图上这一段"和"表里这一行"是同一个颜色。

# 主机档位 → 条形图取色，与 HOST_BANDS 的四档一一对应
BAND_TONE = {
    "非常危险": "#a32a2a",
    "比较危险": "#c2691a",
    "比较安全": "#b39413",
    "非常安全": "#2b6cab",
}


# 章节标题左侧的小图标。单色线条、跟正文同一个墨色（#1b609a），只起点缀和分区的作用：
# 放到纸面上不会喧宾夺主，缩到 15px 也还认得出来。图标内联在 HTML 里，
# 不引外部字体或图片 —— 报告常在离线内网机器上打开，缺一样都难看。
_ICON_PATHS = {
    "summary": "<path d='M6.5 3.5h8l4.5 4.5v12.5h-12.5z'/><path d='M14.5 3.5V8h4.5'/>"
               "<path d='M9.5 13h8M9.5 16.5h5.5'/>",
    "category": "<path d='M12 3.5V12h8.5'/><path d='M20.2 15.2A8.5 8.5 0 1 1 9.2 3.7'/>",
    "list": "<path d='M9 6.5h11M9 12h11M9 17.5h11'/><circle cx='4.6' cy='6.5' r='1.3'/>"
            "<circle cx='4.6' cy='12' r='1.3'/><circle cx='4.6' cy='17.5' r='1.3'/>",
    "detail": "<circle cx='10.8' cy='10.8' r='6.3'/><path d='M15.4 15.4L20.5 20.5'/>",
    "credential": "<circle cx='7.5' cy='12' r='3.6'/><path d='M11.1 12H20.5M17.6 12v3.1M14.8 12v2.2'/>",
    "standard": "<path d='M12 3.2l7.8 2.9v6.1c0 4.8-3.3 8.2-7.8 9.3-4.5-1.1-7.8-4.5-7.8-9.3V6.1z'/>"
                "<path d='M9.1 12l2.1 2.1 3.9-4.2'/>",
    "appendix": "<path d='M4 7h5.4l1.8 2H20v9.5H4z'/>",
    "statement": "<circle cx='12' cy='12' r='8.4'/><path d='M12 7.6v5.2M12 16.3h.01'/>",
}
_CHAPTER_ICONS = {"s1": "summary", "s2": "category", "s3": "list", "s4": "detail",
                  "s5": "credential", "s6": "standard", "sa": "appendix", "sb": "appendix",
                  "sc": "appendix", "sdd": "appendix", "sd": "statement"}
_CHAPTER_RE = re.compile(r"<h2 class=(['\"])ch\1 id=(['\"])([A-Za-z0-9-]+)\2>")


def _icon(name, size=16):
    paths = _ICON_PATHS.get(name or "")
    if not paths:
        return ""
    return ("<svg class='ico' viewBox='0 0 24 24' width='%d' height='%d' fill='none' "
            "stroke='#17568c' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round' "
            "xmlns='http://www.w3.org/2000/svg'>%s</svg>" % (size, size, paths))


def _with_chapter_icons(body):
    """给章节标题挂图标。

    统一后处理，而不是逐个改各章渲染函数 —— 章节函数有好几个出口
    （有发现/无发现各一套），漏改一处就会出现"这一章有图标、那一章没有"。
    """
    def replace(match):
        return match.group(0) + _icon(_CHAPTER_ICONS.get(match.group(3)))
    return _CHAPTER_RE.sub(replace, body)


def _n(value):
    """SVG 坐标保留两位小数并去掉浮点尾巴（1e-16 这类不能写进 path）。"""
    text = "%.2f" % float(value)
    text = text.rstrip("0").rstrip(".")
    return text or "0"


def _polar(cx, cy, radius, degrees):
    """极坐标转直角坐标。角度以正上方为 0°、顺时针为正。"""
    radians = math.radians(degrees - 90.0)
    return cx + radius * math.cos(radians), cy + radius * math.sin(radians)


def _ring_path(cx, cy, r_out, r_in, start, end):
    """一段扇环（donut segment）的 path。

    用 path 而不是 stroke-dasharray —— weasyprint 转 PDF 时前者更稳，
    后者在个别版本上会把 dash 算成整圈，图就花了。
    """
    large = 1 if (end - start) > 180.0 else 0
    xo1, yo1 = _polar(cx, cy, r_out, start)
    xo2, yo2 = _polar(cx, cy, r_out, end)
    xi2, yi2 = _polar(cx, cy, r_in, end)
    xi1, yi1 = _polar(cx, cy, r_in, start)
    return ("M%s %sA%s %s 0 %d 1 %s %sL%s %sA%s %s 0 %d 0 %s %sZ"
            % (_n(xo1), _n(yo1), _n(r_out), _n(r_out), large, _n(xo2), _n(yo2),
               _n(xi2), _n(yi2), _n(r_in), _n(r_in), large, _n(xi1), _n(yi1)))


def _donut_svg(counts, total, size=160):
    """风险等级分布环形图，中心是条目总数。

    只有一段时不留缝：留了会看到一个缺口，像图画错了。
    """
    if not total:
        return ""
    cx = cy = size / 2.0
    r_out = size / 2.0 - 1.0
    r_in = r_out * 0.60
    present = [key for key in SEV_ORDER if counts.get(key)]
    gap = 1.6 if len(present) > 1 else 0.0
    cursor = 0.0
    parts = []
    for key in SEV_ORDER:
        count = counts.get(key) or 0
        if not count:
            continue
        sweep = count * 360.0 / total
        if len(present) == 1:
            parts.append("<circle cx='%s' cy='%s' r='%s' fill='none' stroke='%s' stroke-width='%s'/>"
                         % (_n(cx), _n(cy), _n((r_out + r_in) / 2.0), SEV_BAR[key],
                            _n(r_out - r_in)))
        else:
            start = cursor + gap / 2.0
            end = cursor + sweep - gap / 2.0
            if end > start:
                parts.append("<path d='%s' fill='%s'/>"
                             % (_ring_path(cx, cy, r_out, r_in, start, end), SEV_BAR[key]))
        cursor += sweep
    return ("<svg class='donut' viewBox='0 0 %s %s' width='%s' height='%s' "
            "xmlns='http://www.w3.org/2000/svg' role='img' aria-label='风险等级分布'>%s"
            "<text x='%s' y='%s' text-anchor='middle' font-size='30' font-weight='700' "
            "fill='#122347'>%d</text>"
            "<text x='%s' y='%s' text-anchor='middle' font-size='12' fill='#5a6b7d'>风险项</text>"
            "</svg>"
            % (_n(size), _n(size), _n(size), _n(size), "".join(parts),
               _n(cx), _n(cy - 2), total, _n(cx), _n(cy + 15)))


def _donut_legend(counts, total):
    return "".join(
        "<li><i style='background:%s'></i>%s<b>%d</b><span class='pc'>%.0f%%</span></li>"
        % (SEV_BAR[key], SEV_LABEL[key], counts.get(key) or 0,
           (counts.get(key) or 0) * 100.0 / total if total else 0)
        for key in SEV_ORDER)


def _stacked_bars(rows, caption):
    """按风险类型 / 来源工具的堆叠条形图。

    条长代表该类的条目总数（按最多的一类归一），段色代表严重度构成，
    这样"哪一类问题最多、其中有多少是高危"一眼能看出来。
    """
    if not rows:
        return ""
    scale = max(row[2] for row in rows) or 1
    items = []
    for name, cells, total in rows:
        segments = "".join("<i style='width:%.4f%%;background:%s'></i>"
                           % (cell * 100.0 / scale, SEV_BAR[key])
                           for key, cell in zip(SEV_ORDER, cells) if cell)
        items.append("<li><span class='sb-name' title='%s'>%s</span>"
                     "<span class='sb-meta'>%d</span>"
                     "<span class='sb-track'>%s</span></li>"
                     % (_esc(name), _esc(name), total, segments))
    return "<div class='tcap'>%s</div><ul class='sbars'>%s</ul>" % (caption, "".join(items))


def _host_bars(groups):
    """各评估对象风险值横向条形图（长度按 0–10 的比例给，颜色按主机档位）。

    清单给的是"先看哪台"，这张图把顺序画出来，比只给一张表快。
    """
    groups = [group for group in groups if group[1]]
    if not groups:
        return ""
    rows = []
    for name, items, _worst in groups:
        score = _target_score(items)
        band = _risk_band(score, HOST_BANDS)
        tone = BAND_TONE.get(band, "#2b6cab")
        width = max(1.5, min(100.0, score * 10.0))
        rows.append("<li><span class='hb-name' title='%s'>%s</span>"
                    "<span class='hb-meta'><b>%.1f</b><em style='color:%s'>%s</em></span>"
                    "<span class='hb-track'><i style='width:%s%%;background:%s'></i></span></li>"
                    % (_esc(name), _esc(name), score, tone, _esc(band), _n(width), tone))
    return "<div class='tcap'>图 1-1　各评估对象风险值（主机档位）</div><ul class='hbars'>%s</ul>" % "".join(rows)


def _now_date(now):
    """2026-09-24 10:00:20 → 2026年09月24日，报告正文里的日期用中文写法。"""
    return now[:10].replace("-", "年", 1).replace("-", "月", 1) + "日"


def _elapsed_total(steps):
    total = 0.0
    for step in steps:
        try:
            total += float(step.get("elapsed") or 0)
        except (TypeError, ValueError):
            continue
    return round(total, 1)


def _counts(findings):
    counts = {key: 0 for key in SEV_ORDER}
    for finding in findings:
        counts[_sev_key(finding.get("severity"))] += 1
    return counts


def _risk_score(counts):
    """网络风险值，0-10。公式写在报告正文（第 6.3 节）里，不放在代码里当黑盒。"""
    total = sum(counts[key] * RISK_WEIGHT[key] for key in SEV_ORDER)
    return round(min(10.0, total), 1)


def _risk_band(score, bands=RISK_BANDS):
    """分数落在哪一档。分档表写在报告第 6.2 / 6.3 节，与这里同源。"""
    for label, low, high in bands:
        if low <= score <= high:
            return label
    return bands[-1][0]


def _target_score(items):
    """单台主机的风险值：把这台机器上的条目按同一套权重求和，同样封顶 10。"""
    return round(min(10.0, sum(RISK_WEIGHT[_sev_key(f.get("severity"))] for f in items)), 1)


def _category_of(finding):
    """风险类别。复核阶段给的 note 就是现成的分类，没有就按标题关键词兜一个。"""
    note = (finding.get("note") or "").strip()
    if note:
        return note
    title = str(finding.get("title") or "")
    for keyword, label in (("端口", "服务与端口"), ("CVE", "CVE 相关"), ("nuclei", "扫描模板命中"),
                           ("未完成", "扫描未完成")):
        if keyword in title:
            return label
    return "其他"


def _conclusion(counts, total, rejected=0):
    """评估结论那一段。HTML 与 Word 共用，别各写一份。"""
    # 被推翻的条目要在这句里点名：报告只在正文写"确认了几条"，不写"丢了几条"，
    # 甲方就无从判断这份清单是筛过的还是照抄的。
    if rejected:
        tail = "另有 %d 条经交叉验证推翻，未列入本报告，理由见附录 D。" % rejected
    else:
        tail = ""
    if not total:
        return ("本次评估在授权范围内未确认可归入本报告的风险项，执行过程见附录 A。"
                "需要说明的是，评估只覆盖当时可采集到的信息，未暴露在探测面上的风险不在本报告结论之内。"
                + (tail if rejected else ""))
    text = ("本次评估在授权范围内共确认风险 %d 项，其中严重 %d 项、高危 %d 项、中危 %d 项、"
            "低危 %d 项、提示 %d 项，明细见第 4 章。网络风险值 %.1f，判定为「%s」。"
            % (total, counts["critical"], counts["high"], counts["medium"], counts["low"],
               counts["info"], _risk_score(counts), _risk_band(_risk_score(counts))))
    if counts["critical"] or counts["high"]:
        return (text + tail
                + "其中严重与高危项具备现实可利用性，建议优先安排整改，按第 6.4 节的安全建议推进，整改完成后复测确认。")
    return text + tail + "本次未确认严重与高危风险，第 6.4 节的安全建议按常规版本迭代节奏安排即可。"


def _band_rows(name, bands):
    """把分档表写成"非常危险 | 7.0 ≤ 主机风险值 ≤ 10.0"这样的文字行。
    最高档用闭区间、其余用左闭右开 —— 与分档函数的比较方式一致。"""
    rows = []
    for index, (label, low, high) in enumerate(bands):
        right = "≤" if index == 0 else "<"
        rows.append((label, "%.1f ≤ %s %s %.1f" % (low, name, right, high)))
    return rows


def _level_rows():
    """风险等级评定标准的行，第 6.1 与附录共用。"""
    return [(key, SEV_CRITERIA[key], SEV_DUE[key]) for key in SEV_ORDER]


def _group_rows(findings, key_of):
    """按某个维度统计：分类｜严重｜高危｜中危｜低危｜提示｜合计。跟商用报告的统计表同构。"""
    buckets = {}
    for finding in findings:
        buckets.setdefault(key_of(finding), {key: 0 for key in SEV_ORDER})
        buckets[key_of(finding)][_sev_key(finding.get("severity"))] += 1
    rows = []
    for name in sorted(buckets, key=lambda item: (-sum(buckets[item].values()), str(item))):
        counts = buckets[name]
        cells = [counts[key] for key in SEV_ORDER]
        rows.append((name, cells, sum(cells)))
    return rows


# ------------------------------------------------------------------ 章节

def _cover(run_id, prompt, target, now_date, counts):
    scope = target or "（未指定）"
    score = _risk_score(counts)
    foot = [("报告编号", run_id), ("密级", CLASSIFICATION), ("风险值", "%.1f（%s）" % (score, _risk_band(score)))]
    return """<section class="cover">
  <div class="cover-org">%s</div>
  <h1 class="cover-title">安全评估报告</h1>
  <div class="cover-sub">评估对象：%s</div>
  <div class="cover-bottom">
    <div class="cover-rule"></div>
    <div class="cover-foot">%s</div>
    <div class="cover-foot">报告日期：%s</div>
  </div>
</section>""" % (_esc(ORG), _esc(scope),
                "　｜　".join("%s %s" % (_esc(key), _esc(value)) for key, value in foot),
                _esc(now_date))


def _toc():
    items = [("s1", "1　综述信息", 1), ("s11", "1.1　任务信息", 2), ("s12", "1.2　风险分布", 2),
             ("s13", "1.3　评估依据", 2),
             ("s2", "2　风险类别", 1), ("s21", "2.1　按风险类型统计", 2), ("s22", "2.2　按来源工具统计", 2),
             ("s3", "3　风险清单", 1),
             ("s4", "4　风险详情", 1),
             ("s5", "5　脆弱凭据", 1),
             ("s6", "6　参考标准", 1), ("s61", "6.1　单一风险等级评定标准", 2),
             ("s62", "6.2　主机风险等级评定标准", 2), ("s63", "6.3　网络风险等级评定标准", 2),
             ("s64", "6.4　安全建议", 2),
             ("sa", "附录 A　评估过程", 1), ("sb", "附录 B　审计链校验", 1),
             ("sc", "附录 C　原始输出", 1), ("sdd", "附录 D　交叉验证推翻的条目", 1),
             ("sd", "声明", 1)]
    rows = "".join(
        "<li class='lvl%d'><a href='#%s'><span class='t'>%s</span><span class='d'></span>"
        "<span class='p'></span></a></li>" % (level, anchor, _esc(title))
        for anchor, title, level in items)
    return "<h2 class='ch' id='s-toc'>目录</h2><ol class='toc'>%s</ol>" % rows


def _summary_chapter(prompt, target, plan_result, steps, findings, review_result, blocked,
                     usage, now, started, gpu=None):
    counts = _counts(findings)
    total = len(findings)
    score = _risk_score(counts)
    planned = len((plan_result or {}).get("steps") or [])
    elapsed = _elapsed_total(steps)
    usage_text = _usage_text(usage)
    names = _target_names(findings, target)

    task_rows = [
        "<tr><td class='k'>任务名称</td><td>%s</td></tr>" % _esc(_short(prompt, 80)),
        "<tr><td class='k'>评估对象</td><td>%s</td></tr>"
        % _esc(target or "（未指定）") if not names else
        "<tr><td class='k'>评估对象</td><td>%s（共 %d 个）</td></tr>" % (_esc(target or "（未指定）"), len(names)),
        "<tr><td class='k'>任务类型</td><td>安全评估（已授权）</td></tr>",
        "<tr><td class='k'>网络风险值</td><td>%.1f（%s）</td></tr>" % (score, _risk_band(score)),
        "<tr><td class='k'>风险条目</td><td>%d 项（严重 %d / 高危 %d / 中危 %d / 低危 %d / 提示 %d）</td></tr>"
        % (total, counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"]),
        "<tr><td class='k'>计划步骤</td><td>%d 项</td></tr>" % planned,
        "<tr><td class='k'>实际执行</td><td>%d 项（耗时 %s 秒）</td></tr>" % (len(steps), elapsed),
        "<tr><td class='k'>判定来源</td><td>%s</td></tr>" % _esc((plan_result or {}).get("source") or "-"),
        "<tr><td class='k'>复核来源</td><td>%s</td></tr>" % _esc(review_result.get("source") or "-"),
        "<tr><td class='k'>未执行步骤</td><td>%s</td></tr>"
        % ("%d 项（高风险动作未经显式授权，见附录 A）" % len(blocked) if blocked else "无"),
        "<tr><td class='k'>开始时间</td><td>%s</td></tr>" % _esc(started or "-"),
        "<tr><td class='k'>报告生成</td><td>%s</td></tr>" % _esc(now),
    ]
    if usage_text:
        task_rows.append("<tr><td class='k'>模型用量</td><td>%s</td></tr>" % _esc(usage_text))
    gpu_text = _gpu_text(gpu)
    if gpu_text:
        task_rows.append("<tr><td class='k'>算力环境</td><td>%s</td></tr>" % _esc(gpu_text))
    verdict_text = _verdict_text(review_result)
    if verdict_text:
        task_rows.append("<tr><td class='k'>交叉验证</td><td>%s</td></tr>" % _esc(verdict_text))
    task_table = _table("表 1-1　任务信息", ["项目", "内容"], task_rows, widths=("38mm", None))

    # 1.2.1 主机风险分布：每行一台主机，给出条目数、按同一套权重算出的主机风险值与等级
    targets = _target_rows(findings, target)
    target_table = _table("表 1-2　主机风险分布",
                          ["评估对象", "风险条目", "主机风险值", "主机风险等级", "主要问题"], targets,
                          widths=("30mm", "19mm", "26mm", "30mm", None))

    # 1.2.2 风险等级分布
    dist_rows = []
    for key in SEV_ORDER:
        count = counts[key]
        share = ("%.1f%%" % (count * 100.0 / total)) if total else "-"
        dist_rows.append("<tr><td class='ctr'>%s</td><td class='num'>%d</td><td class='num'>%s</td>"
                         "<td>%s</td></tr>" % (_tag(key), count, share, _esc(SEV_DUE[key])))
    if total:
        dist_rows.append("<tr><td class='ctr'>合计</td><td class='num'>%d</td><td class='num'>100%%</td>"
                         "<td>风险值 %.1f</td></tr>" % (total, score))
    else:
        # 零发现时"合计 100%"是假数字：占比的分母是 0，这里只留风险值
        dist_rows.append("<tr><td class='ctr'>合计</td><td class='num'>0</td><td class='num'>-</td>"
                         "<td>风险值 0.0</td></tr>")
    dist_table = _table("表 1-3　风险等级分布", ["等级", "数量", "占比", "建议处置时限"], dist_rows,
                        widths=("20mm", "18mm", "18mm", None))
    # 1.2.1 的条形图和 1.2.2 的环形图放在一起出：表给准确数字，图给一眼的顺序和占比
    host_bars = _host_bars(_target_groups(findings, target))
    bar = ""
    if total:
        bar = ("<div class='tcap'>图 1-2　风险等级分布</div>"
               "<div class='donut-wrap'>%s<ul class='donut-legend'>%s</ul></div>"
               % (_donut_svg(counts, total), _donut_legend(counts, total)))

    basis = _table("表 1-4　评估依据", ["序号", "依据"],
                   ["<tr><td class='ctr'>%d</td><td>%s</td></tr>" % (index, _esc(text))
                    for index, text in enumerate(BASIS_ROWS, 1)], widths=("16mm", None))

    # 开头先把结论说清楚：出报告的人先讲结果，再讲过程。
    scope = ("本次评估共涉及 %d 个评估对象（%s）" % (len(names), "、".join(names[:6]) + ("等" if len(names) > 6 else ""))
             if names else "本次评估针对 %s" % (target or "（未指定）"))
    if total:
        lead = ("%s，确认 %d 项风险，其中严重 %d、高危 %d；网络风险值 %.1f，属于%s。"
                % (scope, total, counts["critical"], counts["high"], score, _risk_band(score)))
    else:
        lead = ("%s，未确认可归入本报告的风险项，网络风险值 %.1f，属于%s。"
                % (scope, score, _risk_band(score)))

    blocked_note = ""
    if blocked:
        blocked_note = ("<p class='note'>本轮有 %d 个高风险步骤被安全策略拦下，未执行。被拦不代表目标不存在"
                        "对应问题，只说明该动作需要更明确的授权；明细见附录 A。</p>" % len(blocked))
    rejected = _rejected_of(review_result)
    rejected_note = ""
    if rejected:
        rejected_note = ("<p class='note'>交叉验证阶段共推翻 %d 条条目，未列入风险清单，逐条理由见附录 D。"
                         "被推翻不等于目标没有该问题，只说明本轮工具输出里找不到支撑该结论的证据。</p>"
                         % len(rejected))
    return """<h2 class="ch" id="s1">1　综述信息</h2>
<p>%s%s</p>
<h3 id="s11">1.1　任务信息</h3>
%s
<h3 id="s12">1.2　风险分布</h3>
<h4>1.2.1　主机风险分布</h4>
%s
%s
<h4>1.2.2　风险等级分布</h4>
%s
%s
%s
%s
<h3 id="s13">1.3　评估依据</h3>
<p>%s</p>
%s
%s""" % (_esc(lead), _esc(TXT_METHOD), task_table, target_table, host_bars,
         dist_table, bar, blocked_note, rejected_note, _esc(TXT_PURPOSE), basis,
         _esc(_conclusion(counts, total, len(rejected))))


def _target_rows(findings, target):
    """按目标聚合。模型复核给不出目标时，整轮归到本次评估对象名下。"""
    buckets = {}
    for finding in findings:
        name = finding.get("target") or target or "（未指定）"
        buckets.setdefault(name, [])
        buckets[name].append(finding)
    if not buckets:
        # 一条发现都没有时也要把目标列出来：写"无记录"会让人以为这台机器没扫过，
        # 而实际情况恰恰相反 —— 扫过了，只是没确认到风险。
        if target:
            return ["<tr><td>%s</td><td class='num'>0</td><td class='num'>0.0</td>"
                    "<td class='ctr'>非常安全</td><td>未确认到风险项</td></tr>" % _esc(target)]
        return []
    rows = []
    # 风险值高的排前面：清单给的是"先看哪台"的顺序
    for name in sorted(buckets, key=lambda item: (-_target_score(buckets[item]), -len(buckets[item]))):
        items = buckets[name]
        score = _target_score(items)
        worst = min(items, key=lambda f: _rank(f.get("severity")))
        rows.append("<tr><td>%s</td><td class='num'>%d</td><td class='num'>%.1f</td>"
                    "<td class='ctr'>%s</td><td>%s</td></tr>"
                    % (_esc(name), len(items), score, _risk_band(score, HOST_BANDS),
                       _esc(_cell(worst.get("title"), 60))))
    return rows


def _category_chapter(findings):
    def table_for(caption, key_of, key_header):
        rows = _group_rows(findings, key_of)
        body = ["<tr><td>%s</td>%s<td class='num'>%d</td></tr>"
                % (_esc(name), "".join("<td class='num'>%d</td>" % cell for cell in cells), total)
                for name, cells, total in rows]
        if rows:
            body.append("<tr><td>合计</td>%s<td class='num'>%d</td></tr>"
                        % ("".join("<td class='num'>%d</td>" % sum(row[1][i] for row in rows)
                                   for i in range(len(SEV_ORDER))),
                           sum(row[2] for row in rows)))
        return _table(caption, [key_header] + [SEV_LABEL[key] for key in SEV_ORDER] + ["合计"],
                      body, widths=("50mm",) + ("14mm",) * len(SEV_ORDER) + ("16mm",))

    if not findings:
        return """<h2 class="ch" id="s2">2　风险类别</h2>
<p class="muted">本次评估未确认风险项，无分类统计。</p>"""
    return """<h2 class="ch" id="s2">2　风险类别</h2>
<h3 id="s21">2.1　按风险类型统计</h3>
%s
%s
<h3 id="s22">2.2　按来源工具统计</h3>
%s
%s""" % (table_for("表 2-1　按风险类型统计", _category_of, "风险类型"),
         _stacked_bars(_group_rows(findings, _category_of), "图 2-1　按风险类型分布"),
         table_for("表 2-2　按来源工具统计", lambda f: f.get("tool") or "未知", "来源工具"),
         _stacked_bars(_group_rows(findings, lambda f: f.get("tool") or "未知"),
                       "图 2-2　按来源工具分布"))


def _list_chapter(findings, target=""):
    if not findings:
        return """<h2 class="ch" id="s3">3　风险清单</h2>
<p class="muted">本次评估未确认风险项，清单为空。</p>"""
    # 一次跑多个目标时，"这条在谁身上"是清单里最要紧的一列，必须带出来；
    # 单目标时省掉，免得每行都在重复同一个 IP。
    names = _target_names(findings, target)
    marks = _has_verdicts(findings)
    headers = (["序号", "风险名称", "等级"] + (["评估对象"] if names else [])
               + ["来源工具"] + (["交叉验证"] if marks else []) + ["证据摘要"])
    widths = (("12mm", None, "16mm") + (("26mm",) if names else ()) + ("34mm",)
              + (("18mm",) if marks else ()) + ("52mm",))
    rows = []
    for index, finding in enumerate(findings, 1):
        cells = ["<td class='ctr'>%d</td>" % index,
                 "<td>%s</td>" % _esc(_cell(finding.get("title"), 90)),
                 "<td class='ctr'>%s</td>" % _tag(finding.get("severity"))]
        if names:
            cells.append("<td><code>%s</code></td>" % _esc(finding.get("target") or target or "-"))
        cells.append("<td><code>%s</code></td>" % _esc(finding.get("tool") or "-"))
        if marks:
            cells.append("<td class='ctr'>%s</td>"
                         % (_verdict_tag(finding) or "<span class='muted'>—</span>"))
        cells.append("<td>%s</td>" % _esc(_cell(finding.get("evidence"), 70)))
        rows.append("<tr>%s</tr>" % "".join(cells))
    note = ("按风险等级由高到低排列；各目标上的条目数量与最高等级见第 1.2.1 节。"
            if names else "按风险等级由高到低排列，逐条说明见第 4 章。")
    if marks:
        note += "「交叉验证」为第二个判读源对同一批原始输出的复核结论，存疑项的证据在原始输出中可查，但不足"
        note += "以支撑当前定级，处置时请一并核对；被推翻的条目不列入本表，见附录 D。"
    return """<h2 class="ch" id="s3">3　风险清单</h2>
%s
<p class="muted">%s</p>""" % (_table("表 3-1　风险清单", headers, rows, widths=widths), _esc(note))


def _detail_chapter(findings, target=""):
    if not findings:
        return """<h2 class="ch" id="s4">4　风险详情</h2>
<p class="muted">本次评估未确认风险项，无需逐条说明。评估过程见附录 A，原始输出见附录 C。</p>"""
    names = _target_names(findings, target)
    blocks = []
    for index, finding in enumerate(findings, 1):
        key = _sev_key(finding.get("severity"))
        rows = []
        if names:
            rows.append("<tr><td class='k'>评估对象</td><td><code>%s</code></td></tr>"
                        % _esc(finding.get("target") or target or "-"))
        rows += [
            "<tr><td class='k'>风险等级</td><td>%s　%s</td></tr>" % (_tag(key), _esc(SEV_DUE[key])),
            "<tr><td class='k'>来源工具</td><td><code>%s</code></td></tr>" % _esc(finding.get("tool") or "-"),
        ]
        verdict = _verdict_tag(finding)
        if verdict:
            reason = finding.get("verdict_reason")
            rows.append("<tr><td class='k'>交叉验证</td><td>%s%s</td></tr>"
                        % (verdict, "　%s" % _esc(_cell(reason, 200)) if reason else ""))
        if finding.get("note"):
            rows.append("<tr><td class='k'>判定依据</td><td>%s</td></tr>" % _esc(finding["note"]))
        if finding.get("evidence"):
            rows.append("<tr><td class='k'>证据</td><td><code class='ev'>%s</code></td></tr>"
                        % _esc(finding["evidence"]))
        rows.append("<tr><td class='k'>加固建议</td><td>%s</td></tr>" % _esc(_advice(finding)))
        blocks.append("""<div class="finding" id="f%d">
<h4><span class="fno">4.%d</span>%s</h4>
%s
</div>""" % (index, index, _esc(_cell(finding.get("title"), 160)),
            _table("", ["项目", "内容"], rows, widths=("26mm", None)).replace(
                "<div class='tcap'></div>", "")))
    return "<h2 class='ch' id='s4'>4　风险详情</h2>" + "\n".join(blocks)


WEAK_TOOLS = ("hydra_bruteforce", "hashcat_bruteforce", "kerberos_attack", "impacket_secretsdump",
              "mimikatz_memory", "smb_enum", "passwd_dict_gen")


def _credential_chapter(findings):
    weak = [finding for finding in findings
            if finding.get("tool") in WEAK_TOOLS
            or any(word in str(finding.get("title") or "") for word in ("口令", "密码", "凭据", "爆破"))]
    if not weak:
        return """<h2 class="ch" id="s5">5　脆弱凭据</h2>
<p class="muted">本次评估未获取到可确认的脆弱凭据。若后续需要覆盖口令强度，请在授权范围内发起口令审计任务。</p>"""
    rows = ["<tr><td class='ctr'>%d</td><td>%s</td><td class='ctr'>%s</td><td><code>%s</code></td></tr>"
            % (index, _esc(_cell(item.get("title"), 80)), _tag(item.get("severity")),
               _esc(item.get("tool") or "-"))
            for index, item in enumerate(weak, 1)]
    return """<h2 class="ch" id="s5">5　脆弱凭据</h2>
%s
<p>口令类问题不单独给出明文，处置建议见第 6.4 节；涉及凭据轮换的，请在变更窗口内完成。</p>""" % _table(
        "表 5-1　脆弱凭据与口令类发现", ["序号", "风险名称", "等级", "来源工具"], rows,
        widths=("12mm", None, "16mm", "34mm"))


def _standard_chapter(findings):
    level_rows = ["<tr><td class='ctr'>%s</td><td>%s</td><td>%s</td></tr>"
                  % (_tag(key), _esc(criteria), _esc(due)) for key, criteria, due in _level_rows()]
    host_rows = ["<tr><td class='ctr'>%s</td><td>%s</td></tr>" % (_esc(label), _esc(rng))
                 for label, rng in _band_rows("主机风险值", HOST_BANDS)]
    band_rows = ["<tr><td class='ctr'>%s</td><td>%s</td></tr>" % (_esc(label), _esc(rng))
                 for label, rng in _band_rows("网络风险值", RISK_BANDS)]
    weight_rows = ["<tr><td class='ctr'>%s</td><td class='num'>%s</td></tr>"
                   % (SEV_LABEL[key], ("%g" % RISK_WEIGHT[key])) for key in SEV_ORDER]

    if findings:
        advice_rows = []
        for index, finding in enumerate(findings, 1):
            key = _sev_key(finding.get("severity"))
            advice_rows.append("<tr><td class='ctr'>%d</td><td>%s</td><td class='ctr'>%s</td><td>%s</td>"
                               "<td>%s</td></tr>"
                               % (index, _esc(_cell(finding.get("title"), 80)), _tag(key),
                                  _esc(_advice(finding)), _esc(SEV_DUE[key])))
        advice = _table("表 6-4　整改建议与优先级", ["序号", "风险项", "等级", "处置建议", "时限"],
                        advice_rows, widths=("11mm", "42mm", "14mm", None, "23mm"))
    else:
        advice = "<p class='muted'>%s</p>" % _esc(TXT_NO_FINDINGS_FIX)

    return """<h2 class="ch" id="s6">6　参考标准</h2>
<h3 id="s61">6.1　单一风险等级评定标准</h3>
%s
<p class="muted">%s</p>
<h3 id="s62">6.2　主机风险等级评定标准</h3>
%s
<p>主机风险值取该主机上各等级条目的加权之和，上限 10 分；等级按上表区间判定，四档从高到低依次为非常危险、比较危险、比较安全、非常安全。本次评估中各主机的取值见第 1.2.1 节。</p>
<h3 id="s63">6.3　网络风险等级评定标准</h3>
%s
<p>网络风险值取评估范围内全部条目的加权之和，同样上限 10 分，权重见下表；本次评估的网络风险值即按此口径计算。</p>
%s
<p class="muted">%s</p>
<h3 id="s64">6.4　安全建议</h3>
%s
<p>%s</p>""" % (_table("表 6-1　单一风险等级评定标准", ["等级", "判定依据", "建议处置时限"], level_rows,
                    widths=("18mm", None, "34mm")),
                _esc(TXT_LEVELS),
                _table("表 6-2　主机风险等级", ["主机风险等级", "主机风险值区间"], host_rows,
                       widths=("34mm", None)),
                _table("表 6-3　网络风险等级", ["网络风险等级", "网络风险值区间"], band_rows,
                       widths=("34mm", None)),
                _table("表 6-3a　风险值权重", ["等级", "权重"], weight_rows, widths=("30mm", "30mm")),
                _esc(TXT_LEVELS), advice, _esc(TXT_REMEDIATION))


def _appendix_steps(steps, blocked):
    rows = []
    for index, step in enumerate(steps, 1):
        status = "完成" if step.get("ok") else ("失败：%s" % _cell(step.get("error"), 60)
                                               if step.get("error") else "未执行")
        rows.append("<tr><td class='ctr'>%d</td><td><code>%s</code></td><td>%s</td><td>%s</td>"
                    "<td class='num'>%s</td></tr>"
                    % (index, _esc(step.get("tool")), _esc(_short(step.get("params"), 120)),
                       _esc(status), _esc(step.get("elapsed"))))
    out = ["<h2 class='ch' id='sa'>附录 A　评估过程</h2>",
           "<p>%s</p>" % _esc(TXT_METHOD),
           _table("表 A-1　工具执行记录", ["序号", "工具", "参数", "执行结果", "耗时（秒）"], rows,
                  widths=("11mm", "30mm", None, "34mm", "22mm"))]
    if blocked:
        brows = ["<tr><td class='ctr'>%d</td><td><code>%s</code></td><td>%s</td></tr>"
                 % (index, _esc(item.get("tool")), _esc(_cell(item.get("reason"), 160)))
                 for index, item in enumerate(blocked, 1)]
        out.append(_table("表 A-2　因安全策略未执行的步骤", ["序号", "工具", "拦截原因"], brows,
                          "被拦步骤不产生结论，也不代表目标不存在对应问题。", widths=("11mm", "30mm", None)))
    return "\n".join(out)


def _appendix_audit(audit_summary):
    rows = []
    for key, value, fingerprint in (audit_summary.get("rows") or []):
        cell = "<code>%s</code>" % _esc(fingerprint) if fingerprint else "<span class='muted'>—</span>"
        rows.append("<tr><td class='k'>%s</td><td>%s</td><td>%s</td></tr>" % (_esc(key), _esc(value), cell))
    return """<h2 class="ch" id="sb">附录 B　审计链校验</h2>
<p>%s</p>
%s
<p class="muted">复核方式：在 skill 目录执行 <code>python3 scripts/verify_audit.py</code>，
退出码为 0 表示未发现篡改，非 0 时会指出具体是哪一条记录对不上。</p>""" % (
        _esc(TXT_AUDIT_HEAD),
        _table("表 B-1　审计链校验结果", ["项目", "结果", "指纹"], rows, widths=("34mm", None, "40mm")))


def _appendix_outputs(steps):
    blocks = []
    for step in steps:
        output = (step.get("output") or "").strip()
        blocks.append("<details><summary><code>%s</code>　耗时 %s 秒　%s</summary><pre>%s</pre></details>"
                      % (_esc(step.get("tool")), _esc(step.get("elapsed")),
                         "输出已截断" if step.get("truncated") else "完整输出",
                         _esc(output[:4000] or "（无输出）")))
    if not blocks:
        blocks.append("<p class='muted'>本轮没有产生原始输出的步骤。</p>")
    return ("<h2 class='ch' id='sc'>附录 C　原始输出</h2>"
            "<p class='muted'>%s</p>" % _esc(TXT_OUTPUT_HEAD) + "\n".join(blocks))


def _appendix_rejected(rejected):
    """被推翻的条目单列一附。不留痕的做法是静默删掉，那样报告反而不可信：
    甲方看不到被筛掉的东西，就无从判断清单是筛过的还是漏的。"""
    if not rejected:
        return ""
    rows = []
    for index, item in enumerate(rejected, 1):
        rows.append("<tr><td class='ctr'>%d</td><td>%s</td><td class='ctr'>%s</td>"
                    "<td><code>%s</code></td><td>%s</td><td>%s</td></tr>"
                    % (index, _esc(_cell(item.get("title"), 90)),
                       _tag(item.get("severity")), _esc(item.get("tool") or "-"),
                       _esc(_cell(item.get("evidence"), 60)),
                       _esc(_cell(item.get("verdict_reason"), 160))))
    return """<h2 class="ch" id="sdd">附录 D　交叉验证推翻的条目</h2>
<p>%s</p>
%s""" % (_esc(TXT_REJECTED_HEAD),
         _table("表 D-1　被推翻的条目", ["序号", "原条目", "原定级", "来源工具", "原证据", "推翻理由"],
                rows, widths=("11mm", None, "16mm", "32mm", "44mm", "44mm")))


def _statement():
    return """<h2 class="ch" id="sd">声明</h2>
<h3>保密声明</h3>
<p>%s</p>
<h3>责任声明</h3>
<p>%s</p>""" % (_esc(TXT_CONFIDENTIAL), _esc(TXT_LIABILITY))


# ------------------------------------------------------------------ 样式
#
# 配色与版式对齐商用扫描器报告（绿盟 RSA/漏扫那套）：正文近墨蓝、表头浅蓝底、
# 表格浅蓝细边、章节标题加粗无框线、页眉一条横线、封面居中且底部留报告编号与日期。
# 改这里的时候 docx_writer.THEME 要一起改，两份报告出自同一个主题。

CSS = """
*{box-sizing:border-box}
body{margin:0;background:#e8ecf1;color:#122347;
  font:12.5px/1.8 "Microsoft YaHei","微软雅黑","PingFang SC",Arial,"Helvetica Neue",
  "Noto Sans CJK SC","Source Han Sans SC","WenQuanYi Zen Hei",sans-serif}
.page{max-width:210mm;margin:0 auto;background:#fff;padding:18mm 15mm 20mm;
  box-shadow:0 2px 16px rgba(20,35,60,.10)}
h1{margin:0}
p{margin:0 0 8px;text-align:justify}
.muted{color:#5a6b7d;font-size:12px}
a{color:#1b609a}
/* 封面：居中标题 + 底部信息，与商用报告一致 */
.cover{page:cover;page-break-after:always;break-after:page;height:236mm;position:relative;
  text-align:center;padding-top:34mm}
.cover-org{color:#5a6b7d;font-size:12.5px;letter-spacing:1px}
.cover-title{font-size:30px;font-weight:700;letter-spacing:6px;color:#122347;margin:120px 0 0}
.cover-sub{font-size:14px;color:#122347;margin-top:16px}
.cover-bottom{position:absolute;left:0;right:0;bottom:0;text-align:center}
.cover-rule{height:2px;background:#1b609a;margin-bottom:8px}
.cover-foot{font-size:12px;color:#5a6b7d;line-height:1.9}
/* 目录：点线 + 页码 */
.toc-page{page:toc;page-break-after:always;break-after:page}
ol.toc{list-style:none;margin:0;padding:0;font-size:12.5px}
ol.toc li{padding:3px 0}
ol.toc li.lvl2{padding-left:16px;font-size:12px}
ol.toc a{display:flex;align-items:baseline;text-decoration:none;color:#122347}
ol.toc a::after{content:target-counter(attr(href), page);margin-left:6px}
ol.toc .t{flex:0 0 auto}
ol.toc .d{flex:1 1 auto;border-bottom:1px dotted #9aa7b4;margin:0 6px;transform:translateY(-4px)}
/* 章节标题：加粗、无框线，阿拉伯编号 —— 商用报告的章节样式 */
h2.ch{font-size:15px;font-weight:700;color:#122347;margin:26px 0 10px;page-break-after:avoid}
h2.ch svg.ico{vertical-align:-2px;margin-right:5px}
h3{font-size:13px;font-weight:700;color:#122347;margin:16px 0 8px;page-break-after:avoid}
h4{font-size:12.5px;font-weight:700;color:#122347;margin:14px 0 6px;page-break-after:avoid}
/* 表格 */
.tcap{font-size:12px;font-weight:600;color:#122347;margin:12px 0 5px}
table.grid{width:100%;border-collapse:collapse;margin-bottom:4px}
table.grid.fixed{table-layout:fixed}
table.grid th,table.grid td{border:1px solid #9acae1;padding:6px 9px;font-size:12px;
  line-height:1.7;text-align:left;vertical-align:top;word-break:break-word}
table.grid thead th{background:#dcebf0;color:#122347;font-weight:700}
table.grid tbody tr:nth-child(even) td{background:#eaf5f9}
table.grid td.k{background:#dcebf0;font-weight:700;width:26mm}
table.grid td.num{text-align:right;font-variant-numeric:tabular-nums}
table.grid td.ctr{text-align:center;white-space:nowrap}
table.grid td.muted{color:#5a6b7d}
code{font-family:"SFMono-Regular",Menlo,Consolas,"Liberation Mono",monospace;font-size:11.5px}
code.ev{display:block;white-space:pre-wrap;word-break:break-all;background:#f4f8fb;
  border:1px solid #dbe7ee;border-radius:2px;padding:5px 7px;color:#33475e}
.tag{display:inline-block;font-size:11px;line-height:16px;padding:0 5px;border:1px solid;border-radius:2px;
  white-space:nowrap}
/* 分布图 */
.dist{display:flex;height:12px;border:1px solid #9acae1;overflow:hidden}
.dist i{display:block;height:100%}
.legend{list-style:none;margin:7px 0 0;padding:0;font-size:12px;color:#122347}
.legend li{display:inline-block;margin-right:16px}
.legend i{display:inline-block;width:9px;height:9px;margin-right:5px;border:1px solid rgba(0,0,0,.14)}
/* 图表：全部内联，离线打开与打印装订都不依赖外部资源 */
.donut-wrap{overflow:hidden;margin:6px 0 2px;padding:2px 0}
.donut-wrap svg.donut{float:left;margin:0 16px 0 2px}
ul.donut-legend{list-style:none;margin:6px 0 0;padding:0;font-size:12px;color:#122347;
  float:left;border-left:1px solid #dbe7ee;padding-left:14px}
ul.donut-legend li{padding:2px 0;white-space:nowrap}
ul.donut-legend i{display:inline-block;width:9px;height:9px;margin-right:6px;
  border:1px solid rgba(0,0,0,.14)}
ul.donut-legend b{display:inline-block;min-width:22px;text-align:right;
  font-variant-numeric:tabular-nums;margin-left:8px}
ul.donut-legend .pc{display:inline-block;min-width:32px;text-align:right;color:#5a6b7d;margin-left:6px}
ul.sbars{list-style:none;margin:4px 0 6px;padding:0;font-size:12px;color:#122347}
ul.sbars li{overflow:hidden;padding:3px 0}
.sb-name{float:left;width:56mm;margin-right:6px;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.sb-meta{float:right;width:12mm;text-align:right;font-variant-numeric:tabular-nums}
.sb-track{display:block;overflow:hidden;height:11px;background:#eef2f6;
  border:1px solid #dbe7ee;margin:2px 18mm 2px 62mm}
.sb-track i{display:block;float:left;height:100%}
ul.hbars{list-style:none;margin:4px 0 6px;padding:0;font-size:12px;color:#122347}
ul.hbars li{overflow:hidden;padding:2px 0}
.hb-name{float:left;width:34mm;margin-right:6px;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.hb-meta{float:right;width:38mm;text-align:right}
.hb-meta b{font-variant-numeric:tabular-nums;font-weight:700;margin-right:7px}
.hb-meta em{font-style:normal}
.hb-track{display:block;overflow:hidden;height:10px;background:#eef2f6;
  border:1px solid #dbe7ee;margin:3px 44mm 3px 40mm}
.hb-track i{display:block;height:100%}
/* 风险详情 */
.finding{margin:14px 0;page-break-inside:avoid}
.finding h4{font-size:13px;margin:0 0 6px}
.finding .fno{color:#5a6b7d;margin-right:6px}
.finding table.grid td.k{width:26mm}
/* 附录 */
details{border:1px solid #9acae1;border-radius:2px;margin:6px 0;page-break-inside:avoid}
details>summary{cursor:pointer;padding:6px 10px;font-size:12px;color:#1b609a;background:#f4f8fb}
details pre{margin:0;padding:10px;background:#fbfdfe;border-top:1px solid #9acae1;color:#33475e;
  font-size:11.5px;line-height:1.6;white-space:pre-wrap;word-break:break-all}
.note{font-size:12px;color:#122347;border-left:3px solid #9acae1;background:#f4f8fb;
  padding:6px 10px;margin:10px 0}
/* 分页：封面与目录不编页，正文页眉横线 + 页脚页码 */
@page{size:A4;margin:16mm 15mm 18mm}
@page cover{@top-right{content:none}@bottom-center{content:none}}
@page toc{@top-right{content:none}@bottom-center{content:none}}
@page{
  @top-right{content:"安全评估报告";font-size:9pt;color:#5a6b7d;vertical-align:bottom;
    border-bottom:.75pt solid #9acae1;width:100%;padding-bottom:2mm}
  @bottom-center{content:"第 " counter(page) " 页　共 " counter(pages) " 页";font-size:9pt;color:#5a6b7d}
}
@media print{
  body{background:#fff;font-size:10.5pt;line-height:1.7}
  .page{max-width:none;margin:0;padding:0;box-shadow:none}
  .cover{height:243mm}
  table.grid th,table.grid td{font-size:9.5pt;padding:4px 6px}
  h2.ch{font-size:12pt}h3{font-size:11pt}
  code,details pre{font-size:9pt}
  ul.hbars li,ul.sbars li,ul.donut-legend{font-size:9pt}
  .sb-name{width:48mm}.sb-track{margin:2px 16mm 2px 54mm}
  .hb-name{width:30mm}.hb-track{margin:3px 40mm 3px 36mm}.hb-meta{width:35mm}
  a{color:inherit;text-decoration:none}
  table.grid tr,.finding,details{page-break-inside:avoid}
}
"""


def _html_document(run_id, prompt, target, plan_result, steps, findings, review_result,
                   audit_summary, blocked, usage, now, started, gpu=None):
    body = _with_chapter_icons("\n".join([
        _cover(run_id, prompt, target, _now_date(now), _counts(findings)),
        "<section class='toc-page'>", _toc(), "</section>",
        _summary_chapter(prompt, target, plan_result, steps, findings, review_result,
                         blocked, usage, now, started, gpu=gpu),
        _category_chapter(findings),
        _list_chapter(findings, target),
        _detail_chapter(findings, target),
        _credential_chapter(findings),
        _standard_chapter(findings),
        _appendix_steps(steps, blocked or []),
        _appendix_audit(audit_summary),
        _appendix_outputs(steps),
        _appendix_rejected(_rejected_of(review_result)),
        _statement(),
    ]))
    return """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>安全评估报告　%s</title>
<style>%s</style></head>
<body><div class="page">
%s
</div></body></html>""" % (_esc(target or "未指定目标"), CSS, body)


# ------------------------------------------------------------------ Word

def _docx_blocks(run_id, prompt, target, plan_result, steps, findings, review_result,
                 audit_summary, blocked, usage, now, started, gpu=None):
    """与 HTML 同一份数据、同一套章节，交给 docx_writer 渲染。"""
    docx = docx_writer
    counts = _counts(findings)
    total = len(findings)
    score = _risk_score(counts)
    band = _risk_band(score)
    planned = len((plan_result or {}).get("steps") or [])
    elapsed = _elapsed_total(steps)
    usage_text = _usage_text(usage)
    now_date = _now_date(now)
    names = _target_names(findings, target)

    def sev_cell(key):
        return docx.cell(SEV_LABEL[key], bold=True, color=SEV_INK[key], align="center")

    blocks = [{
        "type": "cover", "org": ORG, "title": "安全评估报告",
        "subtitle": "评估对象：%s" % (target or "（未指定）"),
        "foot": [("报告编号", run_id), ("密级", CLASSIFICATION),
                 ("风险值", "%.1f（%s）" % (score, band)), ("报告日期", now_date)],
    }, {"type": "section", "kind": "plain"}]
    blocks.append({"type": "toc", "entries": [
        ("1　综述信息", 1), ("1.1　任务信息", 2), ("1.2　风险分布", 2), ("1.3　评估依据", 2),
        ("2　风险类别", 1), ("2.1　按风险类型统计", 2), ("2.2　按来源工具统计", 2),
        ("3　风险清单", 1), ("4　风险详情", 1), ("5　脆弱凭据", 1),
        ("6　参考标准", 1), ("6.1　单一风险等级评定标准", 2), ("6.2　主机风险等级评定标准", 2),
        ("6.3　网络风险等级评定标准", 2), ("6.4　安全建议", 2),
        ("附录 A　评估过程", 1), ("附录 B　审计链校验", 1), ("附录 C　原始输出", 1),
        ("附录 D　交叉验证推翻的条目", 1), ("声明", 1)]})
    blocks.append({"type": "section", "kind": "plain"})

    # 1 综述信息
    task_rows = [[docx.key_cell("任务名称"), docx.cell(_short(prompt, 80))],
                 [docx.key_cell("评估对象"),
                  docx.cell("%s（共 %d 个）" % (target or "（未指定）", len(names)) if names
                            else (target or "（未指定）"))],
                 [docx.key_cell("任务类型"), docx.cell("安全评估（已授权）")],
                 [docx.key_cell("网络风险值"), docx.cell("%.1f（%s）" % (score, band))],
                 [docx.key_cell("风险条目"), docx.cell("%d 项（严重 %d / 高危 %d / 中危 %d / 低危 %d / 提示 %d）"
                                                   % (total, counts["critical"], counts["high"],
                                                      counts["medium"], counts["low"], counts["info"]))],
                 [docx.key_cell("计划步骤"), docx.cell("%d 项" % planned)],
                 [docx.key_cell("实际执行"), docx.cell("%d 项（耗时 %s 秒）" % (len(steps), elapsed))],
                 [docx.key_cell("判定来源"), docx.cell((plan_result or {}).get("source") or "-")],
                 [docx.key_cell("复核来源"), docx.cell(review_result.get("source") or "-")],
                 [docx.key_cell("未执行步骤"),
                  docx.cell("%d 项（高风险动作未经显式授权，见附录 A）" % len(blocked) if blocked else "无")],
                 [docx.key_cell("开始时间"), docx.cell(started or "-")],
                 [docx.key_cell("报告生成"), docx.cell(now)]]
    if usage_text:
        task_rows.append([docx.key_cell("模型用量"), docx.cell(usage_text)])
    gpu_text = _gpu_text(gpu)
    if gpu_text:
        task_rows.append([docx.key_cell("算力环境"), docx.cell(gpu_text)])
    verdict_text = _verdict_text(review_result)
    if verdict_text:
        task_rows.append([docx.key_cell("交叉验证"), docx.cell(verdict_text)])

    target_rows = [[docx.cell(name), docx.cell(str(len(items)), align="right"),
                    docx.cell("%.1f" % _target_score(items), align="right"),
                    docx.cell(_risk_band(_target_score(items), HOST_BANDS), align="center"),
                    docx.cell(_cell(worst.get("title"), 60))]
                   for name, items, worst in _target_groups(findings, target)]
    dist_rows = [[sev_cell(key), docx.cell(str(counts[key]), align="right"),
                  docx.cell("%.1f%%" % (counts[key] * 100.0 / total) if total else "-", align="right"),
                  docx.cell(SEV_DUE[key])] for key in SEV_ORDER]
    total_share = "100%" if total else "-"
    dist_rows.append([docx.cell("合计", bold=True, align="center"),
                      docx.cell(str(total), bold=True, align="right"),
                      docx.cell(total_share, bold=True, align="right"),
                      docx.cell("风险值 %.1f" % score, bold=True)])
    basis_rows = [[docx.cell(str(index), align="center"), docx.cell(text)]
                  for index, text in enumerate(BASIS_ROWS, 1)]

    if names:
        scope = "本次评估共涉及 %d 个评估对象（%s）" % (
            len(names), "、".join(names[:6]) + ("等" if len(names) > 6 else ""))
    else:
        scope = "本次评估针对 %s" % (target or "（未指定）")
    if total:
        lead = ("%s，确认 %d 项风险，其中严重 %d、高危 %d；网络风险值 %.1f，属于%s。"
                % (scope, total, counts["critical"], counts["high"], score, band))
    else:
        lead = ("%s，未确认可归入本报告的风险项，网络风险值 %.1f，属于%s。"
                % (scope, score, band))

    blocks += [{"type": "heading", "text": "1　综述信息", "level": 1},
               {"type": "para", "text": lead + TXT_METHOD},
               {"type": "heading", "text": "1.1　任务信息", "level": 2},
               {"type": "table", "headers": ["项目", "内容"], "rows": task_rows, "ratios": (1, 3)},
               {"type": "heading", "text": "1.2　风险分布", "level": 2},
               {"type": "heading", "text": "1.2.1　主机风险分布", "level": 3},
               {"type": "table", "headers": ["评估对象", "风险条目", "主机风险值", "主机风险等级", "主要问题"],
                "rows": target_rows, "ratios": (3, 1, 1.4, 1.6, 4)},
               {"type": "heading", "text": "1.2.2　风险等级分布", "level": 3},
               {"type": "table", "headers": ["等级", "数量", "占比", "建议处置时限"],
                "rows": dist_rows, "ratios": (1.2, 1, 1, 2.4)},
               {"type": "heading", "text": "1.3　评估依据", "level": 2},
               {"type": "para", "text": TXT_PURPOSE},
               {"type": "table", "headers": ["序号", "依据"], "rows": basis_rows, "ratios": (1, 9)},
               {"type": "para", "text": _conclusion(counts, total, len(_rejected_of(review_result)))}]
    if blocked:
        blocks.append({"type": "para", "text": "本轮有 %d 个高风险步骤被安全策略拦下，未执行。"
                                               "被拦不代表目标不存在对应问题，只说明该动作需要更明确的授权；"
                                               "明细见附录 A。" % len(blocked)})
    if _rejected_of(review_result):
        blocks.append({"type": "para", "text": "交叉验证阶段共推翻 %d 条条目，未列入风险清单，"
                                               "逐条理由见附录 D。被推翻不等于目标没有该问题，"
                                               "只说明本轮工具输出里找不到支撑该结论的证据。"
                                               % len(_rejected_of(review_result))})

    # 2 风险类别
    blocks.append({"type": "heading", "text": "2　风险类别", "level": 1})
    if findings:
        for index, (caption, key_of, header) in enumerate(
                (("表 2-1　按风险类型统计", _category_of, "风险类型"),
                 ("表 2-2　按来源工具统计", lambda f: f.get("tool") or "未知", "来源工具")), 1):
            rows = _group_rows(findings, key_of)
            body = [[docx.cell(name)] + [docx.cell(str(cell), align="right") for cell in cells]
                    + [docx.cell(str(total), align="right")] for name, cells, total in rows]
            body.append([docx.cell("合计", bold=True)]
                        + [docx.cell(str(sum(row[1][i] for row in rows)), bold=True, align="right")
                           for i in range(len(SEV_ORDER))]
                        + [docx.cell(str(sum(row[2] for row in rows)), bold=True, align="right")])
            blocks += [{"type": "heading", "text": "2.%d　%s" % (index, header.replace("来源工具", "按来源工具").replace("风险类型", "按风险类型")), "level": 2},
                       {"type": "caption", "text": caption},
                       {"type": "table", "headers": [header] + [SEV_LABEL[key] for key in SEV_ORDER] + ["合计"],
                        "rows": body, "ratios": (4, 1, 1, 1, 1, 1, 1.2)}]
    else:
        blocks.append({"type": "para", "text": "本次评估未确认风险项，无分类统计。", "muted": True})

    # 3 风险清单
    blocks.append({"type": "heading", "text": "3　风险清单", "level": 1})
    if findings:
        marks = _has_verdicts(findings)
        list_rows = []
        for index, finding in enumerate(findings, 1):
            row = [docx.cell(str(index), align="center"), docx.cell(_cell(finding.get("title"), 90)),
                   sev_cell(_sev_key(finding.get("severity")))]
            if names:
                row.append(docx.cell(finding.get("target") or target or "-"))
            row.append(docx.cell(finding.get("tool") or "-"))
            if marks:
                row.append(docx.cell(VERDICT_LABEL.get(str(finding.get("verdict") or "").lower(),
                                                       "—"), align="center"))
            row.append(docx.cell(_cell(finding.get("evidence"), 70)))
            list_rows.append(row)
        headers = (["序号", "风险名称", "等级"] + (["评估对象"] if names else []) + ["来源工具"]
                   + (["交叉验证"] if marks else []) + ["证据摘要"])
        ratios = ((0.8, 4, 1.2) + ((2.6,) if names else ()) + (2.2,)
                  + ((1.4,) if marks else ()) + (3.4,))
        blocks += [{"type": "caption", "text": "表 3-1　风险清单"},
                   {"type": "table", "headers": headers, "rows": list_rows, "ratios": ratios},
                   {"type": "para", "text": "按风险等级由高到低排列；各目标上的条目数量与最高等级"
                                            "见第 1.2.1 节。" if names else
                                            "按风险等级由高到低排列，逐条说明见第 4 章。", "muted": True}]
    else:
        blocks.append({"type": "para", "text": "本次评估未确认风险项，清单为空。", "muted": True})

    # 4 风险详情
    blocks.append({"type": "heading", "text": "4　风险详情", "level": 1})
    if findings:
        for index, finding in enumerate(findings, 1):
            key = _sev_key(finding.get("severity"))
            rows = []
            if names:
                rows.append([docx.key_cell("评估对象"),
                             docx.cell(finding.get("target") or target or "-")])
            rows += [[docx.key_cell("风险等级"), docx.cell("%s　%s" % (SEV_LABEL[key], SEV_DUE[key]),
                                                        color=SEV_INK[key], bold=True)],
                     [docx.key_cell("来源工具"), docx.cell(finding.get("tool") or "-")]]
            verdict_key = str(finding.get("verdict") or "").lower()
            if verdict_key in VERDICT_LABEL:
                reason = finding.get("verdict_reason")
                rows.append([docx.key_cell("交叉验证"),
                             docx.cell("%s%s" % (VERDICT_LABEL[verdict_key],
                                                 "　%s" % _cell(reason, 200) if reason else ""))])
            if finding.get("note"):
                rows.append([docx.key_cell("判定依据"), docx.cell(finding["note"])])
            rows.append([docx.key_cell("加固建议"), docx.cell(_advice(finding))])
            blocks.append({"type": "heading", "text": "4.%d　%s" % (index, _cell(finding.get("title"), 160)),
                           "level": 3})
            if finding.get("evidence"):
                blocks.append({"type": "code", "text": str(finding["evidence"])})
            blocks.append({"type": "table", "headers": [], "rows": rows, "ratios": (1.4, 5)})
    else:
        blocks.append({"type": "para", "text": "本次评估未确认风险项，无需逐条说明。"
                                               "评估过程见附录 A，原始输出见附录 C。", "muted": True})

    # 5 脆弱凭据
    weak = _weak_findings(findings)
    blocks.append({"type": "heading", "text": "5　脆弱凭据", "level": 1})
    if weak:
        rows = [[docx.cell(str(index), align="center"), docx.cell(_cell(item.get("title"), 80)),
                 sev_cell(_sev_key(item.get("severity"))), docx.cell(item.get("tool") or "-")]
                for index, item in enumerate(weak, 1)]
        blocks += [{"type": "caption", "text": "表 5-1　脆弱凭据与口令类发现"},
                   {"type": "table", "headers": ["序号", "风险名称", "等级", "来源工具"], "rows": rows,
                    "ratios": (0.8, 5, 1.2, 2.4)},
                   {"type": "para", "text": "口令类问题不单独给出明文，处置建议见第 6.4 节；"
                                            "涉及凭据轮换的，请在变更窗口内完成。"}]
    else:
        blocks.append({"type": "para", "text": "本次评估未获取到可确认的脆弱凭据。若后续需要覆盖口令强度，"
                                               "请在授权范围内发起口令审计任务。", "muted": True})

    # 6 参考标准
    level_rows = [[sev_cell(key), docx.cell(criteria), docx.cell(due)]
                  for key, criteria, due in _level_rows()]
    host_rows = [[docx.cell(label, bold=True), docx.cell(rng)]
                 for label, rng in _band_rows("主机风险值", HOST_BANDS)]
    band_rows = [[docx.cell(label, bold=True), docx.cell(rng)]
                 for label, rng in _band_rows("网络风险值", RISK_BANDS)]
    weight_rows = [[sev_cell(key), docx.cell("%g" % RISK_WEIGHT[key], align="right")] for key in SEV_ORDER]
    blocks += [{"type": "heading", "text": "6　参考标准", "level": 1},
               {"type": "heading", "text": "6.1　单一风险等级评定标准", "level": 2},
               {"type": "caption", "text": "表 6-1　单一风险等级评定标准"},
               {"type": "table", "headers": ["等级", "判定依据", "建议处置时限"], "rows": level_rows,
                "ratios": (1.2, 5, 2.4)},
               {"type": "para", "text": TXT_LEVELS, "muted": True},
               {"type": "heading", "text": "6.2　主机风险等级评定标准", "level": 2},
               {"type": "caption", "text": "表 6-2　主机风险等级"},
               {"type": "table", "headers": ["主机风险等级", "主机风险值区间"], "rows": host_rows,
                "ratios": (2, 6)},
               {"type": "para", "text": "主机风险值取该主机上各等级条目的加权之和，上限 10 分；等级按上表"
                                        "区间判定，四档从高到低依次为非常危险、比较危险、比较安全、非常安全。"
                                        "本次评估中各主机的取值见第 1.2.1 节。"},
               {"type": "heading", "text": "6.3　网络风险等级评定标准", "level": 2},
               {"type": "caption", "text": "表 6-3　网络风险等级"},
               {"type": "table", "headers": ["网络风险等级", "网络风险值区间"], "rows": band_rows,
                "ratios": (2, 6)},
               {"type": "para", "text": "网络风险值取评估范围内全部条目的加权之和，同样上限 10 分，"
                                        "权重见下表；本次评估的网络风险值即按此口径计算。"},
               {"type": "table", "headers": ["等级", "权重"], "rows": weight_rows, "ratios": (2, 2)},
               {"type": "heading", "text": "6.4　安全建议", "level": 2}]
    if findings:
        advice_rows = [[docx.cell(str(index), align="center"), docx.cell(_cell(f.get("title"), 80)),
                        sev_cell(_sev_key(f.get("severity"))), docx.cell(_advice(f)),
                        docx.cell(SEV_DUE[_sev_key(f.get("severity"))])]
                       for index, f in enumerate(findings, 1)]
        blocks += [{"type": "caption", "text": "表 6-4　整改建议与优先级"},
                   {"type": "table", "headers": ["序号", "风险项", "等级", "处置建议", "时限"],
                    "rows": advice_rows, "ratios": (0.8, 4, 1.2, 6, 2.4)}]
    else:
        blocks.append({"type": "para", "text": TXT_NO_FINDINGS_FIX, "muted": True})
    blocks.append({"type": "para", "text": TXT_REMEDIATION})

    # 附录
    step_rows = [[docx.cell(str(index), align="center"), docx.cell(step.get("tool") or "-"),
                  docx.cell(_short(step.get("params"), 120)),
                  docx.cell("完成" if step.get("ok") else ("失败：%s" % _cell(step.get("error"), 60)
                                                          if step.get("error") else "未执行")),
                  docx.cell(str(step.get("elapsed")), align="right")]
                 for index, step in enumerate(steps, 1)]
    blocks += [{"type": "heading", "text": "附录 A　评估过程", "level": 1},
               {"type": "para", "text": TXT_METHOD},
               {"type": "caption", "text": "表 A-1　工具执行记录"},
               {"type": "table", "headers": ["序号", "工具", "参数", "执行结果", "耗时（秒）"],
                "rows": step_rows, "ratios": (0.8, 2.4, 4.4, 3.2, 1.4)}]
    if blocked:
        brows = [[docx.cell(str(index), align="center"), docx.cell(item.get("tool") or "-"),
                  docx.cell(_cell(item.get("reason"), 160))]
                 for index, item in enumerate(blocked, 1)]
        blocks += [{"type": "caption", "text": "表 A-2　因安全策略未执行的步骤"},
                   {"type": "table", "headers": ["序号", "工具", "拦截原因"], "rows": brows,
                    "ratios": (0.8, 2.4, 8)},
                   {"type": "para", "text": "被拦步骤不产生结论，也不代表目标不存在对应问题。", "muted": True}]

    audit_rows = [[docx.key_cell(key), docx.cell(value), docx.cell(fingerprint or "—")]
                  for key, value, fingerprint in (audit_summary.get("rows") or [])]
    blocks += [{"type": "heading", "text": "附录 B　审计链校验", "level": 1},
               {"type": "para", "text": TXT_AUDIT_HEAD},
               {"type": "caption", "text": "表 B-1　审计链校验结果"},
               {"type": "table", "headers": ["项目", "结果", "指纹"], "rows": audit_rows,
                "ratios": (2, 5, 3)},
               {"type": "para", "text": "复核方式：在 skill 目录执行 python3 scripts/verify_audit.py，"
                                        "退出码为 0 表示未发现篡改，非 0 时会指出具体是哪一条记录对不上。",
                "muted": True},
               {"type": "heading", "text": "附录 C　原始输出", "level": 1},
               {"type": "para", "text": TXT_OUTPUT_HEAD, "muted": True}]
    for step in steps:
        blocks += [{"type": "caption", "text": "%s（耗时 %s 秒）" % (step.get("tool"), step.get("elapsed"))},
                   {"type": "code", "text": (step.get("output") or "").strip()[:4000] or "（无输出）"}]
    if not steps:
        blocks.append({"type": "para", "text": "本轮没有产生原始输出的步骤。", "muted": True})
    rejected = _rejected_of(review_result)
    if rejected:
        rejected_rows = [[docx.cell(str(index), align="center"),
                          docx.cell(_cell(item.get("title"), 90)),
                          sev_cell(_sev_key(item.get("severity"))),
                          docx.cell(item.get("tool") or "-"),
                          docx.cell(_cell(item.get("evidence"), 60)),
                          docx.cell(_cell(item.get("verdict_reason"), 160))]
                         for index, item in enumerate(rejected, 1)]
        blocks += [{"type": "heading", "text": "附录 D　交叉验证推翻的条目", "level": 1},
                   {"type": "para", "text": TXT_REJECTED_HEAD},
                   {"type": "caption", "text": "表 D-1　被推翻的条目"},
                   {"type": "table",
                    "headers": ["序号", "原条目", "原定级", "来源工具", "原证据", "推翻理由"],
                    "rows": rejected_rows, "ratios": (0.8, 4, 1.2, 2.2, 3.6, 3.6)}]
    blocks += [{"type": "heading", "text": "声明", "level": 1},
               {"type": "para", "text": TXT_CONFIDENTIAL},
               {"type": "para", "text": TXT_LIABILITY}]
    return blocks


def _target_names(findings, target):
    """本次报告涉及的目标名。单个目标时为空 —— 整份报告只讲一台机器，
    清单里再加一列"评估对象"是重复。"""
    names = []
    for finding in findings:
        name = finding.get("target") or target or "（未指定）"
        if name not in names:
            names.append(name)
    if len(names) <= 1 and (target or names):
        return []
    return names


def _target_groups(findings, target):
    buckets = {}
    for finding in findings:
        name = finding.get("target") or target or "（未指定）"
        buckets.setdefault(name, []).append(finding)
    groups = []
    if not buckets:
        if target:
            return [(target, [], {"severity": "info", "title": "未确认到风险项"})]
        return []
    # 与表 1-2 同序：风险值高的排前面
    for name in sorted(buckets, key=lambda item: (-_target_score(buckets[item]), -len(buckets[item]))):
        items = buckets[name]
        groups.append((name, items, min(items, key=lambda f: _rank(f.get("severity")))))
    return groups


def _weak_findings(findings):
    return [finding for finding in findings
            if finding.get("tool") in WEAK_TOOLS
            or any(word in str(finding.get("title") or "") for word in ("口令", "密码", "凭据", "爆破"))]


# ------------------------------------------------------------------ 入口

def pdf_enabled():
    """要不要顺手出一份 PDF。默认要，`SEC_ASSESSMENT_PDF=0` 关掉。"""
    return str(os.environ.get("SEC_ASSESSMENT_PDF", "1")).lower() not in ("0", "false", "no")


def _write_pdf(html_path, pdf_path):
    """把 HTML 报告转成 PDF。

    weasyprint 不是标准库、离线机器上常常没有 —— 缺了就当没有这一步，
    绝不能因为它把整轮任务的报告搞失败（HTML 本身已经是完整交付物）。
    """
    try:
        from weasyprint import HTML
    except Exception:                              # noqa: BLE001 - 缺库/缺系统依赖都算没装
        # 现场机器（含 DGX Spark）要交付 PDF，得先备齐 pango/cairo 这套系统依赖；
        # 没备齐就退回到"用浏览器打印同一份 HTML"——@page 规则已经按 A4 排好，打印出来是一样的。
        return ""
    try:
        HTML(filename=html_path).write_pdf(pdf_path)
        return pdf_path
    except Exception:                              # noqa: BLE001 - 渲染失败也不影响 HTML
        return ""


def _markdown(run_id, prompt, target, plan_result, steps, findings, review_result,
              audit_summary, blocked, usage, now, started, gpu=None):
    counts = _counts(findings)
    total = len(findings)
    score = _risk_score(counts)
    lines = [
        "# 安全评估报告", "",
        "| 项目 | 内容 |", "| --- | --- |",
        "| 报告编号 | %s |" % run_id,
        "| 密级 | %s |" % CLASSIFICATION,
        "| 编制单位 | %s |" % ORG,
        "| 评估对象 | %s |" % (target or "（未指定）"),
        "| 任务来源 | %s |" % prompt,
        "| 网络风险值 | %.1f（%s） |" % (score, _risk_band(score)),
        "| 生成时间 | %s |" % now, "",
        "## 1　综述信息", "",
        "### 1.1　任务信息", "",
        "| 项目 | 内容 |", "| --- | --- |",
        "| 计划步骤 | %d 项 |" % len((plan_result or {}).get("steps") or []),
        "| 实际执行 | %d 项（耗时 %s 秒） |" % (len(steps), _elapsed_total(steps)),
        "| 判定来源 | %s |" % ((plan_result or {}).get("source") or "-"),
        "| 复核来源 | %s |" % (review_result.get("source") or "-"),
        "| 未执行步骤 | %s |" % ("%d 项" % len(blocked) if blocked else "无"),
        "| 开始时间 | %s |" % (started or "-"),
        "| 模型用量 | %s |" % (_usage_text(usage) or "-"), "",
        "### 1.2　风险分布", "",
        "| 等级 | 数量 | 占比 | 建议处置时限 |", "| --- | --- | --- | --- |",
    ]
    # 算力环境与交叉验证都插在任务信息表的末尾（模型用量之后）：一个是这轮烧了多少算力，
    # 一个是这一轮的判读口径，两者都跟"复核来源"挨着看才有意义
    tail_rows = []
    if _gpu_text(gpu):
        tail_rows.append("| 算力环境 | %s |" % _gpu_text(gpu))
    verdict_text = _verdict_text(review_result)
    if verdict_text:
        tail_rows.append("| 交叉验证 | %s |" % verdict_text)
    if tail_rows:
        for position, text in enumerate(lines):
            if text.startswith("| 模型用量 |"):
                lines[position + 1:position + 1] = tail_rows
                break
    names = _target_names(findings, target)
    for key in SEV_ORDER:
        lines.append("| %s | %d | %s | %s |"
                     % (SEV_LABEL[key], counts[key],
                        ("%.1f%%" % (counts[key] * 100.0 / total)) if total else "-", SEV_DUE[key]))
    lines += ["| 合计 | %d | %s | 风险值 %.1f |"
              % (total, "100%" if total else "-", score), ""]
    groups = _target_groups(findings, target)
    if groups:
        lines += ["| 评估对象 | 风险条目 | 主机风险值 | 主机风险等级 | 主要问题 |",
                  "| --- | --- | --- | --- | --- |"]
        for name, items, worst in groups:
            items_score = _target_score(items)
            lines.append("| %s | %d | %.1f | %s | %s |"
                         % (name, len(items), items_score, _risk_band(items_score, HOST_BANDS),
                            _cell(worst.get("title"), 60)))
        lines.append("")
    lines += ["### 1.3　评估依据", "",
              "评估目的：%s" % TXT_PURPOSE, ""]
    for index, text in enumerate(BASIS_ROWS, 1):
        lines.append("%d. %s" % (index, text))
    if blocked:
        lines += ["", "本轮有 %d 个高风险步骤被安全策略拦下，未执行；明细见附录 A。" % len(blocked)]
    rejected = _rejected_of(review_result)
    if rejected:
        lines += ["", "交叉验证阶段共推翻 %d 条条目，未列入风险清单，逐条理由见附录 D。"
                  % len(rejected)]
    lines += ["", _conclusion(counts, total, len(rejected)), "", "## 2　风险类别", ""]
    if findings:
        for caption, key_of, header in (("表 2-1　按风险类型统计", _category_of, "风险类型"),
                                        ("表 2-2　按来源工具统计", lambda f: f.get("tool") or "未知", "来源工具")):
            lines += ["### %s" % caption.split("　", 1)[1], "",
                      "| %s | %s | 合计 |" % (header, " | ".join(SEV_LABEL[key] for key in SEV_ORDER)),
                      "| --- | --- | --- | --- | --- | --- | --- |"]
            for name, cells, row_total in _group_rows(findings, key_of):
                lines.append("| %s | %s | %d |" % (name, " | ".join(str(c) for c in cells), row_total))
            lines.append("")
    else:
        lines += ["本次评估未确认风险项，无分类统计。", ""]
    lines += ["## 3　风险清单", ""]
    if findings:
        marks = _has_verdicts(findings)
        head = ("| 序号 | 风险名称 | 等级 |" + (" 评估对象 |" if names else "") + " 来源工具 |"
                + (" 交叉验证 |" if marks else ""))
        rule = ("| --- | --- | --- |" + (" --- |" if names else "") + " --- |"
                + (" --- |" if marks else ""))
        lines += [head, rule]
        for index, finding in enumerate(findings, 1):
            mid = (" `%s` |" % (finding.get("target") or target or "-")) if names else ""
            mark = (" %s |" % VERDICT_LABEL.get(str(finding.get("verdict") or "").lower(), "—")
                    if marks else "")
            lines.append("| %d | %s | %s |%s `%s` |%s"
                         % (index, _cell(finding.get("title"), 90),
                            SEV_LABEL[_sev_key(finding.get("severity"))], mid,
                            finding.get("tool") or "-", mark))
    else:
        lines.append("本次评估未确认风险项，清单为空。")
    lines += ["", "## 4　风险详情", ""]
    if not findings:
        lines.append("本次评估未确认风险项，无需逐条说明。")
    for index, finding in enumerate(findings, 1):
        key = _sev_key(finding.get("severity"))
        lines += ["### 4.%d　%s" % (index, finding.get("title")), ""]
        if names:
            lines.append("- 评估对象：`%s`" % (finding.get("target") or target or "-"))
        lines += ["- 风险等级：%s（%s）" % (SEV_LABEL[key], SEV_DUE[key]),
                  "- 来源工具：`%s`" % (finding.get("tool") or "-")]
        verdict_key = str(finding.get("verdict") or "").lower()
        if verdict_key in VERDICT_LABEL:
            reason = finding.get("verdict_reason")
            lines.append("- 交叉验证：%s%s" % (VERDICT_LABEL[verdict_key],
                                             "（%s）" % reason if reason else ""))
        if finding.get("note"):
            lines.append("- 判定依据：%s" % finding["note"])
        if finding.get("evidence"):
            lines += ["", "证据：", "", "```", str(finding["evidence"]), "```"]
        lines += ["", "加固建议：%s" % _advice(finding), ""]
    lines += ["## 5　脆弱凭据", ""]
    weak = _weak_findings(findings)
    if weak:
        lines += ["| 序号 | 风险名称 | 等级 | 来源工具 |", "| --- | --- | --- | --- |"]
        for index, item in enumerate(weak, 1):
            lines.append("| %d | %s | %s | `%s` |"
                         % (index, _cell(item.get("title"), 80),
                            SEV_LABEL[_sev_key(item.get("severity"))], item.get("tool") or "-"))
    else:
        lines.append("本次评估未获取到可确认的脆弱凭据。")
    lines += ["", "## 6　参考标准", "", "### 6.1　单一风险等级评定标准", "",
              "| 等级 | 判定依据 | 建议处置时限 |", "| --- | --- | --- |"]
    for key, criteria, due in _level_rows():
        lines.append("| %s | %s | %s |" % (SEV_LABEL[key], criteria, due))
    lines += ["", "### 6.2　主机风险等级评定标准", "",
              "| 主机风险等级 | 主机风险值区间 |", "| --- | --- |"]
    for label, rng in _band_rows("主机风险值", HOST_BANDS):
        lines.append("| %s | %s |" % (label, rng))
    lines += ["", "### 6.3　网络风险等级评定标准", "",
              "网络风险值 = Σ(各等级条目数 × 权重)，上限 10 分；本次为 %.1f（%s）。"
              % (score, _risk_band(score)), "",
              "| 网络风险等级 | 网络风险值区间 |", "| --- | --- |"]
    for label, rng in _band_rows("网络风险值", RISK_BANDS):
        lines.append("| %s | %s |" % (label, rng))
    lines += ["", "| 等级 | 权重 |", "| --- | --- |"]
    for key in SEV_ORDER:
        lines.append("| %s | %g |" % (SEV_LABEL[key], RISK_WEIGHT[key]))
    lines += ["", "### 6.4　安全建议", "", "| 序号 | 风险项 | 等级 | 处置建议 | 时限 |",
              "| --- | --- | --- | --- | --- |"]
    for index, finding in enumerate(findings, 1):
        key = _sev_key(finding.get("severity"))
        lines.append("| %d | %s | %s | %s | %s |"
                     % (index, _cell(finding.get("title"), 60), SEV_LABEL[key], _advice(finding),
                        SEV_DUE[key]))
    lines += ["", TXT_REMEDIATION, "", "## 附录 A　评估过程", "",
              "| 序号 | 工具 | 参数 | 执行结果 | 耗时（秒） |", "| --- | --- | --- | --- | --- |"]
    for index, step in enumerate(steps, 1):
        lines.append("| %d | `%s` | %s | %s | %s |"
                     % (index, step.get("tool"), _short(step.get("params"), 100),
                        "完成" if step.get("ok") else "失败", step.get("elapsed")))
    if blocked:
        lines += ["", "因安全策略未执行的步骤：", ""]
        for item in blocked:
            lines.append("- `%s`：%s" % (item.get("tool"), item.get("reason")))
    lines += ["", "## 附录 B　审计链校验", ""]
    for key, value, fingerprint in (audit_summary.get("rows") or []):
        lines.append("- %s：%s%s" % (key, value, ("（%s）" % fingerprint) if fingerprint else ""))
    lines += ["", "## 附录 C　原始输出", ""]
    for step in steps:
        lines += ["### %s（耗时 %s 秒）" % (step.get("tool"), step.get("elapsed")), "",
                  "```", (step.get("output") or "").strip()[:4000] or "（无输出）", "```", ""]
    if rejected:
        lines += ["## 附录 D　交叉验证推翻的条目", "", TXT_REJECTED_HEAD, "",
                  "| 序号 | 原条目 | 原定级 | 来源工具 | 原证据 | 推翻理由 |",
                  "| --- | --- | --- | --- | --- | --- |"]
        for index, item in enumerate(rejected, 1):
            lines.append("| %d | %s | %s | `%s` | %s | %s |"
                         % (index, _cell(item.get("title"), 90),
                            SEV_LABEL[_sev_key(item.get("severity"))], item.get("tool") or "-",
                            _cell(item.get("evidence"), 60),
                            _cell(item.get("verdict_reason"), 160)))
        lines.append("")
    lines += ["## 声明", "", TXT_CONFIDENTIAL, "", TXT_LIABILITY]
    return "\n".join(lines)


def build(run_id, prompt, target, plan_result, steps, review_result, audit_summary,
          usage=None, pdf=True, blocked=None, started="", gpu=None):
    """生成报告文件，返回路径字典。

    四份同源：HTML 是主件（自包含、离线可开、可直接打印），PDF 由它转出，
    Word 走标准库拼的 OOXML（不引第三方库），Markdown / JSON 给工单系统与归档。
    正文文案在 TXT_* 常量里，改一处各格式一起变，不会出现两份报告说法不一样。
    """
    folder = paths.report_dir(run_id)
    os.makedirs(folder, exist_ok=True)
    findings = sorted(review_result.get("findings") or [], key=lambda f: _rank(f.get("severity")))
    blocked = blocked or []
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    counts = _counts(findings)
    payload = {
        "run_id": run_id, "report_no": run_id, "title": prompt,
        "org": ORG, "classification": CLASSIFICATION, "report_version": REPORT_VERSION,
        "target": target or "(未指定)",
        "generated_at": now, "started_at": started, "plan": plan_result,
        "risk_score": _risk_score(counts), "risk_level": _risk_band(_risk_score(counts)),
        "steps": [{"tool": s.get("tool"), "params": s.get("params"), "ok": s.get("ok"),
                   "elapsed": s.get("elapsed"), "error": s.get("error")} for s in steps],
        "blocked": blocked,
        "findings": findings, "severity_counts": counts,
        "summary": review_result.get("summary"),
        "review_source": review_result.get("source"),
        "verification": {"summary": review_result.get("verdicts") or "",
                         "source": review_result.get("verdict_source") or "",
                         "rejected": review_result.get("rejected") or []},
        "usage": usage, "gpu": gpu, "audit": audit_summary,
        "disclaimer": DISCLAIMER,
    }
    json_path = os.path.join(folder, "report.json")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)

    md_path = os.path.join(folder, "report.md")
    with open(md_path, "w", encoding="utf-8") as handle:
        handle.write(_markdown(run_id, prompt, target, plan_result, steps, findings,
                               review_result, audit_summary, blocked, usage, now, started,
                               gpu=gpu))

    html_path = os.path.join(folder, "report.html")
    with open(html_path, "w", encoding="utf-8") as handle:
        handle.write(_html_document(run_id, prompt, target, plan_result, steps, findings,
                                    review_result, audit_summary, blocked, usage, now, started,
                                    gpu=gpu))

    # 报告头里带标题与编制单位，用 Word 打开时属性页不会是空的
    docx_path = os.path.join(folder, "report.docx")
    docx_writer.build_docx(
        docx_path,
        _docx_blocks(run_id, prompt, target, plan_result, steps, findings, review_result,
                     audit_summary, blocked, usage, now, started, gpu=gpu),
        title="安全评估报告 %s" % (target or ""), author=ORG,
        created=time.strftime("%Y-%m-%dT%H:%M:%SZ"))

    # PDF 是从 HTML 转的：同源同内容，不会出现"两份报告数字对不上"。
    pdf_path = ""
    if pdf and pdf_enabled():
        pdf_path = _write_pdf(html_path, os.path.join(folder, "report.pdf"))

    return {"html": html_path, "md": md_path, "json": json_path, "docx": docx_path,
            "pdf": pdf_path, "findings": len(findings)}
