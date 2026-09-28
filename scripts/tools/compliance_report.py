#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""[等保三级] 生成合规安全检查报告 - 汇总端口/漏洞/基线结果，输出等保对照整改建议

这个入口本身不做检测，只把前几步（端口、漏洞、基线）的结论收拢成一张等保对照表。
单独跑它只会得到一份空骨架，要有内容得先有前面几轮扫描的结果。
"""


from registry import tool
from helpers import *  # noqa: F401,F403


@tool(
    "compliance_report",
    "[等保三级] 生成合规安全检查报告 - 汇总端口/漏洞/基线结果，输出等保对照整改建议",
    {
        "properties": {
            "target": {
                "type": "string",
                "description": "网段(如 192.168.1.0/24)",
            },
        },
        "required": ["target"],
    },
)
def compliance_report_handler(params):
    return compliance_report(params.get("target",""))
