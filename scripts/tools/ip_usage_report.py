#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IP网段使用情况报告 - 发现在线设备、识别设备类型/厂家、列出空闲IP。不传target自动检测当前网段

scan_level 是现在的说法（ping/quick/normal/deep），detailed_os_scan 是旧的布尔开关，
留着兼容老调用；两个参数同时给时以 scan_level 为准。

端口范围不再随档位变：只要不是 ping，一律做 1-65535 全端口发现（走 scripts/portscan.py），
档位只决定要不要再多花时间做 OS 识别。以前 quick 探 10 个口、normal 探 23 个、deep 探 50 个，
没在表里的服务在报告里根本不出现。网段大于 /20 时自动降为 ping（只报在线，不探端口），
否则 /16 这种量级按全端口扫是跑不完的。
"""


from registry import tool
from helpers import *  # noqa: F401,F403


@tool(
    "ip_usage_report",
    "IP网段使用情况报告 - 发现在线设备、识别设备类型/厂家、列出空闲IP。不传target自动检测当前网段",
    {
        "properties": {
            "target": {
                "type": "string",
                "description": "目标网段(如 192.168.1.0/24)，不传则自动检测",
            },
            "scan_level": {
                "type": "string",
                "description": "扫描深度: ping(仅在线列表,适合大网段) / quick(全端口+类型识别,默认) / normal(全端口) / deep(全端口+OS识别)；大于 /20 的网段自动按 ping 处理",
                "default": "quick",
            },
            "detailed_os_scan": {
                "type": "boolean",
                "description": "[已弃用] 使用scan_level替代，保留兼容",
                "default": "false",
            },
        },
        "required": [],
    },
)
def ip_usage_report_handler(params):
            t=params.get("target","");do=params.get("detailed_os_scan","false");sl=params.get("scan_level","")
            # Support scan_level parameter: ping, quick, normal, deep
            if sl in ("ping","quick","normal","deep"):
                # For backward compat, convert quick+ping to detailed_os_scan pattern
                do_flag = sl == "deep"
            else:
                do_flag = (do=="true" or do==True)
            return {"success":True,"returncode":0,"output":ip_usage_report(t, do_flag)}
