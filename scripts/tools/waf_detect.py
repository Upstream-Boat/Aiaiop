#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WAF/IDS/IPS检测 - 使用wafw00f识别Web应用防火墙品牌，辅助选择WAF绕过策略

wafw00f -a 会把全部指纹过一遍。timeout 被压到最多 30s：wafw00f 自己内部会重试，
给太长反而让上层误以为卡死。
"""


from registry import tool
from utils import run_cmd
from helpers import *  # noqa: F401,F403


@tool(
    "waf_detect",
    "WAF/IDS/IPS检测 - 使用wafw00f识别Web应用防火墙品牌，辅助选择WAF绕过策略",
    {
        "properties": {
            "url": {
                "type": "string",
                "description": "目标URL（带协议，如 https://example.com）",
            },
            "timeout": {
                "type": "integer",
                "description": "超时秒数（默认60）",
                "default": 60,
            },
        },
        "required": ["url"],
    },
)
def waf_detect_handler(params):
            url = params.get("url","")
            timeout = int(params.get("timeout",60))
            return run_cmd(f"wafw00f -a '{url}' -t {min(timeout,30)}", timeout)
