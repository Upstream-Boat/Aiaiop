#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Web目录爆破(内置Python)

走内置的 dirb_python()，不依赖系统装没装 dirb。词表三档 common/small/big，
传别的值会落到 common。目标统一过一遍 ensure_url()，这里不要再自己拼 http://。
"""


from registry import tool
from utils import ensure_url as _ensure_url
from helpers import *  # noqa: F401,F403


@tool(
    "dirb_scan",
    "Web目录爆破(内置Python)",
    {
        "properties": {
            "url": {
                "type": "string",
                "description": "URL",
                "default": None,
            },
            "wordlist": {
                "type": "string",
                "description": "common/small/big(common)",
                "default": "common",
            },
        },
        "required": ["url"],
    },
)
def dirb_scan_handler(params):
    return {"success":True,"returncode":0,"output":dirb_python(_ensure_url(params.get("url","")),params.get("wordlist","common"))}
