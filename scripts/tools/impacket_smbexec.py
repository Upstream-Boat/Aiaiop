#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SMB远程命令"""


from registry import tool
from utils import run_cmd
from helpers import *  # noqa: F401,F403


@tool(
    "impacket_smbexec",
    "SMB远程命令",
    {
        "properties": {
            "target": {
                "type": "string",
                "description": "IP",
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
            "command": {
                "type": "string",
                "description": "命令(whoami)",
                "default": "whoami",
            },
        },
        "required": ["target", "username", "password"],
    },
)
def impacket_smbexec_handler(params):
    # psexec.py 那条路；默认 whoami 是先确认能不能落地，60s 够用，这不是跑长任务的地方
    t=params.get("target","");u=params.get("username","");p=params.get("password","");c=params.get("command","whoami"); return run_cmd("psexec.py %s:'%s'@%s '%s' 2>&1||echo '需impacket'" % (u,p,t,c),60)
