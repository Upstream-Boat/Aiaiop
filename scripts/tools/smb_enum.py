#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SMB枚举(smbmap)

包的 smbmap：给了用户名/密码就带上，给了 command 就用 -x 远程执行。末尾那句
`|| echo '需安装: pip3 install smbmap'` 是缺工具时的兜底提示，不是真实执行结果。
"""


from registry import tool
from utils import run_cmd
from utils import extract_target as _extract_target
from helpers import *  # noqa: F401,F403


@tool(
    "smb_enum",
    "SMB枚举(smbmap)",
    {
        "properties": {
            "target": {
                "type": "string",
                "description": "目标IP",
            },
            "username": {
                "type": "string",
                "description": "用户名",
                "default": "",
            },
            "password": {
                "type": "string",
                "description": "密码",
                "default": "",
            },
            "command": {
                "type": "string",
                "description": "远程命令",
            },
        },
        "required": ["target"],
    },
)
def smb_enum_handler(params):
            t=_extract_target(params.get("target",""));u=params.get("username","");pw=params.get("password","");c=params.get("command","")
            cmd = "smbmap -H %s" % t
            if u: cmd += " -u %s" % u
            if pw: cmd += " -p '%s'" % pw
            if c: cmd += " -x '%s'" % c
            return run_cmd(cmd + " 2>&1||echo '需安装: pip3 install smbmap'", 60)
