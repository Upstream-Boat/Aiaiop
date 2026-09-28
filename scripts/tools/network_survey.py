#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""大网段快速设备普查 - 不逐个扫端口，高速扫描发现在线设备，适用于/16及以上大网段

只做主机发现。ports / rate 两个参数目前没接进命令行（留着等以后换成真 masscan 再说），
实际跑的是 nmap -sn 管道过滤。命令外包了 shell 管道，退出码不可靠，判成败看输出里
有没有 "report for"。
"""


from registry import tool
from utils import run_cmd
from helpers import *  # noqa: F401,F403


@tool(
    "network_survey",
    "大网段快速设备普查 - 不逐个扫端口，高速扫描发现在线设备，适用于/16及以上大网段",
    {
        "properties": {
            "target": {
                "type": "string",
                "description": "目标网段(如 192.168.1.0/16)",
            },
            "ports": {
                "type": "string",
                "description": "端口(22,80,443,3389)",
                "default": "22,80,443,3389",
            },
            "rate": {
                "type": "integer",
                "description": "速率(包/秒)",
                "default": 10000,
            },
        },
        "required": ["target"],
    },
)
def network_survey_handler(params):
            t=params.get("target","")
            if not t:
                return {"success":True,"returncode":0,"output":"需指定target网段，如 192.168.1.0/16"}
            cmd = f"nmap -sn -T5 --min-hostgroup 256 {t} 2>&1|grep -E 'report for|Host is up'"
            return run_cmd(cmd, 300)
