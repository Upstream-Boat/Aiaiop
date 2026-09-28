#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫描指定IP的全部开放端口(全端口65535)，支持单个IP或IP列表

名字叫 masscan，实际命令行是 nmap -T5 -p1-65535 —— 本机没有 masscan，同一套参数
在 nmap 上也能拿到结果。60s 封顶，目标不通就只剩一句超时。
"""


from registry import tool
from utils import run_cmd
from helpers import *  # noqa: F401,F403


@tool(
    "masscan_scan",
    "扫描指定IP的全部开放端口(全端口65535)，支持单个IP或IP列表",
    {
        "properties": {
            "target": {
                "type": "string",
                "description": "目标IP，或用逗号/换行分隔的多IP，或JSON数组",
            },
        },
        "required": ["target"],
    },
)
def masscan_scan_handler(params):
            t=params.get("target","")
            if not t:
                return {"success":False,"returncode":-1,"output":"请提供目标IP"}
            r=run_cmd("nmap -T5 --open --max-rtt-timeout 300ms --min-rate 10000 --max-retries 1 --host-timeout 20s -p1-65535 %s 2>&1" % t, 60)
            if r["success"]:
                ports=[l.split("/")[0] for l in r["output"].split("\n") if "/tcp" in l and "open" in l]
                if ports:
                    r["output"]="%s 开放端口:\n" % t+"\n".join(ports)
                else:
                    r["output"]="%s 未发现开放端口" % t
            return r
