#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ping扫描整个网段发现在线设备(调用系统nmap -sn)，几秒扫完/24

改造点：
1. 目标做白名单校验，杜绝把用户输入直接拼进 shell；
2. `-sn` 一无所获时自动用 `-Pn` 重探一次 —— 生产网里大量主机（尤其 Windows、
   防火墙后设备）是不回 ICMP 的，只发 ping 会整段漏报；
3. 不再用 grep 的退出码判断成败（grep 匹配不到就返回 1，会被误判成"执行失败"）。
"""

import re

from registry import tool
from utils import run_cmd, fail, ok
from utils import extract_target as _extract_target
from helpers import *  # noqa: F401,F403

# 目标白名单：IPv4 / CIDR / 简单域名，防止命令注入
_TARGET_OK_RE = re.compile(r"^[0-9a-zA-Z\.\-/:_,]+$")


def _host_lines(output):
    """从 nmap 输出里挑出"主机存活"相关行。"""
    keep = []
    for line in (output or "").split("\n"):
        if "report for" in line or "Host is up" in line:
            keep.append(line.rstrip())
    return "\n".join(keep)


@tool(
    "ping_scan",
    "Ping扫描整个网段发现在线设备(调用系统nmap -sn)，几秒扫完/24；对不回 ICMP 的主机会自动用 -Pn 重探",
    {
        "properties": {
            "target": {
                "type": "string",
                "description": "网段(如 192.168.1.0/24)",
            },
            "ping_only": {
                "type": "boolean",
                "description": "仅Ping模式(false时禁用Ping用-Pn探测禁Ping设备)",
                "default": True,
            },
        },
        "required": ["target"],
    },
)
def ping_scan_handler(params):
    t = _extract_target(params.get("target", ""))
    # ping_only 允许布尔或字符串（模型/编排层可能传 "false"）
    raw_ping_only = params.get("ping_only", True)
    ping_only = str(raw_ping_only).lower() not in ("false", "0", "no", "off")

    if not t:
        return fail("缺少 target 参数")
    if not _TARGET_OK_RE.match(t):
        return fail("target 含非法字符，已拒绝执行：%s" % t[:60])

    if not ping_only:
        return run_cmd("nmap -Pn -sn -T4 --max-retries 1 %s 2>&1" % t, 180)

    first = run_cmd("nmap -sn -T4 --max-retries 1 %s 2>&1" % t, 120)
    lines = _host_lines(first.get("output", ""))
    if lines:
        return ok(lines)

    # 第一次没结果：目标可能屏蔽 ICMP，降级用 -Pn 再探一次，并在输出里注明来源
    second = run_cmd("nmap -Pn -sn -T4 --max-retries 1 %s 2>&1" % t, 240)
    lines = _host_lines(second.get("output", ""))
    if lines:
        return ok("[回退] ICMP 探测无响应，已改用 -Pn 重新探测\n" + lines)
    return ok("[回退] ICMP 与 -Pn 探测均未发现在线主机\n" + (second.get("output") or ""))
