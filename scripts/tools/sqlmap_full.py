#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQL注入全功能版 - 支持GET/POST/Header/Cookie注入，盲注/报错/联合查询/堆叠，OS-Shell/文件读写/数据脱取。所有高级选项默认关闭，按需开启

高级开关默认全关不是保守，是防误扫：os-shell、文件读写这类默认打开的话，扫错一次
就可能把目标写坏。调用方要什么就显式传什么。
"""


from registry import tool
from utils import run_cmd
from helpers import *  # noqa: F401,F403


@tool(
    "sqlmap_full",
    "SQL注入全功能版 - 支持GET/POST/Header/Cookie注入，盲注/报错/联合查询/堆叠，OS-Shell/文件读写/数据脱取。所有高级选项默认关闭，按需开启",
    {
        "properties": {
            "url": {
                "type": "string",
                "description": "目标URL（必填）",
            },
            "data": {
                "type": "string",
                "description": "POST数据（如 user=admin&pass=123），留空则用GET",
            },
            "cookie": {
                "type": "string",
                "description": "Cookie字符串",
            },
            "headers": {
                "type": "string",
                "description": "自定义Header（每行一个，如 X-Forwarded-For: 127.0.0.1）",
            },
            "technique": {
                "type": "string",
                "description": "注入技术: U(联合查询)/B(布尔盲注)/T(时间盲注)/E(报错)/S(堆叠)，默认自动",
            },
            "level": {
                "type": "integer",
                "description": "测试等级 1-5，越高越深入（默认1）",
                "default": 1,
            },
            "risk": {
                "type": "integer",
                "description": "风险等级 1-3，3可能破坏数据（默认1）",
                "default": 1,
            },
            "dbms": {
                "type": "string",
                "description": "指定数据库类型（mysql/postgresql/mssql/oracle），不指定自动检测",
            },
            "os_shell": {
                "type": "boolean",
                "description": "尝试获取系统Shell",
                "default": "false",
            },
            "os_cmd": {
                "type": "string",
                "description": "通过注入执行系统命令并返回结果",
            },
            "dump_all": {
                "type": "boolean",
                "description": "脱取所有数据库全部数据",
                "default": "false",
            },
            "dump_db": {
                "type": "string",
                "description": "脱取指定数据库",
            },
            "dump_table": {
                "type": "string",
                "description": "脱取指定表（需配合dump_db）",
            },
            "batch": {
                "type": "boolean",
                "description": "自动确认，不交互",
                "default": "true",
            },
            "threads": {
                "type": "integer",
                "description": "并发线程数（默认3）",
                "default": 3,
            },
            "timeout": {
                "type": "integer",
                "description": "超时秒数（默认300）",
                "default": 300,
            },
        },
        "required": ["url"],
    },
)
def sqlmap_full_handler(params):
            url = params.get("url","")
            cmd = f"sqlmap -u '{url}' --batch"
            data = params.get("data","")
            if data: cmd += f" --data='{data}'"
            cookie = params.get("cookie","")
            if cookie: cmd += f" --cookie='{cookie}'"
            headers = params.get("headers","")
            if headers:
                for h in headers.split('\n'):
                    h = h.strip()
                    if h and ':' in h: cmd += f" --headers='{h}'"
            technique = params.get("technique","")
            if technique: cmd += f" --technique={technique}"
            level = int(params.get("level",1))
            cmd += f" --level={level}"
            risk = int(params.get("risk",1))
            cmd += f" --risk={risk}"
            dbms = params.get("dbms","")
            if dbms: cmd += f" --dbms={dbms}"
            threads = int(params.get("threads",3))
            cmd += f" --threads={threads}"
            if params.get("os_shell"): cmd += " --os-shell"
            os_cmd = params.get("os_cmd","")
            if os_cmd: cmd += f" --sql-shell -Q '{os_cmd}'"
            if params.get("dump_all"): cmd += " --dump-all"
            dump_db = params.get("dump_db","")
            if dump_db: cmd += f" -D {dump_db}"
            dump_table = params.get("dump_table","")
            if dump_table and dump_db: cmd += f" -T {dump_table}"
            timeout = int(params.get("timeout",300))
            return run_cmd(cmd, timeout)
