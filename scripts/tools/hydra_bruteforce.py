#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hydra暴力破解

password_list 两用：给的是已存在的文件路径就按路径用，给逗号串就临时落成字典文件，
跑完删掉。并发固定 -t 4，别往上调：多数服务有登录速率限制，线程多了会大面积误判成
密码错误。
"""

import os

from registry import tool
from utils import run_cmd
from helpers import *  # noqa: F401,F403


@tool(
    "hydra_bruteforce",
    "Hydra暴力破解",
    {
        "properties": {
            "target": {
                "type": "string",
                "description": "目标IP",
                "default": None,
            },
            "service": {
                "type": "string",
                "description": "服务(ssh)",
                "default": "ssh",
            },
            "username": {
                "type": "string",
                "description": "用户名",
                "default": None,
            },
            "password_list": {
                "type": "string",
                "description": "密码",
                "default": None,
            },
            "port": {
                "type": "integer",
                "description": "端口",
                "default": None,
            },
        },
        "required": ["target", "username", "password_list"],
    },
)
def hydra_bruteforce_handler(params):
            t=params.get("target","");sv=params.get("service","ssh");u=params.get("username","");pw=params.get("password_list","");pf="-s %d" % params.get("port") if params.get("port") else ""
            import tempfile
            # 如果password_list是逗号分隔的密码列表（非文件路径），写入临时文件
            if os.path.isfile(pw):
                pwf = pw
                cleanup = False
            else:
                pwf = tempfile.mktemp(suffix='.txt')
                with open(pwf,'w') as f: f.write(pw.replace(',','\n'))
                cleanup = True
            result = run_cmd("hydra %s -l %s -P %s %s %s -t 4 -V 2>&1" % (pf,u,pwf,t,sv),300)
            if cleanup: os.remove(pwf)
            return result
