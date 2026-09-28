#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反弹Shell监听器 - 在本地监听端口等待反弹连接，支持nc，自动超时返回结果

只有 nc 一种处理器。timeout>0 用 coreutils 的 timeout 卡住上限、能拿到回显；
timeout=0 表示挂后台无限等，那种模式拿不到输出，得另想办法去连。
"""


from registry import tool
from utils import run_cmd
from helpers import *  # noqa: F401,F403


@tool(
    "revshell_handler",
    "反弹Shell监听器 - 在本地监听端口等待反弹连接，支持nc，自动超时返回结果",
    {
        "properties": {
            "port": {
                "type": "integer",
                "description": "监听端口（默认4444）",
                "default": 4444,
            },
            "handler": {
                "type": "string",
                "description": "处理器: nc（默认，基础Shell）",
                "default": "nc",
            },
            "timeout": {
                "type": "integer",
                "description": "监听超时秒数（0=无限等待，默认120）",
                "default": 120,
            },
        },
        "required": ["port"],
    },
)
def revshell_handler_handler(params):
            port = int(params.get("port",4444))
            handler = params.get("handler","nc")
            timeout = int(params.get("timeout",120))
            if handler == "nc":
                if timeout > 0:
                    res = run_cmd(f"timeout {timeout} nc -lvnp {port} 2>&1", timeout + 10)
                    # 124 是 timeout 到点把监听掐掉，监听器本来就该这么收尾，不算执行失败；
                    # 顺手把"这轮有没有人连进来"写清楚，免得上层把正常超时当故障
                    if res.get("returncode") == 124:
                        if "Connection" in res.get("output", ""):
                            res["output"] += f"\n[监听结束] {timeout} 秒窗口内收到过反弹连接"
                        else:
                            res["output"] += f"\n[监听结束] {timeout} 秒窗口内没有连接进来（预期结果，端口已释放）"
                        res["success"] = True
                    return res
                else:
                    run_cmd(f"nc -lvnp {port} 2>&1 &", 5)
                    return {"success":True,"returncode":0,"output":f"反弹Shell监听已后台启动\n端口: {port}\n等待连接中..."}
            return {"success":False,"returncode":-1,"output":f"不支持的处理器: {handler}"}
