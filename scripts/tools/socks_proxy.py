#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SOCKS代理管理 - 使用Chisel建立反向隧道/正向SOCKS5代理，支持服务端/客户端模式，打通内网横向移动通道

四种动作：server / client / list / kill。server 和 client 都是后台拉起（命令尾带 &），
所以返回值只有一句"已启动"，真想确认起来了用 list 看进程。
"""


from registry import tool
from utils import run_cmd
from helpers import *  # noqa: F401,F403


@tool(
    "socks_proxy",
    "SOCKS代理管理 - 使用Chisel建立反向隧道/正向SOCKS5代理，支持服务端/客户端模式，打通内网横向移动通道",
    {
        "properties": {
            "mode": {
                "type": "string",
                "description": "模式: server(启动服务端)/client(连接服务端)/list(查看活跃代理)/kill(停止代理)",
            },
            "listen_port": {
                "type": "integer",
                "description": "服务端监听端口（默认1080）",
                "default": 1080,
            },
            "server_url": {
                "type": "string",
                "description": "客户端模式下的服务端地址（如 http://192.168.1.1:8080）",
            },
            "remote": {
                "type": "string",
                "description": "反向隧道远端地址（如 127.0.0.1:3389）",
            },
            "proxy_id": {
                "type": "string",
                "description": "要停止的代理PID（kill模式）",
            },
            "timeout": {
                "type": "integer",
                "description": "超时秒数（默认30）",
                "default": 30,
            },
        },
        "required": ["mode"],
    },
)
def socks_proxy_handler(params):
            mode = params.get("mode","")
            port = int(params.get("listen_port",1080))
            server_url = params.get("server_url","")
            remote = params.get("remote","")
            if mode == "server":
                run_cmd(f"chisel server -p {port} --socks5 --reverse 2>&1 &", 5)
                return {"success":True,"returncode":0,"output":f"SOCKS代理服务端已启动\n监听端口: {port}\n客户端连接: chisel client <IP>:{port} R:socks"}
            elif mode == "client":
                if not server_url: return {"success":False,"returncode":-1,"output":"客户端模式需要 server_url"}
                if remote: cmd = f"chisel client {server_url} R:{remote} &"
                else: cmd = f"chisel client {server_url} socks &"
                run_cmd(cmd, 5)
                return {"success":True,"returncode":0,"output":f"SOCKS客户端已连接\n服务端: {server_url}\n{'反向隧道: '+remote if remote else 'SOCKS5代理'}"}
            elif mode == "list":
                return run_cmd("ps aux | grep -E 'chisel|socat' | grep -v grep", 5)
            elif mode == "kill":
                pid = params.get("proxy_id","")
                if pid: return run_cmd(f"kill {pid}", 5)
                return {"success":False,"returncode":-1,"output":"需要 proxy_id (PID)"}
            return {"success":False,"returncode":-1,"output":"未知模式: "+mode}
