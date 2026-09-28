#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""控制台后端 — 只做 HTTP 与 SSE 出口，业务逻辑一律走 scripts/core 与 scripts/agents。

这里不 import .app，改成用到的时候再导：直接跑 `python3 server/app.py` 时，路由里的
`from server import stream` 会先把这个包导进来，而 server/app.py 自己又会以 __main__
跑一遍 —— 在包这层 import .app，等于把 app 建两次，模块级的 start_scheduler 就跟着
起两个调度器，两个线程同时到点抢同一把锁，更新日志里会多出一条
"定时更新跳过：已有一场更新在跑"。
"""


def create_app(*args, **kwargs):
    """建一个控制台 app（具体怎么组装见 server/app.py）。"""
    from .app import create_app as build
    return build(*args, **kwargs)


__all__ = ["create_app"]
