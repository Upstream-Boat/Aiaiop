#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""模型接入层 — 把要用的模型接进来，协议与平台已验证的实现保持一致。

对外只暴露四件事：

    backends.list_backends()   列出可用后端（GPUStack 集群 / Spark 本机 / StepFun 云）
    backends.resolve()         选一个后端（含端点、密钥、模型名）
    client.chat()              一次性对话，返回文本 + 上游真实用量
    client.stream_chat()       流式对话，逐条产出 meta / text / reasoning / usage / done / error

协议细节移植自平台（server/src/adapters/sse.js 与 server/src/usage.js）：
SSE 只负责拆行、usage 只认上游自己算出来的真值，拿不到就返回 None 由调用方决定是否估算。
"""

from . import backends, client, sse, usage  # noqa: F401

__all__ = ["backends", "client", "sse", "usage"]
