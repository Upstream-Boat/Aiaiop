#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSE 行流解析（移植自平台 server/src/adapters/sse.js）。

只负责拆行，不解释事件含义：逐个产出 data: 后面的载荷，跳过空行与 [DONE]。
流结束时冲刷最后一段没有换行的缓冲 —— 否则回复尾部的下载链接会被丢掉。
"""


def iter_sse_data(resp, encoding="utf-8"):
    """从二进制流对象（urllib 的 response）逐个产出 SSE 的 data 载荷。"""
    buffer = ""
    for raw in resp:
        if isinstance(raw, (bytes, bytearray)):
            buffer += raw.decode(encoding, errors="replace")
        else:
            buffer += raw
        while True:
            idx = buffer.find("\n")
            if idx < 0:
                break
            line = buffer[:idx].rstrip("\r").strip()
            buffer = buffer[idx + 1:]
            data = _payload(line)
            if data:
                yield data
    tail = _payload(buffer.rstrip("\r").strip())
    if tail:
        yield tail


def _payload(line):
    if not line.startswith("data:"):
        return ""
    data = line[5:].strip()
    return "" if not data or data == "[DONE]" else data
