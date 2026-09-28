#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSE 出口工具 — 服务端把事件推给前端。

注意与 scripts/llm/sse.py 区分：那个是解析上游（模型）的 SSE，这个是本服务向浏览器输出。
统一格式：每帧 `event: <类型>` + `data: <JSON>`，前端只按类型分发。
"""

import json
import time

SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
}


def frame(event_type, payload):
    """把一条事件编码成 SSE 帧。"""
    return "event: %s\ndata: %s\n\n" % (event_type, json.dumps(payload, ensure_ascii=False))


def encode(events):
    """把 (type, payload) 元组或 dict 序列编码成 SSE 文本流。"""
    for item in events:
        if isinstance(item, tuple):
            yield frame(item[0], item[1])
        elif isinstance(item, dict):
            yield frame(item.get("type", "message"), item.get("data", item))
        else:
            yield frame("message", {"text": str(item)})


def follow(events_fn, is_alive, after=0, interval=0.4, idle_timeout=900.0):
    """轮询式跟随事件：每 interval 秒取一次新事件，任务结束或长时间空闲则收尾。

    events_fn(after) -> [事件, ...]；is_alive() -> 任务是否仍在进行。
    """
    cursor = after
    idle = 0.0
    while True:
        batch = events_fn(cursor) or []
        if batch:
            idle = 0.0
            for entry in batch:
                cursor = max(cursor, int(entry.get("seq") or 0))
                yield (entry.get("type", "message"), entry)
        else:
            idle += interval
        if not batch and (not is_alive() or idle >= idle_timeout):
            yield ("end", {"cursor": cursor})
            return
        time.sleep(interval)
