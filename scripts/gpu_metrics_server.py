#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DGX Spark 侧的算力指标端点。

跑工具的执行机一般没有 GPU，而推理在 DGX Spark 上。把本机 nvidia-smi 的读数用
HTTP 暴露出来，执行机上的 llm/gpu.py 通过 GPU_METRICS_URL 就能把"这轮任务到底
用了多少算力"写进轨迹与报告 —— 否则"用了 GPU"只是文档里的一句话。

只用标准库。默认只监听 127.0.0.1 且**强制要求 token**：部署手册第 8 章明确写了
"暴露在公网端口的服务必须设置 token 或密码"，一个无鉴权的指标端点挂在公网上是红线。
要跨机器读，就把远端端口用 SSH 隧道收到本地，而不是把服务敞到公网。

    python3 scripts/gpu_metrics_server.py --port 9000 --token "$(openssl rand -hex 8)"
    curl -H "X-Auth-Token: <token>" http://127.0.0.1:9000/metrics
"""

import argparse
import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from llm import gpu  # noqa: E402 - 解析逻辑跟报告侧共用一份，避免两边口径不一致


class Handler(BaseHTTPRequestHandler):
    server_version = "sec-assessment-gpu-metrics/1.0"
    token = ""                          # main() 启动时写入

    def _send(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        """没配 token 直接拒绝：宁可起不来，也不要留一个敞着的公网端口。"""
        if not self.token:
            return False
        offered = (self.headers.get("X-Auth-Token")
                   or (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip())
        # 定长比较，避免用响应时间把 token 一位位试出来
        return hmac.compare_digest(offered, self.token)

    def do_GET(self):                       # noqa: N802 - BaseHTTPRequestHandler 的约定命名
        path = self.path.split("?")[0].rstrip("/") or "/"
        if path not in ("/", "/metrics", "/health"):
            self._send(404, {"error": "not found", "paths": ["/metrics", "/health"]})
            return
        if not self._authorized():
            self._send(401, {"error": "缺少或错误的 token（X-Auth-Token / Authorization: Bearer）"})
            return
        snap = gpu.local_snapshot()
        if snap is None:
            self._send(503, {"error": "本机取不到 NVIDIA GPU 指标（没有 nvidia-smi 或没有驱动）"})
            return
        if path == "/health":
            self._send(200, {"ok": True, "name": snap.get("name"),
                             "summary": gpu.summary_line(snap)})
        else:
            self._send(200, snap)

    def log_message(self, fmt, *args):      # 指标端点是高频轮询的，别把日志刷满
        pass


def main():
    parser = argparse.ArgumentParser(description="DGX Spark 算力指标端点（只读）")
    parser.add_argument("--host", default="127.0.0.1",
                        help="监听地址（默认 127.0.0.1；要跨机器读就用 SSH 隧道，别直接敞公网）")
    parser.add_argument("--port", type=int, default=9000, help="监听端口（默认 9000）")
    parser.add_argument("--token", default="", help="访问令牌，默认读 GPU_METRICS_TOKEN")
    args = parser.parse_args()
    token = args.token or os.environ.get("GPU_METRICS_TOKEN") or ""
    if not token:
        sys.stderr.write("拒绝启动：必须提供 --token（或 GPU_METRICS_TOKEN）。\n"
                         "无鉴权的指标端点挂在公网端口上违反部署手册第 8 章的规定。\n")
        return 2
    Handler.token = token
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    line = gpu.summary_line(gpu.local_snapshot())
    sys.stderr.write("算力指标端点已启动 http://%s:%d/metrics\n%s\n"
                     % (args.host, args.port, line or "（本机暂无 GPU 指标）"))
    sys.stderr.flush()
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main() or 0)
