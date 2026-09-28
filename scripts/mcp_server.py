#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sec-assessment MCP Server — 以 SSE/Streamable-HTTP 暴露 tools/ 下的全部工具。

协议照生产服务那套来，FastGPT 可以直接接入：
  GET  /mcp          → SSE 握手，推送 event: endpoint -> /mcp/message
  POST /mcp/message  → JSON-RPC 2.0，直接 200 + JSON 响应体
  GET  /health       → {"status","tools","version","tool_list"}
  GET  /             → HTML 仪表盘

端口默认 8010，可用 MCP_PORT 覆盖；可以和机器上其他服务并存。
"""

import json
import os
import sys
import uuid
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from registry import REGISTRY, auto_discover, get_all_tools, get_handler  # noqa: E402

VERSION = "1.0.0"
SERVER_NAME = "sec-assessment"
HOST = os.environ.get("MCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("MCP_PORT", "8010"))

_FAILED = auto_discover()
TOOLS = get_all_tools()

_sse_clients = {}
_sse_lock = threading.Lock()


def execute_tool(name, params):
    handler = get_handler(name)
    if not handler:
        return {"success": False, "returncode": -1, "output": f"未知工具: {name}"}
    try:
        return handler(params or {})
    except Exception as exc:
        return {"success": False, "returncode": -1,
                "output": f"[ERROR] {exc}\n{traceback.format_exc()}"}


def sse_broadcast(event, data):
    payload = json.dumps(data, ensure_ascii=False)
    with _sse_lock:
        dead = []
        for cid, write in _sse_clients.items():
            try:
                write(event, payload)
            except Exception:
                dead.append(cid)
        for cid in dead:
            _sse_clients.pop(cid, None)


DASHBOARD_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>sec-assessment MCP Server</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;padding:30px 20px}
h1{font-size:26px;color:#58a6ff;margin-bottom:6px}
.stats{display:flex;gap:16px;flex-wrap:wrap;font-size:14px;margin-bottom:20px}
.stat{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:6px 14px}
.stat label{color:#8b949e}
.stat span{color:#58a6ff;font-weight:600}
.links{margin-bottom:24px}
.links a{color:#58a6ff;text-decoration:none;font-size:13px;margin-right:12px;border:1px solid #30363d;padding:4px 12px;border-radius:6px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:10px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px}
.card:hover{border-color:#58a6ff}
.name{font-size:14px;font-weight:600;color:#f0f6fc;margin-bottom:4px}
.desc{font-size:12px;color:#8b949e;line-height:1.4}
.ft{text-align:center;padding:30px;color:#484f58;font-size:12px}
</style></head><body>
<h1>&#x1f512; sec-assessment MCP Server v{version}</h1>
<div class="stats">
<div class="stat"><label>状态</label> <span>&#x2705; 运行中</span></div>
<div class="stat"><label>端口</label> <span>{port}</span></div>
<div class="stat"><label>工具数</label> <span>{tool_count}</span></div>
</div>
<div class="links">
<a href="/health">/health</a><a href="/mcp">/mcp (SSE)</a>
</div>
<div class="grid">{cards}</div>
<div class="ft">sec-assessment — 渗透与安全扫描工具集</div>
</body></html>"""


class MCPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        try:
            sys.stderr.write("[MCP] %s %s %s\n" % args)
        except Exception:
            pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send_json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self):
        cards = "".join(
            '<div class="card"><div class="name">%s</div><div class="desc">%s</div></div>'
            % (t.get("name", ""), t.get("description", ""))
            for t in sorted(TOOLS, key=lambda x: x.get("name", ""))
        )
        html = DASHBOARD_HTML.format(version=VERSION, port=PORT, tool_count=len(TOOLS), cards=cards)
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self._cors()
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self._send_json(200, {
                "status": "ok",
                "server": SERVER_NAME,
                "version": VERSION,
                "tools": len(TOOLS),
                "tool_list": [t["name"] for t in TOOLS],
            })
        elif path == "/":
            self._send_html()
        elif path == "/mcp":
            self._handle_sse()
        else:
            self._send_json(404, {"error": "not_found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else "{}"
        try:
            data = json.loads(body)
        except Exception:
            return self._send_json(400, {"error": "invalid_json"})

        if path in ("/mcp/message", "/mcp"):
            result = self._handle_jsonrpc(data)
            if isinstance(result, dict) and result.get("id") is not None:
                payload = {"jsonrpc": "2.0", **result}
            else:
                payload = result
            self._send_json(200, payload)
        else:
            self._send_json(404, {"error": "not_found"})

    def _handle_sse(self):
        self.send_response(200)
        for key, value in {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "*",
        }.items():
            self.send_header(key, value)
        self.end_headers()

        cid = str(uuid.uuid4())[:8]
        wfile = self.wfile

        def write(event, data):
            wfile.write(b"event: " + event.encode() + b"\ndata: " + data.encode() + b"\n\n")
            wfile.flush()
            return True

        with _sse_lock:
            _sse_clients[cid] = write
        write("endpoint", "/mcp/message")
        try:
            while True:
                wfile.write(b": keepalive\n\n")
                wfile.flush()
                time.sleep(15)
        except Exception:
            pass
        finally:
            with _sse_lock:
                _sse_clients.pop(cid, None)

    def _handle_jsonrpc(self, msg):
        if not isinstance(msg, dict):
            return {"error": {"code": -32600, "message": "Invalid Request"}}
        rid = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params") or {}

        if method == "tools/list":
            return {"id": rid, "result": {"tools": TOOLS}}
        if method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments") or {}
            if name not in REGISTRY:
                return {"id": rid, "error": {"code": -32602, "message": "Unknown: " + name}}
            result = execute_tool(name, args)
            text = str(result.get("output", ""))[:50000]
            return {"id": rid, "result": {"content": [{"type": "text", "text": text}],
                                          "isError": not result.get("success", False)}}
        if method == "initialize":
            return {"id": rid, "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": VERSION}}}
        if method in ("initialized", "notifications/initialized", "shutdown"):
            return {"jsonrpc": "2.0", "id": rid, "result": {}}
        return {"jsonrpc": "2.0", "id": rid, "result": {}}


def main():
    ThreadingHTTPServer.allow_reuse_address = True
    httpd = ThreadingHTTPServer((HOST, PORT), MCPHandler)
    print("=" * 50)
    print(f" {SERVER_NAME} v{VERSION}")
    print(f" {len(TOOLS)} tools | Port {PORT}")
    for line in _FAILED:
        print(f" [warn] 模块加载失败 -> {line}")
    print(f" MCP: http://{HOST}:{PORT}/mcp")
    print("=" * 50)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
