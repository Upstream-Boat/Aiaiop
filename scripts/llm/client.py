#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenAI 兼容模型客户端 — 三个后端共用一份实现（移植平台 gateway.js 的事件口径）。

    client.chat(...)         一次性返回 {"text", "reasoning", "usage", "model"}
    client.stream_chat(...)  流式产出事件：meta / text / reasoning / usage / done / error

只用标准库（urllib），不引入第三方依赖：现场是离线 ARM64 单机，装不上包也照样跑。
错误信息统一脱敏（抹掉 Bearer 串与长令牌），避免把内网地址和密钥带进报告或界面。
"""

import json
import re
import socket
import threading
import time
import urllib.error
import urllib.request

from . import backends as _backends
from . import gpu as _gpu
from . import sse as _sse
from . import usage as _usage

# 推理才是真正的算力消耗，所以采样必须在请求进行中做：等响应回来再采，
# 采到的是推理结束后的回落值，报告里就只剩个"0%"，没有说服力。
SAMPLE_INTERVAL = 0.8


def _sampler(stop):
    """请求期间每隔 SAMPLE_INTERVAL 采一次 GPU（没有 GPU 的环境下这是个空转线程）。"""
    while True:
        try:
            _gpu.recorder.sample("chat")
        except Exception:                   # noqa: BLE001 - 采样失败不能影响模型调用
            pass
        if stop.wait(SAMPLE_INTERVAL):
            return

DEFAULT_TIMEOUT = 180.0

# 需要抹掉的：Bearer 串、常见前缀的长令牌、以及形如 xxx.yyy.zzz 的三段式密钥
_SECRET_PATTERNS = (
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{8,}"),
    re.compile(r"(?i)(sk|api|key|token)[-_][A-Za-z0-9._\-]{12,}"),
    re.compile(r"\b[A-Fa-f0-9]{24,}\.[A-Fa-f0-9]{24,}(?:\.[A-Fa-f0-9]{24,})?\b"),
    re.compile(r"\b[A-Za-z0-9]{32,}\b"),
)


def redact(text, limit=400):
    """脱敏 + 截断：错误信息可以给人看，但不能把密钥/令牌带出去。"""
    out = str(text or "")
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub("<已脱敏>", out)
    out = " ".join(out.split())
    return out[:limit]


class LLMError(RuntimeError):
    """带异常码的模型调用错误（码与 backends.ERR 一致，便于界面分类展示）。"""

    def __init__(self, code, message, status=None):
        super().__init__(message)
        self.code = code
        self.status = status


def _headers(backend):
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if backend.get("api_key"):
        headers["Authorization"] = "Bearer " + backend["api_key"]
    return headers


def _payload(backend, messages, model, stream, temperature, extra):
    body = {
        "model": model or backend.get("model") or "",
        "messages": messages,
        "stream": bool(stream),
    }
    if temperature is not None:
        body["temperature"] = temperature
    if stream:
        # 让上游在流末尾补一帧 usage（OpenAI 兼容网关都认这个开关）
        body["stream_options"] = {"include_usage": True}
    if isinstance(extra, dict):
        body.update(extra)
    return body


def _open(backend, body, timeout):
    parsed = _backends.check_url(backend.get("base_url"))
    if not parsed:
        raise LLMError("BAD_URL", _backends.ERR["BAD_URL"])
    url = _backends.chat_url(backend["base_url"])
    req = urllib.request.Request(
        url, data=json.dumps(body, ensure_ascii=False).encode("utf-8"), method="POST"
    )
    for name, value in _headers(backend).items():
        req.add_header(name, value)
    wait = timeout or backend.get("timeout") or DEFAULT_TIMEOUT
    try:
        return urllib.request.urlopen(req, timeout=float(wait))
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - 读不到正文不影响判错
            detail = ""
        if exc.code in (401, 403):
            raise LLMError("AUTH_FAILED", _backends.ERR["AUTH_FAILED"], exc.code) from None
        message = "上游返回 HTTP %s" % exc.code
        if detail:
            message += "：" + redact(_extract_error(detail), 200)
        raise LLMError("BAD_DATA", message, exc.code) from None
    except socket.timeout:
        raise LLMError("TIMEOUT", _backends.ERR["TIMEOUT"]) from None
    except urllib.error.URLError:
        raise LLMError("UNREACHABLE", _backends.ERR["UNREACHABLE"]) from None
    except OSError:
        raise LLMError("UNKNOWN", _backends.ERR["UNKNOWN"]) from None


def _extract_error(detail):
    try:
        data = json.loads(detail)
    except ValueError:
        return detail
    error = data.get("error") if isinstance(data, dict) else None
    if isinstance(error, dict):
        return str(error.get("message") or error)
    return str(error or detail)


def chat(messages, backend=None, model=None, temperature=0.2, timeout=None, extra=None):
    """一次性对话。返回 {"text", "reasoning", "usage", "model", "backend"}。"""
    conf = _backends.resolve(backend)
    body = _payload(conf, messages, model, False, temperature, extra)
    stop = threading.Event()
    sampler = threading.Thread(target=_sampler, args=(stop,), daemon=True)
    sampler.start()
    try:
        with _open(conf, body, timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    finally:
        stop.set()
        sampler.join(timeout=2)
    try:
        data = json.loads(raw)
    except ValueError:
        raise LLMError("BAD_DATA", _backends.ERR["BAD_DATA"]) from None
    choices = data.get("choices") or []
    message = (choices[0] or {}).get("message") if choices else None
    if not isinstance(message, dict):
        raise LLMError("BAD_DATA", "上游没有返回 choices[0].message：" + redact(raw, 200))
    return {
        "text": message.get("content") or "",
        "reasoning": message.get("reasoning_content") or message.get("reasoning") or "",
        "usage": _usage.normalize_usage(data.get("usage")),
        "model": data.get("model") or body.get("model"),
        "backend": conf["name"],
    }


def stream_chat(messages, backend=None, model=None, temperature=0.2, timeout=None, extra=None):
    """流式对话：逐个产出事件 dict，事件类型与平台一致。

    meta -> text/reasoning（可多次）-> usage（上游给了才有）-> done；出错则 error 结束。
    """
    conf = _backends.resolve(backend)
    body = _payload(conf, messages, model, True, temperature, extra)
    yield {"type": "meta", "data": {"backend": conf["name"], "model": body.get("model"),
                                    "base_url": conf["base_url"]}}
    text_parts, reasoning_parts, usage = [], [], None
    try:
        resp = _open(conf, body, timeout)
    except LLMError as exc:
        yield {"type": "error", "data": {"code": exc.code, "message": str(exc)}}
        return
    try:
        for chunk in _sse.iter_sse_data(resp):
            try:
                frame = json.loads(chunk)
            except ValueError:
                continue
            if isinstance(frame.get("usage"), dict):
                usage = _usage.normalize_usage(frame.get("usage")) or usage
            for choice in frame.get("choices") or []:
                delta = choice.get("delta") or {}
                # 收到内容就说明此刻正在解码 —— 这就是该采样的时刻（Recorder 自带限流，
                # 一段文本采一次不会比推理本身更费）
                if delta.get("content") or delta.get("reasoning_content") or delta.get("reasoning"):
                    try:
                        _gpu.recorder.sample("chat")
                    except Exception:       # noqa: BLE001 - 采样失败不能影响对话
                        pass
                piece = delta.get("content")
                if piece:
                    text_parts.append(piece)
                    yield {"type": "text", "data": piece}
                think = delta.get("reasoning_content") or delta.get("reasoning")
                if think:
                    reasoning_parts.append(think)
                    yield {"type": "reasoning", "data": think}
    except (urllib.error.URLError, socket.timeout, OSError):
        yield {"type": "error", "data": {"code": "UNREACHABLE",
                                         "message": "流式连接中断：" + _backends.ERR["UNREACHABLE"]}}
        return
    finally:
        try:
            resp.close()
        except Exception:  # noqa: BLE001 - 关闭失败不影响结果
            pass
    if usage:
        yield {"type": "usage", "data": usage}
    yield {"type": "done", "data": {
        "text": "".join(text_parts),
        "reasoning": "".join(reasoning_parts),
        "usage": usage or _usage.estimate_usage(
            _usage.messages_char_count(messages), len("".join(text_parts))),
    }}


def _main():
    import argparse

    parser = argparse.ArgumentParser(description="OpenAI 兼容模型客户端（不打印密钥）")
    parser.add_argument("--backend", help="后端名（默认取配置里的 default）")
    parser.add_argument("--model", help="覆盖模型名")
    parser.add_argument("--prompt", help="单轮提问")
    parser.add_argument("--system", default="", help="系统提示词")
    parser.add_argument("--stream", action="store_true", help="流式输出")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--json", action="store_true", help="输出 JSON（含用量）")
    args = parser.parse_args()

    if not args.prompt:
        print(json.dumps(_backends.list_backends(), ensure_ascii=False, indent=2))
        return
    messages = ([{"role": "system", "content": args.system}] if args.system else [])
    messages.append({"role": "user", "content": args.prompt})

    def show(event):
        kind = event["type"]
        if kind == "text":
            print(event["data"], end="", flush=True)
        elif kind == "reasoning":
            print("\n[思考] " + str(event["data"]).strip(), flush=True)
        elif kind == "usage":
            print("\n[用量] " + json.dumps(event["data"], ensure_ascii=False), flush=True)
        elif kind == "error":
            print("\n[错误] %s: %s" % (event["data"]["code"], event["data"]["message"]), flush=True)

    try:
        if args.stream:
            last = None
            for event in stream_chat(messages, args.backend, args.model, args.temperature):
                last = event
                if not args.json or event["type"] in ("error", "usage", "done"):
                    show(event)
            if args.json and last:
                print(json.dumps(last["data"], ensure_ascii=False, indent=2))
            else:
                print()
        else:
            result = chat(messages, args.backend, args.model, args.temperature)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print(result["text"])
                if result["usage"]:
                    print("\n[用量] " + json.dumps(result["usage"], ensure_ascii=False), flush=True)
    except LLMError as exc:
        print("[错误] %s: %s" % (exc.code, exc))
        raise SystemExit(1) from None


if __name__ == "__main__":
    _main()
