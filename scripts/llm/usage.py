#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""上游 Token 用量口径（移植自平台 server/src/usage.js）。

口径原则：只认上游自己算出来的 token 数，本 skill 不自创 tokenizer。

- OpenAI 兼容网关（GPUStack / vLLM / StepFun）：响应体或流末尾的 usage 字段，逐请求精确；
- 上游确实没给（如纯工具节点）：返回 None，由调用方决定是否回落估算并标 estimated。

两处历史坑已在平台踩过，这里直接沿用结论：
  1. 占位值：FastGPT 的 OpenAI 兼容 usage 恒为 1/1/1，直接用会把真实用量压成 1，必须丢弃；
  2. 多轮工具调用：每次上游请求都会回一份用量，逐轮累加才是本轮总消耗。
"""

USAGE_SOURCE = {
    "OPENAI": "openai",        # OpenAI 兼容网关返回的 usage
    "ESTIMATED": "estimated",  # 上游未提供时的兜底估算（前端单独提示）
}


def _int_of(value):
    try:
        n = round(float(value))
    except (TypeError, ValueError):
        return 0
    return n if n > 0 else 0


def is_placeholder_usage(usage):
    """识别占位 usage（1/1/1）：这种值不是真实用量，必须丢掉。"""
    if not isinstance(usage, dict):
        return False
    p = usage.get("prompt_tokens", usage.get("promptTokens"))
    c = usage.get("completion_tokens", usage.get("completionTokens"))
    t = usage.get("total_tokens", usage.get("totalTokens"))
    if p is None and c is None and t is None:
        return False
    return _num(p) == 1 and _num(c) == 1 and _num(t) == 1


def _num(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def normalize_usage(raw):
    """归一化 OpenAI 兼容的 usage（兼容 prompt_tokens / promptTokens 两种命名）。"""
    if not isinstance(raw, dict):
        return None
    body = raw.get("usage") if isinstance(raw.get("usage"), dict) else raw
    keys = ("prompt_tokens", "completion_tokens", "total_tokens",
            "promptTokens", "completionTokens", "totalTokens")
    if not any(k in body for k in keys):
        return None
    if is_placeholder_usage(body):
        return None
    prompt = _int_of(body.get("prompt_tokens", body.get("promptTokens")))
    completion = _int_of(body.get("completion_tokens", body.get("completionTokens")))
    total = _int_of(body.get("total_tokens", body.get("totalTokens"))) or (prompt + completion)
    if not prompt and not completion and not total:
        return None
    return {"promptTokens": prompt, "completionTokens": completion, "totalTokens": total}


def merge_usage(a, b):
    """多轮（工具调用循环）用量累加：只要有一轮是估算，整体就标 estimated。"""
    if not a:
        return b or None
    if not b:
        return a
    prompt = (a.get("promptTokens") or 0) + (b.get("promptTokens") or 0)
    completion = (a.get("completionTokens") or 0) + (b.get("completionTokens") or 0)
    estimated = USAGE_SOURCE["ESTIMATED"]
    source = estimated if estimated in (a.get("source"), b.get("source")) else (b.get("source") or a.get("source"))
    return {"promptTokens": prompt, "completionTokens": completion,
            "totalTokens": prompt + completion, "source": source}


def estimate_usage(prompt_chars, output_chars):
    """兜底估算：仅在上游完全没给用量时使用，结果必须标 estimated 以免与真值混淆。"""
    prompt = -(-max(0, int(prompt_chars or 0)) // 3)
    completion = -(-max(0, int(output_chars or 0)) // 3)
    return {"promptTokens": prompt, "completionTokens": completion,
            "totalTokens": prompt + completion, "source": USAGE_SOURCE["ESTIMATED"]}


def stamp_usage(usage, backend=None, model=None):
    """把"这次请求走的是哪个后端 / 哪个模型"盖到 usage 上。

    报告里要给甲方交代"这轮判定用的是什么模型"，而这个信息跟着 usage 一路传到报告最顺手。
    上游没回 usage 时也要留档（模型名本身就是要交代的事实），所以允许 usage 为空。
    """
    tagged = dict(usage) if isinstance(usage, dict) else {}
    if backend:
        tagged.setdefault("backend", backend)
    if model:
        tagged.setdefault("model", model)
    return tagged or None


def messages_char_count(messages):
    """消息数组的字符数（估算输入用；多模态 content 为数组时只算其中文本部分）。"""
    total = 0
    for msg in messages if isinstance(messages, list) else []:
        content = (msg or {}).get("content")
        if isinstance(content, str):
            total += len(content)
        elif isinstance(content, list):
            for part in content:
                text = (part or {}).get("text")
                if isinstance(text, str):
                    total += len(text)
        elif content is not None:
            total += len(str(content))
    return total
