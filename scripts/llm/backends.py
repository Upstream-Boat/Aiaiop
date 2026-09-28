#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""模型后端清单 — 三个来源，同一套 OpenAI 兼容协议。

| 后端 | 用途 | 端点（环境变量） |
| --- | --- | --- |
| gpustack | 内网/开发联调，算力集群开机即用 | GPUSTACK_BASE_URL / GPUSTACK_API_KEY |
| spark-local | 现场 DGX Spark 本机模型 | SPARK_LLM_BASE_URL（默认 127.0.0.1:11435/v1） |
| stepfun | 阶跃星辰（StepFun）模型 | STEPFUN_BASE_URL / STEPFUN_API_KEY |

配置优先级：SEC_ASSESSMENT_LLM_BACKENDS 指向的 JSON > data/llm_backends.json > 环境变量。
JSON 形如::

    {"default": "gpustack",
     "backends": [{"name": "gpustack", "label": "算力集群", "base_url": "http://<集群端点>/v1",
                   "api_key": "...", "model": "qwen3.6-35b-a3b", "timeout": 180}]}

安全约定：list_backends() 永不回传密钥明文（只给 has_key 布尔），只有 resolve() 内部使用。
"""

import json
import os
import socket
import urllib.error
import urllib.request

from . import usage as _usage  # noqa: F401  (保持包内导入路径一致)

SKILL_HOME = os.environ.get("SEC_ASSESSMENT_HOME") or os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
CONFIG_PATH = os.environ.get("SEC_ASSESSMENT_LLM_BACKENDS") or os.path.join(
    SKILL_HOME, "data", "llm_backends.json"
)

ERR = {
    "NOT_CONFIGURED": "后端未配置（缺少端点或密钥），请检查环境变量或 data/llm_backends.json",
    "BAD_URL": "端点地址不合法（只支持 http/https，且不应带账号密码）",
    "UNREACHABLE": "后端不可达，请检查地址与网络（集群是否开机）",
    "AUTH_FAILED": "后端密钥无效或无权限（401/403）",
    "TIMEOUT": "后端请求超时，请稍后重试",
    "BAD_DATA": "后端返回数据异常，请检查模型名与端点路径",
    "UNKNOWN": "后端请求失败",
}

# 内置后端模板：默认端点 + 对应的环境变量名
SPECS = {
    "gpustack": {
        "label": "算力集群（GPUStack）",
        "base_env": "GPUSTACK_BASE_URL",
        "key_env": "GPUSTACK_API_KEY",
        "model_env": "GPUSTACK_MODEL",
        "default_base": "",
        "default_model": "",
    },
    "spark-local": {
        "label": "DGX Spark 本机模型",
        "base_env": "SPARK_LLM_BASE_URL",
        "key_env": "SPARK_LLM_API_KEY",
        "model_env": "SPARK_LLM_MODEL",
        "default_base": "http://127.0.0.1:11435/v1",
        "default_model": "",
    },
    "stepfun": {
        "label": "StepFun 阶跃星辰",
        "base_env": "STEPFUN_BASE_URL",
        "key_env": "STEPFUN_API_KEY",
        "model_env": "STEPFUN_MODEL",
        "default_base": "https://api.stepfun.com/v1",
        "default_model": "",
    },
}


def chat_url(base_url):
    """补全对话接口路径：端点既可写基址，也可直接写完整的 chat/completions。"""
    base = (base_url or "").rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    return base + "/chat/completions"


def models_url(base_url):
    base = (base_url or "").rstrip("/")
    if base.endswith("/chat/completions"):
        base = base[: -len("/chat/completions")]
    return base + "/models"


def _from_env(name):
    spec = SPECS.get(name)
    if not spec:
        return None
    base = os.environ.get(spec["base_env"], "") or spec["default_base"]
    key = os.environ.get(spec["key_env"], "")
    model = os.environ.get(spec["model_env"], "") or spec["default_model"]
    if not base:
        return None
    return {
        "name": name,
        "label": spec["label"],
        "base_url": base,
        "api_key": key,
        "model": model,
        "timeout": None,
    }


def _from_file():
    if not CONFIG_PATH or not os.path.isfile(CONFIG_PATH):
        return None
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    items = []
    for entry in raw.get("backends") or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or "custom"
        spec = SPECS.get(name, {})
        items.append({
            "name": name,
            "label": entry.get("label") or spec.get("label") or name,
            "base_url": entry.get("base_url") or spec.get("default_base") or "",
            "api_key": entry.get("api_key") or "",
            "model": entry.get("model") or "",
            "timeout": entry.get("timeout"),
        })
    if not items:
        return None
    return {"default": raw.get("default") or items[0]["name"], "backends": items}


def load_config():
    """返回 {default, backends}：文件优先，其次环境变量，最后空清单。"""
    conf = _from_file()
    if conf:
        return conf
    backends = [b for b in (_from_env(name) for name in SPECS) if b]
    default = os.environ.get("SEC_ASSESSMENT_LLM_BACKEND") or (backends[0]["name"] if backends else "")
    return {"default": default, "backends": backends}


def list_backends():
    """列后端（脱敏）：只给 has_key，不给密钥明文，可直接打印或回传前端。"""
    conf = load_config()
    out = []
    for item in conf["backends"]:
        out.append({
            "name": item["name"],
            "label": item["label"],
            "base_url": item["base_url"],
            "model": item["model"],
            "has_key": bool(item["api_key"]),
            "default": item["name"] == conf["default"],
        })
    return out


def resolve(name=None):
    """按名字取后端；不传则取默认后端。取不到时抛 ValueError（不静默回退到别家）。"""
    conf = load_config()
    target = name or conf["default"]
    if not target:
        raise ValueError(ERR["NOT_CONFIGURED"])
    for item in conf["backends"]:
        if item["name"] == target:
            if not item["base_url"]:
                raise ValueError(ERR["NOT_CONFIGURED"])
            return dict(item)
    raise ValueError("未知后端: %s（可用: %s）" % (target, ", ".join(b["name"] for b in conf["backends"]) or "无"))


def check_url(url):
    """地址合法性：仅 http/https，且不允许内嵌账号密码（避免密钥写进地址被日志带出）。"""
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url or "")
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    return parsed


def health(name=None, timeout=8.0):
    """探测后端是否可用：GET /models，按平台同一套异常分类返回 code + 中文提示。"""
    try:
        backend = resolve(name)
    except ValueError as exc:
        return {"ok": False, "backend": name, "code": "NOT_CONFIGURED", "message": str(exc)}
    parsed = check_url(backend["base_url"])
    if not parsed:
        return {"ok": False, "backend": backend["name"], "code": "BAD_URL", "message": ERR["BAD_URL"]}
    req = urllib.request.Request(models_url(backend["base_url"]), method="GET")
    req.add_header("Accept", "application/json")
    if backend["api_key"]:
        req.add_header("Authorization", "Bearer " + backend["api_key"])
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        code = "AUTH_FAILED" if exc.code in (401, 403) else "BAD_DATA"
        return {"ok": False, "backend": backend["name"], "code": code,
                "message": "%s（HTTP %s）" % (ERR[code], exc.code)}
    except socket.timeout:
        return {"ok": False, "backend": backend["name"], "code": "TIMEOUT", "message": ERR["TIMEOUT"]}
    except urllib.error.URLError:
        return {"ok": False, "backend": backend["name"], "code": "UNREACHABLE", "message": ERR["UNREACHABLE"]}
    except OSError:
        return {"ok": False, "backend": backend["name"], "code": "UNKNOWN", "message": ERR["UNKNOWN"]}
    try:
        data = json.loads(body)
    except ValueError:
        return {"ok": False, "backend": backend["name"], "code": "BAD_DATA", "message": ERR["BAD_DATA"]}
    models = [m.get("id") for m in (data.get("data") or []) if isinstance(m, dict)]
    return {"ok": True, "backend": backend["name"], "code": "OK", "message": "可用",
            "models": models[:50], "model_count": len(models)}


def _main():
    import argparse

    parser = argparse.ArgumentParser(description="模型后端探测（不打印密钥明文）")
    parser.add_argument("--health", action="store_true", help="逐个探测 /models")
    parser.add_argument("--json", action="store_true", help="JSON 输出")
    args = parser.parse_args()

    items = list_backends()
    if args.health:
        for item in items:
            item.update(health(item["name"]))
    print(json.dumps(items, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    _main()
