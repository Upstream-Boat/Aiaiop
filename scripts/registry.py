#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""工具注册框架 — 每个工具一个文件，通过 @tool 自注册。

与 8000 打包版 (security-tools/tools/registry.py) 同一约定，保持可互换。
"""

import importlib
import os
from typing import Any, Callable, Dict, List

REGISTRY: Dict[str, Dict[str, Any]] = {}
HANDLERS: Dict[str, Callable] = {}

TOOLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools")
PKG_PREFIX = "tools"


def tool(name: str, description: str, input_schema: Dict = None, **kwargs):
    """装饰器：注册一个工具。

    用法::

        @tool("nmap_quick_scan", "快速服务识别扫描",
              {"properties": {"target": {"type": "string"}}, "required": ["target"]})
        def nmap_quick_scan(params):
            return {"success": True, "returncode": 0, "output": "..."}
    """
    schema = {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": (input_schema or {}).get("properties", {}),
            "required": (input_schema or {}).get("required", []),
        },
    }
    for key, value in kwargs.items():
        schema[key] = value

    # 重名直接抛错：工具名就是 agent 的调用键，静默覆盖比当场崩掉难查得多
    def decorator(fn: Callable):
        if name in REGISTRY:
            raise RuntimeError(f"工具名重复注册: {name}")
        REGISTRY[name] = schema
        HANDLERS[name] = fn
        return fn

    return decorator


# MCP、call.py --list、控制台工具墙都读这一份清单，三处必须一致
def get_all_tools() -> List[Dict]:
    return list(REGISTRY.values())


# 取不到就返回 None，由调用方决定怎么写进轨迹（executor 会记成"工具没有实现"）
def get_handler(name: str) -> Callable:
    return HANDLERS.get(name)


EXTERNAL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "external")


def external_registrar():
    """适配 external/ 模块的 _register(reg) 协议。

    那些模块的 handler 签名是 fn(name, params)，这里包装成本项目的 fn(params)。
    """
    def reg(schema):
        def wrapper(fn):
            @tool(schema["name"], schema.get("description", ""), schema.get("inputSchema"))
            def _handler(params, _fn=fn, _name=schema["name"]):
                return _fn(_name, params or {})
            return fn
        return wrapper
    return reg


def auto_discover() -> List[str]:
    """导入 tools/ 与 external/ 下的所有工具模块，返回加载失败的模块列表。"""
    failed = []
    for root, dirs, files in os.walk(TOOLS_DIR):
        dirs[:] = [d for d in dirs if not d.startswith("_") and d != "__pycache__"]
        for fname in sorted(files):
            if fname.startswith("_") or not fname.endswith(".py"):
                continue
            rel = os.path.relpath(os.path.join(root, fname), TOOLS_DIR)[:-3]
            mod_name = f"{PKG_PREFIX}." + rel.replace(os.sep, ".")
            try:
                importlib.import_module(mod_name)
            except Exception as exc:
                failed.append(f"{mod_name}: {exc}")

    if os.path.isdir(EXTERNAL_DIR):
        for fname in sorted(os.listdir(EXTERNAL_DIR)):
            if fname.startswith("_") or not fname.endswith(".py"):
                continue
            mod_name = f"external.{fname[:-3]}"
            try:
                module = importlib.import_module(mod_name)
                if hasattr(module, "_register"):
                    module._register(external_registrar())
            except Exception as exc:
                failed.append(f"{mod_name}: {exc}")
    return failed
