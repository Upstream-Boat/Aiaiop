#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""事实层 — 任务轨迹、审计链、规则库。

这一层不依赖任何 Web 框架：命令行、MCP 服务、控制台后端都从它取事实。

    from core import store, audit, rules
"""

from . import audit, paths, rules, store  # noqa: F401

__all__ = ["audit", "paths", "rules", "store"]
