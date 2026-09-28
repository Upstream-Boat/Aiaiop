#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""智能体角色 — 把 43 个工具串成「判定 → 执行 → 复核 → 报告」。

    planner   判定：选哪些工具、顺序、参数、为什么
    executor  执行：真正调用工具（复用 registry 的 handler）
    critic    复核：把原始输出收敛成结构化发现，压误报、定严重级
    reporter  报告：产出 HTML / Markdown / JSON
    runner    编排：串起四步，并把每一步写进任务轨迹与审计链

模型可用时用模型判定与复核；模型不可用时退到规则实现，保证离线环境也能完整演示。
"""

from . import catalog, critic, executor, planner, reporter, runner, verifier  # noqa: F401

__all__ = ["catalog", "critic", "executor", "planner", "reporter", "runner", "verifier"]
