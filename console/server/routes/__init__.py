#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""控制台接口 — 按域拆文件，一个文件一个业务面：

    tasks.py    任务与轨迹（列表、详情、事件、SSE）
    config.py   配置（NVD 密钥 / 模型后端，只写不读明文）
    deps.py     依赖与工具状态（外部命令体检 + 43 个工具的依赖与调用）
    audit.py    审计链（查询、校验、演示用篡改/还原）
    rules.py    规则库（状态、更新进度 SSE、定时更新、更新日志、NVD 密钥）
    llm.py      模型后端（清单、健康探测）
    gpu.py      算力状态（本机 nvidia-smi / GPUStack 集群）
    reports.py  报告（列表、读取、导出）

控制台不下达任务，也不做对话 —— 任务由宿主 Agent / MCP 客户端 / 命令行触发，
控制台只负责配置、观测（轨迹 / 审计 / 规则库 / 报告）与体检。
"""
