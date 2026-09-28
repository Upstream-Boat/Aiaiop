#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""运行时目录 — 所有落盘位置只在这里定义一次，其它模块只引用不拼路径。"""

import os

import config

SKILL_HOME = config.SKILL_HOME
DATA_DIR = config.DATA_DIR

RUNTIME_DIR = os.environ.get("SEC_ASSESSMENT_RUNTIME") or os.path.join(DATA_DIR, "runtime")
RUNS_DIR = os.path.join(RUNTIME_DIR, "runs")
AUDIT_DIR = os.path.join(RUNTIME_DIR, "audit")
REPORTS_DIR = os.path.join(RUNTIME_DIR, "reports")

AUDIT_LOG = os.path.join(AUDIT_DIR, "audit.jsonl")
AUDIT_ANCHORS = os.path.join(AUDIT_DIR, "anchors.jsonl")
AUDIT_STATE = os.path.join(AUDIT_DIR, "state.json")
AUDIT_SECRET_FILE = os.path.join(AUDIT_DIR, ".chain-secret")

# 全局事件流：控制台顶栏与跨任务的实时提示读它
STREAM_LOG = os.path.join(RUNTIME_DIR, "stream.jsonl")


def ensure_dirs():
    """按需建目录（幂等）。写入前调用一次即可。"""
    for path in (RUNTIME_DIR, RUNS_DIR, AUDIT_DIR, REPORTS_DIR):
        os.makedirs(path, exist_ok=True)
    return RUNTIME_DIR


def run_dir(run_id):
    return os.path.join(RUNS_DIR, run_id)


def report_dir(run_id):
    return os.path.join(REPORTS_DIR, run_id)
