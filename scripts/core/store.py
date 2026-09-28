#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""任务轨迹存储 — append-only，一个任务一个目录。

    data/runtime/runs/<run_id>/meta.json       任务概要（状态、计数、当前阶段）
    data/runtime/runs/<run_id>/events.jsonl    事件流（每行一个事件，永不改写）
    data/runtime/stream.jsonl                  全局事件流（控制台实时提示用）

设计取舍：不用数据库。演示现场可能只有一台离线机器，JSONL 可以随时用 cat/tail 佐证，
也天然符合"轨迹不可被悄悄改写"的审计诉求（改写会在审计链里暴露）。
"""

import contextlib
import datetime
import fcntl
import json
import os
import secrets

from . import paths

# 事件类型（前端按类型渲染，新增类型只加不删）
EVENT_TYPES = (
    "run",        # 任务开始/结束
    "stage",      # 阶段推进：plan / authorize / exec / verify / crosscheck / report
    "plan",       # 规划结果（要调用哪些工具、顺序、理由）
    "tool_call",  # 工具调用
    "tool_result",
    "text",       # 模型正文分片
    "reasoning",  # 模型思考分片
    "usage",      # token 用量（真值或估算，带 source）
    # 工具运行中的实时进度：输出尾巴 + 已耗时。控制台据此显示"这个工具此刻在做什么"，
    # 没有它就只能显示一个"运行中"三个字，跑长任务时完全看不出进展。
    "tool_progress",
    "rules",      # 规则库状态/更新进度
    "error",
    "done",
)

# 完整工具输出落盘：<run>/outputs/step-<n>-<tool>.txt
# 事件流里只放开头（截断是为了省上下文），原文放文件，控制台要全文时来取。
OUTPUT_DIR = "outputs"
MAX_OUTPUT_FILE = 8 * 1024 * 1024


def _now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


# 任务号 = 人可读的时间戳 + 两位随机：同一秒起两个任务也不会撞名
def new_id(prefix="R"):
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return "%s-%s-%s" % (prefix, stamp, secrets.token_hex(2))


@contextlib.contextmanager
def _locked(path):
    """文件锁：控制台、MCP、命令行可能同时写，用 flock 串行化。"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


# 文件坏了或不存在都当"没写过"：某个任务的 meta 缺了一块，不该让整页读不出来
def _read_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


# 先写 .tmp 再 os.replace：写到一半被杀也不会留下半截 JSON
def _write_json(path, payload):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def meta_path(run_id):
    return os.path.join(paths.run_dir(run_id), "meta.json")


def events_path(run_id):
    return os.path.join(paths.run_dir(run_id), "events.jsonl")


def _safe_name(text):
    return "".join(ch if (ch.isalnum() or ch in "._-") else "_"
                   for ch in str(text or "")) or "output"


# 完整输出落盘是"旁路"：写不进去不该影响这次调用，也不该让任务失败，
# 所以这里只返回 ""，由调用方决定要不要在事件里记 output_file
def output_name(step, tool):
    """一次调用的原文文件名。收尾落盘（save_output）和运行中边跑边写（live_output）
    用的是同一个名字 —— 界面在工具还没跑完时按它去读增量，跑完读到的就是同一份的完整版。"""
    return "step-%s-%s.txt" % (step or 0, _safe_name(tool))


def live_output(run_id, step, tool):
    """打开"运行中就在写"的原文文件，返回 (文件对象, 绝对路径)；开不了返回 (None, "")。

    为什么要它：原文原先只在收尾时一次性落盘，工具跑完之前界面上什么都看不到 ——
    "实时输出"就只剩进度事件里那个 1200 字的尾巴窗口，看不出输出在长。
    改成边跑边写之后，控制台直接读这个文件，"一点一点出结果"才是真的。
    """
    if not run_id:
        return None, ""
    path = os.path.join(paths.run_dir(run_id), OUTPUT_DIR, output_name(step, tool))
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return open(path, "w", encoding="utf-8", errors="replace"), path
    except OSError:
        return None, ""


def save_output(run_id, step, tool, text):
    """把一次调用的完整原始输出落盘，返回相对文件名（写不进去返回 ""）。"""
    text = text or ""
    if not run_id or not text:
        return ""
    name = output_name(step, tool)
    try:
        target_dir = os.path.join(paths.run_dir(run_id), OUTPUT_DIR)
        os.makedirs(target_dir, exist_ok=True)
        tmp = os.path.join(target_dir, name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as handle:
            handle.write(text[:MAX_OUTPUT_FILE])
            if len(text) > MAX_OUTPUT_FILE:
                handle.write("\n[TRUNCATED] 完整输出超过 %d 字符，仅保留前段\n"
                             % MAX_OUTPUT_FILE)
        os.replace(tmp, os.path.join(target_dir, name))
    except OSError:
        return ""
    return "%s/%s" % (OUTPUT_DIR, name)


def read_output(run_id, name, limit=0):
    """读回落盘的完整输出。name 只允许 OUTPUT_DIR 下的文件名，防目录穿越。"""
    name = os.path.basename(str(name or ""))
    if not run_id or not name:
        return ""
    path = os.path.join(paths.run_dir(run_id), OUTPUT_DIR, name)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read(limit if limit and limit > 0 else -1)
    except OSError:
        return ""
    return text


def create(title, kind="task", source="console", meta=None):
    """新建任务。返回任务概要（含 id）。"""
    paths.ensure_dirs()
    run_id = new_id()
    os.makedirs(paths.run_dir(run_id), exist_ok=True)
    summary = {
        "id": run_id,
        "title": title or "未命名任务",
        "kind": kind,
        "source": source,
        "status": "running",
        "stage": "",
        "created_at": _now(),
        "updated_at": _now(),
        "seq": 0,
        "counts": {"tools": 0, "findings": 0},
        "usage": None,
        "model": "",
        "backend": "",
        "meta": meta or {},
    }
    _write_json(meta_path(run_id), summary)
    append(run_id, "run", stage="init", message="任务创建", data={"title": summary["title"]})
    return get(run_id)


# 概要和事件流分两个文件：概要小、被列表频繁读；事件流大、按 seq 增量拉
def get(run_id):
    return _read_json(meta_path(run_id))


def list_runs(limit=50):
    """按更新时间倒序列出任务。"""
    paths.ensure_dirs()
    items = []
    try:
        names = os.listdir(paths.RUNS_DIR)
    except OSError:
        return []
    for name in names:
        summary = _read_json(meta_path(name))
        if summary:
            items.append(summary)
    items.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
    return items[:limit]


def append(run_id, event_type, stage="", message="", data=None):
    """追加一个事件：写任务事件流 + 更新概要 + 记一条全局流。"""
    paths.ensure_dirs()
    lock = os.path.join(paths.run_dir(run_id), ".lock")
    entry = None
    with _locked(lock):
        summary = get(run_id)
        if not summary:
            raise KeyError("任务不存在: %s" % run_id)
        summary["seq"] = int(summary.get("seq") or 0) + 1
        entry = {
            "seq": summary["seq"],
            "ts": _now(),
            "type": event_type,
            "stage": stage,
            "message": message,
            "data": data or {},
        }
        with open(events_path(run_id), "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        summary["updated_at"] = entry["ts"]
        if stage:
            summary["stage"] = stage
        if event_type == "tool_call":
            summary["counts"]["tools"] = int(summary["counts"].get("tools", 0)) + 1
        if event_type == "usage" and isinstance(data, dict):
            summary["usage"] = data
            # 后端与模型名顺手落到概要上：报告里写着"推理后端 StepFun ｜ 模型 step-3.7-flash"，
            # 任务概要里却是空的，同一件事两个说法。只补空值，不让后写的覆盖先前的。
            for key in ("backend", "model"):
                if data.get(key) and not summary.get(key):
                    summary[key] = data[key]
        if event_type == "done":
            summary["status"] = data.get("status", "done") if isinstance(data, dict) else "done"
            # 发现数要跟着终态一起落盘。以前只写进事件流，概要里的 counts.findings
            # 永远是 0 —— "报告里有 3 条发现、任务列表里写 0" 就是这么来的。
            if isinstance(data, dict) and isinstance(data.get("findings"), int):
                summary["counts"]["findings"] = data["findings"]
        elif event_type == "error" and isinstance(data, dict) and data.get("status"):
            # 只有"显式声明终态"的 error 才算任务结束。判定阶段那种
            # "模型不可用，改用规则判定" 的 error 只是警告，任务还要继续跑，
            # 不能把它当成失败收尾。
            # 少了这一条，模型调不通的对话任务会永远停在 running（前端一直转圈）。
            summary["status"] = data["status"]
        _write_json(meta_path(run_id), summary)
    _append_stream(run_id, entry)
    return entry


# 只补指定字段，不整体覆盖；updated_at 必须推新，否则任务列表的排序会乱
def update(run_id, **patch):
    lock = os.path.join(paths.run_dir(run_id), ".lock")
    with _locked(lock):
        summary = get(run_id)
        if not summary:
            raise KeyError("任务不存在: %s" % run_id)
        summary.update(patch)
        summary["updated_at"] = _now()
        _write_json(meta_path(run_id), summary)
        return summary


def events(run_id, after=0, limit=2000):
    """读事件（after 为已读的最大 seq，用于增量拉取）。"""
    out = []
    try:
        with open(events_path(run_id), "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if int(entry.get("seq") or 0) > int(after or 0):
                    out.append(entry)
    except OSError:
        return []
    return out[-limit:] if limit else out


def _append_stream(run_id, entry):
    """全局流：只保留跨任务视图需要的字段，避免把大正文复制一份。"""
    try:
        with _locked(paths.STREAM_LOG):
            with open(paths.STREAM_LOG, "a", encoding="utf-8") as handle:
                handle.write(json.dumps({
                    "run": run_id, "seq": entry["seq"], "ts": entry["ts"],
                    "type": entry["type"], "stage": entry["stage"], "message": entry["message"],
                }, ensure_ascii=False) + "\n")
    except OSError:
        pass


def tail_stream(limit=80):
    if not os.path.isfile(paths.STREAM_LOG):
        return []
    with open(paths.STREAM_LOG, "r", encoding="utf-8") as handle:
        lines = handle.readlines()[-limit:]
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out
