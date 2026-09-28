#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""运行中的任务状态 —— 给对话界面/控制台念的一行话。

为什么单独有这个文件：任务是从对话界面（OpenClaw）发起的，执行在另一台机器上，
而宿主的工具调用只会把"命令跑完"之后的输出交回来 —— 一轮扫描十几分钟，中间
对话里只有一句"执行中"，看不到任何进展。控制台能看是因为它直接读轨迹；对话
界面拿不到轨迹，只能靠执行侧主动喂。

所以这里把轨迹里的实时状态压成一行（第几步、什么工具、跑了多久、输出多少、
最新一行是什么），由执行侧的桥（codex-api）在轮询时追加到对话输出里。

零依赖、只读、失败不抛：取不到状态就返回 None，绝不能因为它把任务本身搞挂。
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import store  # noqa: E402

STAGE_NAMES = {
    "init": "准备", "plan": "判定", "authorize": "授权", "exec": "执行",
    "verify": "复核", "crosscheck": "交叉验证", "report": "出报告", "done": "收尾",
}


def _secs(value):
    try:
        value = float(value)
    except (TypeError, ValueError):
        return "-"
    if value < 90:
        return "%.0fs" % value
    if value < 5400:
        return "%dm%02ds" % (value // 60, value % 60)
    return "%.1fh" % (value / 3600)


def _size(chars):
    try:
        chars = int(chars)
    except (TypeError, ValueError):
        return "-"
    if chars < 1024:
        return "%d 字符" % chars
    if chars < 1024 * 1024:
        return "%.1f KB" % (chars / 1024.0)
    return "%.1f MB" % (chars / 1048576.0)


def _last_meaningful(text):
    for line in reversed((text or "").splitlines()):
        line = line.strip()
        if line:
            return line[:120]
    return ""


def snapshot(run_id=None):
    """取一个任务此刻的状态；没有在跑的任务（且没指定 run_id）返回 None。"""
    try:
        if run_id:
            summary = store.get(run_id)
        else:
            running = [item for item in store.list_runs(limit=40)
                       if item.get("status") == "running"]
            summary = running[0] if running else None
        if not summary:
            return None
        run_id = summary.get("id") or run_id
        events = store.events(run_id, limit=4000)
    except Exception:                       # noqa: BLE001 - 状态是旁路，坏了不影响任务
        return None

    total_steps, step, tool, plan_label = 0, 0, "", ""
    elapsed = chars = None
    step_started = ''          # 本步开始的时间戳（tool_progress 缺位时兜底）
    tail = ""
    stages = []
    for event in events:
        data = event.get("data") or {}
        if not isinstance(data, dict):
            data = {}
        etype = event.get("type")
        if etype == "plan":
            total_steps = len(data.get("steps") or []) or total_steps
        elif etype == "tool_call":
            step = data.get("step") or step
            tool = data.get("tool") or tool
            elapsed = chars = None
            tail = ""
            step_started = event.get("ts") or step_started
            step_started = event.get("ts") or ""
        elif etype == "tool_progress":
            if (data.get("step") or step) == step:
                elapsed = data.get("elapsed", elapsed)
                chars = data.get("chars", chars)
                tail = data.get("tail") or tail
        elif etype == "tool_result":
            if (data.get("step") or step) == step:
                tool = data.get("tool") or tool
                elapsed = data.get("elapsed", elapsed)
                result_line = _last_meaningful(data.get("output"))
                if result_line:
                    tail = result_line
        elif etype in ("stage", "done"):
            stages.append(event.get("message") or "")
        elif etype == "plan":
            pass

    status = summary.get("status") or ""
    stage = summary.get("stage") or ""
    created = summary.get("created_at") or ""
    wall = ""
    try:
        started = time.mktime(time.strptime(created[:19], "%Y-%m-%dT%H:%M:%S"))
        wall = _secs(max(0.0, time.time() - started))
    except (ValueError, TypeError):
        pass

    # 有的步骤是纯 python 调用（比如 CVE 匹配），没有外部命令输出，也就不会有
    # tool_progress —— 用 tool_call 的时间戳兜一下，否则"工具已跑多久"一直是空的，
    # 看上去就像那一步卡住了。
    if status == "running" and elapsed is None and step_started:
        try:
            began = time.mktime(time.strptime(step_started[:19], "%Y-%m-%dT%H:%M:%S"))
            elapsed = round(max(0.0, time.time() - began), 1)
        except (TypeError, ValueError):
            elapsed = None

    where = STAGE_NAMES.get(stage, stage or "-")
    if status == "running":
        head = "第 %s/%s 步 %s%s" % (step or "-", total_steps or "-", tool or "",
                                     " 运行中" if tool else "")
    else:
        head = "已结束（%s）" % (status or "-")
    snap = {
        "run_id": run_id,
        "title": summary.get("title") or "",
        "status": status,
        "stage": where,
        "step": step,
        "total_steps": total_steps,
        "tool": tool,
        "elapsed": elapsed,
        "wall": wall,
        "chars": chars,
        "tail": _last_meaningful(tail),
        "last_stage": _last_meaningful("\n".join(stages[-1:])),
        "source": summary.get("source") or "",
    }
    # 顺带把渲染好的一行话也塞进来：调用方（执行侧的桥）只需要一次 JSON 调用，
    # 不用在那边再抄一份格式化逻辑 —— 两边样式不一致时对话里会出现两种进度行。
    snap["line"] = line(snap)
    return snap


def line(snap):
    """压成一行 —— 对话界面里每 15 秒左右追加一行这个。"""
    if not snap:
        return ""
    bits = ["[进度] %s" % (snap.get("stage") or "-")]
    if snap.get("status") == "running":
        bits.append("第 %s/%s 步" % (snap.get("step") or "-", snap.get("total_steps") or "-"))
        if snap.get("tool"):
            bits.append(str(snap["tool"]))
        if snap.get("elapsed"):
            bits.append("工具已跑 %s" % _secs(snap["elapsed"]))
        elif snap.get("wall"):
            bits.append("任务已跑 %s" % snap["wall"])
        if snap.get("chars"):
            bits.append("输出 %s" % _size(snap["chars"]))
    else:
        bits.append(str(snap.get("status") or ""))
    head = " · ".join(bits)
    return "%s\n        最新输出：%s" % (head, snap["tail"]) if snap.get("tail") else head


def main():
    import argparse

    parser = argparse.ArgumentParser(description="运行中任务的一行状态")
    parser.add_argument("run_id", nargs="?", default="", help="任务号；不给就取最近在跑的")
    parser.add_argument("--json", action="store_true", help="输出结构化状态")
    parser.add_argument("--line", action="store_true", help="输出一行文字（默认）")
    args = parser.parse_args()

    snap = snapshot(args.run_id or None)
    if not snap:
        print("（当前没有正在跑的任务）")
        return 0
    if args.json:
        print(json.dumps(snap, ensure_ascii=False, indent=2))
    else:
        print(line(snap))
    return 0


if __name__ == "__main__":
    sys.exit(main())
