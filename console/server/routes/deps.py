#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""依赖与工具状态接口 — 回答"这台机器上，现在哪些工具能用"。

两块数据，两个来源，都不复制 skill 的业务逻辑：

    GET /api/deps    外部命令 + 自带资源。清单与探测函数直接取自 skill 的
                     scripts/check_deps.py（它本来就带"真实执行探测"：命令在 PATH
                     里不等于能用，nikto 就是活例子），这里只把结果结构化成 JSON。
    GET /api/tools   43 个已注册工具：安全分级、参数、依赖是否就绪、历史调用统计。
                     依赖关系是按工具源码扫描推断的（工具里写的是字面命令名，
                     如 "hydra %s ..."），所以标为"推断"，不当成权威结论。
"""

import os
import re

from fastapi import APIRouter

router = APIRouter(tags=["deps"])

# 工具调用统计的回溯范围：读太多任务会拖慢页面，最近若干条足够说明"哪些工具在用"
STATS_RUNS = 80
SAMPLE_RUNS = 20     # 抽样展示参数样例


def _check_deps():
    """导入 skill 的 check_deps 模块（复用它的清单与探测实现）。"""
    import check_deps
    return check_deps


# ---------------------------------------------------------------- 外部依赖

@router.get("/deps")
def get_deps(probe: int = 1):
    """外部命令与自带资源状态。probe=0 只查存在性（更快，界面上的"快速检查"用）。"""
    import shutil

    check_deps = _check_deps()
    do_probe = bool(probe)

    commands = []
    for cmd, purpose, hint in check_deps.BINARIES:
        path = shutil.which(cmd)
        item = {"cmd": cmd, "purpose": purpose, "hint": hint,
                "present": bool(path), "path": path or "",
                "ok": bool(path), "detail": ""}
        if path and do_probe:
            ok, detail = check_deps._probe(cmd, path)
            item["detail"] = detail or ""
            # _probe 返回 None 表示"没有探测参数，跳过"——有文件就当作可用
            item["ok"] = True if ok is None else bool(ok)
        commands.append(item)

    resources = []
    for label, path, hint in check_deps.DATA:
        exists = bool(path) and os.path.exists(path)
        resources.append({"label": label, "path": path or "", "hint": hint,
                          "exists": exists,
                          "size": check_deps._size(path) if exists else 0})

    missing = [c["cmd"] for c in commands if not c["present"]]
    broken = [(c["cmd"], c["detail"]) for c in commands if c["present"] and not c["ok"]]
    missing_res = [r["label"] for r in resources if not r["exists"]]

    return {
        "probe": do_probe,
        "commands": commands,
        "resources": resources,
        "summary": {
            "commands_total": len(commands),
            "commands_ready": len([c for c in commands if c["present"] and c["ok"]]),
            "missing": missing,
            "broken": [{"cmd": cmd, "detail": detail} for cmd, detail in broken],
            "missing_resources": missing_res,
            "ready": not missing and not broken and not missing_res,
        },
        "nvd_key": bool(_nvd_key_hint()),
        "note": "只检查、不安装；缺什么会给出安装命令。",
    }


def _nvd_key_hint():
    """只回布尔，不回明文（与 config 路由同一口径）。"""
    try:
        import config
        return config.NVD_API_KEY or ""
    except Exception:                                   # noqa: BLE001 - 状态页不能因为读配置失败而报错
        return ""


# ---------------------------------------------------------------- 工具状态

def _tool_sources():
    """工具名 → 它所在的源码文件（按源码里的字面名字推断）。"""
    import registry

    texts = {}
    for root in (registry.TOOLS_DIR, registry.EXTERNAL_DIR):
        if not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            if not name.endswith(".py") or name.startswith("_"):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    texts[path] = handle.read()
            except OSError:
                continue

    mapping = {}
    for tool_name in registry.REGISTRY:
        hits = [path for path, text in texts.items()
                if ('"%s"' % tool_name) in text or ("'%s'" % tool_name) in text]
        mapping[tool_name] = hits
    return texts, mapping


def _deps_of(tool_name, mapping, texts, binaries):
    """扫该工具源码里出现的命令名 —— 标为"推断"，不当权威结论。"""
    hits = []
    for path in mapping.get(tool_name, []):
        text = texts.get(path, "")
        for cmd in binaries:
            if re.search(r"\b%s\b" % re.escape(cmd), text) and cmd not in hits:
                hits.append(cmd)
    return hits


def _tool_stats():
    """从任务轨迹聚合每个工具的调用次数 / 成功数 / 拦截数 / 最近一次调用。"""
    from core import store

    stats = {}
    for run in store.list_runs(limit=STATS_RUNS):
        try:
            events = store.events(run["id"])
        except Exception:                               # noqa: BLE001 - 单个任务读失败不影响整页
            continue
        for event in events:
            data = event.get("data") or {}
            tool = data.get("tool")
            if not tool:
                continue
            row = stats.setdefault(tool, {"calls": 0, "ok": 0, "blocked": 0,
                                          "last_at": "", "total_elapsed": 0.0})
            if event.get("type") == "tool_call":
                row["calls"] += 1
                # store.list_runs() 是"新 → 旧"，无条件赋值会把"最近一次调用"写成
                # 窗口里最早的那次（页面上就成了"刚跑完的工具，最近调用显示几天前"）。
                # 取较大值才是真的最近。
                ts = event.get("ts") or ""
                if ts >= (row["last_at"] or ""):
                    row["last_at"] = ts
            elif event.get("type") == "tool_result":
                if data.get("ok"):
                    row["ok"] += 1
                try:
                    row["total_elapsed"] += float(data.get("elapsed") or 0)
                except (TypeError, ValueError):
                    pass
            elif event.get("type") == "error" and data.get("blocked"):
                row["blocked"] += 1
                ts = event.get("ts") or ""
                if ts >= (row["last_at"] or ""):
                    row["last_at"] = ts
    for row in stats.values():
        row["avg_elapsed"] = round(row["total_elapsed"] / row["calls"], 1) if row["calls"] else None
        row.pop("total_elapsed", None)
    return stats


@router.get("/tools")
def get_tools():
    """43 个工具的清单与状态：安全分级 + 参数 + 依赖推断 + 历史调用。"""
    import shutil

    import registry
    from agents import catalog

    if not registry.REGISTRY:
        registry.auto_discover()

    check_deps = _check_deps()
    binaries = [cmd for cmd, _purpose, _hint in check_deps.BINARIES]
    texts, mapping = _tool_sources()
    stats = _tool_stats()

    items = []
    for name, spec in sorted(registry.REGISTRY.items()):
        schema = spec.get("inputSchema") or {}
        props = schema.get("properties") or {}
        deps = _deps_of(name, mapping, texts, binaries)
        dep_state = []
        for cmd in deps:
            dep_state.append({"cmd": cmd, "present": bool(shutil.which(cmd))})
        row = stats.get(name) or {}
        items.append({
            "name": name,
            "description": (spec.get("description") or "").split("\n")[0][:160],
            "safety": catalog.safety_of(name),
            "params": list(props.keys()),
            "required": list(schema.get("required") or []),
            "deps": dep_state,
            "deps_ready": all(d["present"] for d in dep_state),
            "source": [os.path.relpath(p, registry.TOOLS_DIR.rsplit(os.sep, 1)[0])
                       for p in mapping.get(name, [])],
            "calls": row.get("calls", 0),
            "ok": row.get("ok", 0),
            "blocked": row.get("blocked", 0),
            "avg_elapsed": row.get("avg_elapsed"),
            "last_at": row.get("last_at") or "",
        })

    risky = [i["name"] for i in items if i["safety"] == "risky"]
    not_ready = [i["name"] for i in items if not i["deps_ready"]]
    used = [i["name"] for i in items if i["calls"]]
    return {
        "items": items,
        "scope": "统计范围：最近 %d 个任务" % STATS_RUNS,
        "summary": {
            "total": len(items),
            "risky": len(risky),
            "deps_ready": len(items) - len(not_ready),
            "deps_missing": not_ready,
            "ever_used": len(used),
        },
        "note": "依赖按工具源码里出现的命令名推断。",
    }
