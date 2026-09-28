#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""单次调用入口 — 供 agent 直接执行某个安全工具。

用法::

    python3 call.py --list                      # 列出全部工具
    python3 call.py --schema <tool>             # 查看某工具的参数 schema
    python3 call.py <tool> '<json 参数>'         # 执行工具
    python3 call.py <tool> key=value key2=value2 # 便捷参数形式
    python3 call.py <tool> ... --no-record      # 只执行，不写调用记录

执行完会往运行轨迹里写一条"工具直调"的记录（同一天的调用归到同一个任务，
一次调用一个步骤），审计链也记一笔。管理端的"工具"页读的就是这份轨迹：不写的话，
命令行直调在界面上看起来像"这台机器没被调过工具"。
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools"))

from registry import REGISTRY, auto_discover, get_handler  # noqa: E402

COERCE_FIELDS = {"numeric", "integer", "boolean"}


# 工具是自注册的：import 即注册。这里只把加载失败的模块报到 stderr，
# 一个工具装不全，不该连累其它 42 个
def _load():
    failed = auto_discover()
    for line in failed:
        sys.stderr.write(f"[warn] 工具模块加载失败: {line}\n")
    return len(REGISTRY)


# key=value 是给人用的快捷写法；值一律当字符串，类型交给 _coerce 按 schema 转
def _parse_kv(args):
    params = {}
    for item in args:
        if "=" not in item:
            raise SystemExit(f"参数格式应为 key=value: {item}")
        key, value = item.split("=", 1)
        params[key] = value
    return params


def _coerce(tool_name, params):
    """按 schema 把字符串参数转成对应类型。"""
    schema = REGISTRY.get(tool_name, {}).get("inputSchema", {}).get("properties", {})
    out = {}
    for key, value in params.items():
        spec = schema.get(key, {})
        if isinstance(value, str):
            if spec.get("type") == "integer":
                try:
                    value = int(value)
                except ValueError:
                    pass
            elif spec.get("type") == "boolean":
                value = value.strip().lower() in ("1", "true", "yes", "y", "on")
        out[key] = value
    return out


MANUAL_STATE = "cli_run.json"


def _manual_run(date_str):
    """取当天那条"工具直调"任务，没有就建一条。同一天共用一条，免得刷屏。"""
    from core import paths, store

    paths.ensure_dirs()
    state_path = os.path.join(paths.RUNTIME_DIR, MANUAL_STATE)
    try:
        with open(state_path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
    except (OSError, ValueError):
        state = {}
    run_id = state.get("run_id") or ""
    if state.get("date") == date_str and run_id and store.get(run_id):
        return run_id
    summary = store.create("工具直调 %s" % date_str, kind="manual", source="cli",
                           meta={"note": "命令行 call.py 直接调用工具，一次调用一个步骤"})
    with open(state_path + ".tmp", "w", encoding="utf-8") as handle:
        json.dump({"date": date_str, "run_id": summary["id"]}, handle, ensure_ascii=False)
    os.replace(state_path + ".tmp", state_path)
    return summary["id"]


def _record(tool_name, params, result, elapsed):
    """把这次直调写进轨迹与审计链。写不进去不能连累调用本身，只提示一句。"""
    try:
        from agents import catalog
        from core import audit, store

        run_id = _manual_run(time.strftime("%Y-%m-%d"))
        step = int((store.get(run_id) or {}).get("counts", {}).get("tools", 0)) + 1
        ok = bool(result.get("success"))
        output = result.get("output") or ""
        # 完整原文落盘：轨迹里只放开头（省上下文），控制台要全文按文件名来取
        output_file = store.save_output(run_id, step, tool_name, output)
        store.append(run_id, "tool_call", stage="exec",
                     message="调用 %s" % tool_name,
                     data={"step": step, "tool": tool_name, "params": params,
                           "why": "命令行直调（call.py）",
                           "safety": catalog.safety_of(tool_name)})
        store.append(run_id, "tool_result", stage="exec",
                     message="%s %s（%ss）" % (tool_name, "完成" if ok else "失败", elapsed),
                     data={"step": step, "tool": tool_name, "ok": ok,
                           "returncode": result.get("returncode"), "elapsed": elapsed,
                           "error": "" if ok else output[:200],
                           "output_file": output_file, "output_size": len(output),
                           "output": output[:2000], "truncated": len(output) > 2000})
        # 直调是一次性的：不留 running 状态，否则界面上会一直显示"正在跑"
        store.append(run_id, "done", stage="exec", message="本次直调结束",
                     data={"status": "done", "step": step})
        audit.record("tool_call", target_type="tool", target_id=tool_name,
                     detail="cli直调 step=%d ok=%s elapsed=%ss" % (step, ok, elapsed),
                     actor="cli")
    except Exception as exc:  # noqa: BLE001 - 记录失败不该让调用失败
        sys.stderr.write("[warn] 调用记录写入失败：%s\n" % exc)


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0

    if argv[0] == "--list":
        _load()
        for name, spec in sorted(REGISTRY.items()):
            print(f"{name:32s} {spec.get('description', '')}")
        print(f"\n共 {len(REGISTRY)} 个工具")
        return 0

    if argv[0] == "--schema":
        _load()
        if len(argv) < 2 or argv[1] not in REGISTRY:
            print(f"未找到工具: {argv[1] if len(argv) > 1 else '(未指定)'}", file=sys.stderr)
            return 2
        print(json.dumps(REGISTRY[argv[1]], ensure_ascii=False, indent=2))
        return 0

    record = "--no-record" not in argv
    argv = [a for a in argv if a != "--no-record"]

    tool_name = argv[0]
    _load()
    if tool_name not in REGISTRY:
        print(f"未找到工具: {tool_name}（用 --list 查看）", file=sys.stderr)
        return 2

    raw = argv[1:]
    if len(raw) == 1 and raw[0].lstrip().startswith("{"):
        params = json.loads(raw[0])
    elif raw:
        params = _parse_kv(raw)
    else:
        params = {}

    handler = get_handler(tool_name)
    coerced = _coerce(tool_name, params)
    started = time.time()
    try:
        result = handler(coerced)
    except Exception as exc:
        result = {"success": False, "returncode": -1, "output": f"[ERROR] {exc}"}
    elapsed = round(time.time() - started, 1)

    if record:
        _record(tool_name, coerced, result, elapsed)

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
