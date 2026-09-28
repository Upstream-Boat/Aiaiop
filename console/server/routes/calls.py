#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""工具调用接口 — 任务台的数据来源，以"工具"为主轴。

控制台要回答的第一个问题不是"某次任务走到第几步"，而是
**我这些工具被谁调了、调了什么、多久、成没成**。
所以这里把轨迹（core.store 里 append-only 的 events.jsonl）按工具重新聚合：

    GET /api/calls          按工具分组的调用索引（带运行上下文；输出只给开头）
    GET /api/calls/detail   单次调用的完整参数与原始输出

全是读操作，控制台自己不存一份数据，也不下达任何调用。
"""

import json
import os
import re

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from core import audit, store

router = APIRouter(tags=["calls"])

SCAN_RUNS = 80          # 回溯多少个任务：够看清"最近谁在用"，又不至于拖慢页面
MAX_RECORDS = 40        # 单个工具最多回多少条调用流水
OUTPUT_HEAD = 700       # 列表里每条只带输出开头这么多字符，全文按需取
# 详情页一次回给浏览器的上限：完整原文可能有几 MB（全端口扫描、nuclei 全模板），
# 整份塞进 <pre> 会把页面卡死。超了就在界面上说明"看的是前 N 字符"。
MAX_DETAIL_CHARS = 2 * 1024 * 1024

# ── 结果摘要 ──
# 界面要回答的是"这一步执行出了什么"，不是把工具输出原封不动铺一屏。
# 所以每个工具的输出在这里压成一句话 + 最多三条要点；原始输出仍然完整保留，
# 放在摘要下面备查（要细节的人点开就能看，不关心细节的人扫一眼摘要就够）。
_MAX_HIGHLIGHT = 3
# 装饰符号：工具输出里用来画框、拉分隔线的那些字符
_DECOR_CHARS = set("═─━│┃┄┅┈┉╌╍▁▔▏▕╭╮╯╰=~-_*#·•◦▪▫■□●◆")
# 落盘原文落定后不会再变，摘要算一次就够；缓存的是压好的摘要（很小），不是原文。
# 没有它，每次轮询都要把最近几十个任务的原文重新读一遍。
_DIGEST_CACHE = {}
_DIGEST_CACHE_MAX = 600
_DIGEST_READ = 256 * 1024        # 算摘要只读原文前 256KB：多目标扫描的关键行都在前半段


def _lines(text):
    return [line.rstrip() for line in (text or "").splitlines()]


def _short(text, limit=96):
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _tidy(line, limit=118):
    """工具输出的原始行 → 一句可读的要点。
    收掉长斜杠串（nikto 有些条目就是几百个 /）与连续空白；纯符号行直接丢掉，
    它在"执行了什么"上没有任何信息量。"""
    text = " ".join(str(line or "").split())
    text = re.sub(r"[=\-_/]{6,}", "/…", text)
    if len(re.sub(r"[^0-9A-Za-z\u4e00-\u9fff]", "", text)) < 8:
        return ""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _pick(lines, n=_MAX_HIGHLIGHT):
    """把若干候选行整理成要点列表，最多 n 条。"""
    out = []
    for line in lines:
        tidy = _tidy(line)
        if tidy:
            out.append(tidy)
        if len(out) >= n:
            break
    return out


def _skip_noise(line):
    """工具输出里的横幅/分隔线/版本行对"执行了什么"没有信息量，摘要里不看。"""
    stripped = line.strip()
    if not stripped or len(stripped) < 4:
        return True
    if set(stripped) <= set("-=*_ "):
        return True
    # 纯装饰行与装饰线开头的标题（"═══ 漏洞真实性验证 ═══"、"### 目标:..."）。
    # 判据是"开头连着三个以上装饰符号"：正文行（"+ [000396] /admin/: ..."）不会这样开头。
    head = 0
    while head < len(stripped) and stripped[head] in _DECOR_CHARS:
        head += 1
    if head >= 3:
        return True
    # ASCII 艺术字与终端控制序列：sqlmap 的 banner（"___ ___[.]_____"）、
    # 光标定位串（"[?][?]1049h[22;0;0t"）都没有信息量。
    if re.search(r"\[\d+;\d+", stripped):
        return True
    core = re.sub(r"[^0-9A-Za-z\u4e00-\u9fff]", "", stripped)
    if len(core) < len(stripped) * 0.5:
        return True
    lowered = stripped.lower()
    return any(key in lowered for key in (
        "rfurl", "nikto v", "start time", "end time", "target ip", "target hostname",
        "target port", "platform:", "scan terminated", "host(s) tested",
        "开始时间", "结束时间",
    ))


def _extract_ports(text):
    """从端口扫描类输出里取开放端口（nmap/portscan/nuclei 的常见写法）。"""
    ports = []
    for match in re.finditer(r"\b(\d{1,5})/(tcp|udp)\s+open\b", text or ""):
        port = int(match.group(1))
        if port not in ports:
            ports.append(port)
    if not ports:                        # service_identify 的 ip|port|service|version
        for line in _lines(text):
            parts = [x.strip() for x in line.split("|")]
            if len(parts) >= 3 and parts[1].isdigit() and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                port = int(parts[1])
                if port not in ports:
                    ports.append(port)
    return sorted(ports)


def _digest(tool, text, ok, state="done"):
    """工具输出 → 一句话结论 + 要点。返回 {text, level, highlight}。"""
    text = text or ""
    tool = tool or ""
    level = "ok" if ok else "bad"
    if state == "blocked":
        return {"text": "被安全策略拦下，未执行", "level": "bad", "highlight": []}
    if state == "running":
        return {"text": _short(_running_line(text) or "执行中…"), "level": "warn", "highlight": []}

    # ── 按工具认结果 ──
    if tool == "nikto_scan":
        head = _lines(text)
        summary = head[0] if head and head[0].startswith("nikto 扫描") else ""
        items = [line for line in _lines(text) if re.match(r"^\+\s+(\[\d+\]\s+)?/", line.strip())]
        targets = len(re.findall(r"^### ", text, re.M))
        risk = [line for line in items
                if re.search(r"outdated|vulnerab|inject|traversal|xss|disclosure|reveals|upload|shell|default",
                             line, re.I)]
        if not ok:
            fail = re.search(r"未完成的目标：(.+)", text)
            return {"text": _short(fail.group(1) if fail else (summary or "扫描未完成")),
                    "level": "bad", "highlight": _pick(risk, 2)}
        return {"text": _short("%d 个端点扫到 %d 条结果，其中风险项 %d 条"
                               % (targets or 1, len(items), len(risk))),
                "level": "warn" if risk else "ok",
                "highlight": _pick(risk or items)}

    if tool == "nuclei_scan":
        hits = {}
        # nuclei 的文本输出是 "[模板ID] [协议] [级别] URL"，级别夹在中间，
        # 所以按"任意位置的 [级别]"找，不能只看行尾。
        for match in re.finditer(r"\[(critical|high|medium|low|info|unknown)\]", text, re.I):
            sev = match.group(1).lower()
            hits[sev] = hits.get(sev, 0) + 1
        found = [line for line in _lines(text) if re.match(r"^\[[^\]]+\]\s*\[", line.strip())]
        if not found:
            return {"text": "未命中模板（本次扫描范围无对应漏洞）", "level": "ok", "highlight": []}
        order = ["critical", "high", "medium", "low", "info", "unknown"]
        detail = " / ".join("%s %d" % (s, hits[s]) for s in order if hits.get(s))
        return {"text": _short("命中 %d 条：%s" % (len(found), detail or "未标注等级")),
                "level": "warn" if (hits.get("critical") or hits.get("high")) else "ok",
                "highlight": _pick(found)}

    ports = _extract_ports(text)
    if ports:
        head = ", ".join(str(p) for p in ports[:8])
        more = " 等" if len(ports) > 8 else ""
        lines = [l for l in _lines(text) if re.search(r"\d+/(tcp|udp)\s+open", l)]
        if not lines:                     # service_identify 的 ip|port|service|version
            lines = [l for l in _lines(text)
                     if len(l.split("|")) >= 3 and l.split("|")[1].strip().isdigit()]
        return {"text": _short("%d 个开放端口：%s%s" % (len(ports), head, more)),
                "level": "ok", "highlight": _pick(lines)}

    if tool == "hydra_bruteforce":
        hit = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", text, re.I)
        if hit:
            return {"text": _short("猜出可用凭据：%s / %s" % (hit.group(1), hit.group(2))),
                    "level": "bad", "highlight": _pick([hit.group(0)])}
        return {"text": "未猜出可用口令", "level": "ok", "highlight": []}

    if tool in ("sqlmap_basic", "sqlmap_full"):
        if re.search(r"identified the following injection point", text, re.I):
            param = re.search(r"Parameter:\s*(\S+)", text, re.I)
            return {"text": _short("确认 SQL 注入点%s" % ("（参数 %s）" % param.group(1) if param else "")),
                    "level": "bad", "highlight": []}
        if re.search(r"not injectable|does not seem to be injectable", text, re.I):
            return {"text": "未发现注入（目标参数不可注入）", "level": "ok", "highlight": []}
        if re.search(r"\[\*\]\s*ending", text):        # 正常跑完、没报出注入点
            return {"text": "未发现注入点（扫描正常结束）", "level": "ok", "highlight": []}

    if tool in ("dirb_scan", "ffuf_scan"):
        found = [l.strip() for l in _lines(text)
                 if re.search(r"==> DIRECTORY|^\[\d+\]|Status: \d+|CODE:\d+|^\+\s+https?://",
                              l.strip())]
        if found:
            return {"text": _short("发现 %d 个可访问路径" % len(found)), "level": "warn",
                    "highlight": _pick(found)}
        return {"text": "未发现额外路径", "level": "ok", "highlight": []}

    # ── 兜底：拿第一条有信息量的输出当结论 ──
    for line in _lines(text):
        if _skip_noise(line):
            continue
        return {"text": _short(line), "level": level,
                "highlight": _pick([l for l in _lines(text) if not _skip_noise(l)], 2)}
    if ok:
        return {"text": "执行完成（工具没有输出内容）", "level": "ok", "highlight": []}
    return {"text": _short(text.strip() or "执行失败"), "level": "bad", "highlight": []}


def _digest_cached(run_id, step, name, size, tool, ok, state, fallback_text):
    """列表里的摘要按"能拿到的最全那份"算（落盘原文优先），算过就记住。
    键里必须带 step 与 tool：早期轨迹没有落盘文件（name 为空），只按长度做键
    会让同一个任务里两条同样长的输出互相串味。"""
    key = (run_id, step, name, size, tool)
    hit = _DIGEST_CACHE.get(key)
    if hit is not None:
        return hit
    text = store.read_output(run_id, name, limit=_DIGEST_READ) if name else ""
    out = _digest(tool, text or fallback_text, ok, state=state)
    if len(_DIGEST_CACHE) >= _DIGEST_CACHE_MAX:
        _DIGEST_CACHE.clear()          # 满了整清；摘要重算很便宜，不值得为它写 LRU
    _DIGEST_CACHE[key] = out
    return out


def _running_line(text):
    """跑着的时候取最后一行有信息量的输出，当作"此刻在做什么"。
    取最后一行而不是第一行：工具是顺序打日志的，最新的那行才代表当前位置。"""
    for line in reversed(_lines(text)):
        if not _skip_noise(line):
            return line.strip()
    return ""


# 控制台自己的"不看这条"清单（console/data，不写进 skill）
CONSOLE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HIDDEN_FILE = os.path.join(CONSOLE_DIR, "data", "hidden_calls.json")


# 一行流水的身份 = 任务号 + 步骤号；"隐藏"列表就是按这个键记的
def _key(run_id, step):
    return "%s#%s" % (run_id, step)


def _hidden_load():
    """被隐藏的调用（run#step）。

    这里是"不看"，不是"删掉"：轨迹是 skill 的 append-only 记录，控制台没有权力
    改写它（写了也会在审计链里露馅）。所以选择只存在控制台这一侧，隐藏/恢复都留痕。
    """
    try:
        with open(HIDDEN_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return [str(k) for k in (data.get("keys") or [])]
    except (OSError, ValueError):
        return []


# 同样先 .tmp 再 replace：界面上点"隐藏"不该读到写了一半的文件
def _hidden_save(keys):
    os.makedirs(os.path.dirname(HIDDEN_FILE), exist_ok=True)
    tmp = HIDDEN_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump({"keys": sorted(set(keys))}, handle, ensure_ascii=False, indent=2)
    os.replace(tmp, HIDDEN_FILE)


class HideBody(BaseModel):
    # 全部给默认值：`POST /calls/unhide {}` 是"恢复全部"，不带 body 也该能用。
    # 字段设成必填时 FastAPI 会拿 422 把空 body 顶回去（界面上就是点了没反应）。
    run_id: str = ""
    step: int = 0
    tool: str = ""
    reason: str = ""


# 列表只回前 N 个字符 + 完整长度：几 MB 的工具输出不能整份塞进页面
def _output_name(step, tool):
    """运行中那份原文的文件名。命名函数在 skill 侧（与边跑边写同源，改一处就够）；
    万一控制台比 skill 先升上去，这里按同一规则兜底，不至于整页报错。"""
    fn = getattr(store, "output_name", None)
    if fn:
        return fn(step, tool)
    safe = "".join(ch if (ch.isalnum() or ch in "._-") else "_" for ch in str(tool or "")) or "output"
    return "step-%s-%s.txt" % (step or 0, safe)


def _head(text):
    text = text or ""
    return text[:OUTPUT_HEAD], len(text), len(text) > OUTPUT_HEAD


def _scan(limit_runs=SCAN_RUNS):
    """扫最近若干个任务，抽出所有工具调用。返回 (记录列表, 此刻在跑)。"""
    records = []
    live = None
    for summary in store.list_runs(limit=limit_runs):
        run_id = summary.get("id") or ""
        if not run_id:
            continue
        try:
            events = store.events(run_id, limit=4000)
        except Exception:          # 单个任务的轨迹坏了，不该拖垮整页
            continue
        ctx = {"run_id": run_id, "run_title": summary.get("title") or "",
               "run_source": summary.get("source") or "",
               "run_kind": summary.get("kind") or "task",
               "run_status": summary.get("status") or "",
               "run_created_at": summary.get("created_at") or ""}
        plan_steps = 0
        pending = []
        for event in events:
            etype = event.get("type")
            data = event.get("data") or {}
            if not isinstance(data, dict):
                data = {}
            if etype == "plan":
                plan_steps = len(data.get("steps") or []) or plan_steps
            elif etype == "tool_call":
                head, size, cut = _head(data.get("output"))
                row = dict(ctx)
                row.update({
                    "step": data.get("step") or (len(pending) + 1),
                    "tool": data.get("tool") or "未知工具",
                    "params": data.get("params") or {},
                    "why": data.get("why") or "",
                    "safety": data.get("safety") or "",
                    "at": event.get("ts") or "",
                    "state": "blocked" if data.get("blocked") else "running",
                    "ok": None, "returncode": None, "elapsed": None,
                    "error": "", "output_head": head, "output_size": size,
                    "truncated": cut, "total_steps": plan_steps,
                    # 运行中的实时尾巴（tool_progress 事件填），跑完就固定不动
                    "live_tail": "", "live_chars": 0, "live_elapsed": None,
                    "output_file": "",
                    "digest": _digest(data.get("tool") or "未知工具", "",
                                      not data.get("blocked"),
                                      state="blocked" if data.get("blocked") else "running"),
                })
                records.append(row)
                pending.append(row)
            elif etype == "error" and data.get("blocked"):
                # 被授权闸门拦下的步骤：轨迹里是一条 error（带 blocked 标记），
                # 不是 tool_call。以前这里不收，界面上"这个动作被拒绝了"完全看不见，
                # 统计里的"被拦截"也就永远是 0。
                row = dict(ctx)
                row.update({
                    "step": data.get("step") or (len(pending) + 1),
                    "tool": data.get("tool") or "未知工具",
                    "params": data.get("params") or {},
                    "why": data.get("why") or "",
                    "safety": data.get("safety") or "risky",
                    "at": event.get("ts") or "",
                    "state": "blocked", "ok": False, "returncode": None, "elapsed": None,
                    "error": event.get("message") or "", "output_head": "",
                    "output_size": 0, "truncated": False, "total_steps": plan_steps,
                    "live_tail": "", "live_chars": 0, "live_elapsed": None,
                    "output_file": "",
                    "digest": _digest(data.get("tool") or "未知工具", "", False, state="blocked"),
                })
                records.append(row)
            elif etype == "tool_progress":
                # "这个工具此刻在做什么"：输出尾巴 + 已耗时。按步骤号配回那条
                # 还在跑的调用，界面据此在"运行中"旁边直接给出实时输出。
                row = None
                for cand in pending:
                    if cand.get("step") == data.get("step"):
                        row = cand
                        break
                if row is None and pending:
                    row = pending[-1]
                if row is not None:
                    row["live_tail"] = data.get("tail") or row.get("live_tail") or ""
                    row["live_chars"] = data.get("chars") or row.get("live_chars") or 0
                    row["live_elapsed"] = data.get("elapsed", row.get("live_elapsed"))
                    # 跑着的时候的摘要 = 此刻最后一行有信息量的输出
                    row["digest"] = _digest(row.get("tool"), row["live_tail"], True, state="running")
            elif etype == "tool_result":
                row = None
                for cand in pending:                       # 先按步骤号配，退而取最早未结的
                    if cand.get("step") == data.get("step"):
                        row = cand
                        break
                if row is None and pending:
                    row = pending[0]
                if row is None:
                    continue
                head, size, cut = _head(data.get("output"))
                row.update({
                    "tool": data.get("tool") or row["tool"],
                    "state": "done" if data.get("ok") else "failed",
                    "ok": bool(data.get("ok")),
                    "returncode": data.get("returncode"),
                    "elapsed": data.get("elapsed"),
                    "error": data.get("error") or "",
                    "output_head": head, "truncated": cut,
                    "output_file": data.get("output_file") or "",
                    # 事件里那份是截断的（模型只吃 2000 字），总数用落盘原文的长度，
                    # 界面上"共 N 字符"才对得上用户点开全文看到的量
                    "output_size": data.get("output_size") or size,
                    # 摘要优先用落盘原文算：事件里那份是 2000 字上限，
                    # 多目标扫描按它统计会把后面端点的结果漏掉
                    "digest": _digest_cached(run_id, data.get("step"),
                                             data.get("output_file"),
                                             data.get("output_size") or size,
                                             row.get("tool"), bool(data.get("ok")),
                                             "done" if data.get("ok") else "failed",
                                             data.get("output")),
                })
                pending.remove(row)
            elif etype == "stage" and data.get("stage"):
                ctx["run_stage"] = data.get("stage")
        if summary.get("status") != "running":
            # 任务已经结束，还有调用没等到结果：是"没留下结果"，不是"还在跑"。
            # 把这两种混在一起会让人误以为机器上一直有东西在跑。
            for row in pending:
                row["state"] = "no_result"
                row["digest"] = {"text": "轨迹里只有调用、没有结果（宿主进程可能被中断）",
                                 "level": "info", "highlight": []}
            pending = []
        if summary.get("status") == "running" and pending:
            row = pending[-1]
            live = {"run_id": run_id, "run_title": ctx["run_title"],
                    "run_source": ctx["run_source"], "tool": row["tool"],
                    "step": row["step"], "total_steps": row.get("total_steps") or 0,
                    "params": row["params"], "why": row["why"],
                    "started_at": row["at"]}
            live.update({
                "tail": row.get("live_tail") or "",
                "chars": row.get("live_chars") or 0,
                "elapsed": row.get("live_elapsed"),
                "digest": row.get("digest"),
            })
    hidden = set(_hidden_load())
    for row in records:
        row["hidden"] = _key(row.get("run_id"), row.get("step")) in hidden
    return records, live


# 同一个工具在一轮任务里可能被调多次，这里按工具名聚合成"这个工具用得怎么样"
def _group(records):
    groups = {}
    order = []
    for row in records:
        name = row["tool"]
        if name not in groups:
            groups[name] = {"tool": name, "calls": 0, "ok": 0, "failed": 0,
                            "blocked": 0, "running": 0, "no_result": 0,
                            "elapsed_total": 0.0,
                            "elapsed_n": 0, "last_at": "", "last_why": "",
                            "last_run": "", "last_run_title": "",
                            "records": []}
            order.append(name)
        g = groups[name]
        g["calls"] += 1
        if row["state"] == "done":
            g["ok"] += 1
        elif row["state"] == "failed":
            g["failed"] += 1
        elif row["state"] == "blocked":
            g["blocked"] += 1
        elif row["state"] == "no_result":
            g["no_result"] += 1
        else:
            g["running"] += 1
        if isinstance(row.get("elapsed"), (int, float)):
            g["elapsed_total"] += float(row["elapsed"])
            g["elapsed_n"] += 1
        if (row.get("at") or "") >= (g["last_at"] or ""):
            g["last_at"] = row.get("at") or ""
            g["last_why"] = row.get("why") or ""
            g["last_run"] = row.get("run_id") or ""
            g["last_run_title"] = row.get("run_title") or ""
        g["records"].append(row)

    items = []
    for name in order:
        g = groups[name]
        g["records"].sort(key=lambda r: (r.get("at") or "", r.get("step") or 0), reverse=True)
        g["kept"] = min(len(g["records"]), MAX_RECORDS)
        g["records"] = g["records"][:MAX_RECORDS]
        g["avg_elapsed"] = round(g["elapsed_total"] / g["elapsed_n"], 1) if g["elapsed_n"] else None
        g.pop("elapsed_total", None)
        g.pop("elapsed_n", None)
        g["safety"] = g["records"][0].get("safety") or ""
        items.append(g)
    items.sort(key=lambda g: (g["running"] > 0, g["last_at"] or ""), reverse=True)
    return items


@router.get("/calls")
def list_calls(runs: int = Query(SCAN_RUNS, ge=1, le=400), include_hidden: int = 0):
    """按工具分组的调用索引。默认不含被隐藏的调用。"""
    records, live = _scan(runs)
    hidden_n = sum(1 for r in records if r.get("hidden"))
    if not include_hidden:
        records = [r for r in records if not r.get("hidden")]
    items = _group(records)
    return {
        "items": items,
        "live": live,
        "summary": {
            "calls": len(records),
            "tools_used": len(items),
            "failed": sum(1 for r in records if r["state"] == "failed"),
            "blocked": sum(1 for r in records if r["state"] == "blocked"),
            "no_result": sum(1 for r in records if r["state"] == "no_result"),
            "running": sum(1 for r in records if r["state"] == "running"),
        },
        "hidden": hidden_n,
        "scope": "统计范围：最近 %d 个任务" % runs,
        "note": "只读展示；控制台不下达任务，也不知道宿主 Agent 接下来要调什么。",
    }


@router.post("/calls/hide")
def hide_call(body: HideBody):
    """把某次调用从控制台的流水里挪走（隐藏，不是删除）。

    轨迹本身一个字都不动 —— 需要的话点"恢复"就能回来，隐藏与恢复都进审计链。
    """
    if not store.get(body.run_id):
        raise HTTPException(status_code=404, detail="任务不存在")
    keys = _hidden_load()
    key = _key(body.run_id, body.step)
    if key not in keys:
        keys.append(key)
        _hidden_save(keys)
        audit.record("calls.hide", target_type="tool_call", target_id="%s %s" % (body.tool or "-", key),
                     detail="从控制台流水里隐藏这次调用%s（轨迹未改动，可恢复）"
                            % ("：" + body.reason if body.reason else ""), actor="console")
    return {"ok": True, "hidden": len(keys), "key": key}


@router.post("/calls/unhide")
def unhide_calls(body: HideBody | None = None):
    """恢复：给 run_id+step 就恢复一条，不给（或空 body）就全恢复。"""
    keys = _hidden_load()
    if body is not None and body.run_id:
        key = _key(body.run_id, body.step)
        keys = [k for k in keys if k != key]
        detail = "一条 %s" % key
    else:
        detail = "全部（%d 条）" % len(keys)
        keys = []
    _hidden_save(keys)
    audit.record("calls.unhide", target_type="tool_call", target_id="hidden",
                 detail="把隐藏的调用恢复显示：%s" % detail, actor="console")
    return {"ok": True, "hidden": len(keys), "detail": detail}


@router.get("/calls/detail")
def call_detail(run_id: str, step: int = 0, tool: str = ""):
    """单次调用的完整参数与原始输出（列表里只带了开头，全文在这里取）。"""
    if not store.get(run_id):
        raise HTTPException(status_code=404, detail="任务不存在")
    plan_steps = 0
    picked = None
    for event in store.events(run_id, limit=4000):
        data = event.get("data") or {}
        if not isinstance(data, dict):
            data = {}
        if event.get("type") == "plan":
            plan_steps = len(data.get("steps") or []) or plan_steps
        elif event.get("type") == "tool_call":
            if (data.get("step") or 0) == step or (not step and tool and data.get("tool") == tool):
                picked = {"step": data.get("step"), "tool": data.get("tool") or "",
                          "params": data.get("params") or {}, "why": data.get("why") or "",
                          "safety": data.get("safety") or "", "at": event.get("ts") or "",
                          "state": "blocked" if data.get("blocked") else "running",
                          "ok": None, "returncode": None, "elapsed": None,
                          "error": "", "output": "", "truncated": False,
                          "output_file": "", "output_size": None}
        elif event.get("type") == "error" and data.get("blocked"):
            # 被授权闸门拦下的步骤在轨迹里是 error（不是 tool_call）。列表里既然把它
            # 列出来了，详情也得认 —— 否则用户点开这条"被拦截"，看到的是 404。
            if (data.get("step") or 0) == step or (not step and tool and data.get("tool") == tool):
                picked = {"step": data.get("step"), "tool": data.get("tool") or "",
                          "params": data.get("params") or {}, "why": data.get("why") or "",
                          "safety": data.get("safety") or "risky", "at": event.get("ts") or "",
                          "state": "blocked", "ok": False, "returncode": None, "elapsed": None,
                          "error": event.get("message") or "", "output": "", "truncated": False,
                          "output_file": "", "output_size": 0}
        elif event.get("type") == "tool_progress" and picked is not None:
            # 运行中的尾巴：工具还没跑完，轨迹里没有原文文件，就先拿进度事件里的
            # 实时输出尾巴顶上（executor 每 1.5 秒推一条）。
            if not step or (data.get("step") or 0) == step:
                picked["live_tail"] = data.get("tail") or picked.get("live_tail") or ""
                picked["live_chars"] = data.get("chars") or picked.get("live_chars") or 0
                picked["live_elapsed"] = data.get("elapsed", picked.get("live_elapsed"))
        elif event.get("type") == "tool_result" and picked is not None:
            if not step or (data.get("step") or 0) == step:
                text = data.get("output") or ""
                picked.update({
                    "state": "done" if data.get("ok") else "failed",
                    "ok": bool(data.get("ok")), "returncode": data.get("returncode"),
                    "elapsed": data.get("elapsed"), "error": data.get("error") or "",
                    "output": text, "output_size": data.get("output_size") or len(text),
                    "output_file": data.get("output_file") or "",
                    "truncated": bool(data.get("truncated")),
                })
    if picked is None:
        raise HTTPException(status_code=404, detail="这次调用不在轨迹里")
    # 还在跑的调用：executor 已经把输出边跑边写进 outputs/step-N-tool.txt，
    # 这里直接读那份"正在长"的原文 —— 界面上就是一截一截冒出来的，而不是
    # 等整条命令结束才一次性出现。文件还没写出来（工具没吐字）时退回进度尾巴。
    if picked.get("state") == "running":
        part = store.read_output(run_id, _output_name(picked.get("step"), picked.get("tool")),
                                 limit=MAX_DETAIL_CHARS + 1)
        if part:
            picked["output"] = part[:MAX_DETAIL_CHARS]
            picked["output_size"] = len(part)
            picked["live"] = True
            picked["detail_truncated"] = len(part) > MAX_DETAIL_CHARS
        else:
            picked["output"] = picked.get("live_tail") or ""
            picked["output_size"] = picked.get("live_chars") or 0
            picked["live"] = True
    # 原文优先：轨迹里那份是按上下文预算截断的，落盘文件才是工具的原样输出。
    # 界面要"没被截断的记录"，就得从这里取，而不是拿轨迹里的开头凑数。
    if picked.get("output_file") and picked.get("state") != "running":
        full = store.read_output(run_id, picked["output_file"], limit=MAX_DETAIL_CHARS + 1)
        if full:
            picked["output_size"] = picked.get("output_size") or len(full)
            picked["detail_truncated"] = len(full) > MAX_DETAIL_CHARS
            picked["output"] = full[:MAX_DETAIL_CHARS]
            picked["full"] = True
            picked["truncated"] = False
    # 摘要按"能拿到的最全那份"算：文件在就用文件（多目标时事件里那份是被截断的，
    # 只按它统计会把后面端点的结果漏掉，摘要就跟着报小了）
    picked["digest"] = _digest(picked.get("tool"), picked.get("output"),
                              picked.get("state") == "done", state=picked.get("state") or "done")
    picked["run_id"] = run_id
    picked["total_steps"] = plan_steps
    summary = store.get(run_id) or {}
    picked["run_title"] = summary.get("title") or ""
    picked["run_status"] = summary.get("status") or ""
    picked["run_source"] = summary.get("source") or ""
    return picked
