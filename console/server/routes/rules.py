#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""规则库接口 — 状态、在线更新（SSE 进度）、定时更新、更新日志。

现场可能没有外网，所以更新与导入两条路都给：
    在线：POST /api/rules/update  {"targets": ["cve"]}   -> SSE 逐行进度

更新输出会同时落到控制台自己的日志文件里（见 LOG_FILE），所以刷新页面、重启
控制台之后那段记录还在，想清就点「清除日志」。日志文件放在控制台目录下，
skill 的目录里不落任何控制台自己的东西。
"""

import datetime
import json
import os
import queue
import threading
import time

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from core import audit, rules
from server import stream

router = APIRouter(tags=["rules"])

# 控制台自己的数据目录（console/data）—— 更新日志是控制台的记录，不进 skill
CONSOLE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(CONSOLE_DIR, "data")
LOG_FILE = os.path.join(LOG_DIR, "rules_update.log")
SCHEDULE_FILE = os.path.join(LOG_DIR, "schedule.json")
LOG_KEEP_LINES = 10000
LOG_TRIM_BYTES = 2 * 1024 * 1024   # 超过这个体积才做一次裁剪，避免每行都读整个文件


# 同一时刻只允许一场更新：手动点和定时器撞上时，第二个直接让路
UPDATE_LOCK = threading.Lock()
STATUS_TTL = 20.0          # 状态快照缓存几秒：库目录要扫体积/条数，别每次刷新都重扫
_STATUS_CACHE = {"at": 0.0, "data": None}


def status_cached(force=False):
    """带缓存的状态快照。/api/rules 与页面首屏都走它。"""
    now = time.time()
    if not force and _STATUS_CACHE["data"] is not None and now - _STATUS_CACHE["at"] < STATUS_TTL:
        return _STATUS_CACHE["data"]
    data = rules.status()
    _STATUS_CACHE["at"] = now
    _STATUS_CACHE["data"] = data
    return data


def _log_append(text, err=False):
    """追加一行更新输出。写不进去也不能影响更新本身，所以异常直接吞掉。"""
    entry = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "text": str(text), "err": bool(err)}
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        if os.path.getsize(LOG_FILE) > LOG_TRIM_BYTES:
            _log_trim()
    except OSError:
        pass


def _log_trim():
    """只保留最近 LOG_KEEP_LINES 行，防止日志无限长下去。"""
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as handle:
            lines = handle.readlines()[-LOG_KEEP_LINES:]
        tmp = LOG_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            handle.writelines(lines)
        os.replace(tmp, LOG_FILE)
    except OSError:
        pass


def log_heal():
    """控制台启动时收尾：上一次更新若是被重启打断，日志会停在"开始更新"那一行上。

    不补这一行的话，读日志的人会以为这次更新没结束；实际是"记录中断"。
    只在最后一条是"开始更新"时补，正常结束过的日志一个字都不动。
    """
    items = _log_read(50)
    for item in reversed(items):
        text = (item.get("text") or "").strip()
        if text.startswith("开始更新"):
            _log_append("（控制台在这次更新途中被重启，这条记录到此中断；"
                        "规则库是否更新成功请看审计链里对应的 rules.update 记录）")
            return True
        if text.startswith("更新结束"):
            return False
    return False


def _log_read(limit):
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as handle:
            raw = handle.readlines()[-limit:]
    except OSError:
        return []
    out = []
    for line in raw:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:      # 手写坏了的行也照实显示，不要默默吞掉
            item = {"text": line}
        out.append({"at": item.get("at", ""), "text": item.get("text", ""),
                    "err": bool(item.get("err"))})
    return out


class UpdateBody(BaseModel):
    targets: list[str] = ["cve"]
    actor: str = "console"


@router.get("/rules")
def rules_status(refresh: int = 0):
    """四套规则库的条数、版本、体积与更新时间（不联网）。refresh=1 强制重扫。"""
    return status_cached(force=bool(refresh))


@router.post("/rules/update")
def rules_update(body: UpdateBody):
    """执行更新并把 stdout 实时推给前端（SSE）；结束后再回一次状态快照。"""
    lines = queue.Queue()

    if not UPDATE_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="已有一场更新在跑，等它结束再点")

    def worker():
        """更新在后台线程里跑，日志也由这里写。

        踩过的坑：日志原先是在 SSE 生成器里写的（也就是"谁在看谁负责记"）。
        浏览器一关，生成器被取消，更新还在继续跑，日志却停在半截 ——
        留下的记录既不完整、也看不出更新到底结束没有。日志是这台工具自己的
        运转记录，不该取决于有没有人开着页面，所以挪到执行线程里。
        """
        _log_append("开始更新：%s" % ", ".join(body.targets))

        def emit(text):
            _log_append(text)
            lines.put(text)

        try:
            result = rules.update(body.targets, progress=emit, actor=body.actor)
            lines.put(("result", result))
        except Exception as exc:  # noqa: BLE001 - 任何异常都要让前端看到原因
            _log_append("更新出错：%s" % exc, err=True)
            lines.put(("error", {"message": str(exc)}))
        finally:
            _log_append("更新结束 %s" % time.strftime("%H:%M:%S"))
            status_cached(force=True)          # 条数变了，缓存立刻作废
            UPDATE_LOCK.release()
            lines.put(None)

    threading.Thread(target=worker, daemon=True).start()

    def events():
        at = time.strftime("%H:%M:%S")
        yield ("start", {"targets": body.targets, "at": at})
        while True:
            item = lines.get()
            if item is None:
                break
            if isinstance(item, tuple):
                kind, payload = item
                payload = payload if isinstance(payload, dict) else {"message": payload}
                yield (kind, payload)
            else:
                yield ("line", {"message": item})
        yield ("status", rules.status())
        yield ("end", {"at": time.strftime("%H:%M:%S")})

    return StreamingResponse(stream.encode(events()), media_type="text/event-stream",
                             headers=stream.SSE_HEADERS)


@router.get("/rules/log")
def rules_log(limit: int = 400):
    """更新输出日志（最近 limit 行）。刷新页面、重启控制台都还在。"""
    limit = max(1, min(int(limit), 2000))
    items = _log_read(limit)
    return {"items": items, "count": len(items), "keep": LOG_KEEP_LINES,
            "file_rel": os.path.relpath(LOG_FILE, CONSOLE_DIR)}


@router.post("/rules/log/clear")
def rules_log_clear():
    """手动清空更新输出日志。

    只动控制台自己那份日志 —— 审计链里对应的 rules.update 记录不删：
    那一份的意义正是"不允许删改"，删了就自相矛盾了。
    """
    removed = len(_log_read(LOG_KEEP_LINES))
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(LOG_FILE, "w", encoding="utf-8"):
            pass
    except OSError as exc:
        raise HTTPException(status_code=500, detail="清空日志失败：%s" % exc) from None
    audit.record("rules.log.clear", target_type="rules", target_id="update_log",
                 detail="清空规则库更新输出日志（%d 行）" % removed, actor="console")
    return {"ok": True, "cleared": removed, "file_rel": os.path.relpath(LOG_FILE, CONSOLE_DIR)}


# ─────────────────────────────────────────────── 定时更新

# 周期分档（就是界面上的"频率"这一层）：
#   minute  每分钟        —— 没有子选项
#   hour    每小时        —— 选第几分钟，只给 10 分钟档（00/10/20/30/40/50）
#   day     每天          —— 选几点几分
#   week    每周          —— 选周几 + 几点几分
#   month   每月          —— 选几号 + 几点几分（当月没这一天就顺延到下个月）
# 一个字段 freq 决定"分级"，其余字段按需参与计算，不做交叉组合。
WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
WEEKDAY_CN = ("周一", "周二", "周三", "周四", "周五", "周六", "周日")
FREQS = ("minute", "hour", "day", "week", "month")
FREQ_CN = {"minute": "每分钟", "hour": "每小时", "day": "每天",
           "week": "每周", "month": "每月"}
HOUR_STEPS = tuple(range(0, 60, 10))     # "每小时"这一档的分钟：10 分钟一跳


def _as_int(value, fallback):
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _schedule_default():
    return {"enabled": False, "freq": "day", "hour": 3, "minute": 30,
            "weekday": "mon", "dom": 1, "targets": ["cve"],
            "last_run": "", "last_result": "", "armed_at": ""}


def _migrate(saved):
    """老配置升级。之前存过两种写法，都要能读进来，不能让配置"看着在、其实没生效"。

    - at="03:30"            （最早的"每天一个点"）
    - day="*"/"mon"/"26"    （上一版的分钟+小时+天）
    """
    if not isinstance(saved, dict):
        return {}
    out = dict(saved)
    if "freq" not in out:
        if "day" in out:
            day = str(out.pop("day"))
            if day == "*":
                out["freq"] = "day"
            elif day in WEEKDAYS:
                out["freq"], out["weekday"] = "week", day
            elif day.isdigit():
                out["freq"], out["dom"] = "month", int(day)
        elif "at" in out:
            parsed = _parse_at(out.get("at"))
            out["freq"] = "day"
            if parsed:
                out["hour"], out["minute"] = parsed
    out.pop("at", None)
    return out


def schedule_load():
    cfg = _schedule_default()
    try:
        with open(SCHEDULE_FILE, "r", encoding="utf-8") as handle:
            saved = _migrate(json.load(handle))
        cfg.update({k: saved[k] for k in cfg if k in saved})
    except (OSError, ValueError):
        pass
    if cfg.get("freq") not in FREQS:
        cfg["freq"] = "day"
    cfg["hour"] = max(0, min(23, _as_int(cfg.get("hour"), 3)))
    cfg["minute"] = max(0, min(59, _as_int(cfg.get("minute"), 30)))
    if cfg["freq"] == "hour":                # 这一档只认 10 分钟档，别让界面选不出值
        cfg["minute"] = min(HOUR_STEPS, key=lambda m: abs(m - cfg["minute"]))
    if cfg.get("weekday") not in WEEKDAYS:
        cfg["weekday"] = "mon"
    cfg["dom"] = max(1, min(31, _as_int(cfg.get("dom"), 1)))
    return cfg


def _schedule_save(cfg):
    os.makedirs(LOG_DIR, exist_ok=True)
    tmp = SCHEDULE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(cfg, handle, ensure_ascii=False, indent=2)
    os.replace(tmp, SCHEDULE_FILE)


def _parse_at(text):
    """'HH:MM' -> (时, 分)；不合法返回 None。"""
    try:
        hh, mm = str(text).split(":")
        hh, mm = int(hh), int(mm)
    except (ValueError, AttributeError):
        return None
    if not (0 <= hh <= 23 and 0 <= mm <= 59):
        return None
    return hh, mm


def freq_label(cfg):
    """给人看的周期，例如"每天 03:30""每小时的第 20 分钟"。"""
    freq = cfg.get("freq") or "day"
    hour, minute = cfg.get("hour", 0), cfg.get("minute", 0)
    clock = "%02d:%02d" % (hour, minute)
    if freq == "minute":
        return "每分钟"
    if freq == "hour":
        return "每小时的第 %02d 分钟" % minute
    if freq == "week":
        idx = WEEKDAYS.index(cfg.get("weekday") or "mon")
        return "每" + WEEKDAY_CN[idx] + " " + clock
    if freq == "month":
        return "每月 %d 号 %s" % (cfg.get("dom") or 1, clock)
    return "每天 " + clock


# 把"几点几分"落到具体某一天：秒/微秒清零，比较时不会因为秒数不同而误判
def _slot(now, hour, minute):
    return now.replace(hour=hour, minute=minute, second=0, microsecond=0)


def _prev_due(cfg, now):
    """最近一次应该跑的时刻（≤ now）；算不出来返回 None。"""
    freq = cfg.get("freq") or "day"
    hour, minute = cfg["hour"], cfg["minute"]
    if freq == "minute":
        return now.replace(second=0, microsecond=0)
    if freq == "hour":
        due = _slot(now, now.hour, minute)
        return due if due <= now else due - datetime.timedelta(hours=1)
    if freq == "week":
        back = (now.weekday() - WEEKDAYS.index(cfg["weekday"])) % 7
        due = _slot(now, hour, minute) - datetime.timedelta(days=back)
        return due if due <= now else due - datetime.timedelta(days=7)
    if freq == "month":
        dom = cfg["dom"]
        for back in range(0, 13):            # 往回找第一个"确实有这一天"的月份
            year = now.year + (now.month - 1 - back) // 12
            month = (now.month - 1 - back) % 12 + 1
            try:
                due = now.replace(year=year, month=month, day=dom,
                                  hour=hour, minute=minute, second=0, microsecond=0)
            except ValueError:               # 2 月 30 号这种，跳过这个月
                continue
            if due <= now:
                return due
        return None
    due = _slot(now, hour, minute)
    return due if due <= now else due - datetime.timedelta(days=1)


def _next_due(cfg, now):
    """下一次该跑的时刻（> now，不含此刻）。"""
    prev = _prev_due(cfg, now)
    if prev is None:
        return None
    freq = cfg.get("freq") or "day"
    if freq == "minute":
        return prev + datetime.timedelta(minutes=1)
    if freq == "hour":
        return prev + datetime.timedelta(hours=1)
    if freq == "week":
        return prev + datetime.timedelta(days=7)
    if freq == "month":
        for step in range(1, 14):            # 往后找"确实有这一天"的月份
            year = prev.year + (prev.month - 1 + step) // 12
            month = (prev.month - 1 + step) % 12 + 1
            try:
                return prev.replace(year=year, month=month, day=cfg["dom"])
            except ValueError:
                continue
        return None
    return prev + datetime.timedelta(days=1)


def schedule_next(cfg, now=None):
    """下次该跑的时刻（本地时间）；没启用就返回空。"""
    if not cfg.get("enabled"):
        return ""
    now = now or datetime.datetime.now()
    due = _next_due(cfg, now)
    return due.strftime("%Y-%m-%d %H:%M") if due else ""


def _schedule_due(cfg, now):
    """到点了吗：已经过了最近那个点，而那个点之后还没跑过。

    比的是时间戳而不是日期 —— 颗粒度细到分钟以后，同一天有很多个点，
    只比日期会让 03:30 跑完顺手把 03:31 那一轮也吞掉。

    armed_at 是"这套设置是什么时候生效的"：改设置/刚开启时不追溯它之前的时间点，
    否则把周期设成"每周一"会立刻补跑一次上周一 —— 没人想要这个。
    """
    if not cfg.get("enabled"):
        return False
    prev = _prev_due(cfg, now)
    if prev is None:
        return False
    watermark = max(cfg.get("last_run") or "", cfg.get("armed_at") or "")
    return watermark < prev.strftime("%Y-%m-%d %H:%M:%S")


def _run_scheduled(targets):
    """按定时任务跑一场更新：日志照写，审计留痕，抢不到锁就跳过这一轮。"""
    if not UPDATE_LOCK.acquire(blocking=False):
        _log_append("定时更新跳过：已有一场更新在跑", err=True)
        return False
    try:
        _log_append("定时更新开始：%s" % ", ".join(targets))
        result = rules.update(targets, progress=_log_append, actor="schedule")
        _log_append("定时更新结束：%s 耗时 %ss" % (result.get("codes"), result.get("elapsed")))
        return True
    except Exception as exc:                      # noqa: BLE001 - 定时任务不能把线程带崩
        _log_append("定时更新出错：%s" % exc, err=True)
        return False
    finally:
        status_cached(force=True)
        UPDATE_LOCK.release()


def _scheduler_loop():
    """每 20 秒看一次表。到点就更新，跑没跑过记在配置里，重启也不会重复触发。"""
    while True:
        try:
            cfg = schedule_load()
            now = datetime.datetime.now()
            if _schedule_due(cfg, now):
                cfg["last_run"] = now.strftime("%Y-%m-%d %H:%M:%S")
                ok = _run_scheduled(cfg.get("targets") or ["cve"])
                cfg["last_result"] = "成功" if ok else "未执行（另一场更新在跑）"
                _schedule_save(cfg)
        except Exception:                          # noqa: BLE001 - 调度线程必须活着
            pass
        time.sleep(20)


# 一个进程只留一个调度器。create_app 若在同一个进程里被调两次（直接跑
# server/app.py 就会，见 server/__init__.py 里的说明），不拦着就会起两个调度线程：
# 两个线程同时到点、同时抢 UPDATE_LOCK，赢的那个更新、输的那个记一条跳过，
# 更新日志里就多出一条"定时更新跳过：已有一场更新在跑"。
_SCHEDULER_GUARD = threading.Lock()
_SCHEDULER_STARTED = False


def start_scheduler():
    global _SCHEDULER_STARTED
    with _SCHEDULER_GUARD:
        if _SCHEDULER_STARTED:
            return None
        _SCHEDULER_STARTED = True
        thread = threading.Thread(target=_scheduler_loop, daemon=True, name="rules-scheduler")
        thread.start()
    return thread


class ScheduleBody(BaseModel):
    enabled: bool = False
    freq: str = "day"
    minute: int = 30
    hour: int = 3
    weekday: str = "mon"
    dom: int = 1
    targets: list[str] = ["cve"]


def _schedule_options():
    """界面上的候选项由后端给，省得前端各写一份中英对不上的标签。"""
    return {
        "freqs": [{"value": f, "label": FREQ_CN[f]} for f in FREQS],
        "weekdays": [{"value": k, "label": WEEKDAY_CN[i]} for i, k in enumerate(WEEKDAYS)],
        "doms": [{"value": d, "label": "%d 号" % d} for d in range(1, 32)],
        "hour_steps": list(HOUR_STEPS),
    }


@router.get("/rules/schedule")
def schedule_status():
    cfg = schedule_load()
    return {"enabled": bool(cfg.get("enabled")),
            "freq": cfg["freq"], "minute": cfg["minute"], "hour": cfg["hour"],
            "weekday": cfg["weekday"], "dom": cfg["dom"],
            "label": freq_label(cfg),
            "targets": cfg.get("targets") or [], "last_run": cfg.get("last_run") or "",
            "last_result": cfg.get("last_result") or "",
            "next_run": schedule_next(cfg),
            "running": UPDATE_LOCK.locked(),
            "options": [{"key": spec["key"], "label": spec["label"]}
                        for spec in rules.LIBRARIES if spec.get("target")],
            "choices": _schedule_options(),
            "note": "进程不在就跳过这一轮；保存后从下一个时间点开始跑。"}


@router.post("/rules/schedule")
def schedule_set(body: ScheduleBody):
    if body.freq not in FREQS:
        raise HTTPException(status_code=400, detail="频率要是 每分钟 / 每小时 / 每天 / 每周 / 每月")
    if not (0 <= body.minute <= 59 and 0 <= body.hour <= 23):
        raise HTTPException(status_code=400, detail="分钟要 0–59、小时要 0–23")
    if body.freq == "hour" and body.minute not in HOUR_STEPS:
        raise HTTPException(status_code=400, detail="“每小时”这一档的分钟只能是 0/10/20/30/40/50")
    if body.weekday not in WEEKDAYS:
        raise HTTPException(status_code=400, detail="周几要是 mon–sun")
    if not (1 <= body.dom <= 31):
        raise HTTPException(status_code=400, detail="几号要落在 1–31")
    valid = {spec["key"] for spec in rules.LIBRARIES if spec.get("target")}
    targets = [t for t in body.targets if t in valid]
    if body.enabled and not targets:
        raise HTTPException(status_code=400, detail="至少要选一个要更新的库")
    cfg = schedule_load()
    cfg.update({"enabled": bool(body.enabled), "freq": body.freq, "minute": body.minute,
                "hour": body.hour, "weekday": body.weekday, "dom": body.dom,
                "targets": targets,
                "armed_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    _schedule_save(cfg)
    audit.record("rules.schedule", target_type="rules", target_id=",".join(targets) or "-",
                 detail="定时更新%s：%s 更新 %s"
                        % ("开启" if cfg["enabled"] else "关闭", freq_label(cfg),
                           "、".join(targets) or "（无）"),
                 actor="console")
    return schedule_status()


