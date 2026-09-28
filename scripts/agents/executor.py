#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""执行（executor）— 真正调用工具，并给每次调用加超时与错误归类。

工具是可执行文件驱动（nmap / nuclei / sqlmap ...），可能卡住，所以统一放到线程里跑，
超时后不再等（线程被遗弃，但主流程继续，演示不会因为一条工具挂死而卡住）。
"""

import concurrent.futures
import json
import threading
import time
import traceback

MAX_OUTPUT_CHARS = 6000  # 单条工具输出回传给模型的上限（原文另存文件，见下）
PROGRESS_INTERVAL = 1.5  # 运行中进度事件的最小间隔（秒）：太密会把轨迹撑大
PROGRESS_TAIL = 1200     # 每条进度事件带多少字符的实时输出尾巴
LIVE_FILE_LIMIT = 8 * 1024 * 1024   # 边跑边写的原文上限，与收尾落盘保持一致
LIVE_FLUSH_BYTES = 256   # 攒够这么多字符就刷盘
LIVE_FLUSH_SECS = 0.5    # 或者隔这么久刷一次：控制台按 1 秒轮询，输出慢的工具也不至于攒着


class _LiveOutput:
    """运行中就把原文写进 <run>/outputs/step-N-tool.txt。

    以前原文只在收尾时一次性落盘，工具跑完前控制台拿不到任何东西，"实时输出"只能靠
    进度事件里 1200 字的尾巴窗口凑 —— 看起来就是"跑完才一下子全出来"。这里改成边跑
    边写、攒够一点就刷盘，界面读同一个文件，输出就是一点点长出来的。
    收尾时 save_output 会用完整版覆盖同一个文件名，读到的仍是同一份原文。
    """

    def __init__(self, run_id, step, tool):
        from core import store

        self._lock = threading.Lock()
        self._handle, self.path = store.live_output(run_id, step, tool)
        self._pending = 0
        self._written = 0
        self._flushed_at = time.time()
        self._closed = False
        self._dropped = False

    def write(self, chunk):
        if not chunk:
            return
        with self._lock:
            handle = self._handle
            if handle is None or self._closed or self._dropped:
                return
            try:
                if self._written >= LIVE_FILE_LIMIT:
                    # 到上限就停笔并明说，而不是把磁盘写满；收尾那份同样按上限截断
                    handle.write("\n[TRUNCATED] 原始输出超过 %d 字符，仅保留前段\n"
                                 % LIVE_FILE_LIMIT)
                    handle.flush()
                    self._dropped = True
                    return
                handle.write(chunk)
                self._written += len(chunk)
                self._pending += len(chunk)
                now = time.time()
                if self._pending >= LIVE_FLUSH_BYTES or now - self._flushed_at >= LIVE_FLUSH_SECS:
                    handle.flush()
                    self._pending = 0
                    self._flushed_at = now
            except (OSError, ValueError):   # 盘满、文件被删：进度是旁路，不能影响工具
                self._handle = None

    def close(self):
        with self._lock:
            self._closed = True
            if self._handle is not None:
                try:
                    self._handle.flush()
                    self._handle.close()
                except (OSError, ValueError):
                    pass
                self._handle = None


# 懒加载且只加载一次：CLI 与控制台会反复调 execute，不必每次都重扫目录
def _registry():
    from registry import REGISTRY, auto_discover, get_handler

    if not REGISTRY:
        auto_discover()
    return REGISTRY, get_handler


# 给 planner 的工具清单，排过序：同一个任务两次生成计划时，候选顺序要一致
def available_tools():
    registry, _ = _registry()
    return sorted(registry.keys())


def _tail_buffer(limit):
    """只留最后 limit 个字符的滚动缓冲：进度事件要的是"现在打到哪一行"，
    不是整份输出（整份在 result["output"] 与落盘文件里）。"""
    chunks = []
    size = 0

    def push(text):
        nonlocal size
        if not text:
            return
        chunks.append(text)
        size += len(text)
        while size > limit * 2 and len(chunks) > 1:
            size -= len(chunks.pop(0))

    def text():
        return "".join(chunks)[-limit:]

    return push, text


def execute(step, timeout=300, run_id=None, on_progress=None, step_no=None):
    """执行一个步骤，返回统一结构（不抛异常，失败也返回结果，便于轨迹完整）。

    run_id / on_progress 是给控制台的"实时状态"用的（可选）：
      * on_progress(info) 在工具运行中按 PROGRESS_INTERVAL 被调，
        info = {chars, elapsed, tail}，tail 是此刻输出的尾巴；
      * run_id 给出时，完整原始输出另存 <run>/outputs/step-<n>-<tool>.txt，
        事件流与模型只吃截断版，界面要原文时按文件名来取 —— 这样"报告省上下文"
        和"界面能看全文"两件事不再互相牺牲。
    """
    registry, get_handler = _registry()
    tool = step.get("tool")
    params = step.get("params") or {}
    started = time.time()
    result = {"tool": tool, "params": params, "ok": False, "returncode": None,
              "output": "", "elapsed": 0.0, "error": ""}
    if tool not in registry:
        result["error"] = "工具不存在或未加载: %s" % tool
        return result
    handler = get_handler(tool)
    if not handler:
        result["error"] = "工具没有实现: %s" % tool
        return result

    def call():
        if on_progress is None and not run_id:
            return handler(params)
        # 装上进度回调：所有工具都经由 utils.run_cmd 跑外部命令，装上钩子之后
        # 输出一出来就能被外面看到，不必等整条命令跑完（原文同时边跑边落盘）
        from utils import set_progress_sink

        live = _LiveOutput(run_id, step_no or step.get("step"), tool)
        push, tail_text = _tail_buffer(PROGRESS_TAIL)
        state = {"chars": 0, "last": 0.0}

        def emit():
            if on_progress is None:
                return
            try:
                on_progress({"chars": state["chars"],
                             "elapsed": round(time.time() - started, 1),
                             "tail": tail_text()})
            except Exception:  # noqa: BLE001 - 进度是旁路，坏了不能影响执行
                pass

        def sink(chunk, _elapsed):
            live.write(chunk)
            push(chunk)
            state["chars"] += len(chunk)
            now = time.time()
            if now - state["last"] < PROGRESS_INTERVAL:
                return
            state["last"] = now
            emit()

        previous = set_progress_sink(sink)
        try:
            payload = handler(params)
        finally:
            set_progress_sink(previous)
            live.close()
        emit()          # 收尾补一条：界面上一眼看到最后一行，而不是停在半句话上
        return payload

    try:
        # 工具实现都是同步阻塞的，放进单线程池才有"到点就放弃"这回事；
        # 直接调 handler 的话，一条卡死的命令会把整轮任务一起拖住
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(call)
            payload = future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        # TODO 超时只是"不等它了"，那条工具线程还挂在后台跑（拿不回它的输出）。
        #      跑长任务时能看出来线程数只增不减，想彻底解决得换成子进程再 kill。
        result["error"] = "执行超时（%ss）" % timeout
        result["elapsed"] = round(time.time() - started, 1)
        return result
    except Exception as exc:  # noqa: BLE001 - 工具内部异常不能打断整个任务
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
        result["trace"] = traceback.format_exc(limit=3)
        result["elapsed"] = round(time.time() - started, 1)
        return result

    result["elapsed"] = round(time.time() - started, 1)
    if isinstance(payload, dict):
        result["ok"] = bool(payload.get("success"))
        result["returncode"] = payload.get("returncode")
        output = payload.get("output")
    else:
        result["ok"] = True
        output = payload
    if not isinstance(output, str):
        try:
            output = json.dumps(output, ensure_ascii=False)
        except (TypeError, ValueError):
            output = str(output)
    result["output_size"] = len(output)
    # 完整原文落盘：事件流里那份是截断的，控制台要"没被截断的记录"就按这个文件名来取
    if run_id:
        from core import store

        result["output_file"] = store.save_output(run_id, step_no or step.get("step"),
                                                  tool, output)
    result["output"] = output[:MAX_OUTPUT_CHARS]
    result["truncated"] = len(output) > MAX_OUTPUT_CHARS
    return result
