#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""编排（runner）— 把「判定 → 执行 → 复核 → 交叉验证 → 报告」串成一次完整任务。

    planner   判定：选哪些工具、顺序、参数、为什么
    executor  执行：真正调用工具
    critic    复核：把原始输出收敛成结构化发现，压误报、定严重级
    verifier  交叉验证：拿同一批原始输出逐条判复核结论站不站得住，推翻的记进附录
    reporter  报告：产出 Word / HTML / PDF / Markdown / JSON

五个环节在同一个进程里顺序执行，各自独立发模型请求，可以分别指定后端与模型（roles 参数
或 --planner-backend 这类命令行开关）。不指定时全部落到全局 backend/model；某个环节的后端
探不通，只有它退到规则实现，不影响其他环节 —— 编排层不会因为一个后端挂了就整轮回退。

注意分寸：这是分阶段判读流水线，不是多智能体 —— 环节之间不通信、没有各自的工具循环，
控制流全在本模块。

本模块只做三件事，别的都不做：

    1. 编排    把四步按顺序串起来，任何一步失败都不中断后面的留痕；
    2. 留痕    每一步写进任务轨迹（core.store）与审计链（core.audit）；
    3. 兜底    模型不可用时自动退到规则实现，离线单机也能完整演示。

安全边界（写在代码里，不靠提示词临时叮嘱）：

    * 高风险工具（catalog.SAFETY_RISKY：爆破 / 注入利用 / 凭据窃取 / 横向 / 持久化 / 脱取）
      会照常执行 —— 这套 skill 主要给演练与授权测试用，闸门自己判断"授权"反而会挡住正事。
      但"高风险"这个身份不丢：计划、轨迹、报告里都按 risky 标注，用的人一眼能看见
      这一步有侵入性，自己决定要不要跑。目标授权范围由使用者负责（见 SKILL.md 开头）。
    * 目标参数缺失时不猜，返回 needs_clarification 让上层去问用户。

命令行用法：

    python3 scripts/agents/runner.py "对 192.168.1.0/24 做一次资产发现" --target 192.168.1.0/24
    python3 scripts/agents/runner.py "扫一下 http://x 的漏洞" --no-model --dry-run

进度默认逐行打到 stdout（判定 / 执行 / 复核 / 交叉验证 / 报告各一行，带时间戳），
宿主与终端据此显示过程；只要收尾总结就加 --quiet。完整记录始终在任务轨迹里。
"""

import argparse
import json
import os
import sys
import time

# 兼容两种导入方式：作为包（agents.runner）或直接跑脚本
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import config
    from agents import catalog, critic, executor, planner, reporter, verifier
    from core import audit, store
    from llm import backends as llm_backends
    from llm import gpu as llm_gpu
else:
    import config
    from . import catalog, critic, executor, planner, reporter, verifier
    from core import audit, store
    from llm import backends as llm_backends
    from llm import gpu as llm_gpu

TITLE_LIMIT = 80        # 任务标题截断长度（列表里一行能看完）
DEFAULT_TIMEOUT = 300   # 单个工具的执行上限（秒）
ROLE_NAMES = ("planner", "critic", "verifier")   # 需要模型的角色，各配各的后端
MAX_PLAN_SHOWN = 6      # 进度行里最多列几个工具名，再多就折成"另 N 步"


def _progress(text):
    """往 stdout 打一行进度：带时间戳、立即刷出。

    为什么要有这个：整轮任务对外只有一条命令，而一场带复核的扫描要跑几分钟 —— 进度原先
    只写进运行轨迹（core.store），命令这边从头到尾是静默的，宿主（agent、终端）看到的是
    "跑了半天突然掉出来一份报告"。轨迹仍然是唯一的完整记录，这里只是把同一批事件的摘要
    同时打出来，让过程看得见。--quiet 关掉它。
    """
    print("[%s] %s" % (time.strftime("%H:%M:%S"), text), flush=True)


def _progress_line(event_type, message, data):
    """把一条事件变成为人看的一行；返回空串表示这条只进轨迹、不打到 stdout。"""
    data = data or {}
    if event_type == "plan":
        steps = data.get("steps") or []
        names = "、".join(str(step.get("tool") or "?") for step in steps[:MAX_PLAN_SHOWN])
        tail = "（另 %d 步）" % (len(steps) - MAX_PLAN_SHOWN) if len(steps) > MAX_PLAN_SHOWN else ""
        return "%s：%d 步 —— %s%s" % (message, len(steps), names or "无", tail)
    if event_type == "tool_call":
        return "第 %s 步：%s" % (data.get("step") or "?", message)
    if event_type == "tool_result":
        return "结果：%s" % message
    if event_type == "tool_progress":
        return ""          # 运行中的心跳只进轨迹；终端逐行打会刷屏
    if event_type == "stage":
        return message
    if event_type == "error":
        return "注意：%s" % message
    if event_type == "done":
        return message
    return ""


# ---------------------------------------------------------------- 模型可用性

def model_ready(backend=None, timeout=6.0):
    """探测模型端点是否真的可用。不可用就退规则，不硬等、不报错中断。"""
    try:
        probe = llm_backends.health(backend, timeout=timeout)
    except Exception as exc:                        # noqa: BLE001 - 探测失败等同于不可用
        return False, "%s: %s" % (type(exc).__name__, exc)
    if probe.get("ok"):
        return True, "模型可用"
    return False, probe.get("message") or "模型不可达"


def _role_config(roles, name, backend, model):
    """解析某个角色的后端与模型。返回 (backend, model)。

    规则：角色自己指定了就用角色的；角色换了后端却没给模型名时，模型名置空
    让后端自己挑默认值 —— 把全局的模型名套到另一个后端上，请求必然失败，
    那种"配了却不生效"比没配更难查。
    """
    spec = dict((roles or {}).get(name) or {})
    role_backend = spec.get("backend") or backend
    if spec.get("backend") and not spec.get("model"):
        return role_backend, None
    return role_backend, spec.get("model") or model


# ---------------------------------------------------------------- 用量累计

# 两套命名都要认：OpenAI 网关回 snake_case，本 skill 的 client 归一成 camelCase。
# 只认一种的话，报告里的"模型用量"会一直是 0 —— 数字明明有，就是累不进来。
_USAGE_KEYS = (("prompt_tokens", "promptTokens"),
               ("completion_tokens", "completionTokens"),
               ("total_tokens", "totalTokens"))


def _merge_usage(bucket, usage):
    """把各步的 token 用量累加起来；后端与模型名只记第一个，不做累加。"""
    if not isinstance(usage, dict) or not usage:
        return bucket
    if bucket is None:
        bucket = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
                  "source": usage.get("source") or "openai"}
    for snake, camel in _USAGE_KEYS:
        value = usage.get(snake, usage.get(camel))
        if isinstance(value, (int, float)):
            bucket[snake] = int(bucket.get(snake) or 0) + int(value)
    for key in ("backend", "model"):
        if usage.get(key) and not bucket.get(key):
            bucket[key] = usage[key]
    return bucket


# ---------------------------------------------------------------- 审计摘要

def _audit_summary(review_result):
    """把审计链校验结果整理成报告能直接渲染的行。"""
    try:
        verdict = audit.verify()
    except Exception as exc:                        # noqa: BLE001 - 校验失败也要出报告
        return {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc), "rows": []}
    rows = [
        ("结论", "通过（未发现篡改）" if verdict.get("ok") else "发现异常", ""),
        ("校验记录数", str(verdict.get("checked")), ""),
        ("算法", str(verdict.get("algo")), ""),
        ("链头", str(verdict.get("to_id")), str(verdict.get("head") or "")[:24]),
        ("锚点", "已记录 %s 条，断点 %s" % (verdict.get("anchors", {}).get("recorded"),
                                          verdict.get("anchors", {}).get("breaks")), ""),
        ("复核来源", str(review_result.get("source")), ""),
    ]
    for item in (verdict.get("tampered") or [])[:5]:
        rows.append(("篡改嫌疑", "%s @ %s" % (item.get("action"), item.get("at")),
                     str(item.get("reason"))))
    for item in (verdict.get("broken") or [])[:5]:
        rows.append(("断链", str(item), ""))
    out = dict(verdict)
    out["rows"] = rows
    return out


# ---------------------------------------------------------------- 步骤间传参

CONTEXT_LIMIT = 8000   # 喂给下一步的输出上限（复核类工具要解析文本，太长反而拖慢）
CONTEXT_SNIPPET = 2000  # 单条工具输出参与拼接时的截断长度

# 从上游输出里认端点用的线索。service_identify 的行是 nmap -oG 解析出来的，
# 服务名不可靠时这里也不猜，但仍然区分三种情况 —— 判断标准只有一条：
# nikto 是只做 HTTP 的工具，认错端口的代价是白跑，漏掉端口的代价是漏报。
# 两害相权，所以除"nmap 明确认出来的非 HTTP 服务"之外，一律交给 nikto 试。
HTTP_SERVICE_HINTS = ("http", "https", "ssl", "nginx", "apache", "httpd", "tomcat",
                      "jetty", "iis", "caddy", "lighttpd", "gunicorn", "uwsgi",
                      "grafana", "jenkins", "websphere", "-proxy")
# nmap 报了名字、且显然不是 HTTP 的服务：这些才排除（zabbix-agent 就栽在这条上，
# 它和 Zabbix Web 只差一个后缀，写进 Web 提示里会把监控端口塞给 nikto）
NON_HTTP_SERVICE_HINTS = ("ssh", "smtp", "ftp", "telnet", "domain", "dns", "mysql",
                          "postgres", "ms-sql", "mssql", "oracle", "redis", "mongo",
                          "ms-wbt", "rdp", "netbios", "microsoft-ds", "smb", "ntp",
                          "snmp", "ldap", "kerberos", "zabbix-agent", "zabbix-trapper",
                          "vnc", "nfs", "rsync", "syslog")
HTTP_PORTS = ("80", "81", "88", "443", "591", "8000", "8001", "8008", "8080",
              "8081", "8088", "8090", "8180", "8443", "8888", "9000", "9090",
              "9443", "10000")


def _is_http_endpoint(port, service):
    """这个端口要不要交给只做 HTTP 的工具（nikto）。

    优先级：服务名像 Web > 端口是常见 Web 端口 > 服务名明确不是 HTTP → 排除，
    其余（unknown / 空 / nmap 没认出来）一律算候选 —— 认不出来不等于不是。
    """
    text = (service or "").lower()
    if any(hint in text for hint in HTTP_SERVICE_HINTS):
        return True
    if port in HTTP_PORTS:
        return True
    if text in ("", "-") or text == "unknown":
        return True
    return not any(hint in text for hint in NON_HTTP_SERVICE_HINTS)


def _endpoints_from(results):
    """从上游输出里挑出开放端点，返回 (全部端点, HTTP 端点)。

    只认 service_identify 的 ip|port|service|version 行 —— 端口发现类工具的
    输出格式就这一种。认不出来的行一律跳过，不猜：这里多写一个端口，报告里就
    会多一条对不存在端口的"扫描结论"。

    全部端点给 nuclei（它的 network/ssl/dns 模板不只吃 HTTP），HTTP 端点给
    nikto 这类只做 Web 的工具。
    """
    all_endpoints, http_endpoints, seen = [], [], set()
    for item in results:
        for line in (item.get("output") or "").splitlines():
            line = line.strip()
            if line.count("|") < 2:
                continue
            parts = [part.strip() for part in line.split("|")]
            ip, port, service = parts[0], parts[1], parts[2]
            if not (planner.IP_RE.fullmatch(ip) and port.isdigit()):
                continue
            if (ip, port) in seen:
                continue
            seen.add((ip, port))
            bare = "%s:%s" % (ip, port)
            lowered = service.lower()
            if _is_http_endpoint(port, service):
                scheme = "https" if (port in ("443", "8443", "9443")
                                     or "https" in lowered or "ssl" in lowered) else "http"
                all_endpoints.append("%s://%s:%s" % (scheme, ip, port))
                http_endpoints.append("%s://%s:%s" % (scheme, ip, port))
            else:
                # 认出来不是 Web 的端口照样扫，只是交给 nuclei 的 network/ssl
                # 模板（不信服务名就先别下"它不是 Web"的判断）
                all_endpoints.append(bare)
    return all_endpoints, http_endpoints


def _resolve_step_context(step, results, target=""):
    """把步骤参数里的 $output / $prev / $web / $http 占位符换成真实内容。

    planner 只决定"排哪几步"，真正跨步骤传数据在这里做：
    例如 vuln_verify(report=$output) 要拿到前面扫描的原始输出才能复核，
    否则这一步只会收到字符串字面量 "$output"，复核必然空转。

    端点类占位符（$web / $http）走另一条路：从前面步骤的输出里解析出真实
    开放的端点，让 nuclei/nikto 跟着端口发现结果走，而不是只盯 80/443。

    返回 (解析后的步骤, 是否发生了替换)。
    """
    params = step.get("params") or {}
    if not any(str(value) in planner.CONTEXT_PLACEHOLDERS for value in params.values()):
        return step, False
    all_output = "\n\n".join(
        "### %s\n%s" % (item.get("tool"), (item.get("output") or "")[:CONTEXT_SNIPPET])
        for item in results)
    prev_output = (results[-1].get("output") or "")[:CONTEXT_LIMIT] if results else ""
    endpoints, http_endpoints = _endpoints_from(results)
    if not endpoints and target:
        # 上游没探到端点（端口发现失败、或这一步不依赖它）时退回原始目标，
        # 否则工具会收到空 target 直接报"缺少参数"，看起来像扫过了其实没扫。
        fallback = target if str(target).startswith("http") else "http://" + str(target)
        endpoints, http_endpoints = [fallback], [fallback]
    replacements = {"$output": all_output[:CONTEXT_LIMIT], "$prev": prev_output,
                    "$web": ",".join(endpoints), "$http": ",".join(http_endpoints)}
    resolved = dict(step)
    resolved["params"] = {key: replacements.get(str(value), value)
                          for key, value in params.items()}
    resolved["context_from"] = len(results)
    return resolved, True


# ---------------------------------------------------------------- 主编排

def run(prompt, target=None, backend=None, model=None, use_model=True,
        timeout=DEFAULT_TIMEOUT, source="agent",
        run_id=None, dry_run=False, pdf=True, roles=None, quiet=False):
    """跑完一次完整任务，返回结果概要。

    dry_run=True 时只判定不执行（把计划打印出来），用于演示前核对与回归测试。
    quiet=True 时不逐行打进度，只在收尾给出总结（命令行 --quiet）。
    """
    started = time.time()
    started_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started))

    # 步骤 0：确定任务。调用方已经建好任务时复用（后端先返回 run_id 再开线程，走的就是这条）。
    existing = store.get(run_id) if run_id else None
    if existing:
        run_id = existing["id"]
        store.update(run_id, status="running", stage="init", model=model or "",
                     backend=backend or "")
    else:
        summary = store.create(title=(prompt or "未命名任务")[:TITLE_LIMIT],
                               kind="task", source=source,
                               meta={"prompt": prompt, "target": target,
                                     "dry_run": bool(dry_run)})
        run_id = summary["id"]
        store.update(run_id, model=model or "", backend=backend or "")

    # 算力归因从任务一开始就记录：采样点是模型调用（推理才是真消耗），
    # 这里先采一次底数 —— 报告里"空闲 0% → 推理峰值 X%"才形成对照。
    llm_gpu.recorder.samples = []
    llm_gpu.recorder.sample("start")

    def ev(event_type, stage="", message="", data=None):
        """写一条事件。轨迹断了比什么都严重，所以这里吞掉写失败并打印到 stderr。

        quiet=False 时，同一条事件也往 stdout 打一行摘要（见 _progress_line）：
        进度是给宿主看的，轨迹是给审计看的，两边内容一致、用途不同。
        """
        if not quiet:
            line = _progress_line(event_type, message, data)
            if line:
                _progress(line)
        try:
            return store.append(run_id, event_type, stage=stage, message=message, data=data)
        except Exception as exc:                    # noqa: BLE001
            print("轨迹写入失败: %s" % exc, file=sys.stderr)
            return None

    # 角色配置：每个角色一套 (backend, model)。探测按后端去重 —— 三个角色共用一个
    # 后端时只探一次，不给端点添无谓的请求。
    specs = {name: _role_config(roles, name, backend, model) for name in ROLE_NAMES}
    checks = {}
    if use_model:
        for name in ROLE_NAMES:
            role_backend = specs[name][0]
            if role_backend not in checks:
                checks[role_backend] = model_ready(role_backend)
    ready_by_role = {}
    for name in ROLE_NAMES:
        ready, why = checks.get(specs[name][0], (False, "按调用方要求跳过模型"))
        if use_model and not ready:
            ev("error", stage=name, message="%s 角色的模型不可用，改用规则实现：%s" % (name, why))
        ready_by_role[name] = bool(use_model and ready)

    # 步骤 1：判定。模型可用就用模型，不可用退规则。
    plain = planner.plan(prompt, target=target, backend=specs["planner"][0],
                         model=specs["planner"][1], use_model=ready_by_role["planner"])
    usage = _merge_usage(None, plain.get("usage"))
    ev("plan", stage="plan", message="判定完成（%s）" % plain.get("source"),
       data={"goal": plain.get("goal"), "target": plain.get("target"),
             "steps": plain.get("steps"), "model_error": plain.get("model_error")})

    # 关键参数不全就先问用户 —— 不猜。
    if plain.get("needs_clarification"):
        question = plain.get("question") or "请补充授权范围后再继续"
        ev("done", stage="clarify", message=question,
           data={"status": "needs_clarification", "question": question})
        return {"run_id": run_id, "status": "needs_clarification",
                "question": question, "steps": [], "findings": [],
                "elapsed": round(time.time() - started, 1)}

    steps_plan = plain.get("steps") or []
    audit.record("plan", target_type="run", target_id=run_id,
                 detail="判定 %d 步，来源 %s，目标 %s" % (len(steps_plan), plain.get("source"),
                                                       plain.get("target") or "-"))

    if dry_run:
        ev("done", stage="plan", message="dry-run：只判定不执行",
           data={"status": "dry_run", "steps": steps_plan})
        return {"run_id": run_id, "status": "dry_run", "plan": plain,
                "steps": [], "findings": [], "elapsed": round(time.time() - started, 1)}

    # 步骤 2：执行。逐步留痕；blocked 保留在结果结构里（演练场景下恒为空，
    # 正式环境若有别的闸门接进来，报告那一侧的"被拦步骤"章节直接就能用）。
    results, blocked = [], []
    ev("stage", stage="exec", message="开始执行 %d 个步骤" % len(steps_plan))
    for index, step in enumerate(steps_plan, 1):
        tool = step.get("tool")
        safety = step.get("safety") or catalog.safety_of(tool)

        ev("tool_call", stage="exec", message="调用 %s" % tool,
           data={"step": index, "tool": tool, "params": step.get("params"),
                 "why": step.get("why"), "safety": safety})
        # 步骤间传参放在授权闸门之后：没获授权的步骤不该先把上游数据搬出来
        exec_step, injected = _resolve_step_context(step, results, plain.get("target"))
        # 判定层可以给单步申请更长的上限（catalog 的 step_timeout）：一次扫多个
        # 端点，或者临时放宽的 --timeout 比剧本要求还短时，到点放弃就等于漏扫。
        try:
            step_timeout = max(timeout, int(step.get("timeout") or 0))
        except (TypeError, ValueError):
            step_timeout = timeout
        # 运行中的进度写进轨迹：控制台据此显示"这个工具此刻在做什么"。
        # executor 已按最小间隔节流，这里直接落事件即可（每条只有输出尾巴）。
        def _on_progress(info, _step=index, _tool=tool):
            ev("tool_progress", stage="exec",
               message="%s 运行中（%ss）" % (_tool, info.get("elapsed")),
               data={"step": _step, "tool": _tool, "elapsed": info.get("elapsed"),
                     "chars": info.get("chars"), "tail": info.get("tail")})

        result = executor.execute(exec_step, timeout=step_timeout, run_id=run_id,
                                  on_progress=_on_progress, step_no=index)
        if injected:
            # 轨迹里只留摘要，别把整段扫描输出塞进任务记录
            result["params"] = {key: (value if len(str(value)) <= 120 else
                                      "<%d 字，取自前 %d 步输出>" % (len(str(value)), len(results)))
                                for key, value in (step.get("params") or {}).items()}
            ev("stage", stage="exec", message="%s 已注入上游输出（前 %d 步）"
               % (tool, len(results)))
        results.append(result)
        ev("tool_result", stage="exec",
           message="%s %s（%ss）" % (tool, "完成" if result["ok"] else "失败",
                                    result.get("elapsed")),
           data={"step": index, "tool": tool, "ok": result["ok"],
                 "returncode": result.get("returncode"),
                 "elapsed": result.get("elapsed"), "error": result.get("error"),
                 # 完整原文的文件名与总长度：轨迹里那份是截断的，界面要全文按这个取
                 "output_file": result.get("output_file") or "",
                 "output_size": result.get("output_size"),
                 "output": (result.get("output") or "")[:2000],
                 "truncated": result.get("truncated")})
        audit.record("tool_call", target_type="tool", target_id=tool or "-",
                     detail="step=%d ok=%s elapsed=%s" % (index, result["ok"],
                                                          result.get("elapsed")))

    # 步骤 3：复核。抄输出、定严重级、压误报。
    ev("stage", stage="verify", message="开始复核 %d 条输出" % len(results))
    review_result = critic.review(prompt, plain.get("target"), results,
                                  backend=specs["critic"][0], model=specs["critic"][1],
                                  use_model=ready_by_role["critic"])
    usage = _merge_usage(usage, review_result.get("usage"))
    findings = review_result.get("findings") or []
    ev("stage", stage="verify", message="复核完成（%s），%d 条发现"
       % (review_result.get("source"), len(findings)),
       data={"summary": review_result.get("summary"), "findings": findings,
             "model_error": review_result.get("model_error")})

    # 步骤 3.5：交叉验证。第二个判读源拿同一批原始输出复核复核员的结论：证据对不上的
    # 条目在这里被推翻，不进风险清单，但记进附录 D 与审计链 —— 筛掉的东西也要留痕。
    verdict_result = verifier.verify(prompt, plain.get("target"), findings, results,
                                     backend=specs["verifier"][0],
                                     model=specs["verifier"][1],
                                     use_model=ready_by_role["verifier"])
    usage = _merge_usage(usage, verdict_result.get("usage"))
    findings = verdict_result["findings"]
    review_result["findings"] = findings
    review_result["verdicts"] = verdict_result.get("summary")
    review_result["verdict_source"] = verdict_result.get("source")
    review_result["rejected"] = verdict_result.get("rejected") or []
    ev("stage", stage="crosscheck", message="交叉验证完成（%s）：%s"
       % (verdict_result.get("source"), verdict_result.get("summary")),
       data={"verdicts": verdict_result.get("summary"),
             "rejected": verdict_result.get("rejected"),
             "model_error": verdict_result.get("model_error")})
    audit.record("verify", target_type="run", target_id=run_id,
                 detail=verdict_result.get("summary") or "-")

    # 步骤 4：报告 + 审计摘要。
    ev("stage", stage="report", message="生成报告")
    audit_summary = _audit_summary(review_result)
    if usage:
        ev("usage", stage="report", message="累计 token 用量", data=usage)
    # 收尾再采一次：和开头那次一起，把"这轮任务用了哪块卡、烧了多少算力"钉进轨迹
    llm_gpu.recorder.sample("end")
    gpu_summary = llm_gpu.recorder.summary()
    if gpu_summary:
        ev("gpu", stage="report", message="算力归因：%s" % gpu_summary.get("line", ""),
           data=gpu_summary)
        store.update(run_id, gpu=gpu_summary)
    paths_out = {}
    try:
        # 被安全策略拦下的步骤也要进报告：交付物上要能看出哪些动作没做、为什么没做
        paths_out = reporter.build(run_id, prompt, plain.get("target"), plain,
                                   results, review_result, audit_summary, usage=usage,
                                   pdf=pdf, blocked=blocked, started=started_at,
                                   gpu=gpu_summary)
        ev("stage", stage="report", message="报告已生成",
           data={"docx": paths_out.get("docx"), "html": paths_out.get("html"),
                 "md": paths_out.get("md"), "json": paths_out.get("json"),
                 "pdf": paths_out.get("pdf") or ""})
        audit.record("report", target_type="run", target_id=run_id,
                     detail="生成报告，%d 条发现" % len(findings))
    except Exception as exc:                        # noqa: BLE001 - 报告失败不能吞掉任务
        ev("error", stage="report", message="报告生成失败：%s" % exc)

    elapsed = round(time.time() - started, 1)
    status = "done" if not blocked else "done_with_blocks"
    ev("done", stage="done", message="任务结束（%s）" % status,
       data={"status": status, "findings": len(findings), "tools": len(results),
             "blocked": len(blocked), "elapsed": elapsed})

    return {"run_id": run_id, "status": status, "plan": plain, "steps": results,
            "blocked": blocked, "findings": findings,
            "summary": review_result.get("summary"),
            "review_source": review_result.get("source"), "usage": usage,
            "gpu": gpu_summary,
            "verdicts": review_result.get("verdicts"),
            "verdict_source": review_result.get("verdict_source"),
            "rejected": review_result.get("rejected") or [],
            "audit": {"ok": audit_summary.get("ok"), "checked": audit_summary.get("checked")},
            "reports": paths_out, "elapsed": elapsed}


# ---------------------------------------------------------------- 收尾摘要

SUMMARY_BEGIN = "===== 报告摘要 ====="
SUMMARY_END = "===== 报告摘要结束 ====="

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_CN = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
               "info": "提示"}


def console_base_url():
    """控制台地址 —— 摘要里给的下载链接要指到这台机器的控制台。

    优先环境变量（部署时一条 export 就能改），其次 data/console.json，
    最后退回本机常见地址：链接点不开比不给链接更让人困惑，但给不出正确的
    地址时至少给出能改的地方。
    """
    url = (os.environ.get("SEC_ASSESSMENT_CONSOLE_URL") or "").strip()
    if not url:
        try:
            with open(os.path.join(config.SKILL_HOME, "data", "console.json"),
                      encoding="utf-8") as handle:
                url = (json.load(handle).get("base_url") or "").strip()
        except (OSError, ValueError):
            url = ""
    return (url or "http://127.0.0.1:8787").rstrip("/")


def _download_links(run_id, reports):
    """报告的下载入口：给对话界面点得开的 URL，而不是一串服务器本地路径。"""
    base = console_base_url()
    names = {"docx": "Word 报告", "pdf": "PDF 报告", "html": "网页版报告",
             "md": "Markdown", "json": "JSON"}
    links = []
    for key in ("docx", "pdf", "html", "md", "json"):
        path = (reports or {}).get(key)
        if not path:
            continue
        from urllib.parse import quote

        name = os.path.basename(path)
        links.append("  · %s：%s/api/reports/%s/download/%s"
                     % (names.get(key, key), base, quote(run_id), quote(name)))
    return links


def report_block(result):
    """收尾摘要块：对话界面直接把这一段贴出来就是"执行完的报告"。

    为什么要有 marker：对话界面那侧的工具输出会截断（几千字符），扫描过程的
    进度行会把真正的结论挤出去。有了这对标记，桥那边就能整段取出这一段，
    不管前面打了多少行进度。
    """
    findings = result.get("findings") or []
    counts = {}
    for item in findings:
        sev = str(item.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    dist = " ｜ ".join("%s %d" % (SEVERITY_CN.get(k, k), counts[k])
                      for k in SEVERITY_ORDER if counts.get(k)) or "无"
    reports = result.get("reports") or {}
    target = (result.get("plan") or {}).get("target") or "-"
    steps = len((result.get("plan") or {}).get("steps") or [])

    lines = [SUMMARY_BEGIN,
             "任务：%s ｜ 目标：%s" % (result.get("run_id") or "-", target),
             "状态：%s ｜ 耗时：%ss ｜ 步骤：%d" % (result.get("status") or "-",
                                                  result.get("elapsed", "-"), steps),
             "风险分布：%s" % dist]
    if result.get("verdicts"):
        lines.append("交叉验证：%s（来源：%s）" % (result.get("verdicts"),
                                              result.get("verdict_source") or "-"))
    for item in result.get("blocked") or []:
        lines.append("已拦截：%s" % item.get("reason"))
    if findings:
        lines.append("")
        lines.append("风险清单（前 %d 条，共 %d 条）：" % (min(10, len(findings)), len(findings)))
        for i, item in enumerate(findings[:10], 1):
            lines.append("  %d. [%s] %s%s" % (
                i, SEVERITY_CN.get(str(item.get("severity") or "").lower(),
                                   item.get("severity") or ""),
                (item.get("title") or "")[:120],
                "（来源 %s）" % item.get("tool") if item.get("tool") else ""))
        if len(findings) > 10:
            lines.append("  … 其余 %d 条见报告正文" % (len(findings) - 10))
    else:
        lines.append("")
        lines.append("风险清单：本轮未确认可处置的风险项（详见报告正文的复核与附录）")
    rejected = result.get("rejected") or []
    if rejected:
        lines.append("交叉验证推翻 %d 条（未进清单，见报告附录 D）：%s"
                     % (len(rejected), "、".join((r.get("title") or "")[:40] for r in rejected[:3])))
    lines.append("")
    lines.append("报告下载：")
    links = _download_links(result.get("run_id") or "", reports)
    lines.extend(links or ["  （报告未生成——报告这一环失败时会在这里说明）"])
    lines.append(SUMMARY_END)
    return "\n".join(lines)


# ---------------------------------------------------------------- 命令行

def _main():
    parser = argparse.ArgumentParser(description="sec-assessment 智能体编排（判定→执行→复核→报告）")
    parser.add_argument("prompt", help="用户任务原文")
    parser.add_argument("--target", default="", help="授权目标（IP / CIDR / URL）")
    parser.add_argument("--backend", default=None, help="模型后端：spark-local / gpustack / stepfun")
    parser.add_argument("--model", default=None, help="覆盖模型名")
    parser.add_argument("--roles", default="",
                        help="角色配置 JSON 文件：{\"planner\": {\"backend\": ..., \"model\": ...}, "
                             "\"critic\": {...}, \"verifier\": {...}}；未列出的角色落到 --backend/--model")
    for role in ROLE_NAMES:
        parser.add_argument("--%s-backend" % role, default=None,
                            help="%s 角色单独使用的模型后端（覆盖 --backend）" % role)
        parser.add_argument("--%s-model" % role, default=None,
                            help="%s 角色单独使用的模型名（覆盖 --model）" % role)
    parser.add_argument("--no-model", action="store_true", help="不用模型，走规则判定")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="单个工具超时（秒）")
    parser.add_argument("--dry-run", action="store_true", help="只判定不执行")
    parser.add_argument("--no-pdf", action="store_true",
                        help="不出 PDF（默认在装了 weasyprint 的机器上顺手转一份）")
    parser.add_argument("--json", action="store_true", help="输出 JSON 概要")
    parser.add_argument("--quiet", action="store_true",
                        help="不逐行打进度，只在结束时出总结（默认逐行打）")
    args = parser.parse_args()

    roles = {role: {"backend": getattr(args, "%s_backend" % role),
                    "model": getattr(args, "%s_model" % role)} for role in ROLE_NAMES}
    if args.roles:
        # 配置文件与命令行开关叠加：显式写的开关优先，文件补上没写的角色
        try:
            with open(args.roles, encoding="utf-8") as handle:
                loaded = json.load(handle)
        except (OSError, ValueError) as exc:
            print("角色配置文件读取失败：%s" % exc, file=sys.stderr)
            return 2
        for role, spec in (loaded or {}).items():
            if role not in ROLE_NAMES or not isinstance(spec, dict):
                print("角色配置里有无法识别的项：%s" % role, file=sys.stderr)
                return 2
            merged = dict(roles.get(role) or {})
            for key in ("backend", "model"):
                if not merged.get(key):
                    merged[key] = spec.get(key)
            roles[role] = merged

    result = run(args.prompt, target=args.target, backend=args.backend, model=args.model,
                 use_model=not args.no_model, timeout=args.timeout, source="cli",
                 dry_run=args.dry_run,
                 pdf=not args.no_pdf, roles=roles, quiet=args.quiet)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return 0

    print("任务：%s" % result["run_id"])
    if result["status"] == "needs_clarification":
        print("需要先确认：%s" % result["question"])
        return 3
    planned = (result.get("plan") or {}).get("steps") or []
    if planned:
        print("\n计划：")
        for i, step in enumerate(planned, 1):
            print("  %d. %s %s %s" % (i, step.get("tool"),
                                      json.dumps(step.get("params") or {}, ensure_ascii=False),
                                      "【高风险动作】" if step.get("safety") == "risky" else ""))
    for item in result.get("blocked") or []:
        print("已拦截：%s" % item["reason"])
    print(report_block(result))
    return 0


if __name__ == "__main__":
    sys.exit(_main())
