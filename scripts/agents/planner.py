#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""判定（planner）— 用户一句话 → 可执行的工具步骤。

两条路：
    模型优先：把工具目录摘要 + 用户任务交给模型，要求输出严格 JSON；
    规则兜底：按关键词命中剧本（catalog.PLAYBOOKS），断网/无模型时同样能出计划。

关键参数缺失时不猜：目标（IP/CIDR/URL/域名）解析不到就返回 needs_clarification，
由上层去问用户 —— 这是本 skill 的硬约定（关键参数不全先问，不允许猜测）。

跨步骤数据传递用占位符（由 runner 在执行前替换）：
    $output  前面所有步骤的输出拼接
    $prev    仅上一步的输出
    $web     前面步骤探到的全部开放端点（Web 类带协议，其余 ip:port）
    $http    前面步骤探到的 Web 端点（nikto 这类只吃 HTTP 的工具用）
这样 vuln_verify(report=$output) 这类"吃上一步结果"的工具才能排进同一条链；
扫描类工具用 $web 就能跟着 service_identify 的全端口结果走，不会只扫 80/443。
"""

import re

from llm import client as llm_client, usage
from utils import loads_first_json

from . import catalog

URL_RE = re.compile(r"https?://[^\s'\"]+")

# 地址两侧不能用 \b 划界：Python 的 \w 把中文也算词字符，于是"对192.168.1.165进行
# 巡检"里 IP 两边都是词字符、没有词边界，IP_RE 整个匹配不到 —— 目标丢失后 planner
# 只会反问"请给出授权范围"，看起来就像 skill 没反应。改用"前后不是数字/点"的否定
# 环视：中文、空格、标点都能正常切开，也不会把 192.168.1.1650 切出半个 IP。
CIDR_RE = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}(?![\d.])")
IP_RE = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
DOMAIN_RE = re.compile(r"(?<![a-z0-9.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?![a-z0-9-])", re.I)

# URL 尾部同样会粘上中文："扫描 https://example.com 的漏洞"没空格就成了
# "https://example.com的漏洞"。抽目标时从第一个中日韩字符处截断。
_CJK_RE = re.compile(r"[\u3000-\u303f\u4e00-\u9fff\uff00-\uffef]")

MAX_STEPS = 6                # 一次任务最多排几步（多了一轮跑不完，也超过演示时长）
# 需要 runner 在执行前替换的占位符：前两个是"上游输出"，后两个是"上游端点"
CONTEXT_PLACEHOLDERS = ("$output", "$prev", "$web", "$http")

PLAN_PROMPT = """你是渗透测试任务规划器。给定工具目录和用户任务，输出 JSON 计划。

工具目录：
%s

只输出 JSON，不要解释，格式（示例里的 ping_scan 只是示意，tool 必须换成目录里
真实存在的工具名，params 的键也要跟目录里该工具的参数一致）：
{"goal": "巡检目标主机的开放端口", "steps": [{"tool": "ping_scan", "params": {"target": "192.168.1.5"}, "why": "资产发现"}]}

硬性要求：
1. 只使用目录里出现过的工具；参数名必须与目录一致；
2. 最多 %d 步，按执行顺序排列（先侦察后验证）；
3. 目标地址原样填进 target 参数，不要编造地址；
4. 目录里没有合适工具就返回 {"goal": "...", "steps": []}。
"""

# 需要"站点 URL"而不是裸 IP/网段的工具：拿到网段目标时必须跳过，
# 否则会把 192.168.1.0/24 拼成 http://192.168.1.0/24 白跑一轮。
URL_TOOLS = ("nuclei_scan", "nikto_scan", "dirb_scan", "sqlmap_basic", "sqlmap_full",
             "waf_detect", "subdomain_enum")


def extract_target(prompt):
    """从自然语言里抽目标：URL > CIDR > IP > 域名。"""
    text = prompt or ""
    for pattern in (URL_RE, CIDR_RE, IP_RE, DOMAIN_RE):
        hit = pattern.search(text)
        if hit:
            value = hit.group(0)
            cut = _CJK_RE.search(value)          # 去掉尾部粘上的中文
            if cut:
                value = value[:cut.start()]
            return value.rstrip("，。,.")
    return ""


def needs_url(tool_name):
    return tool_name in URL_TOOLS


def is_range(target):
    """目标是否是网段（CIDR）。"""
    return bool(CIDR_RE.fullmatch((target or "").strip()))


def host_of(target):
    """从 IP / 域名 / URL 里取出主机名（去掉协议、路径与端口）。"""
    text = (target or "").strip()
    text = re.sub(r"^[a-zA-Z][\w+.-]*://", "", text)
    text = text.split("/")[0]
    if ":" in text:
        head, tail = text.rsplit(":", 1)
        if tail.isdigit():
            text = head
    return text


def _fill_params(mapping, target):
    """按剧本的参数映射生成实际参数。

    占位符只有三种，会被目标替换：
        target → 原始目标（IP / CIDR / 域名 / URL）
        url    → 补过协议的 URL
        domain → 只取主机名（subdomain_enum 这类只要域名的工具用）
    其余值一律当字面量常量（如 mode=quick），$output / $web 这类步骤占位符
    也原样保留，交给执行层替换。
    """
    url = target if (target or "").startswith("http") else ("http://" + target if target else "")
    params = {}
    for key, source in mapping.items():
        if source == "target":
            value = target
        elif source == "url":
            value = url
        elif source == "domain":
            value = host_of(target)
        else:
            value = source
        if value:
            params[key] = value
    return params


def _steps_of(plays, target):
    """把若干剧本展开成步骤，按工具名去重（先出现的保留）。"""
    steps, by_tool = [], {}
    for play in plays:
        for tool, mapping in play["tools"]:
            # 网段目标上排不了吃 URL 的工具
            if is_range(target) and needs_url(tool):
                continue
            params = _fill_params(mapping, target)
            if not params and mapping:
                continue      # 目标为空且该工具需要参数，跳过
            if tool in by_tool:
                # 已排过：只补齐缺失参数，并保留首次命中的理由
                for key, value in params.items():
                    by_tool[tool]["params"].setdefault(key, value)
                continue
            step = {"tool": tool, "params": params, "why": play["label"],
                    "safety": catalog.safety_of(tool)}
            # 剧本可以给单步申请更长的执行上限（例如 nuclei 一次扫多个端点）。
            # 不申请就落到调用方的 --timeout。
            if play.get("step_timeout"):
                step["timeout"] = play["step_timeout"]
            by_tool[tool] = step
            steps.append(step)
    return steps


def _risky_steps(prompt, target):
    """用户显式点名的高风险动作。一定带 safety=risky（标注用，不拦截）。"""
    steps = []
    for tool in catalog.match_explicit_risky(prompt):
        step = {"tool": tool, "params": {"target": target} if target else {},
                "why": "用户显式点名的高风险动作（需授权）",
                "safety": catalog.safety_of(tool)}
        steps.append(step)
    return steps


def _rule_plan(prompt, target):
    """规则兜底：按剧本拼步骤，参数用目标填充。

    一句话任务常常同时命中多个剧本（例如"扫端口"同时命中 recon 和 port），
    不同剧本又可能引用同一个工具 —— 这里按工具名去重，避免同一个工具被排两遍。
    """
    hits = catalog.match_playbooks(prompt, target)
    steps = _steps_of(hits, target)

    # 只说了"扫描 192.168.1.0/24"这类：站点类剧本被目标形态过滤掉后可能一步不剩，
    # 但目标形态本身就是网段，按网段普查处理比追问更贴合意图。
    if not steps and is_range(target):
        survey = [p for p in catalog.PLAYBOOKS if p["key"] == "survey"]
        steps = _steps_of(survey, target)

    # 高风险动作排在最后，但要为它们留出步数：先按剩余额度截断安全步骤，
    # 否则 MAX_STEPS 会把用户明确点名的攻击动作挤掉（判定层看起来"没听懂"）。
    risky = _risky_steps(prompt, target)
    risky_names = {s["tool"] for s in risky}
    # 同一意图已有"安全款"排过了，直接去掉，避免扫两遍
    for tool in risky_names:
        for sibling in catalog.RISKY_SUPERSEDES.get(tool, ()):
            steps = [s for s in steps if s["tool"] != sibling]
    steps = [s for s in steps if s["tool"] not in risky_names]

    budget = max(0, MAX_STEPS - len(risky))
    return (steps[:budget] + risky)[:MAX_STEPS]


def _model_plan(prompt, target, backend, model):
    """模型判定：要求严格 JSON，解析失败就抛给上层走兜底。"""
    raw = llm_client.chat(
        [{"role": "user", "content": PLAN_PROMPT % (catalog.plan_hint(), MAX_STEPS)
          + "\n用户任务：" + prompt}],
        backend=backend, model=model, temperature=0.1,
    )
    text = (raw.get("text") or "").strip()
    if text.find("{") < 0:
        raise ValueError("模型没有返回 JSON 计划")
    data = loads_first_json(text)
    steps = []
    known = catalog.tool_index()      # 目录外的工具名一律丢掉：本地模型最容易在这里"编"，
    for item in (data.get("steps") or [])[:MAX_STEPS]:
        tool = (item.get("tool") or "").strip()
        # 也最容易把提示词里的示例原样抄回来（巡检就变成一个叫"工具名"的步骤）
        if not tool or tool not in known:
            continue
        # 模型也可能把站点类工具排给网段目标，这里按同一条规则拦掉
        if is_range(target) and needs_url(tool):
            continue
        steps.append({"tool": tool, "params": item.get("params") or {},
                      "why": item.get("why") or "", "safety": catalog.safety_of(tool)})
    return {"goal": data.get("goal") or prompt, "steps": steps, "source": "model",
            "usage": usage.stamp_usage(raw.get("usage"), raw.get("backend"), raw.get("model"))}


def plan(prompt, target=None, backend=None, model=None, use_model=True):
    """产出执行计划。返回 dict，含 needs_clarification 表示要先问用户。"""
    target = (target or extract_target(prompt) or "").strip()
    result = {"goal": prompt, "target": target, "steps": [], "source": "rule", "usage": None}
    if not target and not any(word in (prompt or "") for word in ("时间", "现在几点")):
        result.update({"needs_clarification": True, "steps": [],
                       "question": "请给出授权范围（IP / CIDR / 站点 URL），例如 192.168.1.0/24 或 https://example.com"})
        return result

    if use_model:
        try:
            model_plan = _model_plan(prompt, target, backend, model)
            result.update(model_plan)
            result["target"] = target
            if result["steps"]:
                return result
        except Exception as exc:  # noqa: BLE001 - 模型不可用/输出不合规都退到规则
            result["model_error"] = str(exc)[:160]

    result["steps"] = _rule_plan(prompt, target)
    return result
