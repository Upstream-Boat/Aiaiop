#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""交叉验证（verifier）— 第二个独立判读同一批原始输出的智能体，专门挑复核结论的毛病。

为什么要有它：
    复核（critic）是单一判读源。它错了没人拦得住 —— 报告里出现一条拍脑袋的高危，
    整份报告的可信度就没了；漏掉一条真正的问题，客户以为没事。漏扫类产品的口碑
    基本就死在误报上。所以这里再跑一遍独立判读，拿到的是**和复核员一样的原始证据**
    加上复核员的结论，任务是逐条判"这条站不站得住"。

    它不是"另一个智能体"：它是本进程里的一次独立模型调用（或纯规则判定），
    没有自己的工具循环，也无法自行扩大检查范围。

三个判定：
    confirmed  证据在原始输出里能对上，定级有依据 —— 照常进报告；
    disputed   结论可能是对的，但证据不足以支撑这个定级 —— 保留，报告里标出来；
    rejected   证据在原始输出里找不到（多半是模型编的），或者引用了原始输出里
               根本没有的 CVE 编号 —— 不进风险清单，但记进附录，不静默丢弃。

规则模式（无模型）也能跑：证据回溯、定级依据、CVE 编号核对、跨工具重复，这四条
都是可以脱离模型做的客观检查，且恰好覆盖模型最容易出错的地方。有模型时再加一层
语义判断，但客观检查失败的一律推翻 —— 模型说"这条没问题"改变不了"输出里查无此证"。

判定结果写进 findings 的 verdict / verdict_reason 字段，由 runner 落审计链、
由 reporter 写进报告，所以"谁推翻了谁"事后可追溯。
"""

import json
import re

from llm import client as llm_client, usage
from utils import loads_first_json

from . import critic

CONFIRMED, DISPUTED, REJECTED = "confirmed", "disputed", "rejected"
VERDICT_LABEL = {CONFIRMED: "确认", DISPUTED: "存疑", REJECTED: "推翻"}

# 定级到 high 以上必须能指出是"哪一条依据"撑起来的。端口基线（PORT_RISK）与
# 信号规则（SIGNAL_RULES）是这套体系里仅有的两个可信来源，别的都只能算推测。
HIGH_RISK = ("critical", "high")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_PORT_EV_RE = re.compile(r"^\s*(\d{1,5})/(tcp|udp)\b")


def _norm(text):
    """比对前先归一：空白折叠、转小写。原始输出的换行与缩进不该影响判定。"""
    return re.sub(r"\s+", " ", str(text or "")).strip().lower()


def _output_index(results):
    """工具名 → 归一化后的输出。证据回溯就是在这个表里查。"""
    index = {}
    for item in results:
        tool = item.get("tool") or ""
        index[tool] = index.get(tool, "") + " " + _norm(item.get("output"))
        if item.get("error"):
            # 报错文本也是证据（"工具未完成"这类条目的证据就是它）
            index[tool] += " " + _norm(item.get("error"))
    return index


def _raw_index(results):
    """工具名 → 未归一化的原始输出。

    定级依据只能在原文里问：nuclei 的等级标记（`[模板] [协议] [severity]`）和
    SIGNAL_RULES 里带 ^/$ 锚点的模式都依赖换行，_norm 把换行折成空格后这些模式
    再也匹配不上 —— 拿归一化文本去查，nuclei 自己报的 high 会被当成"无依据"降级。
    """
    index = {}
    for item in results:
        tool = item.get("tool") or ""
        index[tool] = index.get(tool, "") + "\n" + (item.get("output") or "")
        if item.get("error"):
            index[tool] += "\n" + str(item.get("error"))
    return index


def _signal_severities(results):
    """这份输出里，SIGNAL_RULES 命中的最高等级和 nuclei 自带等级。

    用来回答"这条 high 是谁说的"——如果没有任何一条规则或 nuclei 标记支持，
    那这个 high 只能是猜的。

    传入的 output 必须是**原始输出**（未经 _norm 折叠换行），否则带行锚点的
    模式一律失配，结论会退化成"什么都没说"。
    """
    levels = set()
    for item in results:
        output = item.get("output") or ""
        if item.get("tool") in critic.NUCLEI_TOOLS:
            for match in critic.NUCLEI_LINE_RE.finditer(output):
                levels.add(match.group(3).strip().lower())
        for pattern, severity, _title, _note in critic.SIGNAL_RULES:
            if pattern.search(output):
                levels.add(severity)
    return levels


def _evidence_ok(finding, index):
    """证据能不能在原始输出里找到。返回 (是否通过, 说明)。"""
    evidence = _norm(finding.get("evidence"))
    tool = finding.get("tool") or ""
    haystack = index.get(tool)
    if haystack is None:
        # 工具名对不上（模型常见的笔误）：退一步在全部输出里找
        haystack = " ".join(index.values())
        if not haystack.strip():
            return False, "本轮没有任何工具输出可比对"
    # CVE 聚合条目的证据是一串编号拼的，逐个查更准
    cve_list = finding.get("cve_list") or []
    if cve_list:
        missing = [c for c in cve_list if _norm(c) not in haystack]
        if missing:
            return False, "CVE 编号 %s 在原始输出中不存在" % "、".join(missing[:3])
        return True, "证据可回溯"
    if not evidence:
        return False, "没有给出证据"
    # 长证据取前 60 字比对：原文里跨行、被截断的情况不少
    probe = evidence if len(evidence) <= 60 else evidence[:60]
    if probe and probe in haystack:
        return True, "证据可回溯"
    return False, "证据在原始输出中找不到"


def _severity_ok(finding, index, raw_index=None):
    """high / critical 必须能指出依据来源。返回 (是否降级, 说明)。"""
    severity = str(finding.get("severity") or "").lower()
    if severity not in HIGH_RISK:
        return False, ""
    tool = finding.get("tool") or ""
    haystack = index.get(tool) or " ".join(index.values())
    # 依据一：端口基线（PORT_RISK）—— 高危端口的暴露本身就是结论
    match = _PORT_EV_RE.match(str(finding.get("evidence") or ""))
    if match:
        baseline = critic.PORT_RISK.get(match.group(1))
        if baseline and baseline[0] == severity:
            return False, ""
    # 依据二：信号规则或 nuclei 自带的等级 —— 查原文，不查归一化文本
    raw = raw_index or {}
    source = raw.get(tool) or "\n".join(raw.values()) or haystack
    if severity in _signal_severities([{"tool": tool, "output": source}]):
        return False, ""
    return True, "%s 级定级在原始输出里找不到依据（既非端口基线，也无信号规则命中）" % severity


def _duplicates(findings):
    """跨工具重复：同一现象被两个工具各报一次，留证据更详细的那条。"""
    keep, dup = {}, {}
    for index, finding in enumerate(findings):
        key = (_norm(finding.get("title"))[:40], _norm(finding.get("evidence"))[:40])
        if key in keep:
            dup[index] = keep[key]
            continue
        keep[key] = index
    return dup


def _rule_verdicts(findings, results):
    """四条客观检查。不依赖模型，断网也能给出裁决。"""
    index = _output_index(results)
    raw_index = _raw_index(results)
    verdicts = {}
    for position, finding in enumerate(findings):
        ok, why = _evidence_ok(finding, index)
        if not ok:
            verdicts[position] = (REJECTED, why)
            continue
        degraded, why = _severity_ok(finding, index, raw_index)
        if degraded:
            verdicts[position] = (DISPUTED, why)
            continue
        verdicts[position] = (CONFIRMED, "")
    for position, first in _duplicates(findings).items():
        if verdicts.get(position, ("", ""))[0] == CONFIRMED:
            verdicts[position] = (DISPUTED, "与第 %d 条重复，证据相同" % (first + 1))
    return verdicts


VERIFY_PROMPT = """你是渗透测试结论的交叉验证员。下面有原始工具输出，以及另一位复核员给出的发现清单。

你的任务不是重新找漏洞，而是**逐条检查清单里的结论站不站得住**：
证据是否确实来自原始输出、定级是否被证据支持、有没有把"疑似"写成"确认"。

目标：%s
用户任务：%s

原始工具输出：
%s

待验证的发现清单：
%s

只输出 JSON，不要解释：
{"verdicts": [{"index": 1, "verdict": "confirmed|disputed|rejected", "reason": "一句话理由"}]}

要求：
1. index 是清单里的序号，必须逐条给出，一条不漏；
2. 证据在原始输出里找不到就 rejected；能找到但撑不起当前定级就 disputed；
3. 不要因为"可能还有别的问题"就把站得住的条目判成 disputed，只审已有条目。
"""


def _model_verdicts(prompt, target, findings, results, backend, model):
    """让模型逐条给意见。返回 {位置: (判定, 理由)}，失败抛异常由上层退回规则。"""
    brief = [{"index": index, "title": f.get("title"), "severity": f.get("severity"),
              "evidence": f.get("evidence"), "tool": f.get("tool")}
             for index, f in enumerate(findings, 1)]
    raw = llm_client.chat(
        [{"role": "user", "content": VERIFY_PROMPT % (
            target or "(未指定)", prompt, critic._dump(results, limit=900),
            json.dumps(brief, ensure_ascii=False))}],
        backend=backend, model=model, temperature=0.0)
    text = (raw.get("text") or "").strip()
    if text.find("{") < 0:
        raise ValueError("模型未返回 JSON")
    data = loads_first_json(text)
    out = {}
    for item in data.get("verdicts") or []:
        try:
            position = int(item.get("index")) - 1
        except (TypeError, ValueError):
            continue
        verdict = str(item.get("verdict") or "").strip().lower()
        if verdict not in (CONFIRMED, DISPUTED, REJECTED) or not 0 <= position < len(findings):
            continue
        out[position] = (verdict, str(item.get("reason") or "")[:160])
    return out, usage.stamp_usage(raw.get("usage"), raw.get("backend"), raw.get("model"))


def verify(prompt, target, findings, results, backend=None, model=None, use_model=True):
    """逐条交叉验证，返回 {findings, rejected, summary, source, usage}。

    规则检查先跑：客观不成立的一律推翻，模型无权改判。
    模型只负责在客观检查通过之后，补一层"定级是否合适"的语义判断。
    """
    out = {"findings": [], "rejected": [], "summary": "", "source": "rule", "usage": None}
    verdicts = _rule_verdicts(findings, results)
    if use_model:
        try:
            model_verdicts, usage = _model_verdicts(prompt, target, findings, results,
                                                    backend, model)
            for position, (verdict, why) in model_verdicts.items():
                current = verdicts.get(position, (CONFIRMED, ""))[0]
                if current == REJECTED:
                    continue                      # 客观检查已推翻，模型改不了
                if verdict == REJECTED:
                    verdicts[position] = (REJECTED, "模型复核认为证据不足：%s" % why)
                elif verdict == DISPUTED and current == CONFIRMED:
                    verdicts[position] = (DISPUTED, why or "模型复核存疑")
            out.update({"source": "model", "usage": usage})
        except Exception as exc:                  # noqa: BLE001 - 模型不可用就用规则结论
            out["model_error"] = str(exc)[:160]

    for position, finding in enumerate(findings):
        verdict, why = verdicts.get(position, (CONFIRMED, ""))
        item = dict(finding)
        item["verdict"] = verdict
        item["verdict_source"] = out["source"]
        if why:
            item["verdict_reason"] = why
        if verdict == REJECTED:
            out["rejected"].append(item)
        else:
            out["findings"].append(item)

    # 不带"交叉验证"前缀：这一行会被拼进报告里的"交叉验证"栏与命令行提示，
    # 前缀由调用方加，写在这里会变成"交叉验证：交叉验证：…"。
    out["summary"] = ("%d 条确认、%d 条存疑、%d 条推翻"
                      % (sum(1 for f in out["findings"] if f["verdict"] == CONFIRMED),
                         sum(1 for f in out["findings"] if f["verdict"] == DISPUTED),
                         len(out["rejected"])))
    return out
