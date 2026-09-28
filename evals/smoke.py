#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线冒烟测试 —— 不依赖模型，验证 skill 的确定性行为。

为什么单独有这个文件：
    evals/run.py 是"带模型"的对照评测（with/without skill），必须在集群开机时跑；
    但 Tier-3 基线要求「可复现通过」，而模型输出本身有随机性。
    所以把「规则判定 / 授权闸门 / 输出解析 / 完整性」这些确定性行为单独固化在这里，
    任何机器、任何时间都能跑出同一结果，作为回归基线。

用法：
    python3 evals/smoke.py          # 全部跑一遍，失败返回非 0
"""

import hashlib
import io
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_HOME = os.path.dirname(HERE)
SCRIPT_DIR = os.path.join(SKILL_HOME, "scripts")
sys.path.insert(0, SCRIPT_DIR)

import config  # noqa: E402
from agents import catalog, critic, planner  # noqa: E402

RESULTS = []


def check(name, condition, detail=""):
    RESULTS.append((name, bool(condition), detail))
    print("%s %s%s" % ("PASS" if condition else "FAIL", name,
                       ("  — " + detail) if detail else ""))


def tools_of(plan_result):
    return [s["tool"] for s in plan_result["steps"]]


def case_planner_asks_when_target_missing():
    """目标不明确时必须先追问，不能猜一个地址就扫。"""
    result = planner.plan("帮我扫描一下内网", use_model=False)
    check("planner/缺目标先追问", result.get("needs_clarification") is True,
          "question=%s" % (result.get("question", "")[:40]))


def case_planner_port_uses_inspect():
    """端口类任务要落到 network_inspect，而不是只做主机发现的 ping_scan。"""
    result = planner.plan("巡检 192.168.1.165 的开放端口和服务", use_model=False)
    steps = {s["tool"]: s for s in result["steps"]}
    check("planner/端口任务命中 network_inspect", "network_inspect" in steps,
          "plan=%s" % tools_of(result))
    check("planner/network_inspect 带 mode=quick",
          steps.get("network_inspect", {}).get("params", {}).get("mode") == "quick",
          json.dumps(steps.get("network_inspect", {}).get("params", {}), ensure_ascii=False))


def case_planner_no_duplicate_steps():
    """同一工具不能被排两次（一句话常同时命中多个剧本）。"""
    for prompt in ("对 192.168.1.0/24 网段做资产盘点和端口识别",
                   "巡检 192.168.1.165 的开放端口和服务",
                   "扫描 192.168.1.165 的端口和开放服务"):
        names = tools_of(planner.plan(prompt, use_model=False))
        check("planner/步骤按工具去重 (%s)" % prompt[:14], len(names) == len(set(names)),
              "plan=%s" % names)


def case_planner_literals_survive():
    """剧本里的字面量默认值（mode/severity/ports）不能被目标覆盖。"""
    result = planner.plan("对 192.168.1.0/24 网段做资产盘点", use_model=False)
    survey = next((s for s in result["steps"] if s["tool"] == "network_survey"), None)
    check("planner/字面量参数未被目标覆盖",
          survey is not None and survey["params"].get("ports") == "22,80,443,3389",
          json.dumps(survey["params"], ensure_ascii=False) if survey else "未命中剧本")


def case_planner_target_touching_chinese():
    """地址紧贴中文也要能抽出来（"对192.168.1.165进行扫描"）。

    曾经的实现用 \\b 划界，而 Python 的 \\w 把中文也算词字符，中文和 IP 之间没有
    词边界，IP 就抽不到；表现是子 Agent 收到"对192.168.1.165进行漏洞扫描"后
    planner 反问"请给出授权范围"，看起来像 skill 没反应。
    """
    cases = [
        ("对192.168.1.165进行漏洞扫描，端口与服务识别", "192.168.1.165"),
        ("扫描192.168.1.0/24网段", "192.168.1.0/24"),
        ("扫描https://example.com的漏洞", "https://example.com"),
        ("对example.com做漏洞扫描", "example.com"),
        ("版本号192.168.1.1650不应被当成目标", ""),
    ]
    for prompt, want in cases:
        got = planner.extract_target(prompt)
        check("planner/中文紧邻也能抽出目标 (%s)" % prompt[:16], got == want,
              "want=%r got=%r" % (want, got))
    plan = planner.plan("对192.168.1.165进行端口与服务识别", use_model=False)
    check("planner/中文紧邻时不再反问授权范围",
          plan.get("needs_clarification") is not True,
          "question=%s" % plan.get("question", "")[:40])


def case_explicit_risky_is_flagged():
    """显式点名的高危动作要标记成 risky，并被同族安全款替换掉。"""
    names = tools_of(planner.plan("对 192.168.1.165 做 sqlmap 全量注入", use_model=False))
    check("planner/显式高危动作入队", "sqlmap_full" in names, "plan=%s" % names)
    check("planner/高危款取代安全款", "sqlmap_basic" not in names, "plan=%s" % names)


def _stub_executor(calls, tag="stub"):
    """把 executor.execute 换成桩：验证编排决策，不真的发起攻击。"""
    from agents import executor

    real = executor.execute

    def stub(step, **kw):
        calls.append(step.get("tool"))
        return {"tool": step.get("tool"), "ok": True, "returncode": 0, "elapsed": 0.1,
                "error": "", "output": tag, "output_size": len(tag),
                "truncated": False, "output_file": ""}

    executor.execute = stub
    return real


def case_risky_tools_run():
    """高风险工具不再被闸门拦下：显式点名的 risky 步骤照常进入执行。

    用 RFC5737 文档地址 + 执行桩，碰不到真实主机。
    "高风险"这个身份不能丢：计划与轨迹里仍要标着 risky，用的人得看得见。
    """
    from agents import runner

    calls = []
    real = _stub_executor(calls)
    try:
        result = runner.run("对 192.168.1.10 做 sqlmap 全量注入", use_model=False, timeout=5)
    finally:
        from agents import executor
        executor.execute = real

    planned = [s.get("tool") for s in (result.get("plan") or {}).get("steps") or []]
    safeties = [e.get("data", {}).get("safety") for e in store_events(result.get("run_id"))
                if e.get("type") == "tool_call"]
    check("risk/高风险动作进入计划", "sqlmap_full" in planned, "plan=%s" % planned)
    check("risk/不再拦截，直接执行", calls == ["sqlmap_full"], "executed=%s" % calls)
    check("risk/结果里没有被拦截的步骤", not (result.get("blocked") or []),
          "blocked=%s" % (result.get("blocked") or []))
    check("risk/高风险身份仍写进轨迹", "risky" in safeties, "safety=%s" % safeties)


def store_events(run_id):
    """读一条任务的轨迹事件（放行与否要在轨迹里看得到）。"""
    from core import store

    return store.events(run_id, limit=200) if run_id else []


def case_critic_parses_compact_services():
    """network_inspect 的紧凑服务行要能逐条拆开，不能互相吞并。"""
    sample = [{"tool": "network_inspect", "elapsed": 1.0, "output":
               "     端口: 22,80,445,5000\n"
               "     服务: 22/tcp ssh OpenSSH 9.6 (protocol 2.0); 80/tcp http nginx 1.24.0; "
               "445/tcp microsoft-ds?; 5000/tcp rtsp"}]
    titles = [f["title"] for f in critic._rule_findings(sample)]
    ports = sorted(t.split()[1].split("/")[0] for t in titles)
    check("critic/紧凑服务行逐条解析", ports == ["22", "445", "5000", "80"], "解析到=%s" % ports)
    severities = {f["title"].split()[1].split("/")[0]: f["severity"]
                  for f in critic._rule_findings(sample)}
    check("critic/数据库与共享面定级", severities.get("445") == "medium",
          "445=%s" % severities.get("445"))


def case_critic_ignores_tool_logs():
    """sqlmap 之类工具的 [INFO] 日志不能被当成漏洞发现。"""
    sample = [{"tool": "sqlmap_basic", "elapsed": 1.0, "output":
               "[INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0'\n"
               "[INFO] using 'STDIN' for parsing targets list"}]
    check("critic/工具日志不产生误报", critic._rule_findings(sample) == [],
          "命中=%d" % len(critic._rule_findings(sample)))


def case_registry_and_manifest():
    """工具注册表可加载，且内容清单与文件一致（篡改可发现）。"""
    out = subprocess.run([sys.executable, "-c",
                          "import sys; sys.path.insert(0,'%s');"
                          "from registry import auto_discover, REGISTRY;"
                          "auto_discover(); print(len(REGISTRY))" % SCRIPT_DIR],
                         capture_output=True, text=True, cwd=SCRIPT_DIR)
    count = (out.stdout or "").strip().splitlines()[-1] if out.stdout.strip() else ""
    check("registry/工具数=43", count == "43", "实际=%s" % count)

    verify = subprocess.run(["sha256sum", "-c", "MANIFEST.sha256"],
                            capture_output=True, text=True, cwd=SKILL_HOME)
    ok_count = len([l for l in (verify.stdout or "").splitlines() if l.endswith(": OK")])
    check("manifest/内容清单全部匹配", verify.returncode == 0, "校验通过 %d 个文件" % ok_count)


def case_audit_chain():
    """审计链自校验要通过。"""
    out = subprocess.run([sys.executable, "-c",
                          "import sys; sys.path.insert(0,'%s');"
                          "from core import audit;"
                          "print(audit.verify().get('ok'))" % SCRIPT_DIR],
                         capture_output=True, text=True, cwd=SCRIPT_DIR)
    check("audit/审计链自校验通过", "True" in (out.stdout or ""),
          (out.stdout or out.stderr or "").strip().splitlines()[-1] if (out.stdout or out.stderr) else "")


def case_skill_md_contract():
    """SKILL.md 要满足「窄触发 + 强路由」的形态约定。"""
    import re
    text = io.open(os.path.join(SKILL_HOME, "SKILL.md"), encoding="utf-8").read()
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    check("skill/frontmatter 存在", m is not None)
    if not m:
        return
    fm = m.group(1)
    name = re.search(r"^name:\s*(.+)$", fm, re.M)
    desc = re.search(r"^description:\s*(.+)$", fm, re.M)
    check("skill/frontmatter 有 name", bool(name and name.group(1).strip()),
          name.group(1).strip() if name else "")
    check("skill/frontmatter 有 description", bool(desc and desc.group(1).strip()))
    # 描述是"技能选择阶段"唯一可见的信息，必须带触发语义
    body_desc = desc.group(1).strip() if desc else ""
    trigger_words = ("扫描", "巡检", "渗透测试", "漏洞")
    hit = [w for w in trigger_words if w in body_desc]
    check("skill/description 含触发词", len(hit) >= 2, "命中=%s" % hit)
    check("skill/description 含授权边界", "授权" in body_desc)

    # 路由表要克制：主流程过长会挤占上下文
    body_lines = len(text[m.end():].splitlines())
    check("skill/正文保持精简（<120 行）", body_lines < 120, "正文 %d 行" % body_lines)


def case_skill_md_paths_exist():
    """SKILL.md 里提到的每个仓库内路径都必须真实存在（防止文档漂移）。

    例外：三套大规则库与 NVD 密钥**按设计不随仓库分发**（见 data/README.md），
    缺失时只提示、不计失败 —— 否则刚 clone 下来跑自检会误报"路径缺失"。
    """
    import re
    text = io.open(os.path.join(SKILL_HOME, "SKILL.md"), encoding="utf-8").read()
    # 抓取形如 scripts/xxx.py、references/xxx、evals/xxx.py 的路径
    pattern = re.compile(r"`((?:scripts|references|evals|agents|data)/[A-Za-z0-9_./\-]+)`")
    # 按需下载（update_rules.py）或用户自备，不随仓库分发
    optional = {
        "data/cve_cache_sm_por.sqlite",
        "data/exploit-db",
        "data/nuclei-templates",
        "data/nvd_api_key.txt",
    }
    missing, checked, pending = [], set(), []
    for rel in pattern.findall(text):
        rel = rel.rstrip("/")
        if rel in checked:
            continue
        checked.add(rel)
        if not os.path.exists(os.path.join(SKILL_HOME, rel)):
            (pending if rel in optional else missing).append(rel)
    detail = "已核对 %d 个路径" % len(checked)
    if pending:
        detail += "；按需下载未就位 %d 项：%s" % (len(pending), "、".join(sorted(pending)))
    check("skill/引用的路径都存在", not missing,
          "缺失=%s" % missing if missing else detail)


def case_skill_md_commands_run():
    """SKILL.md 里给出的确定性命令要能真正跑起来（--help / 只读子命令）。"""
    # 注意 check_deps 在缺少外部命令时"故意"返回 1（那是它在正常汇报问题），
    # 所以这里只断言它没崩（无回溯），而不是断言退出码为 0。
    commands = [
        ("scripts/verify_audit.py", ["--json"], (0,)),
        ("scripts/call.py", ["--list"], (0,)),
        ("scripts/check_deps.py", [], (0, 1)),
    ]
    for script, extra, ok_codes in commands:
        proc = subprocess.run([sys.executable, os.path.join(SKILL_HOME, script)] + extra,
                              capture_output=True, text=True, cwd=SKILL_HOME, timeout=180)
        crashed = "Traceback" in (proc.stderr or "")
        check("skill/命令可用 %s" % script,
              proc.returncode in ok_codes and not crashed,
              "rc=%s %s" % (proc.returncode, (proc.stderr or "").strip()[:80]))


def case_credential_scrubbing_ready():
    """凭据脱敏机制就绪 —— 开发用真 key，打包时由 pack_release.py 自动脱敏。

    注意：这里**不**断言"目录里没有真实凭据"。
    开发机需要真实 NVD key 来更新 CVE 库，那是正常的；
    提交前的脱敏由 scripts/pack_release.py 负责，并会在打包时做全量密钥扫描。
    """
    sys.path.insert(0, SCRIPT_DIR)
    import config

    placeholders = ["your-nvd-api-key-here", "<your key>", "示例", "placeholder", "REDACTED", "", "-"]
    # 用假的 UUID 形状字符串做断言样本 —— 千万别写成真实 key，
    # 否则它本身就成了随包分发的凭据（pack_release.py 的扫描会拦下来）。
    real_like = ["f3a91c07e5b2d846"]
    bad = [v for v in placeholders if not config._looks_placeholder(v)]
    ok = [v for v in real_like if config._looks_placeholder(v)]
    check("security/占位写法会被识别", not bad and not ok,
          "误判占位=%s 误判真key=%s" % (bad, ok))
    check("security/打包脱敏脚本存在",
          os.path.isfile(os.path.join(SCRIPT_DIR, "pack_release.py")),
          "scripts/pack_release.py")


def case_secret_scan_has_no_false_positive():
    """打包的密钥扫描不能把正常文本当成凭据，也不能放过真凭据。

    背景：技能跑完一轮评测后，运行记录里会带 Agent 的答复原文。答复里出现
    新闻链接的 slug（40+ 字符、全小写、一串连字符）时，"长令牌"规则会误判，
    于是 116 MB 的包根本打不出来。反过来也不能因为怕误报就把规则放宽到
    真密钥也能过 —— 所以两头都要钉住。
    """
    sys.path.insert(0, SCRIPT_DIR)
    import pack_release

    slug = "macos-tahoe-26-5-1-kritischer-stabilitaetspatch-fuer-m5-macs-am-1-juni"
    check("security/slug 不算长令牌", pack_release.looks_like_slug(slug),
          "误判为凭据的 slug=%s" % slug)

    # 形状像凭据的合成串，两个要求：
    #   1. 不含 example/placeholder 这类白名单词，否则会被 SECRET_ALLOWLIST
    #      提前放过，测不出规则本身有没有失效；
    #   2. 用拼接在运行时生成 —— 源码里不留一整条 40+ 的长串，
    #      否则这行自己会被打包扫描拦下来。
    aws_like = "AKIA" + ("A1B2C3D4E5F6" * 3)
    token_like = "ghp_" + ("9f3a71c85be204d6af17c9" * 2)
    real_like = [aws_like, token_like]
    bad = [t for t in real_like if pack_release.looks_like_slug(t)]
    check("security/真凭据形状不算 slug", not bad, "被误放行的=%s" % bad)

    labels = dict(pack_release.SECRET_PATTERNS)
    hit = [t for t in real_like if not labels["长令牌"].search(t)]
    check("security/真凭据能被长令牌规则命中", not hit, "漏检=%s" % hit)


def case_catalog_names_are_real():
    """目录里出现的工具名和参数名必须真实存在。

    这两条踩过坑，而且都不会报错、只会静默失效：
      * SAFETY_RISKY 里写了不存在的 "lateral_tools"，于是五个 lateral_* 后门类
        工具被判成 safe 直接放行 —— 授权闸门形同虚设；
      * 剧本里给工具挂了它没有的参数（例如给 os_identify 传 target，而它要 data），
        排出来的步骤一执行就报缺参数。
    """
    from registry import REGISTRY, auto_discover

    auto_discover()
    missing = sorted(t for t in catalog.SAFETY_RISKY if t not in REGISTRY)
    check("catalog/risky 名单里的工具都存在", not missing, "不存在的名字=%s" % missing)

    bad_explicit = sorted(t for t, _ in catalog.EXPLICIT_RISKY if t not in REGISTRY)
    check("catalog/显式高危名单里的工具都存在", not bad_explicit,
          "不存在的名字=%s" % bad_explicit)

    bad_tools, bad_params = [], []
    for play in catalog.PLAYBOOKS:
        for tool, mapping in play["tools"]:
            if tool not in REGISTRY:
                bad_tools.append("%s:%s" % (play["key"], tool))
                continue
            props = (REGISTRY[tool].get("inputSchema") or {}).get("properties") or {}
            for key, value in mapping.items():
                # 不跳过 target / url —— 它们恰恰是最容易写错的地方：
                # 有的工具收 target、有的收 url、有的收 domain，写错不会报错，
                # 只会拿到空参数白跑一轮（dirb_scan / sqlmap_basic / waf_detect /
                # subdomain_enum 都踩过）。
                if key not in props:
                    bad_params.append("%s:%s.%s" % (play["key"], tool, key))
    check("catalog/剧本引用的工具都存在", not bad_tools, "=%s" % bad_tools)
    check("catalog/剧本参数名与工具 schema 一致", not bad_params, "=%s" % bad_params)


def case_three_domains_are_routed():
    """三大工作域各有一句话入口，且网段目标不会被排上站点类工具。"""
    cases = {
        "渗透测试 192.168.1.165": ("network_inspect", "nuclei_scan"),
        "漏洞扫描 http://192.168.1.165": ("nuclei_scan",),
        "内网巡检 192.168.1.165": ("network_inspect",),
    }
    for prompt, expected in cases.items():
        tools = tools_of(planner.plan(prompt, use_model=False))
        check("route/一句话可路由：%s" % prompt, all(t in tools for t in expected),
              "plan=%s" % tools)

    # 网段目标 + 含糊的"扫描"：不能排 nuclei/nikto（会把 CIDR 拼成 URL）
    tools = tools_of(planner.plan("扫描 192.168.1.0/24", use_model=False))
    check("route/网段目标不排站点类工具",
          tools and not any(planner.needs_url(t) for t in tools), "plan=%s" % tools)


def case_critic_parses_scan_signals():
    """注入、爆破、nmap 漏洞脚本的结论必须进发现列表，不能只剩端口行。"""
    samples = [
        ({"tool": "sqlmap_basic", "output":
          "sqlmap identified the following injection point(s):\n---\nParameter: id (GET)\n"
          "back-end DBMS: MySQL >= 5.0.12"}, "high"),
        ({"tool": "hydra_bruteforce", "output":
          "[22][ssh] host: 192.168.1.165   login: root   password: toor"}, "critical"),
        ({"tool": "nmap_scan", "output":
          "| smb-vuln-ms17-010:\n|   State: VULNERABLE"}, "critical"),
    ]
    for sample, expected in samples:
        severities = [f["severity"] for f in critic._rule_findings([sample])]
        check("critic/解析出 %s 级结论（%s）" % (expected, sample["tool"]),
              expected in severities, "命中=%s" % severities)


def case_verifier_cross_checks_findings():
    """交叉验证的四条客观检查：查无此证 → 推翻，定级无依据 → 存疑，重复 → 存疑。

    这几条是这套流程里唯一能挡住"模型编一条高危"的闸门，且不依赖模型，
    所以必须固化在冒烟测试里。
    """
    from agents import verifier

    results = [{"tool": "network_inspect", "ok": True,
                "output": "22/tcp open ssh OpenSSH 7.4\n8443/tcp open https\n"
                          "3306/tcp open mysql MySQL 5.7.26"}]
    findings = [
        {"title": "SSH 明文服务暴露", "severity": "medium", "tool": "network_inspect",
         "evidence": "22/tcp open ssh OpenSSH 7.4"},
        {"title": "存在 Log4Shell", "severity": "high", "tool": "network_inspect",
         "evidence": "3306/tcp open mysql MySQL 5.7.26", "cve_list": ["CVE-2021-44228"]},
        {"title": "编造的发现", "severity": "medium", "tool": "network_inspect",
         "evidence": "9200/tcp open elasticsearch"},
        {"title": "HTTPS 服务定级过高", "severity": "high", "tool": "network_inspect",
         "evidence": "8443/tcp open https"},
        {"title": "SSH 明文服务暴露", "severity": "medium", "tool": "network_inspect",
         "evidence": "22/tcp open ssh OpenSSH 7.4"},
    ]
    out = verifier.verify("巡检 192.168.1.10", "192.168.1.10", findings, results, use_model=False)
    kept = [f["verdict"] for f in out["findings"]]
    rejected = [f["title"] for f in out["rejected"]]
    check("verifier/证据可回溯的条目保留", kept[:1] == ["confirmed"], "verdicts=%s" % kept)
    check("verifier/原始输出里没有的 CVE 被推翻", "存在 Log4Shell" in rejected,
          "rejected=%s" % rejected)
    check("verifier/编造的证据被推翻", "编造的发现" in rejected, "rejected=%s" % rejected)
    check("verifier/高危无依据降为存疑",
          "disputed" in kept and len(out["findings"]) + len(out["rejected"]) == len(findings),
          "verdicts=%s rejected=%s" % (kept, len(rejected)))
    check("verifier/重复条目被判存疑",
          sum(1 for f in out["findings"] if f["verdict"] == "disputed") == 2, "verdicts=%s" % kept)
    check("verifier/推翻条目留痕不静默丢弃",
          all(f.get("verdict_reason") for f in out["rejected"]), "理由齐全")


def case_verifier_wired_into_runner():
    """交叉验证必须真的接在编排里：结论进任务结果，也进报告正文。

    用 RFC5737 文档地址 + 执行桩：跑的是真实编排流程，但一个工具都不执行。
    """
    from agents import runner

    calls = []
    real = _stub_executor(calls, tag="7/tcp open  http    nginx 1.24.0")
    try:
        result = runner.run("对 192.168.1.11 做 sqlmap 全量注入", use_model=False, timeout=5)
    finally:
        from agents import executor
        executor.execute = real
    check("verifier/编排结果带交叉验证结论", bool(result.get("verdicts")),
          "verdicts=%s" % result.get("verdicts"))
    check("verifier/编排结果带被推翻列表", isinstance(result.get("rejected"), list),
          "rejected=%s" % result.get("rejected"))
    html_path = (result.get("reports") or {}).get("html")
    text = ""
    if html_path and os.path.exists(html_path):
        with io.open(html_path, encoding="utf-8") as handle:
            text = handle.read()
    check("verifier/报告正文写出交叉验证结论", "交叉验证" in text,
          "报告=%s" % os.path.basename(html_path or ""))


def case_runner_streams_progress():
    """编排链要边跑边报进度：默认逐行打（带时间戳），--quiet 只出收尾总结。

    宿主（agent、终端）靠这些行进显示过程；用 RFC5737 文档地址 + --dry-run，
    只判定不执行，跑得动也碰不到真实主机。
    """
    import re
    runner = os.path.join(SKILL_HOME, "scripts", "agents", "runner.py")

    def run_proc(extra):
        proc = subprocess.run([sys.executable, runner, "对 192.168.1.11 做端口扫描",
                               "--no-model", "--dry-run"] + extra,
                              capture_output=True, text=True, cwd=SKILL_HOME, timeout=120)
        return proc.stdout or ""

    loud = run_proc([])
    quiet = run_proc(["--quiet"])
    check("progress/默认打出带时间戳的进度行",
          bool(re.search(r"^\[\d{2}:\d{2}:\d{2}\] 判定完成", loud, re.M)),
          "首行=%r" % (loud.splitlines()[:1],))
    check("progress/--quiet 只出总结",
          "判定完成" not in quiet and "状态：" in quiet,
          "首行=%r" % (quiet.splitlines()[:1],))


def case_port_scan_covers_all_ports():
    """端口扫描必须覆盖 1-65535：各扫描路径不得再退回常用端口抽样。

    只探常用端口的代价是"没探到的端口不会出现在报告里"——漏报最难被发现，
    所以这里把范围钉死：范围字符串只能来自 portscan，且扫描路径里不许再出现
    --top-ports。
    """
    import re
    import portscan
    check("portscan/范围是 1-65535", portscan.FULL_RANGE == "1-65535", portscan.FULL_RANGE)

    def read(rel):
        return io.open(os.path.join(SKILL_HOME, rel), encoding="utf-8").read()

    # 断言"发现 + 只对发现的端口做版本识别"这个两段式：discover 必须出现在
    # 每条会输出端口结论的路径上
    paths = ("scripts/external/network_inspection.py",
             "scripts/external/service_identify.py",
             "scripts/external/vuln_verify.py",
             "scripts/helpers.py",
             "scripts/external/lateral_tools.py")
    missing = [p for p in paths if "portscan" not in read(p)]
    check("portscan/扫描路径都接了全端口发现", not missing, "未接入=%s" % missing)

    # 只看可执行代码：注释里为了交代历史会提到旧参数，那不是抽样
    def code(rel):
        return "\n".join(re.sub(r"#.*", "", ln) for ln in read(rel).splitlines())

    sampled = [p for p in paths if "--top-ports" in code(p)]
    check("portscan/扫描路径没有残留抽样端口", not sampled, "残留=%s" % sampled)

    # discover 出来的端口要真的被解析出来，别只挂个名字
    grepable = "Host: 192.168.1.5 ()\tPorts: 22/open/tcp//ssh//OpenSSH 9.6/, 9200/open/tcp//http//Elastic/"
    text = "22/tcp   open  ssh     OpenSSH 9.6\n3306/tcp filtered mysql\n80/tcp   open  http"
    check("portscan/解析 -oG 开放端口", portscan.open_ports(grepable) == [22, 9200],
          str(portscan.open_ports(grepable)))
    check("portscan/解析普通输出只取 open", portscan.open_ports(text) == [22, 80],
          str(portscan.open_ports(text)))
    svc = portscan.services(grepable + "\n" + text)
    check("portscan/服务解析带状态", (22, "open", "ssh", "OpenSSH 9.6") in svc, str(svc[:2]))


def case_portscan_subprocess_forms():
    """portscan 调 nmap 的两种写法都要真把参数传进去。

    discover() 传字符串（走 shell），version_scan() 传列表（直接 exec）。shell=True
    配列表会把列表第一项当命令名，nmap 收不到参数只打一页 usage —— 这条曾经真的
    发生过，而 usage 文本会被解析成"没有开放端口"，静默漏报。
    这里用一定存在的 echo 复现两种形态，不依赖 nmap。
    """
    import portscan
    as_str = portscan._run("echo ok-string", 30)
    as_list = portscan._run(["echo", "ok-list"], 30)
    check("portscan/字符串形态的参数传到命令里", "ok-string" in as_str, repr(as_str[:60]))
    check("portscan/列表形态的参数传到命令里", "ok-list" in as_list, repr(as_list[:60]))

    # 没装 / 参数被拒时必须抛错，不能返回空结果
    raised = False
    try:
        portscan._run("definitely-not-a-command-xyz", 10)
    except Exception:
        raised = True
    check("portscan/命令不存在时抛错而不是返回空", raised)
    raised = False
    try:
        portscan._run("echo 'Usage: nmap test'", 10)
    except Exception:
        raised = True
    check("portscan/nmap 打 usage 时抛错", raised)


def case_cli_calls_are_recorded():
    """命令行直调也要留痕：管理端的"工具"页读的就是这份轨迹。

    原先只有编排链写 events.jsonl，call.py 直调不留任何记录，界面看起来像
    "这台机器没被调过工具"。这条用例钉住：直调后轨迹里要出现 tool_call /
    tool_result，且审计链要能接着校验。
    """
    import json as _json
    import shutil
    import tempfile

    runtime = tempfile.mkdtemp(prefix="skill-cli-record-")
    env = dict(os.environ, SEC_ASSESSMENT_RUNTIME=runtime)
    call = os.path.join(SKILL_HOME, "scripts", "call.py")
    try:
        proc = subprocess.run([sys.executable, call, "get_current_time"],
                              capture_output=True, text=True, timeout=120, env=env)
        check("cli/直调正常返回", proc.returncode == 0, proc.stderr.strip()[:120])

        state = os.path.join(runtime, "cli_run.json")
        check("cli/直调写下了当日任务", os.path.exists(state))
        if not os.path.exists(state):
            return
        run_id = (_json.load(open(state, encoding="utf-8")) or {}).get("run_id") or ""
        events = os.path.join(runtime, "runs", run_id, "events.jsonl")
        types = []
        if os.path.exists(events):
            with open(events, encoding="utf-8") as handle:
                types = [_json.loads(line).get("type") for line in handle if line.strip()]
        check("cli/轨迹里有 tool_call 与 tool_result",
              "tool_call" in types and "tool_result" in types, str(types))
        check("cli/直调不留在 running 状态", types and types[-1] == "done", str(types[-1:]))

        again = subprocess.run([sys.executable, call, "get_current_time", "--no-record"],
                               capture_output=True, text=True, timeout=120, env=env)
        after = os.path.join(runtime, "runs", run_id, "events.jsonl")
        count = sum(1 for line in open(after, encoding="utf-8") if line.strip())
        check("cli/--no-record 不再追加记录", again.returncode == 0 and count == len(types),
              "行数=%d 之前=%d" % (count, len(types)))
    finally:
        shutil.rmtree(runtime, ignore_errors=True)


def case_hash_crack_fallback():
    """本机没有 OpenCL（虚拟机常见）时，hashcat_bruteforce 要靠内置回退给出结论。

    直接测回退函数本身：命中、未命中、字典读不到三种结果都要分得清。
    放在子进程里跑，避免把工具模块再注册一遍（注册表不允许重名）。
    """
    import json as _json
    import tempfile

    tool = os.path.join(SKILL_HOME, "scripts", "tools", "hashcat_bruteforce.py")
    with tempfile.TemporaryDirectory(prefix="skill-hash-") as tmp:
        words = os.path.join(tmp, "words.txt")
        with open(words, "w", encoding="utf-8") as handle:
            handle.write("cand1\ncand2\nzebra2026\n")

        def run(hashes):
            code = (
                "import importlib.util, json, hashlib\n"
                "spec = importlib.util.spec_from_file_location('hb', %r)\n"
                "mod = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(mod)\n"
                "found, tried, el = mod._python_crack(%r, %r, 'md5')\n"
                "print(json.dumps({'found': found, 'tried': tried}))\n"
            ) % (tool, hashes, words)
            env = dict(os.environ, PYTHONPATH=SCRIPT_DIR)
            proc = subprocess.run([sys.executable, "-c", code], capture_output=True,
                                  text=True, timeout=120, env=env)
            if proc.returncode != 0:
                return None, proc.stderr.strip()[:160]
            return _json.loads(proc.stdout.strip().splitlines()[-1]), ""

        hit = hashlib.md5(b"zebra2026").hexdigest()
        data, err = run([hit])
        check("hash/回退能撞出明文", (data or {}).get("found") == {hit: "zebra2026"},
              err or str(data))
        data, err = run([hashlib.md5(b"not-in-dict").hexdigest()])
        check("hash/字典里没有就报未命中", (data or {}).get("found") == {}, err or str(data))
        data, err = run([hashlib.sha512(b"zebra2026").hexdigest()])
        check("hash/哈希长度不对时不误报命中", (data or {}).get("found") == {}, err or str(data))


def main():
    print("=" * 62)
    print("  sec-assessment 离线冒烟测试（不依赖模型）")
    print("=" * 62)
    for case in (case_planner_asks_when_target_missing, case_planner_port_uses_inspect,
                 case_planner_no_duplicate_steps, case_planner_literals_survive,
                 case_planner_target_touching_chinese,
                 case_explicit_risky_is_flagged, case_risky_tools_run,
                 case_critic_parses_compact_services, case_critic_ignores_tool_logs,
                 case_catalog_names_are_real, case_three_domains_are_routed,
                 case_critic_parses_scan_signals,
                 case_verifier_cross_checks_findings, case_verifier_wired_into_runner,
                 case_runner_streams_progress,
                 case_port_scan_covers_all_ports,
                 case_portscan_subprocess_forms,
                 case_cli_calls_are_recorded,
                 case_hash_crack_fallback,
                 case_registry_and_manifest, case_audit_chain,
                 case_skill_md_contract, case_skill_md_paths_exist,
                 case_skill_md_commands_run, case_credential_scrubbing_ready,
                 case_secret_scan_has_no_false_positive):
        try:
            case()
        except Exception as exc:  # noqa: BLE001 - 单个用例异常不应中断整轮
            check(case.__name__, False, "异常：%s" % exc)
    failed = [name for name, ok, _ in RESULTS if not ok]
    print("-" * 62)
    print("总计 %d 项，通过 %d 项，失败 %d 项" % (len(RESULTS), len(RESULTS) - len(failed), len(failed)))
    if failed:
        print("失败项：" + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
