#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""工具目录 — 给 planner 看的「能力清单」，也是规则兜底的关键词表。

安全分级（safety）用于两件事：
    safe     只读探测，可直接执行；
    risky    有侵入性（爆破 / 利用 / 横向 / 持久化 / 凭据窃取 / 数据脱取），
             照常执行，但在计划、轨迹与报告里标出来，让用的人知道这一步有侵入性。

    allow_implicit：是否允许被"一句话任务"自动选中。默认只有 safe 为 True，
    risky 的工具必须由用户显式点名，避免演示时误触发攻击行为。

剧本（PLAYBOOKS）说明：
    每个剧本 = 一组关键词 + 一串「工具 + 参数映射」。

    参数映射里的 value 只有两种是占位符，由 planner 用抽出来的目标替换：
        target → 原始目标（IP / CIDR / 域名）
        url    → 补过协议的 URL
    其余值一律当字面量常量（如 mode=quick），这样剧本才能固定住安全参数。

    scope 字段给 planner 做目标形态过滤，避免把站点类工具排给网段目标：
        web      需要站点 URL（拿到 CIDR 时不排，否则会拼出 http://192.168.1.0/24）
        network  面向 IP / 网段
        any      与目标形态无关

    规则兜底与模型失败时都用它，所以这里的顺序就是推荐执行顺序：
    先存活 → 再看端口服务 → 再上漏洞 → 最后统一复核。
"""

# ── 高风险工具白名单 ──────────────────────────────────────────────
# 这里的名字必须与 registry 里注册的工具名逐字一致。
#    写错一个字母等于这条闸门静默失效 —— 曾经把五个 lateral_* 工具
#    误写成不存在的 "lateral_tools"，结果后门类工具被判为 safe 直接放行。
#    evals/smoke.py 里有断言守着这条（risky 名字必须真实存在）。
SAFETY_RISKY = (
    # 口令攻击
    "hydra_bruteforce", "hashcat_bruteforce", "passwd_dict_gen",
    # 注入与利用
    "sqlmap_full", "msf_exploit", "msfvenom_payload", "poc_runner_sm_por",
    # 凭据窃取
    "impacket_smbexec", "impacket_secretsdump", "kerberos_attack",
    "mimikatz_memory", "lateral_hash_dump",
    # 横向通道 / 持久化
    "lateral_redis_backdoor", "lateral_ssh_exec", "persist_install",
    "revshell_handler", "socks_proxy",
    # 数据脱取与反取证
    "db_data_extract", "file_extract", "cleanup_trace",
)

# 关键词 → 工具（顺序即推荐执行顺序）；规则兜底与模型失败时都用它
PLAYBOOKS = (
    {"key": "recon", "label": "资产发现", "scope": "network",
     "keywords": ("资产", "存活", "主机发现", "开放", "盘点", "在线",
                  "有哪些设备", "有哪些主机"),
     "tools": (("ping_scan", {"target": "target"}),)},

    {"key": "survey", "label": "大网段普查", "scope": "network",
     "keywords": ("网段", "扫段", "普查", "整个子网", "c 段", "c段"),
     "tools": (("network_survey", {"target": "target", "ports": "22,80,443,3389"}),)},

    {"key": "port", "label": "端口与服务识别", "scope": "network",
     "keywords": ("端口", "服务", "指纹", "banner", "巡检", "设备类型",
                  "设备识别", "什么设备"),
     "tools": (("network_inspect", {"target": "target", "mode": "quick"}),)},

    {"key": "fullport", "label": "全端口扫描", "scope": "network",
     "keywords": ("全端口", "全部端口", "所有端口", "65535"),
     "tools": (("masscan_scan", {"target": "target"}),)},

    {"key": "ipusage", "label": "IP 使用情况盘点", "scope": "network",
     "keywords": ("空闲 ip", "空闲ip", "ip 使用", "ip使用", "ip 分配",
                  "地址池", "未使用"),
     "tools": (("ip_usage_report", {"target": "target"}),)},

    {"key": "asset", "label": "域名资产测绘", "scope": "web",
     "keywords": ("子域名", "子域", "域名", "资产测绘", "隐藏资产", "攻击面"),
     "tools": (("subdomain_enum", {"domain": "domain"}),)},

    {"key": "waf", "label": "WAF 识别", "scope": "web",
     "keywords": ("waf", "wafw00f", "防火墙识别"),
     "tools": (("waf_detect", {"url": "url"}),)},

    {"key": "web", "label": "Web 漏洞扫描", "scope": "web",
     # 不把裸 "http" 当关键词：它会命中 URL 里的 https://，
     # 于是"子域名枚举 https://x"这种无关任务也会被塞一轮全量 Web 漏洞扫描。
     "keywords": ("web", "站点", "网站", "漏洞", "nuclei", "扫描"),
     # 先做全端口发现，再扫。以前是直接把裸目标拼成 http://<target> 交给
     # nuclei/nikto，等于只覆盖 80/443 —— 目标上其余开放端口（8001、8080、
     # 18789…）在报告里根本不出现，扫描器自己制造的漏报最难查。
     # service_identify 输出 `ip|port|service|version`，runner 据此展开：
     #     $web  → 全部开放端点（Web 类补协议，其余给 ip:port 交给 nuclei 的
     #             network/ssl 模板），nikto 只吃 HTTP 所以另给 $http。
     # step_timeout：目标多了单步会超过默认 300s 上限，到点被放弃就等于漏扫。
     "step_timeout": 900,
     "tools": (("service_identify", {"targets": "target"}),
               # 版本号刚拿到就先过一次 CVE 库：nuclei 只覆盖自己那 1.37 万个模板，
               # 目标上的老版本组件（OpenSSH / nginx / Tomcat…）匹配出来的 CVE
               # 是模板扫不到的那一半。放在这里是为了让 $output 正好等于
               # service_identify 的 ip|port|服务|版本 行 —— 中间插一步 Web 扫描，
               # $output 就会被扫描输出顶掉，匹配器解析不出服务。
               ("cve_match_sm_por", {"data": "$output"}),
               ("nuclei_scan", {"target": "$web", "severity": "critical,high",
                                "timeout": "900"}),
               ("nikto_scan", {"target": "$http", "timeout": "600"}))},

    # cve_match_sm_por 要的是「IP|端口|服务|版本」这种服务指纹数据，不是 IP 本身，
    # 所以这一步必须排在 service_identify 后面，用 $output 接它的输出。
    {"key": "cve", "label": "CVE 匹配", "scope": "network",
     "keywords": ("cve", "版本", "漏洞库", "匹配"),
     "tools": (("service_identify", {"targets": "target"}),
               ("cve_match_sm_por", {"data": "$output"}))},

    {"key": "dir", "label": "目录扫描", "scope": "web",
     "keywords": ("目录", "路径", "后台", "敏感文件"),
     "tools": (("dirb_scan", {"url": "url"}),)},

    {"key": "db", "label": "数据库注入检测", "scope": "web",
     "keywords": ("sql", "注入", "数据库"),
     "tools": (("sqlmap_basic", {"url": "url"}),)},

    # 复核：vuln_verify 吃的是"上一步的扫描输出"，所以参数写 $output，
    # 由 runner 在执行前替换成前面步骤的真实输出（见 planner.CONTEXT_PLACEHOLDERS）。
    # 放这里是为了保证它排在所有扫描类剧本之后。
    {"key": "verify", "label": "漏洞复核", "scope": "any",
     "keywords": ("复核", "误报", "漏洞验证", "确认真实性", "复现漏洞"),
     "tools": (("vuln_verify", {"report": "$output"}),)},

    {"key": "compliance", "label": "等保合规检查", "scope": "any",
     "keywords": ("合规", "等保", "基线", "加固", "检查表"),
     "tools": (("compliance_report", {"target": "target"}),)},

    {"key": "time", "label": "时间基准", "scope": "any",
     "keywords": ("时间", "现在几点", "时间戳"),
     "tools": (("get_current_time", {}),)},

    # 渗透测试：用户嘴里的「渗透测试 / 安全评估」在别的剧本里都没有对应关键词，
    # 所以单列一条，把「主机发现 → 服务版本 → Web 漏洞 → CVE 匹配」串成一次受控评估。
    # 排最后是为了不打乱上面具体剧本的先后；重复工具由 planner 去重。
    {"key": "pentest", "label": "渗透测试（受控）", "scope": "network",
     "keywords": ("渗透测试", "渗透", "安全评估", "评估", "攻防", "红队",
                  "安全性测试", "安全测试", "测一下"),
     "tools": (("network_inspect", {"target": "target", "mode": "quick"}),
               ("service_identify", {"targets": "target"}),
               ("nuclei_scan", {"target": "$web", "severity": "critical,high",
                                "timeout": "900"}),
               ("cve_match_sm_por", {"data": "$output"}))},
)


# 用户「显式点名」的高风险动作 → 工具。
# 规则兜底也必须听懂明确要求的攻击动作：这样即使没有模型，用户点名的高危工具
# 也能进计划并被执行（同时带着 safety=risky 标注）。
# 匹配规则：含中文的关键词按子串匹配；纯 ASCII 关键词加词边界，避免误命中单词内部。
EXPLICIT_RISKY = (
    ("sqlmap_full", ("全量注入", "深度注入", "sqlmap full", "sqlmap_full")),
    ("hydra_bruteforce", ("爆破", "暴力破解", "hydra", "口令猜解", "弱口令", "口令审计",
                          "口令强度", "撞库")),
    ("hashcat_bruteforce", ("hashcat", "哈希破解", "哈希碰撞")),
    ("passwd_dict_gen", ("字典生成", "密码字典", "口令字典", "弱口令字典")),
    ("impacket_secretsdump", ("secretsdump", "导出凭据", "抓取哈希")),
    ("mimikatz_memory", ("mimikatz", "内存抓取凭据", "内存取密码")),
    ("msf_exploit", ("metasploit", "自动利用", "msfconsole", "msf 利用", "拿 shell",
                     "getshell")),
    ("msfvenom_payload", ("msfvenom", "生成 payload", "免杀木马")),
    ("kerberos_attack", ("kerberoast", "黄金票据", "kerberos 攻击", "as-rep")),
    ("lateral_redis_backdoor", ("redis 后门", "redis 未授权写入", "redis 写公钥")),
    ("lateral_hash_dump", ("抓取 sam", "dump 哈希", "shadow 文件", "hash dump")),
    ("lateral_ssh_exec", ("ssh 远程命令", "批量 ssh 执行", "横向 ssh")),
    ("persist_install", ("留后门", "持久化驻留", "安装后门", "权限维持")),
    ("socks_proxy", ("socks 代理", "内网代理", "socks5", "隧道代理")),
    ("revshell_handler", ("反弹 shell", "反弹shell", "reverse shell", "正向 shell")),
    ("poc_runner_sm_por", ("漏洞利用脚本", "poc 验证脚本", "poc 利用")),
    ("db_data_extract", ("脱库", "拖库", "数据库数据采集", "导出数据库数据")),
    ("file_extract", ("读取敏感文件", "提取配置文件", "读取远程文件")),
    ("cleanup_trace", ("清理痕迹", "清除痕迹", "清理日志", "清除日志", "擦除日志",
                       "痕迹清理", "的痕迹", "擦痕迹")),
)

# 同一意图的"安全款"与"高危款"：用户明确点名高危款时，安全款就不必再排一遍。
RISKY_SUPERSEDES = {"sqlmap_full": ("sqlmap_basic",)}


def match_explicit_risky(prompt):
    """命中用户显式点名的高风险动作，返回工具名列表（保持 EXPLICIT_RISKY 顺序）。"""
    import re as _re

    text = (prompt or "").lower()
    hits = []
    for tool, words in EXPLICIT_RISKY:
        for word in words:
            lowered = word.lower()
            if lowered.isascii():
                # ASCII 关键词用词边界，避免 "msf" 命中 "msfvenom" 之外的无意义片段
                if _re.search(r"\b%s\b" % _re.escape(lowered), text):
                    hits.append(tool)
                    break
            elif lowered in text:
                hits.append(tool)
                break
    return hits


def safety_of(tool_name):
    return "risky" if tool_name in SAFETY_RISKY else "safe"


def scope_allows(play, target):
    """剧本的 scope 与目标形态是否匹配。

    站点类剧本（scope=web）拿到网段目标时必须让位：否则 planner 会把
    CIDR 拼成 http://192.168.1.0/24 交给 nuclei/nikto，白跑一轮。
    """
    if play.get("scope") != "web":
        return True
    return not _is_range(target)


def _is_range(target):
    """目标是否是一个网段（CIDR）。"""
    import ipaddress as _ip

    try:
        _ip.IPv4Network(str(target or "").strip(), strict=False)
        return "/" in str(target or "")
    except ValueError:
        return False


def tool_index():
    """当前已加载工具的登记表（auto_discover 之后调用）。"""
    from registry import REGISTRY

    index = {}
    for name, spec in REGISTRY.items():
        index[name] = {
            "name": name,
            "description": spec.get("description", ""),
            "schema": spec.get("inputSchema", {}),
            "safety": safety_of(name),
        }
    return index


def match_playbooks(prompt, target=None):
    """按关键词命中剧本（可命中多个，按 PLAYBOOKS 顺序），并按目标形态过滤。"""
    text = (prompt or "").lower()
    hits = []
    for play in PLAYBOOKS:
        if not any(word.lower() in text for word in play["keywords"]):
            continue
        if not scope_allows(play, target):
            continue
        hits.append(play)
    return hits


def plan_hint():
    """给模型的目录摘要：全部 43 个工具都在，高风险工具带 [risky] 标注但不隐藏。

    早先这里把 risky 工具整个剔除，等于"模型排不出来 = 用户点不动"：skill 是被
    Agent 调取的，调用方看不到计划里还能有哪些动作，属于白白设卡。现在改成只标注、
    不隐藏 —— 模型可以照常把它们排进计划，执行层也不拦，安全性靠 safety=risky
    标注 + 报告里的"高风险动作"提示来表达。
    """
    index = tool_index()
    lines = []
    for name, spec in sorted(index.items()):
        params = list((spec["schema"].get("properties") or {}).keys())
        flag = "[risky] " if spec["safety"] != "safe" else ""
        lines.append("- %s%s(%s): %s" % (flag, name, ", ".join(params),
                                         spec["description"][:60]))
    return "\n".join(lines)
