#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""复核（critic）— 把工具原始输出收敛成结构化发现，压误报、定严重级。

模型可用时让模型读输出做判定（要求严格 JSON）；模型不可用时用规则解析：
nuclei 的 [severity] 标记、nmap 标准端口行、network_inspect 的紧凑服务行、
常见高危关键词。两条路都产出同一种结构，报告与界面不关心来源。
"""

import re

from llm import client as llm_client, usage
from utils import loads_first_json

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_ALIAS = {"严重": "critical", "危急": "critical", "高": "high", "高危": "high",
              "中": "medium", "中危": "medium", "低": "low", "低危": "low", "信息": "info"}

# 只有 nuclei 系扫描器的输出才用 [severity] 标记判级。
# 不能对所有输出套这个正则 —— sqlmap 之类的工具日志也长成 "[INFO] ..."，
# 会被误判成 info 级发现（实测踩过：sqlmap 的 User-Agent 日志进了报告）。
NUCLEI_TOOLS = ("nuclei_scan",)
NUCLEI_SEV_RE = re.compile(r"\[(critical|high|medium|low|info)\]", re.I)
# nuclei 的完整结果行：[模板ID] [协议] [严重级] 目标 [附加键值]
NUCLEI_LINE_RE = re.compile(r"^\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(.+)$", re.M)
# 标准 nmap 行：22/tcp   open  ssh     OpenSSH 9.6
NMAP_PORT_RE = re.compile(r"^(\d{1,5})/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", re.M)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
CVE_LIST_LIMIT = 12   # 聚合条目里最多列出的 CVE 编号个数，避免刷屏

# network_inspect / network_survey 自带的紧凑服务行，形如：
#     服务: 22/tcp ssh OpenSSH 9.6 (protocol 2.0); 80/tcp http nginx 1.24.0
# 它不是标准 nmap 格式，上面的 NMAP_PORT_RE 匹配不到，所以单独解析一遍。
SVC_LINE_RE = re.compile(r"^\s*服务:\s*(.+)$", re.M)
# 逐条匹配（调用前已按 ';' 切分）。service 用 [^\s;]+ 限定，避免把下一条端口
# 当成上一条的版本信息吞掉 —— 例如 "88/tcp tcpwrapped; 445/tcp microsoft-ds?"。
SVC_ITEM_RE = re.compile(r"^(\d{1,5})/(tcp|udp)\s+([^\s;]+)\s*(.*)$")

# 端口暴露风险基线（等保/攻击面视角）：只对"确实探测到开放"的端口加注，不臆测版本漏洞。
# 命中即给出对应严重级，未命中按 info 记录，保证报告里的事实与判断可分离。
PORT_RISK = {
    # ── 凭据可达即等于接管：这些端口一旦暴露，弱口令/未授权就是直接后果 ──
    "2375": ("high", "Docker API 无 TLS 可达，未授权即等同宿主机 root"),
    "2376": ("medium", "Docker API 暴露（TLS 端口），确认证书校验是否强制"),
    "10250": ("high", "kubelet API 可达，未授权可直接在节点上执行容器"),
    "6443": ("medium", "Kubernetes API Server 暴露，确认匿名访问与 RBAC"),
    "7001": ("high", "WebLogic 控制台可达（历史反序列化 RCE 集中区）"),
    "7002": ("high", "WebLogic 管理通道可达（历史反序列化 RCE 集中区）"),
    "8009": ("high", "AJP 连接器可达（Ghostcat 文件读取/RCE 面）"),
    "5985": ("medium", "WinRM over HTTP 可达，横向移动常用入口且多为明文认证"),
    "5986": ("medium", "WinRM over HTTPS 可达，横向移动常用入口"),
    "623": ("high", "IPMI 可达（历史上存在认证绕过与密码哈希泄露）"),
    "512": ("high", "r 系列远程执行服务（明文且信任主机名，极易被横向利用）"),
    "513": ("high", "r 系列远程登录服务（明文且信任主机名）"),
    "514": ("high", "r 系列远程 Shell 服务（明文且信任主机名）"),
    # ── 数据库/缓存/检索服务直接可达 —— 通常不应暴露在业务网段外层 ──
    "3306": ("medium", "MySQL 数据库端口对外可达"),
    "5432": ("medium", "PostgreSQL 数据库端口对外可达"),
    "1433": ("medium", "MSSQL 数据库端口对外可达"),
    "1521": ("medium", "Oracle 数据库端口对外可达"),
    "6379": ("medium", "Redis 未授权访问风险端口对外可达"),
    "6380": ("medium", "Redis（备用端口）对外可达，未授权风险同上"),
    "27017": ("medium", "MongoDB 端口对外可达"),
    "9200": ("medium", "Elasticsearch 端口对外可达"),
    "9300": ("medium", "Elasticsearch 集群传输端口对外可达"),
    "5601": ("medium", "Kibana 控制台对外可达，常伴随未授权数据访问"),
    "5984": ("medium", "CouchDB 端口对外可达（历史存在未授权管理接口）"),
    "11211": ("medium", "Memcached 可达（未授权访问 + 放大攻击面）"),
    "9092": ("medium", "Kafka 端口对外可达（默认无认证）"),
    "2181": ("medium", "ZooKeeper 可达（默认无认证，可读到集群配置）"),
    "8500": ("medium", "Consul 可达（未授权可读服务目录与 KV）"),
    "15672": ("medium", "RabbitMQ 管理台可达（弱口令/默认口令风险）"),
    "10000": ("medium", "Webmin 可达（历史存在多处 RCE）"),
    "2049": ("medium", "NFS 共享可达，确认是否允许匿名挂载与 no_root_squash"),
    "873": ("medium", "rsync 服务可达（未授权可读写同步目录）"),
    "8088": ("medium", "YARN ResourceManager 可达（未授权可提交任务）"),
    # ── 目录与目录服务 ──
    "389": ("medium", "LDAP 明文服务可达，可能存在匿名绑定"),
    "636": ("low", "LDAPS 目录服务可达"),
    "3268": ("medium", "全局编录（GC）可达，域信息可被匿名枚举"),
    # ── Windows 文件共享面 —— 历史高危漏洞集中区，且常泄露共享与账户信息 ──
    "445": ("medium", "SMB 文件共享服务对外可达（高危漏洞面，应做访问控制）"),
    "139": ("medium", "NetBIOS 会话服务对外可达"),
    "135": ("low", "MSRPC 端点映射面暴露"),
    # ── 明文协议 —— 凭据与数据可被嗅探 ──
    "23": ("medium", "Telnet 明文远程登录"),
    "21": ("low", "FTP 明文传输"),
    "25": ("low", "SMTP 明文服务暴露（确认是否需要开放中继）"),
    "110": ("low", "POP3 明文服务"),
    "143": ("low", "IMAP 明文服务"),
    "161": ("medium", "SNMP UDP 可达（public 团体字是常见配置缺陷）"),
    "111": ("low", "rpcbind 暴露，建议配合 NFS 一起收敛"),
    "69": ("low", "TFTP 可达（无认证，可读可写）"),
    "80": ("low", "HTTP 明文服务"),
    # ── 远程管理面 —— 需要访问控制与强口令 ──
    "22": ("low", "SSH 远程管理面暴露"),
    "3389": ("low", "RDP 远程桌面面暴露"),
    "5900": ("low", "VNC 远程桌面面暴露"),
    "5901": ("low", "VNC 远程桌面面暴露"),
}

# ── 关键发现信号 ──────────────────────────────────────────────
# 只解析端口行是不够的：sqlmap 判定出注入点、hydra 猜出可用口令、nmap 脚本打出
# State: VULNERABLE —— 这些才是渗透结论本身。以前它们既不进报告也不进前端，
# 报告里只剩"端口开着"，等于把最有价值的一步丢了。
# 这里的每条都要求原文里有明确措辞，宁缺勿滥（误报比漏报更伤可信度）。
# nikto 条目里这些词说明是实质风险而不是纯配置建议
NIKTO_RISK_WORDS = "outdated|vulnerab|inject|traversal|xss|disclosure|reveals|upload|shell|default"

SIGNAL_RULES = (
    # 成功拿到凭据：hydra / ncrack 一类的固定格式 host: X login: Y password: Z
    (re.compile(r"login:\s*(\S+)\s+password:\s*(\S+)", re.I), "critical",
     "口令猜解成功", "从输出中直接读到可用的账号/口令组合"),
    # SQL 注入被确认
    (re.compile(r"sqlmap identified the following injection point", re.I), "high",
     "确认 SQL 注入点", "sqlmap 已在目标参数上确认注入，可直接读取数据库"),
    (re.compile(r"\bparameter:\s*(.+)$", re.I | re.M), "high",
     "SQL 注入参数", "sqlmap 报告的注入参数名"),
    (re.compile(r"back-end DBMS:\s*(.+)", re.I), "info",
     "数据库指纹", "sqlmap 识别出的后端数据库类型"),
    # nmap 漏洞脚本明确判定可利用
    (re.compile(r"\|\s*smb-vuln-ms17-010:\s*$", re.I | re.M), "critical",
     "MS17-010（永恒之蓝）", "nmap 脚本命中 ms17-010，需立即隔离确认"),
    (re.compile(r"state:\s*VULNERABLE", re.I), "high",
     "nmap 脚本判定可利用", "nmap NSE 脚本给出 VULNERABLE 结论"),
    (re.compile(r"\bCVE-\d{4}-\d{4,7}\b.*\bVULNERABLE\b", re.I), "high",
     "CVE 可利用确认", "输出中同时出现 CVE 编号与 VULNERABLE 结论"),
    # nikto 的两种发现行：
    #   + /composer.json: PHP Composer configuration file reveals ...
    #   + [999986] /: Retrieved x-powered-by header: PHP/8.3.33.
    # 第二种带条目编号，去掉编号后统一按关键词定级：涉及版本过旧、注入、
    # 信息泄露、上传等实质风险给 medium，其余配置类给 low。
    (re.compile(r"^\+\s+(/(?!>)[^\s:][^:]{0,120}):\s*(\S.{6,140})$", re.M), "medium",
     "Web 配置问题", "nikto 报告的可疑路径或配置项"),
    (re.compile(r"^\+\s+\[\d+\]\s+((?=.*(?:%s)).+)$" % NIKTO_RISK_WORDS, re.M), "medium",
     "Web 风险项", "nikto 条目涉及版本过旧/信息泄露/注入等实质风险"),
    (re.compile(r"^\+\s+\[\d+\]\s+((?!.*(?:%s)).{6,180})$" % NIKTO_RISK_WORDS, re.M), "low",
     "Web 配置项", "nikto 条目的配置类发现，按低危记录"),
)

REVIEW_PROMPT = """你是渗透测试结果复核员。下面是对授权目标的工具输出，请判定真实发现。

目标：%s
用户任务：%s

输出严格 JSON（下面是格式示例，title / evidence / tool 必须换成本次输出里的真实内容）：
{"summary": "一段话结论", "findings": [{"title": "开放端口 445/tcp microsoft-ds", "severity": "medium", "evidence": "445/tcp open microsoft-ds", "tool": "service_identify"}]}
severity 只能取 critical / high / medium / low / info 之一。

要求：
1. 只报输出里能直接看到证据的项，evidence 必须是从输出里摘出来的原文片段，不能为空；
2. 去掉误报与重复；3. 没有发现就返回空数组。
"""


def _port_finding(port, proto, service, version, tool):
    """把一条开放端口整理成发现项，按 PORT_RISK 定级。"""
    severity, note = PORT_RISK.get(str(port), ("info", "开放端口"))
    title = "开放端口 %s/%s %s" % (port, proto, (service or "unknown"))
    evidence = "%s/%s %s %s" % (port, proto, service or "", version or "")
    return {"title": title.strip()[:160], "severity": severity,
            "evidence": evidence.strip()[:160], "tool": tool, "note": note}


def _rule_findings(results):
    """规则兜底：从输出里提证据。"""
    findings = []
    for item in results:
        tool = item.get("tool")
        output = item.get("output") or ""
        if tool in NUCLEI_TOOLS:
            # 结构化取出行首的模板 ID 当标题，比整行原文可读得多
            for match in NUCLEI_LINE_RE.finditer(output):
                template, protocol, severity, rest = (g.strip() for g in match.groups())
                title = "nuclei 命中 %s: %s" % (template, rest)
                findings.append({"title": title[:120], "severity": severity.lower(),
                                 "evidence": match.group(0).strip()[:160], "tool": tool,
                                 "note": "协议 %s" % protocol})
            # 兜底：行首结构没匹配上时，退回按 [severity] 标记取整行
            if not NUCLEI_LINE_RE.search(output):
                for match in NUCLEI_SEV_RE.finditer(output):
                    line = output[match.start():output.find("\n", match.start())]
                    findings.append({"title": line.strip()[:120] or "nuclei 命中",
                                     "severity": match.group(1).lower(),
                                     "evidence": line.strip()[:160], "tool": tool})
        for match in NMAP_PORT_RE.finditer(output):
            findings.append(_port_finding(match.group(1), match.group(2),
                                          match.group(3), match.group(4), tool))
        # 兼容 network_inspect / network_survey 的紧凑服务行
        for line_m in SVC_LINE_RE.finditer(output):
            # 注意：这里不能复用外层的 item（那是工具结果字典）
            for svc_part in line_m.group(1).split(";"):
                svc_m = SVC_ITEM_RE.match(svc_part.strip())
                if not svc_m:
                    continue
                findings.append(_port_finding(svc_m.group(1), svc_m.group(2),
                                              svc_m.group(3), svc_m.group(4).strip(), tool))
        # 关键发现信号：sqlmap / hydra / nmap 脚本 / nikto 的结论
        for pattern, severity, title, note in SIGNAL_RULES:
            for match in pattern.finditer(output):
                detail = " ".join(g for g in match.groups() if g)
                findings.append({"title": ("%s: %s" % (title, detail))[:120].strip(),
                                 "severity": severity,
                                 "evidence": match.group(0).strip()[:160],
                                 "tool": tool, "note": note})
        # 只凭"输出里出现了 CVE 编号"不足以定性：CVE 库匹配的是厂商+产品名，
        # 版本区间是从描述文字里读的（"before 9.3" / "2.3.1 through 3.3"），
        # 读不出来的一律标"版本待确认"。以前这里直接给 medium，等于把"疑似"
        # 当"确认"，报告会被一堆撞名 CVE 淹没。改成 info + 分开写明命中/待确认，
        # 严重级只由 SIGNAL_RULES 里那些有明确措辞的证据给出。
        cve_hits = sorted(set(c.upper() for c in CVE_RE.findall(output)))
        if cve_hits:
            # cve_match 现在给每条标了"版本命中 / 版本待确认"：命中数单独报出来，
            # 因为它比"撞了个产品名"更值得复核。
            confirmed = len(re.findall(r"版本命中", output))
            # 聚合成一条：CVE 匹配一次动辄列出十几条，逐条占一行会把报告刷满，
            # 反而盖住真正有证据的发现。
            shown = cve_hits[:CVE_LIST_LIMIT]
            more = len(cve_hits) - len(shown)
            findings.append({
                "title": "疑似受影响 CVE %d 条（版本命中 %d 条，其余待确认）"
                         % (len(cve_hits), confirmed),
                "severity": "info",
                "evidence": "、".join(shown) + ("　… 另有 %d 条" % more if more else ""),
                "tool": tool, "cve_list": shown,
                "note": "CVE 库按厂商+产品名匹配，版本区间读自漏洞描述；标"
                        "「版本命中」的可直接复核，「版本待确认」的要人工核对版本"})
        if item.get("error"):
            findings.append({"title": "工具未完成：%s" % tool, "severity": "info",
                             "evidence": item["error"][:160], "tool": tool})
    # 去重（标题 + 证据前 60 字）
    seen, unique = set(), []
    for finding in findings:
        key = (finding["title"][:60], (finding.get("evidence") or "")[:60])
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    # 按严重级排序，报告里高危先出现
    unique.sort(key=lambda f: severity_rank(f.get("severity")))
    return unique[:60]


def _dump(results, limit=1200):
    blocks = []
    for item in results:
        blocks.append("### 工具 %s（耗时 %ss）\n%s" % (item.get("tool"), item.get("elapsed"),
                                                     (item.get("output") or "")[:limit]))
    return "\n\n".join(blocks)


def review(prompt, target, results, backend=None, model=None, use_model=True):
    """复核工具输出，返回 findings + summary。"""
    out = {"findings": [], "summary": "", "source": "rule", "usage": None}
    if use_model:
        try:
            raw = llm_client.chat(
                [{"role": "user", "content": REVIEW_PROMPT % (target or "(未指定)", prompt)
                  + "\n\n" + _dump(results)}],
                backend=backend, model=model, temperature=0.1)
            text = (raw.get("text") or "").strip()
            start, end = text.find("{"), text.rfind("}")
            if start >= 0 and end > start:
                data = loads_first_json(text)
                findings = []
                for item in data.get("findings") or []:
                    severity = _SEV_ALIAS.get(str(item.get("severity", "")).lower(),
                                              str(item.get("severity", "info")).lower())
                    evidence = str(item.get("evidence") or "")[:300]
                    # 没有证据的条目直接丢：本地模型有时只把示例标题抄回来，
                    # 这种"无证据发现"进了报告就是误报，交叉验证还得再翻一次
                    if not evidence.strip():
                        continue
                    findings.append({"title": str(item.get("title") or "")[:160],
                                     "severity": severity if severity in SEVERITY_ORDER else "info",
                                     "evidence": evidence,
                                     "tool": item.get("tool") or ""})
                out.update({"findings": findings, "summary": data.get("summary") or "",
                            "source": "model",
                            "usage": usage.stamp_usage(raw.get("usage"), raw.get("backend"),
                                                       raw.get("model"))})
                return out
        except Exception as exc:  # noqa: BLE001 - 模型不可用就退规则
            out["model_error"] = str(exc)[:160]
    out["findings"] = _rule_findings(results)
    out["summary"] = "按规则解析得到 %d 条发现（未使用模型复核）" % len(out["findings"])
    return out


# 排序用：认不出的严重级一律排到最后，不会因为写了个新词就冒到 critical 前面
def severity_rank(severity):
    try:
        return SEVERITY_ORDER.index(str(severity).lower())
    except ValueError:
        return len(SEVERITY_ORDER)


# 报告和轨迹摘要都用这份计数，避免两处各数一遍数出两个结果
def counts(findings):
    out = {}
    for finding in findings:
        out[finding["severity"]] = out.get(finding["severity"], 0) + 1
    return out
