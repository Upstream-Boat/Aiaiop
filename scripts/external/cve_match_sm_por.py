#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cve_match_sm_por — 根据服务/版本号查询CVE漏洞库
输入格式：每行一个服务，IP|端口|服务名|版本号
输出：每个服务匹配到的CVE列表（含CVSS评分、描述、修复建议）
"""
import sqlite3, os, re, json

import sys as _sys

_SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SCRIPTS_DIR not in _sys.path:
    _sys.path.insert(0, _SCRIPTS_DIR)
from config import CVE_DB_PATH as DB_PATH

def _register(reg):
    reg({
        "name": "cve_match_sm_por",
        "description": "CVE匹配查询。根据服务名称+版本号查询本地CVE漏洞库，返回所有匹配的CVE（含CVSS评分、描述、修复建议）。",
        "inputSchema": {"type": "object",
                      "properties": {
    "data": {
        "type": "string",
        "description": "服务数据。每行一个：IP|端口|服务名|版本号。示例：\n192.168.1.164|22|ssh|OpenSSH 8.9p1\n192.168.1.164|80|http|nginx 1.24.0"
    },
    "min_cvss": {
        "type": "number",
        "description": "最低CVSS分数过滤（只显示≥此分数的CVE），默认0",
        "default": 0
    },
    "limit": {
        "type": "integer",
        "description": "每个服务最多返回CVE数量，默认20",
        "default": 20
    }
},
                      "required": ["data"]},
    })(tool_cve_match)


# ── 版本号比较工具 ──

def _parse_version(ver_str):
    """解析版本号字符串为可比较的元组"""
    if not ver_str:
        return None
    # 提取数字部分
    nums = re.findall(r'(\d+)', ver_str)
    if not nums:
        return None
    return tuple(int(n) for n in nums)


def _ver_less_than(v, threshold):
    """判断版本v是否小于阈值threshold"""
    if v is None or threshold is None:
        return None
    tv = _parse_version(v)
    tt = _parse_version(str(threshold))
    if tv is None or tt is None:
        return None
    return tv < tt


def _ver_greater_equal(v, threshold):
    if v is None or threshold is None:
        return None
    tv = _parse_version(v)
    tt = _parse_version(str(threshold))
    if tv is None or tt is None:
        return None
    return tv >= tt


def _normalize_service_name(svc):
    """规范化服务名以匹配CVE产品名"""
    s = svc.lower().strip()
    mapping = {
        "ssh": "openssh",
        "http": None,  # 需要进一步判断
        "https": None,
        "ssl": None,
        "http-proxy": None,
        "mysql": "mysql",
        "mariadb": "mariadb",
        "postgresql": "postgresql",
        "postgres": "postgresql",
        "redis": "redis",
        "mongodb": "mongodb",
        "mongod": "mongodb",
        "nginx": "nginx",
        "apache": "apache httpd",
        "httpd": "apache httpd",
        "iis": "microsoft iis",
        "tomcat": "apache tomcat",
        "jenkins": "jenkins",
        "samba": "samba",
        "smb": "samba",
        "netbios-ssn": "samba",
        "microsoft-ds": "windows",
        "rdp": "windows",
        "ms-wbt-server": "windows",
        "winrm": "windows",
        "kubelet": "kubernetes",
        "kube-apiserver": "kubernetes",
        "kubernetes": "kubernetes",
        "etcd": "etcd",
        "docker": "docker",
        "prometheus": "prometheus",
        "grafana": "grafana",
        "zabbix": "zabbix",
        "elasticsearch": "elasticsearch",
        "kibana": "kibana",
        "rabbitmq": "rabbitmq",
        "activemq": "apache activemq",
        "vnc": "vnc",
        "x11": "x11",
        "openssl": "openssl",
        "vsftpd": "vsftpd",
        "proftpd": "proftpd",
        "pure-ftpd": "pure-ftpd",
        "openssh": "openssh",
        "lighttpd": "lighttpd",
        "caddy": "caddy",
        "traefik": "traefik",
        "haproxy": "haproxy",
        "squid": "squid",
        "memcached": "memcached",
        "cassandra": "cassandra",
        "couchdb": "couchdb",
        "couchbase": "couchbase",
        "nexus": "sonatype nexus",
        "jira": "atlassian jira",
        "confluence": "atlassian confluence",
        "gitlab": "gitlab",
        "harbor": "goharbor harbor",
        "vmware": "vmware esxi",
        "esxi": "vmware esxi",
    }
    return mapping.get(s, s)


def _extract_products(service, version):
    """从服务名+版本号中提取可能的产品名和版本号"""
    candidates = []
    svc_lower = service.lower()
    ver_str = version or ""
    
    # 从版本字段中提取产品名
    products_from_ver = re.findall(r'([a-zA-Z][\w.-]*(?:Server|OpenSSH|nginx|Apache|MySQL|Redis|Samba))', ver_str)
    for p in products_from_ver:
        candidates.append(p.lower())
    
    # 从服务名映射
    normalized = _normalize_service_name(svc_lower)
    if normalized:
        candidates.append(normalized)
    
    # 从服务名中提取关键词
    for kw in ["nginx", "apache", "httpd", "mysql", "redis", "samba", 
               "tomcat", "jenkins", "kubernetes", "kubelet", "docker",
               "ssh", "openssh", "postgresql", "mongodb", "iis",
               "activemq", "prometheus", "grafana", "vnc", "vsftpd",
               "proftpd", "lighttpd", "caddy", "traefik", "haproxy",
               "squid", "memcached", "rabbitmq", "elasticsearch",
               "kibana", "etcd", "zabbix", "nexus", "jira",
               "confluence", "gitlab", "harbor", "vmware", "esxi",
               "openssl", "cassandra", "couchdb", "couchbase",
               "mariadb", "wordpress", "drupal", "joomla",
               "phpmyadmin", "php", "python", "node", "java",
               "jenkins", "sonarqube", "salt", "ansible",
               "puppet", "chef", "nagios", "icinga"]:
        if kw in svc_lower or kw in ver_str.lower():
            candidates.append(kw)
    
    return list(set(candidates))


def _desc_version_ranges(desc):
    """从 CVE 描述里抠出"影响哪些版本"，抠不出返回 []。

    只认几种写得最死的说法（before / prior to / X and earlier / A through B）：
    这是保守估计，认不出来就交给人工与 vuln_verify 判断，绝不"猜一个范围"。
    返回 [(下界, 上界)]，None 表示这一侧没有边界。
    """
    text = (desc or "").lower()
    ranges = []
    for m in re.finditer(r"\b(?:before|prior to)\s+([0-9][0-9a-z.\-]*)", text):
        ranges.append((None, m.group(1)))
    for m in re.finditer(r"\b([0-9][0-9a-z.\-]*)\s+(?:and|or)\s+(?:earlier|before|older)", text):
        ranges.append((None, m.group(1)))
    for m in re.finditer(r"\b([0-9][0-9a-z.\-]*)\s+(?:through|thru|to)\s+([0-9][0-9a-z.\-]*)", text):
        ranges.append((m.group(1), m.group(2)))
    return ranges


def _version_verdict(desc, version):
    """拿探测到的版本号去对描述里的版本范围，返回 hit / miss / unknown。

    miss 才会被丢掉：例如目标 OpenSSH 8.0，而漏洞写的是"OpenSSH 2.3.1 through 3.3"。
    只要有一条能解读的范围判定命中就保留 —— 宁可多留给人复核，不可悄悄漏报。
    """
    if not version:
        return "unknown"
    target = _parse_version(version)
    if target is None:
        return "unknown"
    ranges = _desc_version_ranges(desc)
    if not ranges:
        return "unknown"
    for low, high in ranges:
        low_v = _parse_version(low) if low else None
        high_v = _parse_version(high) if high else None
        if low_v is not None and target < low_v:
            continue
        if high_v is not None and target >= high_v:
            continue
        return "hit"
    return "miss"


def _query_cve_for_product(conn, product, version, min_cvss=0, limit=20):
    """查询某个产品的CVE。

    产品名只做精确匹配（库里存的就是 openssh / nginx / wolfssh 这种规范名）。
    以前这里还带一条 `LIKE %product%`：查 openssh 时会把 wolfssh、libssh 的 CVE
    一起捞回来，报告里就出现"OpenSSH 8.0 命中 wolfSSH 漏洞"这种自相矛盾的条目 ——
    扫描器自己制造的误报，比漏报更难解释。
    """
    product_lower = product.lower().replace(" ", " ").strip()

    rows = conn.execute("""
        SELECT DISTINCT c.id, c.description, c.cvss_score, c.cvss_severity, 
               c.cvss_vector, c.affected_products, c.reference_urls
        FROM cve_items c
        JOIN cve_products p ON c.id = p.cve_id
        WHERE LOWER(p.product) = ?
          AND c.cvss_score >= ?
        ORDER BY c.cvss_score DESC
        LIMIT ?
    """, (product_lower, min_cvss, limit * 4)).fetchall()
    
    results = []
    for row in rows:
        cve_id, desc, score, sev, vector, affected, refs = row
        try:
            ref_list = json.loads(refs) if refs and refs.startswith("[") else []
            ref_str = "\n".join(ref_list[:3])
        except:
            ref_str = refs or ""
        
        verdict = _version_verdict(desc or "", version)
        if verdict == "miss":
            continue
        results.append({
            "cve_id": cve_id,
            "description": desc or "",
            "cvss_score": score or 0,
            "severity": sev or "",
            "affected": affected or product,
            "refs": ref_str,
            "version_verdict": verdict,
        })
    
    return results[:limit]


def tool_cve_match(name, params):
    data = params.get("data", "").strip()
    min_cvss = float(params.get("min_cvss", 0))
    limit = int(params.get("limit", 20))
    
    # 入参缺失/库缺失都算失败：返回 success=True 会让上游把它当成
    # "查完了、没有匹配的 CVE"，把一次空转伪装成干净结论。
    if not data:
        return {"success": False, "returncode": -1, "output":
                "请提供服务数据（每行 IP|端口|服务名|版本号）；"
                "也可以先跑 service_identify 再把它的输出传进来"}
    
    if not os.path.exists(DB_PATH):
        return {"success": False, "returncode": -1, "output": 
                "CVE数据库不存在。请先运行 cve_db_build_sm_por 构建漏洞库。"}
    
    # 解析输入
    services = []
    for line in data.strip().split("\n"):
        line = line.strip()
        # 跳过表头/装饰行，以及被拼进来的其它工具输出（service_identify 的
        # 注释行以 # 开头，network_inspect 的"服务:"行没有 | 分隔符）
        if not line or line.startswith("#") or (line.startswith("|") and "---" in line):
            continue
        parts = [p.strip() for p in re.split(r'[|\t]+', line)]
        if len(parts) >= 4 and parts[1].isdigit():
            services.append({"ip": parts[0], "port": int(parts[1]), 
                           "service": parts[2], "version": parts[3]})
        elif len(parts) >= 2:
            # 也支持简单的 "服务名 版本号" 格式
            services.append({"ip": "", "port": 0, "service": parts[0], "version": parts[1]})
    
    if not services:
        return {"success": True, "returncode": 0, "output": "无法解析输入数据"}
    
    conn = sqlite3.connect(DB_PATH)
    
    lines = []
    lines.append("═══ CVE 漏洞匹配结果 ═══\n")
    
    total_cves = 0
    for svc in services:
        ip = svc["ip"]
        port = svc["port"]
        service = svc["service"]
        version = svc["version"]
        
        products = _extract_products(service, version)
        
        lines.append(f"【{ip}:{port}】{service} {version}")
        lines.append(f"   搜索产品: {', '.join(products[:5])}")
        
        all_cves = []
        for product in products:
            cves = _query_cve_for_product(conn, product, version, min_cvss, limit)
            all_cves.extend(cves)
        
        # 去重
        seen = set()
        unique_cves = []
        for c in all_cves:
            if c["cve_id"] not in seen:
                seen.add(c["cve_id"])
                unique_cves.append(c)
        
        if unique_cves:
            for c in unique_cves[:limit]:
                total_cves += 1
                sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
                icon = sev_icon.get(c["severity"].upper(), "⚪")
                # 版本是否落在漏洞描述说的范围内：命中=可直接复核，待确认=要人工看
                tag = {"hit": "版本命中", "unknown": "版本待确认"}.get(c.get("version_verdict"), "")
                lines.append(f"   {icon} {c['cve_id']} (CVSS {c['cvss_score']}){('  ' + tag) if tag else ''}")
                lines.append(f"      {c['description'][:100]}")
            lines.append("")
        else:
            lines.append("   ✅ 未找到匹配的已知CVE\n")
    
    # 统计
    cur = conn.execute("SELECT COUNT(*) FROM cve_items")
    db_total = cur.fetchone()[0]
    lines.append("--- CVE库统计 ---")
    lines.append(f"本地库共 {db_total} 条CVE记录")
    lines.append(f"本次匹配到 {total_cves} 条CVE")
    
    conn.close()
    return {"success": True, "returncode": 0, "output": "\n".join(lines)}
