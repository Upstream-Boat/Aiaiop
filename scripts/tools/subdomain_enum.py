#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""子域名枚举 - Subfinder API聚合+DNS爆破双引擎，扩大攻击面发现隐藏资产

sources 选路：subfinder 走外部 API（要能出网），dnsbrute 用文件里硬编码的那几十个
常见前缀挨个解析（纯本地，离线可用但慢）。all 是先跑 subfinder 再叠一遍字典。
要加词直接改 subs。
"""


from registry import tool
from utils import run_cmd
from helpers import *  # noqa: F401,F403


@tool(
    "subdomain_enum",
    "子域名枚举 - Subfinder API聚合+DNS爆破双引擎，扩大攻击面发现隐藏资产",
    {
        "properties": {
            "domain": {
                "type": "string",
                "description": "目标域名（如 example.com）",
            },
            "sources": {
                "type": "string",
                "description": "数据源: subfinder(API聚合)/dnsbrute(DNS爆破)/all(全部)",
                "default": "all",
            },
            "timeout": {
                "type": "integer",
                "description": "超时秒数（默认300）",
                "default": 300,
            },
        },
        "required": ["domain"],
    },
)
def subdomain_enum_handler(params):
            domain = params.get("domain","")
            sources = params.get("sources","all")
            timeout = int(params.get("timeout",300))
            if sources in ("subfinder","all"):
                r = run_cmd(f"subfinder -d {domain} -silent -t 100 -timeout {min(timeout-30,270)}", timeout)
                if sources == "all" and r["success"]:
                    subs = ["www","mail","ftp","admin","api","dev","test","portal","vpn","app","blog","shop","cdn","remote","webmail","owa","autodiscover","git","gitlab","jenkins","jira","confluence","wiki","status","monitor","grafana","kibana","log","backup","db","mysql","ldap","sso","auth","login","cloud","storage","files","assets","static","internal","secure"]
                    import socket as _sock
                    dns_results = []
                    for sub in subs:
                        try: _sock.gethostbyname(f"{sub}.{domain}"); dns_results.append(f"{sub}.{domain}")
                        except: pass
                    if dns_results: r["output"] += f"\n\n[DNS爆破] 发现 {len(dns_results)} 个:\n" + "\n".join(dns_results)
                return r
            if sources == "dnsbrute":
                subs = ["www","mail","ftp","admin","api","dev","test","portal","vpn","app","blog","shop","cdn","remote","webmail","owa","autodiscover","git","gitlab","jenkins","jira","confluence","wiki"]
                import socket as _sock
                results = []
                for sub in subs:
                    try:
                        host = f"{sub}.{domain}"
                        ip = _sock.gethostbyname(host)
                        results.append(f"{host} -> {ip}")
                    except: pass
                return {"success":True,"returncode":0,"output":f"子域名枚举: {domain}\n发现 {len(results)} 个:\n" + "\n".join(results) if results else f"未发现子域名"}
