#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""重新生成 references/tools.md（从注册表，避免文档与代码脱节）。

用法: python3 scripts/gen_tools_doc.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from registry import REGISTRY, auto_discover  # noqa: E402

REF = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "references", "tools.md")

CATEGORIES = [
    ("侦察与资产发现", ["ping_scan", "ip_usage_report", "network_survey", "masscan_scan"]),
    ("子域名与 DNS", ["subdomain_enum"]),
    ("Web 应用测试", ["nikto_scan", "dirb_scan", "sqlmap_basic", "sqlmap_full", "waf_detect"]),
    ("漏洞扫描", ["nuclei_scan", "cve_match_sm_por", "cve_db_build_sm_por",
                  "poc_runner_sm_por", "vuln_verify", "os_identify", "service_identify"]),
    ("口令攻击", ["hydra_bruteforce", "hashcat_bruteforce", "passwd_dict_gen"]),
    ("利用与后渗透", ["exploit_search", "msfvenom_payload", "msf_exploit", "smb_enum",
                      "impacket_secretsdump", "impacket_smbexec", "kerberos_attack",
                      "mimikatz_memory", "revshell_handler", "persist_install", "socks_proxy",
                      "lateral_portscan", "lateral_smb_enum", "lateral_hash_dump",
                      "lateral_ssh_exec", "lateral_redis_backdoor"]),
    ("网络探测", ["network_inspect", "free_ip_scan"]),
    ("合规检查", ["compliance_report"]),
    ("数据处理", ["db_data_extract", "file_extract", "cleanup_trace"]),
    ("其他", ["get_current_time"]),
]


def main():
    failed = auto_discover()
    lines = ["# 工具目录（%d 个）" % len(REGISTRY), "",
             "> 由 `scripts/gen_tools_doc.py` 从注册表自动生成，请勿手改。", ""]
    placed = set()
    for title, names in CATEGORIES:
        rows = sorted(n for n in names if n in REGISTRY)
        if not rows:
            continue
        lines += [f"## {title}", ""]
        for name in rows:
            spec = REGISTRY[name]
            placed.add(name)
            props = spec.get("inputSchema", {}).get("properties", {})
            required = set(spec.get("inputSchema", {}).get("required", []))
            lines.append(f"### `{name}`")
            lines.append(spec["description"])
            if props:
                lines += ["", "| 参数 | 类型 | 必填 | 说明 |", "| --- | --- | --- | --- |"]
                for key, val in props.items():
                    lines.append(
                        f"| `{key}` | {val.get('type', 'string')} | "
                        f"{'是' if key in required else '否'} | {val.get('description', '')} |"
                    )
            lines.append("")
    rest = sorted(set(REGISTRY) - placed)
    if rest:
        lines += ["## 未分类", ""]
        for name in rest:
            lines.append(f"- `{name}` — {REGISTRY[name]['description']}")
        lines.append("")
    with open(REF, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"已写入 {REF}（{len(REGISTRY)} 个工具）")
    if failed:
        print("警告：部分模块加载失败:")
        for line in failed:
            print(" -", line)


if __name__ == "__main__":
    main()
