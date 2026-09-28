#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
漏洞真实性验证工具 — 对Nuclei/Nikto报告的漏洞进行验证，排除误报，确认漏洞是否真实可利用
"""
import subprocess, re, time

import portscan

from utils import stream_run

def _run_cmd(cmd, timeout=30):
    try:
        r = stream_run(cmd, timeout=timeout, shell=True)
        return (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"

def _run_cmd_short(prog, args, timeout=15):
    """以列表形式运行命令，避免shell注入，自带超时"""
    try:
        r = stream_run([prog] + args, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"


def _verify_nuclei_result(target, vuln_name):
    """对单一nuclei报出的漏洞用nuclei -verify重新确认"""
    # 用nuclei的 -validate 或 -t 指定模板重新跑
    result = _run_cmd(f"nuclei -u {target} -severity critical,high -silent 2>/dev/null", 120)
    # 检查之前报的漏洞名是否还在输出中
    if vuln_name and vuln_name in result:
        return "已确认", result[:500]
    elif result.strip():
        return "其他漏洞", result[:500]
    else:
        return "未复现", ""


def _verify_web_vuln(target, port, ssl):
    """验证Web漏洞 — 用curl尝试实际访问验证"""
    proto = "https" if ssl else "http"
    results = []
    
    # 测试1: 检查服务是否真实可达
    r1 = _run_cmd(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 10 {proto}://{target}:{port}/", 15)
    results.append(f"HTTP状态码: {r1}")
    
    # 测试2: 检查响应头
    r2 = _run_cmd(f"curl -s -I --max-time 10 {proto}://{target}:{port}/ 2>/dev/null | head -20", 15)
    results.append(f"响应头:\n{r2[:500]}")
    
    # 测试3: 检查常见敏感路径是否真实存在
    for path in ["/admin", "/admin/", "/manager", "/phpinfo.php", "/.git/config",
                  "/backup", "/api", "/console", "/actuator/health"]:
        r3 = _run_cmd(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 {proto}://{target}:{port}{path}", 10)
        if r3.strip() in ("200", "401", "403", "302", "301"):
            results.append(f"[真实存在] {path} → HTTP {r3.strip()}")
    
    return "\n".join(results)


def _verify_hydra_result(target, service, user, pwd):
    """验证弱口令 — 实际尝试登录"""
    if service == "ssh":
        r = _run_cmd(f"sshpass -p '{pwd}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {user}@{target} 'echo SUCCESS' 2>&1", 15)
    elif service == "mysql":
        r = _run_cmd(f"mysql -u {user} -p'{pwd}' -h {target} -e 'SELECT 1' 2>&1", 15)
    elif service == "ftp":
        r = _run_cmd(f"curl -s --max-time 5 -u {user}:{pwd} ftp://{target}/ 2>&1", 10)
    else:
        return "不支持自动验证该服务"
    
    if "SUCCESS" in r or "1" in r.strip():
        return f"[已确认] {service}://{user}:{pwd}@{target} 登录成功"
    return f"[未确认] {service}://{user}:{pwd}@{target} 登录失败"


def _register(reg):
    reg({
        "name": "vuln_verify",
        "description": "漏洞真实性验证。对扫描报告中的漏洞进行复现确认，排除误报。输入格式: 每行 类型|IP|端口|漏洞描述（或直接粘贴之前扫描报告的内容）",
        "inputSchema": {"type": "object",
                      "properties": {
    "report": {
        "type": "string",
        "description": "漏洞报告内容或格式化数据。自动从文本中提取漏洞信息进行验证。\n支持直接粘贴 nuclei/nikto/hydra/scanner 的输出。"
    },
    "target": {
        "type": "string",
        "description": "（可选）手动指定目标IP，当report中没有提取到时使用"
    }
},
                      "required": ["report"]},
    })(tool_vuln_verify)


def tool_vuln_verify(name, params):
    report = params.get("report", "").strip()
    manual_target = params.get("target", "").strip()
    vuln_type = params.get("type", "").strip().lower()
    
    # 兼容旧调用方式：type+target -> 构造report
    if vuln_type and manual_target:
        if vuln_type == "snmp_public":
            report = f"SNMP public社区字符串暴露 | {manual_target}"
        elif vuln_type == "web_login":
            report = f"Web管理界面暴露 | {manual_target}"
        elif vuln_type == "default_pwd":
            report = f"默认密码风险 | {manual_target}"
        elif vuln_type:
            report = f"{vuln_type} | {manual_target}"
    
    if not report and not manual_target:
        return {"success": True, "returncode": 0, "output": "请提供漏洞报告内容或目标IP"}
    
    lines = []
    lines.append("═══ 漏洞真实性验证 ═══")
    lines.append(f"开始时间: {time.strftime('%H:%M:%S')}")
    lines.append("")
    
    # 从报告中提取目标
    targets_found = set()
    for line in report.split("\n"):
        ips = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', line)
        for ip in ips:
            if not ip.startswith("127.") and not ip.startswith("0."):
                targets_found.add(ip)
    
    if not targets_found and manual_target:
        targets_found.add(manual_target)
    
    if not targets_found:
        return {"success": True, "returncode": 0, "output": "无法从报告中提取到目标IP"}
    
    for target in sorted(targets_found):
        lines.append(f"\n━━━ 目标: {target} ━━━")
        
        # 1. ping检测是否在线
        ping = _run_cmd(f"ping -c 1 -W 2 {target} 2>&1", 5)
        if "1 received" in ping or "1 packets received" in ping:
            lines.append(f"[在线] {target} 可达")
        else:
            lines.append(f"[注意] {target} ping不可达，可能防火墙屏蔽")
        
        # 2. 端口检测
        # 端口范围走 portscan（1-65535）。这一步原本只探 8 个常用口，复核时
        # "端口没开" 会被当成"漏洞不存在"，非标端口上的真实漏洞会被复核掉。
        try:
            open_ports = [str(x) for x in portscan.discover(target, host_timeout=30, timeout=90)[0]]
        except Exception as exc:
            # 扫描没跑起来时不能把"端口检测失败"写成"端口没开"，那会把真实漏洞复核掉
            lines.append(f"[真实端口] 全端口扫描失败: {exc}")
            open_ports = []
        if open_ports:
            lines.append(f"[真实端口] 开放: {', '.join(open_ports)}")
            # 验证报告中的每项漏洞
            for port in open_ports:
                if port in ("80", "8080"):
                    vresult = _verify_web_vuln(target, port, ssl=False)
                    lines.append(f"\n  Web验证(端口{port}):")
                    for l in vresult.split("\n"):
                        lines.append(f"    {l}")
                elif port in ("443", "8443"):
                    vresult = _verify_web_vuln(target, port, ssl=True)
                    lines.append(f"\n  Web验证(端口{port}):")
                    for l in vresult.split("\n"):
                        lines.append(f"    {l}")
                elif port == "22":
                    lines.append("\n  SSH(端口22): 服务在线，弱口令威胁需要hydra验证")
                elif port == "3306":
                    lines.append("\n  MySQL(端口3306): 数据库在线，弱口令威胁需要hydra验证")
                elif port == "3389":
                    lines.append("\n  RDP(端口3389): 远程桌面在线")
                elif port == "6379":
                    lines.append("\n  Redis(端口6379): 缓存服务在线")
                elif port == "161":
                    snmp_result = _run_cmd(f"snmpwalk -v 2c -c public -t 5 -r 1 {target} 1.3.6.1.2.1.1.1.0 2>/dev/null", 10)
                    if snmp_result.strip() and "TIMEOUT" not in snmp_result:
                        sys_info = snmp_result.strip()[:200]
                        lines.append(f"  ⚠️ SNMP(端口161): public社区字符串可读! 系统信息: {sys_info}")
                    else:
                        lines.append("  SNMP(端口161): 端口开放但public不可读或有防火墙")
        else:
            lines.append("[注意] 未检测到开放端口，目标可能已下线或防火墙拦截")
        
        # 3. 尝试用nuclei重新验证
        lines.append("\n  Nuclei重新验证:")
        nresult = _run_cmd(f"nuclei -u {target} -severity critical,high -silent 2>/dev/null", 120)
        if nresult.strip():
            # 提取漏洞行
            vuln_lines = [l for l in nresult.split("\n") if l.strip()]
            # 比较原始报告中的漏洞和新扫描的漏洞
            report_vulns = set()
            for l in report.split("\n"):
                if target in l and ("critical" in l.lower() or "high" in l.lower() or "[cve" in l.lower()):
                    report_vulns.add(l.strip()[:100])
            
            new_vulns = set()
            for l in vuln_lines:
                new_vulns.add(l.strip()[:100])
            
            still_exist = report_vulns & new_vulns
            disappeared = report_vulns - new_vulns
            new_found = new_vulns - report_vulns
            
            if still_exist:
                lines.append(f"  [已确认] 以下漏洞仍然存在 ({len(still_exist)}个):")
                for v in list(still_exist)[:10]:
                    lines.append(f"    {v}")
            if disappeared:
                lines.append(f"  [可能误报] 以下漏洞已消失 ({len(disappeared)}个):")
                for v in list(disappeared)[:10]:
                    lines.append(f"    {v}")
            if new_found:
                lines.append(f"  [新增] 发现新的漏洞 ({len(new_found)}个):")
                for v in list(new_found)[:10]:
                    lines.append(f"    {v}")
        else:
            lines.append("  nuclei扫描未发现漏洞")
    
    lines.append("\n═══ 验证完成 ═══")
    
    if not lines:
        return {"success": True, "returncode": 0, "output": "目标不可达或无有效数据，无法完成验证"}
    
    return {"success": True, "returncode": 0, "output": "\n".join(lines)}
