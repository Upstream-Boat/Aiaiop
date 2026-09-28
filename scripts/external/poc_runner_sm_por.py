#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
poc_runner_sm_por — 自动POC验证引擎
根据CVE编号自动匹配可用的验证脚本并执行：
  1. nuclei模板（覆盖Web/中间件/CMS）
  2. msfconsole模块（覆盖系统/服务）
  3. searchsploit PoC（覆盖Exploit-DB）
  4. GitHub PoC脚本（覆盖公开CVE验证脚本）
"""
import subprocess, json, os

from utils import stream_run

def _register(reg):
    reg({
        "name": "poc_runner_sm_por",
        "description": "POC自动验证引擎。输入CVE编号+目标IP:端口，自动搜索可用验证脚本并执行。支持nuclei/msf/searchsploit/公开PoC。",
        "inputSchema": {"type": "object",
                      "properties": {
    "target": {
        "type": "string",
        "description": "目标IP地址"
    },
    "port": {
        "type": "integer",
        "description": "目标端口",
        "default": 0
    },
    "cve": {
        "type": "string",
        "description": "CVE编号，如 CVE-2024-6387"
    },
    "auto": {
        "type": "integer",
        "description": "1=从CVE自动推断并尝试所有可用验证方式，0=手动指定验证引擎（默认1）",
        "default": 1
    },
    "engine": {
        "type": "string",
        "description": "指定验证引擎：nuclei/msf/searchsploit/github，auto=1时自动选择",
        "default": "auto"
    }
},
                      "required": ["target", "cve"]},
    })(tool_poc_runner)


def _run_cmd(cmd, timeout=60):
    try:
        r = stream_run(cmd, timeout=timeout, shell=True)
        return (r.stdout or "") + (r.stderr or "")
    except:
        return ""


def _try_nuclei(target, port, cve):
    """用nuclei模板验证CVE"""
    port_flag = f"-p {port}" if port else ""
    cmd = f"nuclei -t http/cves/ -t vulnerabilities/ -json -silent -target {target} {port_flag} 2>/dev/null | grep -i '{cve}' | head -5"
    result = _run_cmd(cmd, 120)
    if result.strip():
        return f"✅ [nuclei] {cve} 验证通过：\n{result[:500]}", True
    return "", False


def _try_msf(target, port, cve):
    """用msfconsole搜索并尝试模块"""
    cmd = f"msfconsole -q -x 'search {cve}; exit' 2>/dev/null"
    result = _run_cmd(cmd, 30)
    
    modules = []
    for line in result.split("\n"):
        if cve.lower() in line.lower() and ("exploit" in line.lower() or "auxiliary" in line.lower()):
            parts = line.strip().split()
            for p in parts:
                if p.startswith("exploit/") or p.startswith("auxiliary/"):
                    modules.append(p)
                    break
    
    if modules:
        info = f"✅ [msf] 找到 {len(modules)} 个可用模块:\n"
        for m in modules[:3]:
            info += f"    运行: msfconsole -q -x 'use {m}; set RHOSTS {target}; run; exit'\n"
        return info, True
    return "", False


def _try_searchsploit(target, port, cve):
    """用searchsploit搜索PoC"""
    cve_id = cve.replace("CVE-", "").replace("cve-", "")
    cmd = f"searchsploit --json {cve_id} 2>/dev/null"
    result = _run_cmd(cmd, 30)
    
    try:
        data = json.loads(result)
        exploits = data.get("RESULTS_EXPLOIT", [])
        papers = data.get("RESULTS_PAPER", [])
        if exploits or papers:
            info = "✅ [searchsploit] 找到 PoC:\n"
            for e in (exploits + papers)[:3]:
                path = e.get("Path", "")
                title = e.get("Title", "")
                info += f"    {title}\n    {path}\n"
            return info, True
    except:
        pass
    
    return "", False


def _try_poc_scripts(target, port, cve):
    """尝试在本地PoC目录中寻找并执行验证脚本"""
    import sys as _sys

    _scripts_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _scripts_dir not in _sys.path:
        _sys.path.insert(0, _scripts_dir)
    from config import EXPLOIT_DB_EXPLOITS
    poc_dirs = [d for d in (EXPLOIT_DB_EXPLOITS,) if d]
    
    found = []
    
    for poc_dir in poc_dirs:
        if os.path.isdir(poc_dir):
            r = _run_cmd(f"grep -rl '{cve}' {poc_dir} --include='*.py' --include='*.rb' --include='*.pl' --include='*.sh' --include='*.txt' 2>/dev/null | head -5", 30)
            for match in r.strip().split("\n"):
                if match.strip():
                    found.append(match.strip())
    
    if found:
        info = f"✅ [本地PoC] 找到 {len(found)} 个验证脚本:\n"
        for f in found[:3]:
            info += f"    {f}\n"
        return info, True
    return "", False


def tool_poc_runner(name, params):
    target = params.get("target", "").strip()
    port = int(params.get("port", 0))
    cve = params.get("cve", "").strip().upper()
    auto = int(params.get("auto", 1))
    engine = params.get("engine", "auto")
    
    if not target or not cve:
        return {"success": True, "returncode": 0, "output": "请提供 target 和 cve 参数"}
    
    lines = []
    lines.append("═══ PoC 自动验证引擎 ═══")
    lines.append(f"目标: {target}:{port if port else '自动'}")
    lines.append(f"CVE: {cve}")
    lines.append("")
    
    verified = False
    
    if auto == 1 or engine in ("auto", "all"):
        engines = ["nuclei", "msf", "searchsploit", "local"]
        
        for eng in engines:
            lines.append(f"▶ 尝试 {eng} 引擎...")
            if eng == "nuclei":
                msg, ok = _try_nuclei(target, port, cve)
            elif eng == "msf":
                msg, ok = _try_msf(target, port, cve)
            elif eng == "searchsploit":
                msg, ok = _try_searchsploit(target, port, cve)
            elif eng == "local":
                msg, ok = _try_poc_scripts(target, port, cve)
            
            if msg:
                lines.append(msg)
                verified = ok
            else:
                lines.append(f"   {eng}: 未找到匹配验证脚本")
            lines.append("")
    else:
        # 指定引擎
        lines.append(f"▶ 使用引擎: {engine}")
        if engine == "nuclei":
            msg, ok = _try_nuclei(target, port, cve)
        elif engine == "msf":
            msg, ok = _try_msf(target, port, cve)
        elif engine == "searchsploit":
            msg, ok = _try_searchsploit(target, port, cve)
        else:
            msg = f"未知引擎: {engine}"
            ok = False
        if msg:
            lines.append(msg)
            verified = ok
    
    if not verified:
        lines.append("⚠ 未找到可用的自动化验证脚本。")
        lines.append("可能原因：")
        lines.append("  - 该CVE是纯信息性漏洞（无PoC）")
        lines.append("  - nuclei模板/msf模块未安装或未更新")
        lines.append("  - 需要手动审查CVE详情后验证")
        lines.append(f"\n建议手动搜索: https://github.com/search?q={cve}&type=repositories")
    
    return {"success": True, "returncode": 0, "output": "\n".join(lines)}
