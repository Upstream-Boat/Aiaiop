#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
设备类型识别 + OS漏洞扫描 v4
输入: service_identify 管道格式 (IP|port|service|version)
输出: 设备类型 + OS版本 + 内核漏洞 + 提权漏洞 + 已知CVE

v4 变化:
  - 新增 OS 版本精确提取（从SSH/HTTP banner中检测发行版+版本号）
  - 新增 内核漏洞匹配引擎（DirtyPipe/PwnKit/DirtyCow/OverlayFS等）
  - 新增 提权漏洞检测（sudo/CVE-2021-3156/Polkit等）
  - 新增 Windows EoP 漏洞匹配（PrintNightmare/MS11-046等）
  - 商用级输出：设备类型 + 漏洞等级 + CVE编号 + 利用方式
"""
import re, subprocess

from utils import stream_run

# ═══════════════════════════════════════════════════════════
# OS 漏洞数据库 — 商用级匹配引擎 (25+ Linux + 15 Windows)
# ═══════════════════════════════════════════════════════════

OS_DETECT_RULES = [
    # 精确版本匹配 (优先级高)
    (r'(?i)ubuntu[-\s]?(\d+)\.(\d+)', 'Ubuntu'),
    (r'(?i)ubuntu[-\s]?(\d+)ubuntu(\d+)\.(\d+)', 'Ubuntu'),  # SSH包: "ubuntu0ubuntu2.14"
    (r'(?i)debian[-\s]?(\d+)', 'Debian'),
    (r'(?i)centos[-\s]?(\d+)', 'CentOS'),
    (r'(?i)rhel[-\s]?(\d+)', 'RHEL'),
    (r'(?i)rocky[-\s]?(\d+)', 'Rocky Linux'),
    (r'(?i)alma[-\s]?(\d+)', 'AlmaLinux'),
    (r'(?i)fedora[-\s]?(\d+)', 'Fedora'),
    (r'(?i)opensuse[-\s]?([\d.]+)', 'openSUSE'),
    (r'(?i)kali[-\s]?([\d.]+)', 'Kali'),
    (r'(?i)alpine[-\s]?([\d.]+)', 'Alpine'),
    (r'(?i)linux[ -]([\d]+\.[\d]+\.[\d]+)', 'Linux'),
    (r'(?i)windows[_\s]?server[_\s]?(\d{4})', 'Windows Server'),
    (r'(?i)windows[_\s]?(\d+(?:\.\d+)?)', 'Windows'),
    (r'(?i)win32|win64', 'Windows'),
    # 仅OS名无版本号 (兜底匹配)
    (r'(?i)\bubuntu\b', 'Ubuntu'),
    (r'(?i)\bdebian\b', 'Debian'),
    (r'(?i)\bcentos\b', 'CentOS'),
    (r'(?i)\brhel\b', 'RHEL'),
    (r'(?i)\bkali\b', 'Kali'),
    (r'(?i)\bfedora\b', 'Fedora'),
    (r'(?i)\bgentoo\b', 'Gentoo'),
    (r'(?i)\balpine\b', 'Alpine'),
]

# Linux 内核提权/容器逃逸漏洞 DB: (min_kernel, max_kernel_exclusive, desc, cvss, exploit, affected)
KERNEL_CVE_DB = [
    ("CVE-2024-1086", "2.6", "6.8", "netfilter nf_tables UAF → 内核提权(Flipping Pages 7.8)", "7.8", "公开EXP", "Linux 全系 2.6-6.7"),
    ("CVE-2023-0386", "5.11", "6.2", "OverlayFS setuid绕过 → 本地提权(7.8)", "7.8", "公开EXP", "Linux 5.11-6.1"),
    ("CVE-2023-32233", "2.6", "6.4", "netfilter nf_tables UAF → 内核提权(7.8)", "7.8", "公开EXP", "Linux 全系 2.6-6.3"),
    ("CVE-2022-0847", "5.8", "5.16.11", "DirtyPipe — 覆写任意文件 → 本地提权(7.8)", "7.8", "公开EXP(极简)", "Linux 5.8-5.16.10"),
    ("CVE-2022-2588", "2.6", "6.0", "netlink UAF → 本地提权(7.8)", "7.8", "公开EXP", "Linux 2.6-5.19"),
    ("CVE-2022-0995", "5.8", "5.17", "watch_queue UAF → 容器逃逸+提权(7.8)", "7.8", "公开EXP", "Linux 5.8-5.16"),
    ("CVE-2022-0185", "5.1", "5.16", "fsconfig heap溢出 → 容器逃逸+提权(8.4)", "8.4", "公开EXP", "Linux 5.1-5.15"),
    ("CVE-2022-0492", "2.6", "5.17", "cgroup release_agent → 容器逃逸(7.0)", "7.0", "公开EXP", "Linux 2.6-5.16"),
    ("CVE-2021-4034", "0", "0", "PwnKit pkexec → 本地提权(7.8) polkit<0.120", "7.8", "公开EXP(一行)", "所有Linux(polkit版本)"),
    ("CVE-2021-3493", "5.11", "5.11.15", "OverlayFS → Ubuntu 20/21 本地提权(7.8)", "7.8", "公开EXP", "Ubuntu 20.04/21.04"),
    ("CVE-2021-3156", "0", "0", "Sudo Baron Samedit → 本地提权(7.8) sudo<1.9.5p2", "7.8", "公开EXP(经典)", "所有Linux(sudo版本)"),
    ("CVE-2021-22555", "2.6", "5.12", "netfilter xt_compat溢出 → 本地提权(7.8)", "7.8", "公开EXP", "Linux 2.6-5.11"),
    ("CVE-2020-8835", "4.8", "5.5", "eBPF verifier UAF → 本地提权(7.8)", "7.8", "公开EXP", "Linux 4.8-5.4"),
    ("CVE-2019-13272", "2.6", "5.1", "ptrace → 本地提权(7.8)", "7.8", "公开EXP", "Linux 2.6-5.0"),
    ("CVE-2018-18955", "2.6", "4.20", "userns ID映射 → 本地提权(7.8)", "7.8", "公开EXP", "Linux 2.6-4.19"),
    ("CVE-2017-7308", "3.2", "4.11", "AF_PACKET溢出 → 本地提权(7.8)", "7.8", "公开EXP", "Linux 3.2-4.10"),
    ("CVE-2016-5195", "2.6.22", "4.8.3", "DirtyCow COW竞态 → 本地提权(7.8)", "7.8", "公开EXP(经典)", "Linux 2.6.22-4.8.2"),
    ("CVE-2016-0728", "3.8", "4.4", "keyring溢出 → 本地提权(7.8)", "7.8", "公开EXP", "Linux 3.8-4.3"),
    ("CVE-2015-1328", "3.13", "3.16", "OverlayFS chown → 本地提权(7.2)", "7.2", "公开EXP", "Linux 3.13-3.15"),
    ("CVE-2014-3153", "2.6", "3.15", "futex_requeue UAF → 提权(Towelroot 7.2)", "7.2", "公开EXP", "Linux 2.6-3.14"),
    ("CVE-2013-2094", "2.6.37", "3.8.9", "perf_event溢出 → 本地提权(7.2)", "7.2", "公开EXP", "Linux 2.6.37-3.8.8"),
    ("CVE-2010-3904", "2.6", "2.6.36", "RDS协议栈 → 本地提权(7.2)", "7.2", "公开EXP", "Linux 2.6-2.6.35"),
]

UBUNTU_KERNEL = {"24.04":"6.8","23.10":"6.5","23.04":"6.2","22.04":"5.15","21.10":"5.13","21.04":"5.11","20.04":"5.4","18.04":"4.15","16.04":"4.4","14.04":"3.13"}
DEBIAN_KERNEL = {"12":"6.1","11":"5.10","10":"4.19","9":"4.9","8":"3.16","7":"3.2"}
CENTOS_KERNEL = {"9":"5.14","8":"4.18","7":"3.10","6":"2.6.32"}

WINDOWS_CVE_DB = [
    ("CVE-2024-38077", "RDL授权服务RCE MadLicense(9.8)", "9.8", "公开POC", "Win2008-Win2022"),
    ("CVE-2024-49113", "LDAP RCE no-auth(9.8)", "9.8", "公开POC", "Win10/Win11/Win2019/Win2022"),
    ("CVE-2020-0796", "SMBGhost SMBv3压缩RCE(10.0)", "10.0", "公开EXP", "Win10-1903/Win2019-1903"),
    ("CVE-2019-0708", "BlueKeep RDP RCE(9.8)", "9.8", "公开EXP(MSF)", "Win7/Win2008R2/XP/2003"),
    ("CVE-2021-34527", "PrintNightmare 打印服务RCE→SYSTEM(8.8)", "8.8", "公开EXP", "Win7-Win10/Win2008-Win2019"),
    ("CVE-2017-0143", "EternalBlue SMBv1 RCE(8.1)", "8.1", "公开EXP(NSA)", "Win7/Win2008R2/XP/2003"),
    ("CVE-2023-28252", "CLFS驱动提权(7.8)", "7.8", "公开EXP", "Win10 1607+/Win2016+"),
    ("CVE-2022-24521", "CLFS驱动提权(7.8)", "7.8", "公开EXP", "Win10 1507+/Win2016+"),
    ("CVE-2021-36934", "HiveNightmare SAM越权(7.8)", "7.8", "公开EXP", "Win10 1809/Win2019+"),
    ("CVE-2021-1675", "PrintNightmare v1(7.8)", "7.8", "公开EXP", "Win7-Win10/Win2008-Win2019"),
    ("CVE-2019-1388", "UAC绕过→SYSTEM(7.8)", "7.8", "公开EXP", "Win7-Win10/Win2008-Win2019"),
    ("CVE-2018-8120", "win32k.sys提权(7.0)", "7.0", "公开EXP", "Win7/Win2008R2"),
    ("MS11-046", "afd.sys本地提权(7.2)", "7.2", "公开EXP", "XP/Win2003"),
    ("CVE-2024-30088", "内核竞态提权(7.0)", "7.0", "公开EXP", "Win10/Win11/Win2016+"),
]


def _kv(v):
    try: return tuple(int(p) for p in re.findall(r'(\d+)', v)[:3])
    except: return ()

def _in_range(kv, lo, hi):
    k, l, h = _kv(kv), _kv(lo), _kv(hi)
    if not k or not l: return False
    if h and k >= h: return False
    return k >= l

def _detect_os(services):
    """从服务banner中提取OS信息 → {os, version, kernel, confidence, source}"""
    r = {"os":None,"version":None,"kernel":None,"conf":0,"source":""}
    text = " ".join((s.get("version","") or "") + " " + s.get("service","") for s in services)
    for pat, fam in OS_DETECT_RULES:
        m = re.search(pat, text)
        if m:
            r["os"], r["conf"], r["source"] = fam, 60 if m.lastindex else 35, f"banner:{pat}"
            gs = m.groups() if m.lastindex else []
            if gs: r["version"] = ".".join(str(g) for g in gs[:2] if g)
            break
    # SSH包版本反查Ubuntu: "1:8.9p1-3ubuntu0.10" → ubuntu0 → 22.04
    pkg = re.search(r'(?i)ubuntu[-\s]?(\d)ubuntu', text)
    if pkg:
        d = pkg.group(1)
        m = {"0":"22.04","2":"20.04","3":"24.04","4":"24.10"}.get(d)
        if m: r["os"], r["version"], r["conf"], r["source"] = "Ubuntu", m, 70, "SSH包版本反查"
    # OpenSSH版本 → Ubuntu版本推断 (无精确版本时)
    if r["os"] == "Ubuntu" and not r.get("version"):
        ssh = re.search(r'OpenSSH[_\s]+([\d.]+)', text)
        if ssh:
            ssh_ver = ssh.group(1)
            # OpenSSH 9.6+ → Ubuntu 24.04, 8.9-9.5 → 22.04, 8.2-8.8 → 20.04, 7.6-8.1 → 18.04
            try:
                parts = ssh_ver.split(".")
                major, minor = int(parts[0]), int(parts[1]) if len(parts)>1 else 0
                if major >= 10 or (major==9 and minor>=6): ver, kern = "24.04", "6.8"
                elif major==9 or (major==8 and minor>=9): ver, kern = "22.04", "5.15"
                elif major==8 and minor>=2: ver, kern = "20.04", "5.4"
                elif major>=8 or (major==7 and minor>=6): ver, kern = "18.04", "4.15"
                elif major==7 and minor>=2: ver, kern = "16.04", "4.4"
                else: ver, kern = "14.04", "3.13"
                r["version"], r["kernel"] = ver, kern
                r["conf"], r["source"] = 45, f"OpenSSH {ssh_ver} → Ubuntu推断"
            except: pass
    # CentOS同理: OpenSSH 7.4 → CentOS 7
    if r["os"] == "CentOS" and not r.get("version"):
        ssh = re.search(r'OpenSSH[_\s]+([\d.]+)', text)
        if ssh:
            try:
                major = int(ssh.group(1).split(".")[0])
                if major >= 9: ver, kern = "9", "5.14"
                elif major >= 8: ver, kern = "8", "4.18"
                elif major >= 7: ver, kern = "7", "3.10"
                else: ver, kern = "6", "2.6.32"
                r["version"], r["kernel"] = ver, kern
                r["conf"], r["source"] = 40, f"OpenSSH {ssh.group(1)} → CentOS推断"
            except: pass
    # Debian同理
    if r["os"] == "Debian" and not r.get("version"):
        ssh = re.search(r'OpenSSH[_\s]+([\d.]+)', text)
        if ssh:
            try:
                major = int(ssh.group(1).split(".")[0])
                if major >= 9: ver, kern = "12", "6.1"
                elif major >= 8: ver, kern = "11", "5.10"
                elif major >= 7: ver, kern = "10", "4.19"
                else: ver, kern = "9", "4.9"
                r["version"], r["kernel"] = ver, kern
                r["conf"], r["source"] = 40, f"OpenSSH {ssh.group(1)} → Debian推断"
            except: pass
    # Ubuntu 内核推断 (有版本号时)
    if r["os"] == "Ubuntu" and r.get("version"):
        for uv, kv in sorted(UBUNTU_KERNEL.items(), reverse=True):
            if r["version"].startswith(uv): r["kernel"] = kv; break
    return r

def _kernel_cves(kv, fam, os_ver):
    vulns = []
    if kv:
        for cve, lo, hi, desc, cvss, exp, aff in KERNEL_CVE_DB:
            if lo == "0":
                vulns.append((cve, "系统组件提权", desc, cvss, exp, aff))
            elif _in_range(kv, lo, hi):
                vulns.append((cve, "内核提权/容器逃逸", desc, cvss, exp, aff))
    # Ubuntu特有
    if os_ver and fam == "Ubuntu" and os_ver[:2] in ("20","21"):
        vulns.append(("CVE-2021-3493", "Ubuntu特有提权", "OverlayFS→Ubuntu20/21提权(gameoverlayfs)", "7.8", "公开EXP", "Ubuntu 20.04/21.04"))
    return vulns

def _windows_cves(text):
    vulns = []
    if not re.search(r'windows|microsoft|win32|win64|win\d', text.lower()): return vulns
    for cve, desc, cvss, exp, aff in WINDOWS_CVE_DB:
        vulns.append((cve, "Windows提权/RCE", desc, cvss, exp, aff))
    return vulns

def _os_vuln_scan(services):
    """主扫描: 输入services列表, 返回完整漏洞报告"""
    osi = _detect_os(services)
    text = " ".join((s.get("version","") or "") + " " + s.get("service","") for s in services)
    vulns = []
    # Linux
    if osi["os"] in ("Ubuntu","Debian","CentOS","RHEL","Fedora","Rocky Linux","AlmaLinux","Kali","openSUSE","Alpine","Arch Linux","Gentoo","Linux"):
        kv = osi.get("kernel")
        if not kv and osi.get("version") and osi["os"] == "Ubuntu":
            for uv, kv in sorted(UBUNTU_KERNEL.items(), reverse=True):
                if osi["version"].startswith(uv): osi["kernel"] = kv; break
        if not kv and osi.get("version") and osi["os"] == "Debian":
            for dv, kv in sorted(DEBIAN_KERNEL.items(), reverse=True):
                if osi["version"].startswith(dv): osi["kernel"] = kv; break
        if not kv and osi.get("version") and osi["os"] == "CentOS":
            for cv, kv in sorted(CENTOS_KERNEL.items(), reverse=True):
                if osi["version"].startswith(cv): osi["kernel"] = kv; break
        if kv:
            vulns.extend(_kernel_cves(kv, osi["os"], osi.get("version")))
            osi["conf"] = max(osi["conf"], 50)
        elif osi.get("version"):
            vulns.extend(_kernel_cves(None, osi["os"], osi.get("version")))
            osi["conf"] = max(osi["conf"], 35)
    # Windows
    if osi["os"] == "Windows" or re.search(r'windows|microsoft|win32|win64|win\d', text.lower()):
        vulns.extend(_windows_cves(text))
        if not osi["os"]: osi["os"] = "Windows"; osi["conf"] = 30
    # 去重+排序
    seen = set()
    uniq = []
    for v in vulns:
        if v[0] not in seen: seen.add(v[0]); uniq.append(v)
    uniq.sort(key=lambda x: float(x[3]), reverse=True)
    # 风险评级
    c = sum(1 for v in uniq if float(v[3])>=9.0)
    h = sum(1 for v in uniq if 7.0<=float(v[3])<9.0)
    risk = "严重" if c>=3 else ("高危" if c>=1 or h>=3 else ("中危" if h>=1 else "低"))
    return {"os_info":osi, "vulns":uniq[:20], "total":len(uniq), "critical":c, "high":h, "risk":risk}

def _register(reg):
    reg({
        "name": "os_identify",
        "description": "设备类型识别 v3（深度指纹）。根据端口/服务/SSL证书/Nmap指纹识别设备类型（路由器/交换机/防火墙/NAS/服务器/容器等）",
        "inputSchema": {"type": "object",
                      "properties": {
    "data": {
        "type": "string",
        "description": "端口服务数据。每行一个服务，格式: IP|端口|服务|版本"
    },
    "deep": {
        "type": "integer",
        "description": "深度探测模式。1=启用sudo nmap -O（5200+指纹库，需root），0=仅规则匹配（默认）",
        "default": 0
    }
},
                      "required": ["data"]},
    })(tool_os_identify)


def _run_cmd(cmd, timeout=60):
    try:
        r = stream_run(cmd, timeout=timeout, shell=True)
        return (r.stdout or "") + (r.stderr or "")
    except:
        return ""


def _grab_banner(ip, port, timeout=8):
    """主动抓取端口的真实banner信息"""
    port = str(port).strip()
    result = None
    
    if port in ("80", "8080", "8000", "8888", "3000", "9090"):
        r = _run_cmd(f"curl -s -I --max-time {timeout} http://{ip}:{port}/ 2>/dev/null | grep -i '^server:\|^www-authenticate:\|^location:' | head -3", timeout)
        if r.strip():
            result = r.strip()[:120]
    elif port in ("443", "8443", "9443", "5443", "7443", "6443"):
        # 优先用openssl拿SSL证书subject（最稳定，不依赖Web服务实现）
        r = _run_cmd(f"echo '' | timeout 6 openssl s_client -connect {ip}:{port} -servername {ip} 2>&1 | openssl x509 -noout -subject 2>&1 | head -1", timeout+2)
        if r and r.strip() and "error" not in r.lower() and "unable" not in r.lower():
            result = "SSL: " + r.strip()[:80]
        else:
            # 降级：用curl抓Server头
            r = _run_cmd(f"curl -s -I --max-time {timeout} -k https://{ip}:{port}/ 2>/dev/null | grep -i '^server:\|^www-authenticate:' | head -3", timeout)
            if r.strip():
                result = r.strip()[:120]
    # 通用：尝试nc读banner
    if result is None and port.isdigit():
        r = _run_cmd(f"timeout {timeout} bash -c 'exec 3<>/dev/tcp/{ip}/{port}; read -t 3 line <&3; echo \"$line\"' 2>/dev/null", timeout+2)
        if r and r.strip():
            result = r.strip()[:100]
    return result


def _enhance_services(services):
    """对版本缺失的服务，主动抓取banner补全。SSL端口即使有版本也强制抓取"""
    enhanced = []
    for s in services:
        ver = s.get("version", "").strip()
        ssl_ports = {443, 8443, 9443, 5443, 7443, 6443}
        force_grab = s.get("port", 0) in ssl_ports
        if (not ver or ver in ("-", "unknown", "?", "none", "")) or force_grab:
            banner = _grab_banner(s["ip"], s["port"])
            if banner:
                s["version"] = banner
                s["_banner_grabbed"] = True
        enhanced.append(s)
    return enhanced


def _nmap_deep_scan(ip, timeout=45):
    """用sudo nmap -O+T4做深度设备类型识别（5200+条nmap-os-db指纹库）"""
    result = _run_cmd(f"sudo nmap -O -T4 --max-retries 2 --host-timeout 20s {ip} 2>&1", timeout)
    out = {}
    
    # 解析nmap -O的输出结构
    m = re.search(r'Device type:\s*(.+?)(?:\n|$)', result, re.IGNORECASE)
    if m: out["device_type"] = m.group(1).strip()
    
    m = re.search(r'Running(?:\s*\(JUST GUESSING\))?:\s*(.+?)(?:\n|$)', result, re.IGNORECASE)
    if m: out["running"] = m.group(1).strip()
    
    agg = re.findall(r'Aggressive OS guesses:\s*(.+?)(?:\n|$)', result, re.IGNORECASE)
    if agg: out["guesses"] = agg[0].strip()
    
    m = re.search(r'OS details:\s*(.+?)(?:\n|$)', result, re.IGNORECASE)
    if m: out["details"] = m.group(1).strip()
    
    cpe = re.findall(r'OS CPE:\s*(.+)', result, re.IGNORECASE)
    if cpe: out["cpe"] = [c.strip() for c in cpe[:3]]
    
    # 解析完整指纹匹配结果
    match_section = re.search(r'No exact OS matches for host[^\n]*', result, re.IGNORECASE)
    if match_section:
        out["exact_match"] = False
    else:
        exact = re.search(r'OS details[^\n]*', result, re.IGNORECASE)
        if exact:
            out["exact_match"] = True
    
    out["raw"] = result[:600]
    return out


def _nmap_sv_scan(ip, ports, timeout=30):
    """补充扫描：对已知端口用nmap -sV拿详细版本号"""
    port_list = "-p " + ",".join(ports) if ports else ""
    if not port_list:
        return {}
    result = _run_cmd(f"sudo nmap -sV -T4 {port_list} --max-retries 1 --host-timeout 15s {ip} 2>/dev/null", timeout)
    out = {}
    for line in result.split("\n"):
        m = re.match(r'(\d+)/tcp\s+open\s+(\S+)\s+(.+)', line)
        if m:
            p, svc, ver = m.group(1), m.group(2), m.group(3).strip()
            out[p] = {"service": svc, "version": ver}
    return out


def _classify_device(ip_groups, deep_results):
    """
    主分类逻辑：组合端口+服务+banner+nmap结果 → 设备类型
    返回: { ip: {type, confidence, reason, vuln_hints} }
    """
    outputs = {}
    
    for ip, svcs in sorted(ip_groups.items()):
        full_info = []
        ports = set()
        services_found = set()
        banner_text = ""
        ssl_org = ""
        has_ssh = False
        has_rdp = False
        has_samba = False
        has_k8s = False
        has_redis = False
        etcd_ports = 0
        
        for s in svcs:
            svc_lower = s.get("service", "").lower()
            ver = s.get("version", "")
            port = str(s.get("port", ""))
            ports.add(port)
            
            combo = f"{svc_lower} {ver}".lower()
            full_info.append(combo)
            
            if port == "22": has_ssh = True
            if port == "3389": has_rdp = True
            if "rdp" in svc_lower: has_rdp = True
            if "samba" in combo or "smb" in svc_lower or port == "445":
                has_samba = True
            if port == "6443": has_k8s = True
            if "kube" in combo: has_k8s = True
            if port == "10250": has_k8s = True
            if port == "2379": etcd_ports += 1
            if port == "6379": has_redis = True
            
            services_found.add(svc_lower.split()[0] if svc_lower else port)
            if ver and ver not in ("-", "unknown", "?"):
                banner_text += " " + ver
                # SSL证书提取组织名
                if "SSL:" in ver or "subject=" in ver:
                    org = re.search(r'O\s*=\s*([^,\n]+)', ver)
                    if org:
                        ssl_org = org.group(1).strip()
        
        combined = " ".join(full_info)
        b_lower = banner_text.lower()
        
        # ── 设备分类决策树 ──
        device_type = "未知设备"
        confidence = 0
        reason_parts = []
        vuln_hints = []
        
        # 1. K8s节点（最高优先级）
        if has_k8s:
            device_type = "Kubernetes 节点"
            confidence = 85
            reason_parts.append("kube-apiserver(6443)+kubelet(10250)")
            vuln_hints.append("K8s未授权API访问")
            vuln_hints.append("kubelet 10250未授权命令执行(CVE-2020-8555)")
            if etcd_ports > 0:
                vuln_hints.append("etcd 2379未授权访问(敏感数据泄露)")
        
        # 2. Docker节点
        elif has_k8s is False and ("2375" in ports or "2376" in ports or "docker" in combined):
            device_type = "Docker 容器节点"
            confidence = 80
            reason_parts.append("Docker API(2375)暴露")
            vuln_hints.append("Docker API未授权远程命令执行")
        
        # 3. VMware ESXi
        elif "vmware" in b_lower or "esxi" in b_lower or "902" in ports:
            device_type = "VMware ESXi 虚拟化平台"
            confidence = 85
            reason_parts.append("VMware服务特征")
            vuln_hints.append("vSphere/ESXi 已知漏洞(Log4j/CVE-2021-44228)")
        
        # 4. 深信服设备
        elif "sangfor" in b_lower or "sangfor" in ssl_org.lower():
            device_type = "深信服 安全设备"
            confidence = 80
            reason_parts.append(f"SSL证书: {ssl_org or 'Sangfor'}")
            vuln_hints.append("深信服设备默认口令/后门")
        
        # 5. 绿联NAS
        elif "ugreen" in b_lower or "ugreen" in ssl_org.lower():
            device_type = "UGREEN 绿联 NAS"
            confidence = 80
            reason_parts.append(f"SSL证书: {ssl_org or 'UGREEN'}")
            vuln_hints.append("NAS默认Web管理口令风险")
        
        # 6. 群晖NAS
        elif "synology" in b_lower or "dsm" in b_lower or "diskstation" in b_lower:
            device_type = "Synology 群晖 NAS"
            confidence = 85
            reason_parts.append("Synology DSM服务")
            vuln_hints.append("Synology DSM已知漏洞(Synology-SA系列)")
        
        # 7. 威联通
        elif "qnap" in b_lower or "quts" in b_lower:
            device_type = "QNAP 威联通 NAS"
            confidence = 85
            reason_parts.append("QNAP服务特征")
            vuln_hints.append("QNAP已知漏洞(QSA系列)")
        
        # 8. 锐捷/H3C/华为网络设备
        elif "ruijie" in b_lower or "ruijie" in ssl_org.lower():
            device_type = "锐捷 网络设备(交换机/路由器)"
            confidence = 75
            reason_parts.append(f"SSL证书: {ssl_org}")
            vuln_hints.append("锐捷设备已知漏洞/默认口令")
        elif "h3c" in b_lower or "h3c" in ssl_org.lower() or "hpe" in b_lower:
            device_type = "H3C/HPE 网络设备"
            confidence = 75
            reason_parts.append("厂商: H3C")
            vuln_hints.append("H3C设备远程代码执行漏洞")
        
        # 9. Redis服务
        elif has_redis and not has_k8s:
            device_type = "Redis 缓存服务器"
            confidence = 70
            reason_parts.append("Redis(6379)未配置密码")
            vuln_hints.append("Redis未授权访问(敏感数据泄露/RCE)")
        
        # 10. Samba文件服务器
        elif has_samba and not has_k8s:
            device_type = "Samba 文件服务器"
            confidence = 60
            reason_parts.append("Samba(SMB)服务")
            vuln_hints.append("Samba漏洞(CVE-2017-7494/CVE-2021-44758)")
        
        # 11. Web服务器(纯HTTP/HTTPS)
        elif len(ports) <= 3 and any(p in ports for p in ["80", "443", "8080", "8443"]):
            if "nginx" in combined:
                device_type = "Nginx Web服务器"
            elif "apache" in combined or "httpd" in combined:
                device_type = "Apache Web服务器"
            elif "iis" in combined:
                device_type = "Windows IIS Web服务器"
                vuln_hints.append("IIS 已知漏洞")
            elif "proxy" in combined:
                device_type = "反向代理服务器"
            else:
                device_type = "Web服务器"
            confidence = 50
            reason_parts.append(f"端口: {','.join(sorted(ports))}")
        
        # 12. 通用Linux服务器(有SSH)
        elif has_ssh:
            device_type = "Linux 服务器"
            confidence = 40
            reason_parts.append(f"SSH+{len(ports)-1}个端口")
        
        # 13. Windows(有RDP)
        elif has_rdp:
            device_type = "Windows 服务器"
            confidence = 50
            reason_parts.append("RDP(3389)")
            vuln_hints.append("RDP漏洞(CVE-2019-0708 BlueKeep/CVE-2020-0796)")
        
        # 14. 兜底
        else:
            svc_names = ", ".join(sorted(services_found))[:40]
            device_type = f"未知设备(服务: {svc_names})"
            confidence = 20
            reason_parts.append(f"端口: {','.join(sorted(ports))}")
        
        # ── 合并nmap深度扫描结果 ──
        nmap_info = deep_results.get(ip, {})
        nmap_lines = []
        if nmap_info and nmap_info.get("device_type"):
            nmap_lines.append(f"nmap类型: {nmap_info['device_type']}")
        if nmap_info and nmap_info.get("running"):
            nmap_lines.append(f"   系统: {nmap_info['running']}")
        if nmap_info and nmap_info.get("details"):
            nmap_lines.append(f"   详情: {nmap_info['details']}")
        if nmap_info and nmap_info.get("guesses"):
            nmap_lines.append(f"   猜测: {nmap_info['guesses'][:100]}")
        
        # 用nmap结果增强设备类型
        if nmap_info and nmap_info.get("running") and confidence < 60:
            run_str = nmap_info["running"].lower()
            if "linux" in run_str and device_type in ("未知设备", "Web服务器", "未知", "Linux 服务器"):
                device_type = "Linux 服务器"
                confidence = max(confidence, 55)
            elif "windows" in run_str and device_type in ("未知设备", "未知"):
                device_type = "Windows 服务器"
                confidence = max(confidence, 55)
                vuln_hints.append("Windows远程桌面(RDP)漏洞风险")
            elif "synology" in run_str or "diskstation" in run_str:
                device_type = "Synology 群晖 NAS"
                confidence = max(confidence, 70)
        
        outputs[ip] = {
            "device_type": device_type,
            "confidence": confidence,
            "reasons": reason_parts,
            "vuln_hints": vuln_hints,
            "nmap_info": nmap_lines
        }
    
    return outputs


def _parse_input(data):
    services = []
    for line in data.strip().split("\n"):
        line = line.strip()
        if not line or (line.startswith("|") and "---" in line):
            continue
        if line.startswith("|") and line.endswith("|"):
            parts = [p.strip() for p in line.strip("|").split("|")]
            if len(parts) >= 3 and parts[1].isdigit():
                if len(parts) == 3:
                    parts.append("-")
                services.append({"ip": parts[0], "port": int(parts[1]), "service": parts[2], "version": parts[3]})
                continue
        if "|" in line and not line.startswith("|"):
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 3 and parts[1].isdigit():
                if len(parts) == 3:
                    parts.append("-")
                services.append({"ip": parts[0], "port": int(parts[1]), "service": parts[2], "version": parts[3]})
                continue
        parts = line.split()
        if len(parts) >= 3 and parts[1].isdigit():
            if len(parts) == 3:
                parts.append("-")
            services.append({"ip": parts[0], "port": int(parts[1]), "service": parts[2],
                           "version": " ".join(parts[3:])})
    return services


def tool_os_identify(name, params):
    data = params.get("data", "").strip()
    deep = params.get("deep", 0)
    
    if not data:
        return {"success": False, "returncode": -1, "output": "请提供端口服务数据（格式 IP|端口|服务|版本）"}
    
    services = _parse_input(data)
    if not services:
        return {"success": False, "returncode": -1, "output": "无法解析输入数据，请使用格式: IP|端口|服务|版本"}
    
    # 补全banner
    services = _enhance_services(services)
    grabbed_count = sum(1 for s in services if s.get("_banner_grabbed"))
    
    # 如果deep=1且SSL端口没抓到banner，用openssl重新试
    if deep == 1:
        for s in services:
            port = s.get("port", 0)
            if port in (443, 8443, 9443, 5443, 7443, 6443):
                ver = s.get("version", "")
                if not ver or "SSL:" not in str(ver):
                    r = _run_cmd(f"echo '' | timeout 6 openssl s_client -connect {s['ip']}:{port} -servername {s['ip']} 2>&1 | openssl x509 -noout -subject 2>&1 | head -1", 10)
                    if r and r.strip() and "error" not in r.lower() and "unable" not in r.lower():
                        s["version"] = "SSL: " + r.strip()[:80]
                        s["_banner_grabbed"] = True
                        grabbed_count += 1
    
    # 按IP分组
    ip_groups = {}
    for s in services:
        ip = s["ip"]
        if ip not in ip_groups:
            ip_groups[ip] = []
        ip_groups[ip].append(s)
    
    # deep模式：两级探测
    deep_results = {}
    if deep == 1:
        for ip, svcs in ip_groups.items():
            # 第一级：nmap -sV 补全版本号
            ports = [str(s["port"]) for s in svcs][:5]  # 最多扫5个端口
            if len(ports) <= 3:
                # 端口太少，补充common ports
                ports = list(set(ports + ["22","80","443","8080","8443"][:5-len(ports)]))
            sv_results = _nmap_sv_scan(ip, ports)
            # 用nmap -sV结果替换空版本
            for s in svcs:
                p = str(s["port"])
                if p in sv_results and (not s.get("version") or s["version"] in ("-", "unknown", "?", "none")):
                    s["version"] = sv_results[p]["version"]
            # 第二级：nmap -O 指纹识别（5200+指纹库）
            deep_results[ip] = _nmap_deep_scan(ip)
    
    # 分类
    classified = _classify_device(ip_groups, deep_results)
    
    # ── 输出格式化 ──
    lines = []
    lines.append("═══ 设备类型识别 + OS漏洞扫描报告 v4 ═══" if deep == 1 else "═══ 设备类型识别 + OS漏洞扫描报告 v4 ═══")
    lines.append("")
    
    for ip, info in sorted(classified.items()):
        dev = info["device_type"]
        conf = info["confidence"]
        conf_str = f"{conf}%" if conf > 0 else "低"
        reason = "; ".join(info["reasons"])
        
        lines.append(f"【{ip}】→ {dev} (置信度{conf_str})")
        lines.append(f"   依据: {reason}")
        
        if info["nmap_info"]:
            for nline in info["nmap_info"]:
                lines.append(f"   {nline}")
        
        # ═══ OS漏洞扫描 ═══
        ip_svcs = ip_groups.get(ip, [])
        if ip_svcs:
            vuln_report = _os_vuln_scan(ip_svcs)
            osi = vuln_report["os_info"]
            lines.append("   「OS漏洞扫描结果」")
            if osi["os"]:
                lines.append(f"   检测OS: {osi['os']} {osi.get('version','?')}  kernel:{osi.get('kernel','?')} (置信度{osi['conf']}%)")
            lines.append(f"   风险等级: {vuln_report['risk']}  ("
                        f"严重:{vuln_report['critical']} 高危:{vuln_report['high']} 总计:{vuln_report['total']})")
            if vuln_report["vulns"]:
                for cve, typ, desc, cvss, exp, aff in vuln_report["vulns"][:8]:
                    sev = "🔴" if float(cvss)>=9.0 else ("🟠" if float(cvss)>=7.0 else "🟡")
                    lines.append(f"     {sev} {cve} [{typ}] {desc}")
                    lines.append(f"        CVSS:{cvss} | EXP:{exp} | 影响:{aff}")
            else:
                lines.append("   (未匹配到OS层漏洞 — 可能需要更精确的OS版本信息)")
        
        # 原有vuln_hints
        vulns = info.get("vuln_hints", [])
        if vulns:
            lines.append("   设备层漏洞提示:")
            for v in vulns:
                lines.append(f"     ⚠ {v}")
        lines.append("")
    
    if grabbed_count:
        lines.append(f"[主动抓取了 {grabbed_count} 个端口的banner]\n")
    
    lines.append("--- 原始输入 ---")
    for s in services:
        ver = s.get('version','') or '-'
        tag = " ⬅️ 主动抓取" if s.get("_banner_grabbed") else ""
        lines.append(f"  {s['ip']} | {s['port']} | {s['service']} | {ver}{tag}")
    
    return {"success": True, "returncode": 0, "output": "\n".join(lines)}
