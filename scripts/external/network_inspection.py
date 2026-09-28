#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
内网巡检工具 — network_inspect + free_ip_scan
功能：子网空闲IP发现、设备分类（安全/网络/服务器/工作站/物联网）、
      CPU/内存/磁盘使用率、开放端口与服务识别、MAC厂商识别
"""
import subprocess, os, re, ipaddress, time

from utils import stream_run

import sys as _sys

_scripts_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _scripts_dir not in _sys.path:
    _sys.path.insert(0, _scripts_dir)
from config import MAC_PREFIX_FILE
import portscan
MAC_CACHE = {}
_last_mac_load = 0

# ── MAC 厂商库 ──────────────────────────────────────────────
def _load_mac_vendors():
    global _last_mac_load
    if MAC_CACHE and time.time() - _last_mac_load < 3600:
        return MAC_CACHE
    try:
        with open(MAC_PREFIX_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    MAC_CACHE[parts[0].upper()] = parts[1]
        _last_mac_load = time.time()
    except Exception:
        pass
    return MAC_CACHE

def _lookup_mac_vendor(mac):
    if not mac:
        return ""
    clean = mac.upper().replace(':', '').replace('-', '').replace('.', '')[:6]
    vendors = _load_mac_vendors()
    return vendors.get(clean, "")

# ── 设备分类规则 ──────────────────────────────────────────────
SECURITY_VENDORS = [
    'sangfor', 'fortinet', 'palo alto', 'check point', 'juniper networks',
    'hillstone', 'venustech', 'topsec', 'nsfocus', 'qianxin', '360',
    'barracuda', 'sonicwall', 'watchguard', 'f5 networks', 'imperva',
    'array networks', 'ruijie', 'sangfor technologies',
]
NETWORK_VENDORS = [
    'cisco', 'huawei', 'h3c', 'arista', 'brocade', 'extreme networks',
    'd-link', 'tp-link', 'netgear', 'zyxel', 'mikrotik', 'ubiquiti',
    'ruijie', 'maipu', 'hpe', 'dell', 'juniper', 'aruba',
]
SERVER_VENDORS = [
    'supermicro', 'lenovo', 'hewlett packard', 'hp ', 'ibm', 'oracle',
    'fujitsu', 'hitachi', 'emc', 'netapp', 'synology', 'qnap',
    'inspur', 'huawei', 'dell inc', 'dell ',
]

def _classify_device(mac_vendor, open_ports, os_guess, services, hostname=""):
    vendor_lower = (mac_vendor or "").lower()
    ports_set = set(open_ports or [])
    svc_lower = " ".join(services or []).lower()
    os_lower = (os_guess or "").lower()

    # 安全设备
    sec_score = 0
    for kw in SECURITY_VENDORS:
        if kw in vendor_lower:
            sec_score += 3
    sec_ports = {443, 8443, 444, 10443, 8089, 8000, 514, 6514, 161, 162}
    if ports_set & sec_ports:
        sec_score += 1
    if any(kw in svc_lower for kw in ['ssl-vpn', 'sslvpn', '防火墙', 'firewall', 'ips', 'ids', 'waf']):
        sec_score += 2
    if sec_score >= 3:
        return ("安全设备", min(sec_score, 5) * 20)

    # 网络设备
    net_score = 0
    for kw in NETWORK_VENDORS:
        if kw in vendor_lower:
            net_score += 3
    if ports_set & {161, 23}:
        net_score += 2
    if any(kw in os_lower for kw in ['ios', 'nx-os', 'junos', 'router', 'switch', 'comware', 'vrp']):
        net_score += 3
    if any(kw in svc_lower for kw in ['snmp', 'telnet', 'bgp', 'ospf', 'lldp']):
        net_score += 2
    if net_score >= 3:
        return ("网络设备", min(net_score, 5) * 20)

    # 服务器
    srv_score = 0
    for kw in SERVER_VENDORS:
        if kw in vendor_lower:
            srv_score += 2
    srv_ports = {3306, 5432, 1433, 6379, 27017, 8080, 8443, 9090, 3000, 5000, 9200, 5601}
    if ports_set & srv_ports:
        srv_score += 2
    if any(kw in os_lower for kw in ['linux', 'windows server', 'centos', 'ubuntu', 'debian', 'rhel', 'freebsd']):
        srv_score += 3
    # 中间件/数据库类服务：指向服务器，但不单独定性
    if any(kw in svc_lower for kw in ['mysql', 'postgresql', 'redis', 'mongodb',
                                      'mssql', 'oracle', 'elasticsearch', 'rabbitmq']):
        srv_score += 2
    # 明确的应用服务软件：出现即判服务器。
    # 以前只按 srv_score>=3 定性，nmap 认不出 OS（虚拟机/容器里很常见）时会漏判 ——
    # 一台只跑 nginx + OpenSSH 的主机 srv_score 只有 2，被归进"其他 30%"，
    # 巡检结论就失真了。这些软件不会跑在交换机/防火墙上，判错的代价远小于漏判。
    app_services = ['nginx', 'apache', 'httpd', 'tomcat', 'jetty', 'iis',
                    'weblogic', 'php-fpm', 'docker', 'kube', 'gitlab',
                    'jenkins', 'gunicorn', 'uwsgi']
    if any(kw in svc_lower for kw in app_services):
        srv_score += 3
    # SSH + Web 端口是很典型的 Linux 服务器组合；单独的 SSH 不判（交换机也有 SSH）
    if 'ssh' in svc_lower and (ports_set & {80, 443, 3000, 8000, 8080, 8443}):
        srv_score += 2
    if any(kw in (hostname or "").lower() for kw in ['server', 'srv', 'db', 'web', 'app', 'k8s', 'node']):
        srv_score += 1
    if srv_score >= 3:
        return ("服务器", min(srv_score, 5) * 20)

    # 工作站
    if os_lower and ('windows' in os_lower or 'microsoft' in os_lower) and 'server' not in os_lower:
        return ("工作站", 60)
    if 'apple' in vendor_lower or 'macos' in os_lower or 'mac os' in os_lower:
        return ("工作站", 70)

    # 物联网
    iot_kw = ['camera', 'cctv', 'hikvision', 'dahua', 'axis', 'printer', 'canon',
              'xerox', 'ip phone', 'polycom', 'yealink', 'door', 'access control',
              'temperature', 'sensor', 'plc', 'scada']
    if any(kw in vendor_lower for kw in iot_kw):
        return ("物联网设备", 70)

    return ("其他", 30) if ports_set else ("其他", 0)


# ── SSH 巡检 ──────────────────────────────────────────────────
def _ssh_collect(ip, username, password, port=22, timeout=15):
    metrics = {"cpu_percent": "", "mem_percent": "", "mem_total": "", "mem_used": "",
               "disk_info": "", "load_avg": "", "uptime": "", "os_release": "",
               "hostname": "", "kernel": "", "error": None}

    cmd_script = (
        "hostname 2>/dev/null; "
        "cat /etc/os-release 2>/dev/null|head -4; "
        "uname -r 2>/dev/null; "
        "uptime 2>/dev/null; "
        "cat /proc/loadavg 2>/dev/null; "
        "free -m 2>/dev/null|tail -2; "
        "df -h / /data /home /var 2>/dev/null; "
        "nproc 2>/dev/null"
    )

    try:
        import shlex
        esc = shlex.quote(cmd_script)
        ssh_cmd = (
            f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no "
            f"-o UserKnownHostsFile=/dev/null -o ConnectTimeout={timeout} "
            f"-p {port} {username}@{ip} {esc} 2>/dev/null"
        )
        r = stream_run(ssh_cmd, timeout=timeout + 10, shell=True)
        output = r.stdout.strip()
        if not output:
            ssh_cmd2 = (
                f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                f"-o ConnectTimeout={timeout} -o BatchMode=no "
                f"-p {port} {username}@{ip} {esc} 2>/dev/null"
            )
            r2 = stream_run(ssh_cmd2, timeout=timeout + 10, shell=True)
            output = r2.stdout.strip()

        if not output or "Permission denied" in output or "Connection refused" in output:
            metrics["error"] = output or "SSH连接失败"
            return metrics

        lines = output.split('\n')
        idx = 0
        if lines and lines[0]:
            metrics["hostname"] = lines[0]; idx = 1
        if len(lines) > idx and lines[idx].startswith("NAME="):
            metrics["os_release"] = lines[idx]; idx += 1
        if len(lines) > idx and lines[idx].startswith("VERSION="):
            metrics["os_release"] += " " + lines[idx]; idx += 1
        # kernel line
        if len(lines) > idx:
            if lines[idx].count('.') >= 1 and any(c.isdigit() for c in lines[idx][:8]):
                metrics["kernel"] = lines[idx]; idx += 1
        # uptime
        if len(lines) > idx and "up" in lines[idx].lower():
            metrics["uptime"] = lines[idx]; idx += 1
        # loadavg
        if len(lines) > idx:
            parts = lines[idx].split()
            if len(parts) >= 3:
                metrics["load_avg"] = f"{parts[0]} {parts[1]} {parts[2]}"
            idx += 1
        # memory
        for i in range(idx, min(idx + 3, len(lines))):
            line = lines[i]
            if "Mem:" in line:
                mem_parts = line.split()
                if len(mem_parts) >= 3:
                    try:
                        metrics["mem_total"] = mem_parts[1] + "MB"
                        metrics["mem_used"] = mem_parts[2] + "MB"
                        total = float(mem_parts[1])
                        used = float(mem_parts[2])
                        metrics["mem_percent"] = f"{used/total*100:.1f}%"
                    except:
                        pass
        # disk
        for i in range(idx, len(lines)):
            line = lines[i].strip()
            if line and line[0] == '/':
                parts = line.split()
                if len(parts) >= 5:
                    metrics["disk_info"] += f"{parts[0]}: {parts[2]}/{parts[1]} ({parts[4]}) | "

        # CPU 粗略估计
        if metrics["load_avg"]:
            try:
                load1 = float(metrics["load_avg"].split()[0])
                # 从输出中找 nproc 结果
                for line in lines:
                    if line.strip().isdigit():
                        cores = max(1, int(line.strip()))
                        cpu_pct = min(round(load1 / cores * 100), 100)
                        metrics["cpu_percent"] = f"{cpu_pct}% ({cores}核, load {load1})"
                        break
            except:
                pass

    except Exception as e:
        metrics["error"] = str(e)

    return metrics


# ── 端口服务解析 ──────────────────────────────────────────────
def _parse_nmap_text(nmap_output):
    hosts = {}
    current_ip = None
    for line in nmap_output.split('\n'):
        # -oG（greppable）输出：`Host: <ip> ()	Ports: 22/open/tcp//ssh//OpenSSH 9.6/, ...`
        # portscan.version_scan 用的就是 -oG。这里以前只认普通文本，
        # 于是 -sV 探到的端口与服务在报告里全被丢掉，只剩"(无)/(未识别)"。
        gm = re.match(r'Host: (\S+)\s*\([^)]*\)\s*Ports: (.*)', line)
        if gm:
            ip = gm.group(1)
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            entry = hosts.setdefault(ip, {"open_ports": [], "services": [], "os": ""})
            for port, state, svc, ver in portscan.services(gm.group(2)):
                if state != "open" or port in entry["open_ports"]:
                    continue
                entry["open_ports"].append(port)
                entry["services"].append(("%d/tcp %s %s" % (port, svc, ver)).strip())
            entry["open_ports"].sort()
            continue
        m = re.match(r'Nmap scan report for (.+)', line)
        if m:
            host_field = m.group(1).strip()
            # nmap 有两种写法："1.2.3.4" 和 "hostname (1.2.3.4)"。
            # 优先取括号里的 IP —— 否则按空格切分会拿到主机名（如 localhost），
            # 导致后面 online_ips 补录时同一个 IP 被登记成两台设备。
            ip_m = re.search(r'\((\d{1,3}(?:\.\d{1,3}){3})\)', host_field)
            if ip_m:
                current_ip = ip_m.group(1)
            elif ' ' in host_field:
                current_ip = host_field.split()[0]
            else:
                current_ip = host_field
            hosts[current_ip] = {"open_ports": [], "services": [], "os": ""}
            continue
        if current_ip and re.match(r'^\d+/', line):
            parts = line.split()
            port_proto = parts[0]
            state = parts[1] if len(parts) > 1 else ""
            service = parts[2] if len(parts) > 2 else ""
            version = " ".join(parts[3:]) if len(parts) > 3 else ""
            if state == "open":
                port_num = port_proto.split('/')[0]
                hosts[current_ip]["open_ports"].append(int(port_num))
                svc_str = service + (" " + version if version else "")
                hosts[current_ip]["services"].append(f"{port_proto} {svc_str}")
        if current_ip and "OS details:" in line:
            hosts[current_ip]["os"] = line.split("OS details:", 1)[-1].strip()
        if current_ip and "MAC Address:" in line:
            mac_m = re.search(r'MAC Address: ([\da-fA-F:]+)', line)
            if mac_m:
                hosts[current_ip]["mac"] = mac_m.group(1)
                ven_m = re.search(r'\((.+?)\)', line)
                if ven_m:
                    hosts[current_ip]["mac_vendor"] = ven_m.group(1)
    return hosts


# ── 空闲 IP ──────────────────────────────────────────────────
def _calc_free_ips(subnet_cidr, online_ips):
    try:
        net = ipaddress.ip_network(subnet_cidr, strict=False)
        online_set = set()
        for ip_str in online_ips:
            try:
                online_set.add(ipaddress.ip_address(ip_str.strip()))
            except:
                pass
        reserved = {net.network_address, net.broadcast_address}
        free = [str(ip) for ip in net.hosts() if ip not in online_set and ip not in reserved]
        return free
    except Exception:
        return []


# ── 排序 IP ──
def _sort_ip(ip_str):
    try:
        return tuple(map(int, ip_str.split('.')))
    except:
        return (999, 999, 999, 999)


# ═══════════════════════════════════════════════════════════════
#  工具入口
# ═══════════════════════════════════════════════════════════════

def _tool_network_inspect(_name, params):
    target = (params.get("target") or "").strip()
    if not target:
        # 以前这里把空目标一路跑到底，产出一份"报告 — （空标题）/ 在线 0 台"，
        # 看着像扫过了其实什么都没扫。参数名写错（例如传 targets）时尤其危险，
        # 所以这里直接判失败，让调用方/Agent 看见明确原因。
        return {"success": False,
                "output": "缺少 target 参数（目标网段，如 192.168.1.0/24 或单机 192.168.1.100）"}
    mode = params.get("mode", "quick")
    ssh_user = params.get("ssh_user")
    ssh_pass = params.get("ssh_pass")
    ssh_port = params.get("ssh_port", 22)
    try:
        result = _do_network_inspect(target, mode, ssh_user, ssh_pass, ssh_port)
        return {"success": True, "output": result}
    except Exception as e:
        import traceback
        return {"success": False, "output": f"[错误] {e}\n{traceback.format_exc()}"}

def _do_network_inspect(target, mode, ssh_user, ssh_pass, ssh_port):
    out = []
    out.append("═" * 60)
    out.append(f"  内网巡检报告 — {target}")
    out.append(f"  模式: {mode} | 时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    out.append("═" * 60)

    # Phase 1: 主机发现
    out.append("\n🔍 Phase 1/4: 主机发现 (nmap -sn)...")

    def _nmap_host_discovery(extra_args):
        """跑一次 nmap 主机发现，返回发现的在线 IP 列表。"""
        try:
            r = stream_run(
                ["nmap", "-sn", "-T4", "--max-retries", "1"] + extra_args + [target],
                timeout=180,
            )
        except subprocess.TimeoutExpired:
            return None
        found = []
        for line in (r.stdout + r.stderr).split('\n'):
            # 用正则从行内提取IPv4地址，避免DNS反查名称干扰
            if 'report for' not in line:
                continue
            ip_m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if not ip_m:
                continue
            ip_str = ip_m.group(1)
            try:
                ipaddress.ip_address(ip_str)
                found.append(ip_str)
            except ValueError:
                pass
        return found

    online_ips = _nmap_host_discovery([])
    if online_ips is None:
        return "═" * 40 + "\n[错误] 主机发现超时（>180s），请缩小网段范围"

    if not online_ips:
        # 很多主机（Windows、防火墙后的设备）不回 ICMP，只发 ping 会整段漏报。
        # 这里自动降级为 -Pn 重探一次，并在报告里写明探测方式，保证结果可解释。
        out.append("  ⚠️ ICMP 无响应，改用 -Pn 重新探测（目标可能屏蔽 ping）...")
        fallback = _nmap_host_discovery(["-Pn"])
        if fallback:
            online_ips = fallback
            out.append("  ↳ -Pn 探测结果：发现在线设备 %d 台" % len(fallback))

    out.append(f"  在线设备: {len(online_ips)} 台")

    # 空闲 IP
    free_ips = _calc_free_ips(target, online_ips)
    # 容量按"可分配主机数"算，别拿 num_addresses 硬减 2：
    # 单机目标（192.168.1.100 → /32）只有 1 个地址，减 2 会算出 -1，
    # 报告里出现"子网容量: -1"这种一眼假的数据。点对点 /31、/30 同理。
    try:
        net = ipaddress.ip_network(target, strict=False)
        total_ips = net.num_addresses - 2 if net.prefixlen <= 30 else net.num_addresses
        total_ips = max(0, total_ips)
    except Exception:
        total_ips = 0
    out.append(f"  子网容量: {total_ips} | 空闲IP: {len(free_ips)} 个")

    if mode == "free":
        out.append("\n📋 空闲IP列表 (前100个):")
        for ip in free_ips[:100]:
            out.append(f"  - {ip}")
        if len(free_ips) > 100:
            out.append(f"  ... 共 {len(free_ips)} 个")
        out.append("═" * 60)
        return "\n".join(out)

    if not online_ips:
        out.append("\n  未发现在线设备")
        return "\n".join(out)

    # Phase 2: 端口扫描 + OS 检测
    out.append("\n🔌 Phase 2/4: 全端口(1-65535)扫描 + OS检测...")
    # 端口范围走 portscan：先全端口发现，再只对发现的端口做 -sV。
    # 这里原来写死 --top-ports 100，没探到的端口在报告里根本不出现，属于默认漏报。
    # 注意：必须带 -Pn —— 主机已由 Phase 1 确认在线，
    # 再让 nmap 依赖 ICMP 探测会把屏蔽 ping 的主机（如 Windows）整台跳过。
    nmap_out = ""
    os_out = ""
    try:
        _found_ports, _discover_raw = portscan.discover(target)
        nmap_out = portscan.version_scan(target, _found_ports) or _discover_raw
        out.append("  全端口发现: %d 个开放端口%s"
                   % (len(_found_ports), ("（%s）" % ",".join(str(p) for p in _found_ports[:40]))
                      if _found_ports else ""))
    except Exception as exc:
        out.append("  ⚠️ 端口扫描失败: %s" % exc)

    try:
        os_r = stream_run(
            ["nmap", "-Pn", "-O", "--osscan-guess", "-T4",
             "--host-timeout", "90s", "--max-os-tries", "1", target],
            timeout=180,
        )
        os_out = os_r.stdout + os_r.stderr
    except:
        pass

    hosts = _parse_nmap_text(nmap_out + '\n' + os_out)
    for ip in online_ips:
        if ip not in hosts:
            hosts[ip] = {"open_ports": [], "services": [], "os": ""}

    # Phase 3: 设备分类
    out.append("\n🏷️  Phase 3/4: 设备分类详情")
    categories = {"安全设备": [], "网络设备": [], "服务器": [], "工作站": [], "物联网设备": [], "其他": []}

    for ip in sorted(hosts.keys(), key=_sort_ip):
        info = hosts[ip]
        mac = info.get("mac", "")
        vendor = info.get("mac_vendor", "") or _lookup_mac_vendor(mac)
        category, confidence = _classify_device(
            vendor, info.get("open_ports", []),
            info.get("os", ""), info.get("services", [])
        )
        port_str = ",".join(str(p) for p in info.get("open_ports", [])[:15])
        svc_str = "; ".join(info.get("services", [])[:10])
        os_str = info.get("os", "")[:60]

        detail = (
            f"\n  📌 {ip:<16} {vendor[:28]:<28} [{category}] {confidence}%"
            f"\n     OS: {os_str or '未知'}"
            f"\n     端口: {port_str or '(无)'}"
            f"\n     服务: {svc_str or '(未识别)'}"
        )
        out.append(detail)
        categories[category].append({"ip": ip, "vendor": vendor, "ports": info.get("open_ports", []),
                                      "services": info.get("services", []), "os": os_str})

    # 分类汇总
    out.append("\n📊 设备分类汇总:")
    for cat, devs in categories.items():
        if devs:
            ips = ", ".join(d["ip"] for d in devs)
            out.append(f"  [{cat}] {len(devs)} 台: {ips}")

    # Phase 4: SSH 深度巡检
    if mode == "full" and ssh_user and ssh_pass:
        out.append("\n🖥️  Phase 4/4: SSH 深度巡检 (系统资源)")
        for cat, devs in categories.items():
            for dev in devs:
                ip = dev["ip"]
                out.append(f"\n  ── {ip} ──")
                metrics = _ssh_collect(ip, ssh_user, ssh_pass, ssh_port)
                if metrics["error"]:
                    out.append(f"  ❌ SSH失败: {metrics['error'][:100]}")
                else:
                    out.append(f"  主机名: {metrics['hostname']}")
                    out.append(f"  系统: {metrics['os_release'][:80]}")
                    out.append(f"  内核: {metrics['kernel']}")
                    out.append(f"  运行: {metrics['uptime']}")
                    if metrics['cpu_percent']:
                        out.append(f"  CPU: {metrics['cpu_percent']}")
                    if metrics['mem_percent']:
                        out.append(f"  内存: {metrics['mem_used']}/{metrics['mem_total']} ({metrics['mem_percent']})")
                    if metrics['load_avg']:
                        out.append(f"  负载: {metrics['load_avg']}")
                    if metrics['disk_info']:
                        out.append(f"  磁盘: {metrics['disk_info'][:200]}")

    # 空闲 IP 节选
    if mode != "free" and free_ips:
        preview = ", ".join(free_ips[:20])
        out.append(f"\n📋 空闲IP ({len(free_ips)} 个, 前20): {preview}")

    out.append("\n" + "═" * 60)
    out.append(f"  ✅ 巡检完成 | 在线 {len(online_ips)} 台 | 空闲IP {len(free_ips)} 个")
    out.append("═" * 60)
    return "\n".join(out)


def _tool_free_ip_scan(_name, params):
    try:
        result = _do_network_inspect(params.get("target", ""), "free", None, None, 22)
        return {"success": True, "output": result}
    except Exception as e:
        import traceback
        return {"success": False, "output": f"[错误] {e}\n{traceback.format_exc()}"}


# ═══════════════════════════════════════════════════════════════
#  插件注册
# ═══════════════════════════════════════════════════════════════
def _register(reg):
    reg({
        "name": "network_inspect",
        "description": "内网巡检 — 发现在线设备、识别设备类型（安全/网络/服务器/工作站/物联网）、开放端口/服务、MAC厂商、空闲IP。支持SSH深度巡检采集CPU/内存/磁盘/负载。模式: free=仅空闲IP, quick=端口+分类, full=全部+SSH系统指标",
        "inputSchema": {"type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标网段(如 192.168.1.0/24)"},
                "mode": {"type": "string", "description": "free/quick/full", "default": "quick",
                         "enum": ["free", "quick", "full"]},
                "ssh_user": {"type": "string", "description": "SSH用户名(mode=full时必填)", "default": None},
                "ssh_pass": {"type": "string", "description": "SSH密码", "default": None},
                "ssh_port": {"type": "integer", "description": "SSH端口", "default": 22}
            },
            "required": ["target"]},
    })(_tool_network_inspect)

    reg({
        "name": "free_ip_scan",
        "description": "快速空闲IP扫描 — 只扫描子网中未被使用的IP地址",
        "inputSchema": {"type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标网段(如 192.168.1.0/24)"}
            },
            "required": ["target"]},
    })(_tool_free_ip_scan)
