#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
服务识别工具 — 根据IP:端口识别对应的服务名称和版本号
输入: IP:端口 列表
输出: 每个端口的服务名+版本
"""
import subprocess, re, ipaddress

import portscan

from utils import stream_run

def _run_nmap(ip, ports, timeout=60):
    """用nmap -sV快速识别指定端口"""
    try:
        # -Pn：有些主机不回 ICMP，默认主机发现会直接判"down"整台漏报。
        # 不再用 --min-rate 5000：把速率顶满会被对端的防扫描策略判成 filtered，
        # 实测同一台机器在激进参数下会从"22/80 open"变成"全部 filtered"。
        r = stream_run(
            ["nmap", "-sT", "-sV", "-Pn", "--version-intensity", "2", "-p", ports, "-T4",
             "--max-retries", "3", "--host-timeout", "60s",
             "-oG", "-", ip],
            timeout=timeout,
        )
        return r.stdout
    except subprocess.TimeoutExpired:
        return ""
    except Exception as e:
        return str(e)


def _parse_nmap_grepable(output):
    """解析nmap -oG格式输出，返回 [{port, state, service, version}]。

    state 必须一起带出来：grepable 里 filtered 的端口同样会带上服务名
    （例如 `23/filtered/tcp//telnet///`），只按"有服务名"取会导致
    被防火墙挡住的端口被当成开放服务报出去。
    """
    results = []
    for line in output.split("\n"):
        line = line.strip()
        if not line.startswith("Host:"):
            continue
        # Host: 192.168.1.3 (192.168.1.3)  Ports: 22/open/tcp//ssh//OpenSSH 8.9p1/, 80/open/tcp//http//nginx 1.24.0/
        port_match = re.findall(r'(\d+)/(\w+)/(tcp|udp)//([^/]*)//([^/]*)', line)
        if port_match:
            for port, state, proto, svc, ver in port_match:
                # 清理版本号
                ver = ver.strip().replace("'", "")
                # nmap 多候选会写成 `ssl|https-alt`：竖线会多切出一列，
                # 下游按 "IP|端口|服务|版本" 读时会错位，只留第一个候选。
                svc = svc.split("|")[0].strip()
                ver = ver.split("|")[0].strip()
                results.append({
                    "port": port,
                    "state": state,
                    "proto": proto,
                    "service": svc if svc else "unknown",
                    "version": ver if ver and ver != svc else ""
                })
    return results


def _quick_guess(port):
    """端口→服务名快速猜测（当nmap没结果时备用）"""
    common = {
        "21": "ftp", "22": "ssh", "23": "telnet", "25": "smtp",
        "53": "dns", "80": "http", "110": "pop3", "135": "epmap",
        "139": "netbios-ssn", "143": "imap", "161": "snmp",
        "389": "ldap", "443": "https", "445": "microsoft-ds",
        "554": "rtsp", "993": "imaps", "995": "pop3s",
        "1433": "ms-sql-s", "1521": "oracle", "2049": "nfs",
        "2375": "docker", "3306": "mysql", "3389": "ms-wbt-server",
        "5432": "postgresql", "5601": "kibana", "5672": "rabbitmq",
        "5900": "vnc", "5901": "vnc", "5984": "couchdb",
        "5985": "winrm-http", "5986": "winrm-https",
        "6379": "redis", "6443": "https-alt",
        "7001": "weblogic", "8080": "http-proxy", "8081": "http-alt",
        "8443": "https-alt", "8888": "http-alt",
        "9000": "http-alt", "9090": "http-alt",
        "9200": "elasticsearch", "9300": "elasticsearch",
        "9418": "git", "9999": "http-alt",
        "10000": "webmin", "11211": "memcache",
        "15672": "rabbitmq-admin", "27017": "mongod",
        "37777": "rtsp-alt", "50000": "db2",
    }
    return common.get(port, "unknown")


def _register(reg):
    reg({
        "name": "service_identify",
        "description": "快速识别IP:端口对应的服务名称和版本号（如nginx、apache、mysql、ssh、rdp等）。批量自动按IP分组扫描。输入: 每行一个 IP:端口 或 空格/逗号分隔",
        "inputSchema": {"type": "object",
                      "properties": {
    "targets": {
        "type": "string",
        "description": "IP:端口列表。每行一个IP:端口，或空格分隔。\n示例:\n192.168.1.3:334\n192.168.1.3:888\n192.168.1.3:22 80 443\n或: 192.168.1.3:22,80,443"
    }
},
                      "required": ["targets"]},
    })(tool_service_identify)


# 裸 IP 输入时默认探测的常见服务端口
def tool_service_identify(name, params):
    raw = params.get("target", "").strip()
    if not raw:
        raw = params.get("targets", "").strip()
    if not raw:
        return {"success": False, "returncode": -1, "output": "请提供目标（IP:端口 或 IP）"}
    
    # 解析输入 → {ip: [port1, port2, ...]}
    ip_ports = {}
    
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        
        # 格式1: 192.168.1.3:22,8001,18789 或 192.168.1.3:22
        m = re.findall(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
        if m:
            for ip, port in m:
                if ip not in ip_ports:
                    ip_ports[ip] = set()
                ip_ports[ip].add(port)
            # 同一行以逗号分隔的纯数字端口也用第一个IP
            _fip = m[0][0]
            for part in line.replace(",", " ").split():
                part = part.strip()
                if part.isdigit() and _fip:
                    ip_ports[_fip].add(part)
            continue
        
        # 格式2: 192.168.1.3 22 80 443
        parts = line.split()
        if len(parts) >= 2:
            ip = parts[0]
            try:
                ipaddress.IPv4Address(ip)
                if ip not in ip_ports:
                    ip_ports[ip] = set()
                for p in parts[1:]:
                    p = p.strip()
                    if p.isdigit():
                        ip_ports[ip].add(p)
                continue
            except:
                pass
        
        # 格式3: 192.168.1.3:22,80,443 或 192.168.1.3:22,8001,18789
        # 找行里第一个IP:端口组合，之后纯数字的端口都用同个IP
        _last_ip = None
        for part in line.replace(",", " ").split():
            part = part.strip()
            m = re.match(r'(\d+\.\d+\.\d+\.\d+):(\d+)', part)
            if m:
                ip, port = m.group(1), m.group(2)
                _last_ip = ip
                if ip not in ip_ports:
                    ip_ports[ip] = set()
                ip_ports[ip].add(port)
            elif part.isdigit() and _last_ip:
                if _last_ip not in ip_ports:
                    ip_ports[_last_ip] = set()
                ip_ports[_last_ip].add(part)
    
    # 只给了裸 IP（没给端口）时做全端口发现：调用方通常就是想知道"这台机器上跑的是
    # 什么服务"。这里原本补的是一张 24 个端口的常用表，没探到的端口在结果里根本不
    # 出现——安全工具自己制造的漏报最难查，所以改成 1-65535 全扫一遍。
    if not ip_ports:
        discover_error = ""
        for ip in re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', raw):
            try:
                found, _discover_raw = portscan.discover(ip, host_timeout=60, timeout=900)
                ip_ports[ip] = set(str(p) for p in found)
            except Exception as exc:
                # 扫描器没跑起来不能当成"没有开放端口"：两件事分开说
                discover_error = "%s: %s" % (ip, exc)
        if discover_error:
            return {"success": False, "returncode": -1,
                    "output": "全端口发现失败（不是\"没有开放端口\"）：%s" % discover_error}

    if not ip_ports:
        # 解析不出目标时必须报失败：返回 success=True 会让上游把它当成
        # "扫描完成、无发现"，把一条格式错误伪装成干净的结论。
        return {"success": False, "returncode": -1,
                "output": "无法解析输入，请提供格式: 192.168.1.3:334 或 192.168.1.3 22 80 443"}
    
    lines = []
    all_services = []

    for ip, ports in sorted(ip_ports.items()):
        if not ports:
            lines.append("# %s: 1-65535 全端口未发现开放端口" % ip)
            continue
        ports_str = ",".join(sorted(ports, key=int))
        nmap_out = _run_nmap(ip, ports_str, 90)
        if not nmap_out.strip():
            # "nmap 没跑起来" 与 "端口都没开" 是两回事，必须分开报
            lines.append("# %s: nmap 未返回结果（检查 nmap 是否可用、目标是否可达）" % ip)
            continue
        parsed = _parse_nmap_grepable(nmap_out)
        # 只输出 nmap 判定 open 的端口，并且只信任 nmap 给出的服务名。
        # 之前把 filtered 也当服务输出、又对没探到的端口用端口名表"猜"一个服务名，
        # 结果一台只开 22/80 的主机会被写成同时还开着 23/telnet、3306/mysql、
        # 6379/redis —— 安全工具自己制造误报，比漏报更伤结论可信度。
        opened, filtered = {}, 0
        for item in parsed:
            if item["state"] == "open":
                opened[item["port"]] = item
            else:
                filtered += 1
        for port in sorted(opened, key=int):
            item = opened[port]
            all_services.append({"ip": ip, "port": port,
                                 "service": item["service"],
                                 "version": item["version"] or _grab_version_hint(ip, port)})
        lines.append("# %s: 探测 %d 个端口 → 开放 %d 个%s；其余 %d 个为 filtered/closed，未计入"
                     % (ip, len(ports), len(opened),
                        ("：" + ",".join(sorted(opened, key=int))) if opened else "（无）",
                        max(0, len(ports) - len(opened))))

    for svc in all_services:
        ver = svc.get("version", "") or "-"
        lines.append(f"{svc['ip']}|{svc['port']}|{svc['service']}|{ver}")

    return {"success": True, "returncode": 0, "output": "\n".join(lines)}

def _grab_version_hint(ip, port):
    """nmap 没探到版本号时不做猜测，返回空串由调用方按"未识别版本"处理。"""
    return ""
