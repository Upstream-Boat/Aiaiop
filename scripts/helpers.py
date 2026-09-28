#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""共享实现层 —— 各工具文件里的实际逻辑基本都在这儿。

多数函数是从生产服务单体里搬过来的，搬运时只做了必需改动（其中 ip_usage_report
里的 scan_level 原本写成了未定义变量 deep，detailed_os_scan=True 一进来必炸，已修）。
包含: exploit_search / dirb_python / image_stego_detect / fingerprint_web_service /
      identify_device_type / ip_usage_report / nmap_vuln_scan_fast / check_*_policy /
      compliance_report / 报告格式化等。
"""

import time

import portscan
from utils import run_cmd  # noqa: F401

def _searchsploit_lookup(keyword, limit=30):
    """用本地 searchsploit 按标题/CVE 检索（覆盖全量 Exploit-DB）。不可用时返回 None。"""
    import json as _json
    import os as _os
    import shutil as _shutil
    import subprocess as _sp

    from config import SEARCHSPLOIT_BIN
    exe = SEARCHSPLOIT_BIN or _shutil.which("searchsploit")
    if not _os.path.exists(exe):
        return None
    try:
        r = _sp.run([exe, "-j", keyword], capture_output=True, text=True, timeout=90)
    except Exception:
        return None
    raw = r.stdout or ""
    start = raw.find("{")
    if start < 0:
        return None
    try:
        data = _json.loads(raw[start:])
    except Exception:
        return None
    rows = data.get("RESULTS_EXPLOIT") or []
    if not rows:
        return None
    lines = ["=== Exploit-DB '%s' (%d 条, 本地 searchsploit) ===" % (keyword, len(rows))]
    for item in rows[:limit]:
        codes = (item.get("Codes") or "").strip()
        tail = "  [%s]" % codes if codes else ""
        verified = " ✅" if str(item.get("Verified", "")) == "1" else ""
        lines.append("  %s%s (EDB-%s, %s)%s\n    %s" % (
            item.get("Title", ""), verified, item.get("EDB-ID", ""),
            item.get("Platform", ""), tail, item.get("Path", "")))
    if len(rows) > limit:
        lines.append("  … 另有 %d 条（可加更精确关键词）" % (len(rows) - limit))
    return "\n".join(lines)


def exploit_search(keyword):
    import os, re, subprocess
    # 如果输入包含换行或看起来像IP列表，自动提取第一个IP并先扫端口
    kw = keyword.strip()
    ip_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    m = re.search(ip_pattern, kw)
    if m:
        ip = m.group(1)
        # 先扫端口拿服务版本
        try:
            # 端口范围走 portscan（1-65535）：只搜 --top-ports 100 里的服务，
            # 非标端口上的组件（比如 8443 / 9200）就永远搜不到对应的 EXP。
            _ports, _ = portscan.discover(ip, host_timeout=60, timeout=300)
            scan_out = portscan.version_scan(ip, _ports, timeout=300)
            svcs = []
            for _port, _state, _svc, _ver in portscan.services(scan_out or _):
                if _state == "open":
                    svcs.append(("%s %s" % (_svc, _ver)).strip())
            if not svcs:
                return "目标 %s 全端口(1-65535)未发现开放端口或服务，无法搜索EXP" % ip
            # 全端口扫出来会有十几条服务，拼成一个长关键词去搜等于什么都没搜
            # （searchsploit 多个词之间是 AND，"OpenSSH 9.6" 这种连版本一起搜命中 0 条，
            # 只搜 "OpenSSH" 才有 29 条）。所以逐服务检索：优先用版本里的产品名，
            # 没有版本就退回服务名，命中即止。
            def _terms(item):
                svc, _, ver = item.partition(" ")
                svc = svc.strip()
                prod = ver.split()[0].strip("()") if ver.split() else ""
                out = []
                if len(prod) >= 3 and prod[0].isalpha():
                    out.append(prod)
                if svc and svc != "unknown" and svc not in out:
                    out.append(svc)
                return out

            blocks, tried = [], set()
            for item in svcs:
                if len(blocks) >= 5:
                    break
                for term in _terms(item):
                    if term in tried:
                        continue
                    tried.add(term)
                    hit = _searchsploit_lookup(term, limit=10)
                    if hit:
                        # 命中上万条说明这个词太泛（"ssl" 这种），塞进来只会把
                        # 真正相关的那几条淹掉，直接跳过
                        m = re.search(r"\((\d+) 条", hit)
                        if m and int(m.group(1)) > 1000:
                            continue
                        blocks.append(hit)
                        break
            if blocks:
                return ("目标 %s 全端口(1-65535)开放: %s\n\n" % (ip, ", ".join(svcs))
                        + "\n\n".join(blocks))
            keyword = " ".join(svcs)
        except Exception as exc:
            return "扫描目标 %s 失败：%s" % (ip, exc)
    
    # 主路径：调用本地 searchsploit（按标题/CVE 检索，覆盖全量数据）
    hit = _searchsploit_lookup(keyword)
    if hit is not None:
        return hit

    # 回退：searchsploit 不可用时，按路径/文件名遍历本地库
    from config import EXPLOIT_DB_EXPLOITS
    edir = EXPLOIT_DB_EXPLOITS
    if not edir or not os.path.isdir(edir):
        return "Exploit-DB 本地库不可用（期望目录 %s）" % edir
    kw = keyword.lower()
    results = []
    for root, dirs, files in os.walk(edir):
        for f in files:
            if kw in (root+"/"+f).lower() or kw in f.lower():
                full = os.path.join(root, f)
                rel = full.replace(edir+"/", "")
                desc = "(%dB)" % os.path.getsize(full)
                try:
                    with open(full,'r',errors='ignore') as fp:
                        first = fp.read(200).split('\n')[0][:150]
                        if first: desc = first
                except: pass
                results.append("  %s\n -> %s" % (rel, desc))
                if len(results) >= 30: break
        if len(results) >= 30: break
    if not results: return "未找到 '%s' 的exploit" % keyword
    return "=== Exploit-DB '%s' (%d条) ===\n" % (keyword, len(results)) + "\n".join(results)

def dirb_python(url, wordlist="common"):
    import requests
    dicts = {"common": ["admin","login","api","backup","config","uploads","test",
        "robots.txt",".git/config",".env","phpmyadmin","wp-admin","manager","console","dashboard"],
        "small": ["admin","login","api","backup","config",".git/config",".env"],
        "big": ["admin","login","api","backup","config","db","download","uploads",
            "tmp","test","assets","css","js","images","includes","lib","modules",
            "plugins","static","vendor","public","private","robots.txt","sitemap.xml",
            ".git/config",".env","composer.json","Dockerfile","nginx.conf","web.config",
            "phpmyadmin","adminer.php","actuator","swagger-ui.html","docs","graphql"]}
    dirs = dicts.get(wordlist, dicts["common"])
    url = url.rstrip("/")
    results = []
    for d in dirs:
        try:
            r = requests.get(url+"/"+d, timeout=5, allow_redirects=False,
                            headers={"User-Agent":"Mozilla/5.0"})
            if r.status_code < 400 or r.status_code in (401,403):
                results.append("[%d] /%s (%dB)" % (r.status_code, d, len(r.content)))
        except: pass
    if not results: return "未发现可访问目录"
    return "=== 目录爆破 %d个 ===\n" % len(results) + "\n".join(results[:100])

OUI_CODES = {
    '00:05:5D': 'Sangfor','00:05:69': 'VMware','00:08:9B': 'Synology','00:0A:E3': 'Acer',
    '00:0C:29': 'VMware','00:0C:43': 'Ralink/Mtk','00:11:32': 'QNAP','00:15:5D': 'Hyper-V',
    '00:1A:4B': 'Juniper','00:1A:79': 'Realtek','00:1A:A0': 'Dell','00:1A:A1': 'Cisco',
    '00:1B:3F': 'Dahua','00:1B:77': 'Sangfor','00:1C:42': 'Parallels','00:1C:DF': 'Netgear',
    '00:1E:66': 'Ubiquiti','00:1E:8C': 'Dell','00:22:6D': 'QNAP','00:23:AE': 'Dell',
    '00:25:90': 'Lenovo','00:26:18': 'ASUS','00:26:C6': 'Apple','00:50:56': 'VMware',
    '00:50:8B': 'HP','00:50:B6': 'QEMU','00:80:C7': 'H3C','04:B3:B6': 'Cisco',
    '04:F0:21': 'Apple','08:00:27': 'Oracle VirtualBox','08:10:76': 'Hikvision',
    '08:62:66': 'MikroTik','0C:37:26': 'Huawei Tech','0C:7D:7C': 'Hikvision',
    '14:3D:12': 'TP-Link','14:7D:DA': 'Apple','18:31:BF': 'QNAP','18:67:B0': 'H3C',
    '1C:B7:2C': 'ASUS','24:3C:20': 'Hewlett Packard','24:4B:FE': 'Cisco',
    '24:AB:81': 'Acer','28:32:C5': 'Tenda','28:80:23': 'Ruijie','2C:54:CF': 'Dell',
    '30:DE:C8': 'Dahua','34:80:B3': 'Lenovo','38:F9:D3': 'Xiaomi','3C:07:54': 'Apple',
    '40:1F:0C': 'Hikvision','44:32:C2': 'ZTE','44:D9:E7': 'Ubiquiti','48:7D:2E': 'Huawei',
    '4C:24:98': 'Dell','4C:5F:70': 'MikroTik','50:C7:BF': 'TP-Link','52:54:00': 'QEMU/KVM',
    '54:E0:32': 'Lenovo','64:5D:86': 'Hikvision','64:9E:F3': 'Huawei','64:D1:54': 'MikroTik',
    '68:7A:B0': 'Huawei','68:AB:1E': 'Apple','6C:59:0E': 'Ruijie','70:0F:6A': 'Aruba/HP',
    '70:3A:CB': 'Hikvision','74:23:44': 'Ruijie','74:40:BB': 'Xiaomi','74:83:C2': 'Ubiquiti',
    '84:38:38': 'Huawei','94:65:2D': 'Xiaomi','9C:6B:00': 'ASUS','A0:0B:BA': 'Huawei',
    'A0:D3:C1': 'Apple','AC:1F:74': 'Huawei Tech','AC:5F:F4': 'Samsung','B0:48:7A': 'Netgear',
    'B0:C5:54': 'TP-Link','B8:17:C2': 'Apple','B8:88:E3': 'Apple','BC:5F:F4': 'Samsung',
    'BC:F5:AC': 'Xiaomi','BC:F6:85': 'ZTE','C0:25:A5': 'Wavlink','C4:04:15': 'Netgear',
    'C8:3A:35': 'Intel','C8:5B:76': 'Dell','CC:08:9B': 'Mercusys','D0:03:4B': 'ASUS',
    'D0:5F:B8': 'Ruijie','D4:6E:0E': 'Xiaomi','DC:0C:5C': 'Xiaomi','DC:7B:94': 'Cisco',
    'E0:2D:E6': 'Huawei','E0:50:8B': 'Synology','E4:F0:42': 'Xiaomi','E8:DE:27': 'TP-Link',
    'EC:08:6B': 'TP-Link','EC:26:CA': 'Tenda',
    'C0:A4:76': 'Ruijie',
    '6C:1F:F7': 'UGREEN',
    '14:61:A4': 'Honor',
    'FE:FC:FE': '虚拟化/网关',
    'FE:FD:FE': '虚拟化/网关',
    'FE:00:00': '虚拟机',
    'FE:FF:FF': '虚拟机',
    '90:09:DF': 'Intel',
    '78:DF:72': 'Xiaomi-Imilab',
    '74:3A:F4': 'Intel',
    '70:08:10': 'Intel',
    '30:F6:EF': 'Intel',
    'B0:BE:83': 'Apple',
}

def fingerprint_web_service(ip, port):
    """对Web端口做HTTP指纹识别，返回应用名称和备注"""
    import urllib.request
    app_name = ''
    note = ''
    scheme = 'https' if port in (443, 8443) else 'http'
    url = '%s://%s:%d/' % (scheme, ip, port)
    try:
        req = urllib.request.Request(url, headers={'User-Agent':'Mozilla/5.0','Accept':'text/html,*/*'})
        if scheme == 'http':
            r = urllib.request.urlopen(req, timeout=6)
        else:
            ctx = __import__('ssl').create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = __import__('ssl').CERT_NONE
            r = urllib.request.urlopen(req, context=ctx, timeout=6)
        html = r.read(5000).decode('utf-8','ignore')
        server_header = r.headers.get('Server','')
        location = r.headers.get('Location','')
        title = ''
        import re as _r
        m = _r.search(r'<title[^>]*>(.*?)</title>', html, _r.I|_r.S)
        if m:
            title = m.group(1).strip()[:60]
        
        # === OA/企业应用 ===
        if '/seeyon/' in location or '/seeyon' in html:
            app_name = 'Seeyon(致远OA)'
            note = '致远互联OA系统'
        elif 'SY8045' in server_header:
            app_name = 'Seeyon(致远OA)'
            note = '致远OA专用Web服务器'
        elif 'Ruijie' in server_header:
            app_name = 'Ruijie(锐捷)'
            note = '锐捷网络设备'
        
        # === NAS/存储 ===
        elif 'UGREEN' in server_header or 'UGREEN' in html or '绿联' in html:
            app_name = 'UGREEN NAS'
            note = '绿联NAS管理界面'
        elif title and ('飞牛' in title or 'fnOS' in html or 'fnos' in html.lower()):
            app_name = '飞牛fnOS'
            note = '飞牛私有云'
        elif 'QNAP' in html or 'QTS' in html:
            app_name = 'QNAP QTS'
            note = '威联通NAS'
        
        # === 面板/管理工具 ===
        elif 'Sun-Panel' in html or 'Sun-Panel' == title:
            app_name = 'Sun-Panel'
            note = '导航面板/书签'
        elif 'Seeyon' in server_header or '致远' in html:
            app_name = 'Seeyon(致远OA)'
            note = '致远OA'
        
        # === 通用 ===
        if not app_name and server_header:
            app_name = server_header.split('/')[0]
        
        if title and not app_name:
            note = title[:40]
        elif not app_name and not note:
            note = 'Web服务'
            
    except Exception:
        note = ''
    return app_name, note

def identify_device_type(ip, mac, open_ports, os_guess):
    """设备类型识别 v2.1 - 稳定版
    基于端口特征+MAC OUI+OS猜测综合判断
    保持与原始版本兼容，只优化明显误判
    
    优先级:
    1. OS猜测（如果可信）
    2. MAC OUI品牌（手机/网络设备/办公PC）
    3. 端口组合（邮件/FTP/多端口=服务器, 单Web=网络设备）
    4. 0端口 → MAC判断
    """
    is_virtual_mac = bool(mac and mac.upper().startswith(('FE:FC:FE','FE:FD:FE','FE:FE:')))
    port_set = set(open_ports)
    mac_upper = mac.upper()[:8] if mac else ''
    
    # === MAC品牌特征表 ===
    phone_mac_prefixes = {'38:F9:D3','94:65:2D','E4:F0:42','74:40:BB','BC:F5:AC',
                         'D4:6E:0E','DC:0C:5C','AC:5F:F4','BC:5F:F4','68:7A:B0',
                         '64:9E:F3','14:61:A4','78:DF:72','A0:53:BD'}
    enterprise_mac_prefixes = {'90:09:DF','70:08:10','74:3A:F4','34:80:B3','54:E0:32',
                               '00:1E:8C','00:23:AE','4C:24:98','2C:54:CF',
                               '00:50:56','00:0C:29','00:1C:42','18:66:DA'}
    known_network_ouis = {'C0:A4:76','D0:5F:B8','50:C7:BF','EC:08:6B','B0:C5:54',
                         'E8:DE:27','EC:26:CA','28:32:C5','D0:03:4B','1C:B7:2C',
                         'C0:25:A5','6C:59:0E','74:23:44','28:80:23','14:3D:12',
                         'E0:63:4D','A8:15:4D','F4:EC:38','18:92:2C','DC:FE:18',
                         '10:7B:44', 'A8:4A:35', 'A0:8C:FD', 'B0:4E:26', '20:47:DA'}
    
    is_phone_mac = mac_upper in phone_mac_prefixes
    is_enterprise_mac = mac_upper in enterprise_mac_prefixes
    is_known_network = mac_upper in known_network_ouis
    
    # === OS猜测优先 ===
    if os_guess:
        ol = os_guess.lower()
        if any(k in ol for k in ['router','switch','ap','access point','bridge','gateway','firewall','vpn']):
            return '\U0001f4e1 网络设备'
        if any(k in ol for k in ['linux','centos','ubuntu','debian','red hat']):
            if len(port_set) >= 2: return '\U0001f5a5 \u670d务器'
            if 22 in port_set: return '\U0001f5a5 \u670d务器'
        if any(k in ol for k in ['windows','microsoft']):
            if 3389 in port_set: return '\U0001f4bb 办公PC'
            if len(port_set) > 3: return '\U0001f5a5 \u670d务器'
        if any(k in ol for k in ['android','ios','iphone','ipad']):
            return '\U0001f4f1 \u624b机'
    
    # === 端口特征优先 ===
    # 邮件/数据库/文件共享 → 服务器
    if 25 in port_set or 110 in port_set:
        return '\U0001f5a5 \u670d务器'
    db_ports = {3306, 5432, 27017, 6379, 1433, 1521}
    if db_ports & port_set:
        return '\U0001f5a5 \u670d务器'
    if 139 in port_set or 445 in port_set:
        return '\U0001f5a5 \u670d务器'
    if 21 in port_set:
        return '\U0001f5a5 \u670d务器'
    
    # 3+ 端口 → 服务器
    if len(port_set) >= 3:
        return '\U0001f5a5 \u670d务器'
    
    # 2端口 → 分情况
    if len(port_set) == 2:
        if 80 in port_set and 443 in port_set:
            if is_known_network or is_virtual_mac:
                return '\U0001f4e1 网络设备'
            return '\U0001f5a5 \u670d务器'
        return '\U0001f5a5 \u670d务器'
    
    # 1端口
    if len(port_set) == 1:
        p = list(port_set)[0]
        if p == 3389:
            return '\U0001f4bb 办公PC'
        if p in (80, 443, 8080, 8443):
            if is_known_network or is_virtual_mac:
                return '\U0001f4e1 网络设备'
            return '\U0001f5a5 \u670d务器'
        if p == 22:
            return '\U0001f5a5 \u670d务器'
        return '\U0001f5a5 \u670d务器'
    
    # === 0端口 ===
    if is_phone_mac:
        return '\U0001f4f1 \u624b机'
    if is_enterprise_mac:
        return '\U0001f4bb 办公PC'
    if is_known_network:
        return '\U0001f4e1 网络设备'
    if is_virtual_mac:
        return '\U0001f4f1 \u624b机'
    return '\U0001f4f1 \u624b机'

def ip_usage_report(target=None, detailed_os_scan=False):
    import re, subprocess
    # Auto-detect network if no target specified
    if not target or target.strip() == '':
        try:
            import re as _re2
            r = subprocess.run("ip route show | grep -v default", shell=True, capture_output=True, text=True, timeout=5)
            all_routes = _re2.findall(r'\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+', r.stdout)
            # Filter out Docker bridges, keep all real network segments
            real_nets = [net for net in all_routes if not ('172.17.' in net or '172.18.' in net)]
            if len(real_nets) > 1:
                return f"[INFO] 检测到多个网段: {', '.join(real_nets)}\n请指定target参数选择要扫描的网段，例如: ip_usage_report(target='{real_nets[0]}')"
            auto_target = real_nets[0] if real_nets else (all_routes[0] if all_routes else '')
        except:
            auto_target = ''
        if not auto_target:
            try:
                r = subprocess.run("hostname -I | awk '{print $1}'", shell=True, capture_output=True, text=True, timeout=5)
                ip = r.stdout.strip().split('.')[:3] + ['0']
                auto_target = '.'.join(ip) + '/24'
            except:
                auto_target = '192.168.1.0/24'
        target = auto_target
    target = target.strip()
    if '/' not in target:
        parts = target.split('.')
        if len(parts) == 4:
            target = target.rstrip('0') + '0/24' if target.count('.') == 3 else target + '/24'
        else:
            return f"[ERROR] 无法识别网段: {target}"
    
    # Calculate total IPs to decide scan strategy
    prefix = int(target.split('/')[1])
    total_ips = 2 ** (32 - prefix)
    # For large subnets, auto-select appropriate scan level
    auto_quick = (total_ips > 4096)  # /20 or larger → use ping-only by default
    scan_level = 'quick' if detailed_os_scan else ('ping' if auto_quick else 'quick')
    if detailed_os_scan:
        scan_level = 'deep'  # backward compat: detailed_os_scan=True → 走深扫
    
    lines = []
    lines.append("=" * 60)
    lines.append("  IP网段使用情况报告: " + target)
    lines.append("=" * 60)
    
    # Step 1: Ping scan
    lines.append("\n[1/3] 扫描在线设备...")
    if total_ips > 65536:
        # Very large subnet - use masscan-style approach
        lines.append(f"  网段较大({total_ips}个IP)，采用高速扫描...")
        r = subprocess.run(f"nmap -sn -T5 --max-retries 1 --min-hostgroup 256 {target}", shell=True, capture_output=True, text=True, timeout=300)
    else:
        r = subprocess.run(f"nmap -sn -T5 --max-retries 1 {target}", shell=True, capture_output=True, text=True, timeout=120)
    output = r.stdout + r.stderr
    
    live_ips = []
    import re as _re
    for line in output.split('\n'):
        if 'report for' in line:
            m = _re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if m:
                live_ips.append(m.group(1))
            else:
                ip = line.split('report for')[-1].strip()
                live_ips.append(ip)
    
    host_count = 0
    for line in output.split('\n'):
        if 'Host is up' in line:
            host_count += 1
    if host_count > 0 and len(live_ips) > host_count:
        live_ips = live_ips[:host_count]
    elif host_count > len(live_ips):
        host_count = len(live_ips)
    
    lines.append(f"  发现 {host_count} 个在线设备")
    
    if scan_level == 'ping':
        # Ping-only: just list IPs, no port/OS scan
        lines.append("\n[2/3] 获取MAC地址信息(仅Ping模式-部分设备有)...")
        r2 = subprocess.run("ip neigh show 2>/dev/null || arp -a 2>/dev/null", shell=True, capture_output=True, text=True, timeout=10)
        arp_table = r2.stdout
        mac_map = {}
        for line in arp_table.split('\n'):
            parts = line.split()
            for i, p in enumerate(parts):
                if p.count(':') >= 2 and len(p) == 17:
                    ip_in_line = None
                    for x in parts:
                        if x.replace('.','').isdigit() and x.count('.') == 3:
                            ip_in_line = x
                            break
                    if ip_in_line:
                        mac_map[ip_in_line] = p.upper()
                    break
        
        lines.append("\n  在线设备列表:")
        device_list = []
        for ip in sorted(set(live_ips), key=lambda x: [int(p) for p in x.split('.')]):
            mac = mac_map.get(ip, '')
            oui = mac[:8] if mac else ''
            vendor = OUI_CODES.get(oui, '') if oui else ''
            vendor_str = f'\U0001f3f7 {vendor}' if vendor else ''
            mac_str = f' [{mac}]' if mac else ''
            lines.append(f"  {ip}{mac_str} {vendor_str}")
            device_list.append({'ip':ip,'mac':mac,'vendor':vendor,'dev_type':'','ports':'','os':'','port_count':0})
        
        # Count unused IPs for small subnets only
        lines.append("\n[3/3] 计算空闲IP...")
        if total_ips <= 65536:
            base = target.split('/')[0].rsplit('.', 1)[0]
            used_ips = set(d['ip'] for d in device_list)
            all_ips = set()
            if prefix <= 24:
                base = target.split('/')[0].rsplit('.', 1)[0]
                for i in range(1, 255):
                    ip = f"{base}.{i}"
                    all_ips.add(ip)
            else:
                import ipaddress
                net = ipaddress.ip_network(target, strict=False)
                all_ips = set(str(ip) for ip in net.hosts())
            idle_list = sorted(all_ips - used_ips, key=lambda x: [int(p) for p in x.split('.')])
            lines.append(f"  \U0001f4ba 已用IP: {len(used_ips)}")
            lines.append(f"  \U0001f507 空闲IP: {len(idle_list)}")
        
        lines.append("\n" + "=" * 60)
        lines.append(f"  \U0001f4ca 在线设备总数: {len(device_list)}")
        lines.append("  " + "*" * 45)
        lines.append("  \U0001f4a1 提示: 使用 scan_level='quick' 或 ip_usage_report(target, detailed_os_scan=True) 获取详细设备类型识别")
        lines.append("\n" + "=" * 60)
        return "\n".join(lines)
    
    # Step 2: Get ARP table for MAC addresses
    lines.append("\n[2/4] 获取MAC地址信息...")
    r2 = subprocess.run("ip neigh show 2>/dev/null || arp -a 2>/dev/null", shell=True, capture_output=True, text=True, timeout=10)
    arp_table = r2.stdout
    
    mac_map = {}
    for line in arp_table.split('\n'):
        parts = line.split()
        for i, p in enumerate(parts):
            if p.count(':') >= 2 and len(p) == 17:
                ip_in_line = None
                for x in parts:
                    if x.replace('.','').isdigit() and x.count('.') == 3:
                        ip_in_line = x
                        break
                if ip_in_line:
                    mac_map[ip_in_line] = p.upper()
                break
    
    # Step 3: Identify each device
    lines.append("\n[3/4] 识别设备类型...")
    
    device_list = []
    base_ip = target.split('/')[0].rsplit('.', 1)[0]
    network_ip = base_ip + '.0'
    broadcast_ip = base_ip + '.255'
    
    for ip in sorted(set(live_ips), key=lambda x: [int(p) for p in x.split('.')]):
        if ip == network_ip or ip == broadcast_ip:
            continue
        
        mac = mac_map.get(ip, '')
        oui = mac[:8] if mac else ''
        vendor = OUI_CODES.get(oui, '') if oui else ''
        
        open_ports = []
        os_guess = ''
        scan_note = ''
        if scan_level != 'ping':
            # quick / normal / deep 一律做全端口发现（1-65535）。端口范围不再随
            # scan_level 变——原来 quick 只探 10 个口、normal 探 23 个、deep 探
            # 50 个，没在表里的服务在报告里根本不出现，是拿"级别"换漏报。
            # 级别现在只决定要不要多花时间做 OS 识别；只要 IP 清单用 ping。
            try:
                _ports, _raw = portscan.discover(ip, host_timeout=60, timeout=600)
                open_ports = list(_ports)
            except Exception as exc:
                scan_note = "全端口扫描失败: %s" % exc
        if scan_level == 'deep' and not scan_note:
            # OS detection
            try:
                r4 = subprocess.run(f"nmap -O -n --osscan-guess --max-os-tries 1 -Pn {ip} 2>&1", shell=True, capture_output=True, text=True, timeout=60)
                for l in r4.stdout.split('\n'):
                    if 'OS details:' in l or 'Aggressive OS guesses:' in l:
                        os_guess = l.split(':', 1)[-1].strip()
                        break
                if not os_guess:
                    for l in r4.stdout.split('\n'):
                        if 'Running:' in l:
                            os_guess = l.split(':', 1)[-1].strip()
                            break
            except Exception:
                pass
        
        dev_type = identify_device_type(ip, mac, open_ports, os_guess)
        
        # HTTP指纹识别（对Web端口做HTTP请求识别具体应用）
        app_name = ''
        web_note = ''
        web_ports = [p for p in open_ports if p in (80, 443, 8080, 8443)]
        if web_ports:
            app_name, web_note = fingerprint_web_service(ip, web_ports[0])
        
        port_str = ','.join(str(p) for p in sorted(open_ports)) if open_ports else '无'
        os_str = f' ({os_guess})' if os_guess else ''
        vendor_str = f'\U0001f3f7 {vendor}' if vendor else ''
        mac_str = f' [{mac}]' if mac else ''
        app_str = f' [{app_name}]' if app_name else ''
        note_str = f' - {web_note}' if web_note else ''
        if scan_note:
            note_str += f' - {scan_note}'
        
        device_list.append({
            'ip': ip, 'mac': mac, 'vendor': vendor,
            'dev_type': dev_type, 'ports': port_str,
            'os': os_guess, 'port_count': len(open_ports),
            'app': app_name, 'note': web_note
        })
        
        line = f"  \n  {ip}{mac_str}{vendor_str}{app_str} {dev_type}{os_str}{note_str}"
        lines.append(line)
        if open_ports:
            p50 = ','.join(str(p) for p in sorted(open_ports)[:10])
            lines[-1] += f' \n   \U0001f6e1 \u7aef\u53e3: {p50}'
    
    # Step 4: Calculate unused IPs
    lines.append("\n[4/4] 计算空闲IP...")
    
    used_ips = set(d['ip'] for d in device_list)
    all_ips_in_subnet = set()
    prefix = int(target.split('/')[1])
    if prefix <= 24:
        base = target.split('/')[0].rsplit('.', 1)[0]
        for i in range(1, 255):
            ip = f"{base}.{i}"
            if ip != network_ip and ip != broadcast_ip:
                all_ips_in_subnet.add(ip)
    
    idle_list = sorted(all_ips_in_subnet - used_ips, key=lambda x: [int(p) for p in x.split('.')])
    
    # Group consecutive idle IPs into ranges
    idle_ranges = []
    if idle_list:
        start = idle_list[0]
        prev = idle_list[0]
        for ip in idle_list[1:]:
            prev_parts = [int(x) for x in prev.split('.')]
            curr_parts = [int(x) for x in ip.split('.')]
            if curr_parts[-1] == prev_parts[-1] + 1 and curr_parts[:-1] == prev_parts[:-1]:
                prev = ip
            else:
                if start == prev:
                    idle_ranges.append(start)
                else:
                    idle_ranges.append(f"{start}-{prev.split('.')[-1]}")
                start = ip
                prev = ip
        if start == prev:
            idle_ranges.append(start)
        else:
            idle_ranges.append(f"{start}-{prev.split('.')[-1]}")
    
    lines.append(f"  \n  \U0001f4ba 已用IP: {len(used_ips)} 个")
    lines.append(f"  \U0001f507 空闲IP: {len(idle_list)} 个")
    if idle_ranges:
        lines.append(f"  \n  \U0001f507 \u7a7a\u95f2\u8303\u56f4: {', '.join(idle_ranges[:20])}")
        if len(idle_ranges) > 20:
            lines.append(f"    ... (共 {len(idle_ranges)} \u6bb5\u8303\u56f4)")
    
    # Summary table
    lines.append("\n" + "=" * 60)
    lines.append("  \U0001f4ca 设备汇总")
    lines.append("=" * 60)
    type_count = {}
    vendor_count = {}
    for d in device_list:
        t = d['dev_type'].replace('\U0001f4f1 ', '').replace('\U0001f5a5 ', '').replace('\U0001f4bb ', '').replace('\U0001f4e1 ', '').replace('\U0001f3f7 ', '')
        type_count[t] = type_count.get(t, 0) + 1
        if d['vendor']:
            vendor_count[d['vendor']] = vendor_count.get(d['vendor'], 0) + 1
    for t, c in sorted(type_count.items(), key=lambda x: -x[1]):
        lines.append(f"  \U0001f4c8 {t}: {c}")
    if vendor_count:
        lines.append("  \n  \U0001f3f7 \u5382\u5546\u7edf\u8ba1:")
        for v, c in sorted(vendor_count.items(), key=lambda x: -x[1]):
            lines.append(f"    {v}: {c}")
    
    lines.append("\n" + "=" * 60)
    return "\n".join(lines)

def compliance_report(target):
    """生成等保三级合规检查综合报告"""
    import subprocess as _sp, re
    lines = []
    lines.append("="*65)
    lines.append("  等保三级合规安全检查报告")
    lines.append("  目标: %s" % target)
    lines.append("  时间: %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("="*65)
    lines.append("")
    
    # 1. 资产发现
    lines.append("一、资产清单")
    lines.append("-"*40)
    try:
        r = _sp.run(["nmap","-sn","-T5","--max-retries","1",target],
            capture_output=True,text=True,timeout=30)
        ips = set()
        for line in r.stdout.split('\n'):
            m = re.search(r'\d+\.\d+\.\d+\.\d+', line)
            if m and 'report for' in line:
                ip = m.group(0)
                ips.add(ip)
        lines.append("在线设备数: %d 台" % len(ips))
        for ip in sorted(ips)[:20]:
            lines.append("  - %s" % ip)
        if len(ips) > 20:
            lines.append("  ... 共%d台，仅显示前20台" % len(ips))
        lines.append("")
    except Exception as e:
        lines.append("资产发现失败: %s" % str(e)[:60])
    
    # 2. 端口暴露面
    lines.append("二、高危端口暴露检查")
    lines.append("-"*40)
    try:
        # 取前10个在线IP扫端口
        for ip in sorted(ips)[:10]:
            r2 = _sp.run(["nmap","-sT","-p","6379,27017,9200,9300,2375,2376,11211,21,23,445,1433,3389,3306,5432,54321,5236,8080,8443","-T5","--min-rate","2000",ip],
                capture_output=True,text=True,timeout=20)
            opens = []
            for line in r2.stdout.split('\n'):
                if '/tcp' in line and 'open' in line:
                    mm = re.search(r'(\d+)/tcp\s+open\s+(\S+)', line.strip())
                    if mm:
                        opens.append("%s(%s)" % (mm.group(1), mm.group(2)))
            if opens:
                lines.append("  %s → %s" % (ip, ", ".join(opens)))
            else:
                lines.append("  %s → 无高危端口开放 ✓" % ip)
        lines.append("")
    except:
        pass
    
    # 3. 基线检查项
    lines.append("三、等保三级符合性检查")
    lines.append("-"*40)
    checks = [
        ("身份鉴别", [
            "a) 应采用密码+动态令牌/生物识别等两种以上鉴别技术",
            "b) 密码长度≥8位,包含大小写字母+数字+特殊字符",
            "c) 密码过期周期≤90天,历史密码≥5次不重用",
            "d) 登录失败5次应锁定账户",
            "e) 空闲超时15分钟应自动退出"
        ]),
        ("访问控制", [
            "a) 应关闭非必要端口和服务",
            "b) 应配置访问控制策略(ACL/白名单)",
            "c) 应限制root远程直接登录"
        ]),
        ("安全审计", [
            "a) 应启用审计功能(auditd/syslog)",
            "b) 应覆盖登录/登出/特权操作/文件访问",
            "c) 日志保存≥180天",
            "d) 日志防篡改"
        ]),
        ("入侵防范", [
            "a) 应安装主机入侵检测(HIDS)",
            "b) 应扫描已知漏洞并修复",
            "c) 应控制终端设备的远程接入"
        ]),
        ("数据安全", [
            "a) 应采用加密协议传输敏感数据(HTTPS/SSH/SFTP)",
            "b) 数据库/缓存应配置访问密码",
            "c) 敏感数据应加密存储"
        ])
    ]
    for title, items in checks:
        lines.append("\n%s:" % title)
        for item in items:
            lines.append("  ☐ %s" % item)
    
    lines.append("")
    # 4. 整改建议
    lines.append("四、整改建议优先级")
    lines.append("-"*40)
    lines.append("\n🔴 立即整改(高优先):")
    lines.append("  1. 未授权服务(Redis/MongoDB/ES/Docker)添加认证")
    lines.append("  2. 关闭非必要的高危端口")
    lines.append("  3. 修改默认密码/弱密码")
    lines.append("\n🟡 限期整改(中优先):")
    lines.append("  1. 启用审计日志(auditd)")
    lines.append("  2. 限制root远程SSH登录")
    lines.append("  3. 配置登录失败锁定策略")
    lines.append("\n🔵 优化建议(低优先):")
    lines.append("  1. 升级老旧服务版本")
    lines.append("  2. 启用SSH密钥认证")
    lines.append("  3. 配置空闲会话超时")
    
    lines.append("\n" + "="*65)
    lines.append("  报告说明: 此报告由自动安全工具生成，仅供参考")
    lines.append("  正式等保测评需配合现场取证和人工检查")
    lines.append("="*65)
    return {"success":True,"returncode":0,"output":"\n".join(lines)}
