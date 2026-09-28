#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""全端口发现 —— 端口扫描的参数量统一从这里出。

以前三处各自写端口范围：巡检用 `--top-ports 100`、IP 盘点 deep 用 `--top-ports 50`、
服务识别的兜底用一张 24 个端口的常用表。没探的端口不会在报告里出现，等于默认漏报，
所以这里统一成两段式：

1. `discover()`  先做 1-65535 全端口发现，只判开不开。用 -T5 预设（与 masscan_scan
   同款参数），65535 个口在百兆内网是秒级~分钟级；
2. `version_scan()` 只对第 1 步真发现的端口做 -sV 版本识别。沿用 service_identify 里
   踩过的坑：版本识别不加 `--min-rate` 顶速，顶满会被对端防扫描策略判成 filtered，
   同一台机器会从"22/80 open"变成"全部 filtered"。

两段分开的代价是要跑两次 nmap；换来的是版本识别只花在真开着的口上，比
`-p1-65535 -sV` 一把梭快得多，也比抽样扫全。
"""

import re
import subprocess

from utils import stream_run

FULL_RANGE = "1-65535"

# -T5 快速发现的参数（与 tools/masscan_scan.py 保持一致）
FAST_RATE = 10000
FAST_RTT = "300ms"
FAST_RETRIES = "1"

_PORT_RE = re.compile(r"(\d+)/open/(?:tcp|udp)/")


class ScanError(RuntimeError):
    """nmap 根本没跑起来（没装 / 权限不够 / 参数写错）。

    这种失败必须往外抛：伪装成"0 个开放端口"，上层会把一个工具错误写成
    "目标没有开放端口"的结论——那是安全工具自己制造的漏报。
    """


def _run(cmd, timeout):
    """跑 nmap，返回文本（stdout + stderr）。

    cmd 两种形态都接：字符串走 shell（discover 那串带选项的长命令），列表直接 exec
    （version_scan）。注意 shell=True 配列表只会把列表第一项当命令名，
    剩下的当 shell 自己的参数——nmap 收不到参数就只打一页 usage，很容易被
    当成"扫描完成、没有端口"。
    """
    try:
        # 走 stream_run 而不是 subprocess.run：nmap 全端口动辄几分钟，
        # 走这里输出才会边跑边进轨迹与控制台（返回结构完全一样）
        r = stream_run(cmd, timeout=timeout, shell=isinstance(cmd, str))
    except FileNotFoundError:
        raise ScanError("找不到 nmap，先装好或确认 PATH")
    except subprocess.TimeoutExpired as exc:
        got = exc.stdout or ""
        if isinstance(got, bytes):
            got = got.decode("utf-8", "ignore")
        raise ScanError("nmap 超时（%ss），已扫到的部分：%s" % (timeout, (got or "")[-200:]))
    text = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0 and not r.stdout:
        raise ScanError("nmap 退出码 %s：%s" % (r.returncode, (text or "").strip()[:200]))
    if "Usage: nmap" in text or "Usage: nmap" in (r.stderr or ""):
        # 参数被 nmap 拒了：这里不能装作"没有开放端口"
        raise ScanError("nmap 参数被拒：%s" % (text or "").strip().splitlines()[0][:120])
    return text


def open_ports(text):
    """从 nmap 输出（-oG 或普通文本）里取 open 端口，返回有序列表。"""
    ports = set()
    for line in (text or "").splitlines():
        if line.startswith("Host:") or "/open/" in line:
            for m in _PORT_RE.finditer(line):
                ports.add(int(m.group(1)))
        if "/tcp" in line and " open " in line:
            m = re.match(r"\s*(\d+)/tcp\s+open", line)
            if m:
                ports.add(int(m.group(1)))
    return sorted(ports)


_G_SVC_RE = re.compile(r"(\d+)/(open|filtered|closed)/(tcp|udp)//([^/]*)//([^/]*)")
_T_SVC_RE = re.compile(r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)$")


def _clean_name(name):
    """nmap 探到多个候选时写成 `ssl|https-alt`，竖线会串掉下游"IP|端口|服务|版本"
    的分列解析（字段会多出来一列，版本号被读成服务名）。只留第一个候选。"""
    return (name or "").split("|")[0].strip()


def services(text):
    """从 nmap 输出里取 [(port, state, service, version)]，普通文本与 -oG 都认。"""
    found = {}
    for line in (text or "").splitlines():
        for m in _G_SVC_RE.finditer(line):
            port, state, _proto, svc, ver = m.groups()
            found.setdefault(int(port), (state, _clean_name(svc) or "unknown",
                                         _clean_name(ver).replace("'", "")))
        m = _T_SVC_RE.match(line)
        if m:
            port, _proto, state, svc, ver = m.groups()
            found.setdefault(int(port), (state, _clean_name(svc) or "unknown", _clean_name(ver)))
    return [(p, st, svc, ver) for p, (st, svc, ver) in sorted(found.items())]


def discover(target, rate=FAST_RATE, host_timeout=90, timeout=1800):
    """全端口发现。返回 (open_ports, raw_output)。

    host_timeout 留得比 masscan_scan 的 20s 宽：那 20s 是"只看结果好不好看"的探测，
    这里是拿来做正式结论的，被防火墙拖住的端口得给足时间，否则漏报会写进报告。
    """
    cmd = ("nmap -Pn -n -T5 --open --max-rtt-timeout %s --min-rate %d --max-retries %s "
           "--host-timeout %ds -p%s -oG - %s"
           % (FAST_RTT, rate, FAST_RETRIES, host_timeout, FULL_RANGE, target))
    raw = _run(cmd, timeout)
    return open_ports(raw), raw


def version_scan(target, ports, timeout=900, intensity=2, udp=False):
    """对指定端口做 -sV 版本识别。ports 为空则直接返回空串。"""
    if not ports:
        return ""
    spec = ",".join(str(p) for p in sorted(set(ports)))
    cmd = ["nmap", "-sT", "-sV", "-Pn", "-n", "--version-intensity", str(intensity),
           "-p", spec, "-T4", "--max-retries", "2", "--host-timeout", "180s", "-oG", "-"]
    if udp:
        cmd.insert(1, "-sU")
    cmd.append(target)
    return _run(cmd, timeout)


def full_scan(target, rate=FAST_RATE, timeout=1800):
    """发现 + 版本识别一步到位，返回 (open_ports, version_output)。"""
    ports, raw = discover(target, rate=rate, timeout=timeout)
    out = version_scan(target, ports, timeout=max(300, timeout // 2))
    return ports, (out or raw)
