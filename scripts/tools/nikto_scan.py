#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nikto Web 扫描。

四个坑（都在下面代码里注明，别改回去）：
  1. nikto 不允许 `-port` 与完整 URL 同时出现，会直接 `- ERROR` 退出（退出码 1）。
     所以目标一律先拆成 host / port / ssl 三段再交给 nikto。
  2. 原来的降级判断写成「含 Required module not found 或不等于 0」，于是上面那个
     参数错误也会被判成"nikto 不可用"，静默换成很弱的内置路径探测 —— 扫描看着
     完成了，实际漏掉一大堆检查项，还附带一句错误的"缺 Perl 模块"。
  3. nikto 的退出码不能当成败：连不上目标它照样退 0，只在正文里写
     `+ [FAIL] Unable to connect`。以前按退出码判，于是"扫了个空"被记成成功。
  4. 协议猜错同样表现为 [FAIL]：端口对但用了 http 去敲 https 端口时也一样。
     所以没显式写协议时先探一次，443/8443 这类端口默认按 https 试。
  5. 单步里给一串目标（通常抄的是上一步的开放端口清单）时，里面总有几个端口
     其实没有 Web 服务 —— 它们只会回报一句 [FAIL] Unable to connect。以前这会
     把整步判成"失败"，于是 nikto 看起来总是失败。现在这类目标记成"不可达"，
     只要还有一个目标扫出结果，这一步就算成功（一个都没扫到才报失败）。
"""

import re
import ssl as _ssl
import time
import urllib.error
import urllib.request

from registry import tool
from utils import run_cmd, fail, split_targets as _split_targets

# 单目标的时间下限/上限：下限保证慢速目标有机会出结果，上限防一个目标吃掉整轮预算
PER_TARGET_MIN = 45
PER_TARGET_MAX = 420
# 多目标拼接后回给模型的上限（完整原文另存输出文件，控制台看得到全文）——
# 不按住的话，第一个目标的长输出会把后面几个目标整个挤掉，报告里就"没有"那些端口
TOTAL_OUTPUT_CAP = 6000
TLS_PORTS = ("443", "8443", "9443")
# 固定扫描范围：nikto 默认 Tuning 含 DoS(6) 与大字典猜名，前者可能把目标打挂，
# 后者在有防护的目标上前进极慢。这组是常用默认集，不碰 DoS、不做爆破式猜名。
DEFAULT_TUNING = "123bde"
# nikto 自己报"这个目标没连上 / 不是 Web 服务"的说法（退出码 0，只能从正文认）
UNREACHABLE_MARKERS = ("unable to connect", "no web server found", "0 host(s) tested",
                       "error: unable to", "cannot resolve", "no such host")
# nikto 到点自己收尾的说法：结论可用，但没扫完 —— 报告里要标成"部分结果"，
# 不能让"到点被砍"看起来和"扫完了"一样
PARTIAL_MARKERS = ("maximum execution time", "scan terminated")


def _truthy(value):
    return str(value).strip().lower() in ("1", "true", "yes", "y", "on")


def _http_alive(scheme, host, port):
    """这个端口用这个协议讲不讲话。401/403 也算在 —— 那是服务拒了你，不是没有服务。"""
    ctx = None
    if scheme == "https":
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
    url = "%s://%s:%d/" % (scheme, host, port)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, context=ctx, timeout=4) as res:
            res.read(1)
        return True
    except urllib.error.HTTPError:
        return True
    except Exception:  # noqa: BLE001 - 探不通就是不通，交给另一种协议再试
        return False


def _probe_scheme(host, port, ssl_on):
    """没显式写协议时探一次 http / https，返回该用的 ssl 开关。

    端口与协议不匹配时 nikto 只会写一句 [FAIL] Unable to connect 然后退 0，
    看起来像"目标不可达"，实际是扫描器自己站错了门；443/8443 默认先按 https 试，
    探不通再换另一种，两种都不通就按原判断交给 nikto 如实报错。
    """
    candidates = ["https", "http"] if (ssl_on or port in TLS_PORTS) else ["http", "https"]
    for scheme in candidates:
        if _http_alive(scheme, host, port):
            return scheme == "https"
    return ssl_on


def _classify(text, result):
    """按正文判这个目标扫成什么样，返回 (状态, 说明)。

    状态四选一：
      ok          正常扫完
      partial     到点收尾（我们的硬超时，或 nikto 自己的 -maxtime）—— 结论可用
      unreachable 这个目标上没有 Web 服务 / 连不上 —— 不是失败，只是跳过
      error       nikto 自己出错了（真异常）

    nikto 连不上目标时退出码仍是 0，只看退出码会把"扫了个空"记成成功，
    所以不可达必须先按正文认出来。
    """
    lowered = (text or "").lower()
    if result.get("timeout"):
        return "partial", ""
    if any(marker in lowered for marker in UNREACHABLE_MARKERS):
        detail = ""
        for line in (text or "").splitlines():
            if "[FAIL]" in line or "Unable to connect" in line:
                detail = line.strip()
                break
        return "unreachable", detail or "nikto 未能与目标建立会话"
    if any(marker in lowered for marker in PARTIAL_MARKERS):
        return "partial", ""
    if not result.get("success"):
        return "error", (result.get("output") or "")[-200:].strip()
    return "ok", ""


def _cap(text, limit):
    """按目标截断正文，头尾都留：头是服务信息，尾是"多少个请求/多少条结果"的收尾行。
    中间省略的部分在输出文件里有全文，事件流与模型只需要这个摘要。"""
    if len(text) <= limit:
        return text
    # 按整行切：多半行接上半行，读起来像乱码，也会让 critic 的行级解析失配
    head = text[: int(limit * 0.6)].rsplit("\n", 1)[0]
    tail = text[-int(limit * 0.4):].split("\n", 1)[-1]
    return "%s\n…（本目标输出另有 %d 字符未在此列出，完整原文见输出文件）\n%s" % (
        head, len(text) - len(head) - len(tail), tail)


def _split_target(target):
    """把 URL / host:port / host 统一拆成 (host, port, ssl, 目标里是否写了端口)。

    nikto 的 -h 可以吃 host 或 URL，但不能和 -port 一起用；统一拆开最省事。
    """
    text = (target or "").strip()
    scheme = ""
    match = re.match(r"^([a-zA-Z][\w+.-]*)://", text)
    if match:
        scheme = match.group(1).lower()
        text = text[match.end():]
    text = text.split("/")[0].split("?")[0]
    host, port, explicit = text, None, False
    if ":" in text:
        head, tail = text.rsplit(":", 1)
        if tail.isdigit():
            host, port, explicit = head, int(tail), True
    ssl_on = scheme == "https"
    if port is None:
        port = 443 if ssl_on else 80
    return host, port, ssl_on, explicit


def _builtin_fallback(host, port, ssl_on):
    """nikto 真的不可用时的兜底：只做几个常见路径的存活探测，结论很弱。"""
    scheme = "https" if ssl_on else "http"
    ctx = None
    if ssl_on:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
    paths = ["/", "/admin", "/login", "/backup", "/test", "/phpinfo.php",
             "/robots.txt", "/.git/config", "/.env"]
    lines = ["(nikto 不可用，已降级为内置路径探测 —— 结论不完整，请补装 nikto)"]
    for path in paths:
        url = "%s://%s:%d%s" % (scheme, host, port, path)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            res = urllib.request.urlopen(req, context=ctx, timeout=5)
            if res.getcode() == 200 and path != "/":
                lines.append("  ! 可访问: %s (HTTP %d)" % (url, res.getcode()))
            elif res.getcode() == 403:
                lines.append("  ? 禁止访问(可能需认证): %s (HTTP %d)" % (url, res.getcode()))
        except Exception:  # noqa: BLE001 - 单条路径失败不影响其他路径
            pass
    lines.append("  提示: %d 个路径检查完成" % len(paths))
    return {"success": True, "returncode": 0, "output": "\n".join(lines)}


@tool(
    "nikto_scan",
    "Nikto Web扫描",
    {
        "properties": {
            "target": {
                "type": "string",
                "description": "URL 或 IP（如 http://192.168.1.5 或 192.168.1.5）",
                "default": None,
            },
            "port": {
                "type": "integer",
                "description": "端口；目标里已写端口时以目标为准",
                "default": 80,
            },
            "ssl": {
                "type": "boolean",
                "description": "是否 HTTPS(false)",
                "default": "false",
            },
            "timeout": {
                "type": "integer",
                "description": "整个步骤的总预算秒数，多目标时按目标数均分（默认 300）",
                "default": 300,
            },
        },
        "required": ["target"],
    },
)
def nikto_scan_handler(params):
    targets = _split_targets(params.get("target"))
    if not targets:
        return fail("缺少 target 参数（URL 或 IP）")
    # timeout 是整个步骤的预算（多个目标要分掉），不是单个目标的秒数
    total_budget = int(params.get("timeout") or 300)
    per_target = min(PER_TARGET_MAX, max(PER_TARGET_MIN, total_budget // len(targets)))
    # nikto 自己的软上限比我们给它的硬上限早一点点到点：让它自己收尾（会打一句
    # 统计再退），而不是被我们连进程组一起杀掉 —— 少一段收尾，报告里就看不出
    # "扫了多少请求、还剩多少没扫"
    soft_limit = max(20, per_target - 15)
    per_target_chars = max(1200, TOTAL_OUTPUT_CAP // len(targets))

    started = time.time()
    outputs, unreachable, failed = [], [], []
    scanned = 0
    for target in targets:
        host, port, ssl_on, port_in_target = _split_target(target)
        if not host:
            outputs.append("### %s\n无法从 target 解析出主机，跳过" % target)
            failed.append("%s（解析不出主机）" % target)
            continue
        # 目标里没写端口时，才看调用方显式给的 port
        if not port_in_target and params.get("port"):
            port = int(params["port"])
        # 显式写了协议（URL 带 scheme，或 ssl=true）就不探，尊重调用方；
        # 没写就探一次 —— 猜错协议时 nikto 的表现和"目标挂了"一模一样，最难查
        explicit = _truthy(params.get("ssl")) or bool(
            re.match(r"^[a-zA-Z][\w+.-]*://", str(target).strip()))
        if explicit:
            ssl_on = True if _truthy(params.get("ssl")) else ssl_on
        else:
            ssl_on = _probe_scheme(host, port, ssl_on)
        args = ["nikto", "-h", host, "-port", str(port),
                "-nointeractive", "-ask", "no", "-nocheck", "-Pause", "0",
                "-Tuning", DEFAULT_TUNING, "-timeout", "5",
                "-maxtime", "%ds" % soft_limit]
        if ssl_on:
            args.append("-ssl")
        result = run_cmd(" ".join(args) + " 2>&1", per_target)
        # 只有"nikto 本身跑不起来"才降级；参数写错、目标不可达这类要如实暴露出来，
        # 否则报告里会出现一个"扫描完成"的假象。
        text = result.get("output") or ""
        if ("command not found" in text or "Required module not found" in text
                or "Can't locate" in text):
            result = _builtin_fallback(host, port, ssl_on)
            text = result.get("output") or ""
        status, why = _classify(text, result)
        if status == "unreachable":
            unreachable.append("%s:%d" % (host, port))
        elif status == "error":
            failed.append("%s:%d（%s）" % (host, port, why))
        else:
            scanned += 1
        scheme = "https" if ssl_on else "http"
        outputs.append("### %s://%s:%d　%s\n%s" % (
            scheme, host, port,
            {"ok": "完成", "partial": "部分结果",
             "unreachable": "不可达", "error": "失败"}[status],
            _cap(text, per_target_chars)))
    # 抬头先给结论：几个目标、成没成。多目标时正文会被截断，这行是不会被截掉的那部分
    header = "nikto 扫描：%d 个目标，扫出结果 %d 个，不可达 %d 个，失败 %d 个（耗时 %.1fs）" % (
        len(targets), scanned, len(unreachable), len(failed), time.time() - started)
    if unreachable:
        header += "\n不可达的目标（这些端口上没有 Web 服务，不计失败）：" + "、".join(unreachable)
    if failed:
        header += "\n出错的目标：" + "；".join(failed)
    if not scanned:
        header += "\n全部目标都没扫出结果：目标不可达，或这些端口上没有可识别的 Web 服务。"
    # 单个目标连不上不算整步失败（拿上游开放端口清单来扫时很常见，里面总有非 Web 端口）；
    # 但一个都没扫出结果时必须如实报失败，否则"扫了个空"会被当成成功
    all_ok = scanned > 0 and not failed
    return {"success": all_ok, "returncode": 0 if all_ok else -1,
            "output": "\n".join([header] + outputs), "timeout": False}
