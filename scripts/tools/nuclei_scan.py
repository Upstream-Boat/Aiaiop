#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""[Nuclei引擎] 专业漏洞扫描 — 支持 CVE / 高危 / 应用类模板。

模板目录的处理是这里的关键：nuclei 官方模板库里有一多半不是「对着目标发请求」的
类型（headless 要浏览器、code 是本地代码审计、workflows 要子模板、helpers 是给别人
引用的公共片段、dast 需要 fuzz 参数、cloud 读云配置）。全量挂上会明显拖慢，对
IP / URL 目标也基本扫不出东西 —— 实测把 13.7k 个模板全挂上扫单个站点会直接超时。
所以这里只挂真正发请求的四类：http / network / ssl / dns。
"""

import os
import shlex
import tempfile

from registry import tool
from utils import run_cmd, fail, require_tool
from utils import split_targets as _split_targets

from config import NUCLEI_BIN as _NUCLEI_BIN, NUCLEI_TEMPLATES as _TEMPLATES

# 二进制解析：环境变量/本机 PATH 优先，都没有时退回命令名，让下面的预检给出安装提示
nuclei_bin = _NUCLEI_BIN or os.path.expanduser("~/go/bin/nuclei")
if not os.path.isfile(nuclei_bin):
    nuclei_bin = "nuclei"

INSTALL_HINT = "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

# 只挂"会对目标发请求"的模板组件
TEMPLATE_SECTIONS = ("http", "network", "ssl", "dns")

# 默认只看能直接处置的级别；要全量给 severity=all 显式指定
DEFAULT_SEVERITY = "critical,high"
SEVERITY_ALIAS = {"all": "critical,high,medium,low,info"}


def _ascii_template_root():
    """返回一个可以安全交给 nuclei -t 的模板根目录（尽量是纯 ASCII 路径）。

    nuclei 对 -t 里的非 ASCII 路径解析是错的：skill 装在中文目录下时，多字节字符
    会把后续参数错位截断 —— 传 network/ssl/dns 三个目录，nuclei 收到的是
    'work'、'/ssl'、'/dns'，然后报一堆 "Could not find template" 并静默少扫一大半
    模板。实测同一台机器换纯 ASCII 路径就正常。
    所以路径里有非 ASCII 字符时，在临时目录建一个 ASCII 符号链接指过去。
    """
    if not _TEMPLATES or not os.path.isdir(_TEMPLATES):
        return ""
    if _TEMPLATES.isascii():
        return _TEMPLATES
    link_root = os.path.join(tempfile.gettempdir(), "sec-assessment-nuclei")
    link = os.path.join(link_root, "nuclei-templates")
    try:
        os.makedirs(link_root, exist_ok=True)
        if os.path.islink(link) and os.path.realpath(link) != os.path.realpath(_TEMPLATES):
            os.remove(link)
        if not os.path.exists(link):
            os.symlink(os.path.abspath(_TEMPLATES), link)
        return link
    except OSError:
        # 建不出来就退回原路径：http 那一类还是能扫，不至于整条链路不可用
        return _TEMPLATES


def _template_args():
    """拼 -t 参数：逐个挂载 skill 自带的模板子目录，避免把非请求类模板也带上。"""
    root = _ascii_template_root()
    if not root:
        return ""
    sections = [os.path.join(root, name) for name in TEMPLATE_SECTIONS]
    sections = [path for path in sections if os.path.isdir(path)]
    if not sections:
        return "-t '%s'" % root
    return " ".join("-t '%s'" % path for path in sections)


@tool(
    "nuclei_scan",
    "[Nuclei引擎] 专业漏洞扫描(10万+规则) - 支持CVE/高危/应用等",
    {
        "properties": {
            "target": {
                "type": "string",
                "description": "目标IP/URL",
            },
            "severity": {
                "type": "string",
                "description": "严重级别: critical/high/medium/low/all(critical+high+medium+low+info)",
                "default": DEFAULT_SEVERITY,
            },
            "tags": {
                "type": "string",
                "description": "规则标签过滤(如 cve,redis,apache,spring,等留空默认)",
                "default": "",
            },
            "timeout": {
                "type": "integer",
                "description": "超时秒数",
                "default": 300,
            },
        },
        "required": ["target"],
    },
)
def nuclei_scan_handler(params):
    # 预检：缺引擎时给出安装命令，而不是丢一句 /bin/sh: nuclei: command not found
    missing = require_tool(nuclei_bin, INSTALL_HINT)
    if missing:
        return missing
    targets = _split_targets(params.get("target"))
    if not targets:
        return fail("缺少 target 参数（目标 IP / URL）")
    severity = (params.get("severity") or DEFAULT_SEVERITY).strip().lower()
    severity = SEVERITY_ALIAS.get(severity, severity)
    tags = (params.get("tags") or "").strip()
    tag_arg = "-tags %s" % tags if tags else ""
    timeout = int(params.get("timeout", 300))
    # 多个目标要逐个 -u：nuclei 的 -u 是 string[]，但整串塞进去时多出来的部分
    # 会被当成位置参数，实际只扫了第一个（端口发现找出来的 8001、18789 全丢）。
    target_arg = " ".join("-u %s" % shlex.quote(t) for t in targets)
    # -no-color：nuclei 默认输出 ANSI 转义，直接进报告与前端会变成乱码
    cmd = ("%s %s -severity %s %s %s -c 30 -rl 100 -timeout 8 -no-color 2>&1"
           % (nuclei_bin, target_arg, severity, tag_arg, _template_args()))
    return run_cmd(cmd, timeout + 30)
