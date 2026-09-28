#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""路径与凭据解析 — 所有环境相关配置的唯一入口。

设计原则：开箱可用 + 可移植。
每个路径都按「环境变量 > 本地约定 > 系统常见位置」的顺序探测，探测不到就返回
None，由调用方给出明确报错，而不是硬编码某台机器的绝对路径。

可通过环境变量覆盖：
    SEC_ASSESSMENT_HOME        skill 根目录（默认自动推断）
    CVE_DB_PATH             CVE sqlite 库路径
    EXPLOIT_DB_DIR          Exploit-DB 根目录（含 exploits/ 与 files_exploits.csv）
    NUCLEI_TEMPLATES        nuclei 模板目录
    NUCLEI_BIN              nuclei 可执行文件
    METASPLOIT_BIN          Metasploit bin 目录（会加入 PATH）
    MAC_PREFIX_FILE         nmap MAC 前缀表
    NVD_API_KEY             NVD API Key（无默认值，必须由用户提供）
"""

import os
import shutil

SKILL_HOME = os.environ.get("SEC_ASSESSMENT_HOME") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)
DATA_DIR = os.path.join(SKILL_HOME, "data")
REPORTS_DIR = os.environ.get("SEC_ASSESSMENT_REPORTS") or os.path.join(DATA_DIR, "reports")


def _first_existing(candidates):
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return None


# ── Exploit-DB ──
def _exploit_db_dir():
    """优先级：环境变量 > skill 自带副本 > 已安装的 searchsploit > 系统常见位置。"""
    env = os.environ.get("EXPLOIT_DB_DIR")
    if env:
        return env
    local = os.path.join(DATA_DIR, "exploit-db")
    if os.path.isdir(local):
        return local
    exe = shutil.which("searchsploit")
    if exe:
        return os.path.dirname(os.path.realpath(exe))
    return _first_existing([
        "/opt/exploit-db",
        "/usr/share/exploitdb",
        "/usr/local/share/exploitdb",
    ]) or "/opt/exploit-db"


EXPLOIT_DB_DIR = _exploit_db_dir()
EXPLOIT_DB_EXPLOITS = os.path.join(EXPLOIT_DB_DIR, "exploits") if EXPLOIT_DB_DIR else None
_local_searchsploit = os.path.join(EXPLOIT_DB_DIR, "searchsploit") if EXPLOIT_DB_DIR else None
SEARCHSPLOIT_BIN = (
    _local_searchsploit
    if _local_searchsploit and os.path.exists(_local_searchsploit)
    else shutil.which("searchsploit")
)

# ── CVE 数据库 ──
# 注意：库不存在时返回「构建目标路径」，便于 cve_db_build 直接写入
CVE_DB_PATH = os.environ.get("CVE_DB_PATH") or _first_existing([
    os.path.join(DATA_DIR, "cve_cache_sm_por.sqlite"),
    os.path.join(DATA_DIR, "cve_cache.sqlite"),
]) or os.path.join(DATA_DIR, "cve_cache_sm_por.sqlite")

# ── nuclei ──
NUCLEI_BIN = os.environ.get("NUCLEI_BIN") or shutil.which("nuclei")
NUCLEI_TEMPLATES = os.environ.get("NUCLEI_TEMPLATES") or _first_existing([
    os.path.join(DATA_DIR, "nuclei-templates"),
    os.path.expanduser("~/nuclei-templates"),
    "/opt/nuclei-templates",
    "/usr/local/share/nuclei-templates",
])

# ── Metasploit / 常见用户级 bin ──
METASPLOIT_BIN = os.environ.get("METASPLOIT_BIN") or _first_existing([
    "/opt/metasploit-framework/bin",
    "/usr/local/share/metasploit-framework/bin",
])


def extra_path_entries():
    """返回需要追加到 PATH 的目录（只保留真实存在的）。"""
    candidates = [
        os.path.expanduser("~/.local/bin"),
        os.path.expanduser("~/go/bin"),
        "/usr/local/bin",
        "/usr/local/sbin",
        METASPLOIT_BIN,
    ]
    return [p for p in candidates if p and os.path.isdir(p)]


def apply_path():
    """把 extra_path_entries() 追加进 PATH（幂等）。"""
    path = os.environ.get("PATH", "")
    for entry in extra_path_entries():
        if entry not in path.split(os.pathsep):
            path += os.pathsep + entry
    os.environ["PATH"] = path


apply_path()


# ── 其他 ──
MAC_PREFIX_FILE = os.environ.get("MAC_PREFIX_FILE") or _first_existing([
    os.path.join(DATA_DIR, "oui", "nmap-mac-prefixes"),
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
])

# 占位写法特征：包里只放示例，不放真实密钥。
# 命中这些特征就当作"没配置"，避免把占位串当密钥发去 NVD 换来一个 403。
_PLACEHOLDER_MARKERS = ("<", "your", "example", "示例", "xxxx", "placeholder", "redacted")


def _looks_placeholder(value):
    lowered = value.lower()
    if lowered in ("", "-", "none", "null"):
        return True
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def _nvd_api_key():
    """环境变量优先，其次读 skill 自带的 data/nvd_api_key.txt（随 skill 目录走，便于迁移）。

    仓库/提交包里只放占位示例，真实 key 由使用者通过环境变量 NVD_API_KEY
    或本机 data/nvd_api_key.txt 提供 —— 避免把凭据随 skill 分发出去。
    """
    key = os.environ.get("NVD_API_KEY", "").strip()
    if key and not _looks_placeholder(key):
        return key
    keyfile = os.path.join(DATA_DIR, "nvd_api_key.txt")
    if os.path.isfile(keyfile):
        try:
            with open(keyfile, encoding="utf-8") as fh:
                file_key = fh.read().strip()
        except OSError:
            return ""
        if not _looks_placeholder(file_key):
            return file_key
    return ""


NVD_API_KEY = _nvd_api_key()
NVD_FEED_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

