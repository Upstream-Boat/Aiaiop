#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NVD 密钥 — 控制台里唯一一项凭据，而且是可选的。

为什么只有这一项：skill 本体自己就是这么声明的（`scripts/check_deps.py` 的
「可选配置」只列 NVD_API_KEY 与 METASPLOIT_BIN）。工具的外部命令属目标机器的
系统依赖（只能体检、不能安装），规则库是点一下就下载，模型后端则由宿主 Agent
那一层决定 —— 都不是这个工具要人填的东西。

它的作用也只有一个：NVD 规则库更新时的下载凭据。不配只是限速
（5 请求/30 秒），扫描、CVE 匹配、报告都不需要它。

安全约定：
    * 只写不读。接口永不回传明文，只回 has_key（与 llm/backends.py 同一口径）。
    * 写入目标必须落在 skill 自己的 data/ 目录内，越界直接拒绝。
    * 写入文件用 0600 权限，且每次写入都记一条审计链。
"""

import os

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import config
from core import audit

router = APIRouter(tags=["nvd"])

DATA_DIR = os.path.realpath(config.DATA_DIR)
KEY_FILE = os.path.join(DATA_DIR, "nvd_api_key.txt")

# 与 config._looks_placeholder 同一套特征：命中即视为"占位符"，等于没配。
_PLACEHOLDER = getattr(config, "_looks_placeholder", None)


def _looks_placeholder(value):
    if callable(_PLACEHOLDER):
        return bool(_PLACEHOLDER(value))
    lowered = (value or "").lower()
    return not lowered or lowered in ("-", "none", "null") or any(
        marker in lowered for marker in ("<", "your", "example", "示例", "xxxx",
                                         "placeholder", "redacted"))


def _read_text(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def _state():
    """密钥现在从哪来、配没配、改了会不会生效。"""
    env_key = (os.environ.get("NVD_API_KEY") or "").strip()
    file_key = _read_text(KEY_FILE)
    env_used = bool(env_key) and not _looks_placeholder(env_key)
    file_used = bool(file_key) and not _looks_placeholder(file_key)
    # 页面用它决定"摆几个圆点"：只给长度，不给内容（长度是形状，不是密文）
    effective = env_key if env_used else (file_key if file_used else "")
    return {
        "has_key": env_used or file_used,
        "source": "env" if env_used else ("file" if file_used else "none"),
        # 环境变量存在时写文件不生效 —— 必须说清楚，不能默默写个没用的值
        "env_locked": env_used,
        "env_var": "NVD_API_KEY",
        # 不回传文件名与路径：页面只用得到"配没配、从哪来、文件在不在"，
        # 位置信息不该出现在浏览器里（要看内容的人本来就在这台机器上）。
        "file_exists": os.path.isfile(KEY_FILE),
        "key_len": len(effective),
        "effect": "只影响 NVD 规则库的下载速度（无密钥限速 5 请求/30 秒）",
    }


class KeyBody(BaseModel):
    key: str = ""


@router.get("/nvd")
def get_nvd():
    """NVD 密钥状态：配没配、来源、文件位置。永不回传明文。"""
    return _state()


@router.post("/nvd/key")
def set_nvd_key(body: KeyBody):
    """写入或清除 NVD 密钥。key 传空串表示清除。"""
    value = (body.key or "").strip()
    if not value:
        if os.path.isfile(KEY_FILE):
            os.remove(KEY_FILE)
            audit.record("config.clear", target_type="config", target_id="nvd_api_key",
                         detail="清除 NVD 密钥文件", actor="console")
        return {"ok": True, "action": "cleared", "nvd": _state()}

    if _looks_placeholder(value) or len(value) > 128 or any(c.isspace() for c in value):
        raise HTTPException(status_code=400, detail="密钥格式不合法（看起来像占位符，或含空白字符）")
    # 页面上的圆点是个占位串，只删一半再保存就会把圆点当密钥写进去 —— 直接挡住。
    if any(ord(c) > 126 for c in value):
        raise HTTPException(status_code=400,
                            detail="密钥只接受 ASCII 字符（输入框里的圆点是占位，不是密钥内容）")

    _write_private(KEY_FILE, value + "\n")
    audit.record("config.write", target_type="config", target_id="nvd_api_key",
                 detail="写入 NVD 密钥（长度 %d，不回传明文）" % len(value), actor="console")
    return {"ok": True, "action": "written", "nvd": _state()}


def _write_private(path, text):
    """按 0600 写文件（内含密钥，不给同机其它用户读）。"""
    _guard(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(tmp, path)


def _guard(path):
    """写入目标必须位于 skill 的 data/ 目录内。"""
    if not path.startswith(DATA_DIR + os.sep):
        raise HTTPException(status_code=400, detail="拒绝写入 skill 目录之外：%s" % path)
    return path
