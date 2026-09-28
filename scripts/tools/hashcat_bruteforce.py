#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hashcat破解 — 用字典撞哈希。

hashcat 的运算后端只有 OpenCL 一种，机器上没装 ICD（pocl / 厂商 runtime）时它
只会吐出 "OpenCL/: No such file or directory" 然后退出；实测的很多机器压根没有
OpenCL 设备（虚拟机 + 虚拟显卡），仓库里也拿不到 CPU 版运行时。所以这里做成三段：

1. hashcat + OpenCL 都就绪 → 走 hashcat；
2. 缺任一样 → 走内置的 CPU 字典回退（纯标准库，逐候选算哈希比对）。算法与参数表
   一致，只是没有掩码和规则、速度慢，结论同样来自真实计算；
3. hash_file / wordlist 不存在、算法不认识 → 直接报错，不猜。

回退能覆盖多大的字典看机器，超过上限会明确说"扫到第几条停了"，不会假装扫完。
"""

import hashlib
import os
import shutil
import time

from registry import tool
from utils import ok, fail
from helpers import *  # noqa: F401,F403


# 内置回退一次最多算多少条候选：留个上限，免得拿 1000 万行的字典把机器拖死
FALLBACK_LIMIT = 5_000_000

FALLBACK_ALGOS = {"md5": "md5", "sha1": "sha1", "sha256": "sha256", "sha512": "sha512"}


def _read_hashes(path):
    """读出待破解的哈希，忽略空行与 # 注释。"""
    out = []
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            item = line.strip().split(":")[-1].strip() if ":" in line else line.strip()
            if item and not item.startswith("#"):
                out.append(item)
    return out


def _python_crack(hashes, wordlist, algo, limit=FALLBACK_LIMIT):
    """纯标准库的字典攻击：每个候选算一次哈希去比对。

    没有掩码、没有规则，速度也不快；换来的是任何机器（没有 OpenCL、没有独显）
    都能给出真实结论。命中即停：字典里没有的哈希，报"未命中"而不是"破解失败"。
    """
    digest = getattr(hashlib, algo)
    targets = {}
    for item in hashes:
        targets.setdefault(item.lower(), item)
    found, tried, started = {}, 0, time.time()
    with open(wordlist, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            candidate = line.rstrip("\r\n")
            if candidate == "":
                continue
            tried += 1
            guard = digest(candidate.encode("utf-8", "ignore")).hexdigest()
            if guard in targets:
                found[targets[guard]] = candidate
            if len(found) == len(targets):
                break
            if tried >= limit:
                break
    return found, tried, time.time() - started


def _fallback(hash_file, wordlist, hash_type, why):
    """hashcat 用不了时的兜底，返回与 run_cmd 同形状的结果。"""
    algo = FALLBACK_ALGOS.get(hash_type)
    if not algo:
        return fail("%s；内置回退只认 md5 / sha1 / sha256 / sha512，%s 请先把 OpenCL 装好"
                    % (why, hash_type))
    hashes = _read_hashes(hash_file)
    if not hashes:
        return fail("hash_file 里没有可解析的哈希: %s" % hash_file)
    lines = ["%s" % why,
             "改用内置 CPU 字典回退（标准库 %s，逐候选比对；无掩码/无规则，速度慢）" % algo,
             "待破解 %d 条哈希，字典 %s" % (len(hashes), wordlist)]
    found, tried, raw_elapsed = _python_crack(hashes, wordlist, algo)
    if raw_elapsed >= 0.01:
        speed_txt = "约 %.0f 条/秒" % (tried / raw_elapsed)
    else:
        speed_txt = "瞬时完成"
    lines.append("已尝试 %d 条候选，用时 %.2fs（%s）%s"
                 % (tried, raw_elapsed, speed_txt,
                    "" if tried < FALLBACK_LIMIT else "，已达上限 %d 条，字典没扫完" % FALLBACK_LIMIT))
    if found:
        lines.append("")
        for digest_value, plain in found.items():
            lines.append("  %s -> %s" % (digest_value, plain))
        lines.append("\n命中 %d / %d 条" % (len(found), len(hashes)))
        return ok("\n".join(lines))
    lines.append("\n字典里没有对应的明文（未命中，不等于哈希无法破解）")
    return {"success": False, "returncode": 1, "output": "\n".join(lines)}


def _opencl_ready():
    """判断本机是否装了任何 OpenCL ICD。"""
    for d in ("/etc/OpenCL/vendors", "/usr/share/OpenCL/vendors"):
        try:
            if any(n.endswith(".icd") for n in os.listdir(d)):
                return True
        except OSError:
            continue
    return False


@tool(
    "hashcat_bruteforce",
    "Hashcat破解 — 用字典撞哈希；本机缺 OpenCL 运行时或 hashcat 时自动改用内置 CPU 回退（md5/sha1/sha256/sha512，无掩码与规则）",
    {
        "properties": {
            "hash_file": {
                "type": "string",
                "description": "hash文件",
                "default": None,
            },
            "wordlist": {
                "type": "string",
                "description": "字典",
                "default": None,
            },
            "hash_type": {
                "type": "string",
                "description": "类型(md5)",
                "default": "md5",
            },
        },
        "required": ["hash_file", "wordlist"],
    },
)
def hashcat_bruteforce_handler(params):
    # 只认这四种类型，传别的会静默落到 md5；--force 是留给没独显的机器，代价是慢
    hm = {"md5": "0", "sha1": "100", "sha256": "1400", "sha512": "1700"}
    hash_type = params.get("hash_type", "md5")
    ht = hm.get(hash_type, "0")
    hf = (params.get("hash_file") or "").strip()
    wl = (params.get("wordlist") or "").strip()
    for path, label in ((hf, "hash_file"), (wl, "wordlist")):
        if not path:
            return fail("缺少 %s 参数" % label)
        if not os.path.exists(path):
            return fail("%s 指向的文件不存在: %s" % (label, path))

    if not shutil.which("hashcat"):
        return _fallback(hf, wl, hash_type, "本机没有 hashcat 可执行文件")
    if not _opencl_ready():
        return _fallback(hf, wl, hash_type,
                         "hashcat 起不来：缺 OpenCL 运行时（/etc/OpenCL/vendors 下没有任何 ICD）")
    return run_cmd("hashcat -m %s -a 0 %s %s --force 2>&1" % (ht, hf, wl), 300)
