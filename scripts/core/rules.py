#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""规则库（CVE / Exploit-DB / nuclei / OUI）状态与更新。

只做三件事，且都不改写既有规则库格式：

    status()                  读状态（条数、版本、体积、更新时间），不联网
    update(targets, progress) 调用现有 scripts/update_rules.py，把 stdout 逐行转成进度
    import_package(archive)   离线导入：从 tar.gz / zip 把规则库摊回 data/（现场无网时用）

每次更新与导入都会往审计链写一条记录：规则库是判断依据，谁在什么时候换了依据必须可查。
"""

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

import config

from . import audit, paths

SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPDATER = os.path.join(SCRIPTS_DIR, "update_rules.py")

# 规则库清单：key 同时是前端标识与更新器参数
LIBRARIES = (
    {"key": "cve", "label": "CVE 漏洞库", "kind": "sqlite",
     "path": os.path.join(config.DATA_DIR, "cve_cache_sm_por.sqlite"),
     "target": "--cve", "note": "NVD 增量更新，几分钟；全量重建用 --cve --full"},
    {"key": "exploit-db", "label": "Exploit-DB", "kind": "git",
     "path": os.path.join(config.DATA_DIR, "exploit-db"),
     "target": "--exploit-db", "note": "git pull 更新，含 searchsploit 与两个索引 CSV"},
    {"key": "nuclei", "label": "nuclei 模板", "kind": "dir",
     "path": os.path.join(config.DATA_DIR, "nuclei-templates"),
     "target": "--nuclei", "note": "调 nuclei -update-templates，需本机已装 nuclei"},
    {"key": "oui", "label": "MAC 厂商表（OUI）", "kind": "file",
     "path": os.path.join(config.DATA_DIR, "oui", "nmap-mac-prefixes"),
     "target": None, "note": "随 nmap 或离线包更新，无独立更新器"},
)


def _size_of(path):
    if not os.path.exists(path):
        return 0
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                continue
    return total


def _mtime_of(path):
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(path)))
    except OSError:
        return ""


def _run(cmd, cwd=None, timeout=15):
    """跑一条只读命令；失败返回空串，不抛异常（状态页不能因为一条命令挂掉）。"""
    try:
        out = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=timeout, check=False)
        return out.stdout.decode("utf-8", errors="replace").strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _count_lines(path):
    if not os.path.isfile(path):
        return 0
    with open(path, encoding="utf-8", errors="replace") as handle:
        return sum(1 for _ in handle)


def _cve_status(path):
    if not os.path.isfile(path):
        return {"installed": False}
    try:
        import sqlite3
        conn = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
        try:
            meta = dict(conn.execute("SELECT key, value FROM db_meta").fetchall())
            total = conn.execute("SELECT COUNT(*) FROM cve_items").fetchone()[0]
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 - 库损坏时也要能展示状态
        return {"installed": True, "error": "读取失败（库可能损坏或正被写入）"}
    return {"installed": True, "count": total, "version": meta.get("last_updated", ""),
            "mode": meta.get("mode", ""), "last_run": meta.get("last_run", "")}


def _git_status(path):
    if not os.path.isdir(path):
        return {"installed": False}
    return {"installed": True,
            "version": _run(["git", "-C", path, "log", "-1", "--format=%h %ad", "--date=short"]),
            "dirty": bool(_run(["git", "-C", path, "status", "--porcelain"]))}


def status():
    """规则库状态（不联网、不改动任何文件）。"""
    items = []
    for spec in LIBRARIES:
        path = spec["path"]
        item = {"key": spec["key"], "label": spec["label"], "kind": spec["kind"],
                "path": path, "note": spec["note"], "updatable": bool(spec["target"]),
                "size": _size_of(path), "mtime": _mtime_of(path)}
        if spec["key"] == "cve":
            item.update(_cve_status(path))
        elif spec["key"] == "exploit-db":
            item.update(_git_status(path))
            item["count"] = max(0, _count_lines(os.path.join(path, "files_exploits.csv")) - 1)
        elif spec["key"] == "nuclei":
            count = 0
            for root, _dirs, files in os.walk(path):
                count += sum(1 for name in files if name.endswith((".yaml", ".yml")))
            item.update({"count": count, "installed": os.path.isdir(path)})
            # 模板目录既不是 git 仓库、也没有版本号文件，所以用目录更新时间当版本
            # （与 OUI 的做法一致）。
            # 注意：不要拿 .checksum 当版本 —— 它是 nuclei 自己的「路径,哈希;」清单，
            # 取前 64 个字符会得到一段本地路径，界面上就成了乱码版本号。
            item["version"] = item.get("mtime") or ""
            checksum = os.path.join(path, ".checksum")
            if os.path.isfile(checksum):
                with open(checksum, encoding="utf-8", errors="replace") as handle:
                    item["checksum_entries"] = handle.read().count(";")
        else:
            item["installed"] = os.path.exists(path)
            item["count"] = _count_lines(path)
            # OUI 这类单文件规则库没有独立版本号，用文件更新时间兜底，
            # 让接口自己就能给出「版本」，不依赖前端再补一次。
            item["version"] = item.get("mtime") or ""
        items.append(item)
    return {"libraries": items, "runtime_dir": paths.RUNTIME_DIR,
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")}


def update(targets, progress=None, actor="console"):
    """更新规则库。targets 是 key 列表（如 ['cve']，或 ['all']）。progress(line) 逐行回调。"""
    requested = list(targets or ["cve"])
    valid = {spec["key"] for spec in LIBRARIES}
    if "all" in requested:
        keys = [spec["key"] for spec in LIBRARIES if spec["target"]]
    else:
        keys = [key for key in requested if key in valid]
    if not keys:
        raise ValueError("没有可更新的目标，可选: cve / exploit-db / nuclei / all")
    if not os.path.isfile(UPDATER):
        raise FileNotFoundError("找不到更新器: %s" % UPDATER)

    def emit(text):
        if progress:
            progress(text.rstrip())

    started = time.time()
    codes = {}
    for key in keys:
        spec = next(s for s in LIBRARIES if s["key"] == key)
        if not spec["target"]:
            emit("[跳过] %s 没有独立更新器（%s）" % (spec["label"], spec["note"]))
            continue
        cmd = [sys.executable, UPDATER, spec["target"]]
        emit("[开始] %s：%s" % (spec["label"], " ".join(cmd[2:])))
        proc = subprocess.Popen(cmd, cwd=SCRIPTS_DIR, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in proc.stdout or []:
            emit(line.rstrip())
        codes[key] = proc.wait()
        emit("[结束] %s：退出码 %s" % (spec["label"], codes[key]))
    elapsed = round(time.time() - started, 1)
    audit.record("rules.update", target_type="rules", target_id=",".join(keys),
                 detail="规则库更新 %s，耗时 %ss，退出码 %s" % (",".join(keys), elapsed, codes),
                 actor=actor)
    return {"targets": keys, "codes": codes, "elapsed": elapsed}


# 允许离线导入的目标：压缩包内的目录/文件名 -> 落到 data/ 的位置
IMPORT_TARGETS = {
    "cve_cache_sm_por.sqlite": "cve_cache_sm_por.sqlite",
    "exploit-db": "exploit-db",
    "nuclei-templates": "nuclei-templates",
    "oui": "oui",
}


def import_package(archive, actor="console"):
    """离线导入规则库：tar.gz / zip 内含上述任一目录或文件即可。

    先解压到临时目录并校验，再逐个移动进 data/（同名先备份），避免解压失败把现有规则库弄坏。
    """
    if not os.path.isfile(archive):
        raise FileNotFoundError("离线包不存在: %s" % archive)
    paths.ensure_dirs()
    moved = []
    backup_dir = os.path.join(paths.RUNTIME_DIR, "rules-backup-%s" % time.strftime("%Y%m%d-%H%M%S"))
    with tempfile.TemporaryDirectory(prefix="rules-import-") as tmp:
        if archive.endswith(".zip"):
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(tmp)
        else:
            with tarfile.open(archive) as tf:
                tf.extractall(tmp)
        found = {}
        for root, dirs, files in os.walk(tmp):
            for name in list(dirs) + list(files):
                if name in IMPORT_TARGETS and name not in found:
                    found[name] = os.path.join(root, name)
        if not found:
            raise ValueError("压缩包里没有可识别的规则库（需包含 %s）" % " / ".join(IMPORT_TARGETS))
        os.makedirs(backup_dir, exist_ok=True)
        for name, src in found.items():
            dest = os.path.join(config.DATA_DIR, IMPORT_TARGETS[name])
            if os.path.exists(dest):
                shutil.move(dest, os.path.join(backup_dir, name))
            shutil.move(src, dest)
            moved.append(name)
    audit.record("rules.import", target_type="rules", target_id=",".join(moved),
                 detail="离线导入规则库: %s（原文件备份在 %s）" % (",".join(moved), backup_dir),
                 actor=actor)
    return {"imported": moved, "backup_dir": backup_dir}
