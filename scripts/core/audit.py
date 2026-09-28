#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""审计哈希链 — 每一步动作留可验证的痕迹（算法与平台实现一致，存储改为 JSONL）。

每行记录自身字段与 hash，且把上一行的 hash 纳入本次计算，形成链：

    hash = HMAC-SHA256(prev_hash | actor | action | target_type | target_id | detail | origin | created_at)

校验时逐行复算，把四类情况分开报，不混为一谈：

    篡改嫌疑 content     内容与 hash 不符（有人直接改了某行字段）
    篡改嫌疑 key-mismatch 该行像是用另一把密钥算的（换过密钥，不是被改）
    篡改嫌疑 downgraded  分界点之后的行必须是 HMAC，被标回 sha256 说明有人动过算法字段
    断链     missing-middle / orphan / unlinked（中间行被删 / 整段被挖掉 / 链头未接上）

另有两道兜底：

    链头锚点 每次校验通过都会把链头指纹追加到库外的 anchors.jsonl；
             校验时回头比对，链被整体重算成自洽也能发现。
    链头截断 校验范围内第一条带 hash 的行，其 prev_hash 非空即说明前面还有行（已不存在），
             单独报告而不计入断链，避免正常清理永远误报。
"""

import datetime
import fcntl
import hashlib
import hmac
import json
import os
import secrets

from . import paths

ALGO_HMAC = "hmac"
ALGO_LEGACY = "sha256"
AUTO_FULL_MAX = 50000
ANCHOR_TAIL_BYTES = 256 * 1024


def _now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def _locked(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    handle = open(path, "a+", encoding="utf-8")
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    return handle


def _secret():
    """链密钥来源：环境变量优先，否则在运行时目录生成一份（权限 600，不进版本库）。"""
    env = os.environ.get("SEC_ASSESSMENT_AUDIT_SECRET")
    if env:
        return env.encode("utf-8")
    path = paths.AUDIT_SECRET_FILE
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as handle:
            value = handle.read().strip()
        if value:
            return value.encode("utf-8")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    value = secrets.token_hex(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(value)
    return value.encode("utf-8")


# 派生链密钥：secret 一换，整条链等于换了把钥匙 —— 校验时会报 key-mismatch，
# 而不是笼统的"篡改嫌疑"
def chain_key():
    return hashlib.sha256(b"sec-assessment-audit-chain-v1|" + _secret()).digest()


# 老记录标 sha256、新记录标 hmac；值不认识就按老算法算，不猜
def normalize_algo(algo):
    return ALGO_HMAC if str(algo or "").lower() == ALGO_HMAC else ALGO_LEGACY


def entry_hash(prev_hash="", actor="", action="", target_type="", target_id="",
               detail="", origin="", created_at="", algo=ALGO_HMAC):
    """单行哈希：写入与校验共用同一实现（避免两处算法漂移）。"""
    payload = "|".join([
        str(prev_hash or ""), str(actor or ""), str(action or ""), str(target_type or ""),
        "" if target_id is None else str(target_id), str(detail or ""),
        str(origin or ""), str(created_at or ""),
    ])
    if normalize_algo(algo) == ALGO_HMAC:
        return hmac.new(chain_key(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return hashlib.sha256(payload.encode("utf-8")).digest().hex()


# 坏行跳过而不是抛异常：审计读不出来，比少读一行更糟
def entries(limit=0):
    if not os.path.isfile(paths.AUDIT_LOG):
        return []
    out = []
    with open(paths.AUDIT_LOG, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out[-limit:] if limit else out


def record(action, target_type="", target_id="", detail="", actor="agent", origin=""):
    """写一条审计记录（自动接上一条的 hash）。"""
    paths.ensure_dirs()
    handle = _locked(paths.AUDIT_LOG)
    try:
        rows = entries()
        prev = rows[-1]["hash"] if rows else ""
        item = {
            "id": (int(rows[-1]["id"]) + 1) if rows else 1,
            "created_at": _now(),
            "actor": actor,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "detail": detail,
            "origin": origin,
            "prev_hash": prev,
            "algo": ALGO_HMAC,
        }
        item["hash"] = entry_hash(
            prev_hash=item["prev_hash"], actor=item["actor"], action=item["action"],
            target_type=item["target_type"], target_id=item["target_id"],
            detail=item["detail"], origin=item["origin"], created_at=item["created_at"],
            algo=item["algo"],
        )
        handle.seek(0, os.SEEK_END)
        handle.write(json.dumps(item, ensure_ascii=False) + "\n")
        handle.flush()
        return item
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def watermark():
    """HMAC 分界点：此 id 之后的行必须是 HMAC（新装为 0，全部 HMAC）。"""
    try:
        with open(paths.AUDIT_STATE, "r", encoding="utf-8") as handle:
            return int(json.load(handle).get("hmac_from") or 0)
    except (OSError, ValueError, TypeError):
        return 0


# 链头指纹另存一份到库外；库被整体重算成自洽（行内全对）时，这里还能发现
def append_anchor(item):
    paths.ensure_dirs()
    try:
        with open(paths.AUDIT_ANCHORS, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")
        return True
    except OSError:
        return False


def read_anchors(limit=200):
    """读最近的锚点（只读尾部 256KB，避免文件长大后整份进内存）。"""
    path = paths.AUDIT_ANCHORS
    if not os.path.isfile(path):
        return []
    try:
        size = os.path.getsize(path)
        start = max(0, size - ANCHOR_TAIL_BYTES)
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            if start:
                handle.seek(start)
                handle.readline()
            text = handle.read()
    except OSError:
        return []
    out = []
    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out[-limit:]


def verify(limit=0, anchor=True):
    """校验审计链，返回逐类结论（字段名与平台实现保持一致，便于对照）。"""
    rows = entries()
    total = len(rows)
    asked = min(200000, int(limit)) if int(limit or 0) > 0 else 0
    trimmed = False
    if asked:
        rows = rows[-asked:]
    elif total > AUTO_FULL_MAX:
        rows = rows[-AUTO_FULL_MAX:]
        trimmed = True
    mark = watermark()

    hash_seen = {str(r.get("hash")) for r in rows if r.get("hash")}
    head_row = next((r for r in rows if r.get("hash")), None)
    tampered, broken = [], []
    legacy = 0
    checked = 0
    expected = ""
    for row in rows:
        stored = row.get("hash")
        if not stored:
            legacy += 1
            expected = ""
            continue
        algo = normalize_algo(row.get("algo"))
        fields = dict(
            prev_hash=row.get("prev_hash"), actor=row.get("actor"), action=row.get("action"),
            target_type=row.get("target_type"), target_id=row.get("target_id"),
            detail=row.get("detail") or "", origin=row.get("origin") or "",
            created_at=row.get("created_at"),
        )
        calc = entry_hash(algo=algo, **fields)
        if calc != str(stored):
            as_legacy = entry_hash(algo=ALGO_LEGACY, **fields) if algo == ALGO_HMAC else ""
            reason = "key-mismatch" if as_legacy and as_legacy == str(stored) else "content"
            tampered.append({"id": row.get("id"), "action": row.get("action"),
                             "at": row.get("created_at"), "algo": algo, "reason": reason,
                             "expect": calc[:12], "actual": str(stored)[:12]})
        elif mark and int(row.get("id") or 0) > mark and algo != ALGO_HMAC:
            tampered.append({"id": row.get("id"), "action": row.get("action"),
                             "at": row.get("created_at"), "algo": algo, "reason": "downgraded",
                             "expect": ALGO_HMAC, "actual": algo})
        else:
            prev = str(row.get("prev_hash") or "")
            if prev != expected:
                is_head = (not asked) and head_row is not None and row.get("id") == head_row.get("id")
                if not is_head:
                    if not prev:
                        kind = "unlinked"
                    elif prev in hash_seen:
                        kind = "missing-middle"
                    else:
                        kind = "orphan"
                    broken.append({"id": row.get("id"), "action": row.get("action"),
                                   "at": row.get("created_at"), "kind": kind,
                                   "prevHash": prev[:12], "expected": expected[:12]})
        checked += 1
        expected = str(stored)

    head = None
    if head_row and head_row.get("prev_hash") and not asked:
        head = {"id": head_row.get("id"), "at": head_row.get("created_at"),
                "prevHash": str(head_row.get("prev_hash"))[:12]}

    truncations = [{"id": r.get("id"), "created_at": r.get("created_at"), "detail": r.get("detail")}
                   for r in rows if r.get("action") == "retention_purge"][-5:]

    anchor_breaks, anchor_checked = [], 0
    anchors = read_anchors(200) if anchor else []
    if anchors:
        in_range = {int(r.get("id") or 0): str(r.get("hash") or "") for r in rows}
        max_id = int(rows[-1].get("id") or 0) if rows else 0
        for item in anchors:
            try:
                ident = int(item.get("id"))
            except (TypeError, ValueError):
                continue
            if not item.get("hash"):
                continue
            if ident > max_id:
                anchor_breaks.append({"id": ident, "action": item.get("action") or "",
                                      "at": item.get("at") or "",
                                      "anchorHash": str(item["hash"])[:12],
                                      "currentHash": "(已不存在)",
                                      "anchoredAt": item.get("anchored_at") or "",
                                      "truncated": True})
                continue
            if ident not in in_range:
                continue
            anchor_checked += 1
            if in_range[ident] != str(item["hash"]):
                anchor_breaks.append({"id": ident, "action": item.get("action") or "",
                                      "at": item.get("at") or "",
                                      "anchorHash": str(item["hash"])[:12],
                                      "currentHash": in_range[ident][:12],
                                      "anchoredAt": item.get("anchored_at") or ""})
    for item in anchor_breaks:
        tampered.append({"id": item["id"], "action": item["action"], "at": item["at"],
                         "algo": ALGO_HMAC,
                         "reason": "truncated" if item.get("truncated") else "anchor",
                         "expect": item["anchorHash"], "actual": item["currentHash"]})

    ok = not tampered and not broken
    result = {
        "ok": ok, "tamper_free": ok,
        "total": total, "checked": checked, "legacy": legacy,
        "scope": "recent" if asked else "all", "trimmed": trimmed,
        "auto_limit": AUTO_FULL_MAX if trimmed else 0,
        "algo": ALGO_HMAC, "watermark": mark,
        "from_id": rows[0].get("id") if rows else None,
        "to_id": rows[-1].get("id") if rows else None,
        "head": head, "head_cut": bool(head),
        "broken": broken, "tampered": tampered, "truncations": truncations,
        "anchors": {"file": paths.AUDIT_ANCHORS, "recorded": len(anchors),
                    "checked": anchor_checked, "breaks": len(anchor_breaks)},
        "checked_at": _now(),
    }
    if ok and rows:
        tail = rows[-1]
        append_anchor({"id": tail.get("id"), "hash": tail.get("hash"),
                       "action": tail.get("action"), "at": tail.get("created_at"),
                       "anchored_at": result["checked_at"]})
    return result


def tamper_demo(new_detail="演示：这行被手工改过，hash 没有跟着重算"):
    """演示用：改动一条记录的 detail 而不同步更新 hash（校验应报 content 篡改）。

    只动最后一条带 hash 的记录，并把原始行备份到 audit.jsonl.demo-backup 供还原。
    """
    rows = entries()
    index = None
    for i in range(len(rows) - 1, -1, -1):
        if rows[i].get("hash"):
            index = i
            break
    if index is None:
        return None
    original = json.dumps(rows[index], ensure_ascii=False)
    with open(paths.AUDIT_LOG + ".demo-backup", "w", encoding="utf-8") as handle:
        handle.write(json.dumps({"index": index, "line": original}, ensure_ascii=False))
    rows[index]["detail"] = new_detail
    with open(paths.AUDIT_LOG, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return {"id": rows[index].get("id"), "action": rows[index].get("action"), "detail": new_detail}


def tamper_restore():
    """把演示改动还原（审计链回到全绿）。"""
    backup = paths.AUDIT_LOG + ".demo-backup"
    if not os.path.isfile(backup):
        return False
    with open(backup, "r", encoding="utf-8") as handle:
        saved = json.load(handle)
    rows = entries()
    if 0 <= int(saved["index"]) < len(rows):
        rows[int(saved["index"])] = json.loads(saved["line"])
        with open(paths.AUDIT_LOG, "w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    os.remove(backup)
    return True
