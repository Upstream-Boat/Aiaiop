#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""审计链接口 — 查询、完整性校验，以及演示用的"篡改/还原"两个开关。

篡改开关只在本地演示用：它把最后一条记录改掉而不同步更新 hash，用来现场证明
"改过就是能被查出来"。还原后链路回到全绿。
"""

from fastapi import APIRouter
from pydantic import BaseModel

from core import audit

router = APIRouter(tags=["audit"])


class VerifyBody(BaseModel):
    limit: int = 0


class RecordBody(BaseModel):
    action: str
    target_type: str = ""
    target_id: str = ""
    detail: str = ""
    actor: str = "agent"
    origin: str = ""


@router.get("/audit")
def list_entries(limit: int = 200):
    """最近的审计记录（倒序，便于界面直接渲染）。"""
    rows = audit.entries(limit=limit)
    return {"items": list(reversed(rows)), "total": len(audit.entries())}


@router.post("/audit/verify")
def verify(body: VerifyBody):
    """校验审计链：返回篡改嫌疑、断链、链头截断与锚点比对结果。"""
    return audit.verify(limit=body.limit)


@router.post("/audit/record")
def record(body: RecordBody):
    """补记一条审计（例如命令行侧的动作想让它出现在控制台）。"""
    return audit.record(body.action, target_type=body.target_type, target_id=body.target_id,
                        detail=body.detail, actor=body.actor, origin=body.origin)


@router.post("/audit/tamper-demo")
def tamper_demo():
    """演示：篡改最后一条记录（不同步更新 hash）。"""
    item = audit.tamper_demo()
    return {"ok": bool(item), "item": item}


@router.post("/audit/tamper-restore")
def tamper_restore():
    """演示：还原被篡改的记录。"""
    return {"ok": audit.tamper_restore()}
