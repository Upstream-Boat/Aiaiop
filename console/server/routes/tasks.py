#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""任务与轨迹接口 — 控制台左栏（任务列表）与中栏（轨迹流）的数据来源。"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from core import store
from server import stream

router = APIRouter(tags=["tasks"])


class RunCreate(BaseModel):
    title: str = ""
    kind: str = "task"
    source: str = "console"
    meta: dict | None = None


@router.get("/tasks")
def list_tasks(limit: int = 50):
    """任务列表（按更新时间倒序）。"""
    return {"items": store.list_runs(limit=limit)}


@router.post("/tasks")
def create_task(body: RunCreate):
    """新建一个空任务（真正的执行由 agents 或对话触发）。"""
    return store.create(body.title, kind=body.kind, source=body.source, meta=body.meta)


@router.get("/tasks/{run_id}")
def get_task(run_id: str):
    summary = store.get(run_id)
    if not summary:
        raise HTTPException(status_code=404, detail="任务不存在")
    return summary


@router.get("/tasks/{run_id}/events")
def get_events(run_id: str, after: int = 0, limit: int = 2000):
    """增量拉取事件（after 传上次拿到的最大 seq）。"""
    if not store.get(run_id):
        raise HTTPException(status_code=404, detail="任务不存在")
    return {"items": store.events(run_id, after=after, limit=limit)}


@router.get("/tasks/{run_id}/events/stream")
def stream_events(run_id: str, after: int = 0):
    """实时跟随某个任务的轨迹（SSE）。"""
    if not store.get(run_id):
        raise HTTPException(status_code=404, detail="任务不存在")

    def alive():
        summary = store.get(run_id) or {}
        return summary.get("status") == "running"

    events = stream.follow(lambda cursor: store.events(run_id, after=cursor), alive, after=after)
    return StreamingResponse(stream.encode(events), media_type="text/event-stream",
                             headers=stream.SSE_HEADERS)


@router.get("/stream")
def global_stream(limit: int = 80):
    """全局事件流（跨任务，用于顶栏实时提示）；用轮询而非长连接，前端 5 秒拉一次即可。"""
    return {"items": store.tail_stream(limit=limit)}
