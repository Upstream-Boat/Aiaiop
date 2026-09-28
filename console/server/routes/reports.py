#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""报告接口 — 任务产出的报告文件清单与下载。

为什么不让前端直接拼路径、也不把报告目录挂成静态目录：对话界面在执行侧的另一台
机器上，它只能给出一个 URL 让人点；而在浏览器里能点的东西就得防"顺着 URL 往上爬"。
所以这里只认白名单里的文件名，且最终路径必须落在该任务的报告目录内。

下载的是 skill 收尾时落盘的正式报告（Word / PDF / 网页 / Markdown / JSON），
对话摘要里给的那几个链接就指到这里。
"""

import os

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from core import paths

router = APIRouter(tags=["reports"])

# 文件名 → (中文名, Content-Type)。只认这几个，别的一律 404 —— 白名单比黑名单可靠。
KINDS = {
    "report.docx": ("Word 报告",
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    "report.pdf": ("PDF 报告", "application/pdf"),
    "report.html": ("网页版报告", "text/html; charset=utf-8"),
    "report.md": ("Markdown 报告", "text/markdown; charset=utf-8"),
    "report.json": ("JSON 报告", "application/json; charset=utf-8"),
}


def _safe_run_id(run_id):
    """任务号只允许字母数字和 . _ -；出现别的字符直接拒绝（`.`/`..` 也不行）。"""
    if run_id in (".", "..") or not run_id:
        raise HTTPException(status_code=400, detail="任务号不合法")
    if any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in run_id):
        raise HTTPException(status_code=400, detail="任务号不合法")
    return run_id


def _report_dir(run_id):
    """把任务号变成报告目录，并确认结果没跑出 REPORTS_DIR 之外。"""
    base = os.path.realpath(paths.REPORTS_DIR)
    target = os.path.realpath(paths.report_dir(_safe_run_id(run_id)))
    if target != base and not target.startswith(base + os.sep):
        raise HTTPException(status_code=400, detail="任务号不合法")
    return target


@router.get("/reports/{run_id}")
def list_reports(run_id: str):
    """某个任务产出了哪些报告（对话界面和控制台都用它判断能不能给下载链接）。"""
    directory = _report_dir(run_id)
    items = []
    for name, (label, _ctype) in KINDS.items():
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        stat = os.stat(path)
        items.append({
            "name": name,
            "label": label,
            "size": stat.st_size,
            "updated_at": int(stat.st_mtime),
            "url": "/api/reports/%s/download/%s" % (run_id, name),
        })
    return {"run_id": run_id, "items": items}


@router.get("/reports/{run_id}/download/{name}")
def download_report(run_id: str, name: str):
    """下载单个报告文件。name 必须是白名单里的名字，且不许带任何路径成分。"""
    directory = _report_dir(run_id)
    if name not in KINDS or os.path.basename(name) != name:
        raise HTTPException(status_code=404, detail="没有这个报告文件")
    path = os.path.join(directory, name)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="报告还没生成")
    label, ctype = KINDS[name]
    return FileResponse(path, media_type=ctype, filename=name,
                        headers={"Content-Disposition": 'attachment; filename="%s"' % name})
