#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""控制台后端入口 — 组装路由、挂载前端静态目录、启动 uvicorn。

    python3 console/server/app.py --port 8787                  # 只本机可访问
    python3 console/server/app.py --host 0.0.0.0 --port 8787   # 演示机/局域网可访问

目录关系（两种摆法都能跑）：

    开发目录（skill 与 console 平级）      发布包（console 装在 skill 内）
    ├── sec_assessment/                    sec-assessment/
    ├── console/server/                    ├── SKILL.md  scripts/  data/
    └── console/web/                       └── console/server/
                                               console/web/

skill 位置按顺序找：环境变量 SEC_ASSESSMENT_HOME → console 上一级的 sec_assessment/ →
console 上一级自身（发布包里 console 就装在 skill 目录内）。认目录的依据是
scripts/config.py 在不在。
"""

import argparse
import os
import sys

CONSOLE_DIR = os.path.dirname(os.path.abspath(__file__))          # <skill>/console/server
PROJECT_DIR = os.path.dirname(os.path.dirname(CONSOLE_DIR))       # <skill>
def _is_skill(path):
    """判定依据只有一个：这个目录里有没有 scripts/config.py。"""
    return os.path.isfile(os.path.join(path, "scripts", "config.py"))


def _find_skill_home():
    """定位 skill 目录：环境变量 → 同级的 sec_assessment/ 或 sec-assessment/ → 上一级自身。

    开发目录里叫 sec_assessment（下划线），交付包里叫 sec-assessment（连字符），
    两种都得认 —— 认错了控制台就是"连不上 skill"，页面上全是空数据。
    """
    env = os.environ.get("SEC_ASSESSMENT_HOME")
    if env:
        return env
    for name in ("sec_assessment", "sec-assessment"):
        candidate = os.path.join(PROJECT_DIR, name)
        if _is_skill(candidate):
            return candidate
    if _is_skill(PROJECT_DIR):          # 打包时 console/ 被塞进 skill 目录内的那种摆法
        return PROJECT_DIR
    return os.path.join(PROJECT_DIR, "sec_assessment")


SKILL_HOME = _find_skill_home()
WEB_DIR = os.path.join(os.path.dirname(CONSOLE_DIR), "web")       # <skill>/console/web

sys.path.insert(0, os.path.dirname(CONSOLE_DIR))                   # 让 server.* 可导入
sys.path.insert(0, os.path.join(SKILL_HOME, "scripts"))            # 让 config/core/llm 可导入
os.environ.setdefault("SEC_ASSESSMENT_HOME", SKILL_HOME)

from fastapi import FastAPI  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402

import config  # noqa: E402
from core import paths  # noqa: E402
from server.routes import audit as audit_routes  # noqa: E402
from server.routes import calls as call_routes  # noqa: E402
from server.routes import deps as deps_routes  # noqa: E402
from server.routes import nvd as nvd_routes  # noqa: E402
from server.routes import reports as report_routes  # noqa: E402
from server.routes import rules as rules_routes  # noqa: E402
from server.routes import tasks as task_routes  # noqa: E402

UI_DIR = WEB_DIR
# 控制台自己的版本：前端页脚也显示同一个串。两边不一致 = 后端是改动前的旧进程，
# 这正是"页面上的接口全 404、看着像没数据"的常见原因。
CONSOLE_BUILD = "v2026-09-28.1"


def create_app():
    paths.ensure_dirs()
    # 上次若是被重启打断在更新途中，先把更新日志补一句收尾说明
    rules_routes.log_heal()
    # 规则库定时更新：调度在控制台进程里跑，不依赖有没有人开着页面
    rules_routes.start_scheduler()
    app = FastAPI(title="工具管理台", docs_url="/api/docs",
                  openapi_url="/api/openapi.json")

    @app.get("/api/health")
    def health():
        """健康检查：前端启动时用它确认后端在跑，并显示生效的目录。"""
        import time

        return {"ok": True, "build": CONSOLE_BUILD, "skill_home": config.SKILL_HOME,
                "runtime_dir": paths.RUNTIME_DIR, "time": time.strftime("%Y-%m-%d %H:%M:%S")}

    # 演示时前端可能从别的端口打开（例如直接双击 index.html），放开本地跨域
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                       allow_headers=["*"])
    # 路由按"这个工具的管理台要回答什么"划分：哪个工具被调了（calls）/
    # 任务的完整轨迹（tasks）/ 留痕（audit）/ 判断依据（rules，含定时更新）/
    # 唯一凭据（nvd）/ 依赖与健康（deps）。
    # 没有报告页（不替宿主 Agent 做报告）；但报告文件要能下载 —— 对话摘要里给的
    # 链接落到 reports 路由上，否则点开就是 404。
    # 没有模型与算力：skill 里 nvidia-smi 出现 0 次，模型后端也不在它自己声明的
    # 可选配置里 —— 那是宿主 Agent 那一层的事。
    for module in (call_routes, task_routes, audit_routes, rules_routes,
                   nvd_routes, deps_routes, report_routes):
        app.include_router(module.router, prefix="/api")
    # 静态资源强制"每次校验"。
    # 踩过的坑：改完前端（例如修好导航）后，浏览器标签页里跑的还是旧 JS，
    # 页面看着正常、点哪都没反应，而服务端日志里只有 `GET / 304` —— 浏览器
    # 认为缓存还新鲜，压根没重新请求 /js/app.js。演示时最忌讳这种"看起来是好的"，
    # 所以这里不让浏览器自作主张：每次都带 ETag 回源，没变就 304（不浪费带宽），
    # 变了立刻拿到新版本。
    @app.middleware("http")
    async def no_cache_for_static(request, call_next):
        response = await call_next(request)
        if not request.url.path.startswith("/api"):
            response.headers["Cache-Control"] = "no-cache, must-revalidate"
        return response

    if os.path.isdir(UI_DIR):
        # html=True：访问 / 时返回 index.html
        app.mount("/", StaticFiles(directory=UI_DIR, html=True), name="ui")
    return app


app = create_app()


def main():
    parser = argparse.ArgumentParser(description="工具管理台后端")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--reload", action="store_true", help="改后端代码自动重载（开发用）")
    args = parser.parse_args()
    import uvicorn

    print("控制台: http://%s:%d/   （接口文档 /api/docs）" % (args.host, args.port))
    print("skill : %s" % SKILL_HOME)
    if not os.path.isfile(os.path.join(SKILL_HOME, "scripts", "config.py")):
        print("        [警告] 这个目录里没有 scripts/config.py，可能指错了 skill")
    if args.reload:
        # app_dir 让 uvicorn 的子进程也能找到 server 包
        uvicorn.run("server.app:app", host=args.host, port=args.port,
                    reload=True, app_dir=os.path.dirname(CONSOLE_DIR), log_level="info")
    else:
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
