# console/ — sec-assessment 本地管理台

skill 的**前后端控制台**，随 skill 一起分发。零构建、零 CDN：后端 FastAPI，
前端 Vue 3（运行时 `web/vendor/vue.global.prod.js` 本地自带），断网也能直接打开。

## 它回答什么

四个页签，对应 skill 的四类留痕 —— 都是**读**，不替 skill 做决定：

| 页签 | 回答的问题 | 数据来源 |
|---|---|---|
| **任务台** | 这一轮跑到哪了？每步的输入输出是什么？ | `data/runtime/` 的运行轨迹；SSE 实时推送 |
| **工具状态** | 43 个工具现在能不能用？缺哪个依赖、缺哪个二进制？ | `scripts/check_deps.py` 的探测结果 |
| **规则库** | CVE 库 / Exploit-DB / nuclei 模板各是什么版本？怎么更新？ | `data/` 下的三套规则库 + `scripts/update_rules.py` |
| **审计链** | 谁在什么时候调了什么？链有没有被动过？ | `scripts/core/audit.py` 的哈希链；可现场演示「篡改 → 校验失败 → 还原」 |

## 界面

**规则库** —— 四套库的条数、体积、版本，单库更新 / 全部更新 / 定时更新，更新输出实时落日志：

![规则库页面](docs/rules.png)

**工具状态** —— 43 个工具的可用性、外部命令就位情况，右侧是选中工具的参数与实现文件：

![工具状态页面](docs/tools.png)

## 起服务

```bash
python3 console/server/app.py --port 8787                  # 只有本机能访问
python3 console/server/app.py --host 0.0.0.0 --port 8787   # 演示机 / 局域网可访问
```

浏览器打开 `http://<地址>:8787/`。页脚显示的构建号应与 `/api/health` 返回的 `build`
一致 —— 两边不一致说明后端还是改动前的旧进程（这是"页面点哪都没反应"的常见原因）。

依赖：

```bash
pip install fastapi uvicorn pydantic
```

## 它是怎么找到 skill 的

按顺序探测，判定依据只有一条：这个目录里有没有 `scripts/config.py`。

1. 环境变量 `SEC_ASSESSMENT_HOME`
2. `console/` 上一级的 `sec_assessment/` 或 `sec-assessment/`
3. `console/` 上一级自身 —— **本仓库就是这种摆法**（`console/` 装在 skill 目录内）

所以从仓库根目录直接起就能跑，不需要另外配路径。

## 冒烟测试

```bash
python3 console/tests/ui_smoke.py                        # 四个页签点得动吗（默认 :8787）
python3 console/tests/ui_smoke.py --base http://<地址>:8787/
python3 console/tests/ui_full_audit.py                   # 全量交互
```

需要 Playwright：`pip install playwright && playwright install chromium`。

## 接口

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/api/health` | 健康检查：构建号、解析到的 skill 目录、运行时目录 |
| GET | `/api/tasks`、`/api/tasks/{run_id}` | 任务列表与单任务轨迹 |
| GET | `/api/tasks/{run_id}/events/stream` | 任务事件 SSE 实时推送 |
| GET | `/api/tools` | 43 个工具的注册表与参数 schema |
| GET | `/api/calls` | 工具调用记录（可按"不看这条"隐藏） |
| GET/POST | `/api/audit`、`/api/audit/verify` | 审计链查询与校验 |
| POST | `/api/audit/tamper-demo`、`/api/audit/tamper-restore` | 篡改演示与还原 |
| GET/POST | `/api/rules`、`/api/rules/update` | 规则库版本与手动更新 |
| GET/POST | `/api/nvd`、`/api/nvd/key` | NVD 密钥状态与写入（**只写不读**，永不回传明文） |
| GET | `/api/deps` | 外部依赖与二进制探测 |
| GET | `/api/reports/{run_id}/download/{name}` | 报告文件下载 |

## 目录

```
console/
├── server/
│   ├── app.py               # 入口：组装路由、挂载静态目录、起 uvicorn
│   ├── stream.py            # 任务事件的 SSE 推送
│   └── routes/              # tasks / tools / calls / rules / audit / nvd / deps / reports
├── web/                     # Vue 3 单页应用（无构建步骤）
│   ├── index.html
│   ├── css/                 # 令牌 → 基础 → 布局 → 组件 → 各视图
│   ├── js/                  # api / events / format / router / views
│   └── vendor/              # vue.global.prod.js（本地自带，见 vendor/README.md）
├── tests/                   # UI 冒烟与全量交互测试
└── data/                    # 控制台自己的运行时状态（不入库）
```

## 边界

- **没有报告页** —— 报告由 skill 的 `reporter` 环节产出，管理台只负责下载。
- **没有模型与算力页** —— 模型后端在宿主 Agent 那一层，不属于 skill。
- **不发数据到外部** —— 前端零 CDN，后端默认只监听 127.0.0.1。
- **凭据只写不读** —— NVD 密钥写入 `data/nvd_api_key.txt`，接口只回 `has_key`，不回明文。
