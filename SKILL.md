---
name: sec-assessment
description: 对已授权目标做安全评估：资产发现、端口与服务识别、Web 漏洞扫描、CVE 匹配与验证、口令审计、内网横向、等保合规检查。当用户要求扫描、巡检、盘点或渗透测试某个 IP、网段、站点，或要排查漏洞、核对等保基线时使用。仅限已获授权目标。
license: Apache-2.0
version: 2.8.0
---

# sec-assessment — 安全评估

43 个本地安全工具 + 一条「判定 → 执行 → 复核 → 交叉验证 → 报告」编排链，工具名与参数跟 8001 线上服务一致。
链上五个环节跑在同一个进程里、由 runner 顺序驱动，各环节独立调模型、可分别指定后端与模型名；某个环节探不通模型时只有它退到规则实现，整轮不中断。

**只对已获授权的目标使用。** 授权范围不明确时先问，不要挑一个地址就扫。

## 必问参数

发起任何扫描前，必须能确定**授权范围**：IP / CIDR / 站点 URL。用户没说清就问一句，例如：

> 请给出授权范围（IP / CIDR / 站点 URL），例如 192.168.x.0/24 或 https://example.com

编排链已内建这个行为：目标缺失时返回 `needs_clarification` 并停下，不会猜测。

## 路由表

| 用户想干什么 | 走哪里 |
|---|---|
| 直接描述任务，如「扫描 / 巡检 / 评估某目标」 | `python3 scripts/agents/runner.py "<任务原文>"`（默认逐行打进度，宿主据此显示过程；只要总结加 `--quiet`，只看判定加 `--dry-run`） |
| 由模型判定（默认走本机 Spark） | 上面加 `--backend spark-local`；不用模型加 `--no-model` |
| 给某个环节单独换模型 | `--planner-backend` / `--critic-backend` / `--verifier-backend`（配 `-model` 一起用），或 `--roles roles.json`；被推翻的条目见报告附录 D |
| 调用单个工具 | `python3 scripts/call.py <工具名> key=value`（直调会写进运行轨迹与审计链，管理端的工具页据此统计；不写加 `--no-record`） |
| 有哪些工具 / 某工具参数是什么 | `python3 scripts/call.py --list` / `--schema <工具名>` |
| 查某工具的完整参数与示例 | `references/tools.md` |
| 按渗透阶段整体推进 | `references/kill-chain.md` |
| 扫完要复核（压误报、确认可利用） | 任务里带上"复核"一词，编排链会自动接上 `vuln_verify` |
| 判断漏洞真伪、找利用细节 | `references/knowledge/` |
| 接到 MCP 客户端（FastGPT 等） | `python3 scripts/mcp_server.py`（默认 8010） |
| 环境缺哪些外部命令 | `python3 scripts/check_deps.py` |
| 更新 CVE / Exploit-DB / nuclei 规则库 | `python3 scripts/update_rules.py --all` |
| 打可提交的包（自动脱敏凭据） | `python3 scripts/pack_release.py`（`--no-data` 只出代码包） |
| 校验运行轨迹有没有被篡改 | `python3 scripts/verify_audit.py` |
| 离线自检（不依赖模型，74 项） | `python3 evals/smoke.py` |

## 什么时候调哪个工具

整轮任务交给编排链（`runner.py`），它按用户句式选剧本、自己串工具；只有单点问题才用 `call.py` 直调。
场景 → 剧本 → 工具的全表：`references/kill-chain.md`（速查表 + 分阶段用法），剧本原文在 `scripts/agents/catalog.py`。

三条固定规则：目标是 CIDR 时，要站点 URL 的工具（nuclei / nikto / dirb / sqlmap / wafw00f）自动让位；
高风险工具照常执行（只在计划与报告里标出"这一步有侵入性"）：任务里带"复核"就自动接上 `vuln_verify(report=$output)`。

复核（critic）是单一判读源，所以后面固定接一道交叉验证（verifier）：它拿同一批原始输出，逐条查证据能不能
回溯、定级有没有依据。证据在输出里找不到的（含引用了输出中不存在的 CVE）判为推翻，不进清单；证据在但撑不起
定级的判为存疑，进清单并标出来。这一层不依赖模型，四条客观检查全是规则实现。

## 报告

每轮任务结束都出报告，落在 `data/runtime/reports/<run_id>/`：封面、目录、正文六章（综述信息 / 风险类别 / 风险
清单 / 风险详情 / 脆弱凭据 / 参考标准）、附录四则与声明。风险等级换成中文档位并附处置时限，风险值按条目加权，
单主机与整个评估范围各分四档；被拦下的步骤与交叉验证推翻的条目各占一表，体例见 `references/reports.md`。

`report.html` 是主件（自包含单文件，离线可开，也能直接打印）；`report.docx` 与 `report.pdf` 由同一份数据
渲染，Word 走标准库拼 OOXML、不引第三方包，PDF 需装 weasyprint（`--no-pdf` 可关，没有就用浏览器打印 HTML）；
`report.md` / `report.json` 给工单系统与归档。`--dry-run` 只判定不执行，不出报告。

## 编排链（scripts/agents/）

五个环节各一个文件，`runner.py` 是入口，Word 渲染另有 `docx_writer.py`：

| 角色 | 文件 | 职责 |
|---|---|---|
| planner | `planner.py` | 自然语言任务 → 可执行步骤。优先用模型；无模型时按关键词剧本兜底，断网也能出计划 |
| executor | `executor.py` | 逐步执行、限时、单步失败不打断整轮，全程留痕 |
| critic | `critic.py` | 原始输出 → 结构化发现，压误报、定严重级 |
| verifier | `verifier.py` | 拿同一批原始输出复核复核员的结论，逐条判确认 / 存疑 / 推翻，推翻的留进附录 |
| reporter | `reporter.py` | 产出 Word / HTML / PDF / Markdown / JSON 报告，按交付体例排版，HTML 自包含可离线打开 |

环节级模型配置走 `runner.run(..., roles={"critic": {"backend": ..., "model": ...}})` 或命令行
`--critic-backend / --critic-model`（planner、verifier 同理）。换后端却没给模型名时留空，由后端取默认值。

`catalog.py` 放着工具清单、关键词剧本与安全分级（`safe` / `risky`），是判定与授权闸门的共同依据。剧本写的是
"哪些工具、什么参数、什么顺序"，命中多个剧本时按工具名去重；目标是网段（CIDR）时，需要站点 URL 的工具
（nuclei / nikto / dirb / sqlmap / wafw00f）会被跳过，不会拼出 `http://192.168.x.0/24` 这种地址。

跨步骤传参用两个占位符，由 `runner.py` 在执行前替换：

| 占位符 | 含义 |
|---|---|
| `$output` | 前面所有步骤的输出拼接（上限 8000 字） |
| `$prev` | 仅上一步的输出 |

`vuln_verify(report=$output)` 就是这么接上的 —— 复核步骤吃的是前面扫描的真实输出，不是字符串字面量。

## 安全边界

- **高风险工具照常执行，但一定标出来。** `hydra_bruteforce`、`sqlmap_full`、`impacket_*`、`kerberos_attack`、
  `persist_install`、`lateral_*`、`mimikatz_memory`、`cleanup_trace`、`file_extract` 等（利用/横向/窃取凭据/脱取数据）在计划与报告里都标 `risky`；**授权范围自己把关**。
- **端口扫描一律全端口。** 扫描路径统一走 `scripts/portscan.py`：先 1-65535 发现，再只对发现的端口做 `-sV`，不退回常用端口抽样。
  高噪声动作（masscan 全端口、nuclei 全模板、hydra 爆破）先小范围验证再放大；破坏性选项（sqlmap `--os-shell`、`persist_install`）需明确授权。
- 结果落盘前用 `vuln_verify` 复核，减少误报。
- 所有动作写入审计链；用 `python3 scripts/verify_audit.py` 校验是否被篡改（被改动则退出码 1 并指出是哪条）。
- 凭据不分发：工作目录可以放真实 `data/nvd_api_key.txt` 用于更新规则库，
  但**发布包由 `scripts/pack_release.py` 自动脱敏**并在打包时做密钥扫描，扫描不过直接中止。

## 自带资源

规则库随 skill 自带，**复制整个目录即可用**，路径由 `scripts/config.py` 从 skill 自身目录推导，装到哪都能跑。

| 资源 | 路径 | 用途 |
|---|---|---|
| CVE 库 39.3 万条 | `data/cve_cache_sm_por.sqlite` | `cve_match_sm_por` |
| Exploit-DB 4.7 万条 | `data/exploit-db/` | `exploit_search`、`poc_runner_sm_por` |
| nuclei 模板 1.37 万个（http/network/ssl/dns 四类） | `data/nuclei-templates/` | `nuclei_scan` |
| nmap OUI 表 | `data/oui/nmap-mac-prefixes` | MAC → 厂商识别 |

外部二进制（nmap / masscan / nuclei / sqlmap / hydra / nikto / ffuf / subfinder …）需目标机器自备，
用 `scripts/check_deps.py` 复核，清单见 `references/dependencies.md`。

## 维护

- 新增工具：在 `scripts/tools/` 放一个文件，用 `@tool(...)` 装饰器自注册，不用改服务端。
- 改完同步文档与指纹：`gen_tools_doc.py` 更新 `references/tools.md`，`gen_manifest.py` 重建 `MANIFEST.sha256`。
- 回归：`python3 evals/smoke.py`（离线确定性用例）；带模型的对照评测见 `evals/run.py`。

评测协议见 `BENCHMARK.md`，用例见 `evals/`，对外说明与安全声明见 `skill-card.md`。
