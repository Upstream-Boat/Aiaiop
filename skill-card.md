---
name: sec-assessment
skill_version: 2.8.0
card_version: 1.0.0
updated: 2026-09-27
license: Apache-2.0
---

# Skill Card — sec-assessment

> 给人看的信任记录。扫描报告告诉审查者机器查到了什么，签名告诉用户文件变没变，
> 这张卡告诉人类自己接受了什么。
>
> 字段口径沿用 NVIDIA-Verified Agent Skills 的 Skill Card 模板：
> `Description / Use Case` · `Owner` · `License / Deployment Geography` ·
> `Requirements / Dependencies` · `Risks & Mitigations` · `References / Version / Ethical`。

---

## 1. Description / Use Case — 它做什么、给谁用

**它做什么.** 对**已获授权**的目标执行资产发现、端口与服务识别、Web 漏洞检测、CVE 匹配与验证、
口令强度审计、内网可达性检查、等保合规对照，并输出可复核的结论。
共 **43 个工具**：`scripts/tools/` 下 25 个，一个工具一个文件；`scripts/external/` 下 11 个模块，
带出另外 18 个工具（巡检模块自己就带着网段普查、MAC 厂商识别、空闲 IP 扫描），
按 kill-chain 阶段组织。

**给谁用.**

| 角色 | 场景 |
| --- | --- |
| 企业安全团队 | 内网资产盘点、暴露面收敛、等保 2.0 自查整改 |
| 渗透测试工程师 | 授权范围内的一次完整评估，按阶段出结论而不是堆工具输出 |
| 甲方安全运营 | 漏洞复现确认（`vuln_verify`）以降低扫描器误报带来的无效工单 |

**什么时候触发.** 出现"资产发现 / 端口扫描 / 漏洞扫描 / CVE 匹配 / 口令审计 / 内网横向 /
等保合规"这类明确任务时。**不适用**于：对未授权目标的任何扫描、真实入侵、数据窃取、
对生产环境的破坏性操作。

---

## 2. Owner — 谁对它有责任

| 项 | 值 |
| --- | --- |
| 归属单位 | 指尖未来（北京）信息技术有限公司 |
| 维护者 | 项目维护组（GitHub：`Upstream-Boat`） |
| 维护者联系方式 | `Upstream-Boat@users.noreply.github.com`，或在本仓库提 Issue |
| 上游来源 | 自研。工具契约与本单位内部服务接口保持一致，脚本实现为本项目独立编写 |
| 责任边界 | 使用者对是否具备授权、所选目标、传入参数与使用后果自负其责；维护者仅对发布内容的真实性负责，不对使用行为及后果承担任何责任（详见 `NOTICE` 与 README 免责声明） |

---

## 3. License / Deployment Geography — 使用与再分发条款、适用地域

| 项 | 值 |
| --- | --- |
| 许可证 | Apache License 2.0（见 `LICENSE`） |
| 再分发 | 允许，需保留 `LICENSE`、`NOTICE` 与本卡片 |
| 适用地域 | 中国大陆境内为主；本地运行，**目标数据与扫描结果不出本机** |
| 数据出境 | 无。默认不向任何外部服务回传目标信息 |

**注意.** `data/exploit-db/` 与 `data/nuclei-templates/` 为第三方上游内容，各自遵循其原始许可证；
`data/cve_cache_sm_por.sqlite` 由 NVD 公开数据构建。再分发前请复核这三项的上游条款。

---

## 4. Requirements / Dependencies — 需要什么凭据

**运行时.** Python 3.9+，仅标准库即可启动 `call.py` / `mcp_server.py`（现场离线 ARM64 单机也能跑）。

**外部二进制（按需，缺哪个由 `scripts/check_deps.py` 提示安装命令）.**

| 域 | 二进制 |
| --- | --- |
| 扫描 | `nmap` `masscan` `nuclei` `nikto` `ffuf` `gobuster` `subfinder` `wafw00f` |
| 利用/验证 | `sqlmap` `searchsploit` `msfconsole` `msfvenom` |
| 口令 | `hydra` `hashcat` |
| 内网 | `smbmap` `impacket-*` `chisel` `tshark` |

`check_deps.py` 不只查"文件在不在"，还会**实际拉起一次进程**看输出：
命令躺在 PATH 里但缺运行时依赖时（例如 nikto 缺 Perl 模块、容器里缺 glibc），
它会标成"存在但不可用"并返回非 0，而不是让上层以为扫描已经跑过了。

**规则库的两层更新口径.**

| 层 | 内容 | 怎么更新 |
| --- | --- | --- |
| 数据规则库 | CVE / Exploit-DB / nuclei 模板 / OUI | 控制台"规则库"页或 `scripts/update_rules.py`；现场无网时用离线包导入 |
| 判定规则 | 端口风险定级、关键发现信号、设备分类、剧本关键词 | 随 skill 代码走（`scripts/agents/critic.py`、`scripts/external/network_inspection.py`、`scripts/agents/catalog.py`），改动有 `evals/smoke.py` 守着 |

数据层更新会写审计链：规则库是判断依据，"谁在什么时候换了依据"必须可查。

**随 skill 自带的规则库（复制目录即可用，无需另外配路径）.**

| 资源 | 路径 |
| --- | --- |
| CVE 库 39.3 万条 / 269MB | `data/cve_cache_sm_por.sqlite` |
| Exploit-DB 4.7 万条 | `data/exploit-db/` |
| nuclei 模板 1.37 万个（http / network / ssl / dns 四类参与扫描） | `data/nuclei-templates/` |
| nmap OUI 表 | `data/oui/nmap-mac-prefixes` |

**凭据（全部可选；不配则相关能力自动跳过，不影响其余工具）.**

| 环境变量 | 用途 |
| --- | --- |
| `GPUSTACK_BASE_URL` / `GPUSTACK_API_KEY` | 内网算力集群，OpenAI 兼容端点 |
| `SPARK_LLM_BASE_URL` | DGX Spark 本机模型（默认 `http://127.0.0.1:11435/v1`） |
| `STEPFUN_BASE_URL` / `STEPFUN_API_KEY` | 阶跃星辰模型端点 |
| `NVD_API_KEY` | 提高 CVE 库更新的速率上限 |
| `SEC_ASSESSMENT_AUDIT_SECRET` | 审计链密钥；不设则本地生成 `data/runtime/audit/.chain-secret` |

**权限.** 需要读取自身目录、写入 `data/runtime/`、发起网络连接（扫描目标与更新规则库）。
**不需要** root；提权类工具（`mimikatz_memory`、`persist_install`）自行要求目标侧管理员权限。

---

## 5. Risks & Mitigations — 可能出什么问题、如何缓解

| # | 风险 | 缓解措施（已内嵌，不靠提示词临时叮嘱） |
| --- | --- | --- |
| R1 | **对未授权目标使用** —— 本 skill 具备真实扫描与利用能力 | ① `SKILL.md` 使用约束首条即"仅对已获授权目标"；② `references/kill-chain.md` 第一步就是确认授权范围并把目标记为 `$T`；③ `agents/openai.yaml` 的 `default_prompt` 写死"已授权目标" |
| R2 | **高危能力外溢** —— 直接利用 / 横向 / 持久化 | 高风险工具在 SKILL.md 单独点名：`hydra_bruteforce` `impacket_*` `kerberos_attack` `persist_install` `lateral_*` `mimikatz_memory` `msf_exploit`；破坏性选项（`sqlmap_full` 的 `os_shell` / `dump_all`）必须取得明确授权后再执行 |
| R3 | **凭据泄漏** —— 密钥进入日志、报告或界面 | ① `llm/backends.py` 的 `list_backends()` 永不回传密钥明文，只给 `has_key` 布尔；② `llm/client.py` 的错误信息统一脱敏，抹掉 `Bearer` 串与长令牌 |
| R4 | **审计不可信** —— 轨迹被悄悄改写 | ① `core/audit.py` 用 HMAC-SHA256 哈希链，每行把上一行 hash 纳入计算；② 校验时区分"篡改嫌疑内容 / 换过密钥 / 算法降级"与"断链"，不混为一谈；③ 链头指纹追加到库外 `anchors.jsonl`，整体重算也能发现；④ `core/store.py` 轨迹为 append-only JSONL |
| R5 | **判断依据被替换** —— 规则库被人换掉 | 每次更新或离线导入规则库都往审计链写一条记录，谁在什么时候换了依据可查（`core/rules.py`） |
| R6 | **扫描噪声打垮目标** | 端口扫描默认全端口（1-65535），单机是分钟级、整段是小时级，且更容易被对端防扫描策略拉黑；发现用 `-T5` 快速预设 +
单机 `--host-timeout`，`nuclei` 全模板、`hydra` 爆破等高噪声操作先小范围验证再放大，所有工具支持 `timeout` 控时 |
| R7 | **误报污染结论** | 结论落盘前先用 `vuln_verify` 复现确认，排除扫描器误报 |

**已知短板（如实声明）.**

- `data/runtime/` 默认落在 skill 目录内，多用户共享部署时应改用 `SEC_ASSESSMENT_RUNTIME` 指向独立位置。
- 审计链密钥默认自动生成并存在同目录；对"防内部人篡改"要求高的场景应改为外部注入 `SEC_ASSESSMENT_AUDIT_SECRET`。
- `pip install model-signing` 未做，`skill.oms.sig` 一栏见第 6 节说明。

---

## 6. References / Version / Ethical — 支撑材料、版本、治理考量

**支撑材料.**

| 材料 | 位置 |
| --- | --- |
| 评测结论与协议 | `BENCHMARK.md` |
| 评测用例（含负样本拒绝检查） | `evals/evals.json` |
| 架构与分层说明 | `docs/ARCHITECTURE.md`（仓库根） |
| 工具清单与参数 | `references/tools.md` |
| 分阶段流程 | `references/kill-chain.md` |
| 漏洞判定知识库 | `references/knowledge/` |
| 依赖与规则库清单 | `references/dependencies.md` |

**版本.**

| 项 | 值 |
| --- | --- |
| skill 版本 | 2.8.0（2.7.0 之后：控制台能看到运行中的增量原文；nikto 多目标不再被误判为失败；算力归因落进轨迹与报告） |
| 工具契约对齐 | 8001 生产服务 v2.1（工具名、参数名、行为一致） |
| 语料快照 | CVE 库 / Exploit-DB / nuclei 模板见 `references/dependencies.md` |
| 更新方式 | `python3 scripts/update_rules.py --all` |

**修订记录.**（只记会影响交付物内容的事，不记账面上的小改）

| 日期 | 版本 | 改了什么 |
| --- | --- | --- |
| 2026-09-22 | 2.4.0 | 43 个工具与「判定→执行→复核→报告」四角色编排链定稿；跑完第一轮双 Agent 评测（原始记录见 `evals/agent-results/`） |
| 2026-09-23 | 2.4.1 | 文档口径对齐（清单 97 / 自检 45 / 用例 19）；工具文件批注重写；管理台界面定稿；打包默认改 zip |
| 2026-09-27 | 2.8.0 | 控制台的「原始输出」改成运行中就能看：executor 一边执行一边把工具原文写进 `<run>/outputs/step-N-tool.txt`，控制台按 1 秒轮询读这份正在增长的文件，输出是一点点长出来的，不再等整条命令跑完才一次性出现（收尾仍用完整版覆盖同一个文件名）。`nikto_scan` 的多目标判定从「有一个端点没 Web 服务就整步失败」改成四态（`ok` / `partial` / `unreachable` / `error`）：不可达的端口记「该端口无 Web 服务、不计失败」，只有全部端点都不可达才报失败 —— 实测同一批 6 个目标从「失败（129s）」变成「完成（129s）」。新增算力归因 `llm/gpu.py`：在模型调用前后采样本机或远程 GPU 的利用率 / 功耗 / 温度与显存占用，写进轨迹事件与报告的「算力环境」行（数据源可选本机 `nvidia-smi`、`GPU_METRICS_SSH` 或带 token 的只读端点）。本地模型输出解析改为只吃第一个完整 JSON 对象（`utils.loads_first_json`），修掉「JSON 后面跟一句解释就整份丢弃」导致 planner / critic / verifier 全部退回规则实现的坑；判定提示词改用真实工具名并注明「只是格式示意」，planner 增加工具名校验、critic 丢弃无证据条目。`web` 剧本补上 CVE 匹配（`service_identify` 之后紧跟 `cve_match_sm_por(data=$output)`，用它刚拿到的 服务|版本 行匹配已知 CVE，覆盖 nuclei 模板扫不到的老组件），同时收紧匹配口径：产品名只做精确匹配（此前 `LIKE %nginx%` 会把 Nginx-UI、`LIKE %ssh%` 会把 wolfSSH/libssh 的洞当成目标命中，报告里会出现「OpenSSH 8.0 命中 wolfSSH 漏洞」这种自相矛盾的条目），并从漏洞描述里读版本区间（before / prior to / X and earlier / A through B），把探测版本落不到范围内的条目丢掉、能读到区间的标「版本命中」、读不出的标「版本待确认」，复核环节据此分开处理。离线自检仍是 74 项。 |
| 2026-09-24 | 2.7.0 | 编排链默认逐行输出进度：`runner.py` 把判定 / 执行 / 复核 / 交叉验证 / 报告各推进度摘要（带时间戳、立即刷出）同时打到 stdout，宿主与终端据此显示过程；`--quiet` 回到只在收尾出总结。轨迹与审计链的内容不变，离线自检 54 → 56 项。另把两个工具的失败信息改成能直接照做的：`hashcat_bruteforce` 开跑前先看 hashcat 在不在、本机有没有 OpenCL ICD、`hash_file` / `wordlist` 存不存在，缺什么直接说缺什么（原先只抛 `OpenCL/: No such file or directory`）；`revshell_handler` 把 `timeout` 到点掐掉监听（returncode 124）认成正常收尾而非执行失败，并点明这一轮有没有连进来。端口扫描统一收口到新增的 `scripts/portscan.py`：先 1-65535 全端口发现、再只对发现的端口做 `-sV`，`network_inspect`、`service_identify`（只给裸 IP 时）、`ip_usage_report`、`lateral_portscan`、`vuln_verify`、`exploit_search` 六条路径原先各自用 `--top-ports 100` / `--top-ports 50` / 23 个常用端口 / 8 个常用端口抽样，没探的端口不会进报告，现改为全端口。`call.py` 直调补写运行轨迹与审计链（同一天的直调归到一个 `kind=manual` 任务，一次调用一个步骤，`--no-record` 可关）：此前只有编排链写 `data/runtime/runs/<run_id>/events.jsonl`，管理端工具页看不到任何命令行直调，与「所有动作写入审计链」的说法不符。`hashcat_bruteforce` 增加内置 CPU 字典回退（标准库逐候选比对，缺 hashcat 或本机没有 OpenCL 运行时/设备时自动启用，回退会明说引擎是谁、扫了多少条候选；实测 20 万条字典 0.20s，约 103 万条/秒）：原实现遇到这两种情况只能报失败，而测评与交付环境都是KVM 虚拟机（显卡是 QEMU 虚拟卡、仓库里也没有 pocl 这类 CPU 版运行时）。离线自检 56 → 74 项 |
| 2026-09-24 | 2.6.0 | 新增交叉验证环节 `verifier.py`：拿同一批原始工具输出逐条复核复核员的结论，证据不可回溯或引用了输出中不存在的 CVE 判为推翻（不进风险清单，记入报告附录 D），高危定级无依据判为存疑（进清单并标注），跨工具重复判为存疑；规则模式四条客观检查不依赖模型。编排链据此改为五环节，`runner.py` 支持环节级模型配置（`--planner-backend` / `--critic-backend` / `--verifier-backend` 等开关与 `--roles` 配置文件），可用性探测按后端逐角色进行，单个角色探不通只影响它自己；离线自检 45 → 54 项 |
| 2026-09-24 | 2.5.0 | 报告改为商用扫描器体例并新增 Word 交付件：版式（A4 / 页边距 / 配色 / 表头填充）取自商用报告源文件，正文六章改为综述信息 / 风险类别 / 风险清单 / 风险详情 / 脆弱凭据 / 参考标准；风险值按条目加权计算，主机与网络两级分档，扫网段时清单与详情带"评估对象"列；新增 `docx_writer.py`（标准库拼 OOXML，不引第三方包），`runner.py` 传任务开始时间并回传四份产物路径 |

**签名状态（如实声明）.**

`skill.oms.sig` 由 NVIDIA Agentic Capabilities 根证书签发，属官方发布流水线产物，自研 skill 无法自行造出。
本 skill 目前的完整性保障走**另一条等价路径**：内容指纹清单 `MANIFEST.sha256`。

```bash
cd Aiaiop
sha256sum -c MANIFEST.sha256      # 104 个文件全部校验；改动任一行都会 FAILED
```

**覆盖范围**：`SKILL.md` / `skill-card.md` / `BENCHMARK.md` / `LICENSE` / `NOTICE` /
`install.sh` / `agents/` / `scripts/` / `references/` / `evals/`（共 104 个文件）。

**不覆盖**：`data/`（第三方规则库，各自有上游许可证与校验）、`data/runtime/`（运行时产物，本就应当变化）。

**已验证**：往 `SKILL.md` 追加一行后，校验立刻报 `SKILL.md: FAILED`；还原后 104 项全 OK。

> 与官方签名的差别要讲清楚：本清单能证明"内容与发布时一致"，但**清单本身与被校验内容在同一目录**，
> 因此它防的是传输与存储环节的意外或偷改，防不住"连清单一起改"。要补上这一点，需要把
> `MANIFEST.sha256` 的哈希值在仓库外另存（如发布时的 CI 日志、纸质记录），本 skill 未做，如实声明。

**治理考量（Ethical）.**

- **只做授权范围内的事.** 该 skill 面向合法安全评估。未获书面授权的目标，一律不碰。
- **最小必要.** 只采集评估必需的信息；`db_data_extract`、`file_extract` 等读取类工具需在授权范围内使用。
- **留痕优先于隐蔽.** 审计链默认开启；`cleanup_trace` 属敏感工具，仅限获得明确授权的场景。
- **不代用户决策.** 高风险动作不猜测参数、不自动升级强度；关键参数不全时先问用户。
- **输出可复核.** 结论必须能追溯到具体事件与原始输出，而不是"某工具说它有问题"。

---

*本卡片随 skill 一同分发。字段口径：NVIDIA-Verified Agent Skills Skill Card 模板。*
