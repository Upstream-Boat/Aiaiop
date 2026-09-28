# 依赖与规则库

**结论：规则库按 skill 自身目录自动寻址，装到任何路径都能直接跑，不需要配置路径。**

> **先说清楚 Git 仓库和发布包的区别。** 本仓库（`git clone` 下来的那份）**只带
> `data/oui/` 的 MAC 厂商表**，三套大规则库（合计约 650 MB）**不在仓库里**，
> 首次部署要拉一次：
>
> ```bash
> python3 scripts/update_rules.py --all
> ```
>
> 下面第一节的表格描述的是**打好包之后的产物** —— `scripts/pack_release.py` 会把规则库
> 一并打进去，那种形态下确实"复制整个目录即可"。拉取方式与当前版本见 `data/README.md`。

所有资源路径由 `scripts/config.py` 以 skill 自身目录为基准自动推导
（`SKILL_HOME = <skill 根目录>`），因此 skill 装到任何路径、任何机器都能直接跑。
只有「外部二进制」需要目标机器自备。

## 一、资源清单（发布包形态：随 skill 一起复制）

| 资源 | 位置 | 体积 | 用途 | 更新方式 |
|---|---|---|---|---|
| CVE 库 | `data/cve_cache_sm_por.sqlite` | 269 MB | `cve_match_sm_por` 服务/版本 → CVE 匹配（39.3 万条） | `python3 scripts/update_rules.py --cve` |
| Exploit-DB | `data/exploit-db/` | 295 MB | `exploit_search`、`poc_runner_sm_por`（含 4.7 万条 EXP） | `python3 scripts/update_rules.py --exploit-db` |
| searchsploit | `data/exploit-db/searchsploit` | — | Exploit-DB 检索入口，随上面自带 | 同上 |
| nuclei 模板 | `data/nuclei-templates/` | 85 MB | `nuclei_scan`（13742 个模板） | `python3 scripts/update_rules.py --nuclei` |
| nmap OUI 表 | `data/oui/nmap-mac-prefixes` | 1 MB | MAC → 厂商识别（`network_inspection`） | 需要时重新复制 nmap 的同名文件 |
| 知识库 | `references/knowledge/` | — | OWASP / Payloads / 等保 2.0 / CIS 等 11 份文档 | 手工维护 |
| NVD API Key | `data/nvd_api_key.txt` | — | 加速 CVE 库更新（可选） | **包里只有占位示例**，写入自己的 key 或设环境变量 |

### 关于 NVD API Key（凭据不分发）

工作目录里的 `data/nvd_api_key.txt` 可以放真实 key（更新 CVE 库要用）。
**发布包由 `scripts/pack_release.py` 自动脱敏**：打包时会把它替换成占位串 `your-nvd-api-key-here`，
并对整棵产物树做密钥扫描，扫出可疑内容就直接中止，不会产出脏包。

`scripts/config.py` 会识别占位写法并当作"未配置"，所以占位文件不会导致 403。

需要加速 CVE 库更新时（无 key 也能跑，只是 NVD 限速更严），二选一：

```bash
export NVD_API_KEY=<你自己的 key>        # 优先读取
# 或
printf '%s\n' '<你自己的 key>' > data/nvd_api_key.txt
```

读取优先级：环境变量 `NVD_API_KEY` > `data/nvd_api_key.txt`；两处都是占位或为空时按"未配置"处理。

`nuclei_scan` 与 `exploit_search` 都**显式**使用上述自带副本，不依赖系统里是否另装了
`~/nuclei-templates` 或 `/opt/exploit-db`。

从发布包解出来，`data/` 合计约 **490 MB**（开发目录里是 935 MB，差的 299 MB 是 Exploit-DB
那份 `.git` 历史 —— 上游仓库的提交记录，跑扫描一行都用不到，打包时直接剔掉了；
要自己更新 Exploit-DB 的话，`update_rules.py` 会重新拉一份带 `.git` 的）。

嫌占地方可以用 `./install.sh --link` 改成软链接，几乎不占额外空间。

## 二、外部二进制（需目标机器自备）

只装实际要用的即可，缺哪个工具 `python3 scripts/check_deps.py` 会列出来。

| 分类 | 命令 |
|---|---|
| 扫描 | nmap、masscan、nuclei、nikto、ffuf、gobuster、subfinder、wafw00f |
| Web/注入 | sqlmap |
| 口令 | hydra、hashcat、sshpass |
| Windows/内网 | impacket（secretsdump/GetNPUsers/GetUserSPNs/psexec）、smbmap、chisel |
| 流量 | tshark（或 tcpdump）、socat、nc |
| 基础 | curl、dig、whois、perl |
| 框架 | Metasploit（msfconsole / msfvenom），默认探测 `/opt/metasploit-framework/bin` |

Python 侧只用标准库；`dirb_scan` 需要 `requests`（字典为内置，无外部 wordlist 依赖）。

**报告 Word / PDF（可选）**：任务结束必出 `report.html`（自包含单文件）与 `report.docx`。
Word 那份由 `scripts/agents/docx_writer.py` 用标准库拼 OOXML 写出（`zipfile` + 手写 XML），
**不需要 python-docx，也不产生任何 pip 依赖**，装了 WPS 或 Office 就能打开、续编、盖章流程走内部系统。

`report.pdf` 需要额外装库：机器上有 `weasyprint`（`pip install weasyprint`，还依赖 pango/cairo
系统库）时，会顺手把同一份 HTML 转成 PDF。没装也不影响：`report.html` 本身就是完整交付物，
浏览器打开后 Ctrl+P 存为 PDF 即可 —— 报告里带了打印样式（去底色、去掉表格阴影、避免跨页断开）。
`--no-pdf` 可以显式关掉转换。

## 三、装到别的 agent

```bash
./install.sh                       # 复制到 ~/.codex/skills/sec-assessment
./install.sh --link                # 软链接方式（省空间）
./install.sh /path/to/skills       # 指定 skills 根目录
```

装完自动跑一次 `check_deps.py` 自检。之后在该机器上：
更新规则库用 `python3 scripts/update_rules.py --all`。
