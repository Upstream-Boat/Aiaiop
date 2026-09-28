# 工具目录（43 个）

> 由 `scripts/gen_tools_doc.py` 从注册表自动生成，请勿手改。

## 侦察与资产发现

### `ip_usage_report`
IP网段使用情况报告 - 发现在线设备、识别设备类型/厂家、列出空闲IP。不传target自动检测当前网段

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 否 | 目标网段(如 192.168.x.0/24)，不传则自动检测 |
| `scan_level` | string | 否 | 扫描深度: ping(仅在线列表,适合大网段) / quick(全端口+类型识别,默认) / normal(全端口) / deep(全端口+OS识别)；大于 /20 的网段自动按 ping 处理 |
| `detailed_os_scan` | boolean | 否 | [已弃用] 使用scan_level替代，保留兼容 |

### `masscan_scan`
扫描指定IP的全部开放端口(全端口65535)，支持单个IP或IP列表

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标IP，或用逗号/换行分隔的多IP，或JSON数组 |

### `network_survey`
大网段快速设备普查 - 不逐个扫端口，高速扫描发现在线设备，适用于/16及以上大网段

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标网段(如 192.168.x.x/16) |
| `ports` | string | 否 | 端口(22,80,443,3389) |
| `rate` | integer | 否 | 速率(包/秒) |

### `ping_scan`
Ping扫描整个网段发现在线设备(调用系统nmap -sn)，几秒扫完/24；对不回 ICMP 的主机会自动用 -Pn 重探

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 网段(如 192.168.x.0/24) |
| `ping_only` | boolean | 否 | 仅Ping模式(false时禁用Ping用-Pn探测禁Ping设备) |

## 子域名与 DNS

### `subdomain_enum`
子域名枚举 - Subfinder API聚合+DNS爆破双引擎，扩大攻击面发现隐藏资产

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `domain` | string | 是 | 目标域名（如 example.com） |
| `sources` | string | 否 | 数据源: subfinder(API聚合)/dnsbrute(DNS爆破)/all(全部) |
| `timeout` | integer | 否 | 超时秒数（默认300） |

## Web 应用测试

### `dirb_scan`
Web目录爆破(内置Python)

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `url` | string | 是 | URL |
| `wordlist` | string | 否 | common/small/big(common) |

### `nikto_scan`
Nikto Web扫描

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | URL 或 IP（如 http://192.168.x.x 或 192.168.x.x） |
| `port` | integer | 否 | 端口；目标里已写端口时以目标为准 |
| `ssl` | boolean | 否 | 是否 HTTPS(false) |
| `timeout` | integer | 否 | 整个步骤的总预算秒数，多目标时按目标数均分（默认 300） |

### `sqlmap_basic`
SQL注入(GET)

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `url` | string | 是 | URL |
| `level` | integer | 否 | 等级(1) |

### `sqlmap_full`
SQL注入全功能版 - 支持GET/POST/Header/Cookie注入，盲注/报错/联合查询/堆叠，OS-Shell/文件读写/数据脱取。所有高级选项默认关闭，按需开启

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `url` | string | 是 | 目标URL（必填） |
| `data` | string | 否 | POST数据（如 user=admin&pass=123），留空则用GET |
| `cookie` | string | 否 | Cookie字符串 |
| `headers` | string | 否 | 自定义Header（每行一个，如 X-Forwarded-For: 127.0.0.1） |
| `technique` | string | 否 | 注入技术: U(联合查询)/B(布尔盲注)/T(时间盲注)/E(报错)/S(堆叠)，默认自动 |
| `level` | integer | 否 | 测试等级 1-5，越高越深入（默认1） |
| `risk` | integer | 否 | 风险等级 1-3，3可能破坏数据（默认1） |
| `dbms` | string | 否 | 指定数据库类型（mysql/postgresql/mssql/oracle），不指定自动检测 |
| `os_shell` | boolean | 否 | 尝试获取系统Shell |
| `os_cmd` | string | 否 | 通过注入执行系统命令并返回结果 |
| `dump_all` | boolean | 否 | 脱取所有数据库全部数据 |
| `dump_db` | string | 否 | 脱取指定数据库 |
| `dump_table` | string | 否 | 脱取指定表（需配合dump_db） |
| `batch` | boolean | 否 | 自动确认，不交互 |
| `threads` | integer | 否 | 并发线程数（默认3） |
| `timeout` | integer | 否 | 超时秒数（默认300） |

### `waf_detect`
WAF/IDS/IPS检测 - 使用wafw00f识别Web应用防火墙品牌，辅助选择WAF绕过策略

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `url` | string | 是 | 目标URL（带协议，如 https://example.com） |
| `timeout` | integer | 否 | 超时秒数（默认60） |

## 漏洞扫描

### `cve_db_build_sm_por`
CVE漏洞库构建工具。从NVD下载全量CVE数据，构建本地SQLite漏洞库。支持增量更新。首次下载较慢（5-15分钟），之后仅增量。

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `force_rebuild` | integer | 否 | 1=强制重新下载全量CVE（覆盖已有库），0=仅增量更新（默认） |

### `cve_match_sm_por`
CVE匹配查询。根据服务名称+版本号查询本地CVE漏洞库，返回所有匹配的CVE（含CVSS评分、描述、修复建议）。

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `data` | string | 是 | 服务数据。每行一个：IP|端口|服务名|版本号。示例：
192.168.x.x|22|ssh|OpenSSH 8.9p1
192.168.x.x|80|http|nginx 1.24.0 |
| `min_cvss` | number | 否 | 最低CVSS分数过滤（只显示≥此分数的CVE），默认0 |
| `limit` | integer | 否 | 每个服务最多返回CVE数量，默认20 |

### `nuclei_scan`
[Nuclei引擎] 专业漏洞扫描(10万+规则) - 支持CVE/高危/应用等

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标IP/URL |
| `severity` | string | 否 | 严重级别: critical/high/medium/low/all(critical+high+medium+low+info) |
| `tags` | string | 否 | 规则标签过滤(如 cve,redis,apache,spring,等留空默认) |
| `timeout` | integer | 否 | 超时秒数 |

### `os_identify`
设备类型识别 v3（深度指纹）。根据端口/服务/SSL证书/Nmap指纹识别设备类型（路由器/交换机/防火墙/NAS/服务器/容器等）

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `data` | string | 是 | 端口服务数据。每行一个服务，格式: IP|端口|服务|版本 |
| `deep` | integer | 否 | 深度探测模式。1=启用sudo nmap -O（5200+指纹库，需root），0=仅规则匹配（默认） |

### `poc_runner_sm_por`
POC自动验证引擎。输入CVE编号+目标IP:端口，自动搜索可用验证脚本并执行。支持nuclei/msf/searchsploit/公开PoC。

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标IP地址 |
| `port` | integer | 否 | 目标端口 |
| `cve` | string | 是 | CVE编号，如 CVE-2024-6387 |
| `auto` | integer | 否 | 1=从CVE自动推断并尝试所有可用验证方式，0=手动指定验证引擎（默认1） |
| `engine` | string | 否 | 指定验证引擎：nuclei/msf/searchsploit/github，auto=1时自动选择 |

### `service_identify`
快速识别IP:端口对应的服务名称和版本号（如nginx、apache、mysql、ssh、rdp等）。批量自动按IP分组扫描。输入: 每行一个 IP:端口 或 空格/逗号分隔

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `targets` | string | 是 | IP:端口列表。每行一个IP:端口，或空格分隔。
示例:
192.168.x.x:334
192.168.x.x:888
192.168.x.x:22 80 443
或: 192.168.x.x:22,80,443 |

### `vuln_verify`
漏洞真实性验证。对扫描报告中的漏洞进行复现确认，排除误报。输入格式: 每行 类型|IP|端口|漏洞描述（或直接粘贴之前扫描报告的内容）

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `report` | string | 是 | 漏洞报告内容或格式化数据。自动从文本中提取漏洞信息进行验证。
支持直接粘贴 nuclei/nikto/hydra/scanner 的输出。 |
| `target` | string | 否 | （可选）手动指定目标IP，当report中没有提取到时使用 |

## 口令攻击

### `hashcat_bruteforce`
Hashcat破解 — 用字典撞哈希；本机缺 OpenCL 运行时或 hashcat 时自动改用内置 CPU 回退（md5/sha1/sha256/sha512，无掩码与规则）

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `hash_file` | string | 是 | hash文件 |
| `wordlist` | string | 是 | 字典 |
| `hash_type` | string | 否 | 类型(md5) |

### `hydra_bruteforce`
Hydra暴力破解

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标IP |
| `service` | string | 否 | 服务(ssh) |
| `username` | string | 是 | 用户名 |
| `password_list` | string | 是 | 密码 |
| `port` | integer | 否 | 端口 |

### `passwd_dict_gen`
根据目标信息生成自定义弱口令字典。传入公司名/姓名/年份等关键信息，生成可能的密码组合，用于hydra等爆破工具的密码列表。

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `company` | string | 否 | 公司名称（中文或英文） |
| `name` | string | 否 | 姓名/用户名 |
| `year` | string | 否 | 年份，如 2024 |
| `keyword` | string | 否 | 其他关键字，如部门名、系统名 |
| `output_format` | string | 否 | 输出格式: text(逐行)/comma(逗号分隔,便于直接传入hydra) |

## 利用与后渗透

### `exploit_search`
Exploit-DB搜索(内置)

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `keyword` | string | 是 | 关键词 |

### `impacket_secretsdump`
NTDS哈希导出

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | IP |
| `domain` | string | 是 | 域名 |
| `username` | string | 是 | 用户名 |
| `password` | string | 是 | 密码 |

### `impacket_smbexec`
SMB远程命令

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | IP |
| `username` | string | 是 | 用户名 |
| `password` | string | 是 | 密码 |
| `command` | string | 否 | 命令(whoami) |

### `kerberos_attack`
Kerberos域认证攻击 - AS-REP Roasting(免密凭证提取) + Kerberoasting(服务账号爆破)，Windows AD域渗透必杀技

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 否 | 域控IP或域名 |
| `domain` | string | 是 | 域名（如 corp.local） |
| `dc_ip` | string | 是 | 域控IP（必填） |
| `username` | string | 否 | 已知用户名（AS-REP模式只需要用户名） |
| `password` | string | 否 | 已知密码（Kerberoasting需要） |
| `hash` | string | 否 | NTLM Hash（替代密码） |
| `users_file` | string | 否 | 用户名列表文件路径（AS-REP批量） |
| `mode` | string | 否 | 攻击模式: asrep(免密)/kerberoast(需凭据)/auto(自动判断) |
| `output_file` | string | 否 | 哈希输出文件路径 |
| `timeout` | integer | 否 | 超时秒数（默认300） |

### `lateral_hash_dump`
凭证收集：从Linux(/etc/shadow)或Windows(SAM)提取哈希

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标IP（已getshell） |
| `mode` | string | 是 | linux=读取/etc/shadow, windows=读取SAM, samdump=从注册表dumpsam |
| `username` | string | 否 | SSH用户名或Win用户名 |
| `password` | string | 否 | 登录密码 |
| `port` | integer | 否 | SSH端口 |

### `lateral_portscan`
内网存活主机快速探测（网段扫描）

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标IP或网段（如 192.168.x.0/24），支持target兼容 |
| `subnet` | string | 否 | 目标网段（留空则用target参数），如 192.168.x.0/24 |
| `ports` | string | 否 | 扫描端口，默认 1-65535 全端口；扫整段时建议显式收窄，全端口 ×256 台主机是很久的事 |
| `rate` | integer | 否 | 速率(包/秒) |

### `lateral_redis_backdoor`
Redis未授权访问 + SSH密钥植入（后门安装）

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标IP |
| `action` | string | 否 | write_cron=写定时任务反弹, write_ssh=写SSH密钥, info=仅查看信息 |
| `lhost` | string | 否 | 反弹shell的监听IP（action=write_cron时需要） |
| `lport` | integer | 否 | 监听端口 |

### `lateral_smb_enum`
SMB枚举：共享目录、用户列表、空会话检测

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标IP |
| `username` | string | 否 | 用户名（空=空会话） |
| `password` | string | 否 | 密码 |

### `lateral_ssh_exec`
SSH远程命令执行（需已有凭据）

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标IP |
| `username` | string | 是 | SSH用户名 |
| `password` | string | 是 | SSH密码 |
| `command` | string | 否 | 要执行的命令 |
| `port` | integer | 否 | SSH端口 |

### `mimikatz_memory`
内存凭证提取 - 使用mimikatz.py远程提取Windows内存中的明文密码/NTLM哈希/Kerberos票据（需管理员权限）

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标IP |
| `username` | string | 是 | Windows管理员用户名 |
| `password` | string | 否 | 密码 |
| `hash` | string | 否 | NTLM Hash（Pass-the-Hash替代密码） |
| `command` | string | 否 | 自定义mimikatz命令，留空自动提取所有凭证 |
| `timeout` | integer | 否 | 超时秒数（默认120） |

### `msf_exploit`
MSF漏洞利用 — 根据漏洞名称自动匹配MSF模块并执行。支持：永恒之蓝、SMBGhost、Tomcat、JBoss、WebLogic、Struts2、Spring4Shell、Fastjson、vsftpd、Samba、Redis、MySQL、RDP等

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标IP |
| `vuln_name` | string | 是 | 漏洞名称（自动匹配MSF模块，如 eternalblue / tomcat / struts2 / redis） |
| `lhost` | string | 是 | 反弹shell监听IP |
| `lport` | integer | 否 | 反弹shell监听端口 |
| `port` | integer | 否 | 目标端口（可选） |
| `timeout` | integer | 否 | 执行超时秒数 |

### `msfvenom_payload`
生成MSF payload

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `payload` | string | 否 | 类型(linux/x64/meterpreter_reverse_tcp) |
| `lhost` | string | 是 | 监听IP |
| `lport` | integer | 否 | 端口(4444) |
| `format` | string | 否 | 格式(elf) |

### `persist_install`
持久化后门安装 - SSH公钥注入/crontab定时任务/systemd服务/.bashrc后门，多种方式确保权限维持

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标IP |
| `username` | string | 是 | SSH用户名 |
| `password` | string | 否 | SSH密码 |
| `key_file` | string | 否 | SSH私钥文件路径（如已有） |
| `method` | string | 否 | 持久化方式: ssh_key/cron/systemd/bashrc/at/all(全部尝试) |
| `ssh_port` | integer | 否 | SSH端口（默认22） |
| `callback_ip` | string | 否 | 反弹Shell回调IP |
| `callback_port` | integer | 否 | 反弹Shell回调端口 |
| `timeout` | integer | 否 | 超时秒数（默认60） |

### `revshell_handler`
反弹Shell监听器 - 在本地监听端口等待反弹连接，支持nc，自动超时返回结果

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `port` | integer | 是 | 监听端口（默认4444） |
| `handler` | string | 否 | 处理器: nc（默认，基础Shell） |
| `timeout` | integer | 否 | 监听超时秒数（0=无限等待，默认120） |

### `smb_enum`
SMB枚举(smbmap)

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标IP |
| `username` | string | 否 | 用户名 |
| `password` | string | 否 | 密码 |
| `command` | string | 否 | 远程命令 |

### `socks_proxy`
SOCKS代理管理 - 使用Chisel建立反向隧道/正向SOCKS5代理，支持服务端/客户端模式，打通内网横向移动通道

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `mode` | string | 是 | 模式: server(启动服务端)/client(连接服务端)/list(查看活跃代理)/kill(停止代理) |
| `listen_port` | integer | 否 | 服务端监听端口（默认1080） |
| `server_url` | string | 否 | 客户端模式下的服务端地址（如 http://192.168.x.x:8080） |
| `remote` | string | 否 | 反向隧道远端地址（如 127.0.0.1:3389） |
| `proxy_id` | string | 否 | 要停止的代理PID（kill模式） |
| `timeout` | integer | 否 | 超时秒数（默认30） |

## 网络探测

### `free_ip_scan`
快速空闲IP扫描 — 只扫描子网中未被使用的IP地址

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标网段(如 192.168.x.0/24) |

### `network_inspect`
内网巡检 — 发现在线设备、识别设备类型（安全/网络/服务器/工作站/物联网）、开放端口/服务、MAC厂商、空闲IP。支持SSH深度巡检采集CPU/内存/磁盘/负载。模式: free=仅空闲IP, quick=端口+分类, full=全部+SSH系统指标

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标网段(如 192.168.x.0/24) |
| `mode` | string | 否 | free/quick/full |
| `ssh_user` | string | 否 | SSH用户名(mode=full时必填) |
| `ssh_pass` | string | 否 | SSH密码 |
| `ssh_port` | integer | 否 | SSH端口 |

## 合规检查

### `compliance_report`
[等保三级] 生成合规安全检查报告 - 汇总端口/漏洞/基线结果，输出等保对照整改建议

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 网段(如 192.168.x.0/24) |

## 数据处理

### `cleanup_trace`
痕迹清理：删除登录日志、历史命令、临时文件

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标IP（需已SSH登录） |
| `username` | string | 是 | SSH用户名 |
| `password` | string | 是 | SSH密码 |
| `level` | string | 否 | level1=基本(清history), level2=中等(清日志), level3=完全(清日志+修改时间) |
| `port` | integer | 否 | SSH端口 |

### `db_data_extract`
数据库数据采集：读取MySQL/MSSQL/PostgreSQL/Redis数据

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标IP |
| `type` | string | 是 | 数据库类型: mysql/mssql/postgres/redis |
| `username` | string | 是 | 数据库用户名 |
| `password` | string | 是 | 数据库密码 |
| `query` | string | 否 | SQL查询语句（mysql/mssql/postgres用），Redis用info |
| `port` | integer | 否 | 数据库端口 |

### `file_extract`
文件/配置信息提取：读取远程服务器敏感文件

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target` | string | 是 | 目标IP（需已连上SSH或已有凭据） |
| `mode` | string | 是 | ssh=通过SSH读取, http=通过Web访问读取 |
| `paths` | string | 否 | 要读取的文件路径，多个用逗号分隔 |
| `username` | string | 否 | SSH用户名（mode=ssh时需要） |
| `password` | string | 否 | SSH密码（mode=ssh时需要） |
| `port` | integer | 否 | SSH端口 |

## 其他

### `get_current_time`
获取当前精确时间 - 返回当前日期和北京时间，包含年/月/日/时/分/周几
