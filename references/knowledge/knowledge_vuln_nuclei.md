# 漏洞扫描知识库 — Nuclei 模板策略与关键 CVE 速查

> 用途：漏洞扫描 Agent 的 Nuclei 深度扫描指南。模板选择策略、2020-2025 关键 CVE 速查、端口检测索引。

---

## 一、Nuclei 模板选择策略

### severity 过滤（控制扫描强度）
```
severity=critical,high,medium    # 默认推荐，快速精准
severity=critical,high           # 极速模式，只看高危
severity=all                     # 全量，最慢，适合最终确认
```

### tags 过滤（按目标技术栈）
```
tags=cve                        # 只扫 CVE
tags=redis / apache / tomcat    # 按服务
tags=spring,log4j               # 按框架
tags=exposure                   # 暴露类（管理台/未授权）
tags=misconfig                  # 配置错误
tags=fuzz                       # Fuzz
```

### 策略建议
| 场景 | 命令/参数 |
|------|----------|
| 快速摸底 | severity=critical,high |
| 标准扫描 | severity=critical,high,medium |
| Web 重点 | tags=exposure,misconfig |
| 已知服务 | 按服务 tags + severity |
| 全量确认 | severity=all, tags=cve |

### 常见误用与修正
- 全模板扫描很慢 → 加 severity 过滤
- 漏 Web 漏洞 → 加 tags=exposure,misconfig
- 误报多 → 结合 vuln_verify 手工验证

---

## 二、2020-2025 关键 CVE 速查（高价值目标）

### Web 中间件/框架
| CVE | 组件 | 类型 | 影响 |
|-----|------|------|------|
| CVE-2021-44228 (Log4Shell) | Log4j2 | RCE | 全国宝库尽收，JNDI 注入 |
| CVE-2021-45046 / CVE-2021-45105 | Log4j2 | RCE/DoS | Log4Shell 变种 |
| CVE-2024-4577 | PHP-CGI | RCE | Windows 全版本 |
| CVE-2024-21762 | FortiOS | RCE | 防火墙 |
| CVE-2024-3400 | Palo Alto PAN-OS | RCE | 防火墙 |

### 应用服务器
| CVE | 组件 | 类型 |
|-----|------|------|
| CVE-2023-21839 | WebLogic | RCE |
| CVE-2022-22965 (Spring4Shell) | Spring | RCE |
| CVE-2022-22963 | Spring Cloud Function | RCE |
| CVE-2023-42795 | Tomcat | DoS |
| CVE-2021-41079 / 41082 (ProxyShell) | Exchange | RCE |

### 办公/网安设备
| CVE | 组件 | 类型 |
|-----|------|------|
| CVE-2023-34362 (MOVEit) | MOVEit | SQL注入→RCE |
| CVE-2024-3400 / 2025 | 深信服/PAN-OS | RCE |
| CVE-2025-13714 | 各类国产OA | 越权/RCE |
| CVE-2022-27925 | Zimbra | RCE |

### 供应链/态势
- **Log4j (2021)**：影响几乎所有 Java 应用，检测参数中带 `${jndi:ldap://...}`
- **Spring4Shell (2022)**：Spring MVC + JDK9+ 数据绑定漏洞
- **MOVEit (2023)**：Clop 勒索组织利用，SQL 注入

---

## 三、25+ 关键端口检测索引

| 端口 | 服务 | 高价值检查 |
|------|------|-----------|
| 21 | FTP | 匿名登录、弱口令 |
| 22 | SSH | 弱口令、OpenSSH 已知 CVE |
| 445 | SMB | EternalBlue (MS17-010)、空会话 |
| 139 | NetBIOS | SMB 枚举 |
| 80/443 | HTTP/HTTPS | Web 全套 |
| 8080 | Tomcat/管理台 | 弱口令、Actuator |
| 7001 | WebLogic | 反序列化 (CVE-2023-21839) |
| 6379 | Redis | 未授权访问、主从RCE |
| 27017 | MongoDB | 未授权 |
| 9200 | Elasticsearch | 未授权、Log4j |
| 11211 | Memcached | 未授权 |
| 3389 | RDP | 弱口令、BlueKeep |
| 3306 | MySQL | 弱口令、未授权 |
| 5432 | PostgreSQL | 弱口令 |
| 8088 | Hadoop YARN | 未授权执行 |
| 8161 | Apache ActiveMQ | 默认弱口令 |
| 1099 | Java RMI | 反序列化 |
| 2181 | Zookeeper | 未授权 |
| 2375 | Docker | 未授权 API |
| 8888 | 常见管理台 | 弱口令 |
| 2222 | JumpServer/SSH alt | 弱口令 |
| 8001 | 管理/API | 暴露检查 |
| 18789 | 深信服/企业应用 | 特定 CVE |
| 26973 | 自定义服务 | 指纹识别 |

---

## 四、Nuclei 结果处理

1. **高危急停**：发现高危 RCE 立即 `vuln_verify` 验证并报告，不继续深入
2. **误报排查**：medium 级别确认是否有真实影响面
3. **证据收集**：保留 nuclei 输出关键行作为报告证据
4. **优先级**：CVSS ≥ 9 且未授权 → P0；需认证/复杂利用 → P1

---

## 五、操作建议

- 大网段先 `masscan_scan` 全端口 → 挑出 Web 端口 → 针对性 `nuclei_scan` + `nikto_scan`
- 结合 `waf_detect`：有 WAF 时降低请求速率、考虑 tamper
- 扫描结果与 `cve_match_sm_por` 结果交叉验证
