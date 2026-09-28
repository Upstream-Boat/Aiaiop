# 漏洞扫描知识库 — CIS 安全基线 + 加固命令

> 用途：漏洞扫描 Agent 的基线核查标准。8 大服务安全基线 + 加固命令 + P0-P3 决策矩阵。

---

## 一、SSH 安全基线 (OpenSSH)

**检查项：**
- 禁用 root 远程登录：`PermitRootLogin no`
- 禁用空密码：`PermitEmptyPasswords no`
- 协议版本 2：`Protocol 2`
- 空闲超时：`ClientAliveInterval 300` / `ClientAliveCountMax 2`
- 密码策略：弱口令检测

**加固命令：**
```bash
# /etc/ssh/sshd_config
PermitRootLogin no
PermitEmptyPasswords no
Protocol 2
MaxAuthTries 4
ClientAliveInterval 300
ClientAliveCountMax 2
# 重启
systemctl restart sshd
```

## 二、Web 服务基线 (Nginx/Apache)

**检查项：**
- 隐藏版本号
- 安全响应头（X-Frame-Options / CSP / nosniff）
- 目录列表关闭
- 上传目录禁用脚本执行
- TLS ≥ 1.2、禁用弱套件

**加固命令：**
```bash
# Nginx
server_tokens off;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
# Apache
ServerTokens Prod
ServerSignature Off
Header set X-Frame-Options "SAMEORIGIN"
```

## 三、MySQL 基线

**检查项：**
- root 空密码 / 弱密码
- 未授权远程访问（bind-address）
- 匿名账号
- 默认端口暴露

**加固命令：**
```sql
-- 改root密码
ALTER USER 'root'@'localhost' IDENTIFIED BY '强密码';
-- 删除匿名用户
DELETE FROM mysql.user WHERE User='';
-- 禁止远程root
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1');
FLUSH PRIVILEGES;
```

## 四、Redis 基线

**检查项：**
- 未授权访问（无 requirepass）
- 暴露公网（bind 127.0.0.1 应为本地）
- 未禁用危险命令（config/flushall）

**加固命令：**
```bash
# redis.conf
bind 127.0.0.1          # 仅本地
requirepass 强密码
rename-command FLUSHALL ""
rename-command CONFIG ""
rename-command EVAL ""
# 不可用必须设密码，否则配合主从可RCE
```

## 五、Tomcat 基线

**检查项：**
- 默认密码 tomcat/tomcat、admin/admin
- manager 页面暴露
- 版本过旧（CVE-2023-42795）
- Actuator 暴露

**加固命令：**
```bash
# tomcat-users.xml 移除默认账号
# web.xml 限制 manager 访问 IP
# 升级到最新稳定版
```

## 六、操作系统基线 (Linux)

**检查项：**
- 弱口令 / 空口令账号
- 多余服务开启
- SSH root 登录
- 未打安全补丁
- 审计日志未开启
- 防火墙未启用

**加固命令：**
```bash
# 开启防火墙
systemctl enable --now firewalld
# 用户密码策略
# /etc/login.defs: PASS_MAX_DAYS 90 / PASS_MIN_LEN 8
# 启用审计
systemctl enable --now auditd
# 更新补丁
yum/dnf update -y
```

## 七、Windows 基线

**检查项：**
- 弱口令 / 空口令
- 未打补丁（MS17-010 EternalBlue）
- SMBv1 开启
- 防火墙关闭
- 多余共享

**加固命令：**
```powershell
# 禁用 SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false
# 开启防火墙
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
# 更新补丁
wuauclt /detectnow
```

## 八、数据库 (PostgreSQL/Mongo)

**检查项：**
- 默认口令 postgres/postgres
- MongoDB 未授权（无认证）
- 远程暴露

**加固命令：**
```bash
# PostgreSQL: 设强密码 + pg_hba.conf 限制来源
# MongoDB:
#  开启认证: security.authorization: enabled
#  绑定本机: net.bindIp: 127.0.0.1
```

---

## P0-P3 决策矩阵

| 优先级 | 触发条件 | 修复窗口 | 动作 |
|--------|---------|---------|------|
| 🔴 P0-紧急 | 未授权 RCE / 未授权 SQLi / 公网弱口令 / 未授权访问 | 24h | 立即隔离+升级+改密 |
| 🟠 P1-尽快 | 需认证 RCE / 存储 XSS / 高危版本漏洞 | 72h | 升级+加固 |
| 🟡 P2-计划 | 中危漏洞 / 敏感信息泄露 | 30天 | 排期修复 |
| 🟢 P3-建议 | 缺安全头 / 版本号泄露 / 配置优化 | 90天 | 加固优化 |

## 基线核查流程

```
1. 扫描开放端口 → 确认启用的服务
2. 对每个服务套用对应基线检查项
3. 记录未达标项 → 给出具体加固命令
4. 按 P0-P3 分级输出整改优先级
```
