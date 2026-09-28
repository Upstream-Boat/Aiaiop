# 漏洞扫描知识库 — OWASP Testing Guide v4 精编

> 用途：漏洞扫描 Agent 的 Web 应用检测基准。10 大类 + 33 项核心检查清单，覆盖 OWASP Testing Guide v4 全流程。
> 此知识库供漏洞扫描时逐类检查，识别常见 Web 漏洞并输出修复建议。

---

## 一、信息收集 (Information Gathering)

1. **robots.txt 检查** — 查看是否泄露敏感路径（/admin /backup /config）
2. **Server 响应头** — 检查是否泄露版本号（Apache/2.4.41、nginx/1.20.1），应设置 `ServerTokens Prod`
3. **安全响应头缺失**：
   - `X-Frame-Options`（防点击劫持）
   - `X-Content-Type-Options: nosniff`（防 MIME 嗅探）
   - `Content-Security-Policy`（防 XSS）必要
   - `Strict-Transport-Security`（HSTS，仅 HTTPS）
4. **注释信息泄露** — HTML 源码注释中的路径/账号/接口
5. **目录枚举** — 常见敏感目录：/backup /test /phpmyadmin /wp-admin /manager /console
6. **备份文件泄露** — .bak .sql .zip .tar.gz .env .git/config .svn

## 二、配置与部署管理 (Configuration & Deploy)

7. **默认凭据未修改** — 设备/应用默认账号密码（admin/admin、root/toor）
8. **管理端口暴露** — 8080 管理台、8001 API、6379 Redis、9200 ES、3389 RDP 公网暴露
9. **调试/测试接口开放** — /actuator /swagger-ui.html /debug /console（Spring Boot Actuator 高危）
10. **错误信息泄露** — 500 错误页泄露堆栈/数据库类型/绝对路径

## 三、身份管理 (Identity Management)

11. **账号枚举** — 登录提示"用户名不存在 vs 密码错误"可枚举有效账号
12. **注册开放** — 允许任意注册，无邀请码/审核

## 四、认证 (Authentication)

13. **弱口令/默认口令** — root/admin 等弱密码
14. **无登录失败锁定** — 可无限次尝试爆破
15. **无验证码/无频率限制** — 配合爆破
16. **会话固定/弱会话** — 登录后 session ID 不变，或 session 可预测

## 五、授权 (Authorization)

17. **越权访问 (IDOR)** — 直接改 URL/请求中的 ID（user_id=1001）访问他人资源
18. **水平越权** — 同角色越权访问他人数据
19. **垂直越权** — 普通用户访问管理员功能（admin/ 接口未校验角色）
20. **功能级访问控制缺失** — 未登录可直接访问受保护接口

## 六、会话管理 (Session Management)

21. **Cookie 缺少 Secure/HttpOnly 标志**
22. **Session 未设置超时**（空闲超时应 ≤ 15 分钟，绝对超时 ≤ 8 小时）
23. **登出未销毁 Session**

## 七、输入验证 (Input Validation)

24. **SQL 注入** — 参数直接拼接进 SQL 查询
25. **XSS** — 反射型/存储型/DOM 型，未转义输出
26. **文件上传** — 未校验扩展名/内容，可上传 webshell（.php .jsp .asp）
27. **SSRF** — 服务端请求用户可控 URL（webhook、图片 URL 参数）
28. **SSTI** — 模板引擎注入（{{7*7}} 返回 49）
29. **XXE** — XML 解析外部实体（上传 XML 文件处）
30. **命令注入** — 拼接字符串到 shell 命令（ping/ipconfig 类参数）
31. **路径遍历** — ../ 穿越读取任意文件
32. **反序列化** — 用户可控序列化数据（.ser、base64 对象）

## 八、错误处理 (Error Handling)

33. **堆栈信息泄露** — 异常堆栈含内部类名/路径/数据库信息

## 九、加密与 TLS (Cryptography)

- 弱 TLS 协议（SSLv3/TLS1.0）
- 弱加密套件（RC4/3DES）
- 自签名/过期证书
- 不安全的密码存储（明文/MD5/弱哈希）

## 十、业务逻辑 (Business Logic)

- 支付/订单金额篡改
- 优惠券/积分越权使用
- 竞态条件（并发导致超卖）
- 流程绕过（跳步骤）

---

## Web 漏洞快速判断表

| 现象 | 可能漏洞 | 后续工具 |
|------|---------|---------|
| 参数含 id= 且报 SQL 错误 | SQL 注入 | sqlmap |
| 输入回显未转义 | XSS | xsstrike |
| 上传无校验 | 文件上传/webshell | msfvenom 验证 |
| URL 参数可访问内网 | SSRF | 手工验证 |
| 模板有 {{ }} 回显 | SSTI | 手工 payload |
| XML 解析 | XXE | 构造外部实体 |
| ping/exec 参数拼接 | 命令注入 | 验证回显 |
| 管理台暴露 | 弱口令/已知 CVE | hydra / cve 匹配 |
| 接口直接返回数据 | 越权 | IDOR 测试 |
| 心宿堆栈泄露 | 信息泄露 | 报告低危 |

## 修复建议模板

- **高危**：参数化查询、输入白名单校验、最小权限、升级版本、加强认证
- **中危**：安全响应头、Session 加固、错误信息隐藏
- **低危**：版本号隐藏、注释清理、默认页面移除
