# HACK.SKILLS — Agent 黑客武装知识库

> 来源: https://github.com/yaklang/hack-skills
> 定位: 为 AI Agent 设计的进攻性安全技能库，覆盖 14 个安全领域、101 个深度技能

## 知识体系架构

三层加载模型：Master Entry（全局路由） → Category Entry（按攻击面分类） → Deep Topic Skills（按需深入）

### 六大 Category Entry（分类入口）

| 分类入口 | 用途 | 触发场景 |
|---------|------|---------|
| recon-for-sec | 资产发现、技术识别 | 刚拿到目标 |
| api-sec | REST、GraphQL、移动后端 | 发现 API 接口 |
| auth-sec | 认证、Session、OAuth、JWT、授权 | 登录、Token、对象ID |
| injection-checking | XSS、SQLi、SSRF、XXE、SSTI、CMDi、NoSQL | 输入进入解释器 |
| file-access-vuln | 上传、下载、LFI、路径控制 | 文件操作 |
| business-logic-vuln | 条件竞争、定价、工作流、状态机 | 业务流程测试 |

## 101 个深度技能覆盖

### 信息侦察与方法论 (3个)
- recon-and-methodology: Java中间件指纹矩阵、泄露检测清单

### API安全 (4个)
- api-recon-and-docs: API发现、OpenAPI/Swagger、隐藏端点
- api-authorization-and-bola: BOLA/BFLA、批量赋值、对象级授权
- api-auth-and-jwt-abuse: JWT攻击、API密钥滥用
- graphql-and-hidden-parameters: GraphQL内省、批处理、隐藏参数

### 认证与授权 (6个)
- authbypass-authentication-flaws: 密码重置22模式矩阵、验证码绕过20方法、UUID v1/mt_rand/ObjectId不安全性
- jwt-oauth-token-attacks: JWT算法混淆、密钥混淆、声明篡改、JWKS滥用
- oauth-oidc-misconfiguration: OAuth流程劫持、OIDC错误配置
- saml-sso-assertion-attacks: SAML断言操纵、SSO绕过
- idor-broken-object-authorization: 8类别系统化IDOR测试、ORM过滤链泄露(Django/Prisma/Ransack)

### 注入攻击 (17个)
- xss-cross-site-scripting: Polyglot payloads、按厂商WAF绕过(Cloudflare/Akamai/Incapsula/WordFence)、CSP绕过、DOM clobbering、CSS注入数据窃取
- sqli-sql-injection: DB2/Cassandra/BigQuery/SQLite特性、SQLite RCE、WAF绕过矩阵、CTF技巧(handler/prepare/innodb)
- ssrf-server-side-request-forgery: 云元数据6平台矩阵、DNS重绑定、无头浏览器攻击、Gopher/Redis RCE链
- ssti-server-side-template-injection: 15+引擎覆盖(Jinja2/Twig/Pug/Handlebars/EJS/Razor/EEx/Smarty)、盲SSTI、Flask PIN计算
- cmdi-command-injection: WAF绕过(wildcards/xor/base64)、PHP disable_functions 6种绕过、组件RCE(ImageMagick/FFmpeg/ES)
- nosql-injection: 盲提取自动化脚本、重复键绕过、聚合管道注入、$where JS执行
- xxe-xml-external-entity: 本地DTD注入(17+路径)、盲XXE、Gopher/FTP OOB
- deserialization-insecure: Java/PHP/Python+Ruby Marshal/YAML链、.NET BinaryFormatter/ViewState/JSON.NET
- ghost-bits-cast-attack: Java char-to-byte窄化WAF绕过(Black Hat Asia 2026)、255个Unicode绕过候选
- expression-language-injection: SpEL/OGNL/Java EL注入RCE链
- jndi-injection: JNDI/LDAP/RMI利用、Log4Shell模式
- crlf-injection: 头注入、HTTP响应拆分
- request-smuggling: CL.TE/TE.CL/TE.TE 8种混淆变体、HTTP/2降级、客户端不同步
- prototype-pollution: Express黑盒探测密钥、EJS/Kibana gadget链
- type-juggling: PHP松散比较表、魔术哈希(MD5/SHA1/SHA256)、HMAC 0e爆破
- http-parameter-pollution: 9平台服务器行为矩阵、HPP+WAF绕过组合
- xslt-injection: 三条RCE链(PHP/Java/.NET)、EXSLT文件写入
- csv-formula-injection: DDE/rundll32 payloads、Google Sheets IMPORT*窃取

### 文件与路径攻击 (2个)
- path-traversal-lfi: LFI-to-RCE 7条路径、PHP包装器矩阵(filter chains/oracle/phar)、pearcmd 4种方法
- upload-insecure-files: 成功率公式、编辑器路径矩阵、验证缺陷5维分类、IIS/Apache/Nginx解析技巧

### 业务逻辑与会话 (8个)
- business-logic-vulnerabilities: 支付操纵矩阵(10种攻击)、状态机绕过方法论、优惠券/库存竞争
- race-condition: TOCTOU模型、HTTP/1.1 last-byte sync、HTTP/2 single-packet攻击、Turbo Intruder模板
- csrf-cross-site-request-forgery: JSON CSRF 3种技术、multipart上传CSRF、CSPT2CSRF现代变体
- clickjacking: 框架攻击、X-Frame-Options/CSP绕过
- cors-cross-origin-misconfiguration: Origin反射、null origin、子域信任滥用
- open-redirect: 重定向链滥用、tabnabbing(反向tabnabbing)
- web-cache-deception: 路径混淆、缓存键操纵

### 高级Web安全 (9个)
- subdomain-takeover: 悬挂DNS记录(CNAME/NS/A)、云服务指纹识别
- waf-bypass-techniques: 编码链、分块传输、HTTP走私绕过、按厂商绕过矩阵
- csp-bypass-advanced: Script gadgets、base-uri滥用、JSONP回调注入
- http-host-header-attacks: 密码重置中毒、Web缓存中毒、路由SSRF
- dangling-markup-injection: HTML注入窃取数据(无需JS)、CSP安全数据窃取
- dns-rebinding-attacks: DNS重绑定内网访问、TTL操纵
- email-header-injection: SMTP头注入、CC/BCC操纵
- http2-specific-attacks: HTTP/2请求走私(H2.CL/H2.TE)、HPACK头压缩攻击
- 401-403-bypass-techniques: 路径规范化技巧、HTTP动词篡改、头绕过(X-Original-URL/X-Rewrite-URL)、代理错误配置、IP ACL绕过

### 基础设施与网络 (7个)
- unauthorized-access-common-services: 服务暴露清单、反向代理错误配置(Nginx off-by-slash、X-Forwarded-For信任、Caddy模板注入)
- insecure-source-code-management: .git/.svn/.hg/.bzr恢复、403 vs 404检测、备份文件模式
- dependency-confusion: npm/pip/gem公共仓库劫持
- websocket-security: CSWSH、Origin验证
- network-protocol-attacks: ARP欺骗、DNS投毒、LLMNR/NBT-NS投毒、DHCP饥饿、IPv6攻击
- tunneling-and-pivoting: SSH隧道(local/remote/dynamic)、SOCKS代理链、chisel/ligolo-ng、DNS/ICMP隧道
- reverse-shell-techniques: 多语言Shell生成、加密反向Shell(OpenSSL/ncat)、分阶段payloads、防火墙绕过、Web Shell

### Linux与容器安全
- linux-privilege-escalation: SUID/Sudo/Capabilities/ Cron/ Docker逃逸等完整Linux提权链

## 知识来源

基于以下公开安全项目进行知识蒸馏（非镜像，是浓缩层）：
- swisskyrepo/PayloadsAllTheThings: 64漏洞类别、payload家族、绕过技巧
- PentesterSpecialDict: OS专用payload字典、Java中间件路径fuzz列表
- Dictionary-Of-Pentesting: BugBounty绕过技巧(12主题)、云元数据端点
- Hello-CTF / ctf-wiki: CTF Web安全/Pwn/Crypto/Reverse/Forensics
- hacktricks: 渗透测试百科全书(Web/Linux/Windows/macOS/AD/Container/Mobile/AI)

## 安装方式

```bash
npx skills add yaklang/hack-skills
```

在线浏览: https://skills.hackbenchmark.com (模糊搜索、分类侧栏、加密ZIP下载)
