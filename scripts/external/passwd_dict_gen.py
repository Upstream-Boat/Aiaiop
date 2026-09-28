#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
弱口令字典生成器 — 根据目标信息生成自定义密码字典
"""
import re

def _register(reg):
    reg({
        "name": "passwd_dict_gen",
        "description": "根据目标信息生成自定义弱口令字典。传入公司名/姓名/年份等关键信息，生成可能的密码组合，用于hydra等爆破工具的密码列表。",
        "inputSchema": {"type": "object",
                      "properties": {
    "company": {
        "type": "string",
        "description": "公司名称（中文或英文）",
        "default": ""
    },
    "name": {
        "type": "string",
        "description": "姓名/用户名",
        "default": ""
    },
    "year": {
        "type": "string",
        "description": "年份，如 2024",
        "default": ""
    },
    "keyword": {
        "type": "string",
        "description": "其他关键字，如部门名、系统名",
        "default": ""
    },
    "output_format": {
        "type": "string",
        "description": "输出格式: text(逐行)/comma(逗号分隔,便于直接传入hydra)",
        "default": "comma",
        "enum": ["text", "comma"]
    }
},
                      "required": []},
    })(tool_passwd_dict_gen)


def _gen_base_words(company, name, year, keyword):
    """生成基础词列表"""
    words = set()
    
    # 常见弱口令
    common = ["admin", "Admin", "root", "Root", "test", "Test", "guest", "Guest",
              "password", "Password", "123456", "12345678", "123456789", "123123",
              "111111", "000000", "888888", "666666", "passwd", "Passwd",
              "system", "System", "manager", "Manager", "server", "Server"]
    words.update(common)
    
    # 年份组合
    if year:
        y = year.strip()
        words.add(y)
        words.add(y[:2])
        words.add(y[2:])
        words.add(y + "@")
        words.add(y + "!")
        words.add(y + "#")
        words.add("P@ssw0rd" + y)
        words.add("Admin" + y)
        words.add("admin" + y)
    
    # 公司名（拼音、缩写、首字母）
    if company:
        c = company.strip()
        words.add(c)
        words.add(c.lower())
        words.add(c.upper())
        # 中文拼音近似
        if re.search(r'[\u4e00-\u9fff]', c):
            # 取首字母
            initials = ''.join([w[0] for w in c if w.isalpha()])
            if initials: words.add(initials.lower())
        else:
            words.add(c[:3].lower())
            words.add(c[:3].upper() + "123")
    
    # 姓名
    if name:
        n = name.strip()
        words.add(n)
        words.add(n.lower())
        words.add(n.upper())
        words.add(n.capitalize())
    
    # 关键字
    if keyword:
        k = keyword.strip()
        words.add(k)
        words.add(k.lower())
    
    # 常见组合模式
    patterns = set()
    base_list = list(words)
    for w in base_list:
        if not w: continue
        # 加数字/符号后缀
        patterns.add(w + "123")
        patterns.add(w + "1234")
        patterns.add(w + "123456")
        patterns.add(w + "@")
        patterns.add(w + "!")
        patterns.add(w + "#")
        patterns.add(w + "2024")
        patterns.add(w + "2025")
        patterns.add(w + "2026")
        # 大写首字母
        patterns.add(w.capitalize())
        patterns.add(w.capitalize() + "123")
        # 加年份
        if year:
            patterns.add(w + year)
    
    words.update(patterns)
    
    # 去空排序
    result = sorted([w for w in words if w and len(w) >= 3], key=lambda x: (len(x), x))
    return result


def tool_passwd_dict_gen(name, params):
    company = params.get("company", "")
    name = params.get("name", "")
    year = params.get("year", "")
    keyword = params.get("keyword", "")
    fmt = params.get("output_format", "comma")
    
    words = _gen_base_words(company, name, year, keyword)
    
    if fmt == "comma":
        output = ",".join(words)
    else:
        output = "\n".join(words)
    
    summary = f"""=== 弱口令字典生成 ===
公司: {company or '(无)'}
姓名: {name or '(无)'}
年份: {year or '(无)'}
关键字: {keyword or '(无)'}
共生成: {len(words)} 条

{output[:30000]}
"""
    if len(output) > 30000:
        summary += "\n...(截断至30000字符)"
    
    return {"success": True, "returncode": 0, "output": summary}
