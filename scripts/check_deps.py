#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""依赖自检 — 检查 43 个工具所需的外部二进制与数据资源。

用法:
    python3 scripts/check_deps.py              # 存在性 + 真实执行探测
    python3 scripts/check_deps.py --no-smoke   # 只查存在性（更快）

只做判定，不安装、不改动系统。缺什么会给出安装命令。
路径解析见 scripts/config.py（支持环境变量覆盖）。

为什么要做"真实执行探测"：
    命令在 PATH 里不代表能用。nikto 就是活例子 —— 文件在、可执行，但它缺配置项
    或参数写错时会直接报错退出，而链路上把它当成"有 nikto"继续跑。
    所以这里实际拉起一次进程，并从输出里找致命标记，而不是只看 shutil.which。
"""

import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config  # noqa: E402

BINARIES = [
    # (命令, 用途, 安装提示)
    ("nmap", "端口/服务扫描", "apt install nmap | dnf install nmap"),
    ("masscan", "全端口高速扫描", "apt install masscan | dnf install masscan"),
    ("nuclei", "漏洞扫描", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ("sqlmap", "SQL 注入", "apt install sqlmap | pipx install sqlmap"),
    ("hydra", "口令爆破", "apt install hydra | dnf install hydra"),
    ("hashcat", "哈希破解", "apt install hashcat | dnf install hashcat"),
    ("nikto", "Web 扫描", "apt install nikto | dnf install nikto"),
    ("msfconsole", "Metasploit 框架", "官方安装脚本 https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"),
    ("msfvenom", "payload 生成", "随 Metasploit 提供"),
    ("ffuf", "目录爆破", "go install github.com/ffuf/ffuf/v2@latest"),
    ("gobuster", "DNS/目录爆破", "go install github.com/OJ/gobuster/v3@latest"),
    ("subfinder", "子域名枚举", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("wafw00f", "WAF 识别", "pip install wafw00f"),
    ("smbmap", "SMB 枚举", "pip install smbmap"),
    ("impacket-secretsdump", "Windows 凭据导出", "pip install impacket"),
    ("GetNPUsers.py", "Kerberos AS-REP", "pip install impacket"),
    ("GetUserSPNs.py", "Kerberoasting", "pip install impacket"),
    ("psexec.py", "远程执行", "pip install impacket"),
    ("chisel", "SOCKS 隧道", "go install github.com/jpillora/chisel@latest"),
    ("sshpass", "SSH 密码登录", "apt install sshpass | dnf install sshpass"),
    ("tshark", "抓包", "apt install tshark | dnf install wireshark-cli"),
    ("tcpdump", "抓包（回退）", "apt install tcpdump"),
    ("nc", "端口连通性探测", "apt install netcat-openbsd | dnf install nmap-ncat"),
    ("socat", "端口转发", "apt install socat"),
    ("curl", "HTTP 请求", "apt install curl"),
    ("dig", "DNS 查询", "apt install dnsutils | dnf install bind-utils"),
    ("whois", "域名注册信息", "apt install whois"),
    ("perl", "Nikto 依赖", "apt install perl"),
]

# skill 自带资源 —— 安装 skill 时一并复制，无需另外配置
DATA = [
    ("CVE 数据库", config.CVE_DB_PATH,
     "更新: python3 scripts/update_rules.py --cve"),
    ("Exploit-DB", config.EXPLOIT_DB_EXPLOITS,
     "更新: python3 scripts/update_rules.py --exploit-db"),
    ("nuclei 模板", config.NUCLEI_TEMPLATES,
     "更新: python3 scripts/update_rules.py --nuclei"),
    ("nmap OUI 表", config.MAC_PREFIX_FILE,
     "随 skill 自带，用于 MAC 厂商识别"),
    ("searchsploit", config.SEARCHSPLOIT_BIN,
     "随 Exploit-DB 自带，无需系统安装"),
]


# 真实执行探测：每条给一个"打印版本/帮助然后退出"的参数。
# 注意不能拿退出码当判据 —— masscan --version 退 1、hydra -h 退 255，
# 都是正常行为。判据是"确实有输出、且不含致命标记"。
PROBE_ARGS = {
    "nmap": ["-v"],
    "masscan": ["--version"],
    "nuclei": ["-version"],
    "sqlmap": ["--version"],
    "hydra": ["-h"],
    "hashcat": ["--version"],
    "nikto": ["-Version"],
    "ffuf": ["-V"],
    "gobuster": ["--help"],
    "subfinder": ["-version"],
    "chisel": ["--version"],
    "sshpass": ["-V"],
    "curl": ["--version"],
    "dig": ["-v"],
    "socat": ["-V"],
    "nc": ["-h"],
    "perl": ["-v"],
    "tshark": ["-v"],
    "tcpdump": ["--version"],
}

# 出现这些字样说明程序起来了但干不了活，等于不可用
FATAL_MARKERS = ("Required module not found", "Can't locate", "command not found",
                 "- ERROR:", "No such file or directory")


def _probe(cmd, path, timeout=15):
    """实际执行一次，返回 (是否可用, 说明)。"""
    args = PROBE_ARGS.get(cmd)
    if not args:
        return None, "无探测参数，跳过"
    try:
        result = subprocess.run([path] + args, capture_output=True, text=True,
                                timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, "执行超时（%ss 无响应）" % timeout
    except OSError as exc:
        return False, "无法执行: %s" % exc
    output = (result.stdout or "") + (result.stderr or "")
    for marker in FATAL_MARKERS:
        if marker in output:
            return False, "输出含致命标记: %s" % marker
    if not output.strip():
        return False, "无任何输出（可能缺少运行时依赖或配置文件）"
    return True, output.strip().splitlines()[0][:60]


def _size(path):
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total


def main():
    print(f"skill 根目录 : {config.SKILL_HOME}")
    extra = config.extra_path_entries()
    if extra:
        print(f"PATH 追加    : {', '.join(extra)}")

    smoke = "--no-smoke" not in sys.argv
    missing, broken = [], []
    print("\n── 外部命令 ──")
    for cmd, purpose, hint in BINARIES:
        path = shutil.which(cmd)
        if not path:
            missing.append((cmd, purpose, hint))
            print(f"  [缺] {cmd:22s} —— {purpose}")
            continue
        if not smoke:
            print(f"  [有] {cmd:22s} {path}")
            continue
        ok, detail = _probe(cmd, path)
        if ok is None:
            print(f"  [有] {cmd:22s} {path}  （{detail}）")
        elif ok:
            print(f"  [有] {cmd:22s} {path}  ✓ {detail}")
        else:
            broken.append((cmd, purpose, detail))
            print(f"  [!] {cmd:22s} {path}  —— 存在但不可用：{detail}")

    print("\n── 自带资源（随 skill 复制，无需配置）──")
    for label, path, hint in DATA:
        if path and os.path.exists(path):
            print(f"  [有] {label:12s} {path}  ({_size(path) / 1048576:.1f} MB)")
        else:
            print(f"  [缺] {label:12s} 期望路径 {path}")
            print(f"       {hint}")

    print("\n── 可选配置 ──")
    print(f"  NVD_API_KEY  : {'已设置' if config.NVD_API_KEY else '未设置（可选，设置后 NVD 下载限速更宽松）'}")
    print(f"  METASPLOIT_BIN: {config.METASPLOIT_BIN or '未探测到'}")

    print("\n── 汇总 ──")
    if not missing and not broken:
        print("  外部命令全部就绪。")
    if missing:
        print(f"  缺 {len(missing)} 个外部命令：")
        for cmd, purpose, hint in missing:
            print(f"    - {cmd}（{purpose}）")
            print(f"      {hint}")
    if broken:
        print(f"  {len(broken)} 个命令存在但执行异常（这部分最容易被忽略）：")
        for cmd, purpose, detail in broken:
            print(f"    - {cmd}（{purpose}）：{detail}")
    return 1 if (missing or broken) else 0


if __name__ == "__main__":
    sys.exit(main())
