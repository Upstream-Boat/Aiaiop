#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""公共工具函数 — 所有工具模块共享。

_extract_target / _ensure_url / _ssh_exec 几个是从旧打包版和生产服务里合并过来的，
其余零散函数是后面按需要陆续补的。
"""

import ipaddress
import json
import re
import subprocess
import threading
import time

from config import apply_path, extra_path_entries

PATH_EXTRA = extra_path_entries()
apply_path()

# 单条命令保留的原始输出上限：一条命令写 4M 以上基本是失控（死循环打印），
# 留个头尾让人能看出是怎么回事，同时保证内存不会被它吃干净。
MAX_RAW_CHARS = 4 * 1024 * 1024

# 运行中的输出回调。默认关闭 —— 没有 sink 时 run_cmd 走原来的 subprocess.run，
# 43 个工具与离线评测的行为一个字都不变；只有编排（runner）执行时才装上，
# 让控制台能看到"这个工具此刻在做什么"。
_PROGRESS = {"sink": None}


def set_progress_sink(sink):
    """装/卸运行中输出回调，返回上一任（便于调用方用完还原）。

    sink(chunk, elapsed) 每读到一段输出被调用一次，chunk 是一整行（含换行）。
    回调抛异常只丢这一条进度，不影响命令本身。
    """
    previous = _PROGRESS["sink"]
    _PROGRESS["sink"] = sink
    return previous


def _kill_tree(proc):
    """连子孙一起杀：shell=True 时直接杀 shell 会把它启动的 nikto/perl 留成孤儿，
    它们继续占着端口和 CPU，下一轮扫描就开始莫名失败。"""
    import os
    import signal

    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:  # noqa: BLE001 - 进程可能刚好自己退了，退化成只杀直接子进程
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass


def _run_streaming(cmd, timeout, sink):
    """带实时回调的执行：边跑边把输出喂给 sink，到点连子孙一起杀。"""
    started = time.time()
    chunks = []
    size = 0
    try:
        proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, errors="replace", start_new_session=True,
        )
    except Exception as exc:  # noqa: BLE001 - 起不来也算一次失败的结果，不要让调用方炸掉
        return {"success": False, "returncode": -1, "output": "[ERROR] %s" % exc}

    def reader():
        nonlocal size
        try:
            for line in proc.stdout:
                if size < MAX_RAW_CHARS:
                    chunks.append(line)
                    size += len(line)
                try:
                    sink(line, time.time() - started)
                except Exception:  # noqa: BLE001 - 进度是旁路，坏了不能影响命令
                    pass
        except Exception:  # noqa: BLE001 - 管道被超时关闭是正常路径
            pass

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            pass
    thread.join(timeout=3.0)
    try:
        proc.stdout.close()
    except Exception:  # noqa: BLE001
        pass

    out = "".join(chunks).strip() or "(no output)"
    if size >= MAX_RAW_CHARS:
        out += "\n[TRUNCATED] 输出超过 %d 字符，只保留前段" % MAX_RAW_CHARS
    if timed_out:
        # 超时不等于什么都没有：nikto/nmap 这类工具到点前已经把结果打出来了，
        # 把已产出的部分交回来，报告里才看得见"扫到哪儿了"，而不是一片空白。
        out += "\n[TIMEOUT] 超过 %ss 已终止，以上为已产出的部分结果" % timeout
    return {"success": (not timed_out) and proc.returncode == 0,
            "returncode": -1 if timed_out else proc.returncode,
            "output": out, "timeout": timed_out, "partial": timed_out}


def stream_run(cmd, timeout=None, shell=None, cwd=None):
    """`subprocess.run` 的"边跑边喂进度"版本 —— 返回值与异常都对齐标准库。

    为什么要有它：`subprocess.run(capture_output=True)` 要等命令跑完才把输出交出来，
    工具跑十分钟，进程外这十分钟里一个字符都看不到 —— 观众看到的就是"跑完才一下子
    全出来"。凡是可能跑得久的命令都该走这里：输出一出来就喂给进度回调（控制台据此
    实时显示原文），同时照旧把完整的 stdout / stderr 返回给调用方；超时同样抛
    `TimeoutExpired`（且带上已经拿到的部分输出，而不是丢掉）。

    没装进度回调时行为与原来的写法一致，离线评测不受影响。
    """
    if shell is None:
        shell = isinstance(cmd, str)
    try:
        proc = subprocess.Popen(cmd, shell=shell, cwd=cwd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, errors="replace",
                                bufsize=1, start_new_session=True)
    except FileNotFoundError:
        raise

    sink = _PROGRESS.get("sink")
    started = time.time()
    out, err = [], []

    def pump(stream, buf):
        try:
            for line in stream:
                buf.append(line)
                if sink is not None:
                    try:                       # 进度是旁路：坏了不能影响命令本身
                        sink(line, time.time() - started)
                    except Exception:          # noqa: BLE001
                        pass
        except Exception:                      # noqa: BLE001 - 管道被超时关闭是正常路径
            pass

    threads = [threading.Thread(target=pump, args=(proc.stdout, out), daemon=True),
               threading.Thread(target=pump, args=(proc.stderr, err), daemon=True)]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        try:
            proc.wait(timeout=5)
        except Exception:                      # noqa: BLE001
            pass
    for thread in threads:
        thread.join(timeout=3.0)
    for stream in (proc.stdout, proc.stderr):
        try:
            stream.close()
        except Exception:                      # noqa: BLE001
            pass

    stdout, stderr = "".join(out), "".join(err)
    if timed_out:
        raise subprocess.TimeoutExpired(cmd, timeout, output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


def run_cmd(cmd, timeout=600):
    """执行 shell 命令，返回统一格式 {success, returncode, output}。"""
    sink = _PROGRESS.get("sink")
    if sink is not None:
        return _run_streaming(cmd, timeout, sink)
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        out = r.stdout.strip() or "(no output)"
        if r.stderr.strip():
            out += "\n[stderr] " + r.stderr.strip()[:500]
        return {"success": r.returncode == 0, "returncode": r.returncode, "output": out}
    except subprocess.TimeoutExpired as exc:
        # 超时也把已经拿到的 stdout 交回来（subprocess.run 是杀进程后再抛异常，
        # 之前已经读到的这段就在异常对象里，丢掉它等于凭空少一段结果）
        partial = (exc.stdout or "")
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", "replace")
        partial = partial.strip()
        out = (partial + "\n" if partial else "") + "[TIMEOUT] > %ss" % timeout
        return {"success": False, "returncode": -1, "output": out,
                "timeout": True, "partial": True}
    except Exception as exc:
        return {"success": False, "returncode": -1, "output": f"[ERROR] {exc}"}


def ok(output):
    """构造成功结果。"""
    return {"success": True, "returncode": 0, "output": output}


def fail(output, returncode=-1):
    """构造失败结果。"""
    return {"success": False, "returncode": returncode, "output": output}


def extract_target(val):
    """从输入中提取目标 IP/网段，支持 JSON 数组、逗号、换行、空格分隔。"""
    if not val:
        return ""
    if isinstance(val, (list, tuple)):
        return " ".join(str(x) for x in val)
    val = str(val).strip()
    try:
        arr = json.loads(val)
        if isinstance(arr, list):
            return " ".join(str(x) for x in arr)
    except Exception:
        pass
    return " ".join(p.strip() for p in re.split(r"[,\n]+", val) if p.strip())


def split_targets(val):
    """把目标参数拆成列表，支持 JSON 数组、逗号、换行、空格分隔。

    与 extract_target 的区别：那个把多个目标拼成一个字符串（给 nmap 这类吃
    空格分隔列表的工具）；这个返回列表，给"一个目标一次调用"的工具用 ——
    比如 nuclei 的 -u 必须每个目标一次，串成一串时多出来的会被当成位置参数，
    结果只扫了第一个，报告却写着扫描完成。
    """
    if not val:
        return []
    if isinstance(val, (list, tuple)):
        parts = [str(x) for x in val]
    else:
        text = str(val).strip()
        try:
            arr = json.loads(text)
            parts = [str(x) for x in arr] if isinstance(arr, list) else [text]
        except Exception:
            parts = re.split(r"[,\s]+", text)
    seen, targets = set(), []
    for part in parts:
        for chunk in re.split(r"[,\s]+", part):
            chunk = chunk.strip()
            if chunk and chunk not in seen:
                seen.add(chunk)
                targets.append(chunk)
    return targets


def ensure_url(val, default_port=80):
    """确保 URL 格式正确，自动补 scheme 与端口。"""
    val = (val or "").strip()
    if not val:
        return ""
    if val.startswith("http://") or val.startswith("https://"):
        return val
    m = re.match(r"^(\d+\.\d+\.\d+\.\d+):(\d+)$", val)
    if m:
        scheme = "https" if int(m.group(2)) == 443 else "http"
        return f"{scheme}://{val}"
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", val):
        return f"http://{val}:{default_port}"
    return "http://" + val


def host_of(val):
    """从 URL 或 host:port 中取出主机名。"""
    v = (val or "").strip()
    v = re.sub(r"^https?://", "", v)
    return v.split("/")[0].split(":")[0]


def port_of(val, default=80):
    """从 URL 或 host:port 中取出端口。"""
    v = (val or "").strip()
    if "://" in v:
        scheme, rest = v.split("://", 1)
        default = 443 if scheme == "https" else 80
        v = rest
    v = v.split("/")[0]
    if ":" in v:
        tail = v.rsplit(":", 1)[1]
        if tail.isdigit():
            return int(tail)
    return default


def ssh_exec(host, cmd, passwd=None, timeout=15, port=22, user="root"):
    """通过 SSH 执行命令；未提供密码时走密钥/agent。"""
    base = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p {port} {user}@{host}"
    if passwd:
        return run_cmd(f"sshpass -p '{passwd}' {base} '{cmd}' 2>&1", timeout)
    return run_cmd(f"{base} '{cmd}' 2>&1", timeout)


def is_valid_ip(val):
    try:
        ipaddress.IPv4Address((val or "").strip())
        return True
    except Exception:
        return False


def is_valid_subnet(val):
    try:
        ipaddress.IPv4Network((val or "").strip(), strict=False)
        return True
    except Exception:
        return False


def parse_ip_port_list(raw_text):
    """解析 IP:端口 列表，返回 {ip: [ports]}。"""
    ip_ports = {}
    for line in (raw_text or "").strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        found = re.findall(r"(\d+\.\d+\.\d+\.\d+):(\d+)", line)
        if found:
            for ip, port in found:
                ip_ports.setdefault(ip, set()).add(port)
            continue
        parts = line.split()
        if len(parts) >= 2 and is_valid_ip(parts[0]):
            ip_ports.setdefault(parts[0], set())
            for p in parts[1:]:
                if p.isdigit():
                    ip_ports[ip].add(p)
    return ip_ports


def which(name):
    """返回可执行文件路径，找不到返回 None。"""
    from shutil import which as _which

    return _which(name)


def require_tool(name, install_hint=""):
    """检查外部命令是否存在，返回错误结果或 None。"""
    if which(name):
        return None
    hint = f"（安装提示：{install_hint}）" if install_hint else ""
    return fail(f"缺少外部命令 {name}{hint}")


def loads_first_json(text):
    """从模型输出里取出第一个完整的 JSON 对象。

    本地模型有两种常见抖动：JSON 后面又跟一段解释；或者一个对象没包住、又补了一个。
    按 text.find("{") / rfind("}") 切片会把两个对象拼在一起，json.loads 直接报
    "Extra data: line 1 column N"，整份计划/复核就被丢掉了 —— 判定、复核、交叉验证
    都会退回规则实现，看起来像"本地模型不能用"，其实只是尾部多了一段文字。
    raw_decode 只吃第一个完整对象，后面多出来的内容忽略掉。
    """
    start = (text or "").find("{")
    if start < 0:
        raise ValueError("输出里没有 JSON 对象")
    try:
        data, _ = json.JSONDecoder().raw_decode(text[start:])
    except ValueError:
        raise ValueError("JSON 对象不完整")
    return data
