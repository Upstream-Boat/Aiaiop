#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""算力归因：把"这一轮跑在哪块 NVIDIA GPU 上"写进轨迹与报告。

平台适配性上有一条通用要求：「合理运用 NVIDIA 技术栈、开源模型和 SDK」。
本 skill 的模型推理跑在 DGX Spark 的 GPU 上，但光在 README 里写一句"用了 GPU"
没有说服力，所以每一轮任务都留下可核查的算力证据：卡型号、驱动与 CUDA 版本、
采样时刻的利用率/温度/功耗，以及推理进程实际占掉的显存。

取数三条路，按可用性依次退：
  1. 本机 nvidia-smi（NVML 的命令行前端，随驱动一起装，任何环境都有）—— Agent 直接
     跑在 GPU 机器上时走这条，最省事；
  2. GPU_METRICS_SSH —— 本机没有 GPU 时，用 SSH 到有 GPU 的那台跑同一条命令。
     本项目就是这种拆法（工具在 x86 执行机、推理在 DGX Spark），而这条路的
     **不需要在对方机器上新增任何常驻服务**，也不用把指标端口暴露到公网；
  3. GPU_METRICS_URL —— 可选的 HTTP 端点（scripts/gpu_metrics_server.py，
     强制 token + 默认只听本机）。只有前两条都不通时才用。

DGX Spark / GB10 的坑：设备级 memory.total / memory.used / power.limit 都返回 N/A
（统一内存架构），显存只能把计算进程的占用累加起来。所以每个字段都允许缺失，
缺了就留空，不编数 —— 报告里出现一个编出来的显存数字，比没有数字更糟。
"""

import json
import os
import re
import shlex
import subprocess
import time
import urllib.error
import urllib.request

TIMEOUT = 6
# skill 根目录：scripts/llm/gpu.py 往上三层（与 backends.py 同一套算法）
SKILL_HOME = os.environ.get("SEC_ASSESSMENT_HOME") or os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONFIG_PATH = os.path.join(SKILL_HOME, "data", "gpu_metrics.json")
# 一次查全：想加字段就加在这里，summary_line 会自己跳过取不到的
_GPU_FIELDS = ("name", "driver_version", "utilization.gpu", "utilization.memory",
               "temperature.gpu", "power.draw")
_APP_FIELDS = ("pid", "process_name", "used_memory")


def _ssh_prefix():
    """GPU_METRICS_SSH 形如 "<user>@<host> -p 22 -i ~/.ssh/id_ed25519"。"""
    target = (_setting("metrics_ssh")).strip()
    if not target:
        return ""
    # BatchMode=yes：缺 key 时立刻报错，不挂在交互式密码提示上把任务拖死
    return ("ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 %s "
            % target)


def _settings():
    """部署相关的值放 data/gpu_metrics.json，和 llm_backends.json 一个路子
    （数据目录不入库，环境变量优先）：
    {"metrics_ssh": "<user>@<host> -p 22 -i <key>", "metrics_url": "", "token": ""}
    """
    try:
        with open(CONFIG_PATH, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _setting(name):
    """环境变量优先，其次配置文件。"""
    env_name = {"metrics_ssh": "GPU_METRICS_SSH", "metrics_url": "GPU_METRICS_URL",
                "token": "GPU_METRICS_TOKEN"}[name]
    return os.environ.get(env_name) or str(_settings().get(name) or "")


def _sh(cmd, via_ssh=False):
    """跑一条只读命令；失败（没装 nvidia-smi、权限不足）一律当"没有"，不抛异常。"""
    if via_ssh:
        prefix = _ssh_prefix()
        if not prefix:
            return ""
        cmd = prefix + shlex.quote(cmd)
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=TIMEOUT)
    except Exception:                       # noqa: BLE001 - 取不到算力数据不该影响任务
        return ""
    return proc.stdout or ""


def _clean(value):
    """nvidia-smi 的"没这个字段"写法有 [N/A] / N/A / Unknown 几种，统一成 None。"""
    text = (value or "").strip()
    if text.strip("[]").upper() in ("", "N/A", "UNKNOWN", "NOT SUPPORTED"):
        return None
    return text


def _number(value):
    """'0 %' / '10.89 W' / '38' → 数值；取不到返回 None。"""
    text = _clean(value)
    if text is None:
        return None
    try:
        return float(text.split()[0])
    except (ValueError, IndexError):
        return None


def _cuda_version(via_ssh=False):
    """CUDA 版本只在 nvidia-smi 的表头里有，没有 --query-gpu 字段可用。"""
    match = re.search(r"CUDA Version:\s*([0-9.]+)", _sh("nvidia-smi 2>/dev/null", via_ssh))
    return match.group(1) if match else None


def _processes(via_ssh=False):
    """占着 GPU 的计算进程。显存是按进程算的 —— 这是 GB10 上唯一能拿到显存的口子。"""
    out = _sh("nvidia-smi --query-compute-apps=%s --format=csv,noheader,nounits 2>/dev/null"
              % ",".join(_APP_FIELDS), via_ssh)
    items, total = [], 0.0
    for line in out.strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 3:
            continue
        used = _number(parts[2])
        items.append({"pid": parts[0], "name": parts[1], "used_memory_mb": used})
        if used:
            total += used
    return items, (int(total) if total else None)


def local_snapshot(via_ssh=False):
    """nvidia-smi 快照；没有 GPU / 没有驱动时返回 None。via_ssh 时在远端机器上跑同一套命令。"""
    line = _sh("nvidia-smi --query-gpu=%s --format=csv,noheader,nounits 2>/dev/null"
               % ",".join(_GPU_FIELDS), via_ssh).strip().splitlines()
    if not line:
        return None
    values = [p.strip() for p in line[0].split(",")]
    if len(values) < len(_GPU_FIELDS):
        return None
    values += [None] * (len(_GPU_FIELDS) - len(values))
    name, driver = _clean(values[0]), _clean(values[1])
    if not name:
        return None
    processes, used = _processes(via_ssh)
    return {
        "source": "nvidia-smi-over-ssh" if via_ssh else "nvidia-smi",
        "host": _sh("hostname 2>/dev/null", via_ssh).strip() or None,
        "name": name,
        "driver": driver,
        "cuda": _cuda_version(via_ssh),
        "utilization_gpu": _number(values[2]),
        "utilization_memory": _number(values[3]),
        "temperature_c": _number(values[4]),
        "power_w": _number(values[5]),
        # 设备级显存在 GB10 上是 N/A，退到按进程累加；两个都取不到才留空
        "memory_used_mb": used,
        "processes": processes,
    }


def remote_snapshot(url=None, timeout=TIMEOUT):
    """去 GPU_METRICS_URL 取快照（DGX Spark 上跑 scripts/gpu_metrics_server.py）。"""
    target = url or _setting("metrics_url")
    if not target:
        return None
    try:
        headers = {}
        token = _setting("token")
        if token:
            headers["X-Auth-Token"] = token
        request = urllib.request.Request(target, headers=headers)
        with urllib.request.urlopen(request, timeout=timeout) as res:
            data = json.loads(res.read().decode("utf-8", "replace"))
    except Exception:                       # noqa: BLE001 - 取不到就如实留空
        return None
    if not isinstance(data, dict) or not data.get("name"):
        return None
    data["source"] = data.get("source") or "remote"
    return data


def snapshot(remote_url=None):
    """本机优先；本机没 GPU 就先走 SSH，再退 HTTP 端点；都不通返回 None。"""
    if time.time() < _NO_GPU_UNTIL[0]:
        return None
    found = local_snapshot() or local_snapshot(via_ssh=True) or remote_snapshot(remote_url)
    if found is None:
        # 没有 GPU 的环境里，每次采样都要白等一个网络超时 —— 一分钟内不再重试
        _NO_GPU_UNTIL[0] = time.time() + 60
    return found


# "这里没有 GPU"这个结论的冷却期（见 snapshot）
_NO_GPU_UNTIL = [0.0]


class Recorder(object):
    """一路攒 GPU 采样，任务结束时给出一份摘要。

    采样点是模型调用（推理才是真正的算力消耗）；任务开始时和结束时各补一次，
    于是报告里既有"空闲时的底数"也有"推理时的峰值"，可核查。
    """

    def __init__(self, remote_url=None, min_interval=0.5):
        self.remote_url = remote_url
        self.min_interval = min_interval
        self.samples = []
        self._last_at = 0.0

    def sample(self, stage=""):
        # 流式调用里每来一段文本都会走到这里，必须限流，否则采样比推理还费
        now = time.time()
        if now - self._last_at < self.min_interval:
            return None
        self._last_at = now
        snap = snapshot(self.remote_url)
        if snap:
            snap["stage"] = stage
            self.samples.append(snap)
        return snap

    def summary(self):
        """last = 最近一次读数；peak_utilization = 整轮里的峰值（推理真的烧了算力才看得出来）。"""
        if not self.samples:
            return None
        peaks = [s.get("utilization_gpu") for s in self.samples
                 if s.get("utilization_gpu") is not None]
        powers = [s.get("power_w") for s in self.samples if s.get("power_w") is not None]
        last = dict(self.samples[-1])
        last.pop("stage", None)
        return {"last": last,
                "peak_utilization_gpu": max(peaks) if peaks else None,
                "peak_power_w": max(powers) if powers else None,
                "samples": len(self.samples),
                "line": summary_line(last)}


# 全进程共用一份：模型客户端采样，编排层取摘要
recorder = Recorder()


def summary_line(gpu):
    """写成一行给报告/控制台用；取不到的字段直接不出现，不留"—"占位。"""
    if not gpu:
        return ""
    bits = [gpu.get("name") or ""]
    if gpu.get("driver"):
        bits.append("驱动 %s" % gpu["driver"])
    if gpu.get("cuda"):
        bits.append("CUDA %s" % gpu["cuda"])
    if gpu.get("utilization_gpu") is not None:
        bits.append("利用率 %.0f%%" % gpu["utilization_gpu"])
    if gpu.get("memory_used_mb"):
        bits.append("显存占用 %.1f GB" % (gpu["memory_used_mb"] / 1024.0))
    if gpu.get("temperature_c") is not None:
        bits.append("%.0f°C" % gpu["temperature_c"])
    if gpu.get("power_w") is not None:
        bits.append("%.1fW" % gpu["power_w"])
    if gpu.get("source"):
        bits.append("来源 %s" % gpu["source"])
    return "　｜　".join([b for b in bits if b])


def _main():
    import argparse

    parser = argparse.ArgumentParser(description="算力归因快照（本机 NVML/nvidia-smi，或远端指标端点）")
    parser.add_argument("--url", default="", help="远端指标端点，默认读 GPU_METRICS_URL")
    parser.add_argument("--line", action="store_true", help="只打印一行摘要")
    args = parser.parse_args()
    snap = snapshot(args.url or None)
    if snap is None:
        print("未取到 GPU 指标（本机没有 nvidia-smi，也没配 GPU_METRICS_SSH / GPU_METRICS_URL）")
        return
    print(summary_line(snap) if args.line else json.dumps(snap, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    _main()
