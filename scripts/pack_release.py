#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打包发布版 —— 生成"可提交"的 skill 压缩包，并自动脱敏。

为什么单独有这个脚本：
    开发机上 `data/nvd_api_key.txt` 里放的是**真实** NVD key（否则没法更新 CVE 库），
    但提交/分发的包里绝不应该带真实凭据（官方治理的 SkillSpector 会做密钥扫描）。
    与其天天手工记得改回来，不如把"脱敏"固定成打包这一步的自动行为：
    真 key 留在工作目录，只有打包产物被清洗。

流程：
    1. 复制 skill 到临时目录，排除 data/runtime、__pycache__、.git、报告等运行产物；
    2. 把已知凭据文件替换为占位示例；
    3. 对整棵产物树做密钥扫描，发现可疑项直接**中止**（不会产出脏包）；
    4. 在产物内重建 MANIFEST.sha256；
    5. 打成 zip（提交方基本只收 zip；要 tar.gz 加 --tar），打印体积与文件数。

用法：
    python3 scripts/pack_release.py                    # 默认输出到 ../dist/
    python3 scripts/pack_release.py --out /tmp/dist
    python3 scripts/pack_release.py --keep-dir         # 保留解包目录，便于人工复核
"""

import argparse
import os
import re
import shutil
import sys
import tarfile
import tempfile
import time
import zipfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_HOME = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, SCRIPT_DIR)

# 不进入发布包的路径（运行产物、缓存、报告、旧的审计数据）
EXCLUDE_DIRS = {"__pycache__", ".git", "node_modules", "runtime", "results"}
EXCLUDE_SUFFIXES = (".pyc", ".pyo")

# 凭据文件 → 打包时写入的占位内容
SCRUB_FILES = {
    "data/nvd_api_key.txt": "your-nvd-api-key-here\n",
}

# 密钥特征（与 evals/run.py 的期望保持一致）
SECRET_PATTERNS = [
    ("OpenAI 风格 key", re.compile(r"sk-[A-Za-z0-9_\-]{16,}")),
    ("Bearer 串", re.compile(r"Bearer\s+[A-Za-z0-9._\-]{16,}")),
    ("私钥块", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("UUID 形密钥", re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")),
    ("长令牌", re.compile(r"\b[A-Za-z0-9_\-]{40,}\b")),
]


def looks_like_slug(token):
    """把"连字符很多的自然语言 slug"从长令牌里摘出去。

    Agent 的答复里经常带新闻链接的 slug，例如
    `macos-tahoe-26-5-1-kritischer-stabilitaetspatch-fuer-m5-macs-am-1-juni`
    —— 40+ 字符、全小写、一串连字符，会被"长令牌"规则误判成凭据。
    真正的密钥基本不会带 4 个以上连字符（UUID 另有专门规则）。
    """
    if token.count("-") >= 4 and not any(c.isupper() for c in token):
        return True
    return False
# 这些是文档里的正常写法，不算泄漏
SECRET_ALLOWLIST = ("<", "your", "example", "示例", "xxxx", "redacted", "placeholder",
                    "sha256", "sha512", "-----BEGIN CERTIFICATE")
# 二进制/大文件跳过扫描
SCAN_SKIP_SUFFIXES = (".sqlite", ".db", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".mp4",
                      ".zip", ".gz", ".tar", ".woff", ".woff2", ".ttf", ".ico")

# 第三方规则库整目录跳过扫描 —— 里面的"疑似密钥"是漏洞 PoC 自带的样本
# （shellcode、base64 payload、被复现的测试私钥），本来就要原样分发；
# 上游按 sha256 校验，不是我们写的东西。扫它只会把误报刷到七万条，
# 把真正的自家代码扫描淹掉。
SCAN_SKIP_DIRS = ("data",)


def copy_tree(dst_root, include_data=True):
    """复制 skill 到 dst_root/sec-assessment，返回产物根目录。

    include_data=False 时跳过 data/ 下的规则库（CVE 库 + Exploit-DB + nuclei 模板约 935 MB），
    只打代码包 —— 便于快速分发；规则库按 references/dependencies.md 自行获取。
    """
    dst = os.path.join(dst_root, "sec-assessment")
    for dirpath, dirnames, filenames in os.walk(SKILL_HOME):
        rel = os.path.relpath(dirpath, SKILL_HOME)
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        if not include_data and (rel == "data" or rel.startswith("data" + os.sep)):
            continue
        if not include_data:
            dirnames[:] = [d for d in dirnames if d != "data"]
        target_dir = dst if rel == "." else os.path.join(dst, rel)
        os.makedirs(target_dir, exist_ok=True)
        for name in filenames:
            if name.endswith(EXCLUDE_SUFFIXES) or name == "MANIFEST.sha256":
                continue
            shutil.copy2(os.path.join(dirpath, name), os.path.join(target_dir, name))
    return dst


def scrub(dst):
    """把凭据文件替换成占位内容。返回被脱敏的文件列表。"""
    scrubbed = []
    for rel, placeholder in SCRUB_FILES.items():
        path = os.path.join(dst, rel)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8", errors="ignore") as handle:
            current = handle.read().strip()
        if current == placeholder.strip():
            continue
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(placeholder)
        scrubbed.append(rel)
    return scrubbed


def scan_secrets(dst):
    """扫描产物树里的明文凭据，返回可疑项列表（不含第三方规则库）。"""
    findings = []
    for dirpath, dirnames, filenames in os.walk(dst):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        rel_dir = os.path.relpath(dirpath, dst)
        if rel_dir.split(os.sep)[0] in SCAN_SKIP_DIRS:
            continue
        for name in filenames:
            if name.endswith(SCAN_SKIP_SUFFIXES):
                continue
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) > 3_000_000:
                    continue
                text = open(full, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if any(a in line.lower() for a in SECRET_ALLOWLIST):
                    continue
                for label, pattern in SECRET_PATTERNS:
                    hit = pattern.search(line)
                    if hit and label == "长令牌" and looks_like_slug(hit.group(0)):
                        continue
                    if hit:
                        findings.append((label, os.path.relpath(full, dst), lineno,
                                         line.strip()[:100]))
    return findings


def rebuild_manifest(dst):
    """在产物里重建 MANIFEST.sha256（用产物自己的 gen_manifest.py）。"""
    import subprocess
    proc = subprocess.run([sys.executable, os.path.join(dst, "scripts", "gen_manifest.py")],
                          capture_output=True, text=True, cwd=dst)
    if proc.returncode != 0:
        raise SystemExit("产物内重建 MANIFEST 失败：\n" + (proc.stderr or proc.stdout))
    return (proc.stdout or "").strip()


def main():
    parser = argparse.ArgumentParser(description="打包可提交的 skill 发布版（自动脱敏）")
    parser.add_argument("--out", default=os.path.join(os.path.dirname(SKILL_HOME), "dist"),
                        help="输出目录（默认 ../dist）")
    parser.add_argument("--keep-dir", action="store_true", help="保留解包目录供人工复核")
    parser.add_argument("--no-data", action="store_true",
                        help="不打规则库（约 935 MB），只出代码包")
    parser.add_argument("--tar", action="store_true",
                        help="改回 tar.gz 输出（默认 zip）")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    stage = tempfile.mkdtemp(prefix="sec-assessment-pack-")
    print("① 复制（排除运行产物%s）…" % ("，跳过 data/ 规则库" if args.no_data else ""))
    dst = copy_tree(stage, include_data=not args.no_data)

    print("② 脱敏凭据…")
    scrubbed = scrub(dst)
    print("   已脱敏：%s" % (", ".join(scrubbed) if scrubbed else "无（本就干净）"))

    print("③ 密钥扫描…（跳过第三方规则库：%s）" % ", ".join(SCAN_SKIP_DIRS))
    findings = scan_secrets(dst)
    if findings:
        print("   ✗ 发现 %d 处可疑内容，已中止打包：" % len(findings))
        for label, path, lineno, snippet in findings[:20]:
            print("     [%s] %s:%d  %s" % (label, path, lineno, snippet))
        shutil.rmtree(stage, ignore_errors=True)
        return 1
    print("   ✓ 未发现明文凭据")

    print("④ 重建 MANIFEST…")
    print("   " + rebuild_manifest(dst))

    stamp = time.strftime("%Y%m%d")
    name = "sec-assessment-%s%s" % (stamp, "-codeonly" if args.no_data else "")
    print("⑤ 打包…")
    if args.tar:
        archive = os.path.join(args.out, name + ".tar.gz")
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(dst, arcname="sec-assessment")
    else:
        archive = os.path.join(args.out, name + ".zip")
        # 顶层套一层 sec-assessment/：解包后目录名固定，install.sh 和 README 都按它写
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for root, _dirs, files in os.walk(dst):
                for fname in files:
                    full = os.path.join(root, fname)
                    zf.write(full, os.path.join("sec-assessment",
                                                os.path.relpath(full, dst)))

    size = os.path.getsize(archive) / 1024 / 1024
    count = sum(len(f) for _, _, f in os.walk(dst))
    print("\n完成：%s" % archive)
    print("  体积 %.1f MB ｜ 文件 %d 个" % (size, count))
    if args.keep_dir:
        print("  解包目录保留在：%s" % dst)
    else:
        shutil.rmtree(stage, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
