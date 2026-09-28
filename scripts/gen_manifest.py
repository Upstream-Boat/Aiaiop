#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 MANIFEST.sha256 —— skill 内容指纹清单，用于完整性校验与篡改演示。

覆盖范围（与 MANIFEST.sha256 头部注释保持一致）：
    SKILL.md / skill-card.md / BENCHMARK.md / LICENSE / NOTICE / install.sh /
    agents/ / scripts/ / references/ / evals/
不覆盖：
    data/           第三方规则库，各自有上游许可证与校验方式
    data/runtime/   运行时产物（轨迹、报告、审计链）
    __pycache__/    字节码缓存
    MANIFEST.sha256 自身（自指会让校验永远失败）

用法：
    python3 scripts/gen_manifest.py            # 重新生成
    sha256sum -c MANIFEST.sha256               # 校验
"""

import hashlib
import os
import sys

SKILL_HOME = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(SKILL_HOME, "MANIFEST.sha256")

# 逐个收录的顶层文件
TOP_FILES = ("SKILL.md", "skill-card.md", "BENCHMARK.md", "LICENSE", "NOTICE", "install.sh")
# 递归收录的目录
TOP_DIRS = ("agents", "scripts", "references", "evals")
# 任何层级都要跳过的目录名
SKIP_DIRS = {"__pycache__", "data", ".git", "node_modules", "results"}

HEADER = """# sec-assessment 内容清单（MANIFEST）
# 覆盖：SKILL.md / skill-card.md / BENCHMARK.md / LICENSE / NOTICE / install.sh / agents/ / scripts/ / references/ / evals/
# 不覆盖：data/（第三方规则库，各自有上游许可证与校验）、data/runtime/（运行时产物）、__pycache__/、本清单自身
# 校验方式：在本目录执行  sha256sum -c MANIFEST.sha256
# 重新生成：python3 scripts/gen_manifest.py
"""


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect():
    """返回排好序的 (相对路径, 绝对路径) 列表。"""
    files = []
    for name in TOP_FILES:
        full = os.path.join(SKILL_HOME, name)
        if os.path.isfile(full):
            files.append((name, full))
    for top in TOP_DIRS:
        root = os.path.join(SKILL_HOME, top)
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            # 就地裁剪，避免走进不该进的目录
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for filename in sorted(filenames):
                if filename.endswith((".pyc", ".pyo")):
                    continue
                full = os.path.join(dirpath, filename)
                files.append((os.path.relpath(full, SKILL_HOME), full))
    return sorted(files, key=lambda item: item[0])


def main():
    files = collect()
    lines = [HEADER]
    for rel, full in files:
        lines.append("%s  %s" % (sha256_of(full), rel))
    with open(MANIFEST, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    print("已生成 %s：%d 个文件" % (MANIFEST, len(files)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
