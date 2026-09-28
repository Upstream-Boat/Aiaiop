#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""校验审计链 —— 确认运行轨迹没有被事后篡改。

审计链是一条 HMAC 串联的哈希链：每条记录都带前一条的哈希，
改动任意一条都会让后续整条链校验失败。这里提供命令行入口，
便于手工复核、演示与 CI 断言。

用法：
    python3 scripts/verify_audit.py              # 校验并打印结论
    python3 scripts/verify_audit.py --json       # 输出原始 JSON，便于脚本消费
    python3 scripts/verify_audit.py --limit 50   # 只校验最近 50 条

退出码：0 = 通过；1 = 发现篡改或链断裂。
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import audit  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="校验 sec-assessment 审计链完整性")
    parser.add_argument("--json", action="store_true", help="输出原始 JSON")
    parser.add_argument("--limit", type=int, default=0, help="只校验最近 N 条（0 = 全部）")
    args = parser.parse_args()

    result = audit.verify(limit=args.limit or 0)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("ok") else 1

    anchors = result.get("anchors") or {}
    print("审计链校验")
    print("  结论      : %s" % ("通过（未发现篡改）" if result.get("ok") else "失败（疑似被篡改）"))
    print("  记录总数  : %s" % result.get("total"))
    print("  已校验    : %s%s" % (result.get("checked"),
                                  "（其中 %s 条为旧格式无哈希）" % result.get("legacy")
                                  if result.get("legacy") else ""))
    print("  算法      : %s" % result.get("algo"))
    print("  链头      : %s" % result.get("to_id"))
    print("  锚点      : 已记录 %s 条，断点 %s" % (anchors.get("recorded"), anchors.get("breaks")))
    for item in (result.get("tampered") or [])[:5]:
        print("  篡改嫌疑  : %s @ %s  %s" % (item.get("action"), item.get("at"), item.get("reason")))
    for item in (result.get("broken") or [])[:5]:
        print("  断链      : %s" % item)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
