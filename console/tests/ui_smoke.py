#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""控制台 UI 冒烟测试 —— 只查"点得动吗"，不查好不好看。

为什么要有这个：Vue 3 的模板表达式只在组件实例作用域里求值，取不到 window 上的
全局变量。导航按钮写的是 `@click="router.go(...)"`，只要忘了把 router 挂到
`app.config.globalProperties`，五个页签就全部点不动，而页面看起来完全正常
（标题、样式、健康状态都对）—— 属于"静默失效"，人眼扫一遍发现不了。

跑法：
    python3 console/tests/ui_smoke.py                       # 默认 http://localhost:8787/
    python3 console/tests/ui_smoke.py --base http://192.168.1.20:8787/ --headed
"""

import argparse
import sys

TABS = ["任务台", "工具状态", "规则库", "审计链"]
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print("%s %s%s" % ("PASS" if ok else "FAIL", name, "  — " + detail if detail else ""))


def main():
    parser = argparse.ArgumentParser(description="控制台 UI 冒烟测试")
    parser.add_argument("--base", default="http://localhost:8787/", help="控制台地址")
    parser.add_argument("--headed", action="store_true", help="显示浏览器窗口")
    args = parser.parse_args()

    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=not args.headed)
        page = browser.new_page(viewport={"width": 1600, "height": 1000})

        errors = []
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append("pageerror: %s" % e))

        page.goto(args.base, wait_until="networkidle")
        page.wait_for_timeout(800)

        check("页面能打开", bool(page.title()), page.title())

        # 1) 五个页签必须真的切得动（顶栏标题跟着变）
        switched = []
        for label in TABS:
            page.click(".nav-item:has-text('%s')" % label)
            page.wait_for_timeout(900)
            heading = page.locator(".topbar h1").inner_text().strip()
            switched.append(heading == label)
        check("四个页签都能切换", all(switched),
              "结果=%s" % list(zip(TABS, switched)))

        # 2) 每个视图都要渲染出内容，不能是空白
        empty = []
        for label in TABS:
            page.click(".nav-item:has-text('%s')" % label)
            page.wait_for_timeout(2500)
            if len(page.evaluate("document.body.innerText")) < 300:
                empty.append(label)
        check("各视图都渲染出内容", not empty, "空视图=%s" % empty)

        # 3) 任务台：控制台不下达任务 —— 页面上不该出现输入框
        page.click(".nav-item:has-text('任务台')")
        page.wait_for_timeout(1500)
        check("任务台没有输入框（控制台不下达任务）",
              page.locator(".view textarea").count() == 0
              and page.locator(".view .composer").count() == 0, "")
        # 4) 任务台进页面就要自己选中一个工具，调用流水不能是空的
        #    （这一页的主轴是"哪个工具被调了"，不是"哪次任务走到哪"）
        picked = page.locator(".view .tool-item.active").count()
        rows = page.locator(".view .call-row").count()
        check("任务台进页面即选中工具", picked == 1, "选中=%d" % picked)
        check("任务台流水立刻有调用数据", rows >= 1, "调用行=%d" % rows)
        # 5) 阶段条：判定 -> 授权 -> 执行 -> 复核 -> 交叉验证 -> 报告
        #    （交叉验证这一格是后加的：断言跟着产品走，不要停在旧版式上）
        check("任务台阶段条六格齐全", page.locator(".view .trace-step").count() == 6,
              "%d 格" % page.locator(".view .trace-step").count())

        check("前端无控制台报错", not errors, "报错=%s" % errors[:3])
        browser.close()

    failed = [n for n, ok, _ in RESULTS if not ok]
    print("-" * 62)
    print("总计 %d 项，通过 %d 项，失败 %d 项" % (len(RESULTS), len(RESULTS) - len(failed), len(failed)))
    if failed:
        print("失败项：" + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
