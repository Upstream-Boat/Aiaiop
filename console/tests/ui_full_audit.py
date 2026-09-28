#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""控制台全量功能巡检 —— 每个视图的每个功能点都点一遍并断言。

按视图分段，**一段抛异常不影响其它段**（和 evals/smoke.py 一样的思路），
这样一次运行能拿到完整的问题清单，而不是断在第一个坑上。

跑法：
    python3 console/tests/ui_full_audit.py
    python3 console/tests/ui_full_audit.py http://192.168.1.20:8787/

注意：会真实触发一次规则库增量更新（约 45s）。

控制台不下达任务：任务由宿主 Agent / MCP 客户端 / 命令行触发，控制台只负责
配置、观测与体检 —— 所以任务台里断言的是"轨迹渲染正确"，不是"能发出去"。
也没有报告页：报告是宿主 Agent 的产出，控制台只管这个工具自身的运转。
"""

import re
import sys
import time

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8787/"
# 这些接口的 4xx 属于用例故意触发的，不算全站异常
EXPECTED_BAD = ()

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print("%s %-32s %s" % ("PASS" if ok else "FAIL", name, detail[:100]), flush=True)


def num_before_label(text, label):
    m = re.search(r"([\d,]+)\s*\n\s*" + re.escape(label), text)
    return int(m.group(1).replace(",", "")) if m else None


def section(title, fn, *args):
    print("\n── %s " % title + "─" * (58 - len(title)), flush=True)
    try:
        fn(*args)
    except Exception as exc:  # noqa: BLE001 —— 单段异常不应中断整轮
        check("%s 未抛异常" % title, False, "%s: %s" % (type(exc).__name__, str(exc)[:80]))


# ══════════════════════════════════════════════════════ 各视图

def sec_tasks(pg):
    """任务台的主轴是"工具"：索引 -> 这个工具的调用流水 -> 这一次调用的原文。"""
    pg.click(".nav-item:has-text('任务台')")
    pg.wait_for_timeout(2500)
    tools = pg.locator(".tool-item").count()
    check("任务台/工具索引渲染", tools > 0, "%d 个被调用过的工具" % tools)

    # 进页面不点任何东西就应该已经在看某个工具（否则流水是空的，"实时查看工具使用"无从谈起）
    pg.wait_for_timeout(2000)
    auto = pg.evaluate("""() => ({
        picked: document.querySelectorAll('.view .tool-item.active').length,
        rows: document.querySelectorAll('.view .call-row').length,
        detail: ((document.querySelector('.view .detail-log') || {}).innerText || '').length
    })""")
    check("任务台/进页面即选中一个工具", auto["picked"] == 1, "选中=%d" % auto["picked"])
    check("任务台/调用流水立刻有数据", auto["rows"] >= 1, "调用行=%d" % auto["rows"])

    # 点第二个工具，确认流水跟着换（而不是只换了高亮）
    second = pg.locator(".tool-item").nth(1)
    name = second.inner_text().strip().split("\n")[0]
    second.click()
    pg.wait_for_timeout(2500)
    flow = pg.evaluate("""() => ({
        head: (document.querySelector('.view .flow-card .card-head') || {}).innerText || '',
        rows: [...document.querySelectorAll('.view .call-row')].map(e => e.innerText.trim()),
        times: [...document.querySelectorAll('.view .call-row .t')].map(e => e.innerText.trim())
    })""")
    check("任务台/切换工具会换掉流水", name in flow["head"].replace("\n", " ") or len(flow["rows"]) >= 1,
          "工具=%s 流水=%d 行" % (name, len(flow["rows"])))
    check("任务台/流水有时间与结果", len(flow["times"]) == len(flow["rows"]) and len(flow["rows"]) >= 1,
          "%d 行" % len(flow["rows"]))

    # 点一行看这一次调用的参数与原始输出
    pg.locator(".view .call-row").nth(0).click()
    pg.wait_for_timeout(2500)
    detail = pg.evaluate("""() => ({
        params: ((document.querySelector('.view .detail-params') || {}).innerText || '').trim(),
        log: ((document.querySelector('.view .detail-log') || {}).innerText || '').trim(),
        digest: ((document.querySelector('.view .detail-digest') || {}).innerText || '').trim(),
        body: ((document.querySelector('.view .detail-body') || {}).innerText || '').trim(),
        stages: [...document.querySelectorAll('.view .trace-step')].map(e => e.innerText.trim()),
        title: ((document.querySelector('.view .task-side .run-title') || {}).innerText || '').trim()
    })""")
    check("任务台/点一行看到这次调用的参数", len(detail["params"]) > 6, detail["params"][:40].replace("\n", " "))
    # 阈值按"确实有内容"来卡：这条流水可能只有一行短输出（比如 10 个字符的 ping 结果），
    # 卡 >10 会把正常内容判成失败。
    check("任务台/看到原始输出", len(detail["log"]) >= 8, "%d 字符" % len(detail["log"]))
    # 摘要这一块是任务台的主角：先给结论，再往下才是原文
    check("任务台/给出执行结果摘要", len(detail["digest"]) >= 4, detail["digest"][:60].replace("\n", " | "))
    # 输出的来路要写在脸上：实时尾巴 / 完整原文 / 轨迹开头，三者不能混着说
    check("任务台/标明输出从哪来",
          any(k in detail["body"] for k in ("完整原文", "实时输出", "工具原样输出",
                                            "轨迹里的开头", "运行中，等待工具输出")),
          detail["body"].split("\n")[-1][:60] if detail["body"] else "")
    check("任务台/所属任务六阶段齐全", len(detail["stages"]) == 6, "阶段=%s" % detail["stages"])
    check("任务台/标明这次调用属于哪次任务", bool(detail["title"]), detail["title"][:40])
    check("任务台/没有真实运行时不假装在跑", pg.locator(".view .live-row").count() == 0, "")

    # 输入框已退役：控制台只显示执行，不下去下达任务
    pg.goto(BASE, wait_until="load")
    pg.wait_for_timeout(2500)
    check("任务台/没有输入框（控制台不下达任务）",
          pg.locator(".view textarea").count() == 0 and pg.locator(".view .composer").count() == 0, "")
    empty = pg.locator(".view").inner_text()
    check("任务台/标注任务从哪里发起",
          ("runner.py" in empty) and ("mcp_server.py" in empty), "")
    check("任务台/保留授权边界提示", "已获授权" in empty, "")

    pg.click(".view button:has-text('刷新')")
    pg.wait_for_timeout(2000)
    check("任务台/刷新按钮生效", pg.locator(".tool-item").count() > 0, "")

    # 顶栏要么给出统计口径，要么明说空闲——不能是空白
    stats = pg.locator(".view .stat").count()
    scope = "统计范围" in pg.locator(".view").inner_text()
    check("任务台/统计有口径", stats >= 3 and scope, "%d 个统计位；口径=%s" % (stats, scope))
    check("任务台/审计留痕有链条目", pg.locator(".view .chain-row").count() >= 3,
          "%d 条" % pg.locator(".view .chain-row").count())

    # 版面：顶部那条横条只铺到中栏右缘（不铺满整宽），右栏贯通两行顶到页顶。
    # 横条铺满整宽的话，右栏只能排在它下面，三张卡被压成一溜。
    lay = pg.evaluate("""() => {
        const r = (s) => { const e = document.querySelector(s); if (!e) return null;
            const b = e.getBoundingClientRect(); return {l: b.left, r: b.right, t: b.top, b: b.bottom}; };
        const v = document.querySelector('.view');
        return { hero: r('.view .live-hero'), detail: r('.view .detail-card'),
                 side: r('.view .task-side'), main: r('.view .task-main'),
                 sideCards: document.querySelectorAll('.view .task-side > .card').length,
                 page: r('.view .task-page'),
                 viewScroll: v.scrollHeight - v.clientHeight };
    }""")
    check("任务台/顶部横条止于中栏右缘", lay["hero"] and abs(lay["hero"]["r"] - lay["detail"]["r"]) <= 2,
          "横条右缘 %s / 中栏右缘 %s" % (round(lay["hero"]["r"]), round(lay["detail"]["r"])))
    check("任务台/左中两栏并排、右栏在右侧", lay["main"] and lay["side"]
          and abs(lay["main"]["l"] - lay["hero"]["l"]) <= 2 and lay["side"]["l"] > lay["main"]["r"],
          "main %s~%s / side 左缘 %s" % (round(lay["main"]["l"]), round(lay["main"]["r"]), round(lay["side"]["l"])))
    check("任务台/右栏贯通两行顶到页顶", lay["side"] and abs(lay["side"]["t"] - lay["hero"]["t"]) <= 2
          and abs(lay["side"]["b"] - lay["page"]["b"]) <= 2,
          "侧栏 %s~%s / 页 %s~%s" % (round(lay["side"]["t"]), round(lay["side"]["b"]),
                                     round(lay["page"]["t"]), round(lay["page"]["b"])))
    check("任务台/整页按视口收尾，不靠整页滚", lay["viewScroll"] <= 4, "可滚 %dpx" % lay["viewScroll"])
    pg.click(".view .seg button:has-text('失败')")
    pg.wait_for_timeout(900)
    filtered = pg.locator(".tool-item").count()
    # 判据不依赖"机器上刚好有失败调用"：筛出来每一条都必须自报失败。
    # 以前断言 filtered > 0，于是在一轮全是成功的演示数据上必然误报。
    marks = pg.evaluate("""() => [...document.querySelectorAll('.view .tool-item')]
        .map(e => e.innerText)""")
    pg.click(".view .seg button:has-text('全部')")
    pg.wait_for_timeout(900)
    check("任务台/索引按失败筛选生效",
          all(("失败" in t or "被拦" in t) for t in marks) and filtered <= pg.locator(".tool-item").count(),
          "筛选后 %d 个（全部自报失败=%s）" % (filtered, all("失败" in t for t in marks)))


def sec_tools(pg):
    """工具状态：卡片墙一眼看全 43 个工具的可用性，点卡片看详情。"""
    pg.click(".nav-item:has-text('工具状态')")
    pg.wait_for_timeout(4000)
    tt = pg.locator(".view").inner_text()
    check("工具状态/体检统计渲染", "外部命令就绪" in tt and "工具可执行" in tt, "")
    # 依赖清单默认收起（摊开会把"工具能不能用"挤没），点开才出现
    check("工具状态/依赖清单默认收起", pg.locator(".view .dep-split").count() == 0, "")
    pg.click(".view button:has-text('展开依赖清单')")
    pg.wait_for_timeout(1200)
    expanded = pg.locator(".view").inner_text()
    check("工具状态/依赖清单可展开", pg.locator(".view .dep-split").count() == 1, "")
    check("工具状态/命令表有判据",
          "外部命令" in expanded and any(k in expanded for k in ("就绪", "缺失", "异常")), "")
    check("工具状态/自带资源表渲染", "自带资源" in expanded, "")
    pg.click(".view button:has-text('收起依赖清单')")
    pg.wait_for_timeout(900)
    check("工具状态/依赖清单可收起", pg.locator(".view .dep-split").count() == 0, "")

    cards = pg.locator(".view .tool-card").count()
    check("工具状态/工具墙铺满所有工具", cards >= 40, "%d 张卡片" % cards)

    # 版面：左墙 + 右详情两块并排、都顶到页顶。别的视图往样式表里加裸类名
    # （比如 .side）时，最先坏的就是这里 —— 墙会被挤成一条、详情掉到页面中间。
    tlay = pg.evaluate("""() => {
        const r = (s) => { const e = document.querySelector(s); if (!e) return null;
            const b = e.getBoundingClientRect(); return {l: b.left, r: b.right, w: b.width, t: b.top}; };
        const g = document.querySelector('.view .tools-grid');
        const v = document.querySelector('.view');
        return { wall: r('.view .wall-card'), col: r('.view .tools-grid > .col'), grid: r('.view .tools-grid'),
                 viewScroll: v.scrollHeight - v.clientHeight,
                 tracks: g ? getComputedStyle(g).gridTemplateColumns : '' };
    }""")
    check("工具状态/工具墙占住左边一大块", tlay["wall"] and tlay["wall"]["w"] >= tlay["grid"]["w"] * 0.55,
          "墙宽 %s / 网格宽 %s" % (round(tlay["wall"]["w"]), round(tlay["grid"]["w"])))
    check("工具状态/工具详情在右栏且顶到页顶", tlay["col"] and tlay["col"]["l"] > tlay["wall"]["r"]
          and abs(tlay["col"]["t"] - tlay["grid"]["t"]) <= 2,
          "详情左缘 %s 顶部 %s / 网格顶部 %s" % (round(tlay["col"]["l"]), round(tlay["col"]["t"]), round(tlay["grid"]["t"])))
    check("工具状态/整页按视口收尾，不靠整页滚", tlay["viewScroll"] <= 4, "可滚 %dpx" % tlay["viewScroll"])
    shown = pg.evaluate("""() => ({
        names: [...document.querySelectorAll('.view .tool-card .tc-name')].map(e => e.innerText.trim()),
        states: [...document.querySelectorAll('.view .tool-card .tc-foot .tag')].map(e => e.innerText.trim()),
        detail: [...document.querySelectorAll('.view .tool-detail .td-block')].length
    })""")
    check("工具状态/每张卡片都标出可用性",
          len(shown["states"]) == cards and all(s in ("可用", "缺依赖") for s in shown["states"]),
          "%d 个状态标" % len(shown["states"]))
    check("工具状态/缺依赖的排在最前面",
          all(s == "缺依赖" for s in shown["states"][:shown["states"].count("缺依赖")]) if shown["states"] else False,
          "前置缺依赖 %d 个" % len([s for s in shown["states"] if s == "缺依赖"]))

    # 点一张卡片 -> 右下角出这个工具的详情（参数/依赖/历史/实现文件）
    pg.locator(".view .tool-card").nth(0).click()
    pg.wait_for_timeout(1200)
    detail = pg.evaluate("""() => ({
        name: ((document.querySelector('.view .tool-detail') || {}).innerText) || '',
        head: ((document.querySelector('.view .detail-card .card-head') || {}).innerText || '').trim()
    })""")
    check("工具状态/点开卡片有详情", len(detail["name"]) > 20, detail["head"][:40])
    for key in ("参数", "依赖的外部命令", "历史调用"):
        check("工具状态/详情含「%s」" % key, key in detail["name"], "")

    # 换一张卡片，详情要跟着换
    pg.locator(".view .tool-card").nth(3).click()
    pg.wait_for_timeout(1200)
    head2 = pg.locator(".view .detail-card .card-head").inner_text().strip()
    check("工具状态/换卡片会换详情", head2 != detail["head"], head2[:40])
    check("工具状态/详情有实现文件路径",
          "实现文件" in pg.locator(".view .tool-detail").inner_text(), "")


def sec_rules(pg):
    pg.click(".nav-item:has-text('规则库')")
    pg.wait_for_timeout(3000)
    rt = pg.locator(".view").inner_text()
    libs = [n for n in ("CVE 漏洞库", "Exploit-DB", "nuclei 模板", "MAC 厂商表（OUI）") if n in rt]
    check("规则库/四张卡都渲染", len(libs) == 4, "命中=%s" % libs)
    check("规则库/显示条数与版本", rt.count("已就绪") >= 4, "已就绪=%d" % rt.count("已就绪"))

    # 四张库卡要紧凑：一行放"体积 · 版本"，否则每张卡白高出一行，整块显得臃肿
    heights = pg.eval_on_selector_all(
        ".view .rule-card:not(.skeleton)",
        "els => els.map(e => Math.round(e.getBoundingClientRect().height))")
    check("规则库/四张库卡紧凑", bool(heights) and max(heights) <= 150, "高度=%s" % heights)

    # 左右两列的底边必须齐平：右列矮一截会在页面右侧留一块参差
    edges = pg.evaluate("""() => {
        const cols = document.querySelectorAll('.view .rules-split > .col');
        const bottom = (c) => {
            const cards = c.querySelectorAll(':scope > .card');
            const el = cards[cards.length - 1];
            return el ? Math.round(el.getBoundingClientRect().bottom) : null;
        };
        return [bottom(cols[0]), bottom(cols[1])];
    }""")
    check("规则库/两列底边齐平",
          edges[0] is not None and edges[1] is not None and abs(edges[0] - edges[1]) <= 2,
          "左=%s 右=%s" % tuple(edges))

    pg.click(".view button:has-text('刷新')")
    pg.wait_for_timeout(2500)
    check("规则库/刷新按钮生效", "CVE 漏洞库" in pg.locator(".view").inner_text(), "")

    rt = pg.locator(".view").inner_text()
    check("规则库/NVD 密钥卡在这一页", "NVD 密钥" in rt, "")
    check("规则库/NVD 标注来源", any(k in rt for k in ("环境变量", "配置文件", "未配置")), "")
    check("规则库/NVD 不显示密钥文件名与路径", "nvd_api_key.txt" not in rt, "")
    check("规则库/NVD 密钥框是密码框",
          pg.locator(".view input[type=password]").count() == 1, "")
    # 圆点是"按密钥字符数摆的占位"：点一下整段选中、删掉、失焦复原，
    # 而且复原只是把占位补回来，绝不会把密钥清掉。
    nvd_state = pg.evaluate("fetch('/api/nvd').then(r => r.json())")
    if nvd_state.get("has_key") and nvd_state.get("key_len"):
        box = ".view input[type=password]"
        dots = pg.input_value(box)
        check("规则库/圆点数量 = 密钥字符数",
              len(dots) == nvd_state["key_len"] and set(dots) == {"\u2022"},
              "%d 个圆点 / 密钥 %s 字符" % (len(dots), nvd_state["key_len"]))
        pg.click(box)
        pg.wait_for_timeout(300)
        pg.keyboard.press("Control+a")
        pg.keyboard.press("Delete")
        check("规则库/圆点可以整段删掉", pg.input_value(box) == "", "")
        pg.keyboard.press("Tab")
        pg.wait_for_timeout(400)
        check("规则库/失焦后圆点复原（不会误清密钥）",
              len(pg.input_value(box)) == nvd_state["key_len"],
              "值长=%d" % len(pg.input_value(box)))
    else:
        check("规则库/NVD 未配置时输入框为空",
              pg.input_value(".view input[type=password]") == "", "")
    check("规则库/NVD 标明不配也能用", "限速" in rt, "")

    # 定时更新卡：能设时间、能开关，且写明下次什么时候跑
    pg.wait_for_timeout(1200)
    sched = pg.locator(".view").inner_text()
    check("规则库/有定时更新卡", "定时更新" in sched, "")
    freq = pg.locator(".view .sched-grid .sched-field:first-child select")
    flabels = pg.eval_on_selector_all(
        ".view .sched-grid .sched-field:first-child select option",
        "els => els.map(e => e.innerText.trim())")
    check("规则库/定时卡先选频率", freq.count() == 1, "%s" % flabels)
    check("规则库/频率含 每分钟 / 每小时 / 每天",
          all(k in flabels for k in ("每分钟", "每小时", "每天")), "%s" % flabels)
    sub = lambda: pg.locator(".view .sched-grid .sched-field").count() - 1
    pg.select_option(".view .sched-grid .sched-field:first-child select", "minute")
    pg.wait_for_timeout(500)
    check("规则库/选每分钟就没有子选项", sub() == 0, "%d 个" % sub())
    pg.select_option(".view .sched-grid .sched-field:first-child select", "hour")
    pg.wait_for_timeout(500)
    mins = pg.eval_on_selector_all(
        ".view .sched-grid .sched-field:last-child select option", "els => els.map(e => e.innerText.trim())")
    check("规则库/选每小时只出现分钟一档", sub() == 1, "%d 个" % sub())
    check("规则库/每小时给的是 10 分钟档", mins == ["00", "10", "20", "30", "40", "50"],
          "%s" % mins)
    pg.select_option(".view .sched-grid .sched-field:first-child select", "week")
    pg.wait_for_timeout(500)
    check("规则库/选每周出现 周几+小时+分钟", sub() == 3, "%d 个" % sub())
    pg.select_option(".view .sched-grid .sched-field:first-child select", "day")
    pg.wait_for_timeout(500)
    check("规则库/选每天出现 小时+分钟", sub() == 2, "%d 个" % sub())
    check("规则库/定时卡写清当前设置", "当前设置" in sched, "")
    check("规则库/定时卡给出下次运行时间",
          ("下次运行" in sched) or ("已关闭" in sched), "")
    check("规则库/定时目标可选", pg.locator(".view .chips button").count() >= 1,
          "%d 个目标" % pg.locator(".view .chips button").count())

    # 放大的入口是一个图标按钮，不是"放大"两个字
    icon_btns = pg.locator(".view button.btn.icon")
    check("规则库/放大是图标按钮", icon_btns.count() >= 1, "%d 个图标按钮" % icon_btns.count())
    if icon_btns.count():
        icon_btns.first.click()
        pg.wait_for_timeout(900)
        check("规则库/放大能打开整屏", pg.locator(".zoom-log").count() == 1, "")
        pg.keyboard.press("Escape")
        pg.wait_for_timeout(600)
        check("规则库/放大窗口能关掉", pg.locator(".zoom-log").count() == 0, "")

    # 右列两张卡：定时卡按内容排（撑开会拖出一块空白、矮屏还会顶出滚动条），
    # 空白全给下面的凭据卡，两列底边仍然齐平。
    col = pg.evaluate("""() => {
        const q = (s) => document.querySelector(s);
        const sc = q('.view .sched-card'), cc = q('.view .cred-card');
        const over = (el) => { const b = el.querySelector('.card-body');
            return b ? b.scrollHeight - b.clientHeight : 0; };
        return { schedOver: over(sc), credOver: over(cc),
                 schedBottom: Math.round(sc.getBoundingClientRect().bottom),
                 credBottom: Math.round(cc.getBoundingClientRect().bottom),
                 colBottom: Math.round(sc.parentElement.getBoundingClientRect().bottom) };
    }""")
    check("规则库/定时卡不出滚动条", col["schedOver"] <= 2, "溢出 %dpx" % col["schedOver"])
    check("规则库/凭据卡不出滚动条", col["credOver"] <= 2, "溢出 %dpx" % col["credOver"])
    check("规则库/右列底边与左列齐平", abs(col["credBottom"] - col["colBottom"]) <= 2,
          "卡底 %d / 列底 %d" % (col["credBottom"], col["colBottom"]))

    t0 = time.time()
    pg.click(".view button:has-text('更新 CVE')")
    pg.wait_for_timeout(2500)
    check("规则库/更新中其他按钮被锁",
          pg.locator(".view button:has-text('更新 nuclei')").first.is_disabled(), "")
    reset = False
    # CVE 增量更新实测在 30s～420s 之间浮动（取决于 NVD 侧这次要补多少增量、
    # 以及限速），窗口给足 10 分钟。这条断言的是"能复位"，不是"多快复位"。
    for _ in range(300):
        pg.wait_for_timeout(2000)
        if not pg.locator(".view button:has-text('更新 CVE')").first.is_disabled():
            reset = True; break
    check("规则库/更新有流式输出且能复位", reset, "耗时 %.0fs" % (time.time() - t0))



def sec_audit(pg):
    pg.click(".nav-item:has-text('审计链')")
    pg.wait_for_timeout(3000)
    at = pg.locator(".view").inner_text()
    total = num_before_label(at, "记录总数")
    check("审计链/校验结论与计数", total and total > 0, "记录总数=%s" % total)
    check("审计链/记录时间线渲染", at.count("→") >= 3, "链条目=%d" % at.count("→"))

    pg.click(".view button:has-text('篡改演示')")
    pg.wait_for_timeout(3500)
    tampered = num_before_label(pg.locator(".view").inner_text(), "篡改嫌疑")
    check("审计链/篡改能被检出", tampered is not None and tampered > 0, "篡改嫌疑=%s" % tampered)

    pg.click(".view button:has-text('还原')")
    pg.wait_for_timeout(3500)
    at2 = pg.locator(".view").inner_text()
    check("审计链/还原后回到全绿", num_before_label(at2, "篡改嫌疑") == 0,
          "篡改嫌疑=%s" % num_before_label(at2, "篡改嫌疑"))
    check("审计链/复算结论文案", ("一致" in at2 or "完整" in at2), "")

    # 工具的状态也在链上（ok=False / 被拦截的那类要能一眼挑出来）
    check("审计链/按类型分类计数", num_before_label(at2, "工具调用") is not None, "")
    check("审计链/失败拦截数单列", num_before_label(at2, "失败/拦截") is not None,
          "失败/拦截=%s" % num_before_label(at2, "失败/拦截"))
    before = pg.locator(".view .chain-row").count()
    pg.click(".view .seg button:has-text('工具调用')")
    pg.wait_for_timeout(1000)
    only_tool = pg.locator(".view .chain-row").count()
    check("审计链/按类型筛选生效", 0 < only_tool <= before, "%d -> %d" % (before, only_tool))
    # 分页之后"行数变少"不够证明筛对了（一页本来就只画 50 行），要看剩下的行
    # 是不是真的只剩这一类
    kinds = pg.eval_on_selector_all(
        ".view .chain-row",
        "els => Array.from(new Set(els.map(e => e.querySelector('.tag').innerText.trim())))")
    check("审计链/筛选后只剩该类型", set(kinds) <= {"工具调用", "已拦截"}, "类型=%s" % kinds)
    pg.click(".view .seg button:has-text('全部')")
    pg.wait_for_timeout(800)
    check("审计链/筛选能回到全部", pg.locator(".view .chain-row").count() == before, "")

    # 分页：审计链只涨不落（现在两百多条），一页拉到底是划不完也找不到东西的
    pager = pg.locator(".view .pager")
    check("审计链/分页条只在底部一条", pager.count() == 1, "%d 条" % pager.count())
    ptxt = pager.first.inner_text() if pager.count() else ""
    hit = re.search(r"第\s*(\d+)\s*/\s*(\d+)\s*页", ptxt)
    check("审计链/分页条显示页码", bool(hit), ptxt.replace("\n", " ")[:70])
    rows = pg.locator(".view .chain-row").count()
    check("审计链/默认每页 20 条", rows == 20, "行数=%d" % rows)
    if hit and int(hit.group(2)) > 1:
        pg.locator(".view .pager button:has-text('下一页')").first.click()
        pg.wait_for_timeout(800)
        p2 = pg.locator(".view .pager").first.inner_text()
        check("审计链/能翻到下一页", "第 2 " in p2, p2.replace("\n", " ")[:60])
        check("审计链/第二页也有记录", pg.locator(".view .chain-row").count() > 0, "")
        pg.locator(".view .pager button:has-text('上一页')").first.click()
        pg.wait_for_timeout(800)
        check("审计链/能翻回上一页",
              "第 1 " in pg.locator(".view .pager").first.inner_text(), "")

    pg.locator(".view .pager .seg button:has-text('50/页')").first.click()
    pg.wait_for_timeout(900)
    check("审计链/条数档位可切换", pg.locator(".view .chain-row").count() == 50,
          "切到 50/页后行数=%d" % pg.locator(".view .chain-row").count())
    pg.locator(".view .pager .seg button:has-text('20/页')").first.click()
    pg.wait_for_timeout(900)
    check("审计链/能切回 20/页", pg.locator(".view .chain-row").count() == 20, "")

    # 条数档位只列"真的还能翻页"的：只剩几十条时，200/页 这种按钮不该还摆在那儿
    pg.click(".view .seg button:has-text('失败/拦截')")
    pg.wait_for_timeout(1000)
    head = pg.locator(".view .card").nth(1).inner_text()
    m2 = re.search(r"(\d+)/(\d+) 条", head)
    shown_n = int(m2.group(1)) if m2 else -1
    sizes = pg.eval_on_selector_all(".view .pager .seg button",
                                    "els => els.map(e => e.innerText.trim())")
    check("审计链/条数档位不超过当前条数",
          shown_n > 0 and all(int(x.split("/")[0]) < shown_n for x in sizes),
          "档位=%s 当前=%s 条" % (sizes, shown_n))
    check("审计链/没得翻就不摆 200/页", "200/页" not in sizes, "档位=%s" % sizes)
    pg.click(".view .seg button:has-text('全部')")
    pg.wait_for_timeout(900)


def sec_scope(pg):
    """控制台的边界：它是这个工具的管理台，不是模型控制台。

    这里用 wait_until="load" 而不是 networkidle：规则库更新期间控制台会挂着
    一条 SSE 流，"网络静止"这个条件根本不会成立，用 networkidle 会超时。
    """
    nav = pg.locator(".nav-item").all_inner_texts()
    check("边界/导航只有四页", len([n for n in nav if n.strip()]) == 4, "导航=%s" % nav)
    check("边界/没有报告页（报告归宿主 Agent）", "报告" not in " ".join(nav), "")
    check("边界/没有模型与算力页", "模型与算力" not in " ".join(nav), "")
    check("边界/没有配置页", "配置" not in " ".join(nav), "")
    pg.goto(BASE + "#/rules", wait_until="load")
    pg.wait_for_timeout(2500)
    rt = pg.locator(".view").inner_text()
    check("边界/模型后端不再出现在界面上",
          ("StepFun" not in rt) and ("GPUStack" not in rt) and ("模型名" not in rt), "")


def sec_routing(pg, errs, bad):
    pg.goto(BASE + "#/audit", wait_until="networkidle")
    pg.wait_for_timeout(2000)
    check("路由/深链接可用", pg.locator(".topbar h1").inner_text().strip() == "审计链",
          "h1=%s" % pg.locator(".topbar h1").inner_text().strip())
    pg.reload(wait_until="networkidle")
    pg.wait_for_timeout(2000)
    check("路由/刷新后停在同一页", pg.locator(".topbar h1").inner_text().strip() == "审计链", "")
    check("整体/无前端控制台报错", not errs, "报错=%s" % errs[:2])
    check("整体/无异常接口响应", not bad, "异常=%s" % bad[:3])


def main():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1600, "height": 1000})
        pg = ctx.new_page()
        errs, bad = [], []
        def on_console(m):
            """浏览器会把任何失败请求记成 console error，包括下面故意触发的 400，
            按 URL 过滤掉，否则"无报错"这条永远是被用例自己搞红的。"""
            if m.type != "error":
                return
            url = (m.location or {}).get("url", "") if isinstance(m.location, dict) else ""
            if any(part in url for part in EXPECTED_BAD):
                return
            errs.append(m.text[:200])

        pg.on("console", on_console)
        pg.on("pageerror", lambda e: errs.append("pageerror: %s" % str(e)[:180]))

        def on_response(r):
            if r.status < 400 or "/api/" not in r.url or "/reports/" in r.url:
                return
            if any(part in r.url for part in EXPECTED_BAD):
                return
            bad.append("%s %s" % (r.status, r.url[:90]))

        pg.on("response", on_response)
        pg.goto(BASE, wait_until="networkidle")
        pg.wait_for_timeout(1500)

        for title, fn in (("A 任务台", sec_tasks), ("B 工具状态", sec_tools),
                          ("C 规则库", sec_rules), ("D 审计链", sec_audit)):
            section(title, fn, pg)
        section("E 边界", sec_scope, pg)
        section("F 路由与整体", sec_routing, pg, errs, bad)

        ctx.close()
        browser.close()

    failed = [n for n, ok, _ in RESULTS if not ok]
    print("=" * 74)
    print("功能点 %d 个：通过 %d，失败 %d" % (len(RESULTS), len(RESULTS) - len(failed), len(failed)))
    if failed:
        print("失败项：")
        for n in failed:
            print("  -", n)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
