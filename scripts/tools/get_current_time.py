#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""获取当前精确时间 - 返回当前日期和北京时间，包含年/月/日/时/分/周几

没有参数。按固定 UTC+8 算，和宿主机时区无关。报告里要落时间戳就用它，
别拿本机 date 命令的输出。
"""


from registry import tool
from helpers import *  # noqa: F401,F403


@tool(
    "get_current_time",
    "获取当前精确时间 - 返回当前日期和北京时间，包含年/月/日/时/分/周几",
    {
        "properties": {},
        "required": [],
    },
)
def get_current_time_handler(params):
            from datetime import datetime,timedelta,timezone
            import locale
            try: locale.setlocale(locale.LC_TIME,'zh_CN.UTF-8')
            except: pass
            tz=timezone(timedelta(hours=8))
            now=datetime.now(tz)
            weekdays=["星期一","星期二","星期三","星期四","星期五","星期六","星期日"]
            wd=weekdays[now.weekday()]
            out=f"📅 当前时间: {now.year}年{now.month:02d}月{now.day:02d}日 {now.hour:02d}:{now.minute:02d}\n"
            out+="🌏 时区: 北京时间 (UTC+8)\n"
            out+=f"📆 星期: {wd}\n"
            out+=f"🕐 完整格式: {now.strftime('%Y-%m-%d %H:%M:%S')} (Asia/Shanghai)"
            return {"success":True,"returncode":0,"output":out}
