#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQL注入(GET)

参数固定 -u / --level / --batch / --random-agent，等级默认 1。要 --risk、POST、
Cookie、os-shell 那些换 sqlmap_full，别往这里加。
"""


from registry import tool
from utils import run_cmd
from utils import ensure_url as _ensure_url
from helpers import *  # noqa: F401,F403


@tool(
    "sqlmap_basic",
    "SQL注入(GET)",
    {
        "properties": {
            "url": {
                "type": "string",
                "description": "URL",
                "default": None,
            },
            "level": {
                "type": "integer",
                "description": "等级(1)",
                "default": 1,
            },
        },
        "required": ["url"],
    },
)
def sqlmap_basic_handler(params):
    return run_cmd("sqlmap -u '%s' --level=%d --batch --random-agent 2>&1" % (_ensure_url(params.get("url","")),params.get("level",1)),300)
