#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
靶场公共工具箱
==================================================================

被 `serve.py`（HTTP 核心）和 `levels/*`（各关卡）共同引用的小工具集合。

抽出来的原因很实际：核心要用 `page()` 渲染 404，关卡要用 `page()` 渲染正文，
如果谁定义谁就被对方 import，会形成循环导入。放中立模块里两边都干净。

收录四类东西：
    ① 转义与文本       esc / sniff    —— 注意：靶场里有些地方**故意不转义**
    ② 页面骨架         page / nav / box / table —— 让各关卡看起来像同一个网站
    ③ 目录列表         directory_listing  —— 模拟服务器开了 autoindex
    ④ 假数据           FAKE_*         —— 固定值，便于"设计文档 ↔ 实际内容"对齐
==================================================================
"""

import urllib.parse

# ------------------------------------------------------------------
# ① 转义与文本
# ------------------------------------------------------------------

def esc(text):
    """HTML 转义。

    ⚠ 靶场里有几处**故意不调用**这个函数（比如把参数原样拼进页面），
      那是「反射型 XSS / 内容注入」的考点，不是疏漏。
    """
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def sniff_text_encoding(data):
    """尽力把字节解成文本，用于判断文件里是否含敏感特征。"""
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return data.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return "", "binary"


# ------------------------------------------------------------------
# ② 页面骨架
# ------------------------------------------------------------------

SITE_NAME = "某某市政务服务网"


def page(title, body, extra_head="", footer=True, nav_html=None,
         site_name=None, footer_html=None):
    """
    渲染一个完整站点页面。所有关卡共用，保证风格统一。

    参数：
        site_name    覆盖站名。**这个参数很重要** ——
                     不同"单位"的站点必须显示不同的站名，
                     否则测试者会误以为它们属于同一家（影响授权判定的公平性）。
        footer_html  覆盖整个页脚（同理，各单位的联系方式不该混用）。
    """
    name = site_name or SITE_NAME
    if footer_html is not None:
        foot = footer_html
    elif footer:
        foot = (
            '<footer><div class="wrap">'
            '<p>某某市政务服务与大数据管理局 · 信息中心　|　值班电话：0571-8xxx-xxxx</p>'
            '<p class="tiny">本站为安全巡检训练靶场，页面内容与数据均为编造的测试数据。</p>'
            '</div></footer>'
        )
    else:
        foot = ""
    nav = nav_html if nav_html is not None else default_nav()
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<link rel="stylesheet" href="/style.css">
{extra_head}</head>
<body>
<header><div class="wrap"><h1><a href="/">{esc(name)}</a></h1>{nav}</div></header>
<main class="wrap">
{body}
</main>
{foot}
</body>
</html>
"""


def default_nav(prefix=""):
    items = [
        ("首页", prefix + "index.html"),
        ("政务公开", prefix + "news.html"),
        ("通知公告", prefix + "notice.html"),
        ("办事服务", prefix + "service.html"),
        ("联系我们", prefix + "contact.html"),
    ]
    links = " | ".join(f'<a href="{href}">{esc(text)}</a>' for text, href in items)
    return f'<nav>{links}</nav>'


def nav_for(prefix, items):
    """自定义导航。"""
    links = " | ".join(f'<a href="{href}">{esc(text)}</a>' for text, href in items)
    return f'<nav>{links}</nav>'


def box(title, body, kind="info"):
    """带标题的信息块，kind 决定左边框颜色（info/warn/danger/ok）。"""
    return (f'<div class="box {kind}">'
            f'<h3>{esc(title)}</h3>{body}</div>')


def table(headers, rows, cls=""):
    """渲染表格。rows 里的单元格默认为纯文本（会被转义）。"""
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = []
    for row in rows:
        cells = "".join(f"<td>{esc(c) if not hasattr(c, '__html__') else str(c)}</td>" for c in row)
        body.append(f"<tr>{cells}</tr>")
    return (f'<table class="{cls}"><thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table>')


def article(title, paragraphs, date=""):
    """一篇文章的排版。"""
    meta = f'<p class="meta">{esc(date)}</p>' if date else ""
    body = "".join(f"<p>{p}</p>" for p in paragraphs)
    return f'<article><h2>{esc(title)}</h2>{meta}{body}</article>'


# ------------------------------------------------------------------
# ③ 目录列表
# ------------------------------------------------------------------

def directory_listing(display_path, entries, banner="Apache", host="localhost", port=80):
    """
    生成"服务器开了目录浏览"的页面。

    entries: [(名称, 是否目录), ...]
    """
    rows = []
    for name, is_dir in entries:
        shown = name + ("/" if is_dir else "")
        href = urllib.parse.quote(name) + ("/" if is_dir else "")
        rows.append(f'<li><a href="{href}">{esc(shown)}</a></li>')
    listing = "\n".join(rows) or "<li><em>（空目录）</em></li>"
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>Index of {esc(display_path)}</title></head>
<body>
<h1>Index of {esc(display_path)}</h1>
<hr>
<ul>
{listing}
</ul>
<hr>
<address>{esc(banner)} Server at {esc(host)} Port {port}</address>
</body></html>
"""


# ------------------------------------------------------------------
# ④ 固定的假数据（设计文档与实际内容必须一致，所以写死）
# ------------------------------------------------------------------

FAKE = {
    # —— 身份证 / 手机 / 银行卡 ——
    "id_card_1": "330106199003074512",
    "id_card_2": "330106198711231267",
    "id_card_3": "330103199512086631",   # 这一张被拆成两半，分别放两个页面
    "id_card_3_a": "330103199512",
    "id_card_3_b": "086631",
    "id_card_4": "330104198205123049",
    "phone_1": "13857198264",
    "phone_2": "15968820031",
    "phone_3": "13777890126",
    "phone_4": "18605711688",
    "bank_1": "6222021202003456789",
    "bank_2": "6217003810045678123",
    "bank_3": "6228480402564890018",

    # —— 账号口令（训练用编造值）——
    "admin_user": "admin",
    "admin_pass": "Admin@888",
    "db_user": "zwfw_app",
    "db_pass": "Zwfw#2023!App",
    "db_pass_2": "P@ssw0rd_2024",
    "ftp_pass": "ftp!Upload#2024",
    "api_key": "AKIA7F2K9QWXZP4M8TVN",
    "api_secret": "kQ9xT2mZ7pL4wR8nV5bY3dH6sJ1gF0aC",

    # —— 主机与内网 ——
    "internal_ip": "10.12.34.51",
    "internal_ip_2": "10.12.34.77",
    "db_ip": "172.16.8.21",
    "oa_url": "http://oa.zwfw.internal/",

    # —— 邮箱 ——
    "mail_1": "zhangsan@zwfw.gov.cn",
    "mail_2": "liwei@zwfw.gov.cn",
    "mail_3": "admin@zwfw.gov.cn",

    # —— 工号 ——
    "staff_1": "GW100237",
    "staff_2": "GW100581",
}

# 编造的名单（用于 db.sql / csv 之类的"批量泄露"场景）
PEOPLE = [
    ("330106199003074512", "张伟明", "13857198264", "信息中心", "GW100237"),
    ("330106198711231267", "李  娜", "15968820031", "政务公开科", "GW100581"),
    ("330103199512086631", "王建国", "13777890126", "综合处", "GW100842"),
    ("330104198205123049", "陈晓东", "18605711688", "运维保障组", "GW100963"),
    ("330102199408162238", "刘丹青", "13588220099", "审批服务科", "GW101127"),
    ("330105197903251156", "赵洪涛", "13906513388", "数据资源科", "GW101204"),
    ("330103199109084427", "孙丽华", "15868122990", "信息中心", "GW101355"),
    ("330108199602113315", "周文斌", "13736008866", "网络安全岗", "GW101418"),
]
