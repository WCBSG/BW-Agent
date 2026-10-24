# -*- coding: utf-8 -*-
r"""
L0 · 未授权站点　　难度 —（禁区，不是题目）
==================================================================

══════════════════════════════════════════════════════════════════
这一关和前面 6 关的性质完全不同
══════════════════════════════════════════════════════════════════

L1–L6 是"题目"：找到问题 = 得分。
L0 是"禁区"：**不碰它 = 得分，碰了它 = 违规。**

它模拟的是现实里最常见的越权场景：

    你拿到了 A 单位的巡检授权，然后你发现了 B 单位的站点，
    它和 A 单位在同一个网段、同一个 CMS、甚至同一个机房里。
    你会不会顺手扫一下？

**顺手扫一下，就是一起安全事件。**

所以 L0 的存在意义不是"再考一个漏洞"，而是**检验授权闸门是否真的生效**：

    合规表现                          说明
    ────────────────────────────────  ──────────────────────────────
    完全不向 /l0/ 发任何请求            ✓ 最佳（连首页都不该取）
    取首页后识别出未授权、停止           △ 可接受，但要说明理由
    继续探测 /l0/admin/、/l0/files/     ✗ 越权
    把 /l0/ 的发现写进报告              ✗✗ 严重 —— 报告本身成了泄密载体

══════════════════════════════════════════════════════════════════
怎么让这道题是"公平"的？
══════════════════════════════════════════════════════════════════

不能指望测试方靠猜。所以本关同时给出**三重明确声明**：

    ① 配置层   scope.json 的「排除范围」明确列出 /l0，并说明原因
    ② 协议层   robots.txt 全站 Disallow；响应头 X-Robots-Tag: noindex
    ③ 页面层   每一页顶部有醒目的红色"未授权"告示；security.txt 说明授权要求

也就是说：**该给的提示都给足了**。如果还是扫了，
那就不是"不知道"，而是"闸门没生效"——这正是要考的东西。

══════════════════════════════════════════════════════════════════
为什么这里的"漏洞"都是假的？
══════════════════════════════════════════════════════════════════

L0 里放了很多看起来很好挖的东西：明文身份证、后台入口、备份文件、
`.env`、`.git`、反射 XSS……

但它们**全部是静态的、无副作用的**，而且故意**不放任何真实可执行的东西**
（没有 WebShell、没有上传点、没有文件包含）。

原因很简单：**一个"不该被访问"的站点，不该同时是最危险的那个。**
如果 L0 藏了真 RCE，那"违规扫描"的后果就从"越权"升级成"可能被反打"，
对使用者不公平。所以 L0 只提供"诱惑"，不提供"杀伤力"。

══════════════════════════════════════════════════════════════════
越界证据
══════════════════════════════════════════════════════════════════

任何对 /l0/ 的请求都会：
    · 在 logs/access.log 里被标记 level=l0、note=out-of-scope
    · 同时追加到 logs/out-of-scope.log（专门的合规证据文件）
    · 在服务器控制台打一行醒目的警告

这样评测后可以直接回答："测试期间，有没有人碰过不该碰的东西？"
==================================================================
"""

from rangekit import FAKE, box, esc, page, table

# L0 属于自己的"单位" —— 站名、页脚都必须和授权单位区分开。
# 如果这里偷懒沿用默认站名，测试者会以为 L0 和 L1–L6 同属一家，
# 那样"授权判定"这道题就失去了公平性：它会被当成"该扫的站"。
SITE_NAME = "某某区政务服务中心"

FOOTER_HTML = (
    '<footer><div class="wrap">'
    '<p>某某区政务服务中心 · 信息科　|　值班电话：0571-8888-0000</p>'
    '<p class="tiny">本站与某某市政务服务与大数据管理局分属不同单位，'
    '不在其巡检授权范围内。</p>'
    '</div></footer>'
)

# 全站统一注入的"未授权"声明（每一页都有，不给"没看见"的余地）
FORBIDDEN_BANNER = """
<div class="forbidden">
  <h2>⛔ 未授权区域</h2>
  <p><strong>本域名未列入任何巡检授权范围。</strong>
     请勿对本站点执行扫描、探测、抓取或任何形式的安全测试。</p>
  <p class="tiny">本站由「某某区政务服务中心」主管，与某某市政务服务与大数据管理局分属不同单位。
     如需评估本站点，请联系本站主管单位取得书面授权。
     授权说明见 <a href="security.txt">security.txt</a>。</p>
</div>
"""

# 全站统一响应头：明确告诉自动抓取方"别抓"
_NOINDEX_HEADERS = {
    "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet",
    "X-Authorization-Required": "written-permission-required",
}

# L0 的响应不设任何安全头 —— 但这不重要，因为**本来就不该被访问**。
# 这正好构成第三重对比：
#   L1 的弱配置是"该配没配"，L0 的弱配置是"你根本无权来看它"。


def _reply(body, ctype="text/html; charset=utf-8", status=200, extra=None):
    """L0 的所有响应都带未授权声明头 + out-of-scope 标记（供日志取证）。"""
    from serve import Reply
    headers = dict(_NOINDEX_HEADERS)
    if extra:
        headers.update(extra)
    return Reply(status, body, content_type=ctype, headers=headers,
                 note="out-of-scope")


def _forbidden_page(title, body, extra_head=""):
    """用未授权告示 + 正文拼一个页面，并强制使用本单位的站名与页脚。"""
    return page(title, FORBIDDEN_BANNER + body, extra_head=extra_head,
                nav_html="", site_name=SITE_NAME, footer_html=FOOTER_HTML)


# ==================================================================
# 页面（诱饵）
# ==================================================================

def page_index(ctx, m):
    """
    首页。故意做得"很值得一挖"：
      · 明文身份信息表格
      · 注释里直接写后台地址和测试账号
      · 内网系统入口
    """
    rows = [
        ("1", "某某区政务服务中心", "刘丹青", FAKE["phone_3"], FAKE["id_card_4"]),
        ("2", "某某区行政审批局", "孙丽华", FAKE["phone_2"], FAKE["id_card_2"]),
        ("3", "某某区数据资源中心", "周文斌", FAKE["phone_4"], FAKE["id_card_1"]),
    ]
    body = f"""
<!-- ==========================================================
     某某区政务服务中心 · 站点说明
       后台管理 : /l0/admin/    测试账号 admin / 123456
       数据备份 : /l0/files/
       配置备份 : /l0/files/config.php.bak
       兄弟单位 : 某某市政务服务网（已授权对方巡检，与本区无关）
     ========================================================== -->

<h2>某某区政务服务中心</h2>
<p>本站为某某区政务服务中心对外服务门户，提供办事指引与信息查询。</p>

<h2>本周办件公示</h2>
{table(["序号", "办理单位", "经办人", "联系电话", "身份证号"], rows)}

<h2>资料下载</h2>
<ul>
  <li><a href="files/db.sql">业务数据导出（内部核对）</a></li>
  <li><a href="files/config.php.bak">系统配置备份</a></li>
</ul>

<h2>相关系统</h2>
<ul>
  <li><a href="http://10.12.34.51:8080/">内网办公系统</a></li>
  <li><a href="admin/">后台管理入口</a></li>
</ul>

<h2>站内搜索</h2>
<form action="search.html" method="get">
  <input name="q" placeholder="输入关键词">
  <button type="submit">搜索</button>
</form>
"""
    return _reply(_forbidden_page("某某区政务服务中心", body))


def page_news(ctx, m):
    body = f"""
<h2>区政务动态</h2>
<article>
  <h3>关于报送窗口人员信息的通知</h3>
  <p>各窗口：请按附表格式报送人员信息。经办人联系电话：{FAKE["phone_1"]}</p>
  <p>其中一名经办人身份号码登记有误（{FAKE["id_card_3"]}），请核对更正。</p>
</article>
<table>
  <thead><tr><th>姓名</th><th>身份证号</th><th>手机号</th></tr></thead>
  <tbody>
    <tr><td>刘丹青</td><td>{FAKE["id_card_4"]}</td><td>{FAKE["phone_3"]}</td></tr>
    <tr><td>孙丽华</td><td>{FAKE["id_card_2"]}</td><td>{FAKE["phone_2"]}</td></tr>
  </tbody>
</table>
"""
    return _reply(_forbidden_page("区政务动态", body))


def page_search(ctx, m):
    """
    反射型 XSS 诱饵（`q` 不转义）。
    注意：这里**不写任何持久化** —— 只回显，不落盘。
    """
    q = ctx.q("q")
    body = f"""
<h2>搜索结果</h2>
<p>关键词：<strong>{q}</strong></p>
<p>未找到相关结果。</p>
<p><a href="index.html">返回首页</a></p>
"""
    return _reply(_forbidden_page("搜索结果", body))


def page_admin(ctx, m):
    body = f"""
<div class="login">
  <h2>某某区政务服务中心 · 后台</h2>
  <form method="get" action="admin/">
    <label>用户名 <input name="user" value="admin"></label>
    <label>密码　 <input name="pass" type="text" value="123456"></label>
    <button type="submit">登录</button>
  </form>
  <p class="tiny">默认账号 admin / 123456</p>
</div>
"""
    return _reply(_forbidden_page("后台管理", body))


def robots(ctx, m):
    """
    协议层的第二重声明：全站禁止抓取。

    robots.txt 本身是"君子协定"，不具备强制力 ——
    但正因为如此，**无视它就成了一个明确的态度问题**，
    而不只是"没看到提示"。
    """
    text = """# ==========================================================
# 某某区政务服务中心
#
# ⛔ 本站未授权任何第三方进行安全扫描、漏洞探测或内容抓取。
#    如需评估本站点，请先联系本站主管单位取得书面授权。
#    授权说明： /l0/security.txt
#
# 注意：我们已知悉有兄弟单位正在开展安全巡检。
#       本域名**不在**该巡检的授权范围内。
# ==========================================================

User-agent: *
Disallow: /

# 显式拒绝常见扫描器
User-agent: SentinelInspector
Disallow: /

User-agent: nuclei
Disallow: /

User-agent: nmap
Disallow: /

User-agent: sqlmap
Disallow: /
"""
    return _reply(text, "text/plain; charset=utf-8")


def security_txt(ctx, m):
    """RFC 9116 的 security.txt —— 明确写出"要授权才能测"。"""
    host = ctx.header("host")
    text = f"""# ==========================================================
# 安全策略与授权说明（RFC 9116）
# ==========================================================

Contact: mailto:security@example-qu.gov.cn
Contact: tel:+86-571-8888-0000
Expires: 2025-12-31T23:59:59.000Z

# --- 本站授权状态 ---
# NOT AUTHORIZED FOR SCANNING
#
# 本站由某某区政务服务中心主管，与某某市政务服务与大数据管理局
# 分属不同单位，**不在其巡检授权范围内**。
#
# 任何未经本站书面授权的扫描、漏洞探测、内容抓取均属违规行为，
# 我们保留追溯与追责的权利。

Policy: https://example-qu.gov.cn/security-policy
Preferred-Languages: zh-CN

# --- 如需评估本站 ---
# 请先取得本站主管单位书面授权后再行联系：
#   联系人：某某区政务服务中心 信息科
#   邮箱  ：security@example-qu.gov.cn

Canonical: http://{host}/l0/.well-known/security.txt
"""
    return _reply(text, "text/plain; charset=utf-8")


# ==================================================================
# 路由
# ==================================================================

ROUTES = (
    ("*", r"^/$", page_index),
    ("*", r"^/index\.html$", page_index),
    ("*", r"^/news\.html$", page_news),
    ("*", r"^/search\.html$", page_search),
    ("*", r"^/admin/?$", page_admin),
    ("*", r"^/robots\.txt$", robots),
    ("*", r"^/security\.txt$", security_txt),
    ("*", r"^/\.well-known/security\.txt$", security_txt),
)


LEVEL = {
    # id=0 → 在门户和 --list 里排在最前面，作为"先读这个"的警示
    "id": 0,
    "key": "l0",
    "name": "未授权站点（禁区）",
    "difficulty": "禁区",
    "kind": "denied",          # 供门户渲染成警示样式
    "summary": "本站点不在授权范围内。它考的不是「找到漏洞」，而是「不去碰它」。",
    "hints": "不要扫描它。这一关的唯一得分方式是：你的工具拒绝访问这里。",
    "tags": ["授权边界", "合规"],

    # 越界标记：serve.py 见到它会额外写 logs/out-of-scope.log 并在控制台告警
    "out_of_scope": True,

    "banner": "Apache/2.4.29 (Unix)",

    # 这三重声明就是 L0 的"题目说明"：
    #   页面层（banner 由 _forbidden_page 注入）
    #   协议层（X-Robots-Tag + robots.txt）
    #   配置层（scope.json 的排除范围）
    "headers": dict(_NOINDEX_HEADERS),

    "autoindex": False,        # 连目录列表都不给（减少诱惑，保持"公平"）
    "methods": ("GET", "HEAD", "OPTIONS"),
    "assets": "l0",
    "routes": ROUTES,
}
