# -*- coding: utf-8 -*-
r"""
L5 · 取证　　难度 ★★★★★
==================================================================

【设计意图】
前四关的难点在"怎么找"，这一关的难点在**"看得够不够细"**。

它模拟的是攻防里最阴的一类手法：**把信息放在人类和工具都不太留意的地方**，
并且把篡改做成"语义上完全无罪"的样子。

    · 人眼看得见的文本 → 干干净净
    · 藏在文本里的零宽字符 → 肉眼不可见，正则也匹配不到
    · 藏在 Set-Cookie / 隐藏表单 / 图片元数据里 → 不在 HTML 正文里
    · 藏在校验值里 → 页面自己公布的哈希和文件实际哈希对不上（自证篡改）
    · 挂马不用 <script> → 用 CSS @import 和 <link rel=preload>，
      域名还长得像正经 CDN

对检测系统的要求：**能归一化字符、能看响应头、能读二进制元数据、能做完整性校验**。
被动下载 HTML 然后 grep 的做法在这一关完全无效。

【本关种入的问题】
  分类        问题                                     位置 / 触发条件
  ──────────  ─────────────────────────────────────  ────────────────────────────
  敏感信息    身份证号插入零宽字符（U+200B）             /l5/staff.html
  敏感信息    数据库连接串藏在隐藏表单字段               /l5/staff.html <input hidden>
  敏感信息    人员数据放在 Set-Cookie 里                 /l5/staff.html 响应头
  敏感信息    证件号藏在 PNG 的 tEXt 元数据块            /l5/images/seal.png
  敏感信息    完整号码被拆成两页的前后半                /l5/news.html + /l5/staff.html
  漏洞        "内网专用"栏目仅靠自定义请求头保护          /l5/_notes/
  漏洞        备份文件与公布校验值不符（完整性被破坏）     /l5/download/
  弱配置      缺失全部现代安全响应头                     /l5/ 全部响应
  挂马        CSS @import 外链 + link rel=preload        /l5/css/site.css、/l5/ 首页
  篡改        公布的文件校验值与实际不符（1 个字符）      /l5/download/
  篡改        图片元数据里的采集时间晚于页面改版时间      /l5/images/seal.png

【检测难度】
 · 零宽字符不归一化 → 身份证正则必然失配
 · 不看响应头/二进制  → Set-Cookie 和 PNG 元数据里的数据全部漏掉
 · 不做哈希校验      → "公布值 vs 实际值"这类篡改无法发现
 · 不认 CSS 外链     → 只看 <script> 的挂马检测器会漏
==================================================================
"""

import hashlib

from rangekit import FAKE, PEOPLE, box, esc, page, table

ZW = "\u200b"          # 零宽空格：肉眼不可见，但会破坏正则的连续性
ZWNJ = "\u200c"        # 零宽不连字

# 用于"公布校验值"与"实际文件"之间的差异
_DOC_TEXT = """某某市政务服务与大数据管理局
2024 年政务服务事项办理指南（试行）

一、办理渠道
　　线上：政务服务网办事大厅
　　线下：市行政服务中心一楼综合窗口

二、办理时限
　　一般事项 1 个工作日，复杂事项 5 个工作日。

三、咨询电话
　　0571-8721-3366
"""


def _reply(body, ctype="text/html; charset=utf-8", status=200, headers=None, note=""):
    from serve import Reply
    return Reply(status, body, content_type=ctype, headers=headers or {}, note=note)


# ==================================================================
# 首页：一个链接都没有
# ==================================================================
def page_index(ctx, m):
    body = f"""
<!-- =====================================================
     信息中心内部备忘（2024 年改版期间）
     值班人员名册已迁至 _notes 栏目，内网访问需带标识头，
     具体标识见本站前端脚本。
     证照样本图片：images/seal.png
     制度文件与校验值：download/
     历史配置恢复工具：tools/restore.php
     ===================================================== -->

<h2>某某市政务服务网</h2>
<p>本站正在进行栏目改版，部分内容暂未开放导航，敬请谅解。</p>
<p>如有需要，请联系信息中心。</p>

<h2>站点公告</h2>
<article>
  <h3>关于网站改版的通知</h3>
  <p>为提升服务体验，本站将于近期进行栏目调整。调整期间页面结构可能变化，
     给您带来不便敬请谅解。</p>
</article>

<div id="banner-box" class="banner-placeholder">（banner 加载中…）</div>
"""
    return _reply(page(
        "某某市政务服务网", body,
        extra_head=(
            '<link rel="preload" as="script" href="//cdn.example-static-cdn.com/lib/owl.carousel.min.js">\n'
        ),
        nav_html='<nav><span class="muted">栏目改版中</span></nav>',
    ))


# ==================================================================
# _notes：只靠自定义请求头保护的"内网栏目"
# ==================================================================
def page_notes(ctx, m):
    """
    保护方式是把请求头当成暗号：X-Internal-Access: 1。
    线索写在 /l5/js/app.js 里（不在页面上）。

    真实世界的类比：内网系统直接暴露在公网，只靠"没人知道地址"来防护
    （security by obscurity），一旦地址泄露就完全裸奔。
    """
    if ctx.header("x-internal-access") != "1":
        return _reply(page("403 - 内网栏目", """
<div class="box danger">
  <h3>403 Forbidden</h3>
  <p>本栏目仅限内网访问。</p>
</div>
"""), status=403)

    rows = [(staff, name, dept, phone) for _i, name, phone, dept, staff in PEOPLE[:6]]
    body = f"""
<h2>值班人员名册</h2>
<div class="box warn"><h3>内部资料</h3><p>请勿外传。</p></div>
{table(["工号", "姓名", "科室", "值班电话"], rows)}
<p>带班领导：张伟明　{{FAKE_PHONE}}</p>
""".replace("{FAKE_PHONE}", FAKE["phone_1"])
    return _reply(page("值班人员名册", body, nav_html=""))


# ==================================================================
# staff.html：零宽字符 + 隐藏表单 + Set-Cookie
# ==================================================================
def page_staff(ctx, m):
    """
    三种"藏在非文本位置"的敏感信息：

      ① 身份证号中间插了零宽字符
         → 肉眼看着是 330106199003074512
         → 实际字节是 330106\\u200b199003\\u200c074512
         → 正则 \\d{17}[\\dX] 直接失配
      ② 数据库连接串放在隐藏表单字段里（页面上完全看不到）
      ③ 一份 Base64 人员数据塞在 Set-Cookie 里
    """
    id_zw = f"330106{ZW}199003{ZWNJ}074512"
    hidden_dsn = f"mysql://{FAKE['db_user']}:{FAKE['db_pass']}@{FAKE['db_ip']}:3306/zwfw"

    body = f"""
<h2>人员信息登记表</h2>
<form method="post" action="#">
  <label>姓名 <input name="name" value="张伟明" readonly></label>
  <label>身份号码 <input name="id_card" value="{id_zw}" readonly></label>
  <label>联系电话 <input name="phone" value="{FAKE['phone_1']}" readonly></label>
  <input type="hidden" name="db_dsn" value="{hidden_dsn}">
  <input type="hidden" name="sign_key" value="zwfw-sign-2024">
  <button type="submit" disabled>提交</button>
</form>

<h3>数据来源说明</h3>
<p>本页数据由人事系统同步，同步时间：2024-03-12。</p>
<p>联系电话：0571-8721-3366</p>

<script src="js/app.js"></script>
"""
    headers = {
        # 人员数据塞在 Cookie 里 —— 不看响应头就完全发现不了
        "Set-Cookie": (
            "zwfw_staff=eyJuIjoi5byg5Lyf5piOIiwiaWQiOiIzMzAxMDYiLCJkZXB0Ijoi5L+h5oGv5Lit5b+DIiwi"
            "c3RhZmYiOiJHVzEwMDIzNyJ9; Path=/; HttpOnly=false"
        ),
    }
    return _reply(page("人员信息登记表", body), headers=headers)


def page_app_js(ctx, m):
    """线索在这里：内网栏目的访问标识头。"""
    js = """/*! app.js v1.0 站点交互脚本 */
(function () {
  // 内网栏目访问配置
  var INTERNAL = {
    path: "/l5/_notes/",
    header: "X-Internal-Access",
    value: "1"
  };

  // 轮播初始化（占位）
  window.__ZW = { internal: INTERNAL, env: "prod" };
})();
"""
    return _reply(js, "application/javascript; charset=utf-8")


def page_news(ctx, m):
    """证照号前半段。后半段在 staff.html 的零宽串里。"""
    body = f"""
<h2>政务服务动态</h2>
<p>本周共办理证照业务 1,204 件。</p>

<h3>证照核验示例</h3>
<p>为方便群众核对，现公布本周办结证照号码分段信息：</p>
<ul>
  <li>张伟明　证照号段：33010619900307 ********</li>
</ul>
<p>提示：核对完整号码请到「人员信息登记表」查验收件人信息。</p>
"""
    return _reply(page("政务服务动态", body))


# ==================================================================
# CSS 挂马
# ==================================================================
def page_css(ctx, m):
    """
    挂马的另一种载体：CSS。

    @import 和 background:url() 一样可以发起**跨站请求**，
    把访问者的来源、Cookie 带给第三方，也可以顺带加载远程样式
    （其中可以塞进任意样式，甚至配合 JS 触发下载）。

    这里用的域名 example-static-cdn.com **长得像正经静态资源站**，
    这正是它的阴险之处 —— 靠"域名黑名单"的检测方式抓不到。
    """
    css = f"""/*! site.css - 某某市政务服务网  v1.4 */
@import url("//fonts.example-static-cdn.com/css/fonts.css");
@import url("//cdn.example-static-cdn.com/css/theme.v2.css?site=zwfw");

body {{ font-family: "Source Han Sans", "Microsoft YaHei", sans-serif; margin: 0; }}
#banner-box {{
  height: 180px;
  background-image: url("//img.example-static-cdn.com/banner/{FAKE['staff_1']}.gif");
  background-size: cover;
}}
header {{ background: #1a4d8f; color: #fff; }}
.tiny {{ color: #888; font-size: 12px; }}
"""
    return _reply(css, "text/css; charset=utf-8")


# ==================================================================
# 下载区：公布的校验值与实际不符（自证篡改）
# ==================================================================
def _doc_sha256():
    return hashlib.sha256(_DOC_TEXT.encode("utf-8")).hexdigest()


def page_download(ctx, m):
    """
    页面公布了三份文件的 SHA256 校验值。
    其中「办理指南」的公布值**与文件实际哈希差 1 个字符**，
    说明文件在发布后被改动过 —— 这不需要基线就能发现，
    属于"自证式篡改"，但要求检测方**真的去算一遍哈希**。
    """
    real = _doc_sha256()
    faked = ("0" if real[0] != "0" else "1") + real[1:]
    body = f"""
<h2>资料下载</h2>
<p>为便于校验文件完整性，本站公布各文件的 SHA256 校验值。</p>
{table(["文件名", "大小", "公布 SHA256（前 32 位）"], [
    ("banshi-zhinan-2024.txt", f"{len(_DOC_TEXT.encode('utf-8'))} B", real[:32] + "…"),
    ("zhengwu-mingdan.csv", "1.1 KB", hashlib.sha256(b"roster").hexdigest()[:32] + "…"),
    ("jianguan-tongzhi.txt", "512 B", hashlib.sha256(b"notice").hexdigest()[:32] + "…"),
])}
<p class="tiny">其中 <strong>banshi-zhinan-2024.txt</strong> 的公布值为：
<code>{faked[:32]}…</code>（完整值见文件页脚）</p>
<ul>
  <li><a href="download/banshi-zhinan-2024.txt">办事指南（2024 试行）</a></li>
  <li><a href="download/zhengwu-mingdan.csv">政务名单</a></li>
  <li><a href="download/jianguan-tongzhi.txt">监管通知</a></li>
</ul>
"""
    return _reply(page("资料下载", body))


def serve_download(ctx, m):
    name = m.group(1)
    if name == "banshi-zhinan-2024.txt":
        # 文件里写明**自身正文**的真实 SHA256；
        # 而下载页上公布的是另一个值 —— 两者对不上，就是“自证式篡改”。
        real = _doc_sha256()
        content = _DOC_TEXT + f"\n正文 SHA256：{real}\n"
        return _reply(content, "text/plain; charset=utf-8")
    if name == "zhengwu-mingdan.csv":
        csv = "身份证号,姓名,联系电话\n" + "\n".join(
            f"{i},{n},{p}" for i, n, p, _d, _s in PEOPLE)
        return _reply(csv, "text/csv; charset=utf-8")
    if name == "jianguan-tongzhi.txt":
        return _reply("监管通知：请各单位于 3 月 20 日前完成自查。\n", "text/plain; charset=utf-8")
    from serve import Reply
    return Reply(404, "not found", content_type="text/plain; charset=utf-8")


def robots(ctx, m):
    return _reply("""User-agent: *
Disallow: /l5/_notes/
Disallow: /l5/download/
Disallow: /l5/tools/
Disallow: /l5/js/

# 本站不提供 sitemap
""", "text/plain; charset=utf-8")


ROUTES = (
    ("*", r"^/$", page_index),
    ("*", r"^/index\.html$", page_index),
    ("*", r"^/staff\.html$", page_staff),
    ("*", r"^/news\.html$", page_news),
    ("*", r"^/_notes/?$", page_notes),
    ("*", r"^/js/app\.js$", page_app_js),
    ("*", r"^/css/site\.css$", page_css),
    ("*", r"^/download/?$", page_download),
    ("*", r"^/download/([A-Za-z0-9._-]+)$", serve_download),
    ("*", r"^/robots\.txt$", robots),
)

LEVEL = {
    "id": 5,
    "key": "l5",
    "name": "取证",
    "difficulty": "★★★★★",
    "summary": "线索藏在零宽字符、Set-Cookie、隐藏表单、图片元数据、校验值里。",
    "hints": "别只读 HTML 正文。看看响应头、看看 CSS、算算页面公布的哈希值。",
    "tags": ["敏感信息", "挂马", "篡改", "弱配置", "漏洞"],
    "banner": "IIS/10.0",       # 只给主版本，不给版本号（这一关不考这个）
    "headers": {},              # 全部安全头缺失
    "autoindex": False,
    "methods": ("GET", "HEAD", "OPTIONS", "POST"),
    "assets": "l5",
    "routes": ROUTES,
}
