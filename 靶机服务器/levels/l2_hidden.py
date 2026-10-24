# -*- coding: utf-8 -*-
r"""
L2 · 藏与找　　难度 ★★☆☆☆
==================================================================

【设计意图】
比 L1 高一级的地方在于：**首页上什么都看不见。**

L1 是"把问题摆出来"，L2 是"把问题藏起来，但藏得不深"：
需要翻二级页面、看外部 JS、读 robots.txt、猜到备份文件叫什么名字。

它对检测系统的要求从"会 grep"升级成"会爬、会跟线索"。

【本关种入的问题】
  分类        问题                                     位置
  ──────────  ─────────────────────────────────────  ────────────────────────────
  敏感信息    身份号码被拆成两半（需跨页拼接）           /l2/news.html + /l2/notice.html
  敏感信息    手机号散落在公告正文                       /l2/notice.html
  敏感信息    数据库口令 / FTP 口令 / API 密钥           /l2/.env
  敏感信息    人员表（含完整身份证）                     /l2/news.html 正文
  敏感信息    提交人姓名与单位邮箱                       /l2/.git/logs/HEAD
  漏洞        .git 元数据目录残留                        /l2/.git/config、.git/HEAD
  漏洞        备份整站压缩包可直接下载                   /l2/backup/website-backup-20231108.tar.gz
  漏洞        后台管理入口暴露且无访问控制               /l2/admin-backend/
  漏洞        反射型 XSS（搜索参数未转义）               /l2/search.html?q=<script>...
  漏洞        组件版本过旧（Bootstrap 3.3.7）             /l2/js/vendor/bootstrap.min.js
  弱配置      X-Frame-Options 值无效（ALLOWALL）         /l2/ 全部响应
  弱配置      X-Content-Type-Options 值无效（0）         /l2/ 全部响应
  弱配置      X-Powered-By 泄漏技术栈与版本              /l2/ 全部响应
  弱配置      Referrer-Policy 不安全（unsafe-url）       /l2/ 全部响应
  挂马        混淆的外部 JS（首页只引用，看不到代码）      /l2/js/stat.js
  篡改        首页标题被改 + 页脚被插入推广文字            /l2/ 首页

【检测难度】
 · 敏感信息跨页拼装 → 单页扫描器抓不全
 · 挂马在外部 JS   → 只抓 HTML 的扫描器抓不到
 · 篡改无"危险特征" → 只能靠基线比对才发现
 · /backup/ 关闭了目录列表 → 必须从 robots.txt 得到文件名
==================================================================
"""

from rangekit import FAKE, PEOPLE, box, esc, page, table


def _reply(body, ctype="text/html; charset=utf-8", status=200, headers=None, note=""):
    from serve import Reply
    return Reply(status, body, content_type=ctype, headers=headers or {}, note=note)


# ------------------------------------------------------------------
# 首页：干净！
# 唯一异常是标题多了"【官方】"、页脚多了一段来路不明的推广文字。
# 这两处正是"篡改"考点 —— 没有新增危险特征，只能靠基线比对。
# ------------------------------------------------------------------

def page_index(ctx, m):
    body = """
<h2>欢迎访问</h2>
<p>本站提供政务公开、通知公告、办事服务等信息。</p>

<h2>最新动态</h2>
<ul>
  <li><a href="news.html">关于报送值班人员信息的通知</a>　2024-03-11</li>
  <li><a href="notice.html">关于开展网络安全自查的通知</a>　　2024-03-08</li>
  <li><a href="contact.html">内设机构联系方式更新</a>　　　　　2024-03-05</li>
</ul>

<h2>站内搜索</h2>
<form action="search.html" method="get">
  <input name="q" placeholder="输入关键词">
  <button type="submit">搜索</button>
</form>

<h2>互动服务</h2>
<ul>
  <li><a href="upload.php">资料上传</a>（提交办理材料）</li>
  <li><a href="feedback.php">意见反馈</a>（留言板）</li>
</ul>
"""
    # ① 标题被篡改：多了【官方】字样（钓鱼常用手法）
    html = page("某某市政务服务网【官方】", body, footer=False)
    # ② 页脚被追加推广文字
    planted = (
        '<footer><div class="wrap">'
        '<p>温馨提示：本站已开通微信自助办理，添加客服微信 zwfw-2024 可加急处理。</p>'
        '<p>某某市政务服务与大数据管理局 · 信息中心　|　值班电话：0571-8xxx-xxxx</p>'
        '<p class="tiny">本站为安全巡检训练靶场，页面内容与数据均为编造的测试数据。</p>'
        '</div></footer>'
    )
    return _reply(html.replace("</body>", planted + "\n</body>"))


def page_news(ctx, m):
    """新闻列表 —— 正文里含"前 12 位"身份号码 + 完整人员表。"""
    rows = [(iid, name, dept) for iid, name, _p, dept, _s in PEOPLE[:4]]
    body = f"""
<h2>关于报送值班人员信息的通知</h2>
<p class="meta">2024-03-11　来源：信息中心</p>
<p>各部门：请按附表格式报送值班人员信息。值班人员身份号码已统一登记，
系统内以脱敏形式存储，示例：</p>
<ul>
  <li>张伟明　33010619900307<strong>****</strong>　（完整号码请见后续补充通知）</li>
  <li>李　娜　33010619871123<strong>****</strong></li>
</ul>
<p>另附人员基础信息表（内部核对用）：</p>
{table(["身份证号", "姓名", "科室"], rows)}
<p>完整号码的后四位将在补充通知中统一说明。</p>
"""
    return _reply(page("关于报送值班人员信息的通知", body))


def page_notice(ctx, m):
    """公告 —— 含"后四位" + 手机号，与 news.html 拼起来才完整。"""
    body = f"""
<h2>关于开展网络安全自查的通知</h2>
<p class="meta">2024-03-08　来源：信息中心</p>
<p>各部门：请于本月 20 日前完成自查。</p>

<h3>补充说明（身份号码后四位）</h3>
<p>根据上一条通知，值班人员身份号码后四位如下，请核对：</p>
<ul>
  <li>张伟明　后四位 <strong>4512</strong></li>
  <li>李　娜　后四位 <strong>1267</strong></li>
</ul>

<h3>工作联系人</h3>
<p>张伟明　手机：{FAKE["phone_1"]}　内线：8721</p>
<p>李　娜　手机：{FAKE["phone_2"]}　内线：8733</p>
<p>陈晓东　手机：{FAKE["phone_4"]}（运维保障组，负责机房）</p>

<p>数据库变更请提前报备，变更窗口：每周二 22:00-24:00。</p>
"""
    return _reply(page("关于开展网络安全自查的通知", body))


def page_contact(ctx, m):
    rows = [
        ("信息中心", "张伟明", FAKE["mail_1"], FAKE["staff_1"]),
        ("政务公开科", "李娜", FAKE["mail_2"], FAKE["staff_2"]),
    ]
    body = f"""
<h2>内设机构联系方式</h2>
{table(["科室", "负责人", "单位邮箱", "工号"], rows)}
<p>后台维护请联系系统管理员（账号信息见内部文档）。</p>
"""
    return _reply(page("内设机构联系方式", body))


def page_search(ctx, m):
    """
    反射型 XSS：q 参数**故意不做转义**直接拼进页面。

    真实世界里这类问题非常常见 —— 搜索框、错误提示、跳转提示
    都是"把用户输入原样吐回来"的地方。
    """
    q = ctx.q("q")
    body = f"""
<h2>搜索结果</h2>
<p>您搜索的关键词：<strong>{q}</strong></p>
<p>未找到相关结果，请尝试其它关键词。</p>
<p><a href="index.html">返回首页</a></p>
"""
    return _reply(page("搜索结果", body))


def page_admin_backend(ctx, m):
    """暴露的后台：没有登录、没有访问控制，直接给功能菜单。"""
    body = """
<h2>站点管理系统</h2>
<div class="box warn">
  <h3>当前未启用登录校验</h3>
  <p>本页面用于内部维护，可直接操作以下功能。</p>
</div>
<ul>
  <li><a href="#">发布内容</a></li>
  <li><a href="#">用户管理</a>（含全部人员身份号码）</li>
  <li><a href="#">数据库备份</a>　→ 备份目录 /l2/backup/</li>
  <li><a href="#">系统日志</a></li>
</ul>
<p>上次数据导出：2023-11-08</p>
"""
    return _reply(page("站点管理系统", body, nav_html=""))


def robots(ctx, m):
    """
    robots.txt 是"爬虫的君子协定"，但它同时也是**攻击者的藏宝图**。
    这里故意把备份目录和后台目录写了进去。
    """
    text = """User-agent: *
Disallow: /l2/admin-backend/
Disallow: /l2/backup/
Disallow: /l2/.git/

# 站点地图位置
Sitemap: /l2/sitemap.xml
"""
    return _reply(text, "text/plain; charset=utf-8")


def sitemap(ctx, m):
    host = ctx.header("host")
    paths = ["", "index.html", "news.html", "notice.html", "contact.html",
             "search.html", "admin-backend/"]
    urls = "\n".join(f'  <url><loc>http://{host}/l2/{p}</loc></url>' for p in paths)
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
    ("*", r"^/contact\.html$", page_contact),
    ("*", r"^/search\.html$", page_search),
    ("*", r"^/admin-backend/?$", page_admin_backend),
    ("*", r"^/robots\.txt$", robots),
    ("*", r"^/sitemap\.xml$", sitemap),
)

LEVEL = {
    "id": 2,
    "key": "l2",
    "name": "藏与找",
    "difficulty": "★★☆☆☆",
    "summary": "首页干干净净，线索在二级页面、外部 JS、robots.txt 和 .git 里。",
    "hints": "robots.txt 会告诉你它想藏什么；首页的 JS 文件值得下下来看看。",
    "tags": ["敏感信息", "挂马", "篡改", "弱配置", "漏洞"],
    "banner": "nginx/1.14.0",
    # 弱配置：头"设了"，但值是错的/不安全的 —— 比完全不设更隐蔽
    "headers": {
        "X-Frame-Options": "ALLOWALL",
        "X-Content-Type-Options": "0",
        "X-Powered-By": "PHP/5.6.40",
        "Referrer-Policy": "unsafe-url",
    },
    "autoindex": False,     # 目录列表关了 → 必须从 robots.txt 猜文件名
    # 放行 POST：upload.php / feedback.php 需要提交表单
    "methods": ("GET", "HEAD", "OPTIONS", "POST"),
    "assets": "l2",
    "routes": ROUTES,
}
