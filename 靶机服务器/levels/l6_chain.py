# -*- coding: utf-8 -*-
r"""
L6 · 链路　　难度 ★★★★★★
==================================================================

【设计意图】
最后一关考的不是"看得细"，而是**"能不能把散落的线索串成一条链"**。

在这一关里，任何**单点**检查都不会有收获：

    · 首页干干净净，没有任何敏感信息、没有挂马、没有外链
    · 所有"看起来可疑"的路径都返回 200 + 一个正常页面（软 404 掩盖）
    · 真正的 .git/config 藏在软 404 的伪装后面 —— 只能靠**内容特征**分辨
    · 源码备份里的配置只给出接口地址和令牌的**前半段**
    · 接口用前半段令牌换出**后半段**

也就是说：必须走完

    读首页注释 → 猜出源码归档路径 → 下载并解开归档 → 读配置拿到接口地址+令牌前半
      → 用令牌前半调接口 → 拿到令牌后半 → 拼出完整密钥

任何一步跳过，都拿不到答案。这是对"任务规划与编排能力"的直接检验 ——
也正是赛题评价指标里"智能体能力 20%"想要考的东西。

【本关种入的问题】
  分类        问题                                     位置 / 触发条件
  ──────────  ─────────────────────────────────────  ────────────────────────────
  敏感信息    完整 API 令牌（需分两步拼接）             源码前半 + 接口后半
  敏感信息    云平台 AccessKey / Secret                 GET /l6/api/internal/keys
  敏感信息    数据库口令                                源码归档内 settings.py
  敏感信息    内网 IP 与运维入口                        源码归档内 settings.py
  漏洞        .git 元数据残留（被软 404 掩盖）           /l6/.git/config（需内容特征识别）
  漏洞        源码归档包可直接下载                       /l6/src/site-2024.tar.gz
  漏洞        内部接口无鉴权，仅靠请求头令牌              /l6/api/internal/keys
  弱配置      全部安全头缺失 + 服务端版本暴露            /l6/ 全部响应
  篡改        HTTPS 被降级为 HTTP，且站内前后不一致      /l6/ 首页 vs /l6/notice.html
  篡改        页面公布的改版日期晚于归档内源文件日期      首页 vs 归档内 settings.py

【检测难度】
 · 软 404 让状态码完全失效 → 必须做内容特征 + 相似度双重校验
 · 单点扫描零收获 → 必须做多步规划与结果关联
 · 需要解压归档、解析源码 → 必须具备"处理非网页资源"的能力
==================================================================
"""

import hashlib
import tarfile
import io

from rangekit import FAKE, box, esc, page, table

# 令牌被拆成两段：前半段在源码归档里，后半段只能通过接口换
TOKEN_HEAD = "ZW1-API-TOKEN-2024-A1B2"
TOKEN_TAIL = "C3D4-E5F6-7890"

_SOFT404_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>某某市政务服务网</title>
<link rel="stylesheet" href="/style.css"></head>
<body>
<header><div class="wrap"><h1><a href="/">某某市政务服务网</a></h1></div></header>
<main class="wrap">
<h2>页面不存在</h2>
<p>您访问的页面可能已被移除、更名，或暂时不可用。</p>
<p>请从<a href="/l6/">首页</a>重新进入，或使用站内搜索。</p>
<p class="tiny">如果您确认该链接来自本站，请联系信息中心。</p>
</main>
<footer><div class="wrap"><p>某某市政务服务与大数据管理局 · 信息中心</p></div></footer>
</body></html>
"""


def _reply(body, ctype="text/html; charset=utf-8", status=200, headers=None, note=""):
    from serve import Reply
    return Reply(status, body, content_type=ctype, headers=headers or {}, note=note)


# ==================================================================
# 软 404：返回 200，内容看似正常，且**不含任何漏洞特征串**
# ==================================================================
def soft_not_found(ctx, sub):
    return _reply(_SOFT404_TEMPLATE)


# ==================================================================
# 首页：干干净净，线索只在 HTML 注释里
# ==================================================================
def page_index(ctx, m):
    body = """
<!-- ============================================================
     2024 年站点改版项目
       改版日期 : 2024-03-12
       源码归档 : /l6/src/site-2024.tar.gz
       归档说明 : 归档包含上线前配置，含内部接口定义，请勿外传
       责任人   : 运维保障组
     ============================================================ -->

<h2>某某市政务服务网</h2>
<p>本站提供政务公开、办事服务、通知公告等信息服务。</p>

<h2>最新公告</h2>
<article>
  <h3>关于政务服务网改版上线的公告</h3>
  <p>为提升服务体验，本站已于 2024 年 3 月完成改版，访问地址不变。</p>
  <p>如遇访问异常，请通过 http://zwfw.example.gov.cn/ 重新进入。</p>
</article>

<h2>常用服务</h2>
<ul>
  <li><a href="https://zwfw.example.gov.cn/service/apply">在线申报</a></li>
  <li><a href="notice.html">通知公告</a></li>
</ul>
"""
    return _reply(page("某某市政务服务网", body))


def page_notice(ctx, m):
    """
    与首页对照：这里用的是 **https**，首页写的是 **http**。
    同一站点两处协议不一致 = 典型的"https 被降级篡改"线索。
    """
    body = f"""
<h2>通知公告</h2>
<article>
  <h3>关于规范政务服务网访问地址的说明</h3>
  <p>本单位政务服务网正式访问地址为：
     <strong>https://zwfw.example.gov.cn/</strong>，请以 https 为准。</p>
  <p>任何以 http 开头的地址均非本单位发布，请勿点击。</p>
</article>
<article>
  <h3>关于系统维护的通知</h3>
  <p>维护窗口：每周二 22:00 - 24:00。维护期间部分功能不可用。</p>
  <p>维护期间联系人：张伟明　{FAKE["phone_1"]}</p>
</article>
"""
    return _reply(page("通知公告", body))


# ==================================================================
# 内部接口：用令牌前半段换后半段
# ==================================================================
def api_keys(ctx, m):
    """
    "内网接口"，只校验一个自定义请求头。

    令牌被刻意拆成两段：
      前半段在源码归档里，后半段只有调通这个接口才拿得到。
    这样设计的目的是**强制多步串联** —— 只拿到源码不够，只猜接口也不够。
    """
    token = ctx.header("x-api-token")
    if not token:
        return _reply('{"code":401,"msg":"missing X-Api-Token"}',
                      "application/json; charset=utf-8", status=401)
    if token != TOKEN_HEAD:
        return _reply('{"code":403,"msg":"invalid token"}',
                      "application/json; charset=utf-8", status=403)

    import json
    payload = json.dumps({
        "code": 0,
        "token_tail": TOKEN_TAIL,
        "full_token": TOKEN_HEAD + TOKEN_TAIL,
        "cloud": {
            "provider": "政务云",
            "access_key": FAKE["api_key"],
            "secret_key": FAKE["api_secret"],
        },
        "database": {
            "host": FAKE["db_ip"],
            "port": 3306,
            "user": FAKE["db_user"],
            "password": FAKE["db_pass"],
            "schema": "zwfw_prod",
        },
        "internal": {
            "oa": FAKE["oa_url"],
            "admin_ip": FAKE["internal_ip"],
        },
        "note": "本接口仅限内网调用，请勿对外暴露。",
    }, ensure_ascii=False, indent=2)
    return _reply(payload, "application/json; charset=utf-8",
                  note="chained-internal-api")


def robots(ctx, m):
    """
    注意：robots.txt 里**不写** src 和 api —— 这一关连"指路"都不给，
    入口只能从首页的 HTML 注释里推出来。
    """
    return _reply("""User-agent: *
Disallow: /l6/search

# 本站未开放目录索引
""", "text/plain; charset=utf-8")


ROUTES = (
    ("*", r"^/$", page_index),
    ("*", r"^/index\.html$", page_index),
    ("*", r"^/notice\.html$", page_notice),
    ("*", r"^/api/internal/keys$", api_keys),
    ("*", r"^/robots\.txt$", robots),
)

LEVEL = {
    "id": 6,
    "key": "l6",
    "name": "链路",
    "difficulty": "★★★★★★",
    "summary": "单点扫描零收获：必须串联「注释→源码归档→配置→内部接口」才能拿到密钥。",
    "hints": "首页源码注释是唯一入口。拿到源码后别停，配置里的接口才是下一环。",
    "tags": ["敏感信息", "篡改", "弱配置", "漏洞", "多步链"],
    "banner": "Apache/2.4.41 (Debian)",
    "headers": {},
    "autoindex": False,
    "not_found": soft_not_found,     # ★ 全站软 404，状态码完全不可信
    "methods": ("GET", "HEAD", "OPTIONS"),
    "assets": "l6",
    "routes": ROUTES,
}
