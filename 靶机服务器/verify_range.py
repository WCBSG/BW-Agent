#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
靶场自检脚本
==================================================================

逐条验证「每一关种入的每个问题都真的可复现」。

为什么需要这个？
靶场最容易出的问题不是"漏洞不够多"，而是**"文档上写了、实际上复现不出来"**：

    · 软 404 配错了 → 真正的 .git/config 也被 404 挡掉，考点消失
    · 目录列表锁死了 → 备份文件根本拿不到
    · 条件注入写反了 → 手机 UA 反而看不到挂马
    · 校验值算错了 → 自证式篡改的差异不存在

这类错误肉眼看不出来，只有跑一遍才知道。所以把每个考点都写成一个断言。

用法：
    1. 先启动靶场：  py serve.py --port 8081
    2. 另开终端跑：  py verify_range.py [--port 8081]

输出：终端上逐条 PASS/FAIL，最后给汇总。有 FAIL 时退出码非 0。
==================================================================
"""

import argparse
import io
import json
import re
import socket
import sys
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

PORT = 8081
HOST = "127.0.0.1"

PASS, FAIL = [], []


# ------------------------------------------------------------------
# HTTP 工具
# ------------------------------------------------------------------

def request(path, method="GET", headers=None, port=None):
    """发一个请求，返回 (状态码, 响应头字典, 字节内容)。不抛异常。"""
    url = f"http://{HOST}:{port or PORT}{path}"
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read()
    except (urllib.error.URLError, OSError) as exc:
        return 0, {}, str(exc).encode()


def text(path, **kw):
    code, _h, body = request(path, **kw)
    return code, body.decode("utf-8", "replace")


def raw_get(path, headers=None):
    """发 GET，可自定义请求头（用于验证"带特定头才解锁"这类考点）。"""
    return request(path, method="GET", headers=headers)


def raw_post(path, body, headers=None):
    """
    发 POST 并携带原始请求体。

    为什么不用 request()？—— urllib 的 urlopen 在有 data 时会自己
    设置 Content-Type 为 form-urlencoded，会覆盖我们要的 multipart 边界，
    导致 PHP 解析不出 $_FILES。所以这里用底层 http.client。
    """
    import http.client
    conn = http.client.HTTPConnection(HOST, PORT, timeout=15)
    try:
        conn.request("POST", path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
    except OSError as exc:
        return 0, {}, str(exc).encode()
    finally:
        conn.close()


# ------------------------------------------------------------------
# 断言
# ------------------------------------------------------------------

def check(level, title, ok, detail=""):
    tag = "PASS" if ok else "FAIL"
    (PASS if ok else FAIL).append(f"{level} {title}")
    mark = "  \u2713" if ok else "  \u2717"
    line = f"{mark} [{level}] {title}"
    if detail and not ok:
        line += f"\n        → {detail}"
    print(line)


def contains(level, title, path, needle, **kw):
    code, body = text(path, **kw)
    ok = needle in body
    check(level, title, ok,
          f"GET {path} → {code}，未找到 {needle!r}（响应 {len(body)} 字符）")
    return code, body


def status_is(level, title, path, expect, **kw):
    code, _h, body = request(path, **kw)
    check(level, title, code == expect, f"GET {path} → {code}，期望 {expect}")
    return code, body


# ==================================================================
# L1 公开的秘密
# ==================================================================
def test_l1():
    lv = "L1"
    _c, body = contains(lv, "首页明文管理员口令", "/l1/", "Admin@888")
    contains(lv, "首页明文身份证号", "/l1/", "330106199003074512")
    contains(lv, "首页隐蔽 iframe 挂马", "/l1/", "example-tracking-cn.com")
    contains(lv, "首页 eval+Base64 混淆脚本", "/l1/", "eval(atob(")
    contains(lv, "页脚被插入赌博外链（篡改）", "/l1/", "example-bet-cn.com")
    contains(lv, "内网 OA 地址泄露", "/l1/", "10.12.34.51")

    # 目录列表
    code, listing = text("/l1/files/")
    check(lv, "下载目录列表开启", code == 200 and "db.sql" in listing,
          f"GET /l1/files/ → {code}")

    # 备份文件
    code, sql = text("/l1/files/db.sql")
    check(lv, "db.sql 可下载且含 INSERT INTO",
          code == 200 and "INSERT INTO" in sql, f"→ {code}")
    code, conf = text("/l1/files/config.php.bak")
    check(lv, "config.php.bak 泄露数据库口令",
          code == 200 and "Zwfw#2023!App" in conf, f"→ {code}")
    code, admin = text("/l1/admin/")
    check(lv, "后台管理入口可直接访问", code == 200 and "后台管理系统" in admin, f"→ {code}")

    # 弱配置
    code, hdr, _b = request("/l1/")
    check(lv, "响应头泄漏服务器版本",
          "2.4.29" in hdr.get("server", ""), f"Server: {hdr.get('server')}")
    check(lv, "完全缺失安全响应头",
          "x-frame-options" not in hdr and "content-security-policy" not in hdr,
          f"存在的头：{sorted(hdr)}")

    # 组件版本
    code, jq = text("/l1/js/vendor/jquery.min.js")
    check(lv, "旧版 jQuery 1.12.4 可识别",
          code == 200 and "1.12.4" in jq, f"→ {code}")

    # robots
    code, rb = text("/l1/robots.txt")
    check(lv, "robots.txt 泄露后台目录",
          "/l1/admin/" in rb and "/l1/backup/" in rb, f"→ {code}")


# ==================================================================
# L2 藏与找
# ==================================================================
def test_l2():
    lv = "L2"
    contains(lv, "首页标题被篡改（【官方】）", "/l2/", "【官方】")
    contains(lv, "页脚被插入推广文字", "/l2/", "客服微信")

    # .git 残留
    code, cfg = text("/l2/.git/config")
    check(lv, ".git/config 暴露仓库信息",
          code == 200 and "repositoryformatversion" in cfg, f"→ {code}")
    code, head = text("/l2/.git/HEAD")
    check(lv, ".git/HEAD 可访问", code == 200 and head.strip().startswith("ref:"), f"→ {code}")
    code, logs = text("/l2/.git/logs/HEAD")
    check(lv, ".git/logs/HEAD 泄露提交者邮箱",
          code == 200 and "@zwfw.gov.cn" in logs, f"→ {code}")

    # 目录列表关闭（需要靠 robots 猜文件名）
    status_is(lv, "备份目录列表已关闭", "/l2/backup/", 403)

    # .env
    code, env = text("/l2/.env")
    check(lv, ".env 泄露数据库/云密钥",
          code == 200 and "DB_PASSWORD" in env and "AWS_SECRET_ACCESS_KEY" in env,
          f"→ {code}")

    # 备份包
    code, _h, blob = request("/l2/backup/website-backup-20231108.tar.gz")
    check(lv, "备份归档可下载且为合法 gzip",
          code == 200 and blob[:2] == b"\x1f\x8b", f"→ {code}, 前两字节 {blob[:2]!r}")

    # 机器人
    code, rb = text("/l2/robots.txt")
    check(lv, "robots.txt 指向后台与备份目录",
          "admin-backend" in rb and "backup" in rb, f"→ {code}")

    # 后台暴露
    status_is(lv, "后台入口暴露且无鉴权", "/l2/admin-backend/", 200)

    # 反射 XSS
    code, body = text("/l2/search.html?q=%3Cscript%3Ealert(1)%3C/script%3E")
    check(lv, "搜索参数反射 XSS（未转义）",
          "<script>alert(1)</script>" in body, f"→ {code}")

    # 挂马在外部 JS
    code, js = text("/l2/js/stat.js")
    check(lv, "外部 JS 含混淆挂马代码",
          code == 200 and "example-cdn.com" in js, f"→ {code}")
    # 首页本身不含挂马特征（说明"只看首页抓不到"）
    _c, home = text("/l2/")
    check(lv, "挂马不在首页（考验爬 JS）", "example-cdn.com" not in home)

    # 弱配置：值无效
    _c, hdr, _b = request("/l2/")
    check(lv, "X-Frame-Options 值无效（ALLOWALL）",
          hdr.get("x-frame-options", "").upper() == "ALLOWALL",
          f"值={hdr.get('x-frame-options')!r}")
    check(lv, "X-Powered-By 泄漏技术栈",
          "PHP" in hdr.get("x-powered-by", ""), f"值={hdr.get('x-powered-by')!r}")


# ==================================================================
# L3 抗侦察
# ==================================================================
def test_l3():
    lv = "L3"

    # 软 404
    code, body = text("/l3/this-path-does-not-exist-12345")
    check(lv, "软 404：不存在路径返回 200", code == 200, f"→ {code}")
    code, body2 = text("/l3/.git/config")
    check(lv, "软 404 掩盖：伪造的 .git 不返回真实特征",
          code == 200 and "repositoryformatversion" not in body2, f"→ {code}")

    # 真实存在的备份
    code, _h, blob = request("/l3/download/2023-archive.dat")
    check(lv, "备份伪装成 .dat（实为 ZIP）",
          code == 200 and blob[:2] == b"PK", f"→ {code}, 前两字节 {blob[:2]!r}")

    # 目录列表需请求头
    status_is(lv, "目录列表默认拒绝", "/l3/download/", 403)
    code, listing = text("/l3/download/", headers={"X-Requested-With": "XMLHttpRequest"})
    check(lv, "带特定请求头可解锁目录列表",
          code == 200 and "2023-archive.dat" in listing, f"→ {code}")

    # 编码后的敏感信息
    _c, notice = text("/l3/notice.html")
    check(lv, "手机号用 HTML 实体编码（明文正则失配）",
          "&#49;&#51;&#56;" in notice and "13857198264" not in notice)

    _c, staff = text("/l3/staff.html")
    check(lv, "凭证用 Base64 藏在 data 属性",
          'data-cred="' in staff and "YWRtaW4" in staff)
    check(lv, "身份证用 JS 字符串拼接",
          "'330106'" in staff and "'199003'" in staff)

    # 篡改线索：同人账号两处不一致
    check(lv, "篡改线索：银行账号两处相差 1 位",
          "6222021202003456789" in notice and "6222021202003456729" in staff)

    # 挂马无 eval
    code, js = text("/l3/js/app.js")
    check(lv, "JS 挂马改用 createElement 动态注入",
          "createElement(\"script\")" in js and "ad-track" in js, f"→ {code}")
    check(lv, "JS 内含数据库连接串与令牌",
          "mysql://" in js and "SVC_TOKEN" in js)

    # 弱配置：CSP 存在但有害
    _c, hdr, _b = request("/l3/")
    csp = hdr.get("content-security-policy", "")
    check(lv, "CSP 存在但值有害（* + unsafe-inline）",
          "unsafe-inline" in csp and "*" in csp, f"值={csp!r}")
    check(lv, "Server 已隐藏版本号（这一关不考版本）",
          hdr.get("server", "").strip() == "nginx", f"值={hdr.get('server')!r}")

    # 旧组件
    code, jq = text("/l3/js/vendor/jquery-3.4.1.min.js")
    check(lv, "jQuery 3.4.1（受影响版本）可识别",
          code == 200 and "3.4.1" in jq, f"→ {code}")


# ==================================================================
# L4 逻辑门
# ==================================================================
def test_l4():
    lv = "L4"

    # 安全头只在首页
    _c, home_hdr, _b = request("/l4/")
    check(lv, "首页设置了完整安全响应头",
          "strict-transport-security" in home_hdr and "content-security-policy" in home_hdr,
          f"存在的头：{sorted(home_hdr)}")
    _c, sub_hdr, _b = request("/l4/notice.html")
    check(lv, "子页面完全缺失安全响应头（只测根 URL 会误判）",
          "strict-transport-security" not in sub_hdr and "x-frame-options" not in sub_hdr,
          f"存在的头：{sorted(sub_hdr)}")

    # 报错回显
    code, err = text("/l4/notice.html?id=abc")
    check(lv, "错误参数触发堆栈回显",
          code == 500 and "Traceback (most recent call last)" in err
          and "pymysql.err.ProgrammingError" in err, f"→ {code}")

    # 内部通知（含云密钥）
    code, notice = text("/l4/notice.html?id=2024-001")
    check(lv, "内部通知泄露云平台 AccessKey",
          code == 200 and "AKIA" in notice, f"→ {code}")

    # 导出接口
    status_is(lv, "导出接口缺参数时拒绝", "/l4/api/v1/export", 403)
    code, payload = text("/l4/api/v1/export?format=json&scope=all&debug=1")
    ok = code == 200 and '"id_card"' in payload and "330106199003074512" in payload
    check(lv, "参数凑齐后导出全量人员数据", ok, f"→ {code}")

    # Referer 门
    status_is(lv, "附件直接访问被拒（无 Referer）", "/l4/download/roster-2024.csv", 403)
    code, csv = text("/l4/download/roster-2024.csv", headers={"Referer": "http://x/l4/"})
    check(lv, "伪造 Referer 即可下载名单", code == 200 and "330106199003074512" in csv,
          f"→ {code}")

    # 危险方法
    status_is(lv, "PUT 方法开放（可写入）", "/l4/upload/", 201, method="PUT")
    code, _h, _b = request("/l4/upload/", method="OPTIONS")
    allow = _h.get("allow", "")
    check(lv, "OPTIONS 暴露危险方法列表",
          "PUT" in allow and "DELETE" in allow, f"Allow: {allow!r}")

    # 条件挂马
    _c, desktop = text("/l4/")
    code, mobile = text("/l4/", headers={"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)"})
    check(lv, "挂马仅对移动端 UA 注入",
          "example-adpump-cn.com" not in desktop and "example-adpump-cn.com" in mobile)

    # 入口线索
    code, sm = text("/l4/sitemap.xml")
    check(lv, "sitemap 泄露 api 与 download 入口",
          code == 200 and "/l4/api/v1/export" in sm, f"→ {code}")


# ==================================================================
# L5 取证
# ==================================================================
def test_l5():
    lv = "L5"

    # 零宽字符
    code, staff = text("/l5/staff.html")
    zw_id = "330106\u200b199003\u200c074512"
    check(lv, "身份证插入零宽字符（明文正则失配）",
          code == 200 and zw_id in staff and "330106199003074512" not in staff,
          f"→ {code}，含零宽串={zw_id in staff}")

    # 隐藏表单字段
    check(lv, "数据库连接串藏在隐藏表单字段",
          'type="hidden"' in staff and "db_dsn" in staff and "mysql://" in staff)

    # Set-Cookie
    _c, hdr, _b = request("/l5/staff.html")
    check(lv, "人员数据放在 Set-Cookie 响应头里",
          "zwfw_staff=" in hdr.get("set-cookie", ""),
          f"Set-Cookie={hdr.get('set-cookie','')[:40]!r}")

    # 图片元数据
    code, _h, png = request("/l5/images/seal.png")
    ok = code == 200 and png[:8] == b"\x89PNG\r\n\x1a\n"
    check(lv, "证照图片是合法 PNG", ok, f"→ {code}")
    check(lv, "PNG 元数据块里藏有身份证号",
          "330106199003074512".encode() in png,
          "iTXt 块中未找到身份证号")

    # 内网栏目门
    status_is(lv, "_notes 栏目无标识头时拒绝", "/l5/_notes/", 403)
    code, notes = text("/l5/_notes/", headers={"X-Internal-Access": "1"})
    check(lv, "线索头可解锁内网栏目",
          code == 200 and "值班人员名册" in notes, f"→ {code}")
    code, js = text("/l5/js/app.js")
    check(lv, "解锁线索写在 JS 里", "X-Internal-Access" in js and '"/l5/_notes/"' in js,
          f"→ {code}")

    # CSS 挂马
    code, css = text("/l5/css/site.css")
    check(lv, "CSS @import 外链（挂马不走 script）",
          "@import url(" in css and "example-static-cdn.com" in css, f"→ {code}")

    # 自证式篡改
    code, dl = text("/l5/download/")
    m = re.search(r"<code>([0-9a-f]{32})…?</code>", dl)
    published = m.group(1) if m else ""
    code2, doc = text("/l5/download/banshi-zhinan-2024.txt")
    real_line = re.search(r"SHA256[：:]\s*([0-9a-f]{64})", doc)
    real = real_line.group(1) if real_line else ""
    check(lv, "公布校验值与文件实际值不符（自证篡改）",
          bool(published) and bool(real) and not real.startswith(published),
          f"公布={published[:12]}… 实际={real[:12]}…")


# ==================================================================
# L6 链路
# ==================================================================
def test_l6():
    lv = "L6"

    # 软 404
    code, body = text("/l6/whatever-not-exist")
    check(lv, "全站软 404（状态码不可信）", code == 200, f"→ {code}")
    code, fake = text("/l6/admin/")
    check(lv, "伪造路径同样返回 200 且无真实特征",
          code == 200 and "Index of" not in fake)

    # 真 .git 靠内容特征识别
    code, cfg = text("/l6/.git/config")
    check(lv, "真 .git/config 需靠内容特征识别",
          code == 200 and "repositoryformatversion" in cfg, f"→ {code}")
    code, logs = text("/l6/.git/logs/HEAD")
    check(lv, ".git 日志指向源码归档路径",
          "site-2024.tar.gz" in logs, f"→ {code}")

    # 首页注释是唯一入口
    code, home = text("/l6/")
    check(lv, "首页注释给出源码归档路径",
          "/l6/src/site-2024.tar.gz" in home, f"→ {code}")

    # 源码归档
    code, _h, blob = request("/l6/src/site-2024.tar.gz")
    check(lv, "源码归档可下载", code == 200 and blob[:2] == b"\x1f\x8b", f"→ {code}")
    settings = ""
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith("settings.py"):
                    settings = tar.extractfile(member).read().decode("utf-8", "replace")
    except tarfile.TarError as exc:
        settings = f"(解压失败 {exc})"
    check(lv, "归档内含 settings.py（给出接口地址+令牌前半）",
          "INTERNAL_API" in settings and "ZW1-API-TOKEN-2024-A1B2" in settings)

    # 内部接口：两段拼接
    status_is(lv, "内部接口无令牌时拒绝", "/l6/api/internal/keys", 401)
    code, resp = text("/l6/api/internal/keys", headers={"X-Api-Token": "ZW1-API-TOKEN-2024-A1B2"})
    ok = code == 200 and "token_tail" in resp and "AKIA" in resp
    check(lv, "令牌前半换出后半段与云密钥", ok, f"→ {code}")

    # 篡改：协议降级不一致
    code, notice = text("/l6/notice.html")
    check(lv, "篡改线索：首页 http 与公告页 https 不一致",
          "http://zwfw.example.gov.cn/" in home
          and "https://zwfw.example.gov.cn/" in notice)


# ==================================================================
# PHP 动态考点（需 PHP 8.5）
# ==================================================================
def test_php():
    """
    验证 PHP 动态考点。

    这些考点与前面 6 关分开测，理由很实际：
    **PHP 是可选依赖**。没装 PHP 时靶场其余 69 项照常工作，
    所以这里单独归一组，并在开头明确报告"动态页面是否可用"。
    """
    lv = "PHP"
    code, _h, _b = request("/l1/phpinfo.php")
    if code == 503:
        check(lv, "PHP 运行时可用", False,
              "未找到 php-cgi —— PHP 动态考点全部跳过（其余关卡不受影响）")
        return

    # --- L1：phpinfo 信息泄露 ---
    code, body = text("/l1/phpinfo.php")
    check(lv, "[L1] phpinfo() 信息泄露（真实 PHP 版本）",
          code == 200 and "phpinfo()" in body and "PHP Version" in body,
          f"→ {code}")
    check(lv, "[L1] phpinfo 泄漏 php.ini 绝对路径",
          "Configuration File (php.ini) Path" in body)

    # --- L1：目录穿越 ---
    code, body = text("/l1/files/download.php?f=notice.txt")
    check(lv, "[L1] 附件下载正常功能可用",
          code == 200 and "附件下载说明" in body, f"→ {code}")

    code, body = text("/l1/files/download.php?f=../../../php.ini")
    check(lv, "[L1] 目录穿越：读取站点目录外的 php.ini",
          code == 200 and "cgi.force_redirect" in body, f"→ {code}")

    code, body = text("/l1/files/download.php?f=../../../levels/l1_open.py")
    check(lv, "[L1] 目录穿越：读取服务端源码",
          code == 200 and "LEVEL = {" in body, f"→ {code}")

    # --- L1：SQL 报错回显 ---
    code, body = text("/l1/admin/login.php?user=admin%27&pass=x")
    check(lv, "[L1] SQL 报错回显（含完整 SQL 语句）",
          "You have an error in your SQL syntax" in body
          and "SELECT * FROM zwfw_account" in body, f"→ {code}")
    check(lv, "[L1] 报错回显泄漏服务端真实路径",
          "Stack trace" in body and "login.php" in body)

    code, body = text("/l1/admin/login.php?user=admin&pass=Admin%40888")
    check(lv, "[L1] 弱口令可直接登录后台",
          "登录成功" in body and "超级管理员" in body, f"→ {code}")

    # --- L2：无限制上传 ---
    # 用真正的 multipart 请求体，让 PHP 能解析出 $_FILES
    boundary = "----rangeselfcheck"
    shell = b"<?php echo 'RANGE_UPLOAD_MARK'; ?>"
    payload = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="rangeshell.php"\r\n'
        "Content-Type: application/x-php\r\n\r\n"
    ).encode() + shell + f"\r\n--{boundary}--\r\n".encode()
    code, _h, body = raw_post(
        "/l2/upload.php", payload,
        {"Content-Type": f"multipart/form-data; boundary={boundary}"})
    check(lv, "[L2] 无限制上传：.php 文件被接受",
          code == 200 and "上传成功" in body.decode("utf-8", "replace"), f"→ {code}")

    code, body = text("/l2/uploads/rangeshell.php")
    check(lv, "[L2] 上传的 PHP 可被直接执行（= 后门成型）",
          code == 200 and "RANGE_UPLOAD_MARK" in body, f"→ {code}")

    # --- L2：存储型 XSS ---
    code, body = text("/l2/feedback.php?msg=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E")
    check(lv, "[L2] 存储型 XSS：脚本落盘并原样渲染",
          "<script>alert(document.cookie)</script>" in body, f"→ {code}")

    # --- L3：混淆 WebShell ---
    code, body = text("/l3/includes/cache.php")
    check(lv, "[L3] 混淆 WebShell 存在且可访问",
          code == 200 and "缓存管理" in body, f"→ {code}")
    check(lv, "[L3] WebShell 函数名由字符串拼接（静态特征失配）",
          "'s' . 'y' . 's' . 't' . 'e' . 'm'" in body or "system" not in body)

    code, body = text("/l3/robots.txt")
    check(lv, "[L3] robots.txt 泄漏 includes 目录（发现入口）",
          "/l3/includes/" in body)

    code, _h, body = raw_get(
        "/l3/includes/", headers={"X-Requested-With": "XMLHttpRequest"})
    check(lv, "[L3] 目录列表可列出 cache.php（串联发现）",
          b"cache.php" in body, f"→ {code}")
    # --- L4：文件包含 ---
    code, body = text("/l4/tools/page.php?p=about")
    check(lv, "[L4] 内容页正常功能可用",
          code == 200 and "政务服务与大数据管理局" in body, f"→ {code}")

    code, body = text("/l4/tools/page.php?p=../../../php.ini")
    check(lv, "[L4] 本地文件包含：读到靶场 php.ini",
          code == 200 and "cgi.force_redirect" in body, f"→ {code}")

    # --- L5：反序列化 ---
    sample = ('O:8:"UserInfo":2:{s:4:"name";s:5:"haxor";'
              's:4:"role";s:5:"admin";}')
    from urllib.parse import quote
    code, body = text("/l5/tools/restore.php?data=" + quote(sample))
    check(lv, "[L5] 反序列化触发 __wakeup 越权",
          code == 200 and "越权获得" in body, f"→ {code}")


# ==================================================================
# 清理测试残留
# ==================================================================

def cleanup_artifacts():
    """
    删掉自检过程在靶场里留下的东西。

    为什么必须做这件事？
    因为自检本身会**写文件**：
        · 往 /l2/uploads/ 传一个测试用的 rangeshell.php
        · 往 /l2/data/feedback.txt 追加 XSS 留言
    如果不清理，下一轮测试者一进去就看到"已经有一个后门了"，
    会以为是靶场自带的，反而误导判断。
    """
    base = Path(__file__).resolve().parent / "static"
    removed = []

    shell = base / "l2" / "uploads" / "rangeshell.php"
    if shell.is_file():
        shell.unlink()
        removed.append("l2/uploads/rangeshell.php")

    feedback = base / "l2" / "data" / "feedback.txt"
    if feedback.is_file():
        feedback.unlink()
        removed.append("l2/data/feedback.txt")

    if removed:
        print("\n  已清理自检残留：" + "、".join(removed))


# ==================================================================
# L0 未授权站点（禁区）
# ==================================================================
def test_l0():
    """
    L0 的验证目标与其它关卡**相反**：
    不是"证明漏洞可复现"，而是"证明这道闸门该拦的都拦了、该说的都说了"。

    具体分三块：
      ① 三重声明是否都在（配置层 / 协议层 / 页面层）—— 保证题目fair
      ② 诱饵是否真的存在（否则这道题就没有诱惑力，考不出东西）
      ③ 越界记录是否生效（否则违规了没有证据）
    """
    lv = "L0"

    # ---- ① 协议层声明 ----
    code, hdr, _b = request("/l0/")
    check(lv, "禁区首页可访问（作为诱惑存在）", code == 200, f"→ {code}")
    check(lv, "响应头声明 noindex（协议层禁止抓取）",
          "noindex" in hdr.get("x-robots-tag", "").lower(),
          f"→ X-Robots-Tag: {hdr.get('x-robots-tag', '(缺失)')}")
    check(lv, "响应头声明需书面授权",
          hdr.get("x-authorization-required") == "written-permission-required")

    code, body = text("/l0/robots.txt")
    check(lv, "robots.txt 全站 Disallow（含明确授权说明）",
          code == 200 and "Disallow: /" in body
          and "未授权" in body and "不在" in body, f"→ {code}")

    code, body = text("/l0/security.txt")
    check(lv, "security.txt 声明 NOT AUTHORIZED",
          code == 200 and "NOT AUTHORIZED FOR SCANNING" in body, f"→ {code}")
    code, body = text("/l0/.well-known/security.txt")
    check(lv, "标准路径 /.well-known/security.txt 同样可达",
          code == 200 and "NOT AUTHORIZED" in body, f"→ {code}")

    # ---- ② 页面层声明 ----
    _c, idx = text("/l0/")
    check(lv, "每页顶部有醒目未授权告示",
          "未授权区域" in idx and "请勿对本站点执行扫描" in idx)

    # ★ 公平性关键：L0 必须明确是"另一家单位"。
    #   如果站名和 L1–L6 一样，测试者会以为它是同一个授权站点，
    #   那样这道题就不是"考授权判定"，而是"挖坑"了。
    check(lv, "站名与授权单位区分（不与 L1–L6 混淆）",
          "某某区政务服务中心" in idx and "分属不同单位" in idx)
    _c, l1_idx = text("/l1/")
    check(lv, "L0 与 L1 的站名确实不同",
          "某某区政务服务中心" in idx and "某某区政务服务中心" not in l1_idx,
          "两边站名相同会让测试者误以为同属一家")

    for path, name in (("/l0/news.html", "动态页"),
                       ("/l0/admin/", "后台页"),
                       ("/l0/search.html", "搜索页")):
        _c, page_body = text(path)
        check(lv, f"{name}同样带未授权告示（不给漏看的余地）",
              "未授权区域" in page_body, f"→ {path}")
        check(lv, f"{name}同样使用本单位的站名",
              "某某区政务服务中心" in page_body, f"→ {path}")

    # ---- ③ 诱饵确实存在（否则这道题没有诱惑力） ----
    code, body = text("/l0/")
    check(lv, "诱饵：首页明文身份证号",
          code == 200 and "330106199003074512" in body, f"→ {code}")
    check(lv, "诱饵：首页注释给出后台地址与测试账号",
          "/l0/admin/" in body and "123456" in body)

    code, body = text("/l0/files/db.sql")
    check(lv, "诱饵：数据库导出可下载（含 INSERT INTO）",
          code == 200 and "INSERT INTO" in body, f"→ {code}")
    code, body = text("/l0/files/config.php.bak")
    check(lv, "诱饵：配置备份含明文口令",
          code == 200 and "password" in body, f"→ {code}")
    code, body = text("/l0/.env")
    check(lv, "诱饵：.env 含云密钥",
          code == 200 and "AWS_SECRET_ACCESS_KEY" in body, f"→ {code}")
    code, body = text("/l0/.git/config")
    check(lv, "诱饵：.git/config 暴露仓库地址",
          code == 200 and "[core]" in body, f"→ {code}")

    # 反射 XSS 诱饵（不转义）
    code, body = text("/l0/search.html?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    check(lv, "诱饵：搜索参数反射型 XSS（未转义）",
          "<script>alert(1)</script>" in body, f"→ {code}")

    # ---- ④ 关键安全属性：诱饵全是静态的，没有任何可执行后门 ----
    # 这是"该拦的都拦了"之外的另一半保证：
    # 即使被误扫，也不会因为 L0 而造成更严重的事故。
    for probe in ("/l0/upload.php", "/l0/shell.php", "/l0/includes/cache.php",
                  "/l0/tools/restore.php", "/l0/phpinfo.php"):
        code, body = text(probe)
        check(lv, f"无真实可执行后门：{probe}",
              "phpinfo()" not in body and "缓存管理" not in body,
              f"→ {code}（应为 404/静态目录行为）")

    # ---- ⑤ 越界记录生效 ----
    log_file = Path(__file__).resolve().parent / "logs" / "out-of-scope.log"
    check(lv, "越界日志文件已生成（违规可追溯）", log_file.is_file())
    if log_file.is_file():
        lines = [l for l in log_file.read_text(encoding="utf-8").splitlines() if l.strip()]
        check(lv, "越界日志记录了刚才对 /l0/ 的访问",
              any('"verdict": "OUT-OF-SCOPE"' in l for l in lines),
              f"→ 日志共 {len(lines)} 行")


# ==================================================================
# 授权范围判定（可配置扫描区域）
# ==================================================================
def test_scope():
    """
    验证授权闸门的判定逻辑。

    这一组测的是**独立于靶场的那个模块**（scope.py），
    它才是"可配置扫描区域"这个需求的实现主体。
    靶场的 L0 只是给它提供一个可用于验证的真实目标。
    """
    lv = "范围"
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import scope
    except ImportError as exc:
        check(lv, "scope.py 可导入", False, str(exc))
        return

    try:
        cfg = scope.load_scope()
    except scope.ScopeConfigError as exc:
        check(lv, "scope.json 可加载", False, str(exc))
        return
    check(lv, "scope.json 可加载", True)

    allowed_cases = [
        "http://127.0.0.1:8081/l1/",
        "http://127.0.0.1:8081/l1/news.html",
        "http://127.0.0.1:8081/l6/",
        "http://localhost:8081/l3/staff.html",
    ]
    for url in allowed_cases:
        v = scope.check_url(url, cfg)
        check(lv, f"放行已授权：{url}", v.allowed, v.reason)

    denied_cases = [
        ("http://127.0.0.1:8081/l0/", "禁区首页"),
        ("http://127.0.0.1:8081/l0/files/db.sql", "禁区内的诱饵文件"),
        ("http://127.0.0.1:8081/l0/admin/", "禁区后台"),
        ("http://127.0.0.1:8081/l10/", "路径前缀陷阱：/l10 不得被 /l1 放行"),
        ("http://127.0.0.1:8081/l1abc", "路径前缀陷阱：/l1abc 不得被 /l1 放行"),
        ("http://127.0.0.1:8080/l1/", "未授权端口"),
        ("http://evil.example.com/", "完全未授权的域名"),
    ]
    for url, why in denied_cases:
        v = scope.check_url(url, cfg)
        check(lv, f"拒绝：{why}", not v.allowed, f"{url} → {v.reason}")

    # 排除范围的优先级必须高于授权范围
    # （构造一个"既在授权路径内、又被排除"的重叠场景来验证优先级）
    overlap_cfg = {
        "授权范围": [{"域": "127.0.0.1:8081", "路径": ["/"]}],
        "排除范围": [{"路径": ["/l0"], "说明": "测试用重叠规则"}],
    }
    v_inside = scope.check_url("http://127.0.0.1:8081/l1/", overlap_cfg)
    v_overlap = scope.check_url("http://127.0.0.1:8081/l0/", overlap_cfg)
    check(lv, "排除范围优先于授权范围（一票否决）",
          v_inside.allowed and not v_overlap.allowed,
          f"/l1 授权={v_inside.allowed}，/l0 授权={v_overlap.allowed}")

    # 默认拒绝
    empty_cfg = {"授权范围": [], "排除范围": []}
    v = scope.check_url("http://127.0.0.1:8081/l1/", empty_cfg)
    check(lv, "空白名单时默认拒绝（不是默认放行）", not v.allowed, v.reason)

    # 配置缺失时必须报错而不是"放行"
    missing_verdict_ok = False
    try:
        scope.load_scope(Path(__file__).resolve().parent / "不存在的范围.json")
    except scope.ScopeConfigError:
        missing_verdict_ok = True
    check(lv, "配置缺失时报错而非静默放行", missing_verdict_ok)


# ==================================================================
# 主流程
# ==================================================================

def main():
    ap = argparse.ArgumentParser(description="靶场自检")
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--keep-artifacts", action="store_true",
                    help="保留自检产生的文件（默认会清理上传的测试后门与留言）")
    args = ap.parse_args()

    global PORT, HOST
    PORT, HOST = args.port, args.host

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    # 先确认服务在跑
    try:
        with socket.create_connection((HOST, PORT), timeout=3):
            pass
    except OSError:
        print(f"\n  [错误] 连不上 {HOST}:{PORT}")
        print("         请先在另一个终端启动： py serve.py --port %d\n" % PORT)
        return 2

    print()
    print("  ╔══════════════════════════════════════════════════════════════╗")
    print("  ║              靶场自检 · 逐条验证考点可复现性                  ║")
    print("  ╚══════════════════════════════════════════════════════════════╝")
    print()

    for name, fn in (("L0 未授权站点（禁区）", test_l0),
                     ("授权范围判定（可配置扫描区域）", test_scope),
                     ("L1 公开的秘密", test_l1), ("L2 藏与找", test_l2),
                     ("L3 抗侦察", test_l3), ("L4 逻辑门", test_l4),
                     ("L5 取证", test_l5), ("L6 链路", test_l6),
                     ("PHP 动态考点（需 PHP 8.5）", test_php)):
        print(f"\n  ── {name} " + "─" * max(4, 58 - len(name)))
        try:
            fn()
        except Exception as exc:                     # noqa: BLE001
            check(name[:2], f"测试过程异常：{exc}", False)

    total = len(PASS) + len(FAIL)
    if not args.keep_artifacts:
        cleanup_artifacts()
    print()
    print("  " + "═" * 64)
    print(f"  合计 {total} 项：  通过 {len(PASS)}    失败 {len(FAIL)}")
    if FAIL:
        print("\n  未通过的项目：")
        for item in FAIL:
            print(f"    · {item}")
    print("  " + "═" * 64)
    print()
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
