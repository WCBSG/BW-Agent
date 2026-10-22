#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""演示靶站服务器（多关卡版）—— 配合「网站安全巡检智能体」。

零第三方依赖，只用 Python 标准库。每关一个端口、一组独立问题，难度递增：

  L0  8890  对照组：正常站点，不应报任何风险
  L1  8891  显性泄露：/.env、/backup.sql、/phpinfo.php + 缺失安全响应头
  L2  8892  隐蔽暴露：/portal/.env、/uploads/ 目录索引、/error.log、管理入口、Cookie 无 HttpOnly、软 404 诱饵
  L3  8893  注入验证：/article?id= 布尔差分 + 报错回显
  L4  8894  内容安全：可疑外链/挂马；/portal/ 可切换被篡改
  L5  8895  特征对抗：/site.tar.gz、/.git/HEAD、/debug.log；HTML 诱饵不应误报；协议相对外链为已知边界
  L6  8896  综合对抗：/.env.save、/info.php、/private.key；/config.json 与 /db.sql 为 HTML 诱饵，不应误报

控制接口（每关端口都带，token 默认 demo）：
  GET /__ctl/status?token=demo
  GET /__ctl/tamper?on=1|off=1&token=demo
  GET /__ctl/fix?item=<项>&token=demo
  GET /__ctl/reset?token=demo

状态只在内存中，重启即复位。只监听 127.0.0.1，仅供本机授权演示。
"""

import http.server
import json
import socketserver
import sys
import threading
import urllib.parse

HOST = "127.0.0.1"
TOKEN = "demo"
LEVEL_PORTS = {0: 8890, 1: 8891, 2: 8892, 3: 8893, 4: 8894, 5: 8895, 6: 8896}

STATE = {
    "headers_l1_fixed": False,
    "l1_env_fixed": False,
    "l2_env_fixed": False,
    "l2_dirlist_fixed": False,
    "l2_cookie_fixed": False,
    "l3_sqli_fixed": False,
    "l4_links_fixed": False,
    "l4_tamper": False,
    "l5_archive_fixed": False,
    "l5_git_fixed": False,
    "l6_envsave_fixed": False,
    "l6_key_fixed": False,
}


def html(title, body):
    return ('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
            "<title>%s</title></head><body>%s</body></html>" % (title, body))


LEVEL_TITLES = {
    0: "L0 对照组（无风险）",
    1: "L1 显性泄露",
    2: "L2 隐蔽暴露",
    3: "L3 注入验证",
    4: "L4 内容安全",
    5: "L5 特征对抗",
    6: "L6 综合对抗",
}


def level_home(level):
    return html(LEVEL_TITLES[level], """
<h1>%s</h1>
<p>本页为演示靶站的第 %d 关，仅用于授权巡检演练。</p>
<ul>
  <li><a href="/about/">关于本站</a></li>
  <li><a href="/contact/">联系方式</a></li>
</ul>
""" % (LEVEL_TITLES[level], level))


ABOUT = html("关于本站", "<h1>关于本站</h1><p>演示用站点，内容正常。</p>")
CONTACT = html("联系方式", "<h1>联系方式</h1><p>演示路 1 号，电话 0000-0000000。</p>")

NEWS_SAFE = html("新闻动态", "<h1>新闻动态</h1><p>本站新闻列表。</p>")
NEWS_BAD = html("新闻动态", """
<h1>新闻动态</h1>
<p>本站新闻列表。</p>
<div style="display:none"><a href="http://badcdn.xyz/x.js">推广位</a></div>
<iframe src="http://203.0.113.7/frame.html" width="0" height="0"></iframe>
<p><a href="http://example.com/friend">友情链接</a></p>
""")
NEWS_RELATIVE = html("新闻动态", """
<h1>新闻动态</h1>
<p>协议相对外链演示（已知边界：当前版本可能不报）。</p>
<script src="//badcdn.xyz/rel.js"></script>
""")

PORTAL_NORMAL = html("业务门户", """
<h1>业务门户</h1>
<p>服务时间 9:00 至 17:00。</p>
<p>本页用于内容基线演示：第一次访问后由巡检程序记录基线。</p>
<footer>演示单位 · 门户页</footer>
""")

PORTAL_TAMPERED = html("业务门户", """
<h1>业务门户</h1>
<p>服务时间 9:00 至 17:00。</p>
<script src="http://badcdn.xyz/portal.js"></script>
<p>页面内容已被改动（演示用）。</p>
""")

ARTICLE_OK = html("文章", "<h1>机构简介</h1><p>本单位负责示范业务的运行与维护。</p>")
ARTICLE_MISS = html("文章", "<h1>机构简介</h1><p>未找到该文章。</p>")
SQL_ERROR = html("系统提示",
                 "<p>You have an error in your SQL syntax; check the manual that corresponds "
                 "to your MySQL server version for the right syntax to use near ''' at line 1</p>")

ENV_BODY = """# 演示用配置（伪造，不含真实凭据）
APP_NAME=demo-portal
DB_HOST=127.0.0.1
DB_USER=portal
DB_PASSWORD=Demo#Passw0rd
REDIS_PASSWORD=DemoRedis#123
SECRET_KEY=demo-secret-key-0123456789abcdef
APP_KEY=AKIDdemo0000000000
AWS_SECRET_ACCESS_KEY=demosecret
"""

SQL_DUMP = """-- MySQL dump 10.13  Distrib 5.7.44, for Linux (x86_64)
--
-- Host: localhost    Database: portal
-- ------------------------------------------------------
/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL,
  `password` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `users` VALUES (1,'admin','5f4dcc3b5aa765d61d8327deb882cf99');
""" + ("-- padding line for demo\n" * 20)

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0demo0demo0demo0demo0demo0demo0demo0demo0demo0
demo0demo0demo0demo0demo0demo0demo0demo0demo0demo0demo0demo0demo
-----END RSA PRIVATE KEY-----
"""

PHPINFO = html("phpinfo()", "<h1>PHP Version => 7.4.33</h1><p>System => Linux demo 5.15</p>")

LOG_BODY = "\n".join(
    ["2026-10-20 10:00:%02d ERROR database connection timeout" % i for i in range(20)]
    + ["2026-10-20 10:01:%02d WARN  cache miss for key home" % i for i in range(20)]
) + "\n"

GIT_HEAD = "ref: refs/heads/main\n"

UPLOADS_LISTING = html("Index of /uploads/", """
<h1>Index of /uploads/</h1>
<pre>
<a href="readme.txt">readme.txt</a>            2026-10-01 10:00   128
<a href="notice.pdf">notice.pdf</a>            2026-10-02 11:00  10240
</pre>
""")

LOGIN = html("管理员登录", """
<h1>管理员登录</h1>
<form method="post" action="/admin/login">
  <p><label>用户名 <input name="user" type="text"></label></p>
  <p><label>口令 <input name="pass" type="password"></label></p>
  <p><button type="submit">登录</button></p>
</form>
""")

SOFT404 = html("页面不存在", """
<h1>页面不存在</h1>
<p>您访问的页面不存在或已被移除。</p>
<p><a href="/">返回首页</a></p>
""")

# HTML 诱饵：正文里出现凭据特征，但整体是 HTML —— 按规则不应被判为配置文件泄露
DECOY_ENV_HTML = html("帮助文档", """
<h1>帮助文档</h1>
<p>示例：在配置文件中填写 DB_PASSWORD=你的密码、DB_HOST=数据库地址。</p>
<p>以上为文档示例，不包含真实配置。</p>
""")

# HTML 诱饵：正文里出现 SQL 关键字，但整体是 HTML —— 不应被判为数据库备份
DECOY_SQL_HTML = html("开发手册", """
<h1>开发手册</h1>
<p>建表语句示例：</p>
<pre>CREATE TABLE users (id INT, name TEXT);
INSERT INTO users VALUES (1, 'demo');</pre>
""")

# HTML 诱饵：JSON 形态但整体是 HTML —— 不应被判为配置文件泄露
DECOY_CONFIG_JSON = html("接口说明", """
<h1>接口说明</h1>
<p>示例响应（节选）：</p>
<pre>{ "db": { "DB_PASSWORD": "示例值", "DB_HOST": "127.0.0.1" } }</pre>
""")


class LevelHandler(http.server.BaseHTTPRequestHandler):
    server_version = "DemoTarget/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    LEVEL = 0

    def log_message(self, fmt, *args):
        sys.stdout.write("[L%s %s] %s\n" % (self.LEVEL, self.log_date_time_string(), fmt % args))
        sys.stdout.flush()

    def _sec_headers(self):
        # L0 与 L2~L6 带齐安全头；L1 故意缺失（可修复），用于弱配置演示
        if self.LEVEL == 1 and not STATE["headers_l1_fixed"]:
            return []
        return [
            ("Content-Security-Policy", "default-src 'self'"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "SAMEORIGIN"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Permissions-Policy", "geolocation=()"),
        ]

    def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in self._sec_headers():
            self.send_header(k, v)
        if headers:
            for k, v in headers:
                self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self._send(405, "method not allowed", "text/plain; charset=utf-8")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path.startswith("/__ctl/"):
            if (qs.get("token", [""])[0]) != TOKEN:
                self._send(403, "forbidden: token=demo required", "text/plain; charset=utf-8")
                return
            self._ctl(path, qs)
            return

        common = {"/": level_home(self.LEVEL), "/about/": ABOUT, "/contact/": CONTACT}
        if path in common:
            self._send(200, common[path])
            return

        fn = getattr(self, "_level_%d" % self.LEVEL, None)
        if fn is not None and fn(path, qs):
            return

        self._send(200, SOFT404)

    # ---------- 各关 ----------
    def _level_0(self, path, qs):
        return False  # L0 只有正常页 + 软 404

    def _level_1(self, path, qs):
        if path == "/.env":
            if STATE["l1_env_fixed"]:
                self._send(404, SOFT404)
            else:
                self._send(200, ENV_BODY, "text/plain; charset=utf-8")
            return True
        if path == "/backup.sql":
            self._send(200, SQL_DUMP, "application/sql")
            return True
        if path == "/phpinfo.php":
            self._send(200, PHPINFO)
            return True
        return False

    def _level_2(self, path, qs):
        if path == "/portal/.env":
            if STATE["l2_env_fixed"]:
                self._send(404, SOFT404)
            else:
                self._send(200, ENV_BODY, "text/plain; charset=utf-8")
            return True
        if path == "/uploads/":
            if STATE["l2_dirlist_fixed"]:
                self._send(404, SOFT404)
            else:
                self._send(200, UPLOADS_LISTING)
            return True
        if path == "/error.log":
            self._send(200, LOG_BODY, "text/plain; charset=utf-8")
            return True
        if path in ("/admin/", "/admin/login"):
            cookie = ("SESSIONID=demo123; Path=/; HttpOnly; SameSite=Lax"
                      if STATE["l2_cookie_fixed"] else "SESSIONID=demo123; Path=/")
            self._send(200, LOGIN, headers=[("Set-Cookie", cookie)])
            return True
        return False  # /secret/ 等未知路径 → 软 404 诱饵

    def _level_3(self, path, qs):
        if path in ("/article", "/article.php"):
            self._send(200, self._article(qs))
            return True
        return False

    def _level_4(self, path, qs):
        if path == "/news/":
            self._send(200, NEWS_SAFE if STATE["l4_links_fixed"] else NEWS_BAD)
            return True
        if path == "/portal/":
            self._send(200, PORTAL_TAMPERED if STATE["l4_tamper"] else PORTAL_NORMAL)
            return True
        return False

    def _level_5(self, path, qs):
        if path == "/site.tar.gz":
            if STATE["l5_archive_fixed"]:
                self._send(404, SOFT404)
            else:
                self._send(200, b"PK\x03\x04" + b"\x00" * 600, "application/zip")
            return True
        if path == "/.git/HEAD":
            if STATE["l5_git_fixed"]:
                self._send(404, SOFT404)
            else:
                self._send(200, GIT_HEAD, "text/plain; charset=utf-8")
            return True
        if path == "/debug.log":
            self._send(200, LOG_BODY, "text/plain; charset=utf-8")
            return True
        if path == "/.env.save":
            self._send(200, DECOY_ENV_HTML)  # 诱饵：内容像配置，但整体是 HTML
            return True
        if path == "/news/":
            self._send(200, NEWS_RELATIVE)
            return True
        return False

    def _level_6(self, path, qs):
        if path == "/.env.save":
            if STATE["l6_envsave_fixed"]:
                self._send(404, SOFT404)
            else:
                self._send(200, ENV_BODY, "text/plain; charset=utf-8")
            return True
        if path == "/info.php":
            self._send(200, PHPINFO)
            return True
        if path == "/private.key":
            if STATE["l6_key_fixed"]:
                self._send(404, SOFT404)
            else:
                self._send(200, PRIVATE_KEY, "text/plain; charset=utf-8")
            return True
        if path == "/config.json":
            self._send(200, DECOY_CONFIG_JSON)  # 诱饵：JSON 片段出现在 HTML 里
            return True
        if path == "/db.sql":
            self._send(200, DECOY_SQL_HTML)  # 诱饵：SQL 关键字出现在 HTML 里
            return True
        return False

    def _article(self, qs):
        val = qs.get("id", [""])[0] or ""
        up = val.upper()
        if STATE["l3_sqli_fixed"]:
            return ARTICLE_OK if val == "1" else ARTICLE_MISS
        has_quote = ("'" in val) or ('"' in val)
        if has_quote and "AND" not in up:
            return SQL_ERROR
        if ("AND 1=1" in up) or ("AND '1'='1" in up):
            return ARTICLE_OK
        if ("AND 1=2" in up) or ("AND '1'='2" in up):
            return ARTICLE_MISS
        if val == "1":
            return ARTICLE_OK
        return ARTICLE_MISS

    # ---------- 控制接口 ----------
    def _ctl(self, path, qs):
        if path == "/__ctl/status":
            self._send(200, json.dumps(STATE, ensure_ascii=False, indent=2),
                       "application/json; charset=utf-8")
            return
        if path == "/__ctl/tamper":
            STATE["l4_tamper"] = (qs.get("on", ["0"])[0] == "1")
            self._send(200, "tamper=%s" % STATE["l4_tamper"], "text/plain; charset=utf-8")
            return
        if path == "/__ctl/fix":
            item = qs.get("item", [""])[0]
            mapping = {
                "headers_l1": "headers_l1_fixed",
                "l1_env": "l1_env_fixed",
                "l2_env": "l2_env_fixed",
                "l2_dirlist": "l2_dirlist_fixed",
                "l2_cookie": "l2_cookie_fixed",
                "l3_sqli": "l3_sqli_fixed",
                "l4_links": "l4_links_fixed",
                "l5_archive": "l5_archive_fixed",
                "l5_git": "l5_git_fixed",
                "l6_envsave": "l6_envsave_fixed",
                "l6_key": "l6_key_fixed",
            }
            if item in mapping:
                STATE[mapping[item]] = True
                self._send(200, "fixed=%s" % item, "text/plain; charset=utf-8")
            else:
                self._send(400, "unknown item: " + item, "text/plain; charset=utf-8")
            return
        if path == "/__ctl/reset":
            for k in STATE:
                STATE[k] = False
            self._send(200, "reset ok", "text/plain; charset=utf-8")
            return
        self._send(404, "unknown ctl", "text/plain; charset=utf-8")


def make_handler(level):
    return type("Handler_L%d" % level, (LevelHandler,), {"LEVEL": level})


def main():
    base = None
    if len(sys.argv) > 1:
        try:
            base = int(sys.argv[1])
        except ValueError:
            pass
    servers = []
    for level, port in LEVEL_PORTS.items():
        # 带参数时把它当作"起始端口"(L0 = 起始端口，L1 = 起始端口 + 1)；
        # 不带参数时用默认的 8890-8896。
        actual = (base + level) if base is not None else port
        srv = socketserver.ThreadingTCPServer((HOST, actual), make_handler(level))
        srv.daemon_threads = True
        servers.append((level, actual, srv))
        print("L%d 已启动: http://%s:%d/" % (level, HOST, actual))
    l1_port = next(actual for level, actual, _ in servers if level == 1)
    print("控制接口示例: http://%s:%d/__ctl/status?token=demo" % (HOST, l1_port))
    threads = []
    for level, actual, srv in servers:
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        threads.append(t)
    try:
        while True:
            for t in threads:
                t.join(0.5)
    except KeyboardInterrupt:
        print("\n已停止")
        for level, actual, srv in servers:
            srv.shutdown()


if __name__ == "__main__":
    main()
