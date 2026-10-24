#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
分级靶场服务器（零依赖）
==================================================================

这是一个**专供安全巡检训练与检测能力评测**的本地靶场。
它把「网站安全」里常见的问题按**难度从易到难**分成 6 个关卡，
每关刻意种入若干处问题，供巡检工具或人工测试者去发现。

──────────────────────────────────────────────────────────────────
为什么不直接用 `python -m http.server`？
──────────────────────────────────────────────────────────────────
因为静态文件服务器**表达不了真实世界的一半问题**：

    想要的效果                          静态服务器能做到吗
    ─────────────────────────────────  ──────────────────
    某个路径不存在却返回 200（软 404）      ✗
    同一个 URL，换个 UA 就返回不同内容      ✗
    只有带对 Referer 才吐敏感数据           ✗
    给错误参数就回显异常堆栈                ✗
    只对特定响应附加（或伪造）安全响应头     ✗
    让 PUT / DELETE 方法"开着"             ✗
    目录列表要特定请求头才给                ✗
    非标准扩展名的备份文件                  ✓（但无内容特征校验价值）

所以本靶场自己实现了 HTTP 层。核心思路是：
**每个关卡 = 一份元数据（LEVEL）+ 一张路由表（ROUTES）**，
核心负责按关卡注入响应头、决定方法白名单、处理软 404、记录访问日志。

──────────────────────────────────────────────────────────────────
目录结构
──────────────────────────────────────────────────────────────────
    serve.py            本文件：HTTP 核心（路由 / 静态 / 软404 / 日志）
    levels/             6 个关卡的实现，每关一个模块
    static/             各关卡的"落地文件"（.git、.env、db.sql、图片等）
    static/index.html   靶场门户（关卡导航）
    logs/access.log     访问日志（谁在什么时候探测了什么）
    关卡设计.md          考点清单与答案（**评测方参考资料**）

──────────────────────────────────────────────────────────────────
使用
──────────────────────────────────────────────────────────────────
    启动：      py serve.py
    换端口：    py serve.py --port 9000
    列关卡：    py serve.py --list
    只开某几关：py serve.py --only l1,l2

默认监听 0.0.0.0:8081，同一局域网的其它设备可直接访问。

──────────────────────────────────────────────────────────────────
合规声明
──────────────────────────────────────────────────────────────────
    本靶场为**自有、离线、训练用途**，所有数据均为编造的测试数据。
    请仅在自己拥有或已获授权的环境中使用。
==================================================================
"""

import argparse
import datetime as _dt
import json
import mimetypes
import os
import re
import socket
import sys
import threading
import traceback
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# ------------------------------------------------------------------
# 路径与全局常量
# ------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "access.log"

# 让 `from levels import REGISTRY` 在直接运行本文件时也能工作
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# 公共工具箱：转义、页面骨架、目录列表、假数据（各关卡也用它）
from rangekit import (  # noqa: E402
    directory_listing as listing_html,
    esc,
    page as html_page,
)

# PHP 运行时（装了 PHP 才能跑真 .php；没装不影响其它功能）
import php_runtime  # noqa: E402

# 靶场专用的 php.ini（刻意打开 display_errors，模拟"生产忘关调试"）
PHP_INI_PATH = php_runtime.ensure_ini(BASE_DIR / "php.ini")

# 默认不泄漏 Python 信息 —— 真实站点也不会告诉你后端是 Python
DEFAULT_BANNER = "Apache"

# 单次请求最多读多少字节（防止被超大请求体拖死）。
# 取 16MB：够 L2 的上传考点用（php.ini 里 upload_max_filesize 是 64M，
# 但靶场不需要真的允许那么大 —— 能验证"无限制上传"这个行为就够）
MAX_BODY = 16 * 1024 * 1024


# ------------------------------------------------------------------
# 第 1 节：数据结构
# ------------------------------------------------------------------

@dataclass
class Ctx:
    """一次请求的全部上下文，关卡处理函数只需要看这个对象。"""

    method: str                     # GET / POST / PUT ...
    path: str                       # **去掉关卡前缀后**的路径，如 /files/db.sql
    full_path: str                  # 完整请求路径，如 /l1/files/db.sql
    query: dict                     # 查询参数（同名取第一个）
    query_all: dict                 # 查询参数（同名保留全部）
    headers: dict                   # 请求头，键统一小写
    body: bytes                     # 请求体（只读用途，不需要时为空）
    level: dict                     # 当前关卡的 LEVEL 元数据
    client: str                     # 客户端地址
    server_port: int

    def header(self, name, default=""):
        return self.headers.get(name.lower(), default)

    def q(self, name, default=""):
        return self.query.get(name, default)

    def is_mobile_ua(self):
        ua = self.header("user-agent").lower()
        return any(k in ua for k in ("iphone", "android", "mobile", "ipad"))

    def is_bot_ua(self):
        ua = self.header("user-agent").lower()
        return any(k in ua for k in ("bot", "crawler", "spider", "scanner", "nuclei", "sentinel"))


@dataclass
class Reply:
    """一次响应的全部内容。"""

    status: int = 200
    body: object = b""
    content_type: str = "text/html; charset=utf-8"
    headers: dict = field(default_factory=dict)
    # 仅供日志使用的标注（如 autoindex-on / soft-404）。
    # ⚠ 绝不能写进响应头 —— 那等于把考点直接告诉测试者。
    note: str = ""

    def payload(self):
        if isinstance(self.body, str):
            return self.body.encode("utf-8")
        return self.body or b""


# 常见状态码的默认说明
STATUS_TEXT = {
    200: "OK", 201: "Created", 204: "No Content",
    301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 418: "I'm a teapot",
    500: "Internal Server Error", 501: "Not Implemented", 503: "Service Unavailable",
}


def safe_header_value(value):
    """
    把响应头值规整成 HTTP 能安全传输的形式。

    为什么需要这个？—— HTTP 头按规范只能是 latin-1，
    但靶场里 PHP 会把带中文的**绝对路径**写进响应头
    （如 `X-Resolved-Path: C:\\Temp\\网络安全\\...`）。
    如果直接 send_header，http.server 会用 latin-1 编码而抛
    UnicodeEncodeError，结果**整个连接被中断**，请求方只看到连接错误。

    处理策略：能 latin-1 就原样发；不能就百分号编码 ——
    这样"路径泄露"这个考点还在，连接又不会崩。真实服务器也正是
    这么做的（RFC 3986 / RFC 8187）。
    """
    text_value = str(value)
    try:
        text_value.encode("latin-1")
        return text_value
    except UnicodeEncodeError:
        return urllib.parse.quote(text_value, safe="")


# ------------------------------------------------------------------
# 第 3 节：HTTP 请求处理器
# ------------------------------------------------------------------

class RangeHandler(BaseHTTPRequestHandler):
    """
    靶场的 HTTP 入口。

    职责划分：
        do_GET / do_HEAD / do_OPTIONS / do_PUT / do_DELETE ...  → 统一交给 dispatch
        dispatch()                                             → 找关卡 → 路由 → 静态 → 软404
    """

    server_version = DEFAULT_BANNER
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # 每请求重置，防止线程间串味
    _banner = None

    # ---- 让 Server 响应头可以按关卡伪造 ----
    def version_string(self):
        return self._banner or DEFAULT_BANNER

    # ---- 1xx/2xx/3xx/4xx/5xx 都走这个开关 ----
    def do_GET(self):
        self.dispatch("GET")

    def do_HEAD(self):
        self.dispatch("HEAD")

    def do_OPTIONS(self):
        self.dispatch("OPTIONS")

    def do_POST(self):
        self.dispatch("POST")

    def do_PUT(self):
        self.dispatch("PUT")

    def do_DELETE(self):
        self.dispatch("DELETE")

    def do_TRACE(self):
        self.dispatch("TRACE")

    def do_PATCH(self):
        self.dispatch("PATCH")

    # ---- 日志：默认打一份到控制台，同时写文件 ----
    def log_message(self, fmt, *args):
        return  # 关掉 stderr 的默认噪声，改用我们自己的格式

    def log_error(self, fmt, *args):
        return

    # ==============================================================
    # 主分发流程
    # ==============================================================
    def dispatch(self, method):
        self._banner = None
        body = b""
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length > 0:
                body = self.rfile.read(min(length, MAX_BODY))

        parsed = urllib.parse.urlsplit(self.path)
        raw_path = urllib.parse.unquote(parsed.path)
        # 归一化：折叠重复斜杠，防止 //l1// 之类绕过
        path = re.sub(r"/{2,}", "/", raw_path)
        query_all = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        query = {k: v[0] for k, v in query_all.items()}

        ctx = Ctx(
            method=method,
            path=path,
            full_path=path,
            query=query,
            query_all=query_all,
            headers={k.lower(): v for k, v in self.headers.items()},
            body=body,
            level={},
            client=self.client_address[0] if self.client_address else "?",
            server_port=self.server.server_address[1],
        )

        try:
            reply = self.resolve(ctx, path)
        except Exception:
            # 靶场自己出错时不要静默 —— 回显堆栈（便于开发时排查）
            tb = traceback.format_exc()
            reply = Reply(500, f"<h1>500 Internal Server Error</h1>"
                               f"<p>靶场内部异常（仅调试用）：</p>"
                               f"<pre>{esc(tb)}</pre>")

        self.write_reply(reply, method, ctx)

    # --------------------------------------------------------------
    def resolve(self, ctx, path):
        """把请求路径映射成一个 Reply。"""
        # ---- 全局路由（门户）----
        if path in ("/", "/index.html"):
            self._banner = DEFAULT_BANNER
            return self.serve_static_file(STATIC_DIR / "index.html", ctx)

        # ---- 关卡路由 ----
        level, sub = match_level(path)
        if level is not None:
            ctx.level = level
            ctx.path = sub
            self._banner = level.get("banner", DEFAULT_BANNER)
            return self.handle_level(level, ctx, sub)

        # ---- 其它全局文件（style.css 等）----
        if path.startswith("/style.css"):
            return self.serve_static_file(STATIC_DIR / "style.css", ctx)

        # ---- 其它一律 404 ----
        return Reply(404, html_page("404 - 页面不存在",
                                    "<h2>404</h2><p>请求的页面不存在。</p>"),
                     note="root-404")

    # --------------------------------------------------------------
    def handle_level(self, level, ctx, sub):
        """关卡内部的处理：接管函数 → 路由表 → 静态文件 → 404/软404。"""
        # 方法白名单
        allowed = set(level.get("methods", ("GET", "HEAD", "OPTIONS")))
        method = ctx.method
        if method not in allowed:
            return Reply(
                405,
                html_page("405 - 方法不被允许",
                          f"<h2>405 Method Not Allowed</h2>"
                          f"<p>该关卡不允许 <code>{esc(method)}</code> 方法。</p>"
                          f"<p>允许：<code>{', '.join(sorted(allowed))}</code></p>"),
                headers={"Allow": ", ".join(sorted(allowed))},
            )

        # 关卡自定义的"完全接管"钩子（保留的扩展点）
        takeover = level.get("handle")
        if callable(takeover):
            reply = takeover(ctx)
            if reply is not None:
                return self.apply_level_headers(reply, level)

        # 路由表：按声明顺序匹配，先到先得
        for rule_method, pattern, func in level.get("routes", ()):
            if rule_method != "*" and rule_method != method:
                continue
            m = re.match(pattern, sub)
            if m:
                reply = func(ctx, m)
                if reply is not None:
                    return self.apply_level_headers(reply, level)

        # 静态文件
        assets = STATIC_DIR / level.get("assets", level["key"])
        target = safe_join(assets, sub)
        if target is not None:
            if target.is_file():
                return self.apply_level_headers(
                    self.serve_static_file(target, ctx), level)
            # 目录：看是否允许列表
            if target.is_dir():
                if not sub.endswith("/"):
                    # 目录没带尾斜杠 → 301 补上（真实服务器行为）
                    return Reply(301, "", headers={"Location": sub + "/"})
                if level.get("autoindex"):
                    return self.apply_level_headers(self.directory_listing(target, ctx), level)
                # 目录存在但列表被关 → 403（要先用请求头触发解锁的关卡在这里返回 None）
                locked = level.get("dir_locked")
                if callable(locked):
                    reply = locked(ctx, target)
                    if reply is not None:
                        return self.apply_level_headers(reply, level)
                return Reply(403, html_page("403 - 禁止访问",
                                            "<h2>403 Forbidden</h2><p>目录列表已关闭。</p>"),
                             note="autoindex-off")

        # 都没命中 → 该关卡的 not_found（可能是软 404）
        return self.not_found(level, ctx, sub)

    # --------------------------------------------------------------
    def not_found(self, level, ctx, sub):
        """404 处理。软 404 的关卡在这里返回 200 + 正常外观的页面。"""
        hook = level.get("not_found")
        if callable(hook):
            reply = hook(ctx, sub)
            if reply is not None:
                return self.apply_level_headers(reply, level)
        return Reply(404, html_page("404 - 页面不存在",
                                    "<h2>404 - 页面不存在</h2>"
                                    "<p>您访问的页面已被移除或从未存在。</p>"),
                     note="level-404")

    # --------------------------------------------------------------
    def apply_level_headers(self, reply, level):
        """
        按关卡注入（或伪造）响应头。

        这是"弱配置"考点的载体：
        · 有的关卡什么安全头都不给
        · 有的给了但值是不安全的（X-Frame-Options: ALLOWALL）
        · 有的给了但形同虚设（CSP: default-src * 'unsafe-inline'）
        """
        for k, v in (level.get("headers") or {}).items():
            reply.headers.setdefault(k, v)
        return reply

    # --------------------------------------------------------------
    def directory_listing(self, dir_path, ctx):
        entries = []
        for entry in sorted(dir_path.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
            if entry.name.startswith(".") and entry.name not in (".git", ".env", ".svn"):
                continue  # 点文件默认不列，但 .git/.env 这类要露出来（那是考点）
            entries.append((entry.name, entry.is_dir()))
        return Reply(200, listing_html(
            ctx.path, entries,
            banner=ctx.level.get("banner", DEFAULT_BANNER),
            host=ctx.header("host"),
            port=ctx.server_port,
        ), note="autoindex-on")

    # --------------------------------------------------------------
    def serve_static_file(self, path, ctx):
        """静态文件。若是 .php，交给 PHP 运行时**真的执行**。"""
        if path.suffix.lower() == ".php":
            return self.run_php(path, ctx)
        try:
            data = path.read_bytes()
        except OSError:
            return Reply(404, html_page("404", "<h2>404</h2>"))
        ctype = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        # 文本类统一补 charset，避免中文乱码
        if ctype.startswith("text/") or ctype in ("application/json", "application/javascript"):
            ctype += "; charset=utf-8"
        return Reply(200, data, content_type=ctype)

    # --------------------------------------------------------------
    def run_php(self, script_path, ctx):
        """
        用 php-cgi 执行一个 .php 文件，把结果转成 Reply。

        注意 DOCUMENT_ROOT 取的是"关卡自己的目录"，这样
        $_SERVER['DOCUMENT_ROOT'] 和相对路径读到的东西都自洽 ——
        目录穿越这类考点要靠它才能表现正确。
        """
        doc_root = STATIC_DIR / ctx.level.get("assets", ctx.level.get("key", "l1"))
        status, headers, payload = php_runtime.run_php(
            script_path, ctx, doc_root, ini_path=PHP_INI_PATH,
        )
        ctype = headers.pop("content-type", "text/html; charset=utf-8")
        # 逐跳响应头（Content-Length / Transfer-Encoding / Connection）
        # 一律丢弃，由我们自己按实际 body 长度重新生成，避免重复或长度不符。
        for hop in ("content-length", "transfer-encoding", "connection", "keep-alive"):
            headers.pop(hop, None)
        note = "php-executed" if php_runtime.PHP_AVAILABLE else "php-unavailable"
        return Reply(status, payload, content_type=ctype, headers=headers, note=note)

    # --------------------------------------------------------------
    def write_reply(self, reply, method, ctx):
        # Server 头在 send_response() 里就会发出去，所以必须**先**定好 banner
        for k, v in list(reply.headers.items()):
            if k.lower() == "server":
                self._banner = v
                del reply.headers[k]
        payload = reply.payload()

        self.send_response(reply.status, STATUS_TEXT.get(reply.status, ""))
        self.send_header("Content-Type", safe_header_value(reply.content_type))
        self.send_header("Content-Length", str(len(payload)))
        for k, v in reply.headers.items():
            self.send_header(safe_header_value(k), safe_header_value(v))
        self.end_headers()

        if method != "HEAD" and payload:
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

        log_access(self.server.server_address[1], ctx, reply, len(payload))
# ------------------------------------------------------------------
# 第 3 节：路径与关卡匹配
# ------------------------------------------------------------------

def safe_join(root, sub):
    """
    把 URL 子路径安全地拼到 root 下。
    返回 None 表示这个路径越界了（../ 逃逸）—— 直接当作不存在。
    """
    parts = [p for p in sub.split("/") if p not in ("", ".", "..")]
    target = root.joinpath(*parts) if parts else root
    try:
        target.relative_to(root)
    except ValueError:
        return None
    return target


def match_level(path):
    """
    判断路径属于哪个关卡。
    /l1/files/db.sql  →  (level1 元数据, "/files/db.sql")
    /                →  (None, None)
    """
    from levels import REGISTRY
    m = re.match(r"^/([A-Za-z0-9_]+)(/.*)?$", path)
    if not m:
        return None, None
    key = m.group(1).lower()
    sub = m.group(2) or "/"
    level = REGISTRY.get(key)
    if level is None:
        return None, None
    return level, sub


# ------------------------------------------------------------------
# 第 4 节：访问日志
# ------------------------------------------------------------------

_LOG_LOCK = threading.Lock()

OUT_OF_SCOPE_LOG = LOG_DIR / "out-of-scope.log"

# 是否抑制**控制台打印**。
# ⚠ 注意：这个开关绝不能影响日志文件的写入。
#   日志文件是审计证据（尤其是越界记录），在任何运行模式下都必须落盘。
#   （早期版本用 `log_access = lambda: None` 来静音，结果把
#     访问日志和越界日志一起关掉了 —— 静音把证据也静掉了，这是错的。）
QUIET = False


def record_violation(ctx, reply):
    """
    记录一次**越界访问**（访问了未授权站点）。

    为什么单独一个文件？
    access.log 是"系统跑了什么"的运行记录；
    out-of-scope.log 是**合规证据** —— 出问题时需要立刻能回答：
        "我们到底碰过哪些没授权的东西？碰了几次？什么时候？"
    混在一起会让这个问题变得难以回答。
    """
    entry = {
        "ts": _dt.datetime.now().isoformat(timespec="seconds"),
        "client": ctx.client,
        "method": ctx.method,
        "path": ctx.full_path,
        "status": reply.status,
        "ua": ctx.header("user-agent"),
        "referer": ctx.header("referer"),
        "verdict": "OUT-OF-SCOPE",
    }
    try:
        LOG_DIR.mkdir(exist_ok=True)
        with _LOG_LOCK:
            with OUT_OF_SCOPE_LOG.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass
    if not QUIET:
        print(f'  \u26a0 越界访问：{entry["client"]} {entry["method"]} {entry["path"]}'
              f'  ← 该目标未在 scope.json 授权范围内')


def log_access(port, ctx, reply, size):
    """
    把每次请求写进 logs/access.log（JSON Lines）。
    靶场保留这份日志的用途：
      · 评测后复盘"测试者/工具到底探测了哪些路径"
      · 证明检测器有没有做目录爆破（合规性证据）
    """
    level = ctx.level or {}
    entry = {
        "ts": _dt.datetime.now().isoformat(timespec="seconds"),
        "client": ctx.client,
        "method": ctx.method,
        "path": ctx.full_path,
        "status": reply.status,
        "size": size,
        "ua": ctx.header("user-agent"),
        "referer": ctx.header("referer"),
        "level": level.get("key", "-"),
        "note": reply.note or "",
    }
    # ★ 越界告警：访问未授权站点是**合规事故**，必须留下独立证据
    if level.get("out_of_scope"):
        record_violation(ctx, reply)
    line = json.dumps(entry, ensure_ascii=False)
    tag = entry["note"] or "-"
    req = f'{entry["method"]:<7} {entry["status"]} {entry["path"]}'
    if not QUIET:
        print(f'  [{entry["client"]}] {req}   [{tag}] {entry["ua"][:48]}')
    try:
        LOG_DIR.mkdir(exist_ok=True)
        with _LOG_LOCK:
            with LOG_FILE.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
    except OSError:
        pass


# ------------------------------------------------------------------
# 第 5 节：服务器与命令行
# ------------------------------------------------------------------

class RangeServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def list_levels():
    from levels import REGISTRY
    print()
    print("  靶场关卡一览")
    print("  " + "-" * 80)
    print(f'  {"编号":<5} {"路径":<8} {"难度":<8} {"名称":<18} 考点')
    print("  " + "-" * 80)
    for key, lv in REGISTRY.items():
        tags = "/".join(lv.get("tags", ()))
        denied = lv.get("kind") == "denied"
        mark = "禁" if denied else f'L{lv["id"]}'
        suffix = "  ← 不应被扫描" if denied else ""
        print(f'  {mark:<5} /{key+"/":<7} {lv.get("difficulty",""):<8} '
              f'{lv.get("name",""):<18} {tags}{suffix}')
    print("  " + "-" * 80)
    print(f'  共 {len(REGISTRY)} 个目标（含 1 个未授权禁区）。详见 关卡设计.md')
    print(f'  授权范围判定： py scope.py --show')
    print()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="分级靶场服务器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例：\n  py serve.py\n  py serve.py --port 9000\n  py serve.py --only l1,l2\n",
    )
    parser.add_argument("--port", type=int, default=8081, help="监听端口（默认 8081）")
    parser.add_argument("--bind", default="0.0.0.0", help="监听地址（默认 0.0.0.0，局域网可访问）")
    parser.add_argument("--only", default="", help="只启用指定关卡，如 l1,l3")
    parser.add_argument("--list", action="store_true", help="列出全部关卡后退出")
    parser.add_argument("--quiet", action="store_true", help="不打印每个请求")
    args = parser.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    import levels
    if args.only:
        keep = {k.strip().lower() for k in args.only.split(",") if k.strip()}
        levels.REGISTRY = {k: v for k, v in levels.REGISTRY.items() if k in keep}
        if not levels.REGISTRY:
            print("[错误] --only 没有匹配到任何关卡，可用：", ", ".join(levels.all_keys()))
            return 2

    if args.list:
        list_levels()
        return 0

    global QUIET
    QUIET = args.quiet

    if args.bind in ("0.0.0.0", "::"):
        ips = local_ips()
    else:
        ips = [args.bind]

    server = RangeServer((args.bind, args.port), RangeHandler)

    print()
    print("  ╔══════════════════════════════════════════════════════════════╗")
    print("  ║        网站安全巡检 · 分级靶场服务器（训练用途）              ║")
    print("  ╚══════════════════════════════════════════════════════════════╝")
    print()
    list_levels()
    print("  访问地址")
    for ip in ips:
        print(f"    http://{ip}:{args.port}/")
    print(f"    http://127.0.0.1:{args.port}/   （本机）")
    print()
    print(f"  ⚠ /l0/ 是未授权禁区。对它的任何访问都会记入：")
    print(f"      {OUT_OF_SCOPE_LOG}")
    print()
    print(f"  访问日志： {LOG_FILE}")
    print("  按 Ctrl+C 停止")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  [i] 靶场已停止。")
    finally:
        server.server_close()
    return 0


def local_ips():
    """列出本机的局域网 IPv4 地址，方便直接给测试者。"""
    ips = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except OSError:
        pass
    if not ips:
        ips = ["<本机IP>"]
    return ips


if __name__ == "__main__":
    sys.exit(main())
