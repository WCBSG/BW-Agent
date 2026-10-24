#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
PHP 运行时（让靶场能跑真 PHP）
==================================================================

══════════════════════════════════════════════════════════════════
为什么靶场需要真 PHP？
══════════════════════════════════════════════════════════════════

因为最有价值的一批漏洞**只有真代码才能复现**：

    漏洞类型            用假页面能模拟吗？        为什么
    ──────────────────  ────────────────────────  ────────────────────────────
    phpinfo() 信息泄露  不行                      它的价值就在于"真实的"
                                                   PHP 版本 / 加载模块 / ini 路径
                                                   / 绝对路径 —— 编不出来
    目录穿越           不行                      真实读文件，读到什么就是什么
    无限文件上传        不行                      要真落盘，才能验证"上传的后门
                                                   真的能被访问"
    SQL 注入报错        勉强                      真 mysqli 报错含真实驱动版本
    混淆 WebShell       不行                      要真能被 PHP 解析执行，
                                                   否则只是个"看起来像"的字符串

所以靶场接入 PHP：**装了就用，没装也能跑**——
`PHP_AVAILABLE` 为 False 时，请求 .php 会拿到一个说明性的
503 页面，而不是让整个靶场崩掉。这和赛题里的"两层设计"是同一个思路。

══════════════════════════════════════════════════════════════════
怎么跑的？—— CGI 协议
══════════════════════════════════════════════════════════════════

PHP 的官方 CGI 程序是 `php-cgi.exe`。它不监听端口，
而是**从环境变量读请求、往标准输出写响应**：

    环境变量（我们设）                      php-cgi 读它干什么
    ─────────────────────────────────────  ────────────────────────────────
    REQUEST_METHOD=GET                     $_SERVER['REQUEST_METHOD']
    QUERY_STRING=a=1&b=2                   $_GET
    SCRIPT_FILENAME=<绝对路径>             要执行哪个文件
    SCRIPT_NAME=/l1/phpinfo.php            $_SERVER['SCRIPT_NAME']
    DOCUMENT_ROOT=<站点根>                 文件路径解析基准
    HTTP_HOST / HTTP_USER_AGENT / ...      所有 HTTP_* → $_SERVER
    CONTENT_TYPE / CONTENT_LENGTH          POST 请求体
    REDIRECT_STATUS=1                      安全开关（cgi.force_redirect）

标准输出格式（CGI 规范）：
    状态行(可选) + 响应头 + 空行 + 响应体
    例如：
        Status: 404 Not Found
        Content-Type: text/html; charset=utf-8

        <html>...
==================================================================
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

# ------------------------------------------------------------------
# 1. 定位 PHP
# ------------------------------------------------------------------

# 候选路径：按优先级排。第一个是用户本机的实际安装位置。
PHP_CANDIDATES = (
    Path(r"C:\Program Files\.tool\php-8.5.10"),
    Path(r"C:\Program Files\.tool\php"),
    Path(r"C:\php"),
    Path(r"C:\xampp\php"),
    Path(r"C:\wamp64\bin\php"),
    Path("/usr/bin"),
    Path("/usr/local/bin"),
)

_PHP_EXE = None
PHP_AVAILABLE = False
PHP_VERSION = ""


def _find_php():
    """找 php-cgi（优先）或 php。返回可执行文件路径或 None。"""
    for base in PHP_CANDIDATES:
        if not base.is_dir():
            continue
        for name in ("php-cgi.exe", "php-cgi", "php.exe", "php"):
            exe = base / name
            if exe.is_file():
                return exe
    # 最后试试 PATH
    for name in ("php-cgi", "php"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def _probe():
    global _PHP_EXE, PHP_AVAILABLE, PHP_VERSION
    exe = _find_php()
    if exe is None:
        return
    try:
        out = subprocess.run([str(exe), "-v"], capture_output=True, timeout=15,
                             text=True, encoding="utf-8", errors="replace")
        first = (out.stdout or out.stderr or "").splitlines()
        if first:
            PHP_VERSION = first[0].strip()
            _PHP_EXE = exe
            PHP_AVAILABLE = True
    except (OSError, subprocess.SubprocessError):
        pass


_probe()


# ------------------------------------------------------------------
# 2. php.ini
# ------------------------------------------------------------------

PHP_INI = r""";; ==========================================================
;; 靶场专用 php.ini
;; ==========================================================
;; 说明：刻意打开 display_errors —— 因为靶场要模拟
;; "生产环境忘了关调试" 这个最常见的问题。
;; 真实站点这么做就是漏洞，在这里是考点。
;; ==========================================================

; --- CGI 必需 ---
cgi.force_redirect = 0
cgi.fix_pathinfo = 1
cgi.rfc2616_headers = 0

; --- 报错：全开，为了演示报错信息泄漏 ---
display_errors = On
display_startup_errors = On
error_reporting = E_ALL
log_errors = Off

; --- 信息暴露 ---
expose_php = On

; --- 会话 ---
session.save_path = ""
session.use_cookies = 1
session.cookie_httponly = 0

; --- 上传：不做任何限制（靶场考点）---
file_uploads = On
upload_max_filesize = 64M
post_max_size = 64M

; --- 时区 ---
date.timezone = Asia/Shanghai
"""


def ensure_ini(ini_path):
    """把 php.ini 写到指定位置（不存在才写）。"""
    ini_path = Path(ini_path)
    if not ini_path.exists():
        ini_path.parent.mkdir(parents=True, exist_ok=True)
        ini_path.write_text(PHP_INI, encoding="utf-8")
    return ini_path


# ------------------------------------------------------------------
# 3. 执行
# ------------------------------------------------------------------

DEFAULT_TIMEOUT = 20


def run_php(script_path, ctx, doc_root, ini_path=None, timeout=DEFAULT_TIMEOUT):
    """
    用 php-cgi 执行一个 .php 文件，返回 (状态码, 响应头 dict, 响应体 bytes)。

    参数：
        script_path  要执行的 .php 文件（绝对路径）
        ctx          请求上下文（提供 method / query / headers / body 等）
        doc_root     DOCUMENT_ROOT
        ini_path     指定 php.ini（不传则用 -n 不加载任何 ini）
        timeout      超时秒数，防止脚本卡死

    异常情况不抛出，一律返回合适的错误响应，保证靶场不崩。
    """
    if not PHP_AVAILABLE:
        return 503, {"content-type": "text/html; charset=utf-8"}, (
            "<h1>503 - PHP 运行时不可用</h1>"
            "<p>本关卡的动态页面需要 PHP，但未能找到 php-cgi 可执行文件。</p>"
            "<p>靶场的其它关卡不受影响。</p>"
        ).encode("utf-8")

    script_path = Path(script_path)
    body = ctx.body or b""

    env = os.environ.copy()
    env.update({
        "REDIRECT_STATUS": "1",                 # cgi.force_redirect 的安全开关
        "GATEWAY_INTERFACE": "CGI/1.1",
        "SERVER_SOFTWARE": ctx.level.get("banner", "Apache"),
        "SERVER_PROTOCOL": "HTTP/1.1",
        "REQUEST_METHOD": ctx.method,
        "REQUEST_URI": ctx.full_path,
        "SCRIPT_NAME": ctx.full_path,
        "SCRIPT_FILENAME": str(script_path),
        "PATH_TRANSLATED": str(script_path),
        "DOCUMENT_ROOT": str(doc_root),
        "QUERY_STRING": _raw_query(ctx),
        "SERVER_NAME": (ctx.header("host") or "localhost").split(":")[0],
        "SERVER_PORT": str(ctx.server_port),
        "REMOTE_ADDR": ctx.client or "127.0.0.1",
        "REMOTE_HOST": ctx.client or "127.0.0.1",
        "CONTENT_TYPE": ctx.header("content-type"),
        "CONTENT_LENGTH": str(len(body)) if body else "",
        "SERVER_ADMIN": "admin@zwfw.gov.cn",
        "SCRIPT_URI": f"http://{ctx.header('host')}{ctx.full_path}",
    })

    # 所有请求头 → HTTP_XXX（CGI 规范）
    for key, value in ctx.headers.items():
        env["HTTP_" + key.upper().replace("-", "_")] = value

    cmd = [str(_PHP_EXE)]
    if ini_path:
        cmd += ["-c", str(ini_path)]
    else:
        cmd += ["-n"]
    cmd.append(str(script_path))

    try:
        proc = subprocess.run(
            cmd, input=body, capture_output=True,
            timeout=timeout, cwd=str(doc_root), env=env,
        )
    except subprocess.TimeoutExpired:
        return 504, {"content-type": "text/html; charset=utf-8"}, (
            "<h1>504 - PHP 脚本执行超时</h1>").encode("utf-8")
    except OSError as exc:
        return 500, {"content-type": "text/html; charset=utf-8"}, (
            f"<h1>500 - 无法启动 PHP</h1><pre>{exc}</pre>").encode("utf-8")

    stdout = proc.stdout or b""
    # 有些错误会写到 stderr，补到响应体里便于排查
    stderr = proc.stderr or b""

    status, headers, payload = parse_cgi_output(stdout)
    if stderr and b"Content-Type" not in stdout[:200]:
        payload += b"\n<!-- php stderr -->\n<pre>" + _escape_bytes(stderr) + b"</pre>"
    return status, headers, payload


def _raw_query(ctx):
    """重建原始查询串（PHP 的 $_GET 从 QUERY_STRING 解析）。"""
    from urllib.parse import urlencode
    pairs = []
    for key, values in (ctx.query_all or {}).items():
        if isinstance(values, (list, tuple)):
            for v in values:
                pairs.append((key, v))
        else:
            pairs.append((key, values))
    return urlencode(pairs)


def _escape_bytes(data):
    return (data.replace(b"&", b"&amp;").replace(b"<", b"&lt;")
            .replace(b">", b"&gt;"))


def parse_cgi_output(raw):
    """
    拆解 CGI 输出：状态行 + 响应头 + 空行 + 响应体。

    为什么这么麻烦？因为 CGI 的响应头是以 **\\r\\n\\r\\n** 或 **\\n\\n**
    结束的，而 PHP 可能只给部分头（比如只给 Content-Type）。
    所以这里要宽容处理，任何一步失败都要给出可用的兜底结果。
    """
    status = 200
    headers = {}
    payload = raw

    # 找出"头/体"分界
    split_at = -1
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            split_at, sep_len = idx, len(sep)
            break

    if split_at == -1:
        # 没有空行 → 整个都当体（PHP 直接 output 了内容）
        return 200, {"content-type": "text/html; charset=utf-8"}, raw

    head_blob = raw[:split_at].decode("utf-8", "replace")
    payload = raw[split_at + sep_len:]

    for line in head_blob.splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip().lower()
        value = value.strip()
        if name == "status":
            # "404 Not Found" → 404
            digits = "".join(ch for ch in value.split(" ")[0] if ch.isdigit())
            if digits:
                status = int(digits)
        elif name == "location":
            headers["Location"] = value
        else:
            headers[name] = value

    if "content-type" not in headers:
        headers["content-type"] = "text/html; charset=utf-8"
    return status, headers, payload


def info():
    """给启动横幅用的一行说明。"""
    if PHP_AVAILABLE:
        return f"PHP 可用：{_PHP_EXE}"
    return "PHP 不可用（动态页面将返回 503）"


def status():
    return {
        "available": PHP_AVAILABLE,
        "exe": str(_PHP_EXE) if _PHP_EXE else "",
        "version": PHP_VERSION,
    }


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    print()
    print("  PHP 运行时自检")
    print("  " + "-" * 60)
    data = status()
    print(f"  可用   ：{data['available']}")
    print(f"  解释器 ：{data['exe'] or '（未找到）'}")
    print(f"  版本   ：{data['version'] or '-'}")
    print("  " + "-" * 60)
    if not data["available"]:
        print("  提示：把 PHP 放到下列任一目录即可自动识别：")
        for p in PHP_CANDIDATES:
            print(f"    {p}")
    print()
