<?php
/**
 * 附件下载
 * ------------------------------------------------------------------
 * 【这道题考什么】
 *   任意文件读取（目录穿越 / Path Traversal）。
 *
 *   漏洞成因：把用户传入的文件名**直接拼进路径**，没有任何约束。
 *   攻击者用 ../ 就能跳出 files 目录，读到服务器上的任意文件
 *   （配置、源码、系统文件）。
 *
 *   注意：这道题不是"猜文件名"，而是要**构造参数**。
 *   顺手抓一遍页面是发现不了的 —— 这正是它比 L1 其它考点难一点的地方。
 *
 * 【触发方式】
 *   正常： /l1/files/download.php?f=notice.txt
 *   穿越： /l1/files/download.php?f=../../../php.ini
 *          /l1/files/download.php?f=../../../levels/l3_evasive.py
 *
 * 【为什么必须真 PHP】
 *   要真的去读文件系统，才能表现"同一段代码能读到不同深度的文件"。
 *
 * 【修复建议】
 *   只用 basename() 取文件名，再与白名单比对；或改为用文件 ID 查表。
 */
$name = isset($_GET['f']) ? $_GET['f'] : 'notice.txt';

// ↓↓↓ 漏洞就在这里：没有 basename()，没有白名单，直接拼接
$path = __DIR__ . '/' . $name;

if (!is_file($path)) {
    http_response_code(404);
    header('Content-Type: text/html; charset=utf-8');
    echo "<h1>404 附件不存在</h1>";
    echo "<p>请求的文件：<code>" . htmlspecialchars($name) . "</code></p>";
    echo "<p><a href=\"/l1/\">返回首页</a></p>";
    exit;
}

header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . basename($path) . '"');
header('Content-Length: ' . filesize($path));
header('X-Resolved-Path: ' . $path);   // ← 顺手把解析出的真实路径也泄了

readfile($path);
