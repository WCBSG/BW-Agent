<?php
/**
 * 内容页加载器
 * ------------------------------------------------------------------
 * 【这道题考什么】
 *   本地文件包含（LFI / Local File Inclusion），并且**可升级为 RCE**。
 *
 *   漏洞成因：把用户传的参数直接交给 include，
 *   既没限定目录，也没限定后缀。
 *
 *   危害分三层，正好对应检测方的三种深度：
 *
 *     ① 读源码     p=./pages/about            正常功能
 *     ② 读任意文件 p=../../../php.ini         拿到配置（LFI）
 *     ③ 执行代码   p=../../../uploads/x.php   配合 L2 的上传点 = RCE
 *
 *   第 ③ 层是"漏洞组合"的典型例子：
 *   单看上传点只是"能传文件"，单看包含点只是"能读文件"，
 *   合起来就是完整接管。这也是 L4→L6 想考的"链路思维"的前置训练。
 *
 * 【触发方式】
 *   正常： /l4/tools/page.php?p=about
 *   LFI：  /l4/tools/page.php?p=../../../php.ini
 *   LFI：  /l4/tools/page.php?p=../../../levels/l1_open.py
 *
 * 【修复建议】
 *   用白名单映射（p=about → pages/about.php），
 *   绝不要把用户输入交给 include/require。
 */

$page = isset($_GET['p']) ? $_GET['p'] : 'about';

// 常规入口：在 pages/ 目录下按名字找
$candidate = __DIR__ . '/pages/' . $page . '.php';

if (is_file($candidate)) {
    $resolved = $candidate;
} else {
    // ↓↓↓ 漏洞在这里：找不到就**直接拿用户输入去 include**
    //     （注释还写得很合理："兼容旧版调用方式"）
    $resolved = $page;
}

ob_start();
$include_error = '';
if ($resolved !== '') {
    // 关闭警告以免页面被警告刷屏，但包含行为照旧
    $old = error_reporting(E_ALL & ~E_WARNING);
    include($resolved);
    error_reporting($old);
}
$content = ob_get_clean();

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
?><!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>政务服务 · 内容页</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header><div class="wrap"><h1>某某市政务服务网</h1></div></header>
<main class="wrap">
<?php echo $content; ?>
  <hr>
  <p class="tiny">
    调试信息：requested=<code><?php echo h($page); ?></code>　
    resolved=<code><?php echo h($resolved); ?></code>　
    docroot=<code><?php echo h($_SERVER['DOCUMENT_ROOT']); ?></code>
  </p>
  <p><a href="/l4/">返回首页</a></p>
</main>
<footer><div class="wrap">
  <p>某某市政务服务与大数据管理局 · 信息中心</p>
  <p class="tiny">本站为安全巡检训练靶场，页面内容与数据均为编造的测试数据。</p>
</div></footer>
</body>
</html>
