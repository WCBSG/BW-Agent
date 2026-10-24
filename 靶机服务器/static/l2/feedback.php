<?php
/**
 * 意见反馈（留言板）
 * ------------------------------------------------------------------
 * 【这道题考什么】
 *   存储型 XSS。
 *
 *   与 L2/search.html 的**反射型** XSS 形成对照：
 *     · 反射型：脚本立刻回显给提交者自己（危害有限）
 *     · 存储型：脚本被**写进文件持久化**，之后每个访问该页的人
 *               都会执行 —— 这才能偷管理员的 Cookie、伪造操作
 *
 *   所以本页同时是"攻击入口"和"投毒页面"：
 *   提交一次，此后所有访问者都中招。
 *
 * 【触发方式】
 *   1) 提交： POST/GET  msg=<script>alert(document.cookie)</script>
 *   2) 回访： 直接打开 feedback.php —— 之前的留言（含脚本）会原样渲染
 *
 * 【修复建议】
 *   输出时用 htmlspecialchars() 转义；配合 CSP 关闭 inline script。
 */

$STORE = __DIR__ . '/data/feedback.txt';
@mkdir(dirname($STORE), 0777, true);

$posted = false;
if (isset($_REQUEST['msg']) && $_REQUEST['msg'] !== '') {
    // ↓↓↓ 漏洞之一：原始内容直接落盘
    file_put_contents($STORE, $_REQUEST['msg'] . "\n", FILE_APPEND | LOCK_EX);
    $posted = true;
}

// ↓↓↓ 漏洞之二：读取后**不转义**直接拼进 HTML
$entries = [];
if (is_file($STORE)) {
    $lines = file($STORE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $entries = array_reverse($lines);
}

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
?><!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>意见反馈</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header><div class="wrap"><h1>意见反馈</h1></div></header>
<main class="wrap">

  <h2>我要反馈</h2>
  <div class="box">
    <form method="post" action="feedback.php">
      <label>反馈内容
        <textarea name="msg" rows="4" style="width:100%"></textarea>
      </label>
      <button type="submit">提交</button>
    </form>
    <p class="tiny">提交后内容会立即显示在下方留言区。</p>
  </div>

<?php if ($posted): ?>
  <div class="box ok"><h3>提交成功</h3><p>感谢您的反馈，我们会尽快处理。</p></div>
<?php endif; ?>

  <h2>历史留言（共 <?php echo count($entries); ?> 条）</h2>
  <div class="box">
<?php if (!$entries): ?>
    <p class="tiny">（暂无留言）</p>
<?php else: ?>
    <ul>
<?php foreach ($entries as $line): ?>
<?php /* ↓↓↓ 这里本该是 h($line) —— 故意不转义，这就是考点 */ ?>
      <li><?php echo $line; ?></li>
<?php endforeach; ?>
    </ul>
<?php endif; ?>
  </div>

  <p><a href="index.html">返回首页</a></p>
</main>
<footer><div class="wrap">
  <p>某某市政务服务与大数据管理局 · 信息中心</p>
  <p class="tiny">本站为安全巡检训练靶场，页面内容与数据均为编造的测试数据。</p>
</div></footer>
</body>
</html>
