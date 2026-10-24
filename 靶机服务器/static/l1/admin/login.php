<?php
/**
 * 后台登录
 * ------------------------------------------------------------------
 * 【这道题考什么】
 *   ① SQL 注入（字符串拼接 SQL）
 *   ② 报错信息回显 —— 数据库错误里带了**完整 SQL 语句**和真实文件路径
 *   ③ 弱口令（默认口令明文写在页面上）
 *
 * 【为什么"报错回显"值得单列一类】
 *   很多巡检工具只检查"页面里有没有身份证/手机号"，
 *   但**报错信息本身就是泄露**：它把数据库类型、表名、字段名、
 *   程序绝对路径、甚至框架版本全告诉攻击者了。
 *
 *   而且这类问题**必须主动构造参数才会出现** ——
 *   正常访问 login.php 什么都看不到。
 *
 * 【触发方式】
 *   正常： /l1/admin/login.php
 *   SQLi： /l1/admin/login.php?user=admin'&pass=x
 *   SQLi： /l1/admin/login.php?user=admin'--&pass=x
 *
 * 【修复建议】
 *   用参数化查询（prepared statement）；关闭 display_errors；
 *   后台入口加访问控制或限制来源 IP。
 */

// 演示用的"账号表"（真实站点这里会是数据库）
$ACCOUNTS = [
    'admin'        => ['password' => 'Admin@888',   'role' => '超级管理员'],
    'zhangweiming' => ['password' => 'Zwfw@2024',   'role' => '内容编辑'],
    'liyang'       => ['password' => 'Zwfw@2024',   'role' => '只读查看'],
];

$user = isset($_GET['user']) ? $_GET['user'] : '';
$pass = isset($_GET['pass']) ? $_GET['pass'] : '';
$error = '';
$logged_in = null;

if ($user !== '') {
    // ↓↓↓ 漏洞在这里：SQL 用字符串拼接
    $sql = "SELECT * FROM zwfw_account WHERE username = '$user' AND password = '$pass' LIMIT 1";

    // 真实站点会执行这条 SQL。这里做等价模拟：
    // 只要输入里含单引号，就会触发"SQL 语法错误"。
    if (strpos($user, "'") !== false || strpos($pass, "'") !== false) {
        // 模拟数据库驱动抛出的原始错误（含完整 SQL 与真实路径）
        $line = __LINE__ - 4;
        $error = <<<ERR
<h2>Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax;
check the manual that corresponds to your MariaDB server version for the right
syntax to use near '{$user}' AND password = '{$pass}' LIMIT 1' at line 1</h2>
<pre>
Stack trace:
#0 /www/zwfw/admin/login.php({$line}): mysqli_query()
#1 /www/zwfw/lib/db.php(58): db_query()
#2 {__FILE__}({$line}): authenticate()
#3 {main}
  thrown in /www/zwfw/lib/db.php on line 58
</pre>
<pre>SQL: {$sql}</pre>
<pre>DocumentRoot: {$_SERVER['DOCUMENT_ROOT']}
Script:       {$_SERVER['SCRIPT_FILENAME']}
Server:       {$_SERVER['SERVER_SOFTWARE']}</pre>
ERR;
    } elseif (isset($ACCOUNTS[$user]) && $ACCOUNTS[$user]['password'] === $pass) {
        $logged_in = ['user' => $user, 'role' => $ACCOUNTS[$user]['role']];
    } else {
        $error = '<div class="box danger"><h3>登录失败</h3><p>用户名或口令不正确。</p></div>';
    }
}

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
?><!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>后台管理系统 · 登录</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header><div class="wrap"><h1>后台管理系统</h1></div></header>
<main class="wrap">
<div class="login">
<?php if ($logged_in): ?>
  <h2>登录成功</h2>
  <div class="box ok">
    <h3>欢迎，<?php echo h($logged_in['user']); ?></h3>
    <p>角色：<?php echo h($logged_in['role']); ?></p>
  </div>
  <ul>
    <li><a href="#">内容发布</a></li>
    <li><a href="#">用户管理</a>（含全部人员身份号码）</li>
    <li><a href="#">数据库备份</a></li>
    <li><a href="#">系统日志</a></li>
  </ul>
  <p class="tiny">当前系统已关闭登录审计，所有操作不会留痕（演示用）。</p>
<?php else: ?>
  <h2>请登录</h2>
  <?php echo $error; ?>
  <form method="get" action="login.php">
    <label>用户名 <input name="user" value="<?php echo h($user); ?>"></label>
    <label>口　令 <input name="pass" type="text" value="<?php echo h($pass); ?>"></label>
    <button type="submit">登录</button>
  </form>
  <p class="tiny">默认账号 admin / Admin@888（上线前请修改）</p>
<?php endif; ?>
  <p><a href="/l1/">返回站点首页</a></p>
</div>
</main>
<footer><div class="wrap">
  <p>某某市政务服务与大数据管理局 · 信息中心</p>
  <p class="tiny">本站为安全巡检训练靶场，页面内容与数据均为编造的测试数据。</p>
</div></footer>
</body>
</html>
