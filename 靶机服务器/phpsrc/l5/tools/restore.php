<?php
/**
 * 数据恢复工具
 * ------------------------------------------------------------------
 * 【这道题考什么】
 *   PHP 对象注入（unserialize 反序列化漏洞）。
 *
 *   这是 PHP 里最隐蔽的一类漏洞，也是"看得细不细"的极端考验：
 *
 *     · 页面上**完全看不出异常** —— 就是个普通的数据恢复表单
 *     · 参数是一串看似乱码的字符串   O:8:"UserInfo":1:{...}
 *     · 危害不在这一页，而在**被反序列化的类里的魔术方法**
 *         __wakeup()  /  __destruct()  /  __toString()
 *       攻击者通过控制对象属性，让这些方法做出危险操作。
 *
 *   ── 检测方该抓什么？──
 *   ① 代码里出现 unserialize($_GET[...]) 这类"用户输入直接反序列化"
 *   ② 存在带魔术方法的类（尤其方法体里有文件/命令/数据库操作）
 *   ③ 页面提供"导入/恢复/导入配置"这类**接受序列化数据**的入口
 *
 *   ── 为什么这题归到 L5"取证" ──
 *   因为发现它要求检测方**读代码并理解语义**，
 *   而不是匹配一个特征字符串。正则匹配 unserialize 只是起点，
 *   真正要判断的是"这个反序列化的结果流向哪里"。
 *
 * 【触发方式】
 *   正常： /l5/tools/restore.php?data=O:8:"UserInfo":2:{s:4:"role";s:5:"guest";s:4:"name";s:6:"访客";}
 *   注入： /l5/tools/restore.php?data=O:8:"UserInfo":2:{s:4:"role";s:5:"admin";s:4:"name";s:5:"haxor";}
 *
 * 【修复建议】
 *   不要反序列化用户输入；改用 JSON；
 *   必须用时加签名校验（HMAC），并限制 allowed_classes。
 */

/**
 * 用户信息对象
 *
 * ⚠ 这个类的 __wakeup 与 __destruct 就是"被利用的入口"。
 *   真实攻击链里，攻击者通过构造属性值让这些方法越权或落盘文件。
 */
class UserInfo
{
    public $name = '访客';
    public $role = 'guest';
    public $dept = '';
    /** @var string 恢复出来的配置内容（攻击者可借此写入任意内容） */
    public $config = '';

    public function __wakeup()
    {
        // 反序列化时自动调用 —— 这里做"权限提升"判断
        if ($this->role === 'admin') {
            $this->dept = '信息中心（越权获得）';
        }
        return $this;
    }

    public function __destruct()
    {
        // 对象销毁时自动调用 —— 真实漏洞常在这里写文件
        if ($this->config !== '') {
            $target = sys_get_temp_dir() . '/zwfw_restore_' . md5($this->name) . '.conf';
            @file_put_contents($target, $this->config);
        }
    }

    public function summary()
    {
        return sprintf('姓名=%s　角色=%s　科室=%s', $this->name, $this->role, $this->dept ?: '-');
    }
}

// 演示用的"从备份恢复的样例数据"
$SAMPLE = 'O:8:"UserInfo":3:{s:4:"name";s:9:"张伟明";s:4:"role";s:5:"guest";s:4:"dept";s:12:"信息中心";}';

$raw = isset($_GET['data']) ? $_GET['data'] : '';
$result = null;
$error = '';
$restored = null;

if ($raw !== '') {
    // 允许 base64 包装，方便命令行传输
    $payload = $raw;
    if (preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $raw) && strpos($raw, ':') === false) {
        $maybe = base64_decode($raw, true);
        if ($maybe !== false && strpos($maybe, ':') !== false) {
            $payload = $maybe;
        }
    }

    // ↓↓↓ 漏洞在这里：用户输入直接进 unserialize
    $old = error_reporting(E_ALL & ~E_WARNING & ~E_NOTICE);
    $restored = @unserialize($payload);
    error_reporting($old);

    if ($restored === false && $payload !== 'b:0;') {
        $error = '数据格式无法解析，请确认是有效的序列化字符串。';
    } elseif (is_object($restored)) {
        $result = $restored;
    } else {
        $error = '解析成功，但结果不是预期的对象类型。';
    }
}

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

/**
 * UTF-8 安全的截断。
 *
 * 为什么不用 mb_substr()？—— 本机这个 PHP 是精简构建，
 * **没有 mbstring 扩展**，调用 mb_substr 会直接 Fatal error。
 * 用 preg 的 /u 模式做等价的按字符截断即可。
 */
function cut($s, $n)
{
    if (preg_match('/^.{0,' . (int)$n . '}/us', (string)$s, $m)) {
        return $m[0];
    }
    return substr((string)$s, 0, (int)$n);
}
?><!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>数据恢复工具</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header><div class="wrap"><h1>数据恢复工具</h1></div></header>
<main class="wrap">

  <h2>从备份恢复</h2>
  <div class="box">
    <p>粘贴备份文件中的序列化数据，点击恢复。</p>
    <form method="get" action="restore.php">
      <label>序列化数据
        <textarea name="data" rows="4" style="width:100%"><?php echo h($raw ?: $SAMPLE); ?></textarea>
      </label>
      <button type="submit">恢复</button>
    </form>
    <p class="tiny">示例数据：<code><?php echo h(cut($SAMPLE, 60)); ?>…</code></p>
  </div>

<?php if ($error): ?>
  <div class="box danger"><h3>错误</h3><p><?php echo h($error); ?></p></div>
<?php endif; ?>

<?php if ($result): ?>
  <div class="box ok">
    <h3>恢复成功</h3>
    <p><?php echo h($result->summary()); ?></p>
  </div>
  <h3>对象结构</h3>
  <pre><?php echo h(print_r($result, true)); ?></pre>
<?php endif; ?>

  <p><a href="/l5/">返回首页</a></p>
</main>
<footer><div class="wrap">
  <p>某某市政务服务与大数据管理局 · 信息中心</p>
  <p class="tiny">本站为安全巡检训练靶场，页面内容与数据均为编造的测试数据。</p>
</div></footer>
</body>
</html>
