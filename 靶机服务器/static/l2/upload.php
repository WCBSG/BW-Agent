<?php
/**
 * 附件上传
 * ------------------------------------------------------------------
 * 【这道题考什么】
 *   无限制文件上传。脚本**不校验扩展名、不校验 MIME、不校验内容**，
 *   并且把文件保存到 Web 可访问目录 —— 直接构成"上传即后门"。
 *
 *   完整攻击链（也是本关的设计意图）：
 *     ① POST 一个 .php 文件到 upload.php
 *     ② 得到返回的访问地址
 *     ③ 直接请求该地址 → 服务器执行你的代码
 *
 *   在真实世界里，这是拿下服务器最快的一条路，
 *   也是政企网站被挂马的最主要入口（挂马 → 见 L1/L2/L3 的考点）。
 *
 * 【触发方式】
 *   curl -F "file=@shell.php" http://<ip>:8081/l2/upload.php
 *   （或用页面上的表单上传）
 *
 * 【为什么必须真 PHP】
 *   要真落盘、真返回可访问 URL，才能验证"上传的文件确实能被执行"。
 *
 * 【修复建议】
 *   白名单扩展名 + 重命名为随机名 + 保存到 Web 根之外 + 禁止该目录执行脚本。
 */

$UPLOAD_DIR = __DIR__ . '/uploads';
if (!is_dir($UPLOAD_DIR)) {
    @mkdir($UPLOAD_DIR, 0777, true);
}

$message = '';
$saved = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (empty($_FILES)) {
        $message = '没有收到文件（表单字段名应为 file）';
    } else {
        $field = array_key_first($_FILES);
        $file = $_FILES[$field];

        if ($file['error'] !== UPLOAD_ERR_OK) {
            $message = '上传失败，PHP 错误码：' . $file['error'];
        } else {
            // ↓↓↓ 漏洞在这里：原始文件名直接用，没有任何校验
            $target = $UPLOAD_DIR . '/' . basename($file['name']);

            if (move_uploaded_file($file['tmp_name'], $target)) {
                $saved = [
                    'name' => basename($target),
                    'size' => filesize($target),
                    'url'  => '/l2/uploads/' . rawurlencode(basename($target)),
                    'path' => $target,
                    'mime' => $file['type'],
                ];
            } else {
                $message = '移动文件失败（检查目录权限）';
            }
        }
    }
}

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
?><!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>资料上传</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header><div class="wrap"><h1>资料上传</h1></div></header>
<main class="wrap">

  <h2>上传附件</h2>
  <div class="box">
    <p>支持任意格式的文档、图片、压缩包。</p>
    <form method="post" action="upload.php" enctype="multipart/form-data">
      <label>选择文件 <input type="file" name="file"></label>
      <button type="submit">上传</button>
    </form>
    <p class="tiny">提示：上传后文件可直接通过 /l2/uploads/&lt;文件名&gt; 访问。</p>
  </div>

<?php if ($message): ?>
  <div class="box danger"><h3>错误</h3><p><?php echo h($message); ?></p></div>
<?php endif; ?>

<?php if ($saved): ?>
  <div class="box ok">
    <h3>上传成功</h3>
    <table>
      <tr><th>文件名</th><td><?php echo h($saved['name']); ?></td></tr>
      <tr><th>大小</th><td><?php echo h($saved['size']); ?> 字节</td></tr>
      <tr><th>类型</th><td><?php echo h($saved['mime']); ?></td></tr>
      <tr><th>访问地址</th>
          <td><a href="<?php echo h($saved['url']); ?>"><?php echo h($saved['url']); ?></a></td></tr>
      <tr><th>落盘路径</th><td><code><?php echo h($saved['path']); ?></code></td></tr>
    </table>
    <p class="tiny">（服务端未对文件类型做任何校验，也未限制该目录执行脚本。）</p>
  </div>
<?php endif; ?>

  <p><a href="index.html">返回首页</a></p>
</main>
<footer><div class="wrap">
  <p>某某市政务服务与大数据管理局 · 信息中心</p>
  <p class="tiny">本站为安全巡检训练靶场，页面内容与数据均为编造的测试数据。</p>
</div></footer>
</body>
</html>
