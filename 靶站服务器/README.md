# 演示靶站服务器（多关卡版）

配合「网站安全巡检智能体」做演示与自测。零第三方依赖，只用 Python 标准库；
只监听 127.0.0.1，仅供本机授权演示，请勿暴露到公网。

每关一个独立端口、一组独立问题，难度递增；不会把所有危险塞在同一个站里。

## 启动

- 双击 `start.bat`；或命令行 `python server.py`；
- 默认端口从 8890 起，依次对应 L0 到 L6；
- 换起始端口：`python server.py 9000`（则 L0 为 9000，L1 为 9001，依此类推）。

## 关卡总览

| 关卡 | 地址 | 难度 | 考点 | 预期发现 |
|---|---|---|---|---|
| L0 对照组 | `127.0.0.1:8890` | ☆ | 正常站点，用于误报对照 | 不应报任何风险 |
| L1 显性泄露 | `127.0.0.1:8891` | ★ | 常见敏感落点 + 缺失安全响应头 | `/.env`（严重）、`/backup.sql`（严重）、`/phpinfo.php`（中）、弱响应头（中/低/信息） |
| L2 隐蔽暴露 | `127.0.0.1:8892` | ★★ | 子目录配置、目录索引、日志、管理入口、Cookie、软 404 诱饵 | `/portal/.env`（严重）、`/error.log`（中）、`/uploads/` 目录索引（低）、`/admin/login` 管理入口（低）、Cookie 无 HttpOnly（低）；`/secret/` 为软 404 诱饵，不应报 |
| L3 注入验证 | `127.0.0.1:8893` | ★★ | 布尔差分注入 + 报错回显 | `/article?id=1` 注入迹象（布尔差分成立；带引号返回 SQL 报错） |
| L4 内容安全 | `127.0.0.1:8894` | ★★★ | 恶意外链/挂马；基线篡改 | `/news/` 可疑外链与隐藏 iframe（挂马，严重）；`/portal/` 篡改后出现内容变化（高） |
| L5 特征对抗 | `127.0.0.1:8895` | ★★★★ | 特征判定与诱饵 | `/site.tar.gz`（中）、`/.git/HEAD`（高）、`/debug.log`（中）；`/.env.save` 为 HTML 诱饵，不应报；`/news/` 用协议相对外链，属已知边界（可能不报） |
| L6 综合对抗 | `127.0.0.1:8896` | ★★★★★ | 组合题 + 精准度 | `/.env.save`（严重）、`/info.php`（中）、`/private.key`（严重）；`/config.json` 与 `/db.sql` 为 HTML 诱饵，不应报 |

## 每题的设计说明

- L0：只有正常页面；任何未知路径返回同形错误页（200）。用来验证“软 404 校准”与误报控制。
- L1：三个最典型的敏感落点，外加整站缺失五个安全响应头（CSP、X-Content-Type-Options、X-Frame-Options、Referrer-Policy、Permissions-Policy）。适合第一轮演示。
- L2：问题分散在子目录与功能页；同时放一个 `/secret/` 诱饵（返回与默认页同形的 200 页面），考察先校准再判定的能力。
- L3：`/article?id=1` 的 `AND 1=1` 与 `AND 1=2` 返回不同长度；带引号触发 SQL 报错文本。考察只确认、不利用的布尔差分。
- L4：新闻页放入可疑域名与裸 IP 外链（正常的 example.com 外链作对照）；门户页先建基线，再通过控制接口切换“被篡改”版本。考察外链与基线比对。
- L5：真问题与诱饵混排——`/.env.save` 里出现凭据字样但整体是 HTML（规则应排除）；协议相对外链 `//badcdn.xyz` 是当前版本已知边界，用来暴露能力边界而不是要求必报。
- L6：`.env.save`、`/info.php`、`/private.key` 为真；`/config.json`、`/db.sql` 为 HTML 诱饵（内容像配置或 SQL，但整体是网页），考察内容特征判定的精确度。

## 控制接口（演示用）

token 默认 `demo`，状态只在内存中，重启即复位。任一关卡端口都可调用：

| 接口 | 作用 |
|---|---|
| `/__ctl/status?token=demo` | 查看全部状态 |
| `/__ctl/tamper?on=1&token=demo` | 让 L4 的 `/portal/` 变成被篡改版本 |
| `/__ctl/tamper?off=1&token=demo` | 恢复 L4 门户页 |
| `/__ctl/fix?item=headers_l1&token=demo` | 给 L1 补上安全响应头 |
| `/__ctl/fix?item=l1_env&token=demo` | L1 的 `/.env` 返回 404（复测“已修复”） |
| `/__ctl/fix?item=l2_env&token=demo` | L2 的 `/portal/.env` 返回 404 |
| `/__ctl/fix?item=l2_dirlist&token=demo` | 关闭 L2 目录索引 |
| `/__ctl/fix?item=l2_cookie&token=demo` | L2 的 Cookie 加 HttpOnly |
| `/__ctl/fix?item=l3_sqli&token=demo` | 修复 L3 注入点 |
| `/__ctl/fix?item=l4_links&token=demo` | 移除 L4 可疑外链 |
| `/__ctl/fix?item=l5_archive&token=demo` | L5 的 `/site.tar.gz` 返回 404 |
| `/__ctl/fix?item=l5_git&token=demo` | L5 的 `/.git/HEAD` 返回 404 |
| `/__ctl/fix?item=l6_envsave&token=demo` | L6 的 `/.env.save` 返回 404 |
| `/__ctl/fix?item=l6_key&token=demo` | L6 的 `/private.key` 返回 404 |
| `/__ctl/reset?token=demo` | 全部复位 |

## 演示脚本

（1）启动靶站；在巡检智能体里把目标设为某一关的地址（例如 L1 的 `127.0.0.1:8891`），勾选授权；
（2）完整巡检一轮，对照本文件的“预期发现”逐条核对；
（3）L4 篡改演示：先巡检建立基线，再访问 `/__ctl/tamper?on=1&token=demo`，复测或再巡检，观察内容变化与新增外域；
（4）复测演示：访问 `/__ctl/fix?item=l1_env&token=demo`，复测，`/.env` 变为 404，状态应推进为已修复；
（5）全部复位：`/__ctl/reset?token=demo`，或直接重启服务。

## 说明

- 所有敏感内容均为伪造的演示数据，不含真实凭据；
- 关卡按“问题类型”拆分，便于分段演示与评分对账；
- L5 的协议相对外链、L2 的软 404 诱饵是刻意放的“边界题”，用于展示能力边界与误报控制思路。
