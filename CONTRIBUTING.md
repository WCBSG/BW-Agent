# 协作说明

这个仓库是一个 C++20 单文件 exe + 内置网页界面的作品。下面是多人一起改它时最少要知道的事。

## 一、先把环境跑起来

```
需要的只有两样:
  · MinGW-w64 的 g++(≥ 13,GCC 16.2 实测)
  · Windows 10/11(用了 WinHTTP / Win32 目录 API / Winsock)

构建:
  agent\build.bat           → agent\build\网站安全巡检智能体.exe(单文件,双击即用)
自检:
  agent\build\agent.exe selftest → 116 项,必须全绿
```

`agent\build.bat` 会把 `agent\ui\` 和 `agent\data\rules.json` 编进 exe（见 `agent\tools\mkres.cpp`），
所以**改完界面不用另外分发文件**，重新编译即可。

数据目录默认 `C:\Users\<你>\.bw_agent`。想让它跟仓库无关地跑测试，设 `BW_AGENT_HOME` 指到别处。

## 二、分支与提交

- `main` 保护：只能通过 PR 合入，CI 必须绿。
- 功能分支：`feat/短描述`；修复：`fix/短描述`。一次 PR 只做一件事。
- 提交信息用 `feat: / fix: / refactor: / docs: / test:` 开头，正文说清"为什么"。
- 提交前本地至少跑一遍：

```
agent\build.bat && agent\build\agent.exe selftest
```

## 三、必须守住的四条线

这个作品是"安全工具"，改代码时下面四件事不能破：

1. **边界**：所有对外请求只能走 `net.cpp`。授权池（`pool.json`）是唯一边界，
   池外请求必须被拒并置越权标记（`net_scope_violation`），让决策循环立刻收束。
2. **只读**：`net_set_readonly(1)` 下只允许 GET/HEAD。不要为了方便加 POST/PUT。
3. **留痕**：新加的对外动作要 `net_audit(...)`；发现落盘要走 `store_upsert_finding`。
4. **审批**：工具执行前会过 `approval_decide`。不要在工具内部绕开这道闸。

## 四、常见的改动落点

| 想改什么 | 改哪里 |
|---|---|
| 检测口径（正则、弱口令表、目录清单…） | `data\rules.json`（数据，不是代码） |
| 新增一个原子动作 | `agent\src\tools.cpp` + 在工具表里登记 schema |
| 新增一个"编排型"能力 | `agent\src\skills.cpp`（检查类）或 `skills_closure.cpp`（收尾类） |
| 界面 | `agent\ui\index.html` / `agent\ui\app.css` / `agent\ui\app.js`（只通过 HTTP + SSE 与后端说话） |
| 授权池 / 周期巡检 / 审批 / 导出 | `agent\src\net.cpp` · `automation.cpp` · `approval.cpp` · `export.cpp` |
| 本单位敏感信息定义 | `agent\src\profile.cpp` + `ui` 的自动化页 |

新增 `.cpp` 不用改构建脚本：`agent\build.bat` 用 `agent\src\*.cpp` 通配。

## 五、界面约定的两条

- 后端只提供数据，前端不复制业务统计逻辑（否则"页面上的数字"和"报告里的数字"会两套）。
- 可读性底线：正文 ≥13.5px、标签 ≥12px、正文对比度 ≥4.5:1。改样式前先看 `agent\ui\app.css` 顶部那段约束。

## 六、提交 PR 前自查

```
[ ] agent\build.bat 通过
[ ] agent\build\agent.exe selftest 全绿
[ ] 没有把 .env / 令牌 / 真实站点数据提交进来
[ ] 新增的对外请求过了 net.cpp（没有自己开 socket / WinHTTP）
[ ] 新增的配置项写进了 README 与界面（不要只藏在代码里）
```
