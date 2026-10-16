/* ext.h —— 可扩展层:像 Claude Code 那样自己加能力,全部放在数据目录下。
 *
 * 三样东西,各一个目录(首次运行时自动生成带注释的示例):
 *
 *   ~\.bw_agent\tools\*.json    外部工具:声明式清单 + 一条命令
 *       智能体执行时会真的调用那条命令,把 stdout 当作工具结果。
 *
 *   ~\.bw_agent\skills\*.md     技能包:Markdown(带 front-matter 的"怎么做")。
 *       没有命令的技能 = 步骤说明(喂给模型当方法论);带命令的技能 = 真去执行。
 *
 *   ~\.bw_agent\mcp.json        外部 MCP 服务器(stdio, JSON-RPC 2.0):
 *       启动时握手 initialize → tools/list 把对方的工具挂进注册表,
 *       被调用时走 tools/call。
 *
 * 安全边界:外部能力必须显式 allow(清单里 "allow": true 或 mcp 项 "allow": true),
 * 否则只登记不执行 —— 免得从别处拷来一份配置就顺手执行了命令。
 */
#ifndef AGENT_EXT_H
#define AGENT_EXT_H

#include "agent.h"
#include "common.h"
#include "json.h"

/* 载入三类扩展(数据目录下);返回成功登记的外部能力个数 */
int  ext_load_all(void);
/* 把已载入的外部能力挂到工具表与技能表上(必须在 tools_init/skills_init 之后调用) */
void ext_register_all(void);
/* 进程退出时收掉我们拉起来的 MCP 子进程 */
void ext_shutdown(void);
/* 供界面/文档展示:各类扩展的条数 */
void ext_stats(int *tools, int *skills, int *mcp, int *mcp_tools);
/* 数据目录里的扩展目录(不存在则创建,并写入带注释的示例) */
const char *ext_dir(char *out, size_t cap, const char *child);
/* 首次运行:建立 tools\ skills\ 目录与示例、mcp.json 示例 */
void ext_bootstrap(void);

#endif /* AGENT_EXT_H */
