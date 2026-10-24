/* ext.h —— 可扩展层(全部在数据目录下):
 *   tools\<名字>\<名字>.json   外部命令工具(stdout 即结果)
 *   skills\<名字>\SKILL.md      技能包;带 command 的技能会真执行
 *   mcp.json                    外部 MCP 服务器(stdio JSON-RPC)
 * 外部能力必须显式 allow,否则只登记不执行。
 */
#ifndef AGENT_EXT_H
#define AGENT_EXT_H

#include "agent.h"
#include "common.h"
#include "json.h"

/* 载入三类扩展(数据目录下);返回成功登记的外部能力个数 */
int  ext_load_all(void);

/* 列出某目录下指定后缀的文件(供界面"配置编辑"用):
   返回文件个数,out 里是完整路径(xstrdup 出来的,用 str_free_list 释放)。 */
int  ext_list_files(const char *dir, const char *ext, char ***out);
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

/* 跑一条外部命令并把 stdout+stderr 收回来(与外部工具用的是同一套进程/管道实现)。
   成功返回 0,超时 -2,起不来 -1;out_text 用 free 释放。给"编排开源工具"用。 */
int  ext_run_capture(const char *cmdline, const char *workdir, int timeout_ms,
                     char **out_text, int *out_exit);

/* ================= 界面里的"能力管理"(图形化,不用手写文件) ================= */

/* 重新读 tools\ 与 skills\ —— 界面里改完立刻生效,不必重启。
   MCP 服务器不动(重启它们会打断正在用的会话)。返回重新登记的外部能力个数。 */
int ext_reload_local(void);

/* 能力清单的结构化快照:技能包 / 外部工具 / MCP 服务器(内置项由调用方另取) */
json_t *ext_inventory_json(void);

#endif /* AGENT_EXT_H */
