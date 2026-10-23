/* fs_tool.h —— 本机文件读/列/写三个工具的实现入口(定义在 fs_tool.cpp)。
   声明单独放一份,是为了让 tools.cpp 的通用实现表不必知道文件工具怎么实现。 */
#ifndef AGENT_FS_TOOL_H
#define AGENT_FS_TOOL_H

#include "agent.h"
#include "json.h"

int fs_tool_read(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int fs_tool_list(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int fs_tool_write(tool_ctx_t *ctx, json_t *args, tool_result_t *out);

/* 独立工具 exe(bwtool)用:把自己所在的可执行目录之外,再允许读一个根
   (主程序把 context.app_dir 传过来)。空字符串表示取消。 */
void fs_tool_set_extra_root(const char *dir);

#endif /* AGENT_FS_TOOL_H */
