/* tools.h —— 工具层:注册表 + 参数校验 + 执行。
   工具是最底层的手:一次取数、一次匹配。无状态、可单测。
   技能(skill)不在这里 —— 技能是"怎么用手",见 skills.h。 */
#ifndef AGENT_TOOLS_H
#define AGENT_TOOLS_H

#include "agent.h"
#include "common.h"
#include "io.h"
#include "json.h"

struct tool_ctx {
  const char *data_dir;        /* 落盘根目录 */
  const char *task_id;         /* 当前任务 */
  const char *run_id;          /* 本次运行编号(发现要挂到运行上) */
  const char **domains;        /* 授权域名 */
  int domain_count;
  tools_io_t io;               /* 取数通道(带合规) */
  void *store;                 /* 存储句柄(store_t*,见 store.h) */
  buf_t *note;                 /* 工具可以往里写"我做了什么"的留痕 */
  int http_calls;              /* 本次会话已发起的请求数(限流与报告用) */
  const char *current_tool;    /* 正在执行的名字 —— 外部扩展的适配器靠它知道自己是谁 */
};

/* 注册表 */
void        tools_init(void);
int         tools_count(void);

/* 正则验枪口:把一条自定义正则拿去试(供 `agent.exe regextest` 用)。
   命中返回 1 并给出偏移/长度 —— 规则是数据,自定义正则必须能当场验证。 */
int         tools_regex_first(const char *pattern, const char *text, int *off, int *len);
tool_t     *tools_get(int index);
tool_t     *tools_find(const char *name);
/* 追加一个外部工具(用户在数据目录里定义的 / MCP 服务器提供的)。
   注册表的头 8 个是内置工具,追加的排在后面 —— 内置的永远优先,避免被外部同名覆盖。 */
int         tools_register_external(const char *name, const char *description,
                                    const char *schema_json, const char *kind,
                                    const char *source_url, int readonly,
                                    int (*run)(tool_ctx_t *, json_t *, tool_result_t *));
/* 这个工具是不是只读(没登记过的按"不是只读"处理:宁可多问一句) */
int         tools_is_readonly(const char *name);
/* 清空工具表(声明文件重新装载前清场用) */
void        tools_reset_all(void);
/* 按磁盘上的声明重新装载(含清理入口注册表)。返回装载条数。 */
int         tools_reload_specs(void);
/* 外置声明工具(entry 型)的条数 */
int         tools_count_external(void);
json_t     *tools_decl_json(void);       /* 工具清单(命题⑤交付物) */
void        tools_manifest(buf_t *out);  /* 给模型看的清单文本 */

/* 参数校验(按 schema 的 required/type 子集)+ 执行 */
int         tools_validate(tool_t *t, json_t *args, buf_t *err);
int         tools_run(tool_ctx_t *ctx, const char *name, json_t *args,
                      tool_result_t *out);
/* 只走程序内实现(不查注册表、不碰外部入口)。
   独立工具 exe(tools/toolhost.cpp)用它:那些进程里没有注册表,
   但如果走 tools_run 又会命中同名入口声明 → 自己调自己。 */
int         tools_run_builtin(tool_ctx_t *ctx, const char *name, json_t *args,
                              tool_result_t *out);
/* 自检模式:工具一律走进程内实现。
   自检用的是本地假网络层(桩服务/假响应头),外部工具进程看不到那一层,
   必须回到同一进程里测同一份业务判断。 */
void        tools_set_force_builtin(int on);

/* 目标解析:把"这个站" / "www.x.cn" / "/news.php?id=1" 补成完整 URL */
void        target_resolve(buf_t *out, const char *raw, const char *fallback_host);
/* 授权校验:不在授权域名内返回 0 */
int         scope_allows(tool_ctx_t *ctx, const char *url, char **err);

#endif /* AGENT_TOOLS_H */
