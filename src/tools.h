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
                                    const char *source_url,
                                    int (*run)(tool_ctx_t *, json_t *, tool_result_t *));
json_t     *tools_decl_json(void);       /* 工具清单(命题⑤交付物) */
void        tools_manifest(buf_t *out);  /* 给模型看的清单文本 */

/* 参数校验(按 schema 的 required/type 子集)+ 执行 */
int         tools_validate(tool_t *t, json_t *args, buf_t *err);
int         tools_run(tool_ctx_t *ctx, const char *name, json_t *args,
                      tool_result_t *out);

/* 目标解析:把"这个站" / "www.x.cn" / "/news.php?id=1" 补成完整 URL */
void        target_resolve(buf_t *out, const char *raw, const char *fallback_host);
/* 授权校验:不在授权域名内返回 0 */
int         scope_allows(tool_ctx_t *ctx, const char *url, char **err);

#endif /* AGENT_TOOLS_H */
