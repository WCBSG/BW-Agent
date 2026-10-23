/* tool_entry.h —— 工具入口层:声明 + 入口(exec/http/builtin)+ 协议(argv/json-stdio)。
 *
 *   <数据目录>\tools\<目录>\<名字>.json
 *   {
 *     "name": "whois_lookup", "kind": "自建", "readonly": true,
 *     "description": "...", "schema": { ... },
 *     "entry": {
 *       "type": "exec",                  // exec | http
 *       "path": "~/tools/whois/whois.exe",  // 或 "cwd": "~/tools/x"
 *       "args": ["--json", "$domain"],      // $名 占位,可写 ${名:-默认值}
 *       "protocol": "argv",              // argv | json-stdio(默认)
 *       "timeout_ms": 30000
 *     }
 *   }
 *
 * 两种"对话"协议:
 *   argv       —— 参数展开进命令行,stdout+stderr 原样作为结果文本;
 *   json-stdio —— 往 stdin 写一份调用 JSON、从 stdout 读一份结果 JSON
 *                 (HTTP 则是 POST 请求体 / 响应体)。
 *
 *   请求 {"tool":"名字","args":{...},
 *         "context":{"data_dir":"...","app_dir":"...","cwd":"...","readonly":false}}
 *   应答 {"text":"给模型看的文本","say":"给人的汇报","data":{...},"is_error":false}
 *        也接受纯文本:stdout 不是 JSON 时整段当 text。
 */
#ifndef AGENT_TOOL_ENTRY_H
#define AGENT_TOOL_ENTRY_H

#include "agent.h"
#include "json.h"

/* 解析声明里的 entry。返回 1 = 收下了(之后可用 tool_entry_run 执行),
   0 = 这份声明没有 entry(交给别的装载器),-1 = 写错了。 */
int tool_entry_parse(json_t *spec, const char *origin);

/* 入口型工具的统一执行体:按 ctx->current_tool 找到对应声明 */
int tool_entry_run(tool_ctx_t *ctx, json_t *args, tool_result_t *out);

/* 重新装载前清空(外部入口全部来自数据目录,重读时不保留旧的) */
void tool_entry_reset(void);
int  tool_entry_count(void);

#endif /* AGENT_TOOL_ENTRY_H */
