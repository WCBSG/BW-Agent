/* tool_entry.h —— 工具的"入口层":让工具真的可以是任何东西。
 *
 * 一份声明只要说清两件事,程序就能把它当工具用:
 *   1. 入口(entry):程序内的实现 / 本机进程 / HTTP 端点;
 *   2. 协议(protocol):怎么把参数交给它、怎么读它的结果。
 *
 * 声明写在 <数据目录>\tools\<名字>.json 里(与内置工具同一目录):
 *
 *   {
 *     "name": "whois_lookup",
 *     "kind": "自建 · 命令",
 *     "readonly": true,
 *     "allow": true,                       // 外部入口必须显式打开
 *     "description": "查域名注册信息",
 *     "schema": { "type": "object", "properties": { "domain": {"type":"string"} } },
 *     "entry": {
 *       "type": "exec",                    // exec | http | builtin
 *       "path": "bin\whois.exe",           // 入口命令;相对路径按数据目录算
 *       "args": ["--json", "$domain"],     // 固定参数(可含 $参数 占位)
 *       "protocol": "argv",                // argv(默认) | json-stdio
 *       "cwd": "",                         // 可选,默认数据目录
 *       "timeout_ms": 30000
 *     }
 *   }
 *
 *   HTTP 端点把 type 换成 "http",写 "url",协议默认 "json"。
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
