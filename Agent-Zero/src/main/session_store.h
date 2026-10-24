/* session_store.h —— 会话存储(v3:带补丁的追加日志)。
 *
 * 一个会话一个文件:<数据目录>\chat\<会话id>.jsonl,只追加,永不重写。
 * 每行是一条"操作"(和 VS Code Copilot 的 chatSessions 一个思路):
 *
 *   {"kind":0,"v":{…}}                              快照:首行,整个会话对象
 *   {"kind":1,"k":["turns",0,"response"],"v":{…}}   把路径上的值换成 v
 *   {"kind":2,"k":["turns",0,"steps"],"v":{…}}      往路径上的数组追加一项
 *
 * 读 = 从快照开始,按顺序把操作应用一遍。好处:
 *   · 崩溃只丢最后半行,前面全部有效(不会出现"文件写坏了整段丢失")
 *   · 一轮对话的开始/每一步/结束各写一次,不需要"读全量、改、再重写"
 *   · 追加是 O(1),长会话也不会越写越慢
 *
 * 会话对象的形状(界面按这个渲染):
 *   {
 *     "schema": 3, "id": "…", "title": "…",
 *     "created_at": "…", "updated_at": "…",
 *     "archived": false, "pinned": false,
 *     "input": { "draft": "", "attachments": [], "approval": "ask", "model": "" },
 *     "turns": [ {
 *        "turnId": "t-0001", "seq": 1, "status": "running|complete|error|aborted",
 *        "started_at": "…", "finished_at": "…",
 *        "user": { "blocks": [ {"type":"text","text":"…"} ] },
 *        "request": { "model": "…", "model_name": "…", "prompt_bytes": N,
 *                     "prompt_hash": "…", "tools": N, "approval": "ask", "max_steps": N },
 *        "steps": [ {"type":"think","text":"…","at":"…","duration_ms":N}
 *                 | {"type":"tool","name":"…","args":{…},"step_id":"…","at":"…",
 *                    "duration_ms":N,"status":"done|error","note":"…","artifact":"…",
 *                    "approved_by":"user|policy|none"} ],
 *        "response": { "text": "…", "stop_reason": "…", "stop_detail": "…",
 *                      "stop_code": N, "steps": N, "llm_ms": N, "first_byte_ms": N,
 *                      "duration_ms": N, "wait_ms": N,
 *                      "tokens": {"prompt":N,"completion":N}, "tool_calls": N }
 *     } ]
 *   }
 *
 * 和旧格式的关系:**不兼容**。旧版把 message/meta/event 混在一个文件里、
 * 每条消息后重写一遍 meta —— 那种结构既浪费又无法表达"一轮里发生了什么"。
 */
#ifndef AGENT_SESSION_STORE_H
#define AGENT_SESSION_STORE_H

#include "common.h"
#include "json.h"

#define SESSION_SCHEMA 3

void    sess_init(const char *data_dir);

/* 确保会话存在(不存在就写快照),返回会话头(调用方 json_free) */
json_t *sess_ensure(const char *id, const char *title);

/* 整个会话(头 + turns),调用方 json_free */
json_t *sess_get(const char *id);

/* 列表:只回头部字段,按 pinned / updated_at 排序 */
json_t *sess_list(void);

int sess_set_title(const char *id, const char *title);
int sess_set_flags(const char *id, int archived, int pinned);
int sess_delete(const char *id);

/* 输入状态(草稿/附件/审批策略/模型):关掉页面再回来还是原来的样子 */
int sess_set_input(const char *id, json_t *input);

/* 压缩结果(摘要 + 压掉几轮):写进会话,界面据此显示压缩点 */
int sess_set_context(const char *id, json_t *ctx);

/* ---------- 一轮对话 ---------- */

/* 开一轮:写入骨架(用户说了什么 + 这次请求的基本信息),立即落盘。
   返回该轮在 turns[] 里的下标(>=0),失败 -1。
   request 可为 NULL(所有权转移)。 */
int sess_begin_turn(const char *id, json_t *user_blocks, json_t *request);

/* 往这一轮的 steps[] 追加一项(思考或工具) */
int sess_turn_add_step(const char *id, int index, json_t *step);

/* 改这一轮里第 step_index 项的某个字段(工具跑完补 note/status 用) */
int sess_step_patch(const char *id, int index, int step_index, const char *key, json_t *value);

/* 改这一轮里的某个字段,例如 "response" / "status" / "finished_at" */
int sess_turn_patch(const char *id, int index, const char *key, json_t *value);

/* 收尾:一次写完 response + status + finished_at */
int sess_turn_finish(const char *id, int index, json_t *response, const char *status);

/* 完整工具输出:超过阈值的部分写到 chat\artifacts\,消息里只留引用。
   返回相对路径(调用方 free),失败返回 NULL。 */
char *sess_artifact_write(const char *id, const char *tag, const char *text, size_t len);

/* 读回某个产物(调用方 free),失败返回 NULL */
char *sess_artifact_read(const char *rel_path, size_t *len);

/* 纯文本块数组(给只关心"说了什么"的地方用) */
json_t *sess_blocks_text(const char *text);

#endif /* AGENT_SESSION_STORE_H */
