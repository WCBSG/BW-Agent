/* thread_store.h —— 对话存储。
 *
 *   <数据目录>\chat\<对话id>.jsonl   一个对话一个文件,只追加
 *      {"type":"message",...}   消息(稳定 id + seq + parent_id + blocks)
 *      {"type":"event",...}     该会话的事件流(步骤 / 审批 / 停止)
 *      {"type":"meta",...}      元数据快照;同文件最后一条说了算
 *
 * 列表 = 扫 chat\*.jsonl 读各自的最后一条 meta,没有额外索引文件。
 */
#ifndef AGENT_THREAD_STORE_H
#define AGENT_THREAD_STORE_H

#include "common.h"
#include "json.h"

#define THREAD_SCHEMA 2

/* 数据目录(只需给一次;之后各接口都用它) */
void thread_store_init(const char *data_dir);

/* 打开/新建一个会话,返回 meta(调用方 json_free)。
   标题为空时用"未命名对话",等第一条用户消息来了再补。 */
json_t *thread_ensure(const char *thread_id, const char *title);

/* 追加一条消息,返回新消息的 JSON(调用方 json_free)。
   blocks 是内容块数组(所有权转移);usage 可为 NULL。
   parent_id 为空表示接着最后一条。 */
json_t *thread_append(const char *thread_id, const char *role, json_t *blocks,
                      json_t *usage, const char *parent_id);

/* 追加一条事件(不给界面看的东西也留在这里:步骤、审批、停止原因) */
void thread_append_event(const char *thread_id, json_t *event);

/* 会话列表(按 updated_at 倒序),字段: id/title/created_at/updated_at/
   archived/pinned/message_count/last_seq  */
json_t *thread_list(void);

/* 读一个会话的全部消息(数组) 。limit<=0 表示不限 */
json_t *thread_messages(const char *thread_id, int limit);

/* 元数据 */
json_t *thread_get(const char *thread_id);
int     thread_set_title(const char *thread_id, const char *title);
int     thread_set_flags(const char *thread_id, int archived, int pinned);
int     thread_delete(const char *thread_id);


/* 拼一条纯文本消息(给只关心"说了什么"的调用方用,例如提示词里的历史) */
json_t *thread_blocks_text(const char *text);

#endif /* AGENT_THREAD_STORE_H */
