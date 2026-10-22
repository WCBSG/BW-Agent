/* thread_store.h —— 对话存储 v2:按主流 Agent 的结构重做。
 *
 * 为什么改:以前是"一个 .jsonl 一行一条消息",够用但缺三样关键东西 ——
 *   ① 消息没有稳定 id 与父指针,没法分支/重生成/精确定位;
 *   ② 没有 thread 这个一等对象,标题、归档、置顶、消息数全靠每次扫文件现算;
 *   ③ 没有 schema 版本与事件流,升级和回放都没抓手。
 *
 * 现在的形状(和 Claude Code / ChatGPT / Cursor 那一类做法对齐):
 *
 *   threads/index.jsonl              追加式索引:一行一次变更(标题/归档/计数)
 *   threads/<tid>/meta.json          权威元数据(小文件,覆盖写)
 *   threads/<tid>/messages.jsonl     追加式消息:稳定 id + seq + parent_id + blocks[]
 *   threads/<tid>/events.jsonl       该会话的事件流(步骤/审批/停止),可回放
 *
 * 几个刻意的选择:
 *   · 消息只追加,永不改写 —— 崩在写一半也只会丢最后一行,不会把历史读坏;
 *   · meta 是快照、index 是流水 —— 列表页读 index 的最后一行就够,不用扫全部消息;
 *   · blocks 数组(text / tool_use / tool_result / thinking)与模型侧的内容块同构,
 *     界面按块渲染,不再从一段拼好的文字里猜哪句是工具输出;
 *   · parent_id 允许形成树:以后要"从这条重新生成"或"回到某个分支"不用改存储。
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

/* 把旧版 transcripts/<sid>.jsonl 迁进新结构(幂等;迁过的保留为 .migrated)。
   返回迁移的会话数。 */
int thread_migrate_legacy(void);

/* 拼一条纯文本消息(给只关心"说了什么"的调用方用,例如提示词里的历史) */
json_t *thread_blocks_text(const char *text);

#endif /* AGENT_THREAD_STORE_H */
