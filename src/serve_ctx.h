/* serve_ctx.h —— 接口实现拆到多个文件后,共用的一点进程状态。
 *
 * 拆文件是为了让人能一口气读完一个域(rules 归 rules、模型归模型),
 * 不是为了再造一层框架 —— 所以这里只借出三样东西:
 * 存储句柄、当前任务号、状态缓存刷新。
 *
 * 为什么是函数而不是 extern 变量:这几个状态由 serve.cpp 在启动时建好,
 * 别处只该"用",不该"改"。给访问器,越权赋值就写不出来。
 */
#ifndef AGENT_SERVE_CTX_H
#define AGENT_SERVE_CTX_H

#include "common.h"
#include "http.h"
#include "store.h"

/* 保存时的审计留痕(内部用 store_audit + 当前任务号) */
store_t *serve_store(void);
const char *serve_task_id(void);
void serve_audit_line(const char *action, const char *target, const char *detail);

/* 规则/配置改完之后重新算一次顶部状态,免得界面还显示旧口径 */
void serve_refresh_status(void);

#endif /* AGENT_SERVE_CTX_H */
