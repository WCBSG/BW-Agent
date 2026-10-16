/* serve.h —— 把智能体挂到本地 HTTP 上,给界面用。
 *
 * 界面(ui/)是一张普通网页:取 /api/status 看状态、用 EventSource 连
 * /api/chat 看决策循环的直播。C 进程只负责"跑循环 + 把每个事件推出去",
 * 不掺任何界面代码 —— 换前端不用重编 C。
 */
#ifndef AGENT_SERVE_H
#define AGENT_SERVE_H

#include "common.h"

/* 启动服务并阻塞运行直到 Ctrl+C。
   domain  = 授权域名(合规边界),传 NULL 表示不授权任何目标(只答不问,不动网络)
   port    = 监听端口,<=0 用默认 8765
   open_ui = 是否自动打开界面窗口 */
int serve_run(const char *domain, int port, int open_ui);

#endif /* AGENT_SERVE_H */
