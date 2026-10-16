/* http.h —— 内置的本地 HTTP + SSE 服务(零第三方依赖,只用 winsock2)。
 *
 * 为什么 C 版要自己写一个 HTTP 服务:
 *   界面层要和智能体说话。可选方案有两条 ——
 *     (a) 把界面嵌进进程(WebView2 嵌入模式)—— 本机不可用,见 exp/probe.c 的取证结论;
 *     (b) 让界面当一个普通网页,跑在系统浏览器里,通过 HTTP 和智能体通信 —— 本方案。
 *   选 (b) 的好处:后端与界面彻底解耦,换前端不用动 C 代码;
 *   而且"网络安全工具开一个本地端口"这件事本身就要求我们把边界收紧:
 *     只绑回环地址(127.0.0.1)、只服务白名单里的静态文件、路径穿越一律拒绝。
 *
 * 流式协议沿用 Python 版的三册合同(stream.py 的六个事件),
 * 只把传输层从 WebSocket 换成 SSE —— 事件 JSON 一字不改,前端同一套代码能用。
 */
#ifndef AGENT_HTTP_H
#define AGENT_HTTP_H

#include "common.h"
#include "json.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

/* 一条进来的请求 */
typedef struct {
  char method[8];
  char path[512];      /* 不含查询串,已 URL 解码 */
  char raw_path[512];
  char query[1024];    /* ? 之后的部分(未解码,取值时按 key 解) */
  char *body;          /* 可能为 NULL */
  size_t body_len;
  int keep_alive;
} http_req_t;

/* 应答通道。send_header 之后状态码/头就定死了。 */
typedef struct {
  SOCKET sock;
  int header_sent;
  int status;
  int aborted;         /* 对端断开 */
} http_res_t;

/* 路由处理函数 */
typedef void (*http_handler_t)(const http_req_t *req, http_res_t *res, void *ud);

/* ---------- 请求参数 ---------- */
/* 取查询参数(自动 URL 解码);没找到返回 def 的副本 */
const char *http_query(const http_req_t *req, const char *key, char *out, size_t cap,
                       const char *def);
char *http_url_decode(const char *s);      /* 调用方 free */

/* ---------- 普通应答 ---------- */
void http_res_text(http_res_t *res, int status, const char *ctype, const char *body);
void http_res_json(http_res_t *res, int status, const char *json);
void http_res_404(http_res_t *res);
/* 二进制应答(图标之类不能用字符串发,遇到 0 字节会被截断) */
void http_res_bytes(http_res_t *res, int status, const char *ctype, const char *data,
                    size_t len);

/* ---------- SSE(服务端推送,给界面做流式) ---------- */
/* 发 SSE 头;返回 1 成功,0 对端已断开。之后反复调 http_sse_json 推事件。 */
int http_sse_begin(http_res_t *res);
/* 推一条事件:自动拼成 "data: {json}\n\n" 并立即 flush;返回 1 表示还能继续推 */
int http_sse_json(http_res_t *res, const char *json);

/* ---------- 服务生命周期 ---------- */
int  http_startup(void);
void http_shutdown(void);
/* 阻塞式运行。只绑 loopback(bind_ip 传 NULL 即 127.0.0.1)。
   返回非 0 表示端口占用/启动失败,具体原因见 http_last_error()。 */
int  http_serve(const char *bind_ip, int port, http_handler_t handler, void *ud);
void http_stop(void);
const char *http_last_error(void);
/* 是否绑定成功(供启动脚本提示"服务已就绪") */
int  http_is_running(void);

#endif /* AGENT_HTTP_H */
