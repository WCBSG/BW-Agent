/* net.h —— 取数通道:HTTPS 请求 + 合规三件事。
   所有对外请求都必须从这里走,这样"授权校验 / 限速 / 审计"就不可能被绕过。 */
#ifndef AGENT_NET_H
#define AGENT_NET_H

#include "common.h"
#include "io.h"
#include "json.h"

typedef struct {
  int status;          /* HTTP 状态码;0 = 没连上 */
  char *headers;       /* 原始响应头整块(CRLF 分隔)—— 弱配置判断必需 */
  char *body;
  size_t body_len;
  char *error;         /* 失败原因(网络类) */
  int rate_limited;    /* 这次是不是被限速拖过 */
  int ms;              /* 耗时 */
} http_resp_t;

/* 初始化(内部会初始化 WinHTTP 会话;退出时 net_shutdown) */
void net_init(void);
void net_shutdown(void);
/* 只读模式开关:为 1 时只允许 GET/HEAD(非破坏性要求,工具层也有一道) */
void net_set_readonly(int on);

/* 合规配置 */
void net_set_scope(const char *task_id, const char **domains, int count);
/* 授权池:允许访问的主机白名单(条目可写 host 或 host:port)。
   池子非空时它是唯一边界 —— "这一轮看哪个站"只是焦点,不是边界。 */
void net_pool_set(const char **entries, int count);
/* 从 pool.json 读授权池(返回条目数,读不到返回 -1) */
int net_pool_load_file(const char *path);
int  net_pool_count(void);
/* 授权池快照:把池里的条目原样拷一份出来(含 ! 不允许的条目,保持录入顺序)。
   "智能体要能说出授权列表"靠它 —— 只告诉模型"本轮焦点"一个域名时,
   用户说"把授权列表都巡检一遍"它无从下手。
   返回条目数;list 用 str_free_list(list, n) 释放。out 可为 NULL(只数个数)。 */
int  net_pool_snapshot(char ***out);
/* path 传 URL 的路径(可传 "/")。条目里可写 !host 或 !host/path 表示"不允许",
   不允许优先于允许 —— 用来表达"允许 exp.com,但除了 exp.com/admin/"。 */
int  net_pool_has(const char *host, int port, const char *path);
/* 最近一次请求是否因越权被拒(决策循环据此立刻收束) */
int  net_scope_violation(void);
void net_scope_violation_clear(void);
/* 这个 URL 现在能不能发:只判断,不发请求、不置越权标记。
   给"手上有一批候选地址,先筛掉越界的再取"用 —— 否则站内一条被 ! 规则
   排除的链接就能把整轮巡检打断,那不是合规,是误伤。 */
int  net_url_allowed(const char *url);
void net_set_audit_path(const char *path);
void net_set_rate_limit(double qps);
/* 叫停信号:请求发出之前检查一次,让"停止"能立刻生效 */
void net_set_cancel(volatile LONG *flag);
int  net_cancelled(void);

/* 增量回调:POST 的响应分块到达时调用(用于模型输出的边收边显示)。
   返回 1 表示"这一轮我收完了,不用再等"(例如已经读到 SSE 的 [DONE]):
   这时会立刻断开,而不是陪着对端把连接挂到超时。 */
typedef int (*net_stream_fn)(void *ud, const char *data, size_t len);
void net_post_stream(const char *url, const char *headers, int timeout_ms,
                     const char *body, net_stream_fn cb, void *ud, http_resp_t *resp);
void hn_http_post_stream(const char *url, const char *app_key, const char *sign,
                         const char *body, net_stream_fn cb, void *ud, http_resp_t *resp);

/* 取一段外部文本(技能/工具市场里的 .md/.json)。
   与"巡检目标"不同:这是使用者自己填的下载地址,属于依赖获取,不走授权池;
   但仍然限制协议、大小,并写审计。成功返回 0,out 用 free 释放。 */
int net_get_text(const char *url, char **out, size_t *out_len, char *err, size_t errcap);
/* 目标地址对齐:把巡检起点指向本地靶站(如 http://127.0.0.1:8081)或非默认端口的站点。
   只改"协议+端口",主机名不变 —— 授权校验只认域名,不受影响。
   不设置时该功能完全不生效(生产环境就是 https://<授权域名>)。 */
void net_set_target_base(const char *base);
/* 把 URL 的协议/端口对齐到 target base(主机相同才动),结果写进 out */
void net_align_url(const char *url, char *out, size_t cap);

/* 一次请求。method 只接受 GET/HEAD/POST(外部站点探测只允许 GET/HEAD)。
   失败不抛异常,把原因写进 resp->error;调用方必须判断 status/error。 */
void net_request(const char *url, const char *method, const char *content_type,
                 const char *body, size_t body_len, http_resp_t *resp);
void http_resp_free(http_resp_t *r);

/* 审计日志:一行一条 JSONL,只追加 */
void net_audit(const char *action, const char *target, int allowed, const char *detail,
               const char *run_id);

/* 已发起的请求计数(限流与报告用) */
int  net_http_calls(void);

/* ---------- 网络层实测工具 ----------
   连接句柄缓存复用这条路我们试过,但 A/B 实测显示 WinHTTP 会话已有连接池,
   缓存句柄没有可测量收益,所以没有采纳。下面这个基准命令保留下来:
   "优化到底有没有用"必须能当场量,而不是靠说法。 */
int  net_bench(const char *url, int n, int *out_conns, int *out_requests);

/* 模型端点专用 POST:带 appKey/sign 自定义头(见 net.c 说明) */
void hn_http_post(const char *url, const char *app_key, const char *sign,
                  const char *body, http_resp_t *resp);

/* 告警投递:POST JSON 到使用者配的 webhook(可选 Bearer 令牌) */
void net_webhook_post(const char *url, const char *token, const char *body,
                      http_resp_t *resp);

/* 兼容 tools.h 的取数回调形状 */
void *net_io(void);

/* 取数通道的实现(给工具层用):内部完成授权校验 → 限速 → 请求 → 审计 */
tools_io_t *net_io_impl(void);

/* 小工具:取主机名、判断是否同一主机 */
void net_host_of(const char *url, char *out, size_t cap);
int  net_same_host(const char *a, const char *b);

/* 从"用户填的地址"里拆出主机与端口(host / host:port / http://host:port/x 都认)。
   返回端口号;0 = 没写端口。 */
int  net_host_port_of(const char *in, char *host_out, size_t hcap);
/* 按用户填的地址设置"地址对齐基准":写了端口就对齐过去(443 用 https,其余用 http)。
   站点不在默认端口上时,这一步是"能不能取到内容"的关键。 */
void net_align_base_from(const char *host_or_url);

#endif /* AGENT_NET_H */
