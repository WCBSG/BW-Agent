/* serve.c —— 本地 HTTP 服务 + 智能体循环的流式直播。
 *
 * 事件协议照抄 Python 版第三册合同(stream.py)的六个事件:
 *   message_start / block_start / block_delta / block_stop / tool_status / message_stop
 * 只把传输层从 WebSocket 换成 SSE —— 前端同一套解析代码能用。
 *
 * 一个关键设计:**循环是同步跑的,hooks 是它的"直播口"**。
 * agent_run_turn 每推进一步就回调一次,回调里把事件写进 SSE 连接,
 * 浏览器立刻就看到 —— 不需要在 C 里搞协程或异步。
 * 代价是一次只能有一轮对话在跑,所以用临界区把并发挡在门外(界面本来就单人用)。
 */
#include "serve.h"

#include <bcrypt.h>
#include <signal.h>

#include "agent.h"
#include "embed.h"
#include "http.h"
#include "llm.h"
#include "net.h"
#include "res.h"
#include "rules.h"
#include "skills.h"
#include "store.h"
#include "tools.h"
#include "ui.h"

static store_t *g_store = NULL;
static agent_t *g_agent = NULL;
static CRITICAL_SECTION g_lock;
static CRITICAL_SECTION g_status_lock;
/* 会话状态用缓存发出去:外面查状态时绝不阻塞正在跑的循环 ——
   循环一跑就是几十秒,界面这时候不该卡住 */
static char *g_status_cache = NULL;
static char g_session[128] = "web-session";
static char g_task[64] = "WEB-TASK";
static char g_domain[256] = "";
static int g_turn_seq = 0;
static char g_data_dir[512];
/* 每次启动生成的接口令牌:只给本程序打开的界面用。
   为什么必须有它:本地 HTTP 服务只绑回环,但用户浏览器里的**任何网页**都能
   向 127.0.0.1 发简单请求(form/text-plain 的 POST 不触发预检),那样别人的页面
   就能改我们的授权目标、甚至借我们的手去扫第三方。令牌 + Host/Origin 校验把这条路堵掉。 */
static char g_token[64] = "";
static int g_port = 0;

/* ---------- SSE 直播上下文 ---------- */
typedef struct {
  http_res_t *res;
  char message_id[64];
  int index;                 /* 下一个内容块的 index */
  int step;                  /* 第几步 */
  int tool_seq;
  char tool_use_id[96];
  int text_open;             /* 当前是否有打开的 text 块 */
  int tool_open;             /* 当前是否有打开的 tool_use 块 */
  char pending_note[512];    /* 比动作先到的状态说明,等卡片开出来再填 */
  int aborted;
} sse_ctx_t;

static sse_ctx_t *g_sse = NULL;

static void sse_send(sse_ctx_t *c, const char *json) {
  if (!c || c->aborted) return;
  if (!http_sse_json(c->res, json)) c->aborted = 1;
}

/* ================= 事件构造 ================= */

static void ev_message_start(sse_ctx_t *c) {
  char ts[64];
  now_iso(ts, sizeof(ts));
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"type\":\"message_start\",\"messageId\":");
  buf_json_str(&b, c->message_id);
  buf_puts(&b, ",\"sessionId\":");
  buf_json_str(&b, g_session);
  buf_puts(&b, ",\"timestamp\":");
  buf_json_str(&b, ts);
  buf_puts(&b, "}");
  sse_send(c, b.data);
  buf_free(&b);
}

static void ev_block_start(sse_ctx_t *c, int index, const char *type,
                           const char *tool_use_id, const char *tool_name) {
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"type\":\"block_start\",\"messageId\":");
  buf_json_str(&b, c->message_id);
  buf_printf(&b, ",\"index\":%d,\"blockType\":", index);
  buf_json_str(&b, type);
  if (!strcmp(type, "tool_use")) {
    buf_puts(&b, ",\"toolUseId\":");
    buf_json_str(&b, tool_use_id ? tool_use_id : "");
    buf_puts(&b, ",\"toolName\":");
    buf_json_str(&b, tool_name ? tool_name : "");
  }
  buf_puts(&b, "}");
  sse_send(c, b.data);
  buf_free(&b);
}

static void ev_block_delta_text(sse_ctx_t *c, int index, const char *text) {
  if (!text || !*text) return;
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"type\":\"block_delta\",\"messageId\":");
  buf_json_str(&b, c->message_id);
  buf_printf(&b, ",\"index\":%d,\"delta\":{\"type\":\"text_delta\",\"text\":", index);
  buf_json_str(&b, text);
  buf_puts(&b, "}}");
  sse_send(c, b.data);
  buf_free(&b);
}

static void ev_block_delta_json(sse_ctx_t *c, int index, const char *partial) {
  if (!partial || !*partial) return;
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"type\":\"block_delta\",\"messageId\":");
  buf_json_str(&b, c->message_id);
  buf_printf(&b,
             ",\"index\":%d,\"delta\":{\"type\":\"input_json_delta\",\"partialJson\":",
             index);
  buf_json_str(&b, partial);
  buf_puts(&b, "}}");
  sse_send(c, b.data);
  buf_free(&b);
}

static void ev_block_stop(sse_ctx_t *c, int index) {
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"type\":\"block_stop\",\"messageId\":");
  buf_json_str(&b, c->message_id);
  buf_printf(&b, ",\"index\":%d}", index);
  sse_send(c, b.data);
  buf_free(&b);
}

static void ev_tool_status(sse_ctx_t *c, const char *tool_use_id,
                           const char *status, const char *note) {
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"type\":\"tool_status\",\"toolUseId\":");
  buf_json_str(&b, tool_use_id ? tool_use_id : "");
  buf_puts(&b, ",\"status\":");
  buf_json_str(&b, status);
  buf_puts(&b, ",\"note\":");
  buf_json_str(&b, note ? note : "");
  buf_puts(&b, "}");
  sse_send(c, b.data);
  buf_free(&b);
}

static void ev_message_stop(sse_ctx_t *c, const char *stop_reason) {
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"type\":\"message_stop\",\"messageId\":");
  buf_json_str(&b, c->message_id);
  buf_puts(&b, ",\"stopReason\":");
  buf_json_str(&b, stop_reason);
  buf_puts(&b, "}");
  sse_send(c, b.data);
  buf_free(&b);
}

/* ================= 循环 → 事件 的翻译层 ================= */

static void t_close_text(sse_ctx_t *c) {
  if (c->text_open) {
    ev_block_stop(c, c->index);
    c->index++;
    c->text_open = 0;
  }
}

static void t_close_tool(sse_ctx_t *c) {
  if (c->tool_open) {
    ev_block_stop(c, c->index);
    c->index++;
    c->tool_open = 0;
  }
}

/* 一条文本块:开了就续写,没开就开 */
static void t_put_text(sse_ctx_t *c, const char *text) {
  if (!text || !*text) return;
  if (!c->text_open) {
    ev_block_start(c, c->index, "text", NULL, NULL);
    c->text_open = 1;
  }
  ev_block_delta_text(c, c->index, text);
}

static void hook_thinking(void *ud, const char *text) {
  (void)ud;
  sse_ctx_t *c = g_sse;
  if (!c) return;
  t_close_tool(c);
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "\n[第 ");
  buf_printf(&b, "%d", c->step + 1);
  buf_puts(&b, " 步 · 思考] ");
  buf_puts(&b, text ? text : "");
  buf_puts(&b, "\n");
  t_put_text(c, b.data);
  buf_free(&b);
}

static void hook_action(void *ud, const char *tool, json_t *args, const char *reason) {
  (void)ud;
  sse_ctx_t *c = g_sse;
  if (!c) return;

  c->step++;
  t_close_text(c);
  t_close_tool(c);

  snprintf(c->tool_use_id, sizeof(c->tool_use_id), "tu-%s-%d",
           c->message_id, ++c->tool_seq);

  ev_block_start(c, c->index, "tool_use", c->tool_use_id, tool);
  c->tool_open = 1;

  char *dump = args ? json_dump(args) : NULL;
  ev_block_delta_json(c, c->index, dump ? dump : "{}");
  if (dump) free(dump);

  /* 状态说明可能比动作先到(agent.c 在"决定要做"时就广播了一次状态),
     那种情况下用暂存的那条,否则用决策理由 */
  if (c->pending_note[0]) {
    ev_tool_status(c, c->tool_use_id, "running", c->pending_note);
    c->pending_note[0] = 0;
  } else {
    ev_tool_status(c, c->tool_use_id, "running",
                   reason && *reason ? reason : "开始执行");
  }
}

static void hook_status(void *ud, const char *tool, const char *status, const char *note) {
  (void)ud;
  sse_ctx_t *c = g_sse;
  if (!c) return;
  buf_t b;
  buf_init(&b);
  buf_puts(&b, tool ? tool : "");
  if (status && *status) buf_printf(&b, " %s", status);
  if (note && *note) buf_printf(&b, " —— %s", note);
  if (c->tool_open) {
    ev_tool_status(c, c->tool_use_id, "running", b.data);
  } else {
    /* 还没有对应的工具卡片:先存着,别把状态挂到上一张卡上 */
    snprintf(c->pending_note, sizeof(c->pending_note), "%s", b.data);
  }
  buf_free(&b);
}

static void hook_observation(void *ud, const char *tool, tool_result_t *r) {
  (void)ud;
  sse_ctx_t *c = g_sse;
  if (!c) return;
  ev_tool_status(c, c->tool_use_id, (r && r->is_error) ? "error" : "done",
                 (r && r->text) ? r->text : "");
  t_close_tool(c);
}

static void hook_answer(void *ud, const char *text) {
  (void)ud;
  sse_ctx_t *c = g_sse;
  if (!c) return;
  t_close_tool(c);
  t_put_text(c, text);
  t_close_text(c);
}

static void hook_ask(void *ud, const char *text) {
  (void)ud;
  sse_ctx_t *c = g_sse;
  if (!c) return;
  t_close_tool(c);
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "\n[需要你补充信息] ");
  buf_puts(&b, text ? text : "");
  buf_puts(&b, "\n");
  t_put_text(c, b.data);
  buf_free(&b);
  t_close_text(c);
}

static const agent_hooks_t g_hooks = {
    NULL, hook_thinking, hook_action, hook_status,
    hook_observation, hook_answer, hook_ask};

/* ================= 会话状态 ================= */

/* 从"用户填的目标"里拆出主机与端口(可能是 host:port,也可能带协议与路径) */
static void apply_scope(const char *domain) {
  if (domain && *domain) {
    snprintf(g_domain, sizeof(g_domain), "%s", domain);
    /* 授权范围只认主机名(端口不参与授权判断),但端口要拿去做"地址对齐":
       否则用户写 127.0.0.1 而站点在 8899 时,请求全会打到 443 上去。 */
    char host_only[256];
    net_host_port_of(domain, host_only, sizeof(host_only));
    if (!host_only[0]) snprintf(host_only, sizeof(host_only), "%s", domain);
    net_align_base_from(domain);
    const char *doms[1];
    doms[0] = host_only;
    /* 授权范围一确定,就把"任务"与"敏感信息定义"落成正式业务对象:
       任务 = 授权域名 + 只读约束 + 用哪套定义。报告与历史页都引用它,
       这样"这次巡检为什么合法、按什么口径"是可查的,而不是只存在于会话里。 */
    if (g_store) {
      int nk = 0, nf = 0;
      const char **kw = rules_str_list("profile_keywords", &nk);
      const char **ft = rules_str_list("profile_file_types", &nf);
      json_t *kws = j_arr();
      for (int i = 0; i < nk; i++) j_add(kws, j_str(kw[i]));
      json_t *fts = j_arr();
      for (int i = 0; i < nf; i++) j_add(fts, j_str(ft[i]));
      char *pid = store_ensure_profile(g_store, "默认敏感信息定义(随规则层)",
                                      kws, fts, NULL);
      char tname[320];
      snprintf(tname, sizeof(tname), "对 %s 的授权巡检", g_domain);
      char *tid = store_ensure_task(g_store, doms, 1, tname, pid);
      if (tid) snprintf(g_task, sizeof(g_task), "%s", tid);
      free(pid);
      free(tid);
      json_free(kws);
      json_free(fts);
    }
    agent_set_scope(g_agent, g_task, doms, 1);
  } else {
    g_domain[0] = 0;
    agent_set_scope(g_agent, g_task, NULL, 0);
  }
}

static char *build_status_json(void) {
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"ok\":true,\"sessionId\":");
  buf_json_str(&b, g_session);
  buf_puts(&b, ",\"taskId\":");
  buf_json_str(&b, g_task);
  buf_puts(&b, ",\"domain\":");
  buf_json_str(&b, g_domain);
  buf_printf(&b, ",\"authorized\":%s", g_domain[0] ? "true" : "false");
  buf_printf(&b, ",\"model\":%s", llm_enabled() ? "true" : "false");
  buf_puts(&b, ",\"modelName\":");
  buf_json_str(&b, llm_enabled() ? "恒脑智能体(在线)" : "本地规则降级(离线可用)");
  buf_printf(&b, ",\"tools\":%d,\"skills\":%d", tools_count(), skills_count());
  buf_printf(&b, ",\"maxSteps\":%d", MAX_STEPS_DEFAULT);

  json_t *findings = store_all(g_store, "findings");
  int n = findings ? j_len(findings) : 0;
  buf_printf(&b, ",\"findingCount\":%d", n);
  buf_puts(&b, ",\"findings\":");
  if (findings) {
    char *dump = json_dump(findings);
    buf_puts(&b, dump ? dump : "[]");
    if (dump) free(dump);
    json_free(findings);
  } else {
    buf_puts(&b, "[]");
  }
  buf_puts(&b, "}");
  char *out = buf_take(&b);
  buf_free(&b);
  return out;
}

/* 重建状态缓存(调用方必须已持有 g_lock) */
static void refresh_status_cache(void) {
  char *j = build_status_json();
  EnterCriticalSection(&g_status_lock);
  free(g_status_cache);
  g_status_cache = j;
  LeaveCriticalSection(&g_status_lock);
}

static char *status_snapshot(void) {
  EnterCriticalSection(&g_status_lock);
  char *j = xstrdup(g_status_cache ? g_status_cache : "{\"ok\":true}");
  LeaveCriticalSection(&g_status_lock);
  return j;
}

/* 每次启动换一把随机令牌(32 位十六进制)—— 换了进程就作废旧页面里的那把 */
static void make_token(char *out, size_t cap) {
  unsigned char raw[16];
  if (BCryptGenRandom(NULL, raw, (ULONG)sizeof(raw),
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
    /* 极端情况下退到时间+计数:令牌不完美也好过没有 */
    DWORD t = GetTickCount();
    for (size_t i = 0; i < sizeof(raw); i++) raw[i] = (unsigned char)((t >> ((i % 4) * 8)) ^ (i * 31));
  }
  size_t o = 0;
  for (size_t i = 0; i < sizeof(raw) && o + 2 < cap; i++) {
    o += (size_t)snprintf(out + o, cap - o, "%02x", raw[i]);
  }
  out[o < cap ? o : cap - 1] = 0;
}

/* Host 头是不是本机:只认 127.0.0.1 / localhost[/::1] 且端口一致 */
static int host_ok(const http_req_t *req) {
  if (!req->host[0]) return 1;                 /* HTTP/1.0 或本地测试客户端没带 Host */
  const char *h = req->host;
  int loopback = (strncmp(h, "127.0.0.1", 9) == 0) ||
                 (strncmp(h, "localhost", 9) == 0) ||
                 (strncmp(h, "[::1]", 5) == 0);
  if (!loopback) return 0;
  const char *colon = strrchr(h, ':');
  if (colon && g_port > 0) {
    int p = atoi(colon + 1);
    if (p != g_port) return 0;                 /* 端口不对:多半是被别的服务/别的端口映射 */
  }
  return 1;
}

/* Origin 只在跨站请求时才有;有就必须是本站 */
static int origin_ok(const http_req_t *req) {
  if (!req->origin[0]) return 1;
  char expect1[64], expect2[64];
  snprintf(expect1, sizeof(expect1), "http://127.0.0.1:%d", g_port);
  snprintf(expect2, sizeof(expect2), "http://localhost:%d", g_port);
  return str_ieq(req->origin, expect1) || str_ieq(req->origin, expect2);
}

static int token_ok(const http_req_t *req) {
  if (!g_token[0]) return 1;                   /* 理论上不会发生 */
  if (req->token[0] && strcmp(req->token, g_token) == 0) return 1;
  /* EventSource 不能自定义请求头,所以查询串里带一把也算 */
  char t[sizeof(g_token)];
  http_query(req, "t", t, sizeof(t), "");
  return t[0] && strcmp(t, g_token) == 0;
}

/* /api/* 的统一门禁:Host → Origin → 令牌 → POST 只收 JSON */
static int api_guard(const http_req_t *req, http_res_t *res) {
  if (!host_ok(req)) {
    log_warn("[接口] 拒绝请求:Host=%s 不是本机", req->host);
    http_res_text(res, 403, "application/json; charset=utf-8",
                  "{\"ok\":false,\"error\":\"只接受来自本机地址的请求\"}");
    return 0;
  }
  if (!origin_ok(req)) {
    log_warn("[接口] 拒绝请求:Origin=%s 不是本站", req->origin);
    http_res_text(res, 403, "application/json; charset=utf-8",
                  "{\"ok\":false,\"error\":\"跨站来源被拒绝\"}");
    return 0;
  }
  if (!token_ok(req)) {
    http_res_text(res, 401, "application/json; charset=utf-8",
                  "{\"ok\":false,\"error\":\"缺少或错误的接口令牌(请从本程序打开的界面操作)\"}");
    return 0;
  }
  if (strcmp(req->method, "POST") == 0 && req->body_len > 0 &&
      !str_icontains(req->content_type, "application/json")) {
    http_res_text(res, 415, "application/json; charset=utf-8",
                  "{\"ok\":false,\"error\":\"只接受 application/json\"}");
    return 0;
  }
  return 1;
}

/* ================= 静态界面资源 ================= */

typedef struct {
  const char *name;
  const char *ctype;
} ui_asset_t;

static const ui_asset_t g_assets[] = {
    {"index.html", "text/html; charset=utf-8"},
    {"app.css", "text/css; charset=utf-8"},
    {"app.js", "application/javascript; charset=utf-8"},
    {"logo.ico", "image/x-icon"},
    {"logo.png", "image/png"},
    {"favicon.ico", "image/x-icon"},
    {NULL, NULL}};

/* 只允许白名单里的文件名 —— 目录穿越在"安全工具"里尤其不能有 */
static const char *asset_type(const char *name) {
  for (int i = 0; g_assets[i].name; i++) {
    if (strcmp(g_assets[i].name, name) == 0) return g_assets[i].ctype;
  }
  return NULL;
}

static void serve_asset(const char *name, http_res_t *res) {
  const char *ctype = asset_type(name);
  if (!ctype) {
    http_res_404(res);
    return;
  }
  /* 先看磁盘上的 ui\(可定制),没有就用编进 exe 里的那份(单文件也能跑) */
  char rel[256];
  snprintf(rel, sizeof(rel), "ui/%s", name);
  char *data = NULL;
  size_t len = 0;
  if (!res_load_text(rel, &data, &len)) {
    log_warn("界面资源取不到: %s(磁盘与内置都没有)", rel);
    http_res_text(res, 500, "application/json; charset=utf-8",
                  "{\"ok\":false,\"error\":\"界面资源缺失\"}");
    return;
  }
  if (strcmp(ctype, "image/x-icon") == 0 || strcmp(ctype, "image/png") == 0) {
    http_res_bytes(res, 200, ctype, data, len);      /* 图标是二进制,不能当字符串发 */
    free(data);
    return;
  }
  if (strcmp(name, "index.html") == 0) {
    /* 把本次的接口令牌注入页面(head 里加一个 meta),界面脚本从这里取。
       注入发生在"发送时",所以磁盘替换的界面同样适用,不需要改 ui\ 里的文件。 */
    buf_t b;
    buf_init(&b);
    const char *tag = "<meta name=\"bw-token\"";
    const char *at = strstr(data, tag);
    if (at) {
      /* 界面自己写了占位 meta:把 content 填进去 */
      size_t head = (size_t)(at - data);
      buf_putn(&b, data, head);
      buf_puts(&b, "<meta name=\"bw-token\" content=\"");
      buf_puts(&b, g_token);
      buf_puts(&b, "\">");
      const char *gt = strchr(at, '>');
      buf_puts(&b, gt ? gt + 1 : "");
    } else {
      const char *head_end = strstr(data, "</head>");
      size_t head = head_end ? (size_t)(head_end - data) : len;
      buf_putn(&b, data, head);
      buf_printf(&b, "<meta name=\"bw-token\" content=\"%s\">", g_token);
      buf_puts(&b, data + head);
    }
    http_res_text(res, 200, ctype, b.data);
    buf_free(&b);
    free(data);
    return;
  }
  http_res_text(res, 200, ctype, data);
  free(data);
}

/* ================= 路由 ================= */

static void h_health(const http_req_t *req, http_res_t *res) {
  (void)req;
  buf_t b;
  buf_init(&b);
  buf_printf(&b, "{\"ok\":true,\"service\":\"网站安全巡检智能体(C 版)\",\"pid\":%lu}",
             (unsigned long)GetCurrentProcessId());
  http_res_json(res, 200, b.data);
  buf_free(&b);
}

static void h_manifest(const http_req_t *req, http_res_t *res) {
  (void)req;
  buf_t b;  buf_init(&b);
  buf_puts(&b, "{\"tools\":");
  char *t = json_dump(agent_tool_list_json());
  buf_puts(&b, t);
  free(t);
  buf_puts(&b, ",\"skills\":");
  char *s = json_dump(agent_skill_list_json());
  buf_puts(&b, s);
  free(s);
  buf_puts(&b, "}");
  http_res_json(res, 200, b.data);
  buf_free(&b);
}

static void h_status(const http_req_t *req, http_res_t *res) {
  (void)req;
  char *j = status_snapshot();
  http_res_json(res, 200, j);
  free(j);
}

/* ================= 只读数据接口(界面用:闭环数据从这里看) =================
   全部只读、只绑回环、按集合名白名单取值 —— 界面能看什么由后端说了算。 */
static void h_collection(const http_req_t *req, http_res_t *res) {
  char name[32];
  http_query(req, "name", name, sizeof(name), "findings");
  static const char *ALLOWED[] = {"findings", "assets", "alerts", "runs", "reports",
                                  "evals", "tasks", "profiles", "testcases",
                                  "baselines", "diffs", NULL};
  int ok = 0;
  for (int i = 0; ALLOWED[i]; i++) if (strcmp(ALLOWED[i], name) == 0) ok = 1;
  if (!ok) {
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"不在白名单里的集合名\"}");
    return;
  }
  char limit_s[16];
  http_query(req, "limit", limit_s, sizeof(limit_s), "50");
  int limit = atoi(limit_s);
  if (limit <= 0 || limit > 500) limit = 50;

  json_t *all = store_all(g_store, name);
  json_t *out = j_arr();
  int n = j_len(all);
  int from = n > limit ? n - limit : 0;      /* 取最近的若干条(时间序在后) */
  for (int i = from; i < n; i++) j_add(out, json_parse(json_dump(j_at(all, i))));
  json_t *root = j_obj();
  j_set_str(root, "ok", "true");
  j_set_str(root, "collection", name);
  j_set_num(root, "total", n);
  j_set(root, "items", out);
  char *text = json_dump(root);
  http_res_json(res, 200, text);
  free(text);
  json_free(root);
  json_free(all);
}

/* 规则层现状:"这次巡查按什么定义做的"必须能自证 */
static void h_rules(const http_req_t *req, http_res_t *res) {
  (void)req;
  json_t *root = j_obj();
  j_set_bool(root, "ok", 1);
  j_set_str(root, "source", rules_source());
  j_set_bool(root, "from_file", rules_from_file());
  json_t *sigs = j_arr();
  int n = 0;
  json_t *arr = rules_root() ? j_get(rules_root(), "signatures") : NULL;
  for (int i = 0; i < j_len(arr); i++) {
    json_t *s = j_at(arr, i);
    json_t *o = j_obj();
    j_set_str(o, "name", j_s(s, "name", ""));
    j_set_str(o, "kind", j_s(s, "kind", ""));
    j_set_str(o, "severity", j_s(s, "severity", ""));
    j_set_str(o, "tag", j_s(s, "tag", ""));
    j_add(sigs, o);
    n++;
  }
  j_set_num(root, "signature_count", n);
  j_set(root, "signatures", sigs);
  const char **list = NULL;
  int np = 0;
  list = rules_str_list("sensitive_paths", &np);
  json_t *paths = j_arr();
  for (int i = 0; i < np; i++) j_add(paths, j_str(list[i]));
  j_set(root, "sensitive_paths", paths);
  int nd = 0;
  const char **dirs = rules_str_list("dir_candidates", &nd);
  json_t *darr = j_arr();
  for (int i = 0; i < nd; i++) j_add(darr, j_str(dirs[i]));
  j_set(root, "dir_candidates", darr);
  char *text = json_dump(root);
  http_res_json(res, 200, text);
  free(text);
  json_free(root);
}
/* 只在"用户明确声明已获授权"时才把目标写进授权范围 —— 合规的第一道闸 */
static void h_scope(const http_req_t *req, http_res_t *res) {
  json_t *body = req->body ? json_parse(req->body) : NULL;
  const char *domain = body ? j_s(body, "domain", "") : "";
  int authorized = body ? (int)j_n(body, "authorized", 0) : 0;
  if (!domain[0] || !authorized) {
    if (body) json_free(body);
    http_res_json(res, 400,
                  "{\"ok\":false,\"error\":\"需提供 domain 且 authorized 必须为真\"}");
    return;
  }
  EnterCriticalSection(&g_lock);
  apply_scope(domain);
  refresh_status_cache();
  char *j = status_snapshot();
  LeaveCriticalSection(&g_lock);
  store_audit(g_store, "设置授权范围", domain, 1, "界面确认已获授权", g_task, "");
  if (body) json_free(body);
  http_res_json(res, 200, j);
  free(j);
}

static void h_chat(const http_req_t *req, http_res_t *res) {
  char q[4096];
  http_query(req, "q", q, sizeof(q), "");
  if (!q[0] && req->body) {
    json_t *body = json_parse(req->body);
    if (body) {
      snprintf(q, sizeof(q), "%s", j_s(body, "q", ""));
      json_free(body);
    }
  }
  if (!q[0]) {
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"缺少参数 q\"}");
    return;
  }

  if (!http_sse_begin(res)) return;

  sse_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.res = res;
  EnterCriticalSection(&g_lock);
  snprintf(ctx.message_id, sizeof(ctx.message_id), "msg-%04d", ++g_turn_seq);
  ev_message_start(&ctx);

  /* 循环是同步跑的,hooks 从 g_sse 里拿直播口 */
  g_sse = &ctx;
  agent_add_history(g_agent, "user", q);
  loop_state_t st;
  memset(&st, 0, sizeof(st));
  agent_run_turn(g_agent, q, &st);
  g_sse = NULL;

  const char *reason = st.stop_reason[0] ? st.stop_reason : "已完成";
  const char *stop = (st.stop_code == STOP_NEED_USER) ? "refusal" : "end_turn";
  if (st.stop_code == STOP_ANSWERED || st.stop_code == STOP_ANSWERING_ONLY) {
    stop = "end_turn";
  }

  /* 收尾把"为什么停"也播出去 —— 这是智能体和脚本的区别,得让评审看见 */
  t_close_tool(&ctx);
  buf_t b;
  buf_init(&b);
  buf_printf(&b, "\n\n——— 本轮循环结束:共 %d 步,停止原因:%s ———\n",
             st.step_count, reason);
  t_put_text(&ctx, b.data);
  buf_free(&b);
  t_close_text(&ctx);
  ev_message_stop(&ctx, stop);

  buf_free(&st.transcript);
  if (st.steps) json_free(st.steps);
  refresh_status_cache();
  LeaveCriticalSection(&g_lock);
}

static void router(const http_req_t *req, http_res_t *res, void *ud) {
  (void)ud;
  if (strcmp(req->method, "GET") != 0 && strcmp(req->method, "POST") != 0) {
    http_res_json(res, 405, "{\"ok\":false,\"error\":\"方法不允许\"}");
    return;
  }
  const char *p = req->path;

  if (!strcmp(p, "/") || !strcmp(p, "/index.html")) {
    serve_asset("index.html", res);
    return;
  }
  if (str_startswith(p, "/ui/")) {
    serve_asset(p + 4, res);
    return;
  }
  /* 接口一律先过门禁:Host / Origin / 令牌 / 内容类型 */
  if (str_startswith(p, "/api/")) {
    if (!api_guard(req, res)) return;
    if (!strcmp(p, "/api/health")) { h_health(req, res); return; }
    if (!strcmp(p, "/api/manifest")) { h_manifest(req, res); return; }
    if (!strcmp(p, "/api/status")) { h_status(req, res); return; }
    if (!strcmp(p, "/api/rules")) { h_rules(req, res); return; }
    if (!strcmp(p, "/api/data")) { h_collection(req, res); return; }
    if (!strcmp(p, "/api/scope")) { h_scope(req, res); return; }
    if (!strcmp(p, "/api/chat")) { h_chat(req, res); return; }
    http_res_404(res);
    return;
  }
  /* 其它静态资源(css/js/图标)不带令牌也能取:它们是页面自己的一部分 */
  if (asset_type(p[0] == '/' ? p + 1 : p)) {
    serve_asset(p[0] == '/' ? p + 1 : p, res);
    return;
  }
  http_res_404(res);
}

/* ================= 入口 ================= */

static BOOL WINAPI on_console_ctrl(DWORD type) {
  if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
    printf("\n正在停止服务……\n");
    http_stop();
    return TRUE;
  }
  return FALSE;
}

int serve_run(const char *domain, int port, int open_ui) {
  if (port <= 0) port = 8765;
  if (!http_startup()) {
    printf("网络初始化失败:%s\n", http_last_error());
    return 1;
  }

  /* 运行数据统一放 <数据目录>(默认 C:\Users\<用户名>\.bw_agent),exe 放哪都行 */
  const char *ddir = app_data_dir();
  ensure_dir(ddir);
  res_bootstrap_data_dir();          /* 首次运行:把可改的规则与说明落一份到数据目录 */
  snprintf(g_data_dir, sizeof(g_data_dir), "%s", ddir);
  g_store = store_open(g_data_dir);
  {
    char audit_path[MAX_PATH * 2];
    app_data_path(audit_path, sizeof(audit_path), "audit.jsonl");
    net_set_audit_path(audit_path);
  }
  net_set_readonly(1);

  /* 演示靶站可能带端口:环境变量 TARGET_BASE_URL 指定真实站点地址 */
  {
    const char *base = getenv("TARGET_BASE_URL");
    if (base && *base) net_set_target_base(base);
  }

  InitializeCriticalSection(&g_lock);
  InitializeCriticalSection(&g_status_lock);
  /* 本次运行的接口令牌与端口:界面页面里会带上它,跨站请求拿不到 */
  g_port = port;
  make_token(g_token, sizeof(g_token));
  g_agent = agent_create(g_session);
  agent_set_store(g_agent, g_store, "");
  agent_set_hooks(g_agent, &g_hooks);
  apply_scope(domain);
  refresh_status_cache();

  printf("════════════════════════════════════════════════════════\n");
  printf("  网站安全巡检智能体(C 版) · 后端服务已启动\n");
  printf("════════════════════════════════════════════════════════\n");
  printf("  界面地址 : http://127.0.0.1:%d/\n", port);
  printf("  决策模型 : %s\n", llm_enabled() ? "恒脑智能体(在线)" : "本地规则降级(离线可用)");
  printf("  授权域名 : %s\n", g_domain[0] ? g_domain : "(未授权 —— 不会对外发请求)");
  printf("  工具/技能: %d 个 / %d 个\n", tools_count(), skills_count());
  /* 单文件交付:界面与默认规则已经在 exe 里,这里把来源说清楚(磁盘上有同名文件则优先用磁盘) */
  {
    int n = embed_count();
    printf("  自带资源 : %d 项(界面与默认规则已内置,无需附带任何目录)\n", n);
    if (res_exists("ui/index.html")) {
      long sz = file_size("ui\\index.html");
      if (sz >= 0) printf("  说明     : 检测到磁盘上的 ui\\ 目录,将优先使用它(可自行替换界面)\n");
      else printf("  说明     : 本次使用 exe 内置界面\n");
    }
  }
  printf("  数据目录 : %s\\\n", g_data_dir);
  printf("  停止服务 : 关掉本窗口或按 Ctrl+C\n\n");

  SetConsoleCtrlHandler(on_console_ctrl, TRUE);

  if (open_ui) {
    /* 界面用系统浏览器打开。为什么不用进程内嵌 WebView2 见 exp/probe.c 的取证结论。 */
    ui_open_url_async(port);
  }

  int serve_rc = http_serve(NULL, port, router, NULL);

  printf("服务已停止。\n");
  ui_close();
  int port_busy = (serve_rc != 0) && str_icontains(http_last_error(), "占用");
  agent_free(g_agent);
  store_close(g_store);
  free(g_status_cache);
  DeleteCriticalSection(&g_status_lock);
  DeleteCriticalSection(&g_lock);
  http_shutdown();
  if (port_busy) return 2;          /* 让调用方换个端口再试 */
  return serve_rc == 0 ? 0 : 1;
}
