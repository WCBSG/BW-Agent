/* serve.cpp —— 本地 HTTP 服务 + 智能体循环的流式直播。
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

#include <ctime>

#include "agent.h"
#include "approval.h"
#include "automation.h"
#include "embed.h"
#include "export.h"
#include "profile.h"
#include "regex.h"
#include "ext.h"
#include "http.h"
#include "llm.h"
#include "net.h"
#include "profile.h"
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
/* 授权池:允许被检查的主机白名单(host 或 host:port)。
   以前这里是"一个全局巡检目标",那样做有两个毛病:
     · 换一个站就得先改全局设置,不然智能体被自己的配置挡住;
     · 边界是"当前目标"而不是"允许的范围",一旦模型自己换个主机名就说不清了。
   现在边界就是池子:任务/周期规则各自从池里挑目标,越池的请求在 net 层就被掐断。 */
static char g_pool_file[512] = "";
static char g_pool_json[16384] = "{\"hosts\":[]}";
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

/* ================= 权限审批(动手之前先问一句) =================
 * 主流 Agent 的形态:动作被策略拦下时,界面出现一张"允许 / 拒绝"的卡,
 * 点下去才发现"这一轮还没结束"。这里用一条 SSE 事件 + 一个等待事件对象实现:
 *   循环线程卡在 WaitForSingleObject 上(连接还开着,可以继续推事件),
 *   用户点按钮走 POST /api/approval,SetEvent 把循环放行。
 * 超时按"拒绝"处理 —— 无人值守时宁可不动手。
 */
typedef struct {
  CRITICAL_SECTION lock;
  HANDLE event;
  char id[40];
  int decision;          /* 0 未定 / 1 允许 / 2 拒绝 */
  int pending;
} approval_slot_t;

static approval_slot_t g_appr;
static int g_appr_ready = 0;
static volatile LONG g_appr_seq = 0;

static void approval_init(void) {
  if (g_appr_ready) return;
  InitializeCriticalSection(&g_appr.lock);
  g_appr.event = CreateEventA(NULL, TRUE, FALSE, NULL);   /* 手动复位:决定一次只生效一次 */
  g_appr.pending = 0;
  g_appr.decision = 0;
  g_appr_ready = 1;
}

/* 循环线程调用:问一句,然后等。 */
static int hook_approval(void *ud, const char *tool, json_t *args, char **reason) {
  (void)ud;
  approval_init();
  if (reason) *reason = NULL;

  approval_action_t act = approval_decide(tool ? tool : "");
  if (act == APPROVAL_ALLOW) return 1;
  if (act == APPROVAL_DENY) {
    if (reason) *reason = xstrdup("按当前审批策略,这个动作被直接拒绝");
    return 0;
  }

  sse_ctx_t *c = g_sse;
  if (!c) {
    /* 无人值守(周期巡检)且策略是"询问":没有人在看,不能默认放行。
       这一轮就地停下,并在观察里写清原因 —— 想让它自己跑就把策略调成"全部允许"。 */
    if (reason) *reason = xstrdup("当前是「询问」策略,但这一轮没有界面在等确认");
    return 0;
  }

  char id[40];
  snprintf(id, sizeof(id), "ap-%ld-%04d", (long)GetCurrentProcessId(),
           (int)InterlockedIncrement(&g_appr_seq));

  EnterCriticalSection(&g_appr.lock);
  snprintf(g_appr.id, sizeof(g_appr.id), "%s", id);
  g_appr.decision = 0;
  g_appr.pending = 1;
  ResetEvent(g_appr.event);
  LeaveCriticalSection(&g_appr.lock);

  char *argtext = args ? json_dump(args) : NULL;
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"type\":\"approval_request\",\"id\":");
  buf_json_str(&b, id);
  buf_puts(&b, ",\"tool\":");
  buf_json_str(&b, tool ? tool : "");
  buf_puts(&b, ",\"args\":");
  buf_json_str(&b, argtext ? argtext : "{}");
  buf_puts(&b, ",\"policy\":");
  buf_json_str(&b, approval_mode_text());
  buf_puts(&b, "}");
  sse_send(c, b.data);
  buf_free(&b);
  free(argtext);

  /* 事件还在同一条 SSE 连接上:先把"等待确认"的状态播出去,界面据此画卡片 */
  ev_tool_status(c, c->tool_use_id, "waiting_approval", "等你确认:允许还是拒绝?");

  DWORD wait_ms = 15 * 60 * 1000;      /* 15 分钟没人理就当拒绝 */
  DWORD got = WaitForSingleObject(g_appr.event, wait_ms);

  EnterCriticalSection(&g_appr.lock);
  int decision = g_appr.decision;
  g_appr.pending = 0;
  LeaveCriticalSection(&g_appr.lock);

  if (got != WAIT_OBJECT_0 || decision == 0) {
    if (reason) *reason = xstrdup("等你确认超时了,这一步没有执行");
    return 0;
  }
  if (decision == 1) return 1;
  if (reason) *reason = xstrdup("你拒绝了这一步");
  return 0;
}

static const agent_hooks_t g_hooks = {
    NULL, hook_thinking, hook_action, hook_status,
    hook_observation, hook_answer, hook_ask, hook_approval};

/* ================= 会话状态 ================= */

/* 从"用户填的目标"里拆出主机与端口(可能是 host:port,也可能带协议与路径) */
/* 池子:读盘 / 落盘 / 应用到取数通道。
   文件就是人可读的一行一个 host(或 host:port),不搞二进制格式 ——
   "允许检查谁"这件事应该能被直接看见、被版本管理。 */
static void pool_apply(void) {
  json_t *root = json_parse(g_pool_json);
  if (!root) return;
  json_t *hosts = j_get(root, "hosts");
  const char *list[512];
  int n = 0;
  for (int i = 0; i < j_len(hosts) && n < 512; i++) {
    json_t *v = j_at(hosts, i);
    if (!v) continue;
    if (v->type == J_STR && v->str) list[n++] = v->str;
    else if (v->type == J_OBJ) list[n++] = j_s(v, "host", "");
  }
  net_pool_set(list, n);
  json_free(root);
}

static void pool_save(void) {
  if (!g_pool_file[0]) return;
  json_t *root = json_parse(g_pool_json);
  char *text = root ? json_dump_pretty(root) : NULL;
  if (text) file_write_all(g_pool_file, text, strlen(text));
  free(text);
  if (root) json_free(root);
}

static void pool_load(void) {
  app_data_path(g_pool_file, sizeof(g_pool_file), "pool.json");
  size_t len = 0;
  char *text = file_read_all(g_pool_file, &len);
  if (text && len > 0 && len < sizeof(g_pool_json)) {
    snprintf(g_pool_json, sizeof(g_pool_json), "%s", text);
  }
  free(text);
  if (!json_parse(g_pool_json)) snprintf(g_pool_json, sizeof(g_pool_json), "{\"hosts\":[]}");
  pool_apply();
}

/* 池内查询:返回 1 表示这个主机(可带端口)在池里 */
static int pool_contains(const char *entry) {
  if (!entry || !entry[0]) return 0;
  char host[256];
  int port = net_host_port_of(entry, host, sizeof(host));
  if (!host[0]) snprintf(host, sizeof(host), "%s", entry);
  return net_pool_has(host, port);
}

static int pool_add(const char *entry) {
  if (!entry || !entry[0]) return -1;
  if (strstr(entry, "://") || strchr(entry, '/') || strchr(entry, ' ')) return -1;
  json_t *root = json_parse(g_pool_json);
  if (!root) root = j_obj();
  json_t *hosts = j_get(root, "hosts");
  if (!hosts || hosts->type != J_ARR) { hosts = j_arr(); j_set(root, "hosts", hosts); }
  for (int i = 0; i < j_len(hosts); i++) {
    const char *cur = j_at(hosts, i)->type == J_STR ? j_at(hosts, i)->str : j_s(j_at(hosts, i), "host", "");
    if (str_ieq(cur, entry)) { json_free(root); return 0; }   /* 已在池里 */
  }
  j_add(hosts, j_str(entry));
  char *text = json_dump(root);
  snprintf(g_pool_json, sizeof(g_pool_json), "%s", text ? text : "{\"hosts\":[]}");
  free(text);
  json_free(root);
  pool_save();
  pool_apply();
  return 1;
}

static int pool_remove(const char *entry) {
  json_t *root = json_parse(g_pool_json);
  if (!root) return -1;
  json_t *hosts = j_get(root, "hosts");
  json_t *keep = j_arr();
  int removed = 0;
  for (int i = 0; i < j_len(hosts); i++) {
    json_t *v = j_at(hosts, i);
    const char *cur = v->type == J_STR ? v->str : j_s(v, "host", "");
    if (str_ieq(cur, entry)) { removed = 1; continue; }
    j_add(keep, json_parse(json_dump(v)));
  }
  j_set(root, "hosts", keep);
  char *text = json_dump(root);
  snprintf(g_pool_json, sizeof(g_pool_json), "%s", text ? text : "{\"hosts\":[]}");
  free(text);
  json_free(root);
  if (!removed) return 0;
  pool_save();
  pool_apply();
  return 1;
}

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
  buf_printf(&b, ",\"authorized\":%s", (g_domain[0] || net_pool_count() > 0) ? "true" : "false");
  buf_puts(&b, ",\"pool\":");          /* 授权池:界面上"能检查谁"就照这个渲染 */
  buf_puts(&b, g_pool_json);
  buf_printf(&b, ",\"poolSize\":%d", net_pool_count());
  /* 审批策略:界面顶栏要显示当前是哪一档,以及"全部允许"的警告标记 */
  buf_puts(&b, ",\"approval\":{\"active\":");
  buf_json_str(&b, approval_active_id());
  buf_puts(&b, ",\"name\":");
  buf_json_str(&b, approval_mode_text());
  buf_printf(&b, ",\"allowAll\":%s}", approval_is_allow_all() ? "true" : "false");
  buf_printf(&b, ",\"model\":%s", llm_enabled() ? "true" : "false");
  buf_puts(&b, ",\"modelName\":");
  buf_json_str(&b, llm_enabled() ? "恒脑智能体(在线)" : "本地规则降级(离线可用)");
  /* 为什么降级:把平台给的原因(如"租户不存在")如实带给界面,而不是只说"离线" */
  buf_puts(&b, ",\"modelError\":");
  buf_json_str(&b, llm_last_error());
  /* 上一次调用模型是否失败(界面据此把原因显示出来) */
  buf_printf(&b, ",\"modelFailed\":%s", llm_last_error()[0] ? "true" : "false");
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
/* /api/* 的统一门禁:Host → Origin → 令牌 → POST 只收 JSON。
   /api/health 是"存活探针",故意免令牌:它只回答"我在不在",不暴露任何数据,
   而运维脚本/端口探测(以及我们自己的"端口被占就换一个"逻辑)拿不到令牌。
   Host 与 Origin 仍然校验,所以别的网页还是打不进来。 */
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
  if (strcmp(req->path, "/api/health") != 0 && !token_ok(req)) {
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

/* ================= 配置文件的读写(前台可编辑) =================
   界面里要能直接改规则/技能/工具/MCP,不用去开记事本。安全边界写死在这里:
     · 只允许数据目录下的白名单文件:rules.json、mcp.json、skills\*.md、tools\*.json
     · 名字里不许出现 .. / 绝对路径 / 多层目录(只允许"一层子目录 + 文件名")
     · 单文件上限 256KB;写之前先备份成 <名字>.bak;JSON 必须先解析通过才落盘
   这样"能改配置"和"不能被当成任意文件写入漏洞"两件事同时成立。 */
#define CFG_MAX_BYTES (256 * 1024)

static int cfg_allowed(const char *name) {
  if (!name || !*name) return 0;
  size_t len = strlen(name);
  if (len > 128) return 0;
  if (strstr(name, "..") || strchr(name, ':') || name[0] == '\\' || name[0] == '/') return 0;
  int slash = 0;
  for (const char *p = name; *p; p++) {
    if (*p == '\\' || *p == '/') slash++;
  }
  int md = str_endswith(name, ".md");
  int js = str_endswith(name, ".json");
  if (!md && !js) return 0;
  if (slash == 0) {
    return strcmp(name, "rules.json") == 0 || strcmp(name, "mcp.json") == 0 ||
           strcmp(name, "rules.default.json") == 0;
  }
  if (slash != 1) return 0;
  if (str_startswith(name, "skills\\") || str_startswith(name, "skills/")) return md;
  if (str_startswith(name, "tools\\") || str_startswith(name, "tools/")) return js;
  return 0;
}

/* 把白名单名字解析成数据目录下的绝对路径;返回 1 成功 */
static int cfg_path(const char *name, char *out, size_t cap) {
  if (!cfg_allowed(name)) return 0;
  char norm[192];
  snprintf(norm, sizeof(norm), "%s", name);
  for (char *p = norm; *p; p++) if (*p == '/') *p = '\\';
  app_data_path(out, cap, norm);
  return 1;
}

static void h_config_list(const http_req_t *req, http_res_t *res) {
  (void)req;
  json_t *arr = j_arr();
  const char *fixed[] = {"rules.json", "mcp.json", NULL};
  for (int i = 0; fixed[i]; i++) {
    char path[MAX_PATH * 2];
    app_data_path(path, sizeof(path), fixed[i]);
    long sz = file_size(path);
    json_t *o = j_obj();
    j_set_str(o, "name", fixed[i]);
    j_set_bool(o, "exists", sz >= 0 ? 1 : 0);
    j_set_num(o, "size", sz > 0 ? (double)sz : 0);
    j_set_str(o, "group", strcmp(fixed[i], "rules.json") == 0 ? "检测口径" : "外部能力");
    j_add(arr, o);
  }
  /* skills\*.md 与 tools\*.json */
  const char *dirs[2][2] = {{"skills", ".md"}, {"tools", ".json"}};
  for (int d = 0; d < 2; d++) {
    char dir[MAX_PATH * 2];
    app_data_path(dir, sizeof(dir), dirs[d][0]);
    ensure_dir(dir);
    char **files = NULL;
    int n = ext_list_files(dir, dirs[d][1], &files);
    for (int i = 0; i < n; i++) {
      const char *full = files[i];
      const char *base = strrchr(full, '\\');
      base = base ? base + 1 : full;
      char name[192];
      snprintf(name, sizeof(name), "%s\\%s", dirs[d][0], base);
      json_t *o = j_obj();
      j_set_str(o, "name", name);
      j_set_bool(o, "exists", 1);
      j_set_num(o, "size", (double)file_size(full));
      j_set_str(o, "group", d == 0 ? "技能说明/技能包" : "外部工具");
      j_add(arr, o);
    }
    if (files) str_free_list(files, n);
  }
  char *dump = json_dump(arr);
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"ok\":true,\"files\":");
  buf_puts(&b, dump);
  buf_puts(&b, "}");
  http_res_json(res, 200, b.data);
  buf_free(&b);
  free(dump);
  json_free(arr);
}

static void h_config_get(const http_req_t *req, http_res_t *res) {
  char name[192];
  http_query(req, "name", name, sizeof(name), "");
  char path[MAX_PATH * 2];
  if (!cfg_path(name, path, sizeof(path))) {
    http_res_text(res, 400, "application/json; charset=utf-8",
                  "{\"ok\":false,\"error\":\"只允许编辑数据目录下的 rules.json / mcp.json / skills\\\\*.md / tools\\\\*.json\"}");
    return;
  }
  size_t len = 0;
  char *text = file_read_all(path, &len);
  buf_t b;
  buf_init(&b);
  if (!text) {
    buf_puts(&b, "{\"ok\":true,\"exists\":false,\"name\":");
    buf_json_str(&b, name);
    buf_puts(&b, ",\"content\":\"\"}");
  } else {
    if (len > CFG_MAX_BYTES) {
      buf_printf(&b, "{\"ok\":false,\"error\":\"文件超过 %dKB,请用记事本打开\"}", CFG_MAX_BYTES / 1024);
      http_res_json(res, 200, b.data);
      buf_free(&b);
      free(text);
      return;
    }
    buf_puts(&b, "{\"ok\":true,\"exists\":true,\"name\":");
    buf_json_str(&b, name);
    buf_printf(&b, ",\"size\":%d,\"content\":", (int)len);
    buf_json_str(&b, text);
    buf_puts(&b, "}");
    free(text);
  }
  http_res_json(res, 200, b.data);
  buf_free(&b);
}

/* 保存 + 校验规则:JSON 必须能解析(否则不落盘);落盘前留一份 .bak */
static void h_config_save(const http_req_t *req, http_res_t *res) {
  json_t *body = req->body ? json_parse(req->body) : NULL;
  const char *name = body ? j_s(body, "name", "") : "";
  const char *content = body ? j_s(body, "content", "") : "";
  if (!body || !name[0]) {
    if (body) json_free(body);
    http_res_text(res, 400, "application/json; charset=utf-8",
                  "{\"ok\":false,\"error\":\"需要 name 与 content\"}");
    return;
  }
  char path[MAX_PATH * 2];
  if (!cfg_path(name, path, sizeof(path))) {
    json_free(body);
    http_res_text(res, 400, "application/json; charset=utf-8",
                  "{\"ok\":false,\"error\":\"文件名不在白名单里\"}");
    return;
  }
  size_t len = strlen(content);
  if (len > CFG_MAX_BYTES) {
    json_free(body);
    http_res_text(res, 400, "application/json; charset=utf-8",
                  "{\"ok\":false,\"error\":\"内容过大(上限 256KB)\"}");
    return;
  }
  int is_json = str_endswith(name, ".json");
  if (is_json) {
    json_t *probe = json_parse(content);
    if (!probe) {
      json_free(body);
      http_res_text(res, 400, "application/json; charset=utf-8",
                    "{\"ok\":false,\"error\":\"JSON 语法不合法,已拒绝保存(检查逗号/引号/括号)\"}");
      return;
    }
    json_free(probe);
  }
  /* 备份上一版:改坏了还能回头 */
  char bak[MAX_PATH * 2];
  snprintf(bak, sizeof(bak), "%s.bak", path);
  if (file_size(path) >= 0) {
    size_t old_len = 0;
    char *old = file_read_all(path, &old_len);
    if (old) {
      file_write_all(bak, old, old_len);
      free(old);
    }
  }
  char dir[MAX_PATH * 2];
  snprintf(dir, sizeof(dir), "%s", path);
  char *slash = strrchr(dir, '\\');
  if (slash) { *slash = 0; ensure_dir(dir); }
  /* 保留原来的换行风格:浏览器 textarea 会把 CRLF 归一成 LF,
     直接写回去会让"只改了一个词"的文件在 git 里整篇 diff。
     策略:原文件用 CRLF 就按 CRLF 写;原文件不存在(新建)按 LF。 */
  int want_crlf = 0;
  if (file_size(path) >= 0) {
    size_t chk_len = 0;
    char *chk = file_read_all(path, &chk_len);
    if (chk) {
      want_crlf = (strstr(chk, "\r\n") != NULL);
      free(chk);
    }
  }
  int rc;
  if (want_crlf && !strstr(content, "\r\n")) {
    buf_t conv;
    buf_init(&conv);
    for (const char *p = content; *p; p++) {
      if (*p == '\n') buf_putc_(&conv, '\r');
      buf_putc_(&conv, *p);
    }
    len = conv.len;
    rc = file_write_all(path, conv.data, conv.len);
    buf_free(&conv);
  } else {
    rc = file_write_all(path, content, len);
  }
  json_free(body);
  buf_t b;
  buf_init(&b);
  if (rc != 0) {
    buf_puts(&b, "{\"ok\":false,\"error\":\"写入失败(检查文件是否被别的程序占用)\"}");
  } else {
    buf_printf(&b, "{\"ok\":true,\"name\":");
    buf_json_str(&b, name);
    buf_printf(&b, ",\"size\":%d,\"backup\":", (int)len);
    buf_json_str(&b, file_size(bak) >= 0 ? "已留 .bak 备份" : "本次无旧版本");
    buf_puts(&b, "}");
    store_audit(g_store, "界面编辑配置", name, 1, "经界面保存并校验", g_task, "");
  }
  http_res_json(res, 200, b.data);
  buf_free(&b);
}

/* 规则热加载:改完 rules.json 不用重启(技能/工具/MCP 仍需重启,界面会写明) */
static void h_reload(const http_req_t *req, http_res_t *res) {
  (void)req;
  rules_shutdown();
  rules_init(app_dir());
  refresh_status_cache();
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"ok\":true,\"rulesSource\":");
  buf_json_str(&b, rules_source());
  buf_puts(&b, "}");
  http_res_json(res, 200, b.data);
  buf_free(&b);
}

/* ================= 周期巡检 =================
 * 数据全部来自 automations 集合;这里只做四件事:
 * 列出来、存一份、删一份、让它"马上跑一次"(把 next_at 拨到现在,交给调度线程)。
 * 「马上跑」不在这里同步执行 —— 否则这个 HTTP 连接要挂着等一整轮巡检。
 */
static void h_automation_list(const http_req_t *req, http_res_t *res) {
  (void)req;
  auto_rule_t *list = NULL;
  int n = 0;
  auto_list(g_store, &list, &n);
  json_t *arr = j_arr();
  for (int i = 0; i < n; i++) j_add(arr, auto_to_json(&list[i]));
  auto_free_list(list);

  json_t *root = j_obj();
  j_set_bool(root, "ok", 1);
  j_set_num(root, "serverNow", (double)time(NULL));
  j_set(root, "items", arr);
  char *text = json_dump(root);
  http_res_json(res, 200, text);
  free(text);
  json_free(root);
}

static void h_automation_post(const http_req_t *req, http_res_t *res) {
  json_t *body = req->body ? json_parse(req->body) : NULL;
  if (!body) {
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"请求体不是合法 JSON\"}");
    return;
  }
  const char *action = j_s(body, "action", "save");
  json_t *body_rule = j_get(body, "rule");
  char id[24];
  snprintf(id, sizeof(id), "%s", j_s(body, "id", ""));
  if (!id[0]) snprintf(id, sizeof(id), "%s", j_s(body_rule, "id", ""));

  if (str_ieq(action, "delete")) {
    int rc = auto_remove(g_store, id);
    json_free(body);
    if (rc != 0) { http_res_json(res, 404, "{\"ok\":false,\"error\":\"没有这条周期规则\"}"); return; }
    store_audit(g_store, "删除周期巡检", id, 1, "界面操作", g_task, "");
    http_res_json(res, 200, "{\"ok\":true}");
    return;
  }

  if (str_ieq(action, "run")) {
    auto_rule_t r;
    if (auto_find(g_store, id, &r) != 0) {
      json_free(body);
      http_res_json(res, 404, "{\"ok\":false,\"error\":\"没有这条周期规则\"}");
      return;
    }
    r.next_at = (long long)time(NULL);      /* 拨到现在:调度线程下一拍就捡走 */
    auto_save(g_store, &r);
    json_free(body);
    store_audit(g_store, "立即执行周期巡检", r.domain, 1, "界面点「马上跑一次」", g_task, "");
    http_res_json(res, 200, "{\"ok\":true,\"queued\":true,\"note\":\"已排进调度队列,几秒内开始;界面会自动刷新\"}");
    return;
  }

  /* save / toggle 都走这里。带 id 时先取出既有规则再做"只覆盖填了的字段" ——
     否则前端只传一个 every_min 就会把 domain 覆盖成空,报"目标不能为空"。 */
  auto_rule_t r;
  json_t *rule = j_get(body, "rule");
  if (!rule) rule = body;
  json_t *merged = NULL;
  if (id[0] && auto_find(g_store, id, &r) == 0) {
    merged = auto_to_json(&r);
    for (int i = 0; i < j_len(rule); i++) {
      if (!rule->keys || !rule->keys[i]) continue;
      j_set(merged, rule->keys[i], json_parse(json_dump(rule->items[i])));
    }
    auto_from_json(merged, &r);
    json_free(merged);
  } else {
    auto_from_json(rule, &r);
  }
  if (str_ieq(action, "toggle")) r.enabled = r.enabled ? 0 : 1;

  const char *bad = auto_validate(&r);
  if (bad) {
    json_free(body);
    buf_t b;
    buf_init(&b);
    buf_puts(&b, "{\"ok\":false,\"error\":");
    buf_json_str(&b, bad);
    buf_puts(&b, "}");
    http_res_json(res, 400, b.data);
    buf_free(&b);
    return;
  }

  /* 周期改了就得重算下次时间,否则还按旧的走 */
  r.next_at = auto_next_at(&r, (long long)time(NULL));
  auto_save(g_store, &r);
  store_audit(g_store, "设置周期巡检", r.domain, 1, r.id, g_task, "");

  json_t *out = auto_to_json(&r);
  json_t *root = j_obj();
  j_set_bool(root, "ok", 1);
  j_set(root, "item", out);
  char *text = json_dump(root);
  json_free(body);
  http_res_json(res, 200, text);
  free(text);
  json_free(root);
}

/* ================= 本单位敏感信息定义 =================
 * 命题①要求"支持录入……本单位敏感信息定义(关键词、正则、文件类型或样例)"。
 * 这里把"定义"做成可编辑对象:一条定义 = 一组关键词 + 正则 + 文件类型 + 落点 + 样例。
 * 保存前逐条校验:正则必须能编译(否则扫描时会被静默跳过,使用者还以为站点干净),
 * 落点必须以 / 开头且不能带 ..(路径穿越在安全工具里尤其不能有)。
 */
static const char *profile_check_list(json_t *p, const char *key, int max_items, size_t max_len,
                                      char *err, size_t cap) {
  json_t *arr = j_get(p, key);
  if (!arr) return NULL;
  if (arr->type != J_ARR) { snprintf(err, cap, "%s 必须是数组", key); return err; }
  if (arr->count > max_items) { snprintf(err, cap, "%s 最多 %d 条", key, max_items); return err; }
  for (int i = 0; i < arr->count; i++) {
    json_t *v = arr->items[i];
    if (!v || v->type != J_STR) { snprintf(err, cap, "%s 的每一项都必须是字符串", key); return err; }
    if (v->str && strlen(v->str) > max_len) { snprintf(err, cap, "%s 第 %d 条太长(上限 %d 字节)", key, i + 1, (int)max_len); return err; }
  }
  return NULL;
}

static const char *profile_validate(json_t *p, char *err, size_t cap) {
  if (!p || p->type != J_OBJ) { snprintf(err, cap, "定义必须是一个 JSON 对象"); return err; }
  const char *name = j_s(p, "name", "");
  if (!name[0]) { snprintf(err, cap, "名称不能为空"); return err; }
  if (strlen(name) > 64) { snprintf(err, cap, "名称最多 64 字节"); return err; }

  const char *bad = profile_check_list(p, "keywords", 200, 200, err, cap);
  if (bad) return bad;
  bad = profile_check_list(p, "samples", 40, 300, err, cap);
  if (bad) return bad;
  bad = profile_check_list(p, "file_types", 40, 16, err, cap);
  if (bad) return bad;
  bad = profile_check_list(p, "regex", 40, 300, err, cap);
  if (bad) return bad;
  bad = profile_check_list(p, "paths", 80, 300, err, cap);
  if (bad) return bad;

  json_t *regex = j_get(p, "regex");
  for (int i = 0; regex && i < regex->count; i++) {
    const char *pat = regex->items[i]->str;
    if (!pat || !pat[0]) continue;
    char rerr[128] = {0};
    rx_pattern *re = rx_compile(pat, rerr, sizeof(rerr));
    if (!re) {
      snprintf(err, cap, "第 %d 条正则不合法:%s", i + 1, rerr[0] ? rerr : "无法编译");
      return err;
    }
    rx_free(re);
  }
  json_t *paths = j_get(p, "paths");
  for (int i = 0; paths && i < paths->count; i++) {
    const char *path = paths->items[i]->str;
    if (!path || !path[0]) continue;
    if (path[0] != '/') { snprintf(err, cap, "第 %d 个落点必须以 / 开头", i + 1); return err; }
    if (strstr(path, "..")) { snprintf(err, cap, "第 %d 个落点不允许出现 ..", i + 1); return err; }
  }
  json_t *types = j_get(p, "file_types");
  for (int i = 0; types && i < types->count; i++) {
    const char *t = types->items[i]->str;
    if (!t || !t[0]) continue;
    for (const char *q = t; *q; q++) {
      if (*q == '.') continue;               /* 允许写 .env,点会被忽略 */
      if (!isalnum((unsigned char)*q)) {
        snprintf(err, cap, "第 %d 个文件类型只能写字母、数字与点", i + 1);
        return err;
      }
    }
  }
  return NULL;
}

static void h_profiles(const http_req_t *req, http_res_t *res) {
  if (strcmp(req->method, "POST") != 0) {
    json_t *all = store_all(g_store, "profiles");
    json_t *root = j_obj();
    j_set_bool(root, "ok", 1);
    j_set(root, "items", all);
    char *text = json_dump(root);
    http_res_json(res, 200, text);
    free(text);
    json_free(root);
    return;
  }

  json_t *body = req->body ? json_parse(req->body) : NULL;
  if (!body) { http_res_json(res, 400, "{\"ok\":false,\"error\":\"请求体不是合法 JSON\"}"); return; }
  const char *action = j_s(body, "action", "save");
  const char *id = j_s(body, "id", "");
  json_t *tpl = j_get(body, "profile");
  if (!id[0] && tpl) id = j_s(tpl, "id", "");

  if (str_ieq(action, "delete")) {
    int rc = id[0] ? store_delete(g_store, "profiles", id) : -1;
    json_free(body);
    if (rc != 0) { http_res_json(res, 404, "{\"ok\":false,\"error\":\"没有这套定义\"}"); return; }
    http_res_json(res, 200, "{\"ok\":true}");
    return;
  }

  /* 合并式保存:只传改了的那几个字段也不会把其它字段抹掉 */
  json_t *merged = j_obj();
  if (id[0]) {
    json_t *old = store_get(g_store, "profiles", id);
    if (old) {
      merged = old;
      if (!j_s(merged, "id", "")[0]) j_set_str(merged, "id", id);
    } else {
      j_set_str(merged, "id", id);
    }
  }
  if (tpl && tpl->type == J_OBJ) {
    for (int i = 0; i < j_len(tpl); i++) {
      if (!tpl->keys || !tpl->keys[i]) continue;
      j_set(merged, tpl->keys[i], json_parse(json_dump(tpl->items[i])));
    }
  }

  char err[256] = {0};
  const char *bad = profile_validate(merged, err, sizeof(err));
  if (bad) {
    json_free(merged);
    json_free(body);
    buf_t b;
    buf_init(&b);
    buf_puts(&b, "{\"ok\":false,\"error\":");
    buf_json_str(&b, bad);
    buf_puts(&b, "}");
    http_res_json(res, 400, b.data);
    buf_free(&b);
    return;
  }
  if (!j_s(merged, "id", "")[0]) {
    char *nid = store_next_id(g_store, "profiles");
    j_set_str(merged, "id", nid);
    free(nid);
  }
  char ts[40];
  now_iso(ts, sizeof(ts));
  if (!j_s(merged, "created_at", "")[0]) j_set_str(merged, "created_at", ts);
  j_set_str(merged, "updated_at", ts);
  store_save(g_store, "profiles", merged);
  store_audit(g_store, "保存敏感信息定义", j_s(merged, "name", ""), 1, j_s(merged, "id", ""), g_task, "");

  json_t *root = j_obj();
  j_set_bool(root, "ok", 1);
  j_set(root, "item", json_parse(json_dump(merged)));
  char *text = json_dump(root);
  json_free(merged);
  json_free(body);
  http_res_json(res, 200, text);
  free(text);
  json_free(root);
}

/* 把某套定义设为当前生效口径(巡检一轮用一套)。没有 id 就清空,回到出厂规则。 */
static void apply_profile(const char *profile_id) {
  if (!profile_id || !profile_id[0]) { profile_clear_active(); return; }
  json_t *p = store_get(g_store, "profiles", profile_id);
  if (!p) { profile_clear_active(); return; }
  profile_set_active(p);
  json_free(p);
}

/* ================= 审批策略接口 ================= */
static void h_approvals(const http_req_t *req, http_res_t *res) {
  if (strcmp(req->method, "POST") == 0) {
    json_t *body = req->body ? json_parse(req->body) : NULL;
    if (!body) { http_res_json(res, 400, "{\"ok\":false,\"error\":\"请求体不是合法 JSON\"}"); return; }
    const char *action = j_s(body, "action", "activate");
    char err[256] = {0};

    if (str_ieq(action, "activate")) {
      const char *id = j_s(body, "id", "");
      int ok = approval_activate(id);
      if (!ok) { json_free(body); http_res_json(res, 404, "{\"ok\":false,\"error\":\"没有这条审批策略\"}"); return; }
      /* 状态缓存要跟着变:界面的顶栏读数来自 /api/status,
         不刷新会出现"后端已经切了、下拉框还停在旧值"的分裂。 */
      EnterCriticalSection(&g_lock);
      refresh_status_cache();
      LeaveCriticalSection(&g_lock);
      json_free(body);
      store_audit(g_store, "切换审批策略", id, 1, approval_mode_text(), g_task, "");
      json_t *root = j_obj();
      j_set_bool(root, "ok", 1);
      j_set_str(root, "active", approval_active_id());
      j_set_bool(root, "allowAll", approval_is_allow_all());
      j_set(root, "items", approval_list_json());
      char *text = json_dump(root);
      http_res_json(res, 200, text);
      free(text);
      json_free(root);
      return;
    }

    if (str_ieq(action, "save")) {
      json_t *p = j_get(body, "policy");
      char *id = approval_save_policy(p, err, sizeof(err));
      if (!id) {
        json_free(body);
        buf_t b;
        buf_init(&b);
        buf_puts(&b, "{\"ok\":false,\"error\":");
        buf_json_str(&b, err);
        buf_puts(&b, "}");
        http_res_json(res, 400, b.data);
        buf_free(&b);
        return;
      }
      store_audit(g_store, "保存审批策略", j_s(p, "name", ""), 1, id, g_task, "");
      EnterCriticalSection(&g_lock);
      refresh_status_cache();
      LeaveCriticalSection(&g_lock);
      json_t *root = j_obj();
      j_set_bool(root, "ok", 1);
      j_set_str(root, "id", id);
      j_set(root, "items", approval_list_json());
      char *text = json_dump(root);
      free(id);
      json_free(body);
      http_res_json(res, 200, text);
      free(text);
      json_free(root);
      return;
    }

    if (str_ieq(action, "delete")) {
      int ok = approval_delete_policy(j_s(body, "id", ""));
      json_free(body);
      EnterCriticalSection(&g_lock);
      refresh_status_cache();
      LeaveCriticalSection(&g_lock);
      json_t *root = j_obj();
      j_set_bool(root, "ok", ok ? 1 : 0);
      j_set(root, "items", approval_list_json());
      char *text = json_dump(root);
      http_res_json(res, ok ? 200 : 404, text);
      free(text);
      json_free(root);
      return;
    }

    json_free(body);
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"未知的 action\"}");
    return;
  }

  json_t *root = j_obj();
  j_set_bool(root, "ok", 1);
  j_set_str(root, "active", approval_active_id());
  j_set_str(root, "modeText", approval_mode_text());
  j_set_bool(root, "allowAll", approval_is_allow_all());
  j_set(root, "items", approval_list_json());
  char *text = json_dump(root);
  http_res_json(res, 200, text);
  free(text);
  json_free(root);
}

/* 用户点了"允许/拒绝":唤醒卡在 hook_approval 里的循环 */
static void h_approval_decision(const http_req_t *req, http_res_t *res) {
  json_t *body = req->body ? json_parse(req->body) : NULL;
  const char *id = body ? j_s(body, "id", "") : "";
  const char *decision = body ? j_s(body, "decision", "") : "";
  if (!id[0] || !decision[0]) {
    if (body) json_free(body);
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"需要 id 与 decision\"}");
    return;
  }
  approval_init();
  EnterCriticalSection(&g_appr.lock);
  int match = g_appr.pending && strcmp(g_appr.id, id) == 0;
  if (match) {
    g_appr.decision = str_ieq(decision, "allow") ? 1 : 2;
    SetEvent(g_appr.event);
  }
  LeaveCriticalSection(&g_appr.lock);
  if (body) json_free(body);
  if (!match) {
    http_res_json(res, 409,
                  "{\"ok\":false,\"error\":\"这条审批请求已经不在了(可能超时或已处理)\"}");
    return;
  }
  http_res_json(res, 200, "{\"ok\":true}");
}

/* ================= 报告导出 ================= */
static void h_export(const http_req_t *req, http_res_t *res) {
  char fmt[16], rid[24];
  http_query(req, "format", fmt, sizeof(fmt), "md");
  http_query(req, "report", rid, sizeof(rid), "");

  buf_t out;
  buf_init(&out);
  char err[512];
  if (export_report(g_store, rid, fmt, &out, err, sizeof(err)) != 0) {
    buf_free(&out);
    buf_t b;
    buf_init(&b);
    buf_puts(&b, "{\"ok\":false,\"error\":");
    buf_json_str(&b, err[0] ? err : "导出失败");
    buf_puts(&b, "}");
    http_res_json(res, 400, b.data);
    buf_free(&b);
    return;
  }

  const char *ctype = "application/octet-stream";
  if (str_ieq(fmt, "md") || str_ieq(fmt, "markdown")) ctype = "text/markdown; charset=utf-8";
  else if (str_ieq(fmt, "html")) ctype = "text/html; charset=utf-8";
  else if (str_ieq(fmt, "csv")) ctype = "text/csv; charset=utf-8";
  else if (str_ieq(fmt, "json")) ctype = "application/json; charset=utf-8";
  else if (str_ieq(fmt, "docx")) ctype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
  else if (str_ieq(fmt, "pdf")) ctype = "application/pdf";

  char fname[128];
  export_filename(rid[0] ? rid : "latest", fmt, fname, sizeof(fname));
  http_res_file(res, 200, ctype, fname, out.data, out.len);
  buf_free(&out);
}

/* ================= 周期巡检调度线程 =================
 * 每秒醒一次,看有没有到点的规则。为什么用 TryEnter 而不是 Enter:
 * 手动那一轮可能正在跑(几十秒到几分钟),周期巡检排到它后面就行,
 * 但不能因为抢锁把调度线程挂死 —— 拿不到锁就下一拍再来。
 * 停机期间错过的周期不补跑(启动时顺延),这是刻意的:补跑会在开机瞬间
 * 对着目标突发十几个请求,既不合规也不像话。
 */
static volatile LONG g_sched_stop = 0;
static HANDLE g_sched_thread = NULL;

static DWORD WINAPI sched_thread(LPVOID param) {
  (void)param;
  {
    auto_rule_t *list = NULL;
    int n = 0;
    auto_list(g_store, &list, &n);
    int fixed = auto_resync(g_store, list, n);
    auto_free_list(list);
    if (fixed) log_info("周期巡检:启动时有 %d 条规则的到期时间已顺延(停机期间不补跑)", fixed);
  }

  while (!g_sched_stop) {
    Sleep(1000);
    if (g_sched_stop) break;
    if (!g_agent) break;

    if (!TryEnterCriticalSection(&g_lock)) continue;     /* 手动那一轮还在跑 */

    auto_rule_t rule;
    long long now = (long long)time(NULL);
    if (!auto_take_due(g_store, &rule, now)) {
      LeaveCriticalSection(&g_lock);
      continue;
    }

    /* 授权边界:周期规则的域名就是它的授权凭据;跑完把会话原有的范围还回去。
       同时按规则指定的"本单位敏感信息定义"设口径 —— 这一轮用哪套定义是可追溯的。 */
    if (!pool_contains(rule.domain)) {
      log_warn("周期巡检: %s 的目标 %s 不在授权池内,本轮跳过(不擅自扩权)", rule.id, rule.domain);
      store_audit(g_store, "周期巡检跳过", rule.domain, 0, "目标不在授权池内", g_task, "");
      LeaveCriticalSection(&g_lock);
      continue;
    }
    char prev_domain[256];
    snprintf(prev_domain, sizeof(prev_domain), "%s", g_domain);
    char prev_task[64];
    snprintf(prev_task, sizeof(prev_task), "%s", g_task);
    char prev_profile[24];
    snprintf(prev_profile, sizeof(prev_profile), "%s", profile_active_id());

    apply_profile(rule.profile_id);
    apply_scope(rule.domain);
    char instr[1400];
    {
      char scope_txt[1024];
      auto_checks_instruction(rule.checks, rule.scope, scope_txt, sizeof(scope_txt));
      snprintf(instr, sizeof(instr), "【周期巡检 %s】对 %s 现在开始,不要问我确认。%s",
               rule.id, rule.domain, scope_txt);
    }
    char sig[128];
    auto_checks_signature(rule.checks, rule.scope, sig, sizeof(sig));
    log_info("周期巡检: %s → %s(范围 %s%s%s)", rule.id, rule.domain, sig,
             rule.profile_id[0] ? ",定义 " : "", rule.profile_id);

    /* 全流程巡检会自己建运行记录(技能内部);收窄范围的那些技能不建,
       所以这里替它建一份 —— 否则「这一轮跑了什么」在历史里看不见。 */
    int is_full = str_ieq(sig, "full");
    int calls_before = net_http_calls();
    char *wrap_run = NULL;
    if (!is_full) {
      wrap_run = store_run_start(g_store, g_task, "周期巡检", sig);
      agent_set_store(g_agent, g_store, wrap_run ? wrap_run : "");
    }

    sse_ctx_t *saved_sse = g_sse;
    g_sse = NULL;                       /* 无人值守:没有界面在等这些事件 */
    store_set_trigger("周期巡检");
    agent_add_history(g_agent, "user", instr);
    loop_state_t st;
    memset(&st, 0, sizeof(st));
    int rc = agent_run_turn(g_agent, instr, &st);
    store_set_trigger("手动");
    g_sse = saved_sse;

    char *run_id = is_full ? auto_latest_run_of_domain(g_store, rule.domain)
                           : (wrap_run ? xstrdup(wrap_run) : NULL);
    if (!is_full && wrap_run) {
      json_t *fs = store_findings_of_run(g_store, wrap_run);
      int nf = j_len(fs);
      json_free(fs);
      store_run_finish(g_store, wrap_run, rc == 0 ? "done" : "failed",
                       0, net_http_calls() - calls_before, nf, rc == 0 ? "" : "巡检未正常收束");
      agent_set_store(g_agent, g_store, "");
    }

    int changed = 0;
    if (rc == 0 && run_id) changed = auto_after_run(g_store, &rule, run_id);
    log_info("周期巡检: %s %s,停止原因 %s%s", rule.id,
             rc == 0 ? "完成" : "失败", st.stop_reason[0] ? st.stop_reason : "—",
             !run_id ? " · 没拿到运行记录,这轮不做差分"
                     : (changed == 2 ? " · 同类范围的首轮,已建立基线(不告警)"
                                     : (changed ? " · 与上一轮相比有变化,已写告警"
                                                : " · 与上一轮相比没有变化")));
    free(run_id);
    free(wrap_run);
    if (st.steps) json_free(st.steps);
    buf_free(&st.transcript);

    /* 恢复会话原来的授权范围与口径,别让周期任务把用户的上下文改掉 */
    apply_scope(prev_domain[0] ? prev_domain : NULL);
    apply_profile(prev_profile);
    if (prev_task[0]) snprintf(g_task, sizeof(g_task), "%s", prev_task);
    refresh_status_cache();
    LeaveCriticalSection(&g_lock);
  }
  return 0;
}

static void sched_start(void) {
  g_sched_stop = 0;
  g_sched_thread = CreateThread(NULL, 0, sched_thread, NULL, 0, NULL);
}

static void sched_stop(void) {
  InterlockedExchange(&g_sched_stop, 1);
  if (g_sched_thread) {
    WaitForSingleObject(g_sched_thread, 5000);
    CloseHandle(g_sched_thread);
    g_sched_thread = NULL;
  }
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
                                  "baselines", "diffs", "automations", NULL};
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
  /* 确认授权 = 把目标加进授权池,并把这一轮焦点设成它。
     以后换站不需要"改全局设置":池子先收进来,后面谁都能从池里挑。 */
  pool_add(domain);
  apply_scope(domain);
  refresh_status_cache();
  char *j = status_snapshot();
  LeaveCriticalSection(&g_lock);
  store_audit(g_store, "授权池加入目标", domain, 1, "界面确认已获授权", g_task, "");
  if (body) json_free(body);
  http_res_json(res, 200, j);
  free(j);
}

/* ================= 授权池接口 ================= */
static void h_pool(const http_req_t *req, http_res_t *res) {
  if (strcmp(req->method, "POST") == 0) {
    json_t *body = req->body ? json_parse(req->body) : NULL;
    if (!body) { http_res_json(res, 400, "{\"ok\":false,\"error\":\"请求体不是合法 JSON\"}"); return; }
    const char *action = j_s(body, "action", "add");
    const char *entry = j_s(body, "entry", "");
    if (!entry[0]) entry = j_s(body, "domain", "");
    int rc = 0;
    if (str_ieq(action, "remove")) {
      rc = pool_remove(entry);
    } else if (str_ieq(action, "add")) {
      rc = pool_add(entry);
      if (rc < 0) {
        json_free(body);
        http_res_json(res, 400,
                      "{\"ok\":false,\"error\":\"只填主机名(可带端口),不要带协议、路径或空格\"}");
        return;
      }
      store_audit(g_store, "授权池加入", entry, 1, "界面操作", g_task, "");
    }
    json_free(body);
    EnterCriticalSection(&g_lock);
    refresh_status_cache();
    LeaveCriticalSection(&g_lock);
    buf_t b;
    buf_init(&b);
    buf_puts(&b, "{\"ok\":true,\"changed\":");
    buf_printf(&b, "%d", rc > 0 ? 1 : 0);
    buf_puts(&b, ",\"pool\":");
    buf_puts(&b, g_pool_json);
    buf_puts(&b, "}");
    http_res_json(res, 200, b.data);
    buf_free(&b);
    return;
  }
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"ok\":true,\"pool\":");
  buf_puts(&b, g_pool_json);
  buf_puts(&b, "}");
  http_res_json(res, 200, b.data);
  buf_free(&b);
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

  /* 这一轮看哪个站由请求带(不是全局设定),但必须落在授权池里。
     越池的目标在这里就挡掉,连 SSE 都不开 —— 省得模型白跑一轮。 */
  char target[256];
  http_query(req, "target", target, sizeof(target), "");
  if (target[0]) {
    if (!pool_contains(target)) {
      buf_t msg;
      buf_init(&msg);
      buf_printf(&msg, "目标 %s 不在授权池内:先把主机加进授权池,再对它发起巡检", target);
      buf_t e;
      buf_init(&e);
      buf_puts(&e, "{\"ok\":false,\"error\":");
      buf_json_str(&e, msg.data);
      buf_puts(&e, "}");
      http_res_json(res, 403, e.data);
      buf_free(&msg);
      buf_free(&e);
      return;
    }
    EnterCriticalSection(&g_lock);
    apply_scope(target);
    net_scope_violation_clear();
    LeaveCriticalSection(&g_lock);
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
    if (!strcmp(p, "/api/pool")) { h_pool(req, res); return; }
    if (!strcmp(p, "/api/chat")) { h_chat(req, res); return; }
    if (!strcmp(p, "/api/config/list")) { h_config_list(req, res); return; }
    if (!strcmp(p, "/api/config")) {
      if (strcmp(req->method, "POST") == 0) h_config_save(req, res);
      else h_config_get(req, res);
      return;
    }
    if (!strcmp(p, "/api/reload")) { h_reload(req, res); return; }
    if (!strcmp(p, "/api/automations")) {
      if (strcmp(req->method, "POST") == 0) h_automation_post(req, res);
      else h_automation_list(req, res);
      return;
    }
    if (!strcmp(p, "/api/export")) { h_export(req, res); return; }
    if (!strcmp(p, "/api/profiles")) { h_profiles(req, res); return; }
    if (!strcmp(p, "/api/approvals")) { h_approvals(req, res); return; }
    if (!strcmp(p, "/api/approval")) { h_approval_decision(req, res); return; }
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
  /* 授权池先load:边界必须在任何请求之前就位。
     首次升级时池子是空的 —— 把启动参数里的域名当作第一条授权收进去,
     否则老用户一升级就"什么都不能查",会以为程序坏了。 */
  pool_load();
  if (net_pool_count() == 0 && domain && *domain) pool_add(domain);
  {
    char apath[MAX_PATH * 2];
    app_data_path(apath, sizeof(apath), "approval.json");
    approval_set_path(apath);
    approval_load();
    approval_init();
  }
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

  /* 周期巡检:服务一起来就把调度线程挂上。关掉浏览器它照样跑 —— 这正是"周期"的意思。 */
  sched_start();

  if (open_ui) {
    /* 界面用系统浏览器打开。为什么不用进程内嵌 WebView2 见 exp/probe.c 的取证结论。 */
    ui_open_url_async(port);
  }

  int serve_rc = http_serve(NULL, port, router, NULL);

  sched_stop();
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
