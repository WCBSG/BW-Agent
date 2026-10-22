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
#include "api.h"
#include "approval.h"
#include "automation.h"
#include "embed.h"
#include "export.h"
#include "profile.h"
#include "regex.h"
#include "ext.h"
#include "http.h"
#include "llm.h"
#include "native_ui.h"
#include "net.h"
#include "profile.h"
#include "res.h"
#include "rules.h"
#include "serve_ctx.h"
#include "skills.h"
#include "store.h"
#include "tools.h"
#include "thread_store.h"
#include "tray.h"
#include "ui.h"

static store_t *g_store = NULL;
static CRITICAL_SECTION g_lock;
static CRITICAL_SECTION g_status_lock;
/* 会话状态用缓存发出去:外面查状态时绝不阻塞正在跑的循环 ——
   循环一跑就是几十秒,界面这时候不该卡住 */
static char *g_status_cache = NULL;
static char g_session[128] = "web-session";
/* 当前任务的"展示态":谁最后发起巡检就显示谁。真正的合规边界不在这里 ——
   那是 net 层的线程本地授权范围,多会话并发也不会互相污染。 */
static char g_task_disp[64] = "WEB-TASK";
static char g_domain_disp[256] = "";
/* 本线程正在处理的目标与任务:审计行要记到正确的那一轮上,所以按线程隔离 */
static thread_local char g_task[64] = "";
static thread_local char g_domain[256] = "";
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
  char session[128];         /* 这一条流属于哪个会话(事件的 sessionId 用它) */
  buf_t answer;              /* 本轮说给用户的最终话(要落进会话转录) */
} sse_ctx_t;

/* 每个连接线程各有一份直播上下文:一个会话在跑的时候,别的会话照样能开自己的流。
   以前这里是全局单例,两个标签页同时说话会互相抢流 —— 表现就是"另一个页面卡住"。 */
static thread_local sse_ctx_t *g_sse = NULL;

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
  buf_json_str(&b, c->session[0] ? c->session : g_session);
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
  /* 记下最后一句:一轮结束时它是"这次对话的结论",要进会话转录 */
  if (text && *text) {
    buf_clear(&c->answer);
    buf_puts(&c->answer, text);
  }
}

/* 模型边收边到的正文:直接追加到当前文本块。
   和"一步一跳"的思考相比,这是唯一能让人看到"模型在写字"的地方。 */
static void hook_delta(void *ud, const char *text) {
  (void)ud;
  sse_ctx_t *c = g_sse;
  if (!c || !text || !*text) return;
  if (c->tool_open) t_close_tool(c);
  t_put_text(c, text);
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
  HANDLE event;
  char id[40];
  int decision;          /* 0 未定 / 1 允许 / 2 拒绝 */
  int pending;
} approval_slot_t;

/* 审批槽做成"一组"而不是一个:两个会话同时撞上需要确认的动作时,
   后来的那个不该把前一个的等待覆盖掉(覆盖的结果是前一轮永远等不到答复)。 */
#define MAX_APPROVAL_SLOTS 8

static approval_slot_t g_appr_slots[MAX_APPROVAL_SLOTS];
static CRITICAL_SECTION g_appr_lock;
static int g_appr_ready = 0;
static volatile LONG g_appr_seq = 0;
/* 定时任务不该被"询问"卡住:规则是你自己建的,到点就等同于预授权。
   但它同样受授权池、只读、限速、审计约束 —— 少掉的只是"每步点一次"。
   线程本地:只有调度线程自己放行,不会顺手把用户会话里的确认也一起放过去。 */
static thread_local int g_appr_unattended = 0;

static void approval_init(void) {
  if (g_appr_ready) return;
  InitializeCriticalSection(&g_appr_lock);
  for (int i = 0; i < MAX_APPROVAL_SLOTS; i++) {
    g_appr_slots[i].event = CreateEventA(NULL, TRUE, FALSE, NULL);  /* 手动复位:决定一次只生效一次 */
    g_appr_slots[i].id[0] = 0;
    g_appr_slots[i].pending = 0;
    g_appr_slots[i].decision = 0;
  }
  g_appr_ready = 1;
}

/* 循环线程调用:问一句,然后等。 */
static int hook_approval(void *ud, const char *tool, json_t *args, char **reason) {
  (void)ud;
  approval_init();
  if (reason) *reason = NULL;

  approval_action_t act = approval_decide(tool ? tool : "");
  if (act == APPROVAL_ALLOW) return 1;
  /* 定时巡检:规则是人建的,到点即预授权。策略里的"拒绝"仍然生效。 */
  if (act == APPROVAL_ASK && g_appr_unattended) return 1;
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

  /* 占一个空槽:并发会话各等各的,互不覆盖 */
  int seq = (int)InterlockedIncrement(&g_appr_seq);
  char id[40];
  snprintf(id, sizeof(id), "ap-%ld-%04d", (long)GetCurrentProcessId(), seq);

  approval_slot_t *slot = NULL;
  EnterCriticalSection(&g_appr_lock);
  for (int i = 0; i < MAX_APPROVAL_SLOTS; i++) {
    if (!g_appr_slots[i].pending) { slot = &g_appr_slots[i]; break; }
  }
  if (slot) {
    snprintf(slot->id, sizeof(slot->id), "%s", id);
    slot->decision = 0;
    slot->pending = 1;
    ResetEvent(slot->event);
  }
  LeaveCriticalSection(&g_appr_lock);

  if (!slot) {
    if (reason) *reason = xstrdup("同时等待确认的动作太多了,这一步先不执行");
    return 0;
  }

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
  DWORD got = WaitForSingleObject(slot->event, wait_ms);

  EnterCriticalSection(&g_appr_lock);
  int decision = slot->decision;
  slot->pending = 0;
  LeaveCriticalSection(&g_appr_lock);

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
    hook_observation, hook_answer, hook_ask, hook_approval, hook_delta};

/* ================= 会话表(每个会话一个智能体实例) =================
   并发的前提:每个会话有自己的历史、自己的步数、自己的审批等待。
   共用同一个 agent 实例的话,两个标签页会互相改对方的对话上下文。 */
#define MAX_AGENT_SLOTS 8
typedef struct {
  char id[64];
  agent_t *a;
  CRITICAL_SECTION lock;     /* 同一会话内串行:两个标签页点同一个会话也不会撞车 */
} agent_slot_t;

static agent_slot_t g_agents[MAX_AGENT_SLOTS];
static int g_agent_count = 0;
static CRITICAL_SECTION g_agent_lock;
static agent_t *g_sched_agent = NULL;   /* 周期巡检专用,不和用户会话抢上下文 */

static void agents_init(void) {
  InitializeCriticalSection(&g_agent_lock);
}

static agent_slot_t *agent_slot_of(const char *sid) {
  char key[64];
  snprintf(key, sizeof(key), "%s", (sid && *sid) ? sid : g_session);
  agent_slot_t *found = NULL;
  EnterCriticalSection(&g_agent_lock);
  for (int i = 0; i < g_agent_count; i++) {
    if (strcmp(g_agents[i].id, key) == 0) { found = &g_agents[i]; break; }
  }
  if (!found && g_agent_count < MAX_AGENT_SLOTS) {
    found = &g_agents[g_agent_count++];
    snprintf(found->id, sizeof(found->id), "%s", key);
    InitializeCriticalSection(&found->lock);
    found->a = agent_create(found->id);
    agent_set_store(found->a, g_store, "");
    agent_set_hooks(found->a, &g_hooks);
  }
  LeaveCriticalSection(&g_agent_lock);
  return found;
}

static agent_slot_t *agent_slot_find(const char *sid) {
  char key[64];
  snprintf(key, sizeof(key), "%s", (sid && *sid) ? sid : g_session);
  agent_slot_t *found = NULL;
  EnterCriticalSection(&g_agent_lock);
  for (int i = 0; i < g_agent_count; i++) {
    if (strcmp(g_agents[i].id, key) == 0) { found = &g_agents[i]; break; }
  }
  LeaveCriticalSection(&g_agent_lock);
  return found;
}

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
  /* 问的是"这个主机整体是否可用"(没有具体路径),所以按 "/" 判 */
  return net_pool_has(host, port, "/");
}

static int pool_add(const char *entry) {
  if (!entry || !entry[0]) return -1;
  if (strstr(entry, "://") || strchr(entry, ' ') || strchr(entry, '\t')) return -1;
  if (strstr(entry, "..")) return -1;              /* 路径穿越在安全工具里尤其不能有 */
  const char *body = entry[0] == '!' ? entry + 1 : entry;
  if (!body[0]) return -1;
  char hostport[300];
  snprintf(hostport, sizeof(hostport), "%s", body);
  char *slash = strchr(hostport, '/');
  if (slash) {
    *slash = 0;
    if (slash[1] == 0) return -1;                  /* "host/" 这种半条规则没有意义 */
  }
  if (!hostport[0]) return -1;
  /* 主机段只允许字母数字与点横线冒号,避免把 URL 或路径写进来 */
  for (const char *p = hostport; *p; p++) {
    char c = *p;
    if (!(isalnum((unsigned char)c) || c == '.' || c == '-' || c == ':' || c == '[' || c == ']')) return -1;
  }
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
    snprintf(g_domain_disp, sizeof(g_domain_disp), "%s", domain);
    /* 授权范围只认主机名(端口不参与授权判断),但端口要拿去做"地址对齐":
       否则用户写 127.0.0.1 而站点在 8081 时,请求全会打到 443 上去。 */
    char host_only[256];
    net_host_port_of(domain, host_only, sizeof(host_only));
    if (!host_only[0]) snprintf(host_only, sizeof(host_only), "%s", domain);
    net_align_base_from(domain);
    const char *doms[1];
    doms[0] = host_only;
    /* 授权范围:池子按"主机 + 路径"判,所以给的是原始目标(保留子路径);
       任务与报告按主机归档,用 host_only。 */
    const char *scope_entry[1];
    scope_entry[0] = domain;
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
      if (tid) {
        snprintf(g_task, sizeof(g_task), "%s", tid);
        snprintf(g_task_disp, sizeof(g_task_disp), "%s", tid);
      }
      free(pid);
      free(tid);
      json_free(kws);
      json_free(fts);
    }
    /* 合规边界落在线程本地(net 层):只有本线程后续的请求受它约束,
       别的会话同时在跑也不会被这一行改掉。
       注意这里传的是**带路径的原始目标**:目标写成 /l1/ 时,这一轮的边界
       就是那棵子树 —— 只留主机名会把它悄悄放大成整站。 */
    net_set_scope(g_task, scope_entry, 1);
  } else {
    g_domain[0] = 0;
    g_domain_disp[0] = 0;
    net_set_scope(g_task, NULL, 0);
  }
}

static char *build_status_json(void) {
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"ok\":true,\"sessionId\":");
  buf_json_str(&b, g_session);
  buf_puts(&b, ",\"taskId\":");
  buf_json_str(&b, g_task_disp);
  buf_puts(&b, ",\"domain\":");
  buf_json_str(&b, g_domain_disp);
  buf_printf(&b, ",\"authorized\":%s", (g_domain_disp[0] || net_pool_count() > 0) ? "true" : "false");
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
  buf_json_str(&b, providers_display_name());
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
/* ---------- 给拆出去的接口实现用的小门(见 serve_ctx.h) ---------- */
store_t *serve_store(void) { return g_store; }
const char *serve_task_id(void) { return g_task; }

void serve_audit_line(const char *action, const char *target, const char *detail) {
  if (!g_store) return;
  store_audit(g_store, action, target, 1, detail, g_task, "");
}

/* 顶部状态是缓存出来的:规则/配置一变就得重算,否则界面还显示旧口径 */
static void refresh_status_cache(void);

void serve_refresh_status(void) { refresh_status_cache(); }

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
  int match = 0;
  EnterCriticalSection(&g_appr_lock);
  for (int i = 0; i < MAX_APPROVAL_SLOTS; i++) {
    if (g_appr_slots[i].pending && strcmp(g_appr_slots[i].id, id) == 0) {
      g_appr_slots[i].decision = str_ieq(decision, "allow") ? 1 : 2;
      SetEvent(g_appr_slots[i].event);
      match = 1;
      break;
    }
  }
  LeaveCriticalSection(&g_appr_lock);
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
    if (!g_sched_agent) break;

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

    /* 规则已经认领、范围也设好了,就放开全局锁 —— 一轮巡检几十秒,
       不能让别人(包括界面本身)在门外干等。 */
    LeaveCriticalSection(&g_lock);

    /* 全流程巡检会自己建运行记录(技能内部);收窄范围的那些技能不建,
       所以这里替它建一份 —— 否则「这一轮跑了什么」在历史里看不见。 */
    int is_full = str_ieq(sig, "full");
    int calls_before = net_http_calls();
    char *wrap_run = NULL;
    if (!is_full) {
      wrap_run = store_run_start(g_store, g_task, "周期巡检", sig);
      agent_set_store(g_sched_agent, g_store, wrap_run ? wrap_run : "");
    }

    store_set_trigger("周期巡检");
    g_appr_unattended = 1;
    net_scope_violation_clear();        /* 每轮从零开始记越界 */
    loop_state_t st;
    memset(&st, 0, sizeof(st));
    int rc = agent_run_turn(g_sched_agent, instr, &st);
    int violated = net_scope_violation();
    net_scope_violation_clear();
    g_appr_unattended = 0;
    store_set_trigger("手动");

    char *run_id = is_full ? auto_latest_run_of_domain(g_store, rule.domain)
                           : (wrap_run ? xstrdup(wrap_run) : NULL);
    if (!is_full && wrap_run) {
      json_t *fs = store_findings_of_run(g_store, wrap_run);
      int nf = j_len(fs);
      json_free(fs);
      store_run_finish(g_store, wrap_run, rc == 0 ? "done" : "failed",
                       0, net_http_calls() - calls_before, nf, rc == 0 ? "" : "巡检未正常收束");
      agent_set_store(g_sched_agent, g_store, "");
    }

    int changed = 0;
    /* 越界中止的一轮不参与差分:它本来就没跑完,拿它当基线会把"没查到"
       误读成"问题消失了"。 */
    if (rc == 0 && run_id && !violated) changed = auto_after_run(g_store, &rule, run_id);
    log_info("周期巡检: %s %s,停止原因 %s%s", rule.id,
             rc == 0 ? "完成" : "失败", st.stop_reason[0] ? st.stop_reason : "—",
             violated ? " · 有请求越出授权池,本轮中止且不做差分"
                      : (!run_id ? " · 没拿到运行记录,这轮不做差分"
                                 : (changed == 2 ? " · 同类范围的首轮,已建立基线(不告警)"
                                                : (changed ? " · 与上一轮相比有变化,已写告警"
                                                           : " · 与上一轮相比没有变化"))));
    free(run_id);
    free(wrap_run);
    if (st.steps) json_free(st.steps);
    buf_free(&st.transcript);

    /* 恢复会话原来的授权范围与口径,别让周期任务把用户的上下文改掉 */
    apply_scope(prev_domain[0] ? prev_domain : NULL);
    apply_profile(prev_profile);
    if (prev_task[0]) snprintf(g_task, sizeof(g_task), "%s", prev_task);
    refresh_status_cache();
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
                                  "tasks", "profiles", "testcases",
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
/* 单条加入:也允许一次给多行(批量):entries 可以是数组,也可以是换行/逗号分隔的文本。
   "一次录一批"是真实场景(一个单位十几个站),让人一条条点不现实。 */
static int pool_add_text(const char *text, int *added, int *skipped, buf_t *bad, int max_add) {
  if (!text || !text[0]) return 0;
  *added = 0;
  *skipped = 0;
  char *copy = xstrdup(text);
  /* 换行、逗号、分号、空白都当分隔符 */
  for (char *p = copy; *p; p++) {
    if (*p == ',' || *p == ';' || *p == '\r' || *p == '\t') *p = '\n';
  }
  char **lines = NULL;
  int n = str_split(copy, '\n', &lines, 400);
  for (int i = 0; i < n; i++) {
    char *e = str_trim(lines[i]);
    if (!e[0] || e[0] == '#') continue;
    if (*added >= max_add) break;
    int rc = pool_add(e);
    if (rc > 0) (*added)++;
    else if (rc == 0) (*skipped)++;
    else {
      if (bad && bad->len < 400) {
        if (bad->len) buf_puts(bad, "、");
        buf_printf(bad, "%s(格式不对)", e);
      }
      (*skipped)++;
    }
  }
  str_free_list(lines, n);
  free(copy);
  return *added;
}

static void h_pool(const http_req_t *req, http_res_t *res) {
  if (strcmp(req->method, "POST") == 0) {
    json_t *body = req->body ? json_parse(req->body) : NULL;
    if (!body) { http_res_json(res, 400, "{\"ok\":false,\"error\":\"请求体不是合法 JSON\"}"); return; }
    const char *action = j_s(body, "action", "add");
    const char *entry = j_s(body, "entry", "");
    if (!entry[0]) entry = j_s(body, "domain", "");
    int changed = 0, added = 0, skipped = 0;
    buf_t bad;
    buf_init(&bad);

    if (str_ieq(action, "remove")) {
      changed = pool_remove(entry);
    } else if (str_ieq(action, "batch")) {
      /* 批量:优先数组,其次多行文本 —— 两种都给用户留了路 */
      json_t *arr = j_get(body, "entries");
      if (arr && arr->type == J_ARR) {
        buf_t joined;
        buf_init(&joined);
        for (int i = 0; i < j_len(arr); i++) {
          json_t *v = j_at(arr, i);
          if (!v || v->type != J_STR || !v->str) continue;
          if (joined.len) buf_putc_(&joined, '\n');
          buf_puts(&joined, v->str);
        }
        changed = pool_add_text(joined.data, &added, &skipped, &bad, 400);
        buf_free(&joined);
      } else {
        const char *text = j_s(body, "text", "");
        if (!text[0]) text = entry;
        changed = pool_add_text(text, &added, &skipped, &bad, 400);
      }
      if (added) store_audit(g_store, "授权池批量加入", "批量", 1, "", g_task, "");
    } else {
      changed = pool_add(entry);
      if (changed < 0) {
        json_free(body);
        buf_free(&bad);
        http_res_json(res, 400,
                      "{\"ok\":false,\"error\":\"只填主机名(可带端口，前面加 ! 表示不允许；不允许写成 http:// 或带空格)\"}");
        return;
      }
      added = changed > 0 ? 1 : 0;
      if (changed > 0) store_audit(g_store, "授权池加入", entry, 1, "界面操作", g_task, "");
    }
    json_free(body);
    EnterCriticalSection(&g_lock);
    refresh_status_cache();
    LeaveCriticalSection(&g_lock);
    buf_t b;
    buf_init(&b);
    buf_puts(&b, "{\"ok\":true,\"changed\":");
    buf_printf(&b, "%d,\"added\":%d,\"skipped\":%d", changed > 0 ? 1 : 0, added, skipped);
    if (bad.len) {
      buf_puts(&b, ",\"rejected\":");
      buf_json_str(&b, bad.data);
    }
    buf_puts(&b, ",\"pool\":");
    buf_puts(&b, g_pool_json);
    buf_puts(&b, "}");
    http_res_json(res, 200, b.data);
    buf_free(&b);
    buf_free(&bad);
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

static char *attach_read(const char *sid, const char *id, size_t cap, size_t *out_len);

static void h_chat(const http_req_t *req, http_res_t *res) {
  /* 会话 id 先读出来:附件与历史都按会话存,拼输入时要用。
     查询串和 JSON 体都认 —— 界面走查询串,脚本调接口时更顺手的是 body。 */
  char q[4096];
  char sid[64];
  http_query(req, "q", q, sizeof(q), "");
  http_query(req, "sid", sid, sizeof(sid), "");
  if ((!q[0] || !sid[0]) && req->body) {
    json_t *body = json_parse(req->body);
    if (body) {
      if (!q[0]) snprintf(q, sizeof(q), "%s", j_s(body, "q", ""));
      if (!sid[0]) snprintf(sid, sizeof(sid), "%s", j_s(body, "sid", ""));
      json_free(body);
    }
  }
  if (!q[0]) {
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"缺少参数 q\"}");
    return;
  }

  /* 附件:文本内容拼进这一轮输入(模型能读),图片只存档并如实注明(模型读不了)。
     把"贴日志"变成一句话的事 —— 让人自己转述是给使用者添麻烦。 */
  buf_t input;
  buf_init(&input);
  buf_puts(&input, q);
  json_t *att_list = j_arr();
  {
    char att_ids[1024];
    http_query(req, "att", att_ids, sizeof(att_ids), "");
    if (att_ids[0]) {
      char **ids = NULL;
      int n = str_split(att_ids, ',', &ids, 0);
      int budget = 24000;                     /* 总量上限:别把提示词撑爆 */
      for (int i = 0; i < n; i++) {
        char *id = str_trim(ids[i]);
        if (!id[0]) continue;
        json_t *a = j_obj();
        j_set_str(a, "id", id);
        j_set_str(a, "kind", str_startswith(id, "img-") ? "image" : "text");
        if (str_startswith(id, "img-")) {
          j_add(att_list, a);
          buf_printf(&input,
                     "\n\n[附件] %s(图片已存档;当前模型不支持读图,不要据此推断图片内容)", id);
          continue;
        }
        size_t len = 0;
        char *text = attach_read(sid, id, 8000, &len);
        if (!text) { json_free(a); continue; }
        j_add(att_list, a);
        buf_printf(&input, "\n\n【用户附上的材料:%s】\n", id);
        int take = (int)len;
        if (take > budget) take = budget;
        buf_putn(&input, text, (size_t)take);
        budget -= take;
        free(text);
        if (budget <= 0) {
          buf_puts(&input, "\n(附件总量已达上限,后续附件内容从略)");
          break;
        }
      }
      str_free_list(ids, n);
    }
  }

  /* 这一轮看哪个站由请求带(不是全局设定),但必须落在授权池里。
     越池的目标在这里就挡掉,连 SSE 都不开 —— 省得模型白跑一轮。
     没带目标就沿用上一次的焦点,这样"接着刚才那个站继续"不用重复输入。 */
  char target[256];
  http_query(req, "target", target, sizeof(target), "");
  if (!target[0]) snprintf(target, sizeof(target), "%s", g_domain_disp);
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
    LeaveCriticalSection(&g_lock);
  }

  /* 会话 id:界面每个标签页带一个。不同会话各有各的上下文与授权范围,
     两个页面可以同时干活;同一会话内则串行,免得互相改历史。 */
  agent_slot_t *slot = agent_slot_of(sid);
  if (!slot) {
    http_res_json(res, 503,
                  "{\"ok\":false,\"error\":\"同时打开的会话太多了,先关掉一个再试\"}");
    return;
  }

  if (!http_sse_begin(res)) return;

  sse_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.res = res;
  snprintf(ctx.session, sizeof(ctx.session), "%s", sid[0] ? sid : g_session);
  buf_init(&ctx.answer);
  EnterCriticalSection(&g_lock);
  snprintf(ctx.message_id, sizeof(ctx.message_id), "msg-%04d", ++g_turn_seq);
  LeaveCriticalSection(&g_lock);
  ev_message_start(&ctx);

  /* 会话转录:先记"用户说了什么"。这样即使这一轮中途崩掉,
     历史里也不会只剩半句话 —— 用户回看时能看出是从哪儿断的。
     结构按主流 Agent 的做法来:消息有稳定 id、序号、父指针,内容是块数组。 */
  {
    thread_ensure(sid, NULL);
    json_t *blocks = j_arr();
    json_t *b = j_obj();
    j_set_str(b, "type", "text");
    j_set_str(b, "text", q);
    j_add(blocks, b);
    if (j_len(att_list) > 0) {
      json_t *ab = j_obj();
      j_set_str(ab, "type", "attachment");
      j_set(ab, "items", att_list);      /* 所有权交给这个块 */
      j_add(blocks, ab);
    } else {
      json_free(att_list);
    }
    json_t *meta = j_obj();
    if (target[0]) j_set_str(meta, "target", target);
    j_set(meta, "client", j_str("web"));
    json_t *msg = thread_append(sid, "user", blocks, NULL, NULL);
    json_free(msg);
    json_free(meta);
  }
  store_set_chat(sid);

  /* —— 从这里开始不再持有全局锁:一轮几十秒,别人(尤其是界面自己的状态轮询)
        不能在门外干等。共享数据一律走各自的锁(store 自带锁,状态缓存自带锁)。 —— */
  EnterCriticalSection(&slot->lock);

  /* 这一轮的授权范围落在线程本地,并由智能体自己持有 —— 别的会话同时在跑,
     边界也不会被串改。 */
  if (g_domain[0]) {
    const char *domvs[1];
    domvs[0] = g_domain;              /* 带路径:这一轮就只看这棵子树 */
    agent_set_scope(slot->a, g_task, domvs, 1);
  } else {
    agent_set_scope(slot->a, g_task, NULL, 0);
  }

  net_scope_violation_clear();       /* 每轮从零开始记越界 */
  g_sse = &ctx;                      /* 线程本地:只影响本连接 */

  /* 这一轮到底算不算"一次运行"?
     技能自己会建运行记录(全流程巡检就是),那就用它那份,别再记一条重复的;
     纯对话、只查一项、复测这类没有自建记录的,由这里补一条 ——
     否则"聊了几句"在运行记录里彻底看不见,用户会以为这些对话没留下痕迹。 */
  int runs_before = store_count(g_store, "runs");
  int assets_before = store_count(g_store, "assets");
  int findings_before = store_count(g_store, "findings");
  int calls_before_chat = net_http_calls();

  loop_state_t st;
  memset(&st, 0, sizeof(st));
  agent_run_turn(slot->a, input.data ? input.data : q, &st);
  g_sse = NULL;
  buf_free(&input);

  const char *reason = st.stop_reason[0] ? st.stop_reason : "已完成";
  const char *stop = (st.stop_code == STOP_NEED_USER) ? "refusal" : "end_turn";
  if (st.stop_code == STOP_ANSWERED || st.stop_code == STOP_ANSWERING_ONLY) {
    stop = "end_turn";
  }

  if (store_count(g_store, "runs") == runs_before) {
    /* 这一轮用了哪个技能?记到运行记录上 ——
       列表里写"证据与覆盖核对"显然比写"对话"更有用。 */
    char scope[48] = "chat";
    const char *label = "对话";
    char labelBuf[96] = {0};
    json_t *stepsArr = NULL;
    if (st.steps) {
      /* st.steps 收尾时被包成了一个对象({steps:[...], stop_reason...}),
         不是数组 —— 这里两种形状都认,免得以后结构再变一次又读不到。 */
      if (st.steps->type == J_ARR) stepsArr = st.steps;
      else {
        json_t *inner = j_get(st.steps, "steps");
        if (inner && inner->type == J_ARR) stepsArr = inner;
      }
    }
    for (int i = 0; stepsArr && i < j_len(stepsArr); i++) {
      const char *act = j_s(j_at(stepsArr, i), "action", "");
      if (str_startswith(act, "skill_") && act[6]) {
        snprintf(scope, sizeof(scope), "%s", act + 6);
        skill_t *sk = skills_find(act);
        snprintf(labelBuf, sizeof(labelBuf), "%s", (sk && sk->title && sk->title[0]) ? sk->title : scope);
        label = labelBuf;
      }
    }
    char *rid = store_run_start(g_store, g_task, label, scope);
    if (rid) {
      int pages = store_count(g_store, "assets") - assets_before;
      int fresh = store_count(g_store, "findings") - findings_before;
      if (pages < 0) pages = 0;
      if (fresh < 0) fresh = 0;
      store_run_finish(g_store, rid, st.stop_code == STOP_ERROR ? "failed" : "done",
                       pages, net_http_calls() - calls_before_chat, fresh,
                       st.stop_code == STOP_ERROR ? reason : "");
      free(rid);
    }
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

  /* 会话转录:再记"智能体说了什么",以及这一轮为什么停 ——
     点开历史对话时,能原样看到当时的结论,而不是只有一条运行记录。
     正文是一块 text,停止原因与步数进事件流:两者用途不同,不该混在一条里。 */
  {
    json_t *blocks = j_arr();
    json_t *b = j_obj();
    j_set_str(b, "type", "text");
    j_set_str(b, "text", ctx.answer.data ? ctx.answer.data : "");
    j_add(blocks, b);

    json_t *usage = j_obj();
    j_set_num(usage, "steps", st.step_count);
    j_set_num(usage, "http_calls", net_http_calls() - calls_before_chat);
    j_set_str(usage, "stop_reason", reason);

    json_t *msg = thread_append(sid, "assistant", blocks, usage, NULL);
    json_free(msg);

    json_t *ev = j_obj();
    j_set_str(ev, "type", "turn_end");
    j_set_str(ev, "stop_reason", reason);
    j_set_num(ev, "steps", st.step_count);
    j_set_num(ev, "stop_code", st.stop_code);
    if (target[0]) j_set_str(ev, "target", target);
    thread_append_event(sid, ev);
  }
  store_set_chat("");
  buf_free(&ctx.answer);
  LeaveCriticalSection(&slot->lock);
  refresh_status_cache();
}

/* ================= 附件(贴日志 / 传截图) =================
   为什么要有:巡检里最常见的求助是"这段报错什么意思""这张后台截图哪里不对"。
   让人把内容转成文字再贴进来,是把工具的麻烦转嫁给使用者。
   这里只做两件事:把文件**存进本条会话**、把文本内容**拼进这一轮的输入**。
   图片当前模型读不了 —— 那就如实存档并展示,不假装"我看懂了这张图"。 */
static void h_attach(const http_req_t *req, http_res_t *res) {
  if (strcmp(req->method, "POST") != 0) {
    http_res_json(res, 405, "{\"ok\":false,\"error\":\"只接受 POST\"}");
    return;
  }
  json_t *body = req->body ? json_parse(req->body) : NULL;
  if (!body) {
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"请求体不是合法 JSON\"}");
    return;
  }
  const char *sid = j_s(body, "sid", "");
  const char *name = j_s(body, "name", "attachment");
  const char *kind = j_s(body, "kind", "text");
  const char *text = j_s(body, "text", "");
  if (!text[0]) {
    json_free(body);
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"附件是空的\"}");
    return;
  }
  char safe_sid[64], safe_name[96];
  snprintf(safe_sid, sizeof(safe_sid), "%s", (sid && *sid) ? sid : "default");
  for (char *p = safe_sid; *p; p++) {
    if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_') *p = '_';
  }
  snprintf(safe_name, sizeof(safe_name), "%s", (name && *name) ? name : "attachment");
  for (char *p = safe_name; *p; p++) {
    if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_' && *p != '.') *p = '_';
  }

  char dir[MAX_PATH * 2], path[MAX_PATH * 4];
  path_join(dir, sizeof(dir), g_data_dir, "attachments");
  path_join(dir, sizeof(dir), dir, safe_sid);
  ensure_dir(dir);

  /* id 就是文件名:kind + 毫秒时间戳 + 原名。不引入额外索引,
     回看会话时按 id 就能取到内容。 */
  char id[MAX_PATH];
  snprintf(id, sizeof(id), "%s-%lld-%s", str_ieq(kind, "image") ? "img" : "txt",
           (long long)now_ms(), safe_name);
  path_join(path, sizeof(path), dir, id);
  size_t len = strlen(text);
  file_write_all(path, text, len);

  json_t *out = j_obj();
  j_set_bool(out, "ok", 1);
  j_set_str(out, "id", id);
  j_set_str(out, "name", name ? name : "");
  j_set_str(out, "kind", str_ieq(kind, "image") ? "image" : "text");
  j_set_num(out, "size", (double)len);
  char *dump = json_dump(out);
  http_res_json(res, 200, dump);
  free(dump);
  json_free(out);
  json_free(body);
}

/* 取附件内容:只认 attachments/<sid>/ 下的文件,id 里不许有路径分隔符 */
static char *attach_read(const char *sid, const char *id, size_t cap, size_t *out_len) {
  if (out_len) *out_len = 0;
  if (!sid || !id || !*id) return NULL;
  if (strchr(id, '\\') || strchr(id, '/') || strstr(id, "..")) return NULL;
  char safe_sid[64];
  snprintf(safe_sid, sizeof(safe_sid), "%s", sid);
  for (char *p = safe_sid; *p; p++) {
    if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_') *p = '_';
  }
  char dir[MAX_PATH * 2], path[MAX_PATH * 4];
  path_join(dir, sizeof(dir), g_data_dir, "attachments");
  path_join(dir, sizeof(dir), dir, safe_sid);
  path_join(path, sizeof(path), dir, id);
  size_t len = 0;
  char *text = file_read_all(path, &len);
  if (!text) return NULL;
  if (len > cap) {
    text[cap] = 0;
    len = cap;
  }
  if (out_len) *out_len = len;
  return text;
}

/* 会话列表与回看:界面左栏点一条,就能回到那次对话。
   ?run=RUN-0001 时返回"这次运行"的详情与它所属的会话 —— 老记录没有会话,
   也能点进去看当时的统计与发现,而不是掉进一个笼统的历史页。 */
static void h_chats(const http_req_t *req, http_res_t *res) {
  /* 归档/取消归档:记在 chats 集合里(id 就是那条运行/会话的编号)。
     换浏览器、换标签页都还在 —— 归档是用户的决定,不该只活在一个页面里。 */
  if (strcmp(req->method, "POST") == 0) {
    json_t *body = req->body ? json_parse(req->body) : NULL;
    const char *action = body ? j_s(body, "action", "") : "";
    const char *id = body ? j_s(body, "id", "") : "";
    if (!id[0] || (!str_ieq(action, "archive") && !str_ieq(action, "unarchive"))) {
      if (body) json_free(body);
      http_res_json(res, 400, "{\"ok\":false,\"error\":\"需要 id 与 action(archive/unarchive)\"}");
      return;
    }
    int on = str_ieq(action, "archive") ? 1 : 0;
    int pinned = (int)j_n(body, "pinned", -1);
    json_t *cur = thread_get(id);
    int cur_pinned = cur ? (int)j_b(cur, "pinned", 0) : 0;
    json_free(cur);
    thread_set_flags(id, on, pinned >= 0 ? pinned : cur_pinned);
    if (body) json_free(body);
    json_t *root = j_obj();
    j_set_bool(root, "ok", 1);
    j_set_str(root, "id", id);
    j_set_bool(root, "archived", on);
    char *text = json_dump(root);
    http_res_json(res, 200, text);
    free(text);
    json_free(root);
    return;
  }

  char arch[8];
  http_query(req, "archived", arch, sizeof(arch), "");
  if (arch[0]) {
    /* 归档状态现在存在会话 meta 里,按 id 拼成 {id: archived} 给界面用 */
    json_t *all = thread_list();
    json_t *items = j_arr();
    for (int i = 0; i < j_len(all); i++) {
      json_t *m = j_at(all, i);
      json_t *o = j_obj();
      j_set_str(o, "id", j_s(m, "id", ""));
      j_set_bool(o, "archived", j_b(m, "archived", 0));
      j_set_bool(o, "pinned", j_b(m, "pinned", 0));
      j_add(items, o);
    }
    json_free(all);
    json_t *root = j_obj();
    j_set_bool(root, "ok", 1);
    j_set(root, "items", items);
    char *text = json_dump(root);
    http_res_json(res, 200, text);
    free(text);
    json_free(root);
    return;
  }

  char run_id[32];
  http_query(req, "run", run_id, sizeof(run_id), "");
  if (run_id[0]) {
    json_t *r = store_get(g_store, "runs", run_id);
    json_t *fs = store_findings_of_run(g_store, run_id);
    json_t *root = j_obj();
    j_set_bool(root, "ok", 1);
    j_set_str(root, "session", r ? j_s(r, "session", "") : "");
    j_set(root, "run", r ? r : j_obj());
    j_set(root, "findings", fs ? fs : j_arr());
    char *text = json_dump(root);
    http_res_json(res, 200, text);
    free(text);
    json_free(root);
    return;
  }

  char sid[64];
  http_query(req, "sid", sid, sizeof(sid), "");
  if (sid[0]) {
    json_t *msgs = thread_messages(sid, 0);
    json_t *meta = thread_get(sid);
    json_t *root = j_obj();
    j_set_bool(root, "ok", 1);
    j_set_str(root, "id", sid);
    j_set_str(root, "title", j_s(meta, "title", ""));
    j_set(root, "messages", msgs);
    json_free(meta);
    char *text = json_dump(root);
    http_res_json(res, 200, text);
    free(text);
    json_free(root);
    return;
  }
  json_t *list = thread_list();
  json_t *root = j_obj();
  j_set_bool(root, "ok", 1);
  j_set(root, "items", list);
  char *text = json_dump(root);
  http_res_json(res, 200, text);
  free(text);
  json_free(root);
}

/* 退出程序:和托盘右键「彻底退出」走同一条路 —— 服务收摊、主线程返回、
   再把托盘图标摘掉。放在这里是因为界面里也该有个"退出"的入口,
   而且自动化测试没法去点托盘菜单,只能靠这个接口验证同一条收尾路径。 */
static void h_quit(const http_req_t *req, http_res_t *res) {
  (void)req;
  log_info("收到退出请求,服务即将停止");
  http_res_json(res, 200, "{\"ok\":true,\"bye\":true}");
  /* 回包要先发出去,再停服务 —— 顺序反了浏览器只会看到连接被断开 */
  Sleep(120);
  http_stop();
}

/* 用户点"停止":把信号打给正在跑的那一轮。   循环在每一步、每一次请求发出之前都会看这个标志,所以能立刻撒手。 */
static void h_cancel(const http_req_t *req, http_res_t *res) {
  char sid[64];
  http_query(req, "sid", sid, sizeof(sid), "");
  if (!sid[0] && req->body) {
    json_t *body = json_parse(req->body);
    if (body) {
      snprintf(sid, sizeof(sid), "%s", j_s(body, "sid", ""));
      json_free(body);
    }
  }
  agent_slot_t *slot = agent_slot_find(sid);
  if (!slot) {
    http_res_json(res, 404, "{\"ok\":false,\"error\":\"没有这个会话\"}");
    return;
  }
  int was = agent_cancelled(slot->a);
  agent_cancel(slot->a);
  http_res_json(res, 200, was ? "{\"ok\":true,\"already\":true}" : "{\"ok\":true}");
}

/* ================= 能力管理(技能 / 工具,图形化) =================
   目的:加一个技能或工具不该要求人会写 front-matter、会拼 JSON。
   这里把同一份落盘文件用表单生成,并提供两条"不用自己动脑"的路:
     · 用大模型生成(给一句话描述,模型产出草稿,人再改)
     · 从市场导入(粘贴一段技能/工具文本,校验后落盘)
   落盘格式与手写完全一致 —— 想手改随时还能改。 */
static void h_caps(const http_req_t *req, http_res_t *res) {
  if (strcmp(req->method, "POST") == 0) {
    json_t *body = req->body ? json_parse(req->body) : NULL;
    if (!body) {
      http_res_json(res, 400, "{\"ok\":false,\"error\":\"请求体不是合法 JSON\"}");
      return;
    }
    const char *action = j_s(body, "action", "");
    /* action 指向 body 内部,body 释放后就成了野指针 —— 先拷一份 */
    char action_copy[64];
    snprintf(action_copy, sizeof(action_copy), "%s", action);
    char err[512] = {0};
    int rc = -1;

    if (str_ieq(action, "save_skill")) {
      rc = ext_save_skill(j_s(body, "name", ""), j_s(body, "title", ""),
                          j_s(body, "purpose", ""), j_s(body, "when", ""),
                          j_s(body, "tools", ""), j_s(body, "body", ""),
                          j_s(body, "command", ""), (int)j_n(body, "allow", 0),
                          (int)j_n(body, "timeout_ms", 20000), err, sizeof(err));
    } else if (str_ieq(action, "save_tool")) {
      rc = ext_save_tool(j_s(body, "name", ""), j_s(body, "description", ""),
                         j_s(body, "command", ""), j_s(body, "schema", ""),
                         j_s(body, "kind", ""), (int)j_n(body, "allow", 0),
                         (int)j_n(body, "timeout_ms", 20000), err, sizeof(err));
    } else if (str_ieq(action, "delete_skill")) {
      rc = ext_delete_skill(j_s(body, "name", ""), err, sizeof(err));
    } else if (str_ieq(action, "delete_tool")) {
      rc = ext_delete_tool(j_s(body, "name", ""), err, sizeof(err));
    } else if (str_ieq(action, "reload")) {
      ext_reload_local();
      rc = 0;
    } else if (str_ieq(action, "fetch")) {
      /* 从市场下载一份定义(只是"取回来看看",不落盘) */
      const char *url = j_s(body, "url", "");
      char *text = NULL;
      size_t len = 0;
      int ok = net_get_text(url, &text, &len, err, sizeof(err));
      json_free(body);
      json_t *o = j_obj();
      j_set_bool(o, "ok", ok == 0);
      if (ok == 0) j_set_str(o, "text", text ? text : "");
      else j_set_str(o, "error", err[0] ? err : "下载失败");
      char *dump = json_dump(o);
      http_res_json(res, ok == 0 ? 200 : 400, dump);
      free(dump);
      json_free(o);
      free(text);
      return;
    } else if (str_ieq(action, "draft")) {
      /* 用大模型起草。模型不可用时如实说明,并给一份能直接用的模板 ——
         不能因为平台 403 就把这条路堵死。 */
      const char *kind = j_s(body, "kind", "skill");
      const char *brief = j_s(body, "brief", "");
      json_t *draft = j_obj();
      int from_model = 0;

      buf_t prompt;
      buf_init(&prompt);
      if (str_ieq(kind, "tool")) {
        buf_puts(&prompt,
            "你在为一个网站安全巡检智能体写「外部工具」的定义。只输出一个 JSON 对象,不要解释、不要代码块。\n"
            "字段:name(小写字母数字下划线,动词_名词)、description(一句话说明它做什么、什么时候用)、\n"
            "command(要执行的命令行,参数用 $参数名 占位)、schema(JSON Schema 对象,描述参数)、\n"
            "timeout_ms(整数,默认 20000)。\n用户需求:");
      } else {
        buf_puts(&prompt,
            "你在为一个网站安全巡检智能体写「技能」的定义。只输出一个 JSON 对象,不要解释、不要代码块。\n"
            "字段:name(以 skill_ 开头)、title(中文名)、purpose(解决什么问题,一句话)、\n"
            "when(什么时候该用它,一句话)、tools(用到的工具名,逗号分隔)、body(给模型看的做法说明,Markdown)。\n"
            "可用工具:site_crawl、sensitive_file_probe、dir_probe、page_diff、nuclei_scan、sqli_probe、"
            "sensitive_scan、password_check。\n用户需求:");
      }
      buf_puts(&prompt, brief);
      buf_t out;
      buf_init(&out);
      int ok = llm_ask(prompt.data, &out);
      buf_free(&prompt);
      if (ok == 0) {
        const char *s = out.data ? strstr(out.data, "{") : NULL;
        json_t *parsed = s ? json_parse(s) : NULL;
        if (parsed && parsed->type == J_OBJ) {
          j_set(draft, "draft", parsed);
          from_model = 1;
        } else {
          json_free(parsed);
          j_set_str(draft, "note", "模型返回的内容不是可用的 JSON,已给出模板");
        }
      } else {
        j_set_str(draft, "note", llm_last_error()[0] ? llm_last_error()
                                                     : "模型当前不可用,已给出模板");
      }
      buf_free(&out);
      if (!from_model) {
        json_t *t = j_obj();
        if (str_ieq(kind, "tool")) {
          j_set_str(t, "name", "my_check");
          j_set_str(t, "description", "调用本机脚本做一次自定义检查(输出即结论依据)");
          j_set_str(t, "command", "powershell -NoProfile -Command \"$u='$target'; ...\"");
          j_set_str(t, "schema", "{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\"}},\"required\":[\"target\"]}");
          j_set_num(t, "timeout_ms", 20000);
        } else {
          j_set_str(t, "name", "skill_my_check");
          j_set_str(t, "title", "自定义检查");
          j_set_str(t, "purpose", "按本单位的口径做一次针对性检查");
          j_set_str(t, "when", "用户提出这类检查需求时");
          j_set_str(t, "tools", "site_crawl,sensitive_file_probe");
          j_set_str(t, "body", "1. 先用 site_crawl 拿到assets\n2. 对关心的路径做 sensitive_file_probe\n3. 只报有证据的结论");
        }
        j_set(draft, "draft", t);
      }
      j_set_bool(draft, "ok", 1);
      j_set_bool(draft, "fromModel", from_model);
      char *text = json_dump(draft);
      http_res_json(res, 200, text);
      free(text);
      json_free(draft);
      json_free(body);
      return;
    } else {
      json_free(body);
      http_res_json(res, 400, "{\"ok\":false,\"error\":\"未知的 action\"}");
      return;
    }

    json_free(body);
    if (rc != 0) {
      json_t *o = j_obj();
      j_set_bool(o, "ok", 0);
      j_set_str(o, "error", err[0] ? err : "操作失败");
      char *text = json_dump(o);
      http_res_json(res, 400, text);
      free(text);
      json_free(o);
      return;
    }
    ext_reload_local();
    store_audit(g_store, "修改能力定义", action_copy, 1, "", g_task, "");
    json_t *inv = ext_inventory_json();
    json_t *o = j_obj();
    j_set_bool(o, "ok", 1);
    j_set(o, "ext", inv);
    j_set_num(o, "tools", tools_count());
    j_set_num(o, "skills", skills_count());
    char *text = json_dump(o);
    http_res_json(res, 200, text);
    free(text);
    json_free(o);
    return;
  }

  /* GET:内置 + 外部合成一张清单 */
  json_t *inv = ext_inventory_json();
  json_t *extSkills = j_get(inv, "skills");
  json_t *extTools = j_get(inv, "tools");
  json_t *mcp = j_get(inv, "mcp");

  char dirSkills[MAX_PATH * 2], dirTools[MAX_PATH * 2];
  ext_dir(dirSkills, sizeof(dirSkills), "skills");
  ext_dir(dirTools, sizeof(dirTools), "tools");

  json_t *skills = j_arr();
  for (int i = 0; i < skills_count(); i++) {
    skill_t *sk = skills_get(i);
    if (!sk || !sk->name) continue;
    json_t *o = j_obj();
    j_set_str(o, "name", sk->name);
    j_set_str(o, "title", sk->title ? sk->title : "");
    j_set_str(o, "purpose", sk->purpose ? sk->purpose : "");
    j_set_str(o, "when", sk->when ? sk->when : "");
    j_set_str(o, "tools", sk->tools ? sk->tools : "");
    j_set_str(o, "source", "内置");
    char mdPath[MAX_PATH * 4];
    snprintf(mdPath, sizeof(mdPath), "%s\\%s.md", dirSkills, sk->name);
    if (file_size(mdPath) >= 0) j_set_bool(o, "customized", 1);
    for (int k = 0; k < j_len(extSkills); k++) {
      if (strcmp(j_s(j_at(extSkills, k), "name", ""), sk->name) == 0) {
        j_set_str(o, "source", "技能包");
        j_set_str(o, "file", j_s(j_at(extSkills, k), "file", ""));
        j_set_bool(o, "hasCommand", j_s(j_at(extSkills, k), "command", "")[0] ? 1 : 0);
        j_set_str(o, "body", j_s(j_at(extSkills, k), "body", ""));
        j_set_str(o, "command", j_s(j_at(extSkills, k), "command", ""));
        j_set_bool(o, "allow", j_b(j_at(extSkills, k), "allow", 0));
        break;
      }
    }
    j_add(skills, o);
  }

  json_t *tools = j_arr();
  for (int i = 0; i < tools_count(); i++) {
    tool_t *t = tools_get(i);
    if (!t || !t->name) continue;
    json_t *o = j_obj();
    j_set_str(o, "name", t->name);
    j_set_str(o, "kind", t->kind ? t->kind : "");
    j_set_str(o, "description", t->description ? t->description : "");
    j_set_str(o, "source", "内置");
    j_set_str(o, "sourceUrl", t->source_url ? t->source_url : "");
    if (str_startswith(t->name, "mcp__")) j_set_str(o, "source", "MCP");
    for (int k = 0; k < j_len(extTools); k++) {
      if (strcmp(j_s(j_at(extTools, k), "name", ""), t->name) == 0) {
        j_set_str(o, "source", "外部");
        j_set_str(o, "file", j_s(j_at(extTools, k), "file", ""));
        j_set_str(o, "command", j_s(j_at(extTools, k), "command", ""));
        j_set_str(o, "schema", j_s(j_at(extTools, k), "schema", ""));
        j_set_str(o, "extDescription", j_s(j_at(extTools, k), "description", ""));
        j_set_bool(o, "allow", j_b(j_at(extTools, k), "allow", 0));
        j_set_num(o, "timeout_ms", j_n(j_at(extTools, k), "timeout_ms", 20000));
        break;
      }
    }
    j_add(tools, o);
  }

  int nTools = 0, nSkills = 0, nMCP = 0, nMCPTools = 0;
  ext_stats(&nTools, &nSkills, &nMCP, &nMCPTools);

  json_t *root = j_obj();
  j_set_bool(root, "ok", 1);
  j_set(root, "skills", skills);
  j_set(root, "tools", tools);
  /* j_set 会接管所有权,mcp 是 inv 的子节点 —— 直接交出去,
     紧接着 json_free(inv) 就会把它再释放一次(堆被踩坏,表现为"点保存后服务消失了")。
     所以这里深拷贝一份再交。 */
  {
    char *mcpText = json_dump(mcp);
    json_t *mcpCopy = mcpText ? json_parse(mcpText) : NULL;
    free(mcpText);
    j_set(root, "mcp", mcpCopy ? mcpCopy : j_arr());
  }
  j_set_str(root, "skillsDir", dirSkills);
  j_set_str(root, "toolsDir", dirTools);
  json_t *stats = j_obj();
  j_set_num(stats, "skills", skills_count());
  j_set_num(stats, "tools", tools_count());
  j_set_num(stats, "extSkills", nSkills);
  j_set_num(stats, "extTools", nTools);
  j_set_num(stats, "mcp", nMCP);
  j_set_num(stats, "mcpTools", nMCPTools);
  j_set(root, "stats", stats);
  char *text = json_dump(root);
  http_res_json(res, 200, text);
  free(text);
  json_free(root);
  json_free(inv);
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
    if (!strcmp(p, "/api/cancel")) { h_cancel(req, res); return; }
    if (!strcmp(p, "/api/chats")) { h_chats(req, res); return; }
    if (!strcmp(p, "/api/attach")) { h_attach(req, res); return; }
    if (!strcmp(p, "/api/settings")) { api_rules(req, res); return; }
    if (!strcmp(p, "/api/caps")) { h_caps(req, res); return; }
    if (!strcmp(p, "/api/models")) { api_models(req, res); return; }
    if (!strcmp(p, "/api/quit")) { h_quit(req, res); return; }
    if (!strcmp(p, "/api/chat")) { h_chat(req, res); return; }
    if (!strcmp(p, "/api/config/list")) { api_config_list(req, res); return; }
    if (!strcmp(p, "/api/config")) {
      if (strcmp(req->method, "POST") == 0) api_config_save(req, res);
      else api_config_get(req, res);
      return;
    }
    if (!strcmp(p, "/api/reload")) { api_reload(req, res); return; }
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
  /* 对话存储:新结构(threads/<id>/{meta,messages,events})。
     启动时把旧的 transcripts/*.jsonl 迁进来,只迁一次(迁过的改名 .migrated)。 */
  thread_store_init(g_data_dir);
  {
    int migrated = thread_migrate_legacy();
    if (migrated > 0) log_info("[对话] 已迁移 %d 个旧会话到 threads/ 结构", migrated);
  }
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

  /* 目标可能不是 443/80,也不一定是 https:环境变量 TARGET_BASE_URL 指定真实站点地址 */
  {
    const char *base = getenv("TARGET_BASE_URL");
    if (base && *base) net_set_target_base(base);
  }

  InitializeCriticalSection(&g_lock);
  InitializeCriticalSection(&g_status_lock);
  /* 本次运行的接口令牌与端口:界面页面里会带上它,跨站请求拿不到 */
  g_port = port;
  make_token(g_token, sizeof(g_token));
  agents_init();
  approval_init();
  g_sched_agent = agent_create("scheduler");
  agent_set_store(g_sched_agent, g_store, "");
  agent_set_hooks(g_sched_agent, &g_hooks);
  apply_scope(domain);
  refresh_status_cache();

  printf("════════════════════════════════════════════════════════\n");
  printf("  网站安全巡检智能体(C 版) · 后端服务已启动\n");
  printf("════════════════════════════════════════════════════════\n");
  printf("  界面地址 : http://127.0.0.1:%d/\n", port);
  printf("  决策模型 : %s\n", providers_display_name());
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
    /* 先挂托盘,再开窗口 —— 顺序反了的话,窗口一关就找不到"留在托盘"这条路,
       程序会当场退出(托盘还没建好)。 */
    tray_start(port, "网站安全巡检智能体");
    /* UI_MODE=native:本进程内的原生窗口(正在逐块搭建,尚未到达功能对等)。
       默认仍开系统的 --app 应用窗口,保证任何时候都有一个能用的界面。 */
    const char *ui_mode = getenv("UI_MODE");
    int want_native = ui_mode && str_ieq(ui_mode, "native");
    int native_ok = 0;
    if (want_native) {
      native_ok = (native_ui_start(port, "网站安全巡检") == 0);
      if (!native_ok) log_warn("原生窗口起不来,回退到 --app 应用窗口");
    }
    if (!native_ok) ui_open_url_async(port);
  }

  int serve_rc = http_serve(NULL, port, router, NULL);

  sched_stop();
  printf("服务已停止。\n");
  native_ui_stop();
  ui_close();
  tray_stop();
  int port_busy = (serve_rc != 0) && str_icontains(http_last_error(), "占用");
  for (int i = 0; i < g_agent_count; i++) {
    agent_free(g_agents[i].a);
    DeleteCriticalSection(&g_agents[i].lock);
  }
  g_agent_count = 0;
  agent_free(g_sched_agent);
  g_sched_agent = NULL;
  store_close(g_store);
  free(g_status_cache);
  DeleteCriticalSection(&g_status_lock);
  DeleteCriticalSection(&g_lock);
  http_shutdown();
  if (port_busy) return 2;          /* 让调用方换个端口再试 */
  return serve_rc == 0 ? 0 : 1;
}

const char *serve_token(void) { return g_token; }
