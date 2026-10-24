/* agent.cpp —— 决策循环:智能体的"大脑回路"。
 *
 * 一轮对话 = 一次完整循环:
 *
 *   ┌─→ 感知(把用户输入 + 历史 + 已获得的观察组织成决策上下文)
 *   │      ↓
 *   │   规划/决策(模型:选技能或工具,或直接回答;模型不可用则如实中止)
 *   │      ↓
 *   │   行动(执行技能/工具 —— 全部经过授权校验与限速)
 *   │      ↓
 *   │   观察(把结果结构化并追加到观察序列)
 *   │      ↓
 *   └── 反思(结果是否推进了结论?重复了吗?够不够收尾?……由程序判定 + 模型再决策)
 *          ↓
 *        收敛(给出结论 / 需要用户补充 / 判定无进展 / 触发预算上限)
 *
 * 与"扫描脚本"的本质区别,就在这个"反思"环节:
 *   · 观察到"目标不可达" → 不再继续跑别的检查,直接如实汇报;
 *   · 观察到"同一件事结果没变化" → 判定无进展,收尾而不是无限重试;
 *   · 观察到"已经拿到足够信息" → 直接给结论,不再多跑;
 *   · 每一步的决策理由与观察都留痕,报告里能回答"为什么是这个结论"。
 */
#include "agent.h"

#include <ctype.h>

#include "llm.h"
#include "net.h"
#include "skills.h"
#include "store.h"
#include "tools.h"

struct agent {
  char session_id[128];
  char task_id[64];
  char run_id[64];
  char **domains;
  int domain_count;
  void *store;           /* store_t*,可为 NULL(不落盘也能跑) */
  agent_hooks_t hooks;
  /* 对话历史:决定"这轮说的是哪个站""刚才聊到哪了" */
  json_t *history;
  int turn_index;
  /* 步数预算:兜底用,正常情况下靠"反思"提前收尾 */
  int max_steps;
  /* 用户叫停:跨线程写、循环线程读。动作用的是原子读,不用锁。 */
  volatile LONG cancel;
  /* 1 = 定时/自动巡检,没有人在看:不许提问,直接按增量做 */
  int unattended;
  /* 累计花在模型请求上的毫秒数:用来向用户解释"为什么这轮快/那轮慢" */
  long long llm_ms;
  buf_t scope_note;      /* 拼好的授权范围说明(提示词里用) */
  /* ---- 上下文(占用环 + 压缩) ----
     used 是"上一次提示词估算出来的 token 数",window 是模型的输入上限,
     reserve 是留给响应的那一截。三个数一起决定"要不要压缩"。 */
  int ctx_used;
  int ctx_window;
  int ctx_reserve;
  int ctx_compressed;    /* 这一会话已经压缩过几轮 */
  buf_t ctx_summary;     /* 压缩出来的摘要(拼进提示词,替代被压掉的轮次) */
};

/* ================= 生命周期 ================= */
agent_t *agent_create(const char *session_id) {
  tools_init();
  skills_init();

  agent_t *a = (agent_t *)xcalloc(1, sizeof(agent_t));
  snprintf(a->session_id, sizeof(a->session_id), "%s",
           session_id && *session_id ? session_id : "agent-session");
  a->history = j_arr();
  a->max_steps = MAX_STEPS_DEFAULT;
  buf_init(&a->scope_note);
  buf_init(&a->ctx_summary);
  a->ctx_window = 128000;
  a->ctx_reserve = 16000;
  return a;
}

void agent_free(agent_t *a) {
  if (!a) return;
  json_free(a->history);
  if (a->domains) str_free_list(a->domains, a->domain_count);
  buf_free(&a->scope_note);
  buf_free(&a->ctx_summary);
  free(a);
}

/* ---------- 上下文用量与压缩 ---------- */
void agent_set_ctx_used(agent_t *a, int tokens) { if (a) a->ctx_used = tokens; }
void agent_set_ctx_window(agent_t *a, int window, int reserve) {
  if (!a) return;
  a->ctx_window = window > 0 ? window : 128000;
  a->ctx_reserve = reserve > 0 ? reserve : (a->ctx_window / 8);
}
int agent_ctx_used(agent_t *a) { return a ? a->ctx_used : 0; }
int agent_ctx_window(agent_t *a) { return a ? a->ctx_window : 0; }
int agent_ctx_reserve(agent_t *a) { return a ? a->ctx_reserve : 0; }
int agent_ctx_compressed(agent_t *a) { return a ? a->ctx_compressed : 0; }
const char *agent_ctx_summary(agent_t *a) { return a && a->ctx_summary.data ? a->ctx_summary.data : ""; }

void agent_ctx_set_summary(agent_t *a, const char *summary, int compacted_turns) {
  if (!a) return;
  buf_clear(&a->ctx_summary);
  if (summary && *summary) buf_puts(&a->ctx_summary, summary);
  a->ctx_compressed = compacted_turns > 0 ? compacted_turns : 0;
}

/* 压缩后历史只剩"最近几轮":旧的那部分已经被摘要代表了 */
void agent_history_keep_recent(agent_t *a, int keep) {
  if (!a || keep < 0) return;
  while (j_len(a->history) > keep) {
    json_t *keepArr = j_arr();
    for (int i = 1; i < j_len(a->history); i++) j_add(keepArr, j_clone(j_at(a->history, i)));
    json_free(a->history);
    a->history = keepArr;
  }
}

void agent_set_hooks(agent_t *a, const agent_hooks_t *hooks) {
  if (a && hooks) a->hooks = *hooks;
}

void agent_set_unattended(agent_t *a, int on) {
  if (a) a->unattended = on ? 1 : 0;
}

int agent_unattended(agent_t *a) { return a ? a->unattended : 0; }

long long agent_llm_ms(agent_t *a) { return a ? a->llm_ms : 0; }
void agent_llm_ms_reset(agent_t *a) {
  if (a) a->llm_ms = 0;
}

static void emit(agent_t *a, int which, const char *s1, const char *s2, json_t *args) {
  if (!a) return;
  switch (which) {
    case 0: if (a->hooks.on_thinking) a->hooks.on_thinking(a->hooks.userdata, s1); break;
    case 1: if (a->hooks.on_action) a->hooks.on_action(a->hooks.userdata, s1, args, s2); break;
    case 2: if (a->hooks.on_status) a->hooks.on_status(a->hooks.userdata, s1, s2, ""); break;
    case 3: if (a->hooks.on_answer) a->hooks.on_answer(a->hooks.userdata, s1); break;
    case 4: if (a->hooks.on_ask) a->hooks.on_ask(a->hooks.userdata, s1); break;
    default: break;
  }
}
#define EMIT_THINKING(a, t)  emit((a), 0, (t), NULL, NULL)
#define EMIT_ANSWER(a, t)    emit((a), 3, (t), NULL, NULL)
#define EMIT_ASK(a, t)       emit((a), 4, (t), NULL, NULL)
#define EMIT_STATUS(a, t, s) emit((a), 2, (t), (s), NULL)

void agent_set_scope(agent_t *a, const char *task_id, const char **domains, int n) {
  if (!a) return;
  if (a->domains) { str_free_list(a->domains, a->domain_count); a->domains = NULL; }
  a->domain_count = 0;
  if (domains && n > 0) {
    a->domains = (char **)xcalloc((size_t)n, sizeof(char *));
    for (int i = 0; i < n; i++) a->domains[i] = xstrdup(domains[i]);
    a->domain_count = n;
  }
  snprintf(a->task_id, sizeof(a->task_id), "%s", task_id ? task_id : "");
  net_set_scope(a->task_id, (const char **)a->domains, a->domain_count);

  buf_clear(&a->scope_note);
  if (a->domain_count == 0) {
    buf_puts(&a->scope_note,
             "本轮没有指定单一目标(用户没点具体某个站,或是在问整体情况)。\n");
  } else {
    buf_printf(&a->scope_note, "本轮焦点:%s\n任务 %s。\n", a->domains[0],
               a->task_id[0] ? a->task_id : "(未命名)");
    if (a->domain_count > 1) {
      buf_puts(&a->scope_note, "本轮可覆盖:");
      for (int i = 1; i < a->domain_count; i++) buf_printf(&a->scope_note, " %s", a->domains[i]);
      buf_puts(&a->scope_note, "\n");
    }
  }

  /* —— 授权池:必须让模型看见完整的"能查谁" ——
     以前这里只写"本轮焦点"一个域,用户说"把授权列表里的站都巡检一遍"时,
     模型压根不知道列表里有什么,只能反问或只查一个站(实测遇到的问题)。
     现在把池子原样摊给它:允许的、明确不允许的,以及"多站点要逐个来"的做法。 */
  {
    char **pool = NULL;
    int pn = net_pool_snapshot(&pool);
    int allow = 0, deny = 0;
    for (int i = 0; i < pn; i++) {
      if (pool[i] && pool[i][0] == '!') deny++;
      else if (pool[i] && pool[i][0]) allow++;
    }
    if (pn == 0) {
      buf_puts(&a->scope_note,
               "授权池是空的 —— 一个对外请求都不允许发。先让用户把主机加进授权池。\n");
    } else {
      buf_printf(&a->scope_note, "授权池(共 %d 条,允许 %d 个目标):", pn, allow);
      for (int i = 0; i < pn; i++) {
        if (!pool[i] || !pool[i][0] || pool[i][0] == '!') continue;
        buf_printf(&a->scope_note, " %s;", pool[i]);
      }
      buf_puts(&a->scope_note, "\n");
      if (deny > 0) {
        buf_puts(&a->scope_note, "明确不允许访问(不要碰):");
        for (int i = 0; i < pn; i++) {
          if (pool[i] && pool[i][0] == '!' && pool[i][1]) buf_printf(&a->scope_note, " %s;", pool[i]);
        }
        buf_puts(&a->scope_note, "\n");
      }
      buf_puts(&a->scope_note,
               "池里的目标都在授权范围内:用户点名某个站就以它为本轮焦点;\n"
               "用户要求「所有授权站点/授权列表都查一遍」时,逐个站点来做 —— 一次只对一个目标动手,\n"
               "每个站单独传 target(带协议与端口,例如 https://host),不要合并成一次请求,\n"
               "也不要因为第一个站跑完就收尾,还没查的站要接着查。\n");
    }
    str_free_list(pool, pn);
  }
}

void agent_set_store(agent_t *a, void *store, const char *run_id) {
  if (!a) return;
  a->store = store;
  snprintf(a->run_id, sizeof(a->run_id), "%s", run_id ? run_id : "");
}

/* 叫停本轮:界面点"停止"时从另一个线程写,循环在下一步 / 下一次请求前读到。 */
void agent_cancel(agent_t *a) {
  if (a) InterlockedExchange(&a->cancel, 1);
}

void agent_cancel_clear(agent_t *a) {
  if (a) InterlockedExchange(&a->cancel, 0);
}

int agent_cancelled(agent_t *a) { return a ? (int)InterlockedCompareExchange(&a->cancel, 0, 0) : 0; }

void agent_emit_delta(agent_t *a, const char *text) {
  if (!a || !a->hooks.on_delta || !text || !*text) return;
  a->hooks.on_delta(a->hooks.userdata, text);
}

void agent_add_history(agent_t *a, const char *role, const char *text) {
  if (!a) return;
  json_t *turn = j_obj();
  j_set_str(turn, "role", role);
  j_set_str(turn, "text", text);
  j_add(a->history, turn);
  /* 历史只为"多轮指代"服务,不该无限膨胀 —— 留最近 20 条足够。 */
  while (j_len(a->history) > 20) {
    json_t *keep = j_arr();
    for (int i = 1; i < j_len(a->history); i++)
      j_add(keep, j_clone(j_at(a->history, i)));
    json_free(a->history);
    a->history = keep;
  }
}

int agent_history_count(agent_t *a) { return a ? j_len(a->history) : 0; }

const char *agent_history_at(agent_t *a, int i, const char **role_out) {
  if (!a || i < 0 || i >= j_len(a->history)) return NULL;
  json_t *t = j_at(a->history, i);
  if (role_out) *role_out = j_s(t, "role", "");
  return j_s(t, "text", "");
}

/* ================= 反思:程序侧的收敛判定 =================
   模型负责"选下一步",但"该不该停"不能全交给模型 —— 程序必须兜住两类失控:
     ① 原地打转(同样的动作、同样的结果);
     ② 观察到硬性否定信息(不可达/未授权)还硬往下跑。
   这两条是"智能体"和"脚本"的分水岭,所以放在程序里强制生效。 */

/* 观察序列里是否出现过"硬否定"信息 */
static int observed_blocker(json_t *observations, char **why) {
  /* 取数通道的越权标记比"文案匹配"更可靠:只要有一次请求被边界拦下,
     这一轮就必须停 —— 不指望模型自己从文字里读出"我越界了"。 */
  if (net_scope_violation()) {
    if (why) *why = xstrdup("有请求越出授权池,已按合规要求立刻停止整轮");
    return 1;
  }
  for (int i = 0; i < j_len(observations); i++) {
    json_t *o = j_at(observations, i);
    /* 结构化的"被拦住"标记(由各工具/技能写在 data.blocked 里,observation_append
       已经把它带到这一步)优先;下面那点文案匹配只是给"没写标记的老实现"兜底。 */
    const char *blk = j_s(o, "blocker", "");
    if (blk[0]) {
      if (why) {
        *why = xstrdup(strcmp(blk, "out_of_scope") == 0
                           ? "目标不在授权范围内,已按合规要求停止"
                           : "目标不可达,继续跑其他检查没有意义");
      }
      return 1;
    }
    const char *res = j_s(o, "result", "");
    int is_err = j_b(o, "is_error", 0);
    if (!is_err) continue;   /* 只在"失败的那一条"上判定,不拿正常汇报当证据 */
    /* 越权是硬事实:出现了就收束 */
    const char *code = fail_code(res);
    if (strcmp(code, "out_of_scope") == 0) {
      if (why) *why = xstrdup("目标不在授权范围内,已按合规要求停止");
      return 1;
    }
    /* "不可达"以前是全文子串匹配,结果一段正常汇报里出现"2 个地址返回异常(5xx 或连不上)"
       也会被当成整站不可达,整轮白跑 —— 这是误判,不是能力。 */
    if (strcmp(code, "unreachable") == 0) {
      if (why) *why = xstrdup("目标不可达,继续跑其他检查没有意义");
      return 1;
    }
  }
  return 0;
}

/* 这一步和之前某一步是不是"完全同一件事":同名 + 同参 + 同结果 */
static int same_step(json_t *obs, int i, int j) {
  const char *t1 = j_s(j_at(obs, i), "tool", "");
  const char *t2 = j_s(j_at(obs, j), "tool", "");
  const char *g1 = j_s(j_at(obs, i), "args", "");
  const char *g2 = j_s(j_at(obs, j), "args", "");
  const char *r1 = j_s(j_at(obs, i), "result", "");
  const char *r2 = j_s(j_at(obs, j), "result", "");
  if (!t1[0] || strcmp(t1, t2) != 0) return 0;
  if (strcmp(g1, g2) != 0) return 0;
  return strncmp(r1, r2, 200) == 0;
}

/* 这一步的动作+结果在历史里出现过吗?
   为什么要在整段历史里找,而不是只比相邻两步:
     A,B,A,B 这种"交替复读"看起来像在推进工作,其实一个字的新信息都没有 ——
     比单纯的重复更该被识破。旧的相邻比较正好漏掉它。 */
static int is_repeat_of_history(json_t *obs, int idx) {
  for (int j = 0; j < idx; j++) {
    if (same_step(obs, j, idx)) return 1;
  }
  return 0;
}

/* 是否在原地打转:最新这一步与之前某一步同名同参同结果 → 零新信息,没有继续的理由 */
static int is_stuck(json_t *observations) {
  int n = j_len(observations);
  if (n < 2) return 0;
  return is_repeat_of_history(observations, n - 1);
}

/* 连续几步用的都是本轮已经用过的手段?
   同一个技能反复调、只是把参数改一改,结果必然是同一批数据 ——
   这是"看着像在干活"的空转,和逐字重复一样该被识破。 */
static int trailing_no_new_skill(json_t *obs) {
  int n = j_len(obs);
  int run = 0;
  for (int i = n - 1; i >= 0; i--) {
    json_t *o = j_at(obs, i);
    if (!o || o->type != J_OBJ) break;
    /* 只对"技能"设这道闸:技能是成套路的一整轮,换参数重跑同一套确实常是空转。
       工具不一样 —— http_get 连着读十个页面、record_finding 连着记三条,
       正是"顺着线索往下查"的样子,不该被当成打转。 */
    if (!str_startswith(j_s(o, "tool", ""), "skill_")) break;
    if (j_b(o, "new_skill", 0)) break;
    run++;
  }
  return run;
}

/* 这一步有没有"被拦住" —— 先读结构化字段,再读计数,最后才退回文案。
   为什么要分层:上层判断"整轮要不要停"是在读事实,不该靠中文子串。
   但事实目前只有一部分工具会写(data.blocked / data.error / tested-unreachable 计数),
   没写的只能退回文案 —— 归类只在 fail_code 里做一次,别散到决策循环里。 */
static const char *data_blocker(json_t *data) {
  if (!data || data->type != J_OBJ) return "";
  const char *b = j_s(data, "blocked", "");
  if (b[0]) return b;
  const char *code = fail_code(j_s(data, "error", ""));
  if (code[0] == 'o' || code[0] == 'u') return code;   /* out_of_scope / unreachable */
  double tested = j_n(data, "tested", 0);
  if (tested > 0 && j_n(data, "unreachable", 0) >= tested) return "unreachable";
  return "";
}

/* ================= 一步:执行技能或工具 ================= */
static void observation_append(json_t *observations, const char *name, json_t *args,
                              const char *result_text, int is_error, const char *blocker) {
  json_t *o = j_obj();
  j_set_str(o, "tool", name);
  { /* 参数也留一份:判定"打转"时,同名不同参不算重复 */
    char *dump = args ? json_dump(args) : NULL;
    j_set_str(o, "args", dump ? dump : "{}");
    if (dump) free(dump);
  }
  j_set_str(o, "result", result_text ? result_text : "");
  j_set_bool(o, "is_error", is_error);
  if (blocker && *blocker) j_set_str(o, "blocker", blocker);
  /* 这一步用的是不是本轮还没用过的手段?
     模型很会"把参数改一个字再跑一遍",看起来在推进,其实一个新手艺都没用上 ——
     这个标记就是拿来识破它的。 */
  int fresh = 1;
  for (int i = 0; i < j_len(observations); i++) {
    const char *t = j_s(j_at(observations, i), "tool", "");
    if (t[0] && strcmp(t, name) == 0) { fresh = 0; break; }
  }
  j_set_bool(o, "new_skill", fresh);
  j_add(observations, o);
}

/* 最近一步是不是在说"和上次一样、没有变化" */
static int last_observation_unchanged(json_t *observations) {
  int n = j_len(observations);
  if (n <= 0) return 0;
  const char *res = j_s(j_at(observations, n - 1), "result", "");
  return str_icontains(res, "与基线一致") || str_icontains(res, "指纹未变") ||
         str_icontains(res, "未发现改动") || str_icontains(res, "没有发现变化");
}

static int run_step(agent_t *a, tool_ctx_t *ctx, const char *name, json_t *args,
                    json_t *observations, int *out_findings) {
  tool_result_t tr;
  memset(&tr, 0, sizeof(tr));
  skill_result_t sr;
  memset(&sr, 0, sizeof(sr));

  skill_t *sk = skills_find(name);
  tool_t *tl = sk ? NULL : tools_find(name);

  if (!sk && !tl) {
    buf_t msg;
    buf_init(&msg);
    buf_printf(&msg, "没有「%s」这个技能或工具。可用技能:%s", name,
               skills_count() > 0 ? skills_get(0)->name : "(无)");
    EMIT_ANSWER(a, msg.data);
    observation_append(observations, name, args, msg.data, 1, "");
    buf_free(&msg);
    return -1;
  }

  /* —— 行动 —— */
  EMIT_STATUS(a, name, "running");
  if (a->hooks.on_action) {
    a->hooks.on_action(a->hooks.userdata, name, args,
                       sk ? sk->when : tl->description);
  }

  /* —— 用户叫停 —— */
  if (a->cancel) {
    buf_t msg;
    buf_init(&msg);
    buf_puts(&msg, "已按你的要求停下,这一步没有执行。");
    EMIT_ANSWER(a, msg.data);
    observation_append(observations, name, args, msg.data, 1, "");
    buf_free(&msg);
    return -1;
  }

  /* —— 提问:停下来等用户回答 ——
     这是"问一句",不是"动手":不经过审批,也不产生任何请求。
     无人值守(定时巡检)时没人可问,就把这件事写成一条观察,让模型自己按最保守的做法继续。 */
  if (!sk && strcmp(name, "ask_user") == 0) {
    char *payload = args ? json_dump(args) : NULL;
    char *answer = NULL;
    int ok = 0;
    if (!a->unattended && a->hooks.on_question) {
      ok = a->hooks.on_question(a->hooks.userdata, payload ? payload : "{}", &answer);
    }
    free(payload);

    buf_t msg;
    buf_init(&msg);
    if (ok && answer && answer[0]) {
      buf_printf(&msg, "用户回答:%s", answer);
    } else if (a->unattended) {
      buf_puts(&msg,
               "这一轮是定时/自动巡检,没有人在看,没人回答:不要停下来等。"
               "按最保守的做法继续(没有变化就只做增量),并在结论里说明。");
    } else {
      buf_puts(&msg, "用户没有回答(可能关掉了界面):按最保守的做法继续,并在结论里说明这一点。");
    }
    free(answer);
    EMIT_STATUS(a, name, "done");
    observation_append(observations, name, args, msg.data, 0, "");
    if (a->hooks.on_observation) {
      tool_result_t view;
      memset(&view, 0, sizeof(view));
      view.text = msg.data;
      view.say = (char *)"我等你回答。";
      a->hooks.on_observation(a->hooks.userdata, name, &view);
    }
    buf_free(&msg);
    return 0;
  }

  /* —— 权限审批 ——
     主流 Agent 的做法:动手之前先问一句。拒绝不是"报错",而是一条观察 ——
     模型能读到"这一步被拒了、原因是什么",然后换路子或老实收束。
     返回 0 = 拒绝(不执行),返回 1 = 放行。 */
  if (a->hooks.on_approval) {
    char *reason = NULL;
    int allow = a->hooks.on_approval(a->hooks.userdata, name, args, &reason);
    if (!allow) {
      buf_t msg;
      buf_init(&msg);
      buf_printf(&msg, "这一步没有得到你的允许,已跳过(%s)。",
                 (reason && reason[0]) ? reason : "按审批策略未放行");
      EMIT_ANSWER(a, msg.data);
      observation_append(observations, name, args, msg.data, 1, "");
      buf_free(&msg);
      free(reason);
      return 0;
    }
    free(reason);
  }

  int rc;
  const char *text = NULL;
  json_t *data = NULL;
  const char *say = NULL;
  int is_err = 0;

  if (sk) {
    rc = skills_run(ctx, name, args, &sr);
    text = sr.summary;
    data = sr.data;
    say = sr.summary;
    is_err = sr.is_error;
    if (out_findings) *out_findings += sr.finding_count;
  } else {
    rc = tools_run(ctx, name, args, &tr);
    text = tr.text;
    data = tr.data;
    say = tr.say;
    is_err = tr.is_error;
  }

  EMIT_STATUS(a, name, is_err ? "error" : "done");

  /* —— 观察 —— */
  observation_append(observations, name, args, text, is_err, data_blocker(data));

  /* 结构化结果通过 hook 推给界面(界面要渲染工具卡片) */
  if (a->hooks.on_observation) {
    tool_result_t view;
    memset(&view, 0, sizeof(view));
    view.text = (char *)text;
    view.data = data;
    view.say = (char *)say;
    view.is_error = is_err;
    a->hooks.on_observation(a->hooks.userdata, name, &view);
  }

  if (sk) { skill_result_free(&sr); }
  else { free(tr.text); free(tr.say); json_free(tr.data); }
  return rc;
}

/* ================= 斜杠命令:绕过模型直接跑一个检查 =================
   主流 agent 产品都有 / 命令:当用户已经知道自己要跑什么时,不该再让模型去猜意图,
   也不该因为模型调不通就什么都干不了。
   命令名 = 技能/工具的短别名(见 kSlash)或真实名字;
   执行仍走同一条路径 —— 授权池、只读、限速、审计、落库一样不少。 */
static const struct {
  const char *cmd;
  const char *name;
  const char *hint;
} kSlash[] = {
    {"inspect", "skill_full_inspection", "完整巡检(资产→完整性→敏感文件→目录→模板)"},
    {"recon", "skill_recon", "摸清资产:页面、静态资源、接口"},
    {"leak", "skill_leak_check", "按本单位定义查敏感文件与泄露"},
    {"integrity", "skill_integrity_check", "内容基线比对:有没有被改"},
    {"retest", "skill_retest", "复测未闭环的问题"},
    {"report", "skill_report", "汇总成分级报告"},
    {"evidence", "skill_evidence", "核对每条结论的证据是否齐"},
    {"get", "http_get", "读一个地址的状态、响应头、正文与链接"},
    {"assets", "asset_list", "列已摸到的资产底账"},
    {"record", "record_finding", "把一条结论落成发现(参数用 JSON)"},
    {"pool", "pool_list", "看授权池"},
    {"info", "agent_info", "看本机状态"},
};

/* 命令名 → 真实名字。先查别名表,再按原名/加 skill_ 前缀查 ——
   三种写法都认:`/recon`、`/skill_recon`、`/recon` 与 `/http_get`。 */
static const char *slash_resolve(const char *cmd) {
  for (size_t i = 0; i < sizeof(kSlash) / sizeof(kSlash[0]); i++) {
    if (str_ieq(kSlash[i].cmd, cmd)) return kSlash[i].name;
  }
  return NULL;
}

static void slash_list(buf_t *out) {
  buf_puts(out, "可用命令(斜杠后面的名字不区分大小写):\n");
  for (size_t i = 0; i < sizeof(kSlash) / sizeof(kSlash[0]); i++) {
    buf_printf(out, "  /%-10s %s\n", kSlash[i].cmd, kSlash[i].hint);
  }
  buf_puts(out, "用法:/命令 目标地址,例如 /recon 127.0.0.1:8081\n"
                "需要多个参数时直接给 JSON:/record {\"title\":\"…\",\"severity\":\"高\",\"evidence\":\"…\"}\n"
                "不带参数就列出该命令的用法。");
}

/* 把命令名后面那一段变成参数:整段是 JSON 就按 JSON;否则按目标地址填到
   该命令真正需要的那个参数名上(schema 里有 target 就是 target,否则 url/path)。 */
static json_t *slash_args(const char *name, const char *rest) {
  json_t *args = j_obj();
  const char *p_rest = rest ? rest : "";
  while (*p_rest == ' ') p_rest++;
  if (!*p_rest) return args;

  if (*p_rest == '{') {
    json_t *given = json_parse(p_rest);
    if (given && given->type == J_OBJ) {
      json_free(args);
      return given;
    }
    if (given) json_free(given);
  }

  /* 参数名从声明里取:不同工具要的字段名不一样,写死一个会调不动 */
  const char *want = "target";
  tool_t *tl = tools_find(name);
  if (tl && tl->schema && tl->schema[0]) {
    json_t *sc = json_parse(tl->schema);
    json_t *props = sc ? j_get(sc, "properties") : NULL;
    if (props && props->type == J_OBJ) {
      if (!j_get(props, "target") && j_get(props, "url")) want = "url";
      else if (!j_get(props, "target") && j_get(props, "path")) want = "path";
    }
    if (sc) json_free(sc);
  }
  j_set_str(args, want, p_rest);
  return args;
}

/* 直接执行一条 / 命令,不经过模型。 */
static int slash_run(agent_t *a, tool_ctx_t *ctx, buf_t *notes, const char *line,
                     loop_state_t *st) {
  const char *p = line + 1;
  while (*p == ' ') p++;
  char cmd[64] = {0};
  size_t n = 0;
  while (p[n] && p[n] != ' ' && n < sizeof(cmd) - 1) {
    cmd[n] = p[n];
    n++;
  }
  cmd[n] = 0;
  const char *rest = p + n;

  if (!cmd[0] || str_ieq(cmd, "help") || str_ieq(cmd, "?")) {
    buf_t t;
    buf_init(&t);
    slash_list(&t);
    EMIT_ANSWER(a, t.data);
    buf_free(&t);
    if (st) {
      st->stop_code = STOP_ANSWERING_ONLY;
      snprintf(st->stop_reason, sizeof(st->stop_reason), "列出斜杠命令");
      st->step_count = 1;
    }
    return 0;
  }

  const char *real = slash_resolve(cmd);
  if (!real) real = cmd;
  const char *name = NULL;
  if (skills_find(real)) name = real;
  else if (tools_find(real)) name = real;
  if (!name) {
    buf_t t;
    buf_init(&t);
    buf_printf(&t, "没有「%s」这条命令。\n\n", cmd);
    slash_list(&t);
    EMIT_ANSWER(a, t.data);
    buf_free(&t);
    if (st) {
      st->stop_code = STOP_NEED_USER;
      snprintf(st->stop_reason, sizeof(st->stop_reason), "命令名不认识");
      st->step_count = 1;
    }
    return 0;
  }

  /* 需要目标的命令没给目标:直接说清楚该带什么,不发请求 */
  json_t *args = slash_args(name, rest);
  if (args->count == 0) {
    skill_t *sk = skills_find(name);
    if (sk && sk->multi_step) {
      buf_t t;
      buf_init(&t);
      buf_printf(&t, "/%s 需要目标地址,例如 /%s 127.0.0.1:8081", cmd, cmd);
      EMIT_ANSWER(a, t.data);
      buf_free(&t);
      json_free(args);
      if (st) {
        st->stop_code = STOP_NEED_USER;
        snprintf(st->stop_reason, sizeof(st->stop_reason), "命令缺少目标");
        st->step_count = 1;
      }
      return 0;
    }
  }

  EMIT_THINKING(a, "直接执行命令,不经过模型…");
  net_scope_violation_clear();
  json_t *observations = j_arr();
  int findings = 0;
  int step_rc = run_step(a, ctx, name, args, observations, &findings);
  (void)notes;

  if (st) {
    json_t *rec = j_obj();
    j_set_num(rec, "step", 1);
    j_set_str(rec, "kind", "act");
    j_set_str(rec, "action", name);
    j_set_str(rec, "reason", "斜杠命令直接执行");
    j_set_bool(rec, "from_model", 0);
    j_add(st->steps, rec);
    st->step_count = 1;
    buf_printf(&st->transcript, "[第 1 步] 斜杠命令:执行 %s\n", name);
  }

  /* 收尾:把工具/技能自己的结论原样交给用户 —— 这就是他要的东西 */
  const char *last = NULL;
  if (j_len(observations) > 0) last = j_s(j_at(observations, j_len(observations) - 1), "result", "");
  buf_t out;
  buf_init(&out);
  if (last && *last) {
    buf_puts(&out, last);
    if (!str_endswith(last, "\n")) buf_puts(&out, "\n");
  } else {
    buf_printf(&out, "/%s 已执行,但没有返回内容。", cmd);
  }
  if (findings > 0) buf_printf(&out, "本轮新增/更新 %d 条发现。\n", findings);
  EMIT_ANSWER(a, out.data);
  buf_free(&out);

  json_free(observations);
  json_free(args);
  if (st) {
    st->stop_code = step_rc == 0 ? STOP_ANSWERED : STOP_ERROR;
    snprintf(st->stop_reason, sizeof(st->stop_reason), "%s",
             step_rc == 0 ? "命令执行完成" : "命令执行出错");
  }
  return step_rc;
}

/* ================= 核心:一轮对话 ================= */
int agent_run_turn(agent_t *a, const char *user_text, loop_state_t *st) {
  if (!a) return -1;
  if (st) {
    memset(st, 0, sizeof(*st));
    buf_init(&st->transcript);
    st->steps = j_arr();
  }

  json_t *observations = j_arr();
  int findings_total = 0;
  int asked_no_change = 0;     /* 同一轮只问一次"要不要重跑" */
  int rc = 0;

  /* 授权范围由智能体自己持有,并在本轮开始时落到本线程的取数通道上。
     这样即使服务端同时在跑别的会话,本轮的边界也只认自己的那一份。 */
  net_set_scope(a->task_id, (const char **)a->domains, a->domain_count);
  net_scope_violation_clear();
  agent_cancel_clear(a);
  a->llm_ms = 0;
  /* 叫停信号也接到取数通道上:一轮里有几十上百次请求,
     只在步与步之间检查的话,"停止"点下去还要等半分钟才生效。 */
  net_set_cancel(&a->cancel);

  /* 决策上下文:授权范围 + 运行编号 + 探测通道 + 存储 */
  tool_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.data_dir = NULL;
  ctx.task_id = a->task_id;
  ctx.run_id = a->run_id;
  ctx.domains = (const char **)a->domains;
  ctx.domain_count = a->domain_count;
  ctx.store = a->store;
  ctx.io.userdata = NULL;
  {
    extern tools_io_t *net_io_impl(void);
    tools_io_t *io = net_io_impl();
    if (io) ctx.io = *io;
  }
  buf_t notes;
  buf_init(&notes);
  ctx.note = &notes;

  /* ---- 斜杠命令:/xxx 目标 → 直接执行,不经过模型 ---- */
  {
    const char *p0 = user_text ? user_text : "";
    while (*p0 == ' ' || *p0 == '\t') p0++;
    if (*p0 == '/') {
      buf_t n;
      buf_init(&n);
      ctx.note = &n;
      int src = slash_run(a, &ctx, &n, p0, st);
      buf_free(&n);
      buf_free(&notes);
      net_set_cancel(NULL);
      return src;
    }
  }

  EMIT_THINKING(a, "正在理解你的意图并规划检查步骤……");
  if (st) buf_puts(&st->transcript, "== 一轮对话开始 ==\n");

  const char *scope = a->scope_note.data ? a->scope_note.data : "";

  for (int step = 0; step < a->max_steps; step++) {
    /* ---- 用户叫停:比任何反思都优先 ---- */
    if (a->cancel) {
      if (st) {
        st->stop_code = STOP_CANCELLED;
        snprintf(st->stop_reason, sizeof(st->stop_reason), "用户中途叫停");
      }
      buf_t n;
      buf_init(&n);
      buf_puts(&n, "已按你的要求停下。");
      if (findings_total > 0)
        buf_printf(&n, "停下前已确认 %d 条风险,详见结果卡片。", findings_total);
      else
        buf_puts(&n, "还没有确认到风险。");
      EMIT_ANSWER(a, n.data);
      buf_free(&n);
      break;
    }

    /* ---- 反思(先于决策):程序侧的硬性收敛判定 ---- */
    char *blocker = NULL;
    if (step > 0 && observed_blocker(observations, &blocker)) {
      if (st) {
        st->stop_code = STOP_OUT_OF_SCOPE;
        snprintf(st->stop_reason, sizeof(st->stop_reason), "%s", blocker);
      }
      EMIT_ANSWER(a, blocker);
      buf_t n;
      buf_init(&n);
      buf_printf(&n, "我没有继续执行:%s\n", blocker);
      buf_puts(&n,
               "这类情况我不会硬报结论。请确认:① 目标是否在授权范围内;"
               "② 站点当前是否可达;然后我可以重试。");
      EMIT_ANSWER(a, n.data);
      buf_free(&n);
      free(blocker);
      break;
    }
    if (step > 0 && is_stuck(observations)) {
      if (st) {
        st->stop_code = STOP_NO_PROGRESS;
        snprintf(st->stop_reason, sizeof(st->stop_reason),
                 "这一步的动作与结果此前已经出现过,判定无进展");
      }
      buf_t n;
      buf_init(&n);
      buf_puts(&n, "我发现这一步的动作和结果在前面已经出现过了 —— 再跑下去不会有新信息,所以停下来汇报。\n");
      if (findings_total > 0)
        buf_printf(&n, "本次已确认 %d 条风险,详见结果卡片。", findings_total);
      else
        buf_puts(&n, "本次没有确认到新的风险。");
      EMIT_ANSWER(a, n.data);
      buf_free(&n);
      break;
    }
    /* 反思第二道:连着两步都在用已经用过的手段 → 空转,收尾 */
    if (step > 0 && trailing_no_new_skill(observations) >= 2) {
      if (st) {
        st->stop_code = STOP_NO_PROGRESS;
        snprintf(st->stop_reason, sizeof(st->stop_reason),
                 "连续两步用的都是前面已经用过的手段,判定没有推进");
      }
      buf_t n;
      buf_init(&n);
      buf_puts(&n,
               "我注意到连着两步都在重复已经做过的检查 —— 换参数重跑同一批数据不会有新结论,"
               "所以停下来汇报。\n");
      if (findings_total > 0)
        buf_printf(&n, "本次已确认 %d 条风险,详见结果卡片。", findings_total);
      else
        buf_puts(&n, "本次没有确认到新的风险。");
      EMIT_ANSWER(a, n.data);
      buf_free(&n);
      break;
    }

    /* ---- 决策 ---- */
    decision_t d;
    memset(&d, 0, sizeof(d));
    int decided = -1;
    if (llm_enabled()) {
      long long t_llm = now_ms();
      decided = llm_decide(a, user_text, observations, scope, &d);
      /* 失败也要计:那次干等同样是"慢"的一部分,不记就永远解释不清 */
      a->llm_ms += now_ms() - t_llm;
    }
    /* 停止信号可能正好落在模型调用里(那一段已经被掐断):这一轮到此为止,
       不要再用规则"替模型把话说完" —— 用户点停止就是不想继续了。
       跳回循环顶部,由那里统一的叫停分支收尾(写停止原因、给一句交代)。 */
    if (a->cancel) {
      decision_free(&d);
      continue;
    }
    if (decided != 0) {
      /* 模型不可用就如实停下。
         以前这里会"降级为本地规则"接着跑,结果是:用户看到一段像模像样的结论,
         但其实一次模型都没问过 —— 智能体的判断不能由关键词匹配冒充。
         要跑确定性的检查,用 / 命令(见下方 slash_run),那是用户明确点的。 */
      const char *why = llm_last_error();
      if (st) {
        st->stop_code = STOP_ERROR;
        snprintf(st->stop_reason, sizeof(st->stop_reason), "模型不可用:%s",
                 (why && *why) ? why : "没有可用的模型配置");
        /* 长原因会被 snprintf 截断:从末尾退到 UTF-8 字符边界,
           不然界面上最后半个汉字会变成乱码方块。 */
        size_t n = strlen(st->stop_reason);
        size_t keep = u8_prefix(st->stop_reason, n);
        if (keep < n) st->stop_reason[keep] = 0;
      }
      buf_t n;
      buf_init(&n);
      buf_puts(&n, "这一步没做成:模型调不通,所以我没有继续。\n");
      if (why && *why) buf_printf(&n, "原因:%s\n", why);
      if (findings_total > 0) buf_printf(&n, "停下前已确认 %d 条风险,详见结果卡片。\n", findings_total);
      buf_puts(&n,
               "可以稍后重试,或在「设置 → 模型」里换一家;"
               "要直接跑某个检查(不经过模型),用 / 命令,例如 /recon 目标地址、/inspect 目标地址。");
      EMIT_ANSWER(a, n.data);
      buf_free(&n);
      decision_free(&d);
      break;
    }

    if (st) {
      json_t *rec = j_obj();
      j_set_num(rec, "step", step + 1);
      j_set_str(rec, "kind", d.kind == ACT_ACT ? "act" : (d.kind == ACT_ANSWER ? "answer" : "ask"));
      if (d.tool) j_set_str(rec, "action", d.tool);
      if (d.reason) j_set_str(rec, "reason", d.reason);
      j_set_bool(rec, "from_model", d.from_model);
      j_add(st->steps, rec);
      st->step_count = step + 1;
      buf_printf(&st->transcript, "[第 %d 步] %s %s%s%s\n", step + 1,
                 d.from_model ? "模型决策:" : "直接执行:",
                 d.kind == ACT_ACT ? "执行 " : (d.kind == ACT_ANSWER ? "回答" : "追问"),
                 d.tool ? d.tool : "",
                 d.reason ? d.reason : "");
    }

    /* ---- 直接回答 / 追问 ---- */
    if (d.kind == ACT_ANSWER) {
      EMIT_ANSWER(a, d.text ? d.text : "(无内容)");
      if (st) {
        st->stop_code = observations->count ? STOP_ANSWERED : STOP_ANSWERING_ONLY;
        snprintf(st->stop_reason, sizeof(st->stop_reason), "%s",
                 observations->count ? "已给出结论" : "纯问答,不需要动手");
      }
      decision_free(&d);
      break;
    }
    if (d.kind == ACT_ASK) {
      EMIT_ASK(a, d.text ? d.text : "需要你补充一点信息。");
      if (st) {
        st->stop_code = STOP_NEED_USER;
        snprintf(st->stop_reason, sizeof(st->stop_reason), "需要用户补充信息");
      }
      decision_free(&d);
      break;
    }

    /* ---- 行动 ---- */
    if (!d.tool || !*d.tool) {
      if (st) {
        st->stop_code = STOP_ERROR;
        snprintf(st->stop_reason, sizeof(st->stop_reason), "模型没有给出可执行的动作");
      }
      decision_free(&d);
      break;
    }
    /* 目标兜底:模型常说"这个站"却不给 target —— 用授权域名补上(与 Python 版同策略) */
    json_t *args = d.args ? d.args : j_obj();
    if (a->domain_count > 0) {
      json_t *t = j_get(args, "target");
      if (!t || t->type != J_STR || !t->str[0]) {
        buf_t home;
        buf_init(&home);
        buf_puts(&home, "https://");
        buf_puts(&home, a->domains[0]);
        j_set_str(args, "target", home.data);
        buf_free(&home);
      }
    }
    int step_rc = run_step(a, &ctx, d.tool, args, observations, &findings_total);
    if (step_rc != 0 && observations->count >= a->max_steps - 1) rc = step_rc;
    decision_free(&d);

    /* —— 手动巡检撞上"没有变化",这一问必须发生 ——
       同一个站刚查过、这次比对又没变化,该由人决定要不要重跑。
       全交给模型的话,它一旦超时不返回就会悄悄收尾 ——
       所以这条规则写在循环里,用同一个提问工具问出去。 */
    if (!a->unattended && !asked_no_change && a->hooks.on_question &&
        str_icontains(user_text, "巡检") && last_observation_unchanged(observations)) {
      asked_no_change = 1;
      static const char *kPayload =
          "{\"message\":\"这个站上次巡检过,这次比对没有发现变化。还要继续做完整巡检吗?\","
          "\"questions\":[{\"id\":\"mode\",\"title\":\"接下来怎么做\",\"type\":\"select\","
          "\"options\":[\"继续完整巡检\",\"只看增量\",\"先不做\"],\"default\":\"只看增量\"}]}";
      char *answer = NULL;
      if (a->hooks.on_question(a->hooks.userdata, kPayload, &answer) && answer) {
        buf_t msg;
        buf_init(&msg);
        buf_printf(&msg, "用户回答:%s", answer);
        observation_append(observations, "ask_user", NULL, msg.data, 0, "");
        if (a->hooks.on_observation) {
          tool_result_t view;
          memset(&view, 0, sizeof(view));
          view.text = msg.data;
          view.say = (char *)"我等你拿主意。";
          a->hooks.on_observation(a->hooks.userdata, "ask_user", &view);
        }
        buf_free(&msg);
      }
      free(answer);
    }

    if (step == a->max_steps - 1 && st) {
      st->stop_code = STOP_BUDGET;
      snprintf(st->stop_reason, sizeof(st->stop_reason),
               "达到本轮步数上限(%d 步),为避免空转先收尾", a->max_steps);
    }
  }

  /* ---- 收尾:如果循环是"步数用完"退出的,要如实说明 ---- */
  net_set_cancel(NULL);

  if (st && (st->stop_code == STOP_BUDGET || st->stop_code == STOP_NONE)) {
    buf_t n;
    buf_init(&n);
    buf_printf(&n, "我已经跑了 %d 步检查。", st->step_count);
    if (findings_total > 0) buf_printf(&n, "本次确认 %d 条风险,详见结果卡片。", findings_total);
    buf_puts(&n, "如果还想继续深入某个方向,可以再告诉我。");
    EMIT_ANSWER(a, n.data);
    buf_free(&n);
    if (st->stop_code == STOP_NONE) {
      st->stop_code = STOP_BUDGET;
      snprintf(st->stop_reason, sizeof(st->stop_reason), "步数预算用尽");
    }
  }

  if (st) {
    buf_printf(&st->transcript, "== 结束:%s(共 %d 步,新增发现 %d 条)==\n",
               st->stop_reason, st->step_count, findings_total);
    json_t *s = j_obj();
    j_set_num(s, "finding_count", findings_total);
    j_set_str(s, "stop_reason", st->stop_reason);
    j_set_num(s, "stop_code", st->stop_code);
    j_set(s, "steps", st->steps);
    j_set_str(s, "scope", scope);
    /* 注意:上面 j_set 已经把 st->steps 的所有权交给 s 了,这里不能再释放它,
       否则就是"同一个指针 free 两次"—— 会把堆踩坏(排查过一回)。 */
    st->steps = s;
  }

  agent_add_history(a, "user", user_text);
  buf_free(&notes);
  json_free(observations);
  a->turn_index++;
  return rc;
}

/* ================= 清单打印 ================= */
void agent_print_tools(void) {
  printf("工具清单(共 %d 个)\n", tools_count());
  for (int i = 0; i < tools_count(); i++) {
    tool_t *t = tools_get(i);
    printf("  %-24s [%s] %s\n", t->name, t->kind,
           t->source_url[0] ? t->source_url : "自研");
  }
}

void agent_print_skills(void) {
  printf("技能清单(共 %d 个)—— 智能体的专业能力\n", skills_count());
  for (int i = 0; i < skills_count(); i++) {
    skill_t *s = skills_get(i);
    printf("  %-26s %s\n", s->name, s->title);
    printf("      用途:%s\n", s->purpose);
    printf("      何时用:%s\n", s->when);
    printf("      用到的工具:%s\n", s->tools);
  }
}

/* 清单里补一个 cmd 字段:界面据此画 / 命令补全,后端据此解析 —— 
   两边不再各写一份别名表。 */
static void stamp_cmd(json_t *arr) {
  for (int i = 0; i < j_len(arr); i++) {
    json_t *o = j_at(arr, i);
    const char *name = j_s(o, "name", "");
    const char *cmd = NULL;
    for (size_t k = 0; k < sizeof(kSlash) / sizeof(kSlash[0]); k++) {
      if (strcmp(kSlash[k].name, name) == 0) { cmd = kSlash[k].cmd; break; }
    }
    if (!cmd && str_startswith(name, "skill_")) cmd = name + 6;
    if (!cmd) cmd = name;
    j_set_str(o, "cmd", cmd);
  }
}

json_t *agent_skill_list_json(void) {
  json_t *arr = skills_decl_json();
  stamp_cmd(arr);
  return arr;
}

json_t *agent_tool_list_json(void) {
  json_t *arr = tools_decl_json();
  stamp_cmd(arr);
  return arr;
}


