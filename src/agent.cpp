/* agent.cpp —— 决策循环:智能体的"大脑回路"。
 *
 * 一轮对话 = 一次完整循环:
 *
 *   ┌─→ 感知(把用户输入 + 历史 + 已获得的观察组织成决策上下文)
 *   │      ↓
 *   │   规划/决策(模型:选技能或工具,或直接回答;无网则规则降级)
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
  buf_t scope_note;      /* 拼好的授权范围说明(提示词里用) */
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
  return a;
}

void agent_free(agent_t *a) {
  if (!a) return;
  json_free(a->history);
  if (a->domains) str_free_list(a->domains, a->domain_count);
  buf_free(&a->scope_note);
  free(a);
}

void agent_set_hooks(agent_t *a, const agent_hooks_t *hooks) {
  if (a && hooks) a->hooks = *hooks;
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
    buf_puts(&a->scope_note, "当前没有配置授权域名 —— 任何对外动作都不允许执行。");
  } else {
    buf_printf(&a->scope_note, "任务 %s,授权域名:", a->task_id[0] ? a->task_id : "(未命名)");
    for (int i = 0; i < a->domain_count; i++) buf_printf(&a->scope_note, " %s", a->domains[i]);
  }
}

void agent_set_store(agent_t *a, void *store, const char *run_id) {
  if (!a) return;
  a->store = store;
  snprintf(a->run_id, sizeof(a->run_id), "%s", run_id ? run_id : "");
}

void agent_add_history(agent_t *a, const char *role, const char *text) {
  if (!a) return;
  json_t *turn = j_obj();
  j_set_str(turn, "role", role);
  j_set_str(turn, "text", text);
  j_add(a->history, turn);
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
    const char *res = j_s(j_at(observations, i), "result", "");
    if (str_icontains(res, "不在授权池内") || str_icontains(res, "不在授权域名内")) {
      if (why) *why = xstrdup("目标不在授权范围内,已按合规要求停止");
      return 1;
    }
    if (str_icontains(res, "全部请求都失败") || str_icontains(res, "不可达") ||
        str_icontains(res, "连不上")) {
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
    if (j_b(o, "new_skill", 0)) break;
    run++;
  }
  return run;
}

/* ================= 一步:执行技能或工具 ================= */
static void observation_append(json_t *observations, const char *name, json_t *args,
                              const char *result_text, int is_error) {
  json_t *o = j_obj();
  j_set_str(o, "tool", name);
  { /* 参数也留一份:判定"打转"时,同名不同参不算重复 */
    char *dump = args ? json_dump(args) : NULL;
    j_set_str(o, "args", dump ? dump : "{}");
    if (dump) free(dump);
  }
  j_set_str(o, "result", result_text ? result_text : "");
  j_set_bool(o, "is_error", is_error);
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
    observation_append(observations, name, args, msg.data, 1);
    buf_free(&msg);
    return -1;
  }

  /* —— 行动 —— */
  EMIT_STATUS(a, name, "running");
  if (a->hooks.on_action) {
    a->hooks.on_action(a->hooks.userdata, name, args,
                       sk ? sk->when : tl->description);
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
      observation_append(observations, name, args, msg.data, 1);
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
  observation_append(observations, name, args, text, is_err);

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
  int rc = 0;

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

  EMIT_THINKING(a, "正在理解你的意图并规划检查步骤……");
  if (st) buf_puts(&st->transcript, "== 一轮对话开始 ==\n");

  const char *scope = a->scope_note.data ? a->scope_note.data : "";

  for (int step = 0; step < a->max_steps; step++) {
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
      decided = llm_decide(a, user_text, observations, scope, &d);
    }
    if (decided != 0) {
      rule_decide(user_text, scope, &d);        /* 降级:本地规则 */
      if (decided != 0 && llm_enabled()) {
        log_warn("模型决策不可用,已降级为本地规则(d=%d)", decided);
      }
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
                 d.from_model ? "模型决策:" : "规则降级:",
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

    if (step == a->max_steps - 1 && st) {
      st->stop_code = STOP_BUDGET;
      snprintf(st->stop_reason, sizeof(st->stop_reason),
               "达到本轮步数上限(%d 步),为避免空转先收尾", a->max_steps);
    }
  }

  /* ---- 收尾:如果循环是"步数用完"退出的,要如实说明 ---- */
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

json_t *agent_skill_list_json(void) { return skills_decl_json(); }
json_t *agent_tool_list_json(void) { return tools_decl_json(); }


