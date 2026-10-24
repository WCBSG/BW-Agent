/* llm.cpp —— 模型接入 + 决策解析。
   平台鉴权照抄文档:sign = 毫秒时间戳 + Base64(HMAC-SHA256(appSecret,
   "{时间戳}\n{appSecret}\n{appKey}")),有效期 60 分钟 → 每次请求现签。 */
#include "llm.h"

#include <ctype.h>

#include "llm_provider.h"
#include "net.h"
#include "skills.h"
#include "tools.h"


/* 最近一次调用模型失败的原因(界面/命令行据此说明"为什么这次没查成") */
static char *g_last_error = NULL;
/* 自检模式:不联网、也不假装有模型 —— 自检只验证循环与工具,不许打真实接口 */
static int g_test_mode = 0;
/* 失败冷却截止时刻(毫秒时间戳):失败后短时间内不再重试,避免每步都白等一次超时 */
static long long g_fail_until_ms = 0;

void llm_set_last_error(const char *msg) {
  free(g_last_error);
  g_last_error = msg && *msg ? xstrdup(msg) : NULL;
}

const char *llm_last_error(void) { return g_last_error ? g_last_error : ""; }

void llm_reset_error(void) {
  g_fail_until_ms = 0;
  llm_set_last_error("");
}

/* 模型配置全交给 llm_provider:这里只保留"哪一条在生效"的问法 */
void llm_init(const char *env_dir) {
  (void)env_dir;              /* 路径统一由 providers 决定(数据目录下的 models.json) */
  providers_init();
}

/* "有模型可用"= 当前选中的那一条可用。配了三家但选中的那条不通,
   就不该对界面说"在线" —— 否则顶栏亮着、每轮又都失败,自相矛盾。 */
int llm_enabled(void) {
  if (g_test_mode) return 0;      /* 自检不联网:显式关掉模型 */
  int idx = providers_active_index();
  provider_t *p = idx >= 0 ? provider_at(idx) : NULL;
  return provider_ready(p) ? 1 : 0;
}

void llm_set_test_mode(int on) {
  g_test_mode = on ? 1 : 0;
  if (on) llm_set_last_error("自检模式:未调用模型");
}
/* ================= 决策解析(容错) ================= */
/* 模型爱加解释、爱包代码块、爱把 JSON 写坏。这里从最可信到最宽泛逐级尝试。 */
static const char *find_json_span(const char *s, size_t *out_len) {
  const char *start = NULL;
  int depth = 0;
  int in_str = 0, esc = 0;
  for (const char *p = s; *p; p++) {
    if (in_str) {
      if (esc) { esc = 0; continue; }
      if (*p == '\\') { esc = 1; continue; }
      if (*p == '"') in_str = 0;
      continue;
    }
    if (*p == '"') { in_str = 1; continue; }
    if (*p == '{') {
      if (depth == 0) start = p;
      depth++;
    } else if (*p == '}') {
      if (depth > 0) {
        depth--;
        if (depth == 0 && start) { *out_len = (size_t)(p - start + 1); return start; }
      }
    }
  }
  return NULL;
}

/* 复读检测:同一小段重复几十次 = 模型退化了,不能当回答 */
static int degenerate(const char *s) {
  size_t n = strlen(s);
  if (n < 400) return 0;
  const char *tail = s + (n > 2000 ? n - 2000 : 0);
  size_t tn = strlen(tail);
  for (size_t size = 8; size <= 32; size += 8) {
    if (tn <= size) continue;
    const char *piece = tail + tn - size;
    int count = 0;
    for (const char *p = tail; (p = strstr(p, piece)) != NULL; p += size) count++;
    if (count > 60) return 1;
  }
  return 0;
}

int llm_extract_action(const char *raw, decision_t *out) {
  memset(out, 0, sizeof(*out));
  if (!raw || !*raw) return -1;
  if (degenerate(raw)) return -2;

  /* 去代码块围栏 */
  buf_t clean;
  buf_init(&clean);
  const char *s = raw;
  while (*s == ' ' || *s == '\n' || *s == '\r' || *s == '\t') s++;
  if (str_startswith(s, "```")) {
    s += 3;
    while (*s && *s != '\n') s++;
    if (*s == '\n') s++;
    const char *end = strstr(s, "```");
    if (end) buf_putn(&clean, s, (size_t)(end - s));
    else buf_puts(&clean, s);
  } else {
    buf_puts(&clean, s);
  }

  json_t *j = json_parse(clean.data);
  if (!j) {
    size_t span = 0;
    const char *p = find_json_span(clean.data, &span);
    if (p) j = json_parse_n(p, span);
  }
  buf_free(&clean);

  if (j && j->type == J_OBJ) {
    /* 原生 function calling 形态:模型若直接给出结构化调用,
       优先认它 —— 比"从散文里抠 JSON"可靠得多。
       支持 OpenAI 的 {"tool_calls":[{"function":{"name","arguments"}}]}
       与简化的 {"name":"x","arguments":{…}}。 */
    json_t *calls = j_get(j, "tool_calls");
    json_t *fn = NULL;
    if (calls && calls->type == J_ARR && j_len(calls) > 0) {
      json_t *c0 = j_at(calls, 0);
      if (c0) fn = j_get(c0, "function");
    } else if (j_get(j, "name") && j_get(j, "arguments")) {
      fn = j;
    }
    if (fn) {
      const char *fname = j_s(fn, "name", NULL);
      const char *fwhy = j_s(fn, "reason", NULL);
      if (fname && *fname) {
        out->kind = ACT_ACT;
        out->tool = xstrdup(fname);
        out->reason = (fwhy && *fwhy) ? xstrdup(fwhy) : NULL;
        out->raw = xstrdup(raw);
        out->from_model = 1;
        json_t *aa = j_get(fn, "arguments");
        if (aa && aa->type == J_STR && aa->str) {
          json_t *tmp = json_parse(aa->str);
          if (tmp) {
            char *dump = json_dump(tmp);
            out->args = json_parse(dump);
            free(dump);
            json_free(tmp);
          }
        } else if (aa && aa->type == J_OBJ) {
          char *dump = json_dump(aa);
          out->args = json_parse(dump);
          free(dump);
        }
        if (!out->args) out->args = j_obj();
        json_free(j);
        return 0;
      }
    }

    const char *tool = j_s(j, "tool", NULL);
    const char *skill = j_s(j, "skill", NULL);
    const char *final = j_s(j, "final", NULL);
    const char *ask = j_s(j, "ask", NULL);
    const char *why = j_s(j, "reason", NULL);
    const char *name = (tool && *tool) ? tool : ((skill && *skill) ? skill : NULL);
    if (name) {
      out->kind = ACT_ACT;
      out->tool = xstrdup(name);
      out->reason = why ? xstrdup(why) : NULL;
      out->raw = xstrdup(raw);
      out->from_model = 1;
      /* args 做一次深拷贝:比手工搬所有权可靠(少一处踩空指针的机会) */
      json_t *args = j_get(j, "args");
      if (args) {
        char *args_dump = json_dump(args);
        out->args = json_parse(args_dump);
        free(args_dump);
      }
      if (!out->args) out->args = j_obj();
      json_free(j);
      return 0;
    }
    if (final && *final) {
      out->kind = ACT_ANSWER;
      out->text = xstrdup(final);
      out->reason = why ? xstrdup(why) : NULL;
      out->raw = xstrdup(raw);
      out->from_model = 1;
      json_free(j);
      return 0;
    }
    if (ask && *ask) {
      out->kind = ACT_ASK;
      out->text = xstrdup(ask);
      out->raw = xstrdup(raw);
      out->from_model = 1;
      json_free(j);
      return 0;
    }
  }
  json_free(j);

  /* 兜底:JSON 被截断时,至少把工具名捞出来(参数交给工具自己用默认值) */
  const char *t = strstr(raw, "\"tool\"");
  if (t) {
    const char *q1 = strchr(t + 6, '"');
    if (q1) {
      const char *q2 = strchr(q1 + 1, '"');
      if (q2 && q2 > q1 + 1) {
        out->kind = ACT_ACT;
        out->tool = xstrndup(q1 + 1, (size_t)(q2 - q1 - 1));
        out->args = j_obj();
        out->raw = xstrdup(raw);
        out->from_model = 1;
        return 0;
      }
    }
  }
  return -3;
}

void decision_free(decision_t *d) {
  if (!d) return;
  free(d->tool);
  free(d->text);
  free(d->reason);
  free(d->raw);
  json_free(d->args);
  memset(d, 0, sizeof(*d));
}

/* ================= 提示词 ================= */
/* 提示词里既给工具也给技能:工具是"能做什么动作",技能是"该怎么把一件事做完"。
   模型的任务是选一个技能或一个工具,并给参数。 */
/* 观察结果按"单步 + 总量"双重截断:一轮 6 步、每步上万字时,
   全文塞进提示词只会把真正有用的信息挤出去,还可能超出模型的输入上限。
   截断保留头尾 —— 结论通常在末尾,链接与样本通常在开头。 */
#define OBS_PER_STEP_MAX 2500
#define OBS_TOTAL_MAX 12000
#define HISTORY_TURNS 6
#define HISTORY_PER_TURN 600

static void put_clipped(buf_t *out, const char *s, size_t cap) {
  if (!s || !*s) return;
  size_t n = strlen(s);
  if (n <= cap) {
    buf_puts(out, s);
    return;
  }
  size_t head = cap * 2 / 3;
  size_t tail = cap - head;
  buf_puts(out, "[结果较长,已截断,原文共 ");
  buf_printf(out, "%zu", n);
  buf_puts(out, " 字符]\n");
  buf_putn(out, s, head);
  buf_puts(out, "\n…(中间省略)…\n");
  buf_puts(out, s + (n - tail));
}

static void build_prompt(buf_t *out, agent_t *a, const char *user_text,
                         json_t *observations, const char *scope_note) {
  int used_steps = observations ? j_len(observations) : 0;
  buf_puts(out,
      "你是「BlueWhiteAgent」的决策内核:自主判断下一步,不跑固定流程。\n\n"
      "## 判断(一步一动作,拿到结果我会再问你一次)\n"
      "1. 先定意图:巡检 / 复测 / 出报告 / 只是提问。\n"
      "2. 观察结果够下结论就直接 final,不为凑步数再跑。\n"
      "3. 否定结果(不可达/未授权/被排除/超时/被拒)只能如实说明,不得推成「安全」。\n"
      "4. 同一动作已有结果且无变化,不再重复,直接收尾。\n\n"
      "## 选择\n"
      "优先技能(一次调用即跑完、直接给结论);技能覆盖不到才单独用工具。\n"
      "全流程巡检已含完整性/敏感信息/目录/模板,别再单独重跑这几个技能。\n"
      "技能只是成套路的第一步:跑完还有线索(页面、接口、外链)就用工具接着看,别急着收尾。\n"
      "非只读工具会弹审批、可能被拒:被拒按否定结果处理,不要换个说法再试。\n"
      "args 只填必需参数,不要枚举长列表。\n\n"
      "## 深入分析(需要真判断时)\n"
      "- 看底账:asset_list 拿页面清单;http_get 读状态、响应头、标题、正文与链接。\n"
      "- 篡改:跨页比对标题/关键文案/外链/脚本来源,再结合基线差异;新增外域或裸 IP 最可疑。\n"
      "- 漏洞:看响应头缺失、错误回显、危险方法、参数回显;有参数就上 sqli_probe 做差分。\n"
      "- 多步链:上一步拿到的路径/参数就是下一步的输入,链上每一环都要写进证据。\n"
      "- 有结论就用 record_finding 落库(等级/证据/影响/修复),再决定继续还是收尾。\n");
  buf_printf(out, "\n## 本轮预算\n最多 %d 步,已用 %d 步,还剩 %d 步。\n", MAX_STEPS_DEFAULT,
             used_steps, MAX_STEPS_DEFAULT - used_steps > 0 ? MAX_STEPS_DEFAULT - used_steps : 0);

  buf_puts(out, "\n## 可用技能\n");
  skills_manifest(out);
  buf_puts(out, "\n## 可用工具\n");
  tools_manifest(out);

  if (scope_note && *scope_note) {
    buf_puts(out, "\n## 授权范围(硬约束)\n");
    buf_puts(out, scope_note);
    buf_puts(out, "\n池外不动手,直接说明。\n");
  }

  /* 同一件事该不该重做,取决于"有没有人在看" —— 
     无人值守时没人回答,问题问出去只会卡住整轮。 */
  if (agent_unattended(a)) {
    buf_puts(out, "\n## 无人值守\n"
                  "本轮是定时/自动巡检:不要用 ask_user。没有变化的站只做增量比对,结论直接写。\n");
  } else {
    buf_puts(out, "\n## 什么时候该问\n"
                  "用户手动让查某个站时,如果它已经巡检过、这次比对又没变化,必须先 ask_user 问清楚"
                  "(选项:继续完整巡检 / 只看增量 / 先不做),不要自行收尾。\n"
                  "其它情况不要打断用户。\n");
  }

  /* 压缩过的老对话:用摘要代表,原文不再进提示词。
     这段要排在"最近的对话"之前 —— 先给背景,再给细节。 */
  {
    const char *sum = agent_ctx_summary(a);
    if (sum && *sum) {
      buf_puts(out, "\n## 更早的对话(已压缩成摘要)\n");
      buf_puts(out, sum);
      buf_puts(out, "\n");
    }
  }

  /* 多轮上下文:没有这一段,"继续""那个站也一样查一下"就没法消解 ——
     模型只会看到孤立的一句话,于是要么重复上一件事,要么反问用户。 */
  {
    int total = agent_history_count(a);
    int from = total > HISTORY_TURNS ? total - HISTORY_TURNS : 0;
    if (total > 0) {
      buf_puts(out, "\n## 最近的对话(按时间顺序,供你理解指代)\n");
      for (int i = from; i < total; i++) {
        const char *role = "";
        const char *text = agent_history_at(a, i, &role);
        if (!text || !*text) continue;
        buf_puts(out, (role && strcmp(role, "assistant") == 0) ? "- 你:" : "- 用户:");
        put_clipped(out, text, HISTORY_PER_TURN);
        buf_puts(out, "\n");
      }
    }
  }

  if (observations && j_len(observations) > 0) {
    buf_puts(out, "\n## 已经拿到的观察结果(按时间顺序)\n");
    int budget = OBS_TOTAL_MAX;
    for (int i = 0; i < j_len(observations); i++) {
      json_t *o = j_at(observations, i);
      const char *tool = j_s(o, "tool", "?");
      const char *result = j_s(o, "result", "");
      buf_printf(out, "--- 第 %d 步 [%s] ---\n", i + 1, tool);
      if (budget <= 0) {
        buf_puts(out, "(前面的观察已经占满上下文预算,这一步的结果从略)\n");
        continue;
      }
      size_t cap = OBS_PER_STEP_MAX;
      if ((int)cap > budget) cap = (size_t)budget;
      size_t before = out->len;
      put_clipped(out, result, cap);
      budget -= (int)(out->len - before);
      buf_puts(out, "\n");
    }
  }

  buf_puts(out, "\n## 用户本轮输入\n");
  buf_puts(out, user_text);
  buf_puts(out,
      "\n\n## 输出:只输出一个 JSON,无解释、无代码块\n"
      "{\"skill\":\"技能名\",\"args\":{…}} 或 {\"tool\":\"工具名\",\"args\":{…}}\n"
      "或 {\"final\":\"中文回答\"} 或 {\"ask\":\"需用户补充什么\"}\n"
      "可加 \"reason\":\"一句话理由\"。\n"
      "final 要像跟人汇报:先用两三句自然语言说清「查了什么、发现几条、最要紧的是哪条」,"
      "再给证据位置、影响与下一步;不要只回「见上面的结果」「已生成报告」。\n");
}

/* 一次补全:只用「当前」那一条(理由见 llm_call 里的注释) */
typedef struct {
  agent_t *agent;     /* 用来把正文增量推给界面 */
  int suppress;       /* 判定为决策 JSON 后,这一轮不再往外播 */
} emit_ctx_t;

static void emit_prose(void *ud, const char *text) {
  emit_ctx_t *c = (emit_ctx_t *)ud;
  if (!c || c->suppress || !text || !*text) return;
  const char *p = text;
  while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') p++;
  /* 决策本身是 JSON(或 JSON 的前半截),不是给人读的正文 —— 别一个字一个字地抖 */
  if (*p == '{' || *p == '[' || *p == '"') { c->suppress = 1; return; }
  if (c->agent) agent_emit_delta(c->agent, text);
}

static int llm_call(agent_t *a, const char *prompt, buf_t *answer_out) {
  buf_clear(answer_out);
  if (!prompt || !*prompt) return -1;

  /* 只用「当前」那一条:和主流 agent 一样,配几家由人挑一家在用。
     不再"这家不通就悄悄换下一条" —— 换了人也不知道刚才用的是谁,
     而排查问题最需要的恰恰是"到底哪家在回话"。 */
  int idx = providers_active_index();
  provider_t *p = idx >= 0 ? provider_at(idx) : NULL;
  if (!p || !provider_ready(p)) {
    llm_set_last_error("当前没有可用的模型(在「设置 → 模型」里选一条可用的)");
    return -1;
  }

  emit_ctx_t ec;
  memset(&ec, 0, sizeof(ec));
  ec.agent = a;
  char err[512] = "";
  long long t0 = now_ms();
  int rc = provider_chat(p, prompt, emit_prose, &ec, answer_out, err, sizeof(err));
  long long ms = now_ms() - t0;
  if (rc == 0 && answer_out->len > 0) {
    /* 单次调用的耗时:一轮要问好几次,平均几十秒和偶尔三分钟是两种体验,
       记下来才能回答"为什么时快时慢" */
    log_info("[模型] %s 用时 %lldms,输出 %d 字节", p->name, ms, (int)answer_out->len);
    return 0;
  }
  log_warn("[模型] %s 失败前等了 %lldms", p->name, ms);

  /* 失败时可能已经有半截输出,清掉:别把"说到一半的话"当成回答 */
  buf_clear(answer_out);
  char last[512];
  snprintf(last, sizeof(last), "%s:%s", p->name, err[0] ? err : "没有返回内容");
  llm_set_last_error(last);
  log_warn("模型 %s 调用失败:%s", p->name, err[0] ? err : "空回复");
  return -1;
}

int llm_decide(agent_t *a, const char *user_text, json_t *observations,
               const char *scope_note, decision_t *out) {
  memset(out, 0, sizeof(*out));
  if (!llm_enabled()) { llm_set_last_error("没有可用的模型配置"); return -1; }
  /* 已经叫停:连这一次请求都不发 —— 省掉一次无意义的往返 */
  if (net_cancelled()) { llm_set_last_error("本轮已被叫停"); return -1; }
  /* 刚失败过就先别试:一轮要决策 6 次,每次都白等一次超时的话,
     用户看到的就是"智能体在发呆"。冷却期内直接如实报错,失败原因保留着。 */
  if (g_fail_until_ms > 0 && now_ms() < g_fail_until_ms) return -1;

  buf_t prompt;
  buf_init(&prompt);
  build_prompt(&prompt, a, user_text, observations, scope_note);
  /* 估算 token 并记到 agent 上:占用环与压缩阈值都用这个数 */
  agent_set_ctx_used(a, (int)est_tokens(prompt.data));
  /* 提示词体积直接换算成首字节延迟,留个读数方便以后继续压 */
  log_info("[模型] 提示词 %d 字节(观察 %d 条)", (int)prompt.len,
           observations ? j_len(observations) : 0);

  buf_t answer;
  buf_init(&answer);
  int rc = llm_call(a, prompt.data, &answer);
  buf_free(&prompt);

  if (rc != 0) {
    buf_free(&answer);
    g_fail_until_ms = now_ms() + 120000;      /* 两分钟内不再重试 */
    return -1;
  }

  int pr = llm_extract_action(answer.data, out);
  if (pr != 0) {
    log_warn("模型输出无法解析为决策(rc=%d),长度 %zu", pr, answer.len);
    net_audit("llm_bad_output", providers_active_id(), 0,
              answer.data ? answer.data : "", NULL);
  } else {
    g_fail_until_ms = 0;
    llm_set_last_error("");
  }
  buf_free(&answer);
  return pr == 0 ? 0 : -2;
}

int llm_ask(const char *prompt, buf_t *out) {
  if (!llm_enabled()) return -1;
  if (g_fail_until_ms > 0 && now_ms() < g_fail_until_ms) return -1;
  if (!prompt || !*prompt) return -1;
  int rc = llm_call(NULL, prompt, out);
  if (rc != 0) {
    g_fail_until_ms = now_ms() + 120000;
    return -1;
  }
  g_fail_until_ms = 0;
  return 0;
}
