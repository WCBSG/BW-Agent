/* llm.cpp —— 恒脑接入 + 决策解析 + 本地规则降级。
   平台鉴权照抄文档:sign = 毫秒时间戳 + Base64(HMAC-SHA256(appSecret,
   "{时间戳}\n{appSecret}\n{appKey}")),有效期 60 分钟 → 每次请求现签。 */
#include "llm.h"

#include <ctype.h>

#include "llm_provider.h"
#include "net.h"
#include "skills.h"
#include "tools.h"


/* 最近一次调用模型失败的原因(界面/命令行可以据此说明"为什么降级了") */
static char *g_last_error = NULL;
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
   就不该对界面说"在线" —— 否则顶栏亮着、每轮又都降级,自相矛盾。 */
int llm_enabled(void) {
  int idx = providers_active_index();
  provider_t *p = idx >= 0 ? provider_at(idx) : NULL;
  return provider_ready(p) ? 1 : 0;
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
      "你是「网站安全巡检智能体」的决策内核:自主判断下一步,不跑固定流程。\n\n"
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

/* 一次补全:按"当前厂商优先,其余就绪的顺延"依次尝试。
   这么排的原因很实际 —— 用户把某家设成当前,是希望优先用它;
   但它限流或欠费时,这一轮不该就此失败,顺延到下一家还能把活干完。 */
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
  int rc = provider_chat(p, prompt, emit_prose, &ec, answer_out, err, sizeof(err));
  if (rc == 0 && answer_out->len > 0) return 0;

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
  /* 全都失败过就先别试:一轮要决策 6 次,每次都白等一次超时的话,
     用户看到的就是"智能体在发呆"。冷却期内直接走本地规则,并保留失败原因。 */
  if (g_fail_until_ms > 0 && now_ms() < g_fail_until_ms) return -1;

  buf_t prompt;
  buf_init(&prompt);
  build_prompt(&prompt, a, user_text, observations, scope_note);
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

/* ================= 本地规则路由(降级通道) =================
   规则不是"简化版智能体",而是**没网时的保底**:覆盖最常见的几类意图,
   保证演示现场网络抖动也能把流程走完。纯粹的关键词+正则,不猜。 */
typedef struct {
  const char *skill;        /* 命中的技能 */
  const char *arg_key;      /* 参数名 */
  const char *target_hint;  /* 取目标时用 */
} rule_entry_t;

void rule_decide(const char *user_text, const char *scope_note, decision_t *out) {
  memset(out, 0, sizeof(*out));
  out->from_model = 0;
  const char *t = user_text ? user_text : "";

  /* 目标:优先取带点的域名/URL */
  char target[512] = {0};
  for (const char *p = t; *p; p++) {
    if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')) {
      const char *q = p;
      while (*q && (isalnum((unsigned char)*q) || *q == '.' || *q == '-' || *q == '_' ||
                    *q == ':' || *q == '/' || *q == '?' || *q == '=' || *q == '&')) q++;
      size_t n = (size_t)(q - p);
      if (n > 3 && n < sizeof(target) && memchr(p, '.', n)) {
        memcpy(target, p, n);
        target[n] = 0;
        break;
      }
      p = q;
    }
  }

  json_t *args = j_obj();
  if (target[0]) j_set_str(args, "target", target);

  /* 意图判定:从强到弱(更具体的先命中) */
  if ((str_icontains(t, "授权列表") || str_icontains(t, "授权池") ||
       str_icontains(t, "能查哪些") || str_icontains(t, "可以查哪些")) &&
      !str_icontains(t, "巡检") && !str_icontains(t, "检查") && !str_icontains(t, "扫")) {
    /* 只问"授权了谁"。带了巡检动词就不走这条 —— 那是整池巡检,
       由服务端展开成每站一轮(见 serve.cpp 的 wants_whole_pool)。 */
    out->kind = ACT_ACT;
    out->tool = xstrdup("pool_list");
    out->reason = xstrdup("规则降级:读授权列表");
  } else if (str_icontains(t, "你的状态") || str_icontains(t, "本机信息") ||
             str_icontains(t, "你自己的") || str_icontains(t, "数据目录") ||
             str_icontains(t, "配置在哪")) {
    out->kind = ACT_ACT;
    out->tool = xstrdup("agent_info");
    out->reason = xstrdup("规则降级:查本机信息与状态");
  } else if (str_icontains(t, "当前设置") || str_icontains(t, "现在的设置") ||
             (str_icontains(t, "设置") &&
              (str_icontains(t, "看一下") || str_icontains(t, "查一下") ||
               str_icontains(t, "是什么") || str_icontains(t, "当前")))) {
    out->kind = ACT_ACT;
    out->tool = xstrdup("settings_get");
    out->reason = xstrdup("规则降级:读当前设置");
  } else if (str_icontains(t, "复测") || str_icontains(t, "复查") || str_icontains(t, "修好")) {
    out->kind = ACT_ACT;
    out->tool = xstrdup("skill_retest");
    out->reason = xstrdup("规则降级:命中复测意图");
  } else if (str_icontains(t, "报告") || str_icontains(t, "导出")) {
    out->kind = ACT_ACT;
    out->tool = xstrdup("skill_report");
    out->reason = xstrdup("规则降级:命中出报告意图");
  } else if (str_icontains(t, "核对证据") || str_icontains(t, "证据") ||
             str_icontains(t, "召回") || str_icontains(t, "误报率") ||
             str_icontains(t, "准确率") || str_icontains(t, "评测") ||
             str_icontains(t, "跑分")) {
    out->kind = ACT_ACT;
    out->tool = xstrdup("skill_evidence");
    out->reason = xstrdup("规则降级:命中证据核对意图(指标由评测方给,本工具只给逐条证据)");
  } else if (str_icontains(t, "篡改") || str_icontains(t, "有没有被改") ||
             str_icontains(t, "基线")) {
    out->kind = ACT_ACT;
    out->tool = xstrdup("skill_integrity_check");
    out->reason = xstrdup("规则降级:命中完整性/篡改意图");
  } else if (str_icontains(t, "敏感") || str_icontains(t, "泄露") ||
             str_icontains(t, ".env") || str_icontains(t, "配置")) {
    out->kind = ACT_ACT;
    out->tool = xstrdup("skill_leak_check");
    out->reason = xstrdup("规则降级:命中敏感信息意图");
  } else if (str_icontains(t, "口令") || str_icontains(t, "密码") ||
             str_icontains(t, "弱口令")) {
    out->kind = ACT_ACT;
    out->tool = xstrdup("password_check");
    out->reason = xstrdup("规则降级:口令强度评估");
  } else if (str_icontains(t, "页面") || str_icontains(t, "资产") ||
             str_icontains(t, "有哪些") || str_icontains(t, "爬")) {
    out->kind = ACT_ACT;
    out->tool = xstrdup("skill_recon");
    out->reason = xstrdup("规则降级:命中资产发现意图");
  } else if (str_icontains(t, "巡检") || str_icontains(t, "检查") ||
             str_icontains(t, "扫") || str_icontains(t, "风险")) {
    out->kind = ACT_ACT;
    out->tool = xstrdup("skill_full_inspection");
    out->reason = xstrdup("规则降级:命中巡检意图");
  } else {
    /* 什么都没命中:给出能力说明,而不是硬报一个结论 */
    out->kind = ACT_ANSWER;
    out->text = xstrdup(
        "我是网站安全巡检智能体。可以让我:① 对授权域名做一次完整巡检"
        "(资产发现 → 内容完整性 → 敏感文件 → 配置/漏洞);② 复测未闭环的问题;"
        "③ 生成报告;④ 核对每条结论的证据与闭环状态。\n"
        "效果指标不在这里给 —— 那取决于评测集与口径,应由评测方按自己的数据集算。\n"
        "另外我还能单独做:敏感信息扫描、口令强度评估、页面篡改比对、目录/入口探测。\n"
        "请告诉我目标和想做的事。");
  }

  if (out->kind == ACT_ACT) {
    out->args = args;
    out->raw = xstrdup("(local rules)");
  } else {
    json_free(args);
  }
  (void)scope_note;
}
