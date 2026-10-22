/* llm.cpp —— 恒脑接入 + 决策解析 + 本地规则降级。
   平台鉴权照抄文档:sign = 毫秒时间戳 + Base64(HMAC-SHA256(appSecret,
   "{时间戳}\n{appSecret}\n{appKey}")),有效期 60 分钟 → 每次请求现签。 */
#include "llm.h"

#include <ctype.h>

#include "net.h"
#include "skills.h"
#include "tools.h"

#include <bcrypt.h>

static llm_config_t g_cfg;

/* ================= 签名 ================= */
void llm_make_sign(const char *app_key, const char *app_secret, char *out, size_t cap) {
  out[0] = 0;
  if (!app_key || !app_secret) return;
  long long ts = now_ms();
  buf_t data;
  buf_init(&data);
  buf_printf(&data, "%lld\n%s\n%s", ts, app_secret, app_key);

  unsigned char digest[32] = {0};
  BCRYPT_ALG_HANDLE alg = NULL;
  BCRYPT_HASH_HANDLE hash = NULL;
  if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL,
                                  BCRYPT_ALG_HANDLE_HMAC_FLAG) == 0) {
    if (BCryptCreateHash(alg, &hash, NULL, 0, (PUCHAR)app_secret,
                         (ULONG)strlen(app_secret), 0) == 0) {
      BCryptHashData(hash, (PUCHAR)data.data, (ULONG)data.len, 0);
      BCryptFinishHash(hash, digest, sizeof(digest), 0);
      BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
  }
  buf_free(&data);

  buf_t b64;
  buf_init(&b64);
  b64_encode(digest, sizeof(digest), &b64);
  snprintf(out, cap, "%lld%s", ts, b64.data);
  buf_free(&b64);
}

/* ================= 配置 ================= */
/* 最近一次调用模型失败的原因(界面/命令行可以据此说明"为什么降级了") */
static char *g_last_error = NULL;

void llm_set_last_error(const char *msg) {
  free(g_last_error);
  g_last_error = msg && *msg ? xstrdup(msg) : NULL;
}

const char *llm_last_error(void) { return g_last_error ? g_last_error : ""; }

static void cfg_set(char *dst, size_t cap, const char *value) {
  strncpy_s(dst, cap, value ? value : "", _TRUNCATE);
  char *t = str_trim(dst);
  if (t != dst) memmove(dst, t, strlen(t) + 1);
}

void llm_init(const char *env_dir) {
  memset(&g_cfg, 0, sizeof(g_cfg));
  cfg_set(g_cfg.base_url, sizeof(g_cfg.base_url), getenv("DAS_BASE_URL"));
  if (!g_cfg.base_url[0]) strcpy_s(g_cfg.base_url, sizeof(g_cfg.base_url), "https://www.das-ai.com");
  cfg_set(g_cfg.app_key, sizeof(g_cfg.app_key), getenv("DAS_APP_KEY"));
  cfg_set(g_cfg.app_secret, sizeof(g_cfg.app_secret), getenv("DAS_APP_SECRET"));
  cfg_set(g_cfg.user_app_key, sizeof(g_cfg.user_app_key), getenv("DAS_USER_APP_KEY"));
  cfg_set(g_cfg.agent_id, sizeof(g_cfg.agent_id), getenv("DAS_AGENT_ID"));
  cfg_set(g_cfg.agent_keyword, sizeof(g_cfg.agent_keyword), getenv("DAS_AGENT_KEYWORD"));
  if (!g_cfg.agent_keyword[0]) strcpy_s(g_cfg.agent_keyword, sizeof(g_cfg.agent_keyword), "安全助手");
  g_cfg.timeout = 90.0;
  g_cfg.enabled = (g_cfg.app_key[0] && g_cfg.app_secret[0]);

  /* 没有环境变量时,尝试读程序目录下的 .env(部署时最省事的一种) */
  if (!g_cfg.enabled && env_dir) {
    char path[MAX_PATH * 2];
    size_t len = 0;
    char *text = NULL;
    /* 先找程序目录;构建产物在 build\ 下,所以再往上找一层 ——
       部署时把 .env 放在 exe 旁边或项目根目录都能生效 */
    for (int level = 0; level < 2 && !text; level++) {
      char dir[MAX_PATH * 2];
      snprintf(dir, sizeof(dir), "%s", env_dir);
      for (int k = 0; k < level; k++) {
        size_t l = strlen(dir);
        while (l > 0 && (dir[l - 1] == '\\' || dir[l - 1] == '/')) dir[--l] = 0;
        char *slash = strrchr(dir, '\\');
        if (!slash) slash = strrchr(dir, '/');
        if (slash) *slash = 0; else break;
      }
      path_join(path, sizeof(path), dir, ".env");
      text = file_read_all(path, &len);
    }
    if (text) {
      char **lines = NULL;
      int n = str_split(text, '\n', &lines, 0);
      for (int i = 0; i < n; i++) {
        char *line = str_trim(lines[i]);
        if (!line[0] || line[0] == '#') continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        char *k = str_trim(line);
        char *v = str_trim(eq + 1);
        size_t vl = strlen(v);
        if (vl >= 2 && v[0] == '"' && v[vl - 1] == '"') { v[vl - 1] = 0; v++; }
        if (str_ieq(k, "DAS_BASE_URL")) cfg_set(g_cfg.base_url, sizeof(g_cfg.base_url), v);
        else if (str_ieq(k, "DAS_APP_KEY")) cfg_set(g_cfg.app_key, sizeof(g_cfg.app_key), v);
        else if (str_ieq(k, "DAS_APP_SECRET")) cfg_set(g_cfg.app_secret, sizeof(g_cfg.app_secret), v);
        else if (str_ieq(k, "DAS_USER_APP_KEY")) cfg_set(g_cfg.user_app_key, sizeof(g_cfg.user_app_key), v);
        else if (str_ieq(k, "DAS_AGENT_ID")) cfg_set(g_cfg.agent_id, sizeof(g_cfg.agent_id), v);
        else if (str_ieq(k, "DAS_AGENT_KEYWORD")) cfg_set(g_cfg.agent_keyword, sizeof(g_cfg.agent_keyword), v);
      }
      str_free_list(lines, n);
      free(text);
      g_cfg.enabled = (g_cfg.app_key[0] && g_cfg.app_secret[0]);
    }
  }
}

const llm_config_t *llm_config(void) { return &g_cfg; }
int llm_enabled(void) { return g_cfg.enabled; }

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
static void build_prompt(buf_t *out, agent_t *a, const char *user_text,
                         json_t *observations, const char *scope_note) {
  buf_puts(out,
      "你是「网站安全巡检智能体」的决策内核。你的职责是自主判断下一步该做什么,"
      "而不是机械地跑一遍固定流程。\n\n");
  buf_puts(out,
      "## 你的工作方式(重要)\n"
      "1. 先判断用户到底想要什么结果(巡检?复测?出报告?只是问个问题?)\n"
      "2. 再看已有的观察结果够不够支撑结论:够就直接回答,不要为了「多跑一步」而跑\n"
      "3. 观察结果里若出现「目标不可达」「未授权」这类否定信息,不要自行编造结论\n"
      "4. 若同一件事已经做过且结果没变化,不要重复做 —— 应当收尾并说明\n"
      "5. 一次只决定一个动作;拿到观察结果后系统会再问你一次\n\n");

  buf_puts(out, "## 可用技能(推荐优先选技能,它包含完整做法)\n");
  skills_manifest(out);
  buf_puts(out, "\n## 可用原子工具(技能覆盖不到时才单独用)\n");
  tools_manifest(out);

  if (scope_note && *scope_note) {
    buf_puts(out, "\n## 授权范围(合规硬约束)\n");
    buf_puts(out, scope_note);
    buf_puts(out, "\n目标不在授权范围内的,不要动手,直接说明。\n");
  }

  if (observations && j_len(observations) > 0) {
    buf_puts(out, "\n## 已经拿到的观察结果(按时间顺序)\n");
    for (int i = 0; i < j_len(observations); i++) {
      json_t *o = j_at(observations, i);
      const char *tool = j_s(o, "tool", "?");
      const char *result = j_s(o, "result", "");
      buf_printf(out, "--- 第 %d 步 [%s] ---\n", i + 1, tool);
      buf_puts(out, result);
      buf_puts(out, "\n");
    }
  }

  buf_puts(out, "\n## 用户本轮输入\n");
  buf_puts(out, user_text);
  buf_puts(out,
      "\n\n## 输出要求(只输出这一个 JSON 对象,不要解释、不要代码块)\n"
      "调技能/工具: {\"skill\":\"技能名\",\"args\":{…}} 或 {\"tool\":\"工具名\",\"args\":{…}}\n"
      "直接回答:     {\"final\":\"给用户的中文回答\"}\n"
      "需要补充:     {\"ask\":\"需要用户确认或补充什么\"}\n"
      "可选加 \"reason\":\"一句话说明你为什么这么决定\"。\n"
      "args 只填必需参数,不要枚举长列表。\n");
}

/* 解析 JSON 里的 SSE 数据行 */
static int hn_call(const char *prompt, buf_t *answer_out) {
  if (!g_cfg.enabled) return -1;
  char sign[512];
  llm_make_sign(g_cfg.app_key, g_cfg.app_secret, sign, sizeof(sign));

  buf_t payload;
  buf_init(&payload);
  buf_puts(&payload, "{\"id\":");
  buf_json_str(&payload, g_cfg.agent_id);
  buf_puts(&payload, ",\"sid\":\"");
  /* sid 必须是 UUID 格式:用时间戳拼一个稳定且合规的伪 UUID */
  {
    unsigned int r = (unsigned int)(now_ms() & 0xFFFFFFFF);
    buf_printf(&payload, "%08x-0000-4000-8000-%08x%04x", r, r,
               (unsigned)(now_ms() & 0xFFFF));
  }
  buf_puts(&payload, "\",\"input\":");
  buf_json_str(&payload, prompt);
  buf_puts(&payload, ",\"stream\":true,\"order\":\"routine\",\"debugSwitch\":false}");

  char url[512];
  snprintf(url, sizeof(url), "%s/open/api/v2/agent/execute", g_cfg.base_url);

  http_resp_t resp;
  /* 模型端点是"我们的依赖",不是"被检目标",所以不套用被检目标的只读限制;
     但它同样要留审计 —— 调用失败必须能查。 */
  hn_http_post(url, g_cfg.app_key, sign, payload.data, &resp);
  buf_free(&payload);

  int rc = -1;
  if (resp.error) {
    log_warn("恒脑调用失败: %s", resp.error);
    llm_set_last_error(resp.error);
  } else if (resp.status != 200) {
    log_warn("恒脑返回 HTTP %d", resp.status);
    llm_set_last_error("接口返回非 200");
  } else if (resp.body && resp.body[0] == '{') {
    /* 平台在鉴权/参数不对时也是 HTTP 200,但在体里给错误:
         {"msg":"请求头中缺少appKey或sign","code":-402,...}
       这种必须原样说出来 —— 否则用户只看到「解析失败」,不知道该去填 .env。 */
    json_t *o = json_parse(resp.body);
    const char *msg = o ? j_s(o, "msg", NULL) : NULL;
    if (msg && *msg) {
      double code = o ? j_n(o, "code", 0) : 0;
      log_warn("恒脑接口拒绝请求: %s(code=%.0f)。检查数据目录或 exe 旁的 .env 里的 "
               "DAS_APP_KEY / DAS_APP_SECRET / DAS_AGENT_ID", msg, code);
      llm_set_last_error(msg);
    }
    json_free(o);
  } else if (resp.body) {
    /* SSE:逐行取 data:{...};答案类内容(execute_result/react_answer)优先 */
    char **lines = NULL;
    int n = str_split(resp.body, '\n', &lines, 0);
    buf_t answer;
    buf_init(&answer);
    buf_t fallback;
    buf_init(&fallback);
    for (int i = 0; i < n; i++) {
      char *line = str_trim(lines[i]);
      if (!str_startswith(line, "data:")) continue;
      char *js = str_trim(line + 5);
      if (!js[0]) continue;
      json_t *o = json_parse(js);
      if (!o) continue;
      json_t *data = j_get(o, "data");
      const char *content = j_s(data, "content", NULL);
      const char *from = j_s(data, "from", "");
      if (content && *content) {
        int is_answer = (strcmp(from, "execute_result") == 0 ||
                         strcmp(from, "react_answer") == 0 ||
                         strcmp(from, "restful_answer") == 0);
        if (is_answer) buf_puts(&answer, content);
        else buf_puts(&fallback, content);
      }
      json_free(o);
    }
    str_free_list(lines, n);
    buf_puts(answer_out, answer.len ? answer.data : fallback.data);
    rc = answer_out->len ? 0 : -1;
    buf_free(&answer);
    buf_free(&fallback);
  }
  http_resp_free(&resp);
  return rc;
}

int llm_decide(agent_t *a, const char *user_text, json_t *observations,
               const char *scope_note, decision_t *out) {
  memset(out, 0, sizeof(*out));
  if (!g_cfg.enabled) return -1;
  if (!g_cfg.agent_id[0]) {
    /* 没配智能体 ID 就按关键词检索一个 —— 与 Python 版同样的策略 */
    log_warn("未配置 DAS_AGENT_ID,本次先用本地规则路由");
    return -1;
  }

  buf_t prompt;
  buf_init(&prompt);
  build_prompt(&prompt, a, user_text, observations, scope_note);

  buf_t answer;
  buf_init(&answer);
  int rc = hn_call(prompt.data, &answer);
  buf_free(&prompt);

  if (rc != 0) { buf_free(&answer); return -1; }

  int pr = llm_extract_action(answer.data, out);
  if (pr != 0) {
    log_warn("模型输出无法解析为决策(rc=%d),长度 %zu", pr, answer.len);
    net_audit("llm_bad_output", "hn", 0, answer.data ? answer.data : "", NULL);
  }
  buf_free(&answer);
  return pr == 0 ? 0 : -2;
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
  if (str_icontains(t, "复测") || str_icontains(t, "复查") || str_icontains(t, "修好")) {
    out->kind = ACT_ACT;
    out->tool = xstrdup("skill_retest");
    out->reason = xstrdup("规则降级:命中复测意图");
  } else if (str_icontains(t, "报告") || str_icontains(t, "导出")) {
    out->kind = ACT_ACT;
    out->tool = xstrdup("skill_report");
    out->reason = xstrdup("规则降级:命中出报告意图");
  } else if (str_icontains(t, "评测") || str_icontains(t, "召回") ||
             str_icontains(t, "误报率") || str_icontains(t, "跑分")) {
    out->kind = ACT_ACT;
    out->tool = xstrdup("skill_evaluate");
    out->reason = xstrdup("规则降级:命中评测意图");
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
        "③ 生成报告;④ 跑评测看召回率与误报率。\n"
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
