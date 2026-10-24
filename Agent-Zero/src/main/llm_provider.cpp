/* llm_provider.cpp —— 多家模型厂商的接入与兜底。
 *
 * 一份 models.json 描述"用哪些模型、按什么顺序试":
 *   调用方只问 provider_chat() 要一段补全,这里负责鉴权、拼请求、
 *   解 SSE、把增量吐给界面、把失败原因说清楚。
 */
#include "llm_provider.h"

#include <bcrypt.h>
#include <ctype.h>

#include "http.h"
#include "net.h"
static provider_t g_list[PROVIDER_MAX];
static int g_count = 0;
static char g_active[64] = {0};
static char g_path[MAX_PATH * 2] = {0};

/* ================= 小工具 ================= */

static void copy_trim(char *dst, size_t cap, const char *src) {
  if (!dst || cap == 0) return;
  strncpy_s(dst, cap, src ? src : "", _TRUNCATE);
  char *t = str_trim(dst);
  if (t != dst) memmove(dst, t, strlen(t) + 1);
}

static int ends_with(const char *s, const char *tail) {
  if (!s || !tail) return 0;
  size_t ls = strlen(s), lt = strlen(tail);
  return ls >= lt && strcmp(s + ls - lt, tail) == 0;
}

static void url_append(char *out, size_t cap, const char *base, const char *suffix) {
  size_t n = base ? strlen(base) : 0;
  while (n > 0 && base[n - 1] == '/') n--;
  snprintf(out, cap, "%.*s%s", (int)n, base ? base : "", suffix);
}

/* 掩码:界面上只回显后四位,但"留空/原样回传"都表示不修改 */
static void mask_secret(const char *in, char *out, size_t cap) {
  if (!in || !*in) { out[0] = 0; return; }
  size_t n = strlen(in);
  if (n <= 4) { snprintf(out, cap, "\xe2\x80\xa2\xe2\x80\xa2\xe2\x80\xa2\xe2\x80\xa2"); return; }
  snprintf(out, cap, "\xe2\x80\xa2\xe2\x80\xa2\xe2\x80\xa2\xe2\x80\xa2%s", in + n - 4);
}

static int is_masked(const char *s) {
  return s && strncmp(s, "\xe2\x80\xa2\xe2\x80\xa2\xe2\x80\xa2\xe2\x80\xa2", 12) == 0;
}

/* ================= 签名(恒脑平台) ================= */
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

/* ================= 载入 / 落盘 ================= */

const char *provider_kind_name(int kind) {
  switch (kind) {
    case PROVIDER_DAS: return "das";
    case PROVIDER_OPENAI: return "openai";
    case PROVIDER_ANTHROPIC: return "anthropic";
    default: return "openai";
  }
}

int provider_kind_from_name(const char *name) {
  if (!name) return PROVIDER_OPENAI;
  if (str_ieq(name, "das") || str_ieq(name, "hengn") || str_ieq(name, "\xe6\x81\x92\xe8\x84\x91"))
    return PROVIDER_DAS;
  if (str_ieq(name, "anthropic") || str_ieq(name, "claude")) return PROVIDER_ANTHROPIC;
  return PROVIDER_OPENAI;
}

const char *providers_path(void) { return g_path; }

static void provider_defaults(provider_t *p) {
  memset(p, 0, sizeof(*p));
  p->kind = PROVIDER_OPENAI;
  p->timeout_ms = 45000;
  p->temperature = 0.2;
  p->enabled = 1;
}

/* 老配置(.env / 环境变量)平滑升级:有恒脑密钥就自动生成一条,别让升级把
   已经能用的模型弄丢了。这条只在 models.json 还不存在时用。 */
static void seed_from_env(void) {
  const char *a = getenv("DAS_APP_KEY"), *s = getenv("DAS_APP_SECRET");
  const char *b = getenv("DAS_BASE_URL"), *i = getenv("DAS_AGENT_ID");
  const char *k = getenv("DAS_AGENT_KEYWORD"), *u = getenv("DAS_USER_APP_KEY");
  char envs[6][256] = {{0}};
  if (!a || !s) {
    /* 再看 exe 旁边的 .env(部署时最省事的一种写法) */
    char path[MAX_PATH * 2];
    path_join(path, sizeof(path), app_dir(), ".env");
    size_t len = 0;
    char *text = file_read_all(path, &len);
    if (!text) return;
    char **lines = NULL;
    int n = str_split(text, '\n', &lines, 0);
    for (int j = 0; j < n; j++) {
      char *line = str_trim(lines[j]);
      if (!line[0] || line[0] == '#') continue;
      char *eq = strchr(line, '=');
      if (!eq) continue;
      *eq = 0;
      char *key = str_trim(line), *val = str_trim(eq + 1);
      size_t vl = strlen(val);
      if (vl >= 2 && val[0] == '"' && val[vl - 1] == '"') { val[vl - 1] = 0; val++; }
      if (str_ieq(key, "DAS_APP_KEY")) copy_trim(envs[0], sizeof(envs[0]), val);
      else if (str_ieq(key, "DAS_APP_SECRET")) copy_trim(envs[1], sizeof(envs[1]), val);
      else if (str_ieq(key, "DAS_BASE_URL")) copy_trim(envs[2], sizeof(envs[2]), val);
      else if (str_ieq(key, "DAS_AGENT_ID")) copy_trim(envs[3], sizeof(envs[3]), val);
      else if (str_ieq(key, "DAS_AGENT_KEYWORD")) copy_trim(envs[4], sizeof(envs[4]), val);
      else if (str_ieq(key, "DAS_USER_APP_KEY")) copy_trim(envs[5], sizeof(envs[5]), val);
    }
    str_free_list(lines, n);
    free(text);
    a = envs[0][0] ? envs[0] : NULL;
    s = envs[1][0] ? envs[1] : NULL;
    b = envs[2][0] ? envs[2] : NULL;
    i = envs[3][0] ? envs[3] : NULL;
    k = envs[4][0] ? envs[4] : NULL;
    u = envs[5][0] ? envs[5] : NULL;
  }
  if (!a || !s) return;
  provider_t *p = &g_list[0];
  provider_defaults(p);
  copy_trim(p->id, sizeof(p->id), "das");
  copy_trim(p->name, sizeof(p->name), "\xe6\x81\x92\xe8\x84\x91\xe6\x99\xba\xe8\x83\xbd\xe4\xbd\x93");
  p->kind = PROVIDER_DAS;
  copy_trim(p->base_url, sizeof(p->base_url), b ? b : "");
  copy_trim(p->api_key, sizeof(p->api_key), a);
  copy_trim(p->api_secret, sizeof(p->api_secret), s);
  copy_trim(p->agent_id, sizeof(p->agent_id), i ? i : "");
  copy_trim(p->agent_keyword, sizeof(p->agent_keyword), k ? k : "");
  copy_trim(p->user_app_key, sizeof(p->user_app_key), u ? u : "");
  g_count = 1;
  copy_trim(g_active, sizeof(g_active), p->id);
}

int providers_load(void) {
  const char *dir = app_data_dir();
  path_join(g_path, sizeof(g_path), dir, "models.json");
  g_count = 0;
  g_active[0] = 0;

  size_t len = 0;
  char *text = file_read_all(g_path, &len);
  if (!text) { seed_from_env(); return g_count; }

  json_t *root = json_parse(text);
  free(text);
  if (!root) { seed_from_env(); return g_count; }

  json_t *arr = j_get(root, "providers");
  int n = arr ? j_len(arr) : 0;
  for (int i = 0; i < n && g_count < PROVIDER_MAX; i++) {
    json_t *it = j_at(arr, i);
    if (!it) continue;
    provider_t *p = &g_list[g_count];
    provider_defaults(p);
    copy_trim(p->id, sizeof(p->id), j_s(it, "id", ""));
    copy_trim(p->name, sizeof(p->name), j_s(it, "name", ""));
    p->kind = provider_kind_from_name(j_s(it, "kind", "openai"));
    copy_trim(p->base_url, sizeof(p->base_url), j_s(it, "base_url", ""));
    copy_trim(p->model, sizeof(p->model), j_s(it, "model", ""));
    copy_trim(p->api_key, sizeof(p->api_key), j_s(it, "api_key", ""));
    copy_trim(p->api_secret, sizeof(p->api_secret), j_s(it, "api_secret", ""));
    copy_trim(p->user_app_key, sizeof(p->user_app_key), j_s(it, "user_app_key", ""));
    copy_trim(p->agent_id, sizeof(p->agent_id), j_s(it, "agent_id", ""));
    copy_trim(p->agent_keyword, sizeof(p->agent_keyword), j_s(it, "agent_keyword", ""));
    copy_trim(p->headers, sizeof(p->headers), j_s(it, "headers", ""));
    p->timeout_ms = j_n(it, "timeout_ms", 45000);
    p->temperature = j_n(it, "temperature", 0.2);
    p->max_tokens = (int)j_n(it, "max_tokens", 0);
    p->enabled = j_b(it, "enabled", 1);
    if (!p->id[0]) snprintf(p->id, sizeof(p->id), "p%d", g_count + 1);
    if (!p->name[0]) snprintf(p->name, sizeof(p->name), "%s", p->id);
    g_count++;
  }
  copy_trim(g_active, sizeof(g_active), j_s(root, "active", ""));
  json_free(root);
  if (g_count == 0) seed_from_env();
  return g_count;
}

void providers_init(void) { providers_load(); }

int providers_count(void) { return g_count; }

provider_t *provider_at(int i) {
  return (i >= 0 && i < g_count) ? &g_list[i] : NULL;
}

provider_t *provider_find(const char *id) {
  if (!id || !*id) return NULL;
  for (int i = 0; i < g_count; i++)
    if (str_ieq(g_list[i].id, id)) return &g_list[i];
  return NULL;
}

int providers_active_index(void) {
  for (int i = 0; i < g_count; i++)
    if (str_ieq(g_list[i].id, g_active)) return i;
  for (int i = 0; i < g_count; i++)
    if (g_list[i].enabled && provider_ready(&g_list[i])) return i;
  return g_count > 0 ? 0 : -1;
}

const char *providers_active_id(void) {
  int i = providers_active_index();
  return i >= 0 ? g_list[i].id : "";
}

static int provider_complete(const provider_t *p) {
  if (!p || !p->base_url[0]) return 0;
  if (p->kind == PROVIDER_DAS) return p->api_key[0] && p->api_secret[0];
  return p->api_key[0] && p->model[0];
}

int provider_ready(const provider_t *p) { return p && p->enabled && provider_complete(p); }

int providers_ready_count(void) {
  int n = 0;
  for (int i = 0; i < g_count; i++)
    if (provider_ready(&g_list[i])) n++;
  return n;
}

const char *providers_display_name(void) {
  int idx = providers_active_index();
  const provider_t *p = idx >= 0 ? provider_at(idx) : NULL;
  if (p && provider_ready(p)) return p->name;
  for (int i = 0; i < g_count; i++)
    if (provider_ready(&g_list[i])) return g_list[i].name;
  return "还没接模型";
}

static void provider_to_json(json_t *o, const provider_t *p, int mask) {
  j_set_str(o, "id", p->id);
  j_set_str(o, "name", p->name);
  j_set_str(o, "kind", provider_kind_name(p->kind));
  j_set_str(o, "base_url", p->base_url);
  j_set_str(o, "model", p->model);
  char m[320];
  if (mask) {
    mask_secret(p->api_key, m, sizeof(m));
    j_set_str(o, "api_key", m);
    mask_secret(p->api_secret, m, sizeof(m));
    j_set_str(o, "api_secret", m);
    mask_secret(p->user_app_key, m, sizeof(m));
    j_set_str(o, "user_app_key", m);
  } else {
    j_set_str(o, "api_key", p->api_key);
    j_set_str(o, "api_secret", p->api_secret);
    j_set_str(o, "user_app_key", p->user_app_key);
  }
  j_set_bool(o, "has_key", p->api_key[0] != 0);
  j_set_bool(o, "has_secret", p->api_secret[0] != 0);
  j_set_str(o, "agent_id", p->agent_id);
  j_set_str(o, "agent_keyword", p->agent_keyword);
  j_set_str(o, "headers", p->headers);
  j_set_num(o, "timeout_ms", p->timeout_ms);
  j_set_num(o, "temperature", p->temperature);
  j_set_num(o, "max_tokens", p->max_tokens);
  j_set_bool(o, "enabled", p->enabled);
  j_set_bool(o, "ready", provider_ready(p));
}

char *providers_json(int mask) {
  json_t *root = j_obj();
  j_set_num(root, "schema", 1);
  j_set_str(root, "active", g_active);
  j_set_str(root, "path", g_path);
  json_t *arr = j_arr();
  for (int i = 0; i < g_count; i++) {
    json_t *o = j_obj();
    provider_to_json(o, &g_list[i], mask);
    j_add(arr, o);
  }
  j_set(root, "providers", arr);
  j_set_num(root, "ready", providers_ready_count());
  char *out = json_dump_pretty(root);
  json_free(root);
  return out;
}

int providers_save(void) {
  json_t *root = j_obj();
  j_set_num(root, "schema", 1);
  j_set_str(root, "active", g_active);
  json_t *arr = j_arr();
  for (int i = 0; i < g_count; i++) {
    json_t *o = j_obj();
    provider_to_json(o, &g_list[i], 0);
    j_add(arr, o);
  }
  j_set(root, "providers", arr);
  char *text = json_dump_pretty(root);
  json_free(root);
  if (!text) return -1;
  int rc = file_write_all(g_path, text, strlen(text));
  free(text);
  if (rc != 0) log_warn("写 models.json 失败: %s", g_path);
  return rc;
}

int providers_apply(json_t *root, char *err, size_t errcap) {
  if (err && errcap) err[0] = 0;
  if (!root) {
    if (err) snprintf(err, errcap, "请求体不是合法 JSON");
    return -1;
  }
  json_t *arr = j_get(root, "providers");
  int n = arr ? j_len(arr) : 0;
  if (n > PROVIDER_MAX) {
    if (err) snprintf(err, errcap, "最多 %d 个模型", PROVIDER_MAX);
    return -2;
  }
  provider_t tmp[PROVIDER_MAX];
  int m = 0;
  for (int i = 0; i < n; i++) {
    json_t *it = j_at(arr, i);
    if (!it) continue;
    provider_t *p = &tmp[m];
    provider_defaults(p);
    const char *old_id = j_s(it, "id", "");
    const provider_t *old = provider_find(old_id);
    copy_trim(p->id, sizeof(p->id), old_id);
    copy_trim(p->name, sizeof(p->name), j_s(it, "name", ""));
    p->kind = provider_kind_from_name(j_s(it, "kind", "openai"));
    copy_trim(p->base_url, sizeof(p->base_url), j_s(it, "base_url", ""));
    copy_trim(p->model, sizeof(p->model), j_s(it, "model", ""));
    /* 密钥:空 = 不改,掩码 = 不改,别的都当新值 */
    const char *k = j_s(it, "api_key", "");
    if (*k && !is_masked(k)) copy_trim(p->api_key, sizeof(p->api_key), k);
    else if (old) copy_trim(p->api_key, sizeof(p->api_key), old->api_key);
    const char *s = j_s(it, "api_secret", "");
    if (*s && !is_masked(s)) copy_trim(p->api_secret, sizeof(p->api_secret), s);
    else if (old) copy_trim(p->api_secret, sizeof(p->api_secret), old->api_secret);
    const char *u = j_s(it, "user_app_key", "");
    if (*u && !is_masked(u)) copy_trim(p->user_app_key, sizeof(p->user_app_key), u);
    else if (old) copy_trim(p->user_app_key, sizeof(p->user_app_key), old->user_app_key);
    copy_trim(p->agent_id, sizeof(p->agent_id), j_s(it, "agent_id", ""));
    copy_trim(p->agent_keyword, sizeof(p->agent_keyword), j_s(it, "agent_keyword", ""));
    copy_trim(p->headers, sizeof(p->headers), j_s(it, "headers", ""));
    p->timeout_ms = j_n(it, "timeout_ms", old ? old->timeout_ms : 45000);
    p->temperature = j_n(it, "temperature", old ? old->temperature : 0.2);
    p->max_tokens = (int)j_n(it, "max_tokens", old ? old->max_tokens : 0);
    p->enabled = j_b(it, "enabled", 1);
    if (!p->id[0]) snprintf(p->id, sizeof(p->id), "p%d", m + 1);
    if (!p->name[0]) snprintf(p->name, sizeof(p->name), "%s", p->id);
    /* id 撞车会让界面选错行,后缀区分一下 */
    for (int j = 0; j < m; j++) {
      if (str_ieq(tmp[j].id, p->id)) {
        char fixed[64];
        snprintf(fixed, sizeof(fixed), "%s-%d", p->id, j + 2);
        copy_trim(p->id, sizeof(p->id), fixed);
        break;
      }
    }
    m++;
  }

  char active[64];
  copy_trim(active, sizeof(active), j_s(root, "active", g_active));
  /* 校验要针对"即将生效的新列表",不能查旧列表:删掉当前那条时,
     旧列表里它还在,active 就会被留下来指向一个已经不存在的条目。 */
  int active_ok = 0;
  for (int i = 0; i < m; i++) {
    if (active[0] && str_ieq(tmp[i].id, active)) { active_ok = 1; break; }
  }
  if (!active_ok) {
    active[0] = 0;
    for (int i = 0; i < m; i++)
      if (tmp[i].enabled) { copy_trim(active, sizeof(active), tmp[i].id); break; }
    if (!active[0] && m > 0) copy_trim(active, sizeof(active), tmp[0].id);
  }

  /* 通过校验才提交,失败不破坏正在生效的配置 */
  memcpy(g_list, tmp, sizeof(provider_t) * (size_t)m);
  g_count = m;
  copy_trim(g_active, sizeof(g_active), active);
  if (providers_save() != 0) {
    if (err) snprintf(err, errcap, "配置写盘失败: %s", g_path);
    return -3;
  }
  return 0;
}

/* ================= SSE 解析 ================= */

typedef struct {
  buf_t line;        /* 行缓冲:一次读可能只到半行 */
  buf_t alt;         /* 恒脑:非最终答案的内容(过程/思考) */
  buf_t *out;        /* 最终答案 */
  provider_emit_fn emit;
  void *ud;
  int kind;
  int any;           /* 收到过正文没有 */
  int done;          /* 见到 [DONE]:这一轮已经收完,不必再等对端关连接 */
} sse_parser_t;

static void emit_text(sse_parser_t *p, const char *t) {
  if (!t || !*t) return;
  p->any = 1;
  if (p->emit) p->emit(p->ud, t);
}

static void parse_event(sse_parser_t *p, json_t *o) {
  if (!o) return;
  if (p->kind == PROVIDER_DAS) {
    json_t *data = j_get(o, "data");
    const char *content = j_s(data, "content", NULL);
    if (!content || !*content) return;
    const char *from = j_s(data, "from", "");
    int is_answer = (strcmp(from, "execute_result") == 0 ||
                     strcmp(from, "react_answer") == 0 ||
                     strcmp(from, "restful_answer") == 0);
    if (is_answer) buf_puts(p->out, content);
    else buf_puts(&p->alt, content);
    emit_text(p, content);
    return;
  }
  if (p->kind == PROVIDER_ANTHROPIC) {
    const char *type = j_s(o, "type", "");
    if (strcmp(type, "content_block_delta") == 0) {
      json_t *d = j_get(o, "delta");
      const char *t = j_s(d, "text", NULL);
      if (t) { buf_puts(p->out, t); emit_text(p, t); }
    } else if (strcmp(type, "content_block_start") == 0) {
      json_t *b = j_get(o, "content_block");
      const char *t = j_s(b, "text", NULL);
      if (t && *t) { buf_puts(p->out, t); emit_text(p, t); }
    } else if (strcmp(type, "error") == 0) {
      json_t *e = j_get(o, "error");
      const char *m = j_s(e, "message", NULL);
      if (m) log_warn("模型返回错误: %s", m);
    } else {
      /* 非流式:{"content":[{"type":"text","text":"..."}]} */
      json_t *arr = j_get(o, "content");
      json_t *c0 = j_at(arr, 0);
      const char *t = j_s(c0, "text", NULL);
      if (t) { buf_puts(p->out, t); emit_text(p, t); }
    }
    return;
  }
  /* OpenAI 兼容 */
  json_t *choices = j_get(o, "choices");
  json_t *c0 = j_at(choices, 0);
  if (!c0) return;
  json_t *delta = j_get(c0, "delta");
  const char *t = j_s(delta, "content", NULL);
  if (!t || !*t) {
    json_t *msg = j_get(c0, "message");
    t = j_s(msg, "content", NULL);
  }
  if (t && *t) { buf_puts(p->out, t); emit_text(p, t); }
}

static void feed_line(sse_parser_t *p, const char *raw) {
  char buf[8192];
  copy_trim(buf, sizeof(buf), raw);
  const char *js = NULL;
  if (str_startswith(buf, "data:")) js = str_trim(buf + 5);
  else if (buf[0] == '{') js = buf;   /* 有些网关直接一行一个 JSON */
  if (!js || !*js) return;
  if (js[0] != '{') {
    /* [DONE] 是"这一段说完了"的正牌信号:记下来,让取数层立刻断开。
       心跳/注释不是结束,不处理。 */
    if (!strcmp(js, "[DONE]")) p->done = 1;
    return;
  }
  json_t *o = json_parse(js);
  if (o) { parse_event(p, o); json_free(o); }
}

static int on_chunk(void *ud, const char *data, size_t n) {
  sse_parser_t *p = (sse_parser_t *)ud;
  for (size_t i = 0; i < n; i++) {
    char c = data[i];
    if (c != '\n') { buf_putc_(&p->line, c); continue; }
    feed_line(p, p->line.data ? p->line.data : "");
    buf_clear(&p->line);
    if (p->done) return 1;              /* 收完了:让取数层别陪着等超时 */
  }
  return p->done;
}

/* 整个响应体当一次性输入再喂一遍(非流式 / 末尾没有换行的最后一行) */
static void feed_tail(sse_parser_t *p, const char *body) {
  if (!body || !*body) return;
  char **lines = NULL;
  int n = str_split(body, '\n', &lines, 0);
  for (int i = 0; i < n; i++) feed_line(p, lines[i]);
  str_free_list(lines, n);
  if (p->line.len) feed_line(p, p->line.data);
}

static int body_error(json_t *o, char *err, size_t cap) {
  if (!o) return 0;
  json_t *e = j_get(o, "error");
  if (e) {
    const char *m = j_s(e, "message", NULL);
    if (!m) m = j_s(e, "msg", NULL);
    if (m && *m) { snprintf(err, cap, "%s", m); return 1; }
  }
  const char *m = j_s(o, "msg", NULL);
  if (m && *m) { snprintf(err, cap, "%s", m); return 1; }
  m = j_s(o, "message", NULL);
  if (m && *m) { snprintf(err, cap, "%s", m); return 1; }
  return 0;
}

/* ================= 三种协议的请求 ================= */

static void add_extra_headers(buf_t *h, const char *headers) {
  if (!headers || !*headers) return;
  char **lines = NULL;
  int n = str_split(headers, '\n', &lines, 0);
  for (int i = 0; i < n; i++) {
    char *ln = str_trim(lines[i]);
    if (!ln[0] || !strchr(ln, ':')) continue;
    buf_printf(h, "%s\r\n", ln);
  }
  str_free_list(lines, n);
}

int provider_chat(const provider_t *p, const char *prompt, provider_emit_fn emit,
                  void *ud, buf_t *out, char *err, size_t errcap) {
  if (err && errcap) err[0] = 0;
  if (!p || !prompt || !out) {
    if (err) snprintf(err, errcap, "调用参数不完整");
    return -1;
  }
  if (!provider_complete(p)) {
    if (err) snprintf(err, errcap, p->kind == PROVIDER_DAS
        ? "还没填接口地址 / appKey / appSecret"
        : "还没填接口地址 / API Key / 模型名");
    return -1;
  }

  char url[512];
  buf_t hdrs, body;
  buf_init(&hdrs);
  buf_init(&body);
  buf_puts(&hdrs, "Content-Type: application/json\r\n");

  if (p->kind == PROVIDER_DAS) {
    if (ends_with(p->base_url, "/agent/execute"))
      snprintf(url, sizeof(url), "%s", p->base_url);
    else
      url_append(url, sizeof(url), p->base_url, "/open/api/v2/agent/execute");
    char sign[512];
    llm_make_sign(p->api_key, p->api_secret, sign, sizeof(sign));
    buf_printf(&hdrs, "appKey: %s\r\nsign: %s\r\next: child_preview:0;reason:1\r\n",
               p->api_key, sign);
    buf_puts(&body, "{\"id\":");
    buf_json_str(&body, p->agent_id);
    buf_puts(&body, ",\"sid\":\"");
    unsigned int r = (unsigned int)(now_ms() & 0xFFFFFFFF);
    buf_printf(&body, "%08x-0000-4000-8000-%08x%04x", r, r, (unsigned)(now_ms() & 0xFFFF));
    buf_puts(&body, "\",\"input\":");
    buf_json_str(&body, prompt);
    buf_puts(&body, ",\"stream\":true,\"order\":\"routine\",\"debugSwitch\":false}");
  } else if (p->kind == PROVIDER_ANTHROPIC) {
    if (ends_with(p->base_url, "/messages")) snprintf(url, sizeof(url), "%s", p->base_url);
    else if (ends_with(p->base_url, "/v1")) url_append(url, sizeof(url), p->base_url, "/messages");
    else url_append(url, sizeof(url), p->base_url, "/v1/messages");
    buf_printf(&hdrs, "x-api-key: %s\r\nanthropic-version: 2023-06-01\r\n", p->api_key);
    buf_puts(&body, "{\"model\":");
    buf_json_str(&body, p->model);
    buf_printf(&body, ",\"max_tokens\":%d,\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":",
               p->max_tokens > 0 ? p->max_tokens : 2048);
    buf_json_str(&body, prompt);
    buf_puts(&body, "}]");
    if (p->temperature >= 0) buf_printf(&body, ",\"temperature\":%.2f", p->temperature);
    buf_puts(&body, "}");
  } else {
    if (ends_with(p->base_url, "/chat/completions")) snprintf(url, sizeof(url), "%s", p->base_url);
    else url_append(url, sizeof(url), p->base_url, "/chat/completions");
    buf_printf(&hdrs, "Authorization: Bearer %s\r\n", p->api_key);
    if (p->api_secret[0]) buf_printf(&hdrs, "api-key: %s\r\n", p->api_secret);
    buf_puts(&body, "{\"model\":");
    buf_json_str(&body, p->model);
    buf_puts(&body, ",\"messages\":[{\"role\":\"user\",\"content\":");
    buf_json_str(&body, prompt);
    buf_puts(&body, "}],\"stream\":true");
    if (p->temperature >= 0) buf_printf(&body, ",\"temperature\":%.2f", p->temperature);
    if (p->max_tokens > 0) buf_printf(&body, ",\"max_tokens\":%d", p->max_tokens);
    buf_puts(&body, "}");
  }
  add_extra_headers(&hdrs, p->headers);

  sse_parser_t st;
  memset(&st, 0, sizeof(st));
  buf_init(&st.line);
  buf_init(&st.alt);
  st.out = out;
  st.emit = emit;
  st.ud = ud;
  st.kind = p->kind;

  http_resp_t resp;
  int timeout = (int)(p->timeout_ms > 0 ? p->timeout_ms : 45000);
  net_post_stream(url, hdrs.data, timeout, body.data, on_chunk, &st, &resp);
  buf_free(&st.line);
  buf_free(&hdrs);
  buf_free(&body);

  int rc = -1;
  if (resp.error) {
    if (err) snprintf(err, errcap, "网络: %s", resp.error);
  } else if (resp.status != 200) {
    char detail[256] = {0};
    json_t *o = resp.body ? json_parse(resp.body) : NULL;
    if (o) { body_error(o, detail, sizeof(detail)); json_free(o); }
    if (!detail[0] && resp.body) {
      snprintf(detail, sizeof(detail), "%.180s", resp.body);
      char *nl = strchr(detail, '\n');
      if (nl) *nl = 0;
    }
    if (err) snprintf(err, errcap, "HTTP %d %s", resp.status, detail);
  } else {
    /* 流式时正文已经在 on_chunk 里累积;非流式到此再解一遍 */
    if (!st.any && resp.body) feed_tail(&st, resp.body);
    if (!st.any && resp.body) {
      char detail[256] = {0};
      json_t *o = json_parse(resp.body);
      if (o) { body_error(o, detail, sizeof(detail)); json_free(o); }
      if (!detail[0]) snprintf(detail, sizeof(detail), "%.160s", resp.body);
      if (err) snprintf(err, errcap, "接口没有返回内容: %s", detail);
    } else if (out->len == 0 && st.alt.len) {
      buf_puts(out, st.alt.data);
    }
    rc = st.any ? 0 : -1;
  }
  if (rc != 0 && err && errcap && !err[0]) snprintf(err, errcap, "调用失败");
  if (rc != 0) {
    log_warn("模型 [%s] 调用失败: %s", p->name, err ? err : "");
  } else {
    net_audit("llm_ok", p->id, 1, url, NULL);
  }
  buf_free(&st.alt);
  http_resp_free(&resp);
  return rc;
}

int providers_test(const char *id, char *detail, size_t detailcap) {
  if (detail && detailcap) detail[0] = 0;
  provider_t *p = provider_find(id);
  if (!p) {
    if (detail) snprintf(detail, detailcap, "找不到这个模型: %s", id ? id : "");
    return -1;
  }
  buf_t out;
  buf_init(&out);
  char err[512] = {0};
  /* 一句话就够:能返回任何正文,说明地址、密钥、模型名都对了 */
  int rc = provider_chat(p, "回复两个字:通了", NULL, NULL, &out, err, sizeof(err));
  size_t n = out.len;
  buf_free(&out);
  if (rc != 0) {
    if (detail) snprintf(detail, detailcap, "%s", err);
    return -1;
  }
  if (detail) snprintf(detail, detailcap, "模型回了 %zu 个字", n);
  return 0;
}
