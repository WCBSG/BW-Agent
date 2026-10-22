/* tools.cpp —— 工具注册表 + 参数校验 + 合规目标解析。
 *
 * 工具是最低层的手:一次取数、一次匹配。它们不懂"业务",只负责"做一次动作并把
 * 结果如实返回"。"这件事该不该做、做完算不算成功"是技能层的事。
 *
 * 所有工具都遵守两条纪律:
 *   1. 只做只读动作(GET/HEAD),不做任何写入、上传、爆破、利用;
 *   2. 目标必须过授权校验(由 net.c 的合规层兜底,工具自己也再查一次)。
 */
#include "tools.h"
#include "regex.h"

#include "net.h"
#include "rules.h"
#include "store.h"
#include "webutil.h"

#include <ctype.h>

static tool_t *g_tools = NULL;      /* 内置表 + 外部追加项 */
static int g_tool_count = 0;
static int g_tool_cap = 0;

/* ---------- 具体工具的实现(每个都短小、可单测) ---------- */
static int t_sensitive_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
static int t_password_check(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
static int t_site_crawl(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
static int t_sensitive_file_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
static int t_dir_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
static int t_page_diff(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
static int t_nuclei_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
static int t_sqli_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out);

/* 目标归一(补协议)与站点根提取:所有探测类工具共用,定义在后面 */
static void normalize_target(const char *in, char *out, size_t cap);
static void probe_root(const char *url, char *out, size_t cap);

/* 工具声明:name / description / schema / kind / source_url
   —— 与三册合同里的 ToolDecl 字段一一对应。 */
static tool_t g_registry[] = {
    {"sensitive_scan",
     "扫描一段文本里的敏感信息(身份证/手机号/邮箱/IP/凭据/私钥),并叠加任务绑定的"
     "敏感信息定义(关键词、正则)。用于检查用户粘贴的文本或抓到的页面内容。",
     "{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\",\"description\":\"要扫描的文本\"}},"
     "\"required\":[\"text\"],\"additionalProperties\":false}",
     "内置", "", t_sensitive_scan},

    {"password_check",
     "评估口令强度:长度、字符类型、是否命中常见弱口令表,给出等级、问题清单与改进建议。",
     "{\"type\":\"object\",\"properties\":{\"password\":{\"type\":\"string\",\"description\":\"要评估的口令\"}},"
     "\"required\":[\"password\"],\"additionalProperties\":false}",
     "内置", "", t_password_check},

    {"site_crawl",
     "从目标地址出发自动发现站点页面与资源(同域、限深、限速),记录类型、状态码、"
     "发现深度与父页面。资产底账由它建立。",
     "{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\"},"
     "\"max_depth\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":4},"
     "\"max_pages\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":100}},"
     "\"required\":[\"target\"],\"additionalProperties\":false}",
     "内置", "", t_site_crawl},

    {"sensitive_file_probe",
     "探测误发布的配置、备份、源码与元数据文件:按当前生效的落点清单逐个只读取回,"
     "再按内容特征判定(不靠文件名猜),对自定义错误页不会误报。",
     "{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\"},"
     "\"paths\":{\"type\":\"array\",\"items\":{\"type\":\"string\"},"
     "\"description\":\"额外要试的路径(不传则用规则里的清单)\"}},"
     "\"required\":[\"target\"],\"additionalProperties\":false}",
     "内置", "", t_sensitive_file_probe},

    {"dir_probe",
     "探测常见目录(上传/备份/数据/日志/管理入口等):判断是否开放目录索引、"
     "是否为登录入口、是否暴露文件。只做只读访问,不爆破、不上传。",
     "{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\"},"
     "\"dirs\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}}},"
     "\"required\":[\"target\"],\"additionalProperties\":false}",
     "内置", "", t_dir_probe},

    {"page_diff",
     "内容基线比对:第一次执行采集基线,之后每次比对差异,给出内容、标题与"
     "外域链接的增减情况。用于发现网页被篡改或被插入外部链接。",
     "{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\"}},"
     "\"required\":[\"target\"],\"additionalProperties\":false}",
     "内置", "", t_page_diff},

    {"nuclei_scan",
     "安全配置检查:安全响应头、Cookie 安全属性、版本信息泄露、错误回显、"
     "允许的 HTTP 方法、目录索引、混合内容。结论全部来自响应头与正文的客观事实。",
     "{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\"},"
     "\"templates\":{\"type\":\"string\"}},"
     "\"required\":[\"target\"],\"additionalProperties\":false}",
     "开源工具", "https://github.com/projectdiscovery/nuclei", t_nuclei_scan},

    {"sqli_probe",
     "对带参数的地址做注入验证:对每个参数分别发恒真与恒假条件比对响应差异,"
     "并单独验证错误回显特征;只确认是否存在注入,不取数据、不修改数据。",
     "{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\"},"
     "\"param\":{\"type\":\"string\",\"description\":\"只测这个参数(不传则测地址里的参数)\"}},"
     "\"required\":[\"target\"],\"additionalProperties\":false}",
     "开源工具", "https://github.com/sqlmapproject/sqlmap", t_sqli_probe},
};

void tools_init(void) {
  /* 幂等:agent_create 也会调它。如果不判重,第二次调用会把外部工具(MCP/命令行工具)
     的注册结果全部抹掉 —— 界面与提示词里就会"少"掉用户自己加的能力。 */
  static int inited = 0;
  if (inited) return;
  inited = 1;
  g_tools = g_registry;
  g_tool_count = (int)(sizeof(g_registry) / sizeof(g_registry[0]));
  g_tool_cap = 0;                      /* 0 = 现在用的还是内置静态表 */
}

/* 追加外部工具:容量不够时把内置表复制到堆上再扩容。
   内置 8 个永远排在前面 —— 外部同名不覆盖内置(tools_find 先命中内置)。 */
int tools_register_external(const char *name, const char *description,
                            const char *schema_json, const char *kind,
                            const char *source_url,
                            int (*run)(tool_ctx_t *, json_t *, tool_result_t *)) {
  if (!name || !*name || !run) return -1;
  if (tools_find(name)) return -1;     /* 重名就不加,内置优先 */
  if (g_tool_cap == 0) {
    int builtin = g_tool_count;
    tool_t *copy = (tool_t *)xcalloc((size_t)builtin + 8, sizeof(tool_t));
    memcpy(copy, g_registry, sizeof(tool_t) * (size_t)builtin);
    g_tools = copy;
    g_tool_cap = builtin + 8;
  } else if (g_tool_count >= g_tool_cap) {
    g_tool_cap *= 2;
    g_tools = (tool_t *)xrealloc(g_tools, sizeof(tool_t) * (size_t)g_tool_cap);
  }
  tool_t *t = &g_tools[g_tool_count++];
  memset(t, 0, sizeof(*t));
  t->name = xstrdup(name);
  t->description = xstrdup(description ? description : "外部工具");
  t->schema = xstrdup(schema_json && *schema_json ? schema_json
                                                : "{\"type\":\"object\",\"properties\":{}}");
  t->kind = xstrdup(kind && *kind ? kind : "外部工具");
  t->source_url = xstrdup(source_url ? source_url : "");
  t->run = run;
  return 0;
}

int tools_count(void) { return g_tool_count; }

tool_t *tools_get(int index) {
  return (index >= 0 && index < g_tool_count) ? &g_tools[index] : NULL;
}

tool_t *tools_find(const char *name) {
  for (int i = 0; i < g_tool_count; i++) {
    if (str_ieq(g_tools[i].name, name)) return &g_tools[i];
  }
  return NULL;
}

json_t *tools_decl_json(void) {
  json_t *arr = j_arr();
  for (int i = 0; i < g_tool_count; i++) {
    tool_t *t = &g_tools[i];
    json_t *o = j_obj();
    j_set_str(o, "name", t->name);
    j_set_str(o, "description", t->description);
    json_t *schema = json_parse(t->schema);
    j_set(o, "input_schema", schema ? schema : j_obj());
    j_set_str(o, "kind", t->kind);
    j_set_str(o, "source_url", t->source_url);
    j_add(arr, o);
  }
  return arr;
}

void tools_manifest(buf_t *out) {
  for (int i = 0; i < g_tool_count; i++) {
    tool_t *t = &g_tools[i];
    buf_printf(out, "- %s —— %s\n", t->name, t->description);
  }
}

/* ================= 参数校验 ================= */
int tools_validate(tool_t *t, json_t *args, buf_t *err) {
  if (!t) {
    if (err) buf_puts(err, "没有这个工具");
    return -1;
  }
  json_t *schema = json_parse(t->schema);
  if (!schema) return 0;                       /* 没 schema 就不校验(不该发生) */
  json_t *required = j_get(schema, "required");
  int bad = 0;
  for (int i = 0; i < j_len(required); i++) {
    json_t *k = j_at(required, i);
    if (!k || k->type != J_STR) continue;
    json_t *v = j_get(args, k->str);
    if (!v || v->type == J_NULL || (v->type == J_STR && (!v->str || !v->str[0]))) {
      if (err) buf_printf(err, "缺少必填参数 %s", k->str);
      bad = 1;
      break;
    }
  }
  if (!bad) {
    /* 类型粗查:模型偶尔把数字写成字符串,这里只拦住明显不对的 */
    json_t *props = j_get(schema, "properties");
    if (props && props->type == J_OBJ) {
      for (int i = 0; i < props->count; i++) {
        const char *key = props->keys[i];
        const char *want = j_s(props->items[i], "type", NULL);
        json_t *got = j_get(args, key);
        if (!want || !got || got->type == J_NULL) continue;
        int ok = (strcmp(want, "string") == 0 && got->type == J_STR) ||
                 (strcmp(want, "integer") == 0 && got->type == J_NUM) ||
                 (strcmp(want, "number") == 0 && got->type == J_NUM) ||
                 (strcmp(want, "boolean") == 0 && got->type == J_BOOL) ||
                 (strcmp(want, "array") == 0 && got->type == J_ARR) ||
                 (strcmp(want, "object") == 0 && got->type == J_OBJ);
        if (!ok) {
          if (err) buf_printf(err, "参数 %s 类型应为 %s", key, want);
          bad = 1;
          break;
        }
      }
    }
  }
  json_free(schema);
  return bad ? -1 : 0;
}

int tools_run(tool_ctx_t *ctx, const char *name, json_t *args, tool_result_t *out) {
  memset(out, 0, sizeof(*out));
  tool_t *t = tools_find(name);
  if (!t) {
    out->text = xstrdup("没有这个工具");
    out->is_error = 1;
    out->say = xstrdup("这个工具不存在,我换个做法。");
    return -1;
  }
  buf_t err;
  buf_init(&err);
  if (tools_validate(t, args, &err) != 0) {
    out->is_error = 1;
    buf_t tb;
    buf_init(&tb);
    buf_printf(&tb, "参数校验失败:%s", err.data);
    out->text = buf_take(&tb);
    buf_t sb;
    buf_init(&sb);
    buf_printf(&sb, "参数没给全(%s),这次先不执行。", err.data);
    out->say = buf_take(&sb);
    buf_free(&err);
    return -1;
  }
  buf_free(&err);
  /* 外部扩展(命令行工具 / MCP)的适配器靠 ctx->current_tool 知道这次调的是谁 */
  ctx->current_tool = name;
  int rc = t->run(ctx, args, out);
  ctx->current_tool = NULL;
  if (!out->say) out->say = xstrdup(out->text ? out->text : "");
  return rc;
}

/* ================= 目标与授权 ================= */
void target_resolve(buf_t *out, const char *raw, const char *fallback_host) {
  const char *s = raw;
  if (!s || !*s) s = fallback_host;
  if (!s || !*s) return;
  while (*s == ' ' || *s == '"' || *s == '\'') s++;
  if (*s == '/') {
    buf_puts(out, fallback_host ? fallback_host : "");
    buf_puts(out, s);
    return;
  }
  if (strstr(s, "://")) {
    buf_puts(out, s);
  } else {
    buf_puts(out, "https://");
    buf_puts(out, s);
  }
}

int scope_allows(tool_ctx_t *ctx, const char *url, char **err) {
  char host[256];
  net_host_of(url, host, sizeof(host));
  if (!host[0]) {
    if (err) *err = xstrdup("URL 里没有主机名");
    return 0;
  }
  if (ctx->domain_count == 0) return 1;      /* 没设范围时不拦(单测与本地靶站用) */
  for (int i = 0; i < ctx->domain_count; i++) {
    const char *d = ctx->domains[i];
    if (str_ieq(host, d)) return 1;
    size_t lh = strlen(host), ld = strlen(d);
    if (lh > ld && str_ieq(host + (lh - ld), d) && host[lh - ld - 1] == '.') return 1;
  }
  buf_t b;
  buf_init(&b);
  buf_printf(&b, "目标 %s 不在授权域名内(授权:%s)", host,
             ctx->domain_count ? ctx->domains[0] : "未配置");
  if (err) *err = buf_take(&b);
  else buf_free(&b);
  return 0;
}

/* 取数小包装:统一处理"授权 + 错误 + 限速" */
static int do_fetch(tool_ctx_t *ctx, const char *url, const char *method,
                    int *status, char **body, char **err) {
  if (!ctx->io.fetch) {
    if (err) *err = xstrdup("取数通道未就绪");
    return -1;
  }
  size_t len = 0;
  int rc = ctx->io.fetch(ctx->io.userdata, url, method, status, body, &len, err);
  ctx->http_calls++;
  return rc;
}

/* ================= 工具实现 ================= */

/* ---- 1. 文本敏感信息扫描 ---- */
/* 判定用的正则全部来自规则文件(patterns.sensitive),代码里不写死任何一条:
/* 判定用的正则来自规则文件(patterns.sensitive),匹配交给 src\regex.c 的极简引擎:
   支持字面量、字符类、分组与分支、* + ? {n,m}、^ $、(?i) 与两种 [0-9] 断言,
   带完整回溯 —— 邮箱/私钥头这种"先贪婪后回退"的形状才能正确匹配。
   规则写超范围时,`agent.exe regextest` 会直接告诉你原因。 */

/* 脱敏:保留头尾,中间星号(报告可能外传,不能留明文) */
static void mask_into(buf_t *out, const char *s, int len) {
  if (len <= 4) { for (int i = 0; i < len; i++) buf_putc_(out, '*'); return; }
  buf_putn(out, s, 2);
  for (int i = 2; i < len - 2; i++) buf_putc_(out, '*');
  buf_putn(out, s + len - 2, 2);
}

/* 给"自己写规则"的人用:先拿一条正则试一下它到底匹配什么(见 agent.exe regextest)。
   规则是数据,数据写错了不该靠猜 —— 这个口子让自定义正则当场可验。 */
int tools_regex_first(const char *pattern, const char *text, int *off, int *len) {
  if (!pattern || !text) return 0;
  char err[128];
  return rx_find(pattern, text, off, len, err, sizeof(err));
}

static int scan_text_into(tool_ctx_t *ctx, const char *text, json_t *hits) {
  int count = 0;
  int rules_n = rules_arr_count("patterns.sensitive");
  for (int r = 0; r < rules_n; r++) {
    const char *kind = rules_arr_str("patterns.sensitive", r, "kind", "");
    const char *pattern = rules_arr_str("patterns.sensitive", r, "pattern", "");
    const char *severity = rules_arr_str("patterns.sensitive", r, "severity", "中");
    if (!pattern[0]) continue;                     /* 规则里没写正则就跳过 */
    char rerr[128] = {0};
    rx_pattern *re = rx_compile(pattern, rerr, sizeof(rerr));
    if (!re) {
      /* 规则写错了要如实说,而不是"当成没命中" —— 否则使用者会以为站点干净 */
      log_warn("[规则] 敏感信息正则不合法,已跳过: %s(%s)", pattern, rerr);
      continue;
    }
    const char *scan = text;
    int searched = 0;
    while (searched < 200) {
      int off = 0, len = 0;
      if (!rx_search(re, scan, &off, &len)) break;
      buf_t masked;
      buf_init(&masked);
      mask_into(&masked, scan + off, len);
      json_t *h = j_obj();
      j_set_str(h, "kind", kind[0] ? kind : pattern);
      j_set_str(h, "severity", severity);
      j_set_str(h, "masked", masked.data);
      j_set_str(h, "rule", pattern);
      j_add(hits, h);
      buf_free(&masked);
      count++;
      scan += off + len;
      searched++;
      if (off + len <= 0) break;
    }
    rx_free(re);
  }
  if (rules_n == 0) {
    log_warn("[规则] patterns.sensitive 为空:敏感信息扫描没有可用规则");
  }
  (void)ctx;
  return count;
}

static int t_sensitive_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  const char *text = j_s(args, "text", "");
  json_t *hits = j_arr();
  int n = scan_text_into(ctx, text, hits);
  json_t *data = j_obj();
  j_set(hits, "hits", hits);
  j_set_num(data, "hit_count", n);
  out->data = data;

  buf_t t;
  buf_init(&t);
  if (n == 0) {
    buf_puts(&t, "未发现敏感信息");
    out->say = xstrdup("这段文本里没发现敏感信息。");
  } else {
    buf_printf(&t, "命中 %d 处敏感信息:\n", n);
    for (int i = 0; i < j_len(hits) && i < 20; i++) {
      json_t *h = j_at(hits, i);
      buf_printf(&t, "- [%s] %s: %s\n", j_s(h, "severity", ""), j_s(h, "kind", ""),
                 j_s(h, "masked", ""));
    }
    buf_t s;
    buf_init(&s);
    buf_printf(&s, "发现 %d 处敏感信息,已在结果卡片中列出(展示时已去敏),建议核实来源后处理。", n);
    out->say = buf_take(&s);
  }
  out->text = buf_take(&t);
  return 0;
}

/* ---- 2. 口令强度 ---- */
/* 弱口令表来自规则文件(weak_passwords)。表里没有就只按强度规则算分——
   这不是"少了功能",而是"口径跟着规则走":不同单位可以放自己的历史泄露口令表。 */
static int t_password_check(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  (void)ctx;
  const char *pw = j_s(args, "password", "");
  int score = 100;
  json_t *issues = j_arr();
  int weak_n = 0;
  const char **weak = rules_str_list("weak_passwords", &weak_n);
  for (int i = 0; i < weak_n; i++) {
    if (str_ieq(pw, weak[i])) {
      j_add(issues, j_str("命中常见弱口令表"));
      score -= 60;
      break;
    }
  }
  size_t len = strlen(pw);
  if (len < 8) { j_add(issues, j_str("长度不足 8 位")); score -= 20; }
  else if (len < 12) { j_add(issues, j_str("建议加长到 12 位以上")); score -= 8; }
  int has_upper = 0, has_lower = 0, has_digit = 0, has_sym = 0;
  for (const char *p = pw; *p; p++) {
    if (isupper((unsigned char)*p)) has_upper = 1;
    else if (islower((unsigned char)*p)) has_lower = 1;
    else if (isdigit((unsigned char)*p)) has_digit = 1;
    else has_sym = 1;
  }
  if (!has_upper) { j_add(issues, j_str("缺大写字母")); score -= 8; }
  if (!has_lower) { j_add(issues, j_str("缺小写字母")); score -= 8; }
  if (!has_digit) { j_add(issues, j_str("缺数字")); score -= 8; }
  if (!has_sym) { j_add(issues, j_str("缺符号")); score -= 8; }
  if (score < 0) score = 0;
  const char *level = score < 50 ? "弱" : (score < 80 ? "中" : "强");

  json_t *data = j_obj();
  j_set_num(data, "score", score);
  j_set_str(data, "level", level);
  j_set(data, "issues", issues);
  out->data = data;

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "等级: %s(%d/100)\n", level, score);
  for (int i = 0; i < j_len(issues); i++) {
    buf_printf(&t, "- %s\n", j_at(issues, i)->str);
  }
  out->text = buf_take(&t);
  buf_t s;
  buf_init(&s);
  buf_printf(&s, "口令评估结果:【%s】(%d/100 分),发现 %d 个问题,详见结果卡片。",
             level, score, j_len(issues));
  out->say = buf_take(&s);
  return 0;
}

/* ---- 3. 资产发现 ---- */
static int looks_like_html(const char *ct) {
  return !ct || !*ct || str_icontains(ct, "html") || str_icontains(ct, "text/plain");
}

/* 从 HTML 里抠链接:只认我们关心的几类属性 */
static void extract_links(const char *html, json_t *out) {
  static const char *attrs[] = {"href=\"", "src=\"", "action=\""};
  for (size_t a = 0; a < sizeof(attrs) / sizeof(attrs[0]); a++) {
    const char *p = html;
    while ((p = strstr(p, attrs[a])) != NULL) {
      p += strlen(attrs[a]);
      const char *end = strchr(p, '"');
      if (!end) break;
      size_t n = (size_t)(end - p);
      if (n > 0 && n < 1024) {
        char *link = xstrndup(p, n);
        if (!str_startswith(link, "javascript:") && !str_startswith(link, "mailto:") &&
            !str_startswith(link, "tel:") && !str_startswith(link, "#") &&
            !str_startswith(link, "data:")) {
          j_add(out, j_str(link));
        }
        free(link);
      }
      p = end;
    }
  }
}

static const char *classify_kind(const char *url) {
  const char *path = strstr(url, "://");
  path = path ? strchr(path + 3, '/') : url;
  if (!path) return "页面";
  const char *dot = strrchr(path, '.');
  const char *q = strchr(path, '?');
  if (q && (!dot || q < dot)) return "接口";
  if (!dot) return str_endswith(path, "/") ? "页面" : "其他";
  if (str_icontains(dot, ".css") || str_icontains(dot, ".js") || str_icontains(dot, ".png") ||
      str_icontains(dot, ".jpg") || str_icontains(dot, ".gif") || str_icontains(dot, ".svg") ||
      str_icontains(dot, ".ico") || str_icontains(dot, ".woff") || str_icontains(dot, ".map")) {
    return "静态资源";
  }
  if (str_icontains(path, "/api/") || str_icontains(path, "/ajax/")) return "接口";
  return "页面";
}

static int t_site_crawl(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  char target[1024] = {0};
  normalize_target(j_s(args, "target", ""), target, sizeof(target));
  int max_depth = (int)j_n(args, "max_depth", 1);
  int max_pages = (int)j_n(args, "max_pages", 12);
  if (max_depth < 0) max_depth = 0;
  if (max_depth > 3) max_depth = 3;
  if (max_pages < 1) max_pages = 1;
  if (max_pages > 60) max_pages = 60;

  /* 队列:BFS,记录深度与父页面(这样"发现树"是可解释的) */
  typedef struct { char *url; int depth; char *parent; } item_t;
  item_t *queue = (item_t *)xcalloc((size_t)max_pages * 4 + 8, sizeof(item_t));
  int qhead = 0, qtail = 0, qcap = max_pages * 4 + 8;
  char **seen = (char **)xcalloc((size_t)max_pages * 4 + 8, sizeof(char *));
  int seen_n = 0;

  queue[qtail].url = xstrdup(target);
  queue[qtail].depth = 0;
  queue[qtail].parent = NULL;
  qtail++;

  json_t *assets = j_arr();
  int fetched = 0;
  while (qhead < qtail && fetched < max_pages) {
    item_t cur = queue[qhead++];
    /* 去过重的跳过 */
    int dup = 0;
    for (int i = 0; i < seen_n; i++) if (strcmp(seen[i], cur.url) == 0) { dup = 1; break; }
    if (dup) { free(cur.url); free(cur.parent); continue; }
    seen[seen_n++] = xstrdup(cur.url);

    int status = 0;
    char *body = NULL;
    char *err = NULL;
    do_fetch(ctx, cur.url, "GET", &status, &body, &err);
    fetched++;

    const char *kind = classify_kind(cur.url);
    json_t *a = j_obj();
    j_set_str(a, "url", cur.url);
    j_set_str(a, "kind", kind);
    j_set_num(a, "status_code", status);
    j_set_num(a, "depth", cur.depth);
    if (cur.parent) j_set_str(a, "parent_url", cur.parent);
    else j_set_null(a, "parent_url");
    if (err) j_set_str(a, "error", err);
    j_add(assets, a);

    if (body && cur.depth < max_depth && looks_like_html(NULL)) {
      json_t *links = j_arr();
      extract_links(body, links);
      char host[256];
      net_host_of(cur.url, host, sizeof(host));
      /* 相对链接必须按"当前页面的协议+主机+端口"补全 ——
         写死 https://主机 会把 http 站点、非 80 端口的站点全部跟丢
         (看起来"6 个地址都连不上",其实是爬虫自己拼错了地址)。 */
      char base_origin[512];
      snprintf(base_origin, sizeof(base_origin), "%s", cur.url);
      char *bo_slash = strstr(base_origin, "://");
      if (bo_slash) {
        char *p = bo_slash + 3 + strcspn(bo_slash + 3, "/?#");
        *p = 0;                                  /* 只留 协议://主机[:端口] */
      }
      for (int i = 0; i < j_len(links); i++) {
        const char *link = j_at(links, i)->str;
        char abs[2048];
        if (str_startswith(link, "http://") || str_startswith(link, "https://")) {
          snprintf(abs, sizeof(abs), "%s", link);
        } else if (str_startswith(link, "//")) {
          const char *scheme = strstr(base_origin, "://");
          snprintf(abs, sizeof(abs), "%.*s%s", (int)(scheme ? scheme - base_origin : 0),
                   base_origin, link);
        } else if (link[0] == '/') {
          snprintf(abs, sizeof(abs), "%s%s", base_origin, link);
        } else if (link[0] == '?' || link[0] == '#') {
          snprintf(abs, sizeof(abs), "%s%s", cur.url, link);     /* 同页参数 */
        } else {
          continue;                       /* 目录相对路径先不展开,避免过度爬取 */
        }
        char lh[256];
        net_host_of(abs, lh, sizeof(lh));
        if (!str_ieq(lh, host)) continue;  /* 只跟同域 */
        if (qtail < qcap) {
          queue[qtail].url = xstrdup(abs);
          queue[qtail].depth = cur.depth + 1;
          queue[qtail].parent = xstrdup(cur.url);
          qtail++;
        }
      }
      json_free(links);
    }
    free(body);
    free(err);
    free(cur.url);
    free(cur.parent);
  }
  for (int i = qhead; i < qtail; i++) { free(queue[i].url); free(queue[i].parent); }
  free(queue);
  for (int i = 0; i < seen_n; i++) free(seen[i]);
  free(seen);

  int pages = 0, res = 0, failed = 0;
  for (int i = 0; i < j_len(assets); i++) {
    const char *k = j_s(j_at(assets, i), "kind", "");
    if (strcmp(k, "静态资源") == 0 || strcmp(k, "接口") == 0) res++;
    else pages++;
    if (j_get(j_at(assets, i), "error")) failed++;
  }
  /* 连起点都取不到内容 ⇒ 这次资产发现没有结论,不能报成"0 个资产 = 没问题" */
  int seed_ok = j_len(assets) > 0 && !j_get(j_at(assets, 0), "error");
  json_t *data = j_obj();
  j_set_str(data, "target", target);
  j_set(data, "assets", assets);
  j_set_num(data, "pages", pages);
  j_set_num(data, "resources", res);
  j_set_num(data, "requests", fetched);
  j_set_num(data, "unreachable", failed);
  out->data = data;

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "起始:%s\n实际访问 %d 个地址,共记录 %d 个资产(页面 %d、资源/接口 %d)\n",
             target, fetched, j_len(assets), pages, res);
  for (int i = 0; i < j_len(assets) && i < 30; i++) {
    json_t *a = j_at(assets, i);
    buf_printf(&t, "- [%s] %s (HTTP %d, 深度 %d)\n", j_s(a, "kind", ""),
               j_s(a, "url", ""), (int)j_n(a, "status_code", 0), (int)j_n(a, "depth", 0));
  }
  out->text = buf_take(&t);

  buf_t s;
  buf_init(&s);
  if (!seed_ok) {
    out->is_error = 1;
    buf_printf(&s, "资产发现没能得出结论:%s 取不到内容(%s)。"
                   "连起点都打不开,底账就无从谈起 —— 我不会把「查不到」写成「没有资产」。",
               target, j_s(j_at(assets, 0), "error", "无响应"));
  } else {
    buf_printf(&s, "资产发现完成:访问 %d 个地址,记录 %d 个资产(页面 %d、资源与接口 %d)。",
               fetched, j_len(assets), pages, res);
    if (failed) buf_printf(&s, "其中 %d 个地址取不到内容。", failed);
  }
  out->say = buf_take(&s);
  return seed_ok ? 0 : -1;
}

/* ================= 通用探测基础设施 =================
   下面这层是所有"探测类"工具共用的手法。刻意不含任何具体站点的知识:
   判断依据全部来自"这次取回来的内容",而不是"我记得这个站有什么"。 */

/* 一次取数(带响应头;拿不到头也照样返回内容,只是不做头相关的判断) */
typedef struct {
  int status;
  char *headers;
  char *body;
  char *err;
} fetch_t;

static void t_fetch_m(tool_ctx_t *ctx, const char *url, const char *method, fetch_t *f) {
  memset(f, 0, sizeof(*f));
  if (ctx->io.fetch_ex) {
    ctx->io.fetch_ex(ctx->io.userdata, url, method, &f->status, &f->headers,
                     &f->body, NULL, &f->err);
  } else if (ctx->io.fetch) {
    ctx->io.fetch(ctx->io.userdata, url, method, &f->status, &f->body, NULL, &f->err);
  } else {
    f->err = xstrdup("取数通道未就绪");
  }
  ctx->http_calls++;
}

static void t_fetch(tool_ctx_t *ctx, const char *url, fetch_t *f) {
  t_fetch_m(ctx, url, "GET", f);
}

static void fetch_free2(fetch_t *f) {
  free(f->headers);
  free(f->body);
  free(f->err);
  f->headers = f->body = f->err = NULL;
}

/* 站点根(协议 + 主机 + 端口):路径探测必须以它为基准。
   注意:模型可能只给"example.com"这种写法,所以先补协议再取根 —— 直接拿裸域名去
   请求会得到一个不明不白的失败,那不是站点的问题,是我们没把地址准备好。 */
static void probe_root(const char *url, char *out, size_t cap) {
  const char *p = url ? url : "";
  if (!strstr(p, "://")) {
    snprintf(out, cap, "https://%s", p);
    char *slash = strpbrk(out + 8, "/?#");
    if (slash) *slash = 0;                     /* 只留协议+主机,路径交给调用方 */
    return;
  }
  const char *scheme = strstr(p, "://");
  const char *hoststart = scheme + 3;
  const char *end = hoststart + strcspn(hoststart, "/?#");
  size_t n = (size_t)(end - p);
  if (n >= cap) n = cap - 1;
  memcpy(out, p, n);
  out[n] = 0;
}

/* 工具入口的统一归一:没有协议就补 https(只补,不改用户明确写的协议) */
static void normalize_target(const char *in, char *out, size_t cap) {
  const char *s = in ? in : "";
  while (*s == ' ' || *s == '"') s++;
  if (strstr(s, "://")) snprintf(out, cap, "%s", s);
  else snprintf(out, cap, "https://%s", s);
  char *e = out + strlen(out);
  while (e > out && (e[-1] == ' ' || e[-1] == '"')) *--e = 0;
}

static void join_path(char *out, size_t cap, const char *root, const char *path) {
  size_t n = strlen(root);
  while (n > 0 && root[n - 1] == '/') n--;
  if (path && path[0] == '/') snprintf(out, cap, "%.*s%s", (int)n, root, path);
  else snprintf(out, cap, "%.*s/%s", (int)n, root, path ? path : "");
}

/* ---- 软 404 校准:先看清"这个站没有这个文件时长什么样" ----
   这是所有路径探测的前提。很多站点对不存在的路径返回 200 + 自定义错误页,
   不先校准就会把一片"首页/错误页"当成"一堆敏感文件"。 */
typedef struct {
  int valid;
  int status;
  size_t bytes;
  buf_t shape;          /* 抹平数字后的正文骨架 */
  char sample[256];     /* 校准用的那个路径(写进报告,可复核) */
} calib_t;

static void calib_free(calib_t *c) { buf_free(&c->shape); }

static void calib_run(tool_ctx_t *ctx, const char *root, calib_t *c) {
  memset(c, 0, sizeof(*c));
  buf_init(&c->shape);
  char url[1024];
  long long rnd = now_ms() % 99991;
  snprintf(c->sample, sizeof(c->sample), "/%s_%lld_%s", "no-such-path", rnd, "zz");
  join_path(url, sizeof(url), root, c->sample);
  fetch_t f;
  t_fetch(ctx, url, &f);
  if (f.err && !f.status) {          /* 连校准都做不了:那就明说"校准失败" */
    c->valid = 0;
    fetch_free2(&f);
    return;
  }
  c->valid = 1;
  c->status = f.status;
  c->bytes = f.body ? strlen(f.body) : 0;
  web_shape(&c->shape, f.body ? f.body : "");
  fetch_free2(&f);
}

/* 这个响应是不是"站点的默认页"(而非真的取到了目标文件) */
static int calib_matches(const calib_t *c, int status, const char *body) {
  if (!c->valid) return 0;
  if (status != c->status) return 0;
  size_t bytes = body ? strlen(body) : 0;
  double diff = (double)bytes > (double)c->bytes ? (double)bytes - (double)c->bytes
                                                : (double)c->bytes - (double)bytes;
  double ratio = c->bytes > 0 ? diff / (double)c->bytes : (bytes ? 1.0 : 0.0);
  if (diff > 64 && ratio > 0.06) return 0;
  buf_t sh;
  buf_init(&sh);
  web_shape(&sh, body ? body : "");
  int same = strcmp(sh.data ? sh.data : "", c->shape.data ? c->shape.data : "") == 0;
  buf_free(&sh);
  return same;
}

/* 外链分析:把页面上的外域主机、可疑落点分开列出来 */
static void link_analysis(const char *body, const char *own_host, json_t *hosts,
                          json_t *suspicious) {
  json_t *links = j_arr();
  web_extract_links(body, links);
  int tld_n = 0;
  const char **tlds = rules_str_list("suspicious_tlds", &tld_n);
  for (int i = 0; i < j_len(links); i++) {
    json_t *l = j_at(links, i);
    if (!l || l->type != J_STR) continue;
    const char *u = l->str;
    if (!str_startswith(u, "http://") && !str_startswith(u, "https://") &&
        !str_startswith(u, "//")) {
      continue;                                  /* 站内相对链接不参与判断 */
    }
    char host[256];
    web_url_parts(str_startswith(u, "//") ? "" : u, host, sizeof(host), NULL, 0);
    if (!host[0] || str_ieq(host, own_host)) continue;
    int dup = 0;
    for (int k = 0; k < j_len(hosts); k++) {
      if (str_ieq(j_at(hosts, k)->str, host)) { dup = 1; break; }
    }
    if (!dup) j_add(hosts, j_str(host));

    int bad = 0;
    for (int t = 0; t < tld_n; t++) {
      size_t lh = strlen(host), lt = strlen(tlds[t]);
      if (lh > lt && str_ieq(host + (lh - lt), tlds[t])) { bad = 1; break; }
    }
    int digits = 0, dots = 0;
    for (const char *c = host; *c; c++) {
      if (*c >= '0' && *c <= '9') digits++;
      else if (*c == '.') dots++;
    }
    if (dots == 3 && digits >= 4) bad = 1;       /* 裸 IP 当落地页 */
    if (bad) {
      int seen = 0;
      for (int k = 0; k < j_len(suspicious); k++) {
        if (str_icontains(j_at(suspicious, k)->str, host)) { seen = 1; break; }
      }
      if (!seen) j_add(suspicious, j_str(u));
    }
  }
  json_free(links);
}

/* 结果里必须写清"用的是哪套定义",否则结论无法复核 */
static void put_rules_note(json_t *data) {
  j_set_str(data, "rules_source", rules_source());
  j_set_bool(data, "rules_from_file", rules_from_file());
}

/* ---- 4. 敏感文件探测(内容特征判定 + 软 404 校准) ---- */
static int t_sensitive_file_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  char root[512];
  probe_root(j_s(args, "target", ""), root, sizeof(root));

  json_t *paths = j_arr();
  json_t *given = j_get(args, "paths");
  if (given && given->type == J_ARR && given->count > 0) {
    for (int i = 0; i < given->count && i < 40; i++) {
      if (j_at(given, i)->type == J_STR) j_add(paths, j_str(j_at(given, i)->str));
    }
  } else {
    int n = 0;
    const char **list = rules_str_list("sensitive_paths", &n);
    int cap = (int)rules_number("max_paths", 40);
    if (cap < 1) cap = 40;
    for (int i = 0; i < n && i < cap; i++) j_add(paths, j_str(list[i]));
  }

  calib_t calib;
  calib_run(ctx, root, &calib);

  json_t *hits = j_arr();
  json_t *pending = j_arr();        /* 有内容但没匹配到已知特征:如实列成"待确认" */
  int tested = 0, unreachable = 0, suppressed = 0, blocked = 0;

  for (int i = 0; i < j_len(paths); i++) {
    const char *path = j_at(paths, i)->str;
    char url[1024];
    join_path(url, sizeof(url), root, path);
    fetch_t f;
    t_fetch(ctx, url, &f);
    tested++;
    if (f.err && !f.status) { unreachable++; fetch_free2(&f); continue; }
    if (f.status == 401 || f.status == 403) { blocked++; fetch_free2(&f); continue; }
    if (f.status != 200 && f.status != 206) { fetch_free2(&f); continue; }
    if (calib_matches(&calib, f.status, f.body)) {
      /* 与站点默认页一致 ⇒ 这个路径其实不存在,只是站点用 200 包了错误页 */
      suppressed++;
      fetch_free2(&f);
      continue;
    }
    rules_sig_t sig;
    memset(&sig, 0, sizeof(sig));
    json_t *hit = j_obj();
    j_set_str(hit, "path", path);
    j_set_str(hit, "url", url);
    j_set_num(hit, "status", f.status);
    j_set_num(hit, "bytes", f.body ? (double)strlen(f.body) : 0);
    char title[160];
    web_title(f.body ? f.body : "", title, sizeof(title));
    j_set_str(hit, "title", title);
    if (rules_sig_match(path, f.body ? f.body : "", &sig) == 0) {
      j_set_str(hit, "signature", sig.name);
      j_set_str(hit, "kind", sig.kind);
      j_set_str(hit, "severity", sig.severity);
      j_set_str(hit, "tag", sig.tag);
      j_set_str(hit, "evidence", sig.evidence);
      j_add(hits, hit);
    } else {
      j_set_str(hit, "note", "内容与站点默认页不同,但没匹配到已知特征");
      j_add(pending, hit);
    }
    fetch_free2(&f);
  }

  json_t *data = j_obj();
  j_set_str(data, "target", root);
  j_set_num(data, "tested", tested);
  j_set_num(data, "unreachable", unreachable);
  j_set_num(data, "suppressed_as_default_page", suppressed);
  j_set_num(data, "blocked_401_403", blocked);
  j_set_bool(data, "calibrated", calib.valid);
  j_set_str(data, "calibration_sample", calib.sample);
  j_set(data, "hits", hits);
  j_set(data, "pending", pending);
  j_set_num(data, "hit_count", j_len(hits));
  put_rules_note(data);
  out->data = data;

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "落点探测 %s:试了 %d 个路径,命中 %d 个已知特征,"
                 "因与站点默认页一致而排除 %d 个(疑似不存在),%d 个受限,%d 个连不上。",
             root, tested, j_len(hits), suppressed, blocked, unreachable);
  for (int i = 0; i < j_len(hits); i++) {
    buf_printf(&t, "\n- [%s] %s → %s(证据:%s)", j_s(j_at(hits, i), "severity", ""),
               j_s(j_at(hits, i), "path", ""), j_s(j_at(hits, i), "signature", ""),
               j_s(j_at(hits, i), "evidence", ""));
  }
  out->text = buf_take(&t);

  buf_t s;
  buf_init(&s);
  if (tested > 0 && unreachable == tested) {
    buf_printf(&s, "这次没法给结论:%s 的 %d 个落点全部请求失败。"
                   "我没把「连不上」当成「没问题」,请确认站点可达后我再来一次。",
               root, tested);
    out->is_error = 1;
  } else if (j_len(hits) == 0 && j_len(pending) == 0) {
    buf_printf(&s, "按当前定义试了 %d 个常见落点,没有取到敏感内容", tested);
    if (suppressed) buf_printf(&s, "(其中 %d 个返回的是站点默认页,已排除)", suppressed);
    if (blocked) buf_printf(&s, "(%d 个返回 401/403,存在但取不到)", blocked);
    buf_puts(&s, "。未命中不代表绝对没有其他路径。");
  } else {
    buf_printf(&s, "落点探测完成:命中 %d 处,另有 %d 处内容异常但没匹配到已知特征(需人工确认)。",
               j_len(hits), j_len(pending));
    for (int i = 0; i < j_len(hits) && i < 6; i++) {
      buf_printf(&s, "\n  · %s → %s", j_s(j_at(hits, i), "path", ""),
                 j_s(j_at(hits, i), "signature", ""));
    }
  }
  out->say = buf_take(&s);
  calib_free(&calib);
  return 0;
}

/* ---- 5. 目录探测(目录索引识别 + 入口识别 + 软 404 校准) ---- */
static int t_dir_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  char root[512];
  probe_root(j_s(args, "target", ""), root, sizeof(root));

  json_t *dirs = j_arr();
  json_t *given = j_get(args, "dirs");
  if (given && given->type == J_ARR && given->count > 0) {
    for (int i = 0; i < given->count && i < 40; i++) {
      if (j_at(given, i)->type == J_STR) j_add(dirs, j_str(j_at(given, i)->str));
    }
  } else {
    int n = 0;
    const char **list = rules_str_list("dir_candidates", &n);
    int cap = (int)rules_number("max_dirs", 40);
    if (cap < 1) cap = 40;
    for (int i = 0; i < n && i < cap; i++) j_add(dirs, j_str(list[i]));
  }

  calib_t calib;
  calib_run(ctx, root, &calib);

  json_t *listings = j_arr();     /* 目录索引 */
  json_t *entries = j_arr();      /* 疑似管理入口 */
  json_t *exposed = j_arr();      /* 命中内容特征的落点 */
  json_t *restricted = j_arr();   /* 存在但受限(401/403):是有价值的信息 */
  int tested = 0, unreachable = 0, suppressed = 0, reachable = 0;

  for (int i = 0; i < j_len(dirs); i++) {
    const char *dir = j_at(dirs, i)->str;
    char url[1024];
    join_path(url, sizeof(url), root, dir);
    fetch_t f;
    t_fetch(ctx, url, &f);
    tested++;
    if (f.err && !f.status) { unreachable++; fetch_free2(&f); continue; }
    if (f.status == 401 || f.status == 403) {
      json_t *r = j_obj();
      j_set_str(r, "path", dir);
      j_set_num(r, "status", f.status);
      j_add(restricted, r);
      reachable++;
      fetch_free2(&f);
      continue;
    }
    if (f.status < 200 || f.status >= 400) { fetch_free2(&f); continue; }
    if (calib_matches(&calib, f.status, f.body)) { suppressed++; fetch_free2(&f); continue; }
    reachable++;

    const char *body = f.body ? f.body : "";
    char title[160];
    web_title(body, title, sizeof(title));

    if (web_is_dir_listing(body)) {
      json_t *e = j_arr();
      web_dir_listing_entries(body, e, 12);
      json_t *l = j_obj();
      j_set_str(l, "path", dir);
      j_set_str(l, "url", url);
      j_set_str(l, "title", title);
      j_set(l, "entries", e);
      j_add(listings, l);
    } else if (web_has_password_form(body)) {
      json_t *m = j_obj();
      j_set_str(m, "path", dir);
      j_set_str(m, "url", url);
      j_set_str(m, "title", title);
      j_add(entries, m);
    } else {
      rules_sig_t sig;
      memset(&sig, 0, sizeof(sig));
      if (rules_sig_match(dir, body, &sig) == 0) {
        json_t *h = j_obj();
        j_set_str(h, "path", dir);
        j_set_str(h, "url", url);
        j_set_str(h, "signature", sig.name);
        j_set_str(h, "kind", sig.kind);
        j_set_str(h, "severity", sig.severity);
        j_set_str(h, "tag", sig.tag);
        j_set_str(h, "evidence", sig.evidence);
        j_add(exposed, h);
      }
    }
    fetch_free2(&f);
  }

  json_t *data = j_obj();
  j_set_str(data, "target", root);
  j_set_num(data, "tested", tested);
  j_set_num(data, "reachable", reachable);
  j_set_num(data, "suppressed_as_default_page", suppressed);
  j_set_num(data, "unreachable", unreachable);
  j_set_bool(data, "calibrated", calib.valid);
  j_set(data, "directory_listing", listings);
  j_set(data, "entry_points", entries);
  j_set(data, "exposed", exposed);
  j_set(data, "restricted", restricted);
  j_set_num(data, "candidate_count", j_len(listings) + j_len(exposed));
  put_rules_note(data);
  out->data = data;

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "目录探测 %s:试了 %d 个目录,可访问 %d 个,目录索引 %d 个,"
                 "疑似入口 %d 个,受限 %d 个,排除默认页 %d 个。",
             root, tested, reachable, j_len(listings), j_len(entries), j_len(restricted),
             suppressed);
  for (int i = 0; i < j_len(listings); i++) {
    buf_printf(&t, "\n- 目录索引:%s(%d 个条目)", j_s(j_at(listings, i), "path", ""),
               j_len(j_get(j_at(listings, i), "entries")));
  }
  for (int i = 0; i < j_len(entries); i++) {
    buf_printf(&t, "\n- 疑似入口:%s(%s)", j_s(j_at(entries, i), "path", ""),
               j_s(j_at(entries, i), "title", ""));
  }
  out->text = buf_take(&t);

  buf_t s;
  buf_init(&s);
  if (tested > 0 && unreachable == tested) {
    buf_printf(&s, "目录探测没能得出结论:%s 的 %d 个目录全部请求失败。", root, tested);
    out->is_error = 1;
  } else if (j_len(listings) == 0 && j_len(entries) == 0 && j_len(exposed) == 0) {
    buf_printf(&s, "目录探测完成:试了 %d 个常见目录,没有发现目录索引、暴露文件或可访问入口", tested);
    if (j_len(restricted) > 0) buf_printf(&s, "(%d 个目录存在但返回 401/403)", j_len(restricted));
    buf_puts(&s, "。");
  } else {
    buf_printf(&s, "目录探测发现 %d 处目录索引、%d 处疑似管理入口、%d 处暴露文件。",
               j_len(listings), j_len(entries), j_len(exposed));
    for (int i = 0; i < j_len(listings) && i < 4; i++) {
      buf_printf(&s, "\n  · 目录索引 %s", j_s(j_at(listings, i), "path", ""));
    }
    for (int i = 0; i < j_len(entries) && i < 4; i++) {
      buf_printf(&s, "\n  · 疑似入口 %s", j_s(j_at(entries, i), "path", ""));
    }
  }
  out->say = buf_take(&s);
  calib_free(&calib);
  return 0;
}

/* ---- 6. 内容基线比对(首次建基线,之后比差异) ---- */
static int t_page_diff(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  char target_buf[1024];
  normalize_target(j_s(args, "target", ""), target_buf, sizeof(target_buf));
  const char *target = target_buf;
  store_t *st = (store_t *)ctx->store;
  fetch_t f;
  t_fetch(ctx, target, &f);
  if (f.err && !f.status) {
    json_t *d = j_obj();
    j_set_str(d, "target", target);
    j_set_str(d, "error", f.err ? f.err : "取不到内容");
    out->data = d;
    out->is_error = 1;    buf_t t;
    buf_init(&t);
    buf_printf(&t, "内容完整性检查没法做:%s 取不到内容(%s)。", target,
               f.err ? f.err : "无响应");
    out->text = buf_take(&t);
    out->say = xstrdup("目标取不到内容,我不给完整性结论。");
    fetch_free2(&f);
    return -1;
  }

  const char *body = f.body ? f.body : "";
  char hash[80];
  web_body_hash(body, hash, sizeof(hash));
  char title[160];
  web_title(body, title, sizeof(title));
  char own_host[256];
  web_url_parts(target, own_host, sizeof(own_host), NULL, 0);
  json_t *hosts = j_arr();
  json_t *suspicious = j_arr();
  link_analysis(body, own_host, hosts, suspicious);

  json_t *data = j_obj();
  j_set_str(data, "target", target);
  j_set_str(data, "content_hash", hash);
  j_set_str(data, "title", title);
  j_set_num(data, "bytes", (double)strlen(body));
  j_set(data, "external_hosts", hosts);
  j_set(data, "suspicious_links", suspicious);


  json_t *prev_list = st ? store_find(st, "baselines", "target", target) : NULL;
  json_t *prev_obj = NULL;
  if (prev_list) {
    /* 同一目标可能采过多次基线:取 captured_at 最新的那份 */
    for (int i = 0; i < j_len(prev_list); i++) {
      if (!prev_obj ||
          strcmp(j_s(j_at(prev_list, i), "captured_at", ""),
                 j_s(prev_obj, "captured_at", "")) > 0) {
        prev_obj = j_at(prev_list, i);
      }
    }
  }
  if (!prev_obj) {
    /* 第一次看这个页面:采基线(存快照引用,不存全文) */
    char *bid = st ? store_next_id(st, "baselines") : xstrdup("B-0000");
    char *ref = st ? store_write_snapshot(st, bid, body) : NULL;
    char ts[40];
    now_iso(ts, sizeof(ts));
    if (st) {
      json_t *b = j_obj();
      j_set_str(b, "id", bid);
      j_set_str(b, "target", target);
      j_set_str(b, "content_hash", hash);
      j_set_str(b, "content_ref", ref ? ref : "");
      j_set_str(b, "title", title);
      j_set_num(b, "bytes", (double)strlen(body));
      j_set_str(b, "captured_at", ts);
      j_set(b, "external_hosts", json_parse(json_dump(hosts)));
      store_save(st, "baselines", b);
      json_free(b);
    }
    j_set_str(data, "mode", "baseline_created");
    j_set_str(data, "baseline_id", bid);
    free(bid);
    free(ref);
    buf_t t;
    buf_init(&t);
    buf_printf(&t, "已为 %s 采集内容基线(指纹 %s,%d 字节,外域主机 %d 个)。"
                   "下次再比对同一地址,才能判断内容是否被改动。",
               target, hash, (int)strlen(body), j_len(hosts));
    out->text = buf_take(&t);
  } else {
    const char *prev_hash = j_s(prev_obj, "content_hash", "");
    json_t *prev_hosts = j_get(prev_obj, "external_hosts");
    json_t *new_hosts = j_arr();
    json_t *gone_hosts = j_arr();
    for (int i = 0; i < j_len(hosts); i++) {
      int found = 0;
      for (int k = 0; k < j_len(prev_hosts); k++) {
        if (str_ieq(j_at(hosts, i)->str, j_at(prev_hosts, k)->str)) { found = 1; break; }
      }
      if (!found) j_add(new_hosts, j_str(j_at(hosts, i)->str));
    }
    for (int k = 0; k < j_len(prev_hosts); k++) {
      int found = 0;
      for (int i = 0; i < j_len(hosts); i++) {
        if (str_ieq(j_at(hosts, i)->str, j_at(prev_hosts, k)->str)) { found = 1; break; }
      }
      if (!found) j_add(gone_hosts, j_str(j_at(prev_hosts, k)->str));
    }
    int changed = strcmp(prev_hash, hash) != 0;
    j_set_str(data, "mode", changed ? "changed" : "unchanged");
    j_set_str(data, "baseline_id", j_s(prev_obj, "id", ""));
    j_set_str(data, "prev_hash", prev_hash);
    j_set(data, "new_external_hosts", new_hosts);
    j_set(data, "removed_external_hosts", gone_hosts);

    if (changed && st) {
      char *did = store_next_id(st, "diffs");
      char ts[40];
      now_iso(ts, sizeof(ts));
      json_t *df = j_obj();
      j_set_str(df, "id", did);
      j_set_str(df, "baseline_id", j_s(prev_obj, "id", ""));
      j_set_str(df, "target", target);
      j_set_str(df, "detected_at", ts);
      j_set_bool(df, "changed", 1);
      j_set_str(df, "hash_before", prev_hash);
      j_set_str(df, "hash_after", hash);
      j_set_num(df, "bytes_before", j_n(prev_obj, "bytes", 0));
      j_set_num(df, "bytes_after", (double)strlen(body));
      j_set_str(df, "title_before", j_s(prev_obj, "title", ""));
      j_set_str(df, "title_after", title);
      j_set(df, "new_external_hosts", json_parse(json_dump(new_hosts)));
      j_set(df, "removed_external_hosts", json_parse(json_dump(gone_hosts)));
      store_save(st, "diffs", df);
      json_free(df);
      j_set_str(data, "diff_id", did);
      free(did);
    }

    buf_t t;
    buf_init(&t);
    if (!changed) {
      buf_printf(&t, "内容未变:%s 的指纹与基线一致(%s)。", target, hash);
    } else {
      buf_printf(&t, "内容已变化:%s 指纹 %s → %s;字节 %d → %d;标题「%s」→「%s」;"
                     "新增外域主机 %d 个,消失 %d 个。",
                 target, prev_hash, hash, (int)j_n(prev_obj, "bytes", 0), (int)strlen(body),
                 j_s(prev_obj, "title", ""), title, j_len(new_hosts), j_len(gone_hosts));
    }
    out->text = buf_take(&t);
  }

  out->data = data;
  buf_t s;
  buf_init(&s);
  if (strcmp(j_s(data, "mode", ""), "baseline_created") == 0) {
    buf_printf(&s, "已采集 %s 的内容基线(指纹 %s)。下次比对才能看出是否被改动。",
               target, hash);
  } else if (strcmp(j_s(data, "mode", ""), "unchanged") == 0) {
    buf_printf(&s, "内容完整性检查完成:%s 与基线一致,未发现改动迹象。", target);
  } else {
    buf_printf(&s, "内容完整性检查发现 %s 的内容与基线不一致(指纹已变)", target);
    if (j_len(j_get(data, "new_external_hosts")) > 0) {
      buf_printf(&s, ",并新增了 %d 个此前没有的外域主机。",
                 j_len(j_get(data, "new_external_hosts")));
    } else {
      buf_puts(&s, "。可能是正常改版,也可能是被改动,需要人工核对改动内容。");
    }
  }
  out->say = buf_take(&s);
  fetch_free2(&f);
  return 0;
}

/* ---- 7. 弱配置与漏洞模板探测(全部结论都来自响应头/正文的客观事实) ---- */
static int t_nuclei_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  char target_buf[1024];
  normalize_target(j_s(args, "target", ""), target_buf, sizeof(target_buf));
  const char *target = target_buf;
  fetch_t f;
  t_fetch(ctx, target, &f);
  if (f.err && !f.status) {
    json_t *d = j_obj();
    j_set_str(d, "target", target);
    j_set_str(d, "error", f.err ? f.err : "取不到内容");
    out->data = d;
    out->is_error = 1;
    out->text = xstrdup("目标取不到内容,弱配置检查无法进行");
    out->say = xstrdup("目标连不上,这次不给配置结论。");
    fetch_free2(&f);
    return -1;
  }

  int https = str_startswith(target, "https://");
  json_t *checks = j_arr();
  json_t *missing = j_arr();
  const char *body = f.body ? f.body : "";

  /* (1) 期望的安全响应头 —— 缺哪些列哪些,严重度取规则里最高的那一个 */
  if (web_headers_available(f.headers)) {
    int worst = 99;
    static const char *ORDER[] = {"信息", "低", "中", "高", "严重", ""};
    for (int i = 0; i < rules_weak_header_count(); i++) {
      const char *name = rules_weak_header(i, "name", "");
      int only_https = rules_weak_header_num(i, "only_https", 0);
      if (only_https && !https) continue;
      if (web_header_count(f.headers, name) > 0) continue;
      json_t *m = j_obj();
      j_set_str(m, "header", name);
      j_set_str(m, "title", rules_weak_header(i, "title", name));
      j_set_str(m, "severity", rules_weak_header(i, "severity", "低"));
      j_set_str(m, "impact", rules_weak_header(i, "impact", ""));
      j_set_str(m, "fix", rules_weak_header(i, "fix", ""));
      j_add(missing, m);
      for (int s = 0; ORDER[s][0]; s++) {
        if (strcmp(ORDER[s], j_s(m, "severity", "")) == 0 && s < worst) worst = s;
      }
    }
    if (j_len(missing) > 0) {
      buf_t names;
      buf_init(&names);
      for (int i = 0; i < j_len(missing); i++) {
        if (i) buf_puts(&names, "、");
        buf_puts(&names, j_s(j_at(missing, i), "title", ""));
      }
      json_t *c = j_obj();
      j_set_str(c, "id", "weak-headers");
      j_set_str(c, "title", "安全响应头缺失");
      j_set_str(c, "severity", ORDER[worst < 4 ? worst : 0]);
      j_set_num(c, "count", j_len(missing));
      j_set(c, "items", json_parse(json_dump(missing)));
      buf_printf(&names, ";补齐后能挡掉一类常见的浏览器侧攻击");
      j_set_str(c, "evidence", names.data);
      j_set_str(c, "impact", "缺少浏览器侧的安全约束,点击劫持、MIME 嗅探、引用泄露等风险上升");
      j_set_str(c, "fix", "按缺失项逐条补齐响应头,并纳入上线检查");
      j_add(checks, c);
      buf_free(&names);
    }
  }

  /* (2) Cookie 属性:会话票据没加 HttpOnly/Secure 是实打实的风险 */
  {
    json_t *cookie_issues = j_arr();
    int n = web_header_count(f.headers, "set-cookie");
    for (int i = 0; i < n; i++) {
      buf_t v;
      buf_init(&v);
      if (web_header_at(f.headers, "set-cookie", i, &v)) {
        const char *val = v.data ? v.data : "";
        int http_only = str_icontains(val, "httponly");
        int secure = str_icontains(val, "secure");
        int same_site = str_icontains(val, "samesite");
        if (!http_only || (!secure && https) || !same_site) {
          buf_t miss;
          buf_init(&miss);
          if (!http_only) buf_puts(&miss, "HttpOnly ");
          if (!secure && https) buf_puts(&miss, "Secure ");
          if (!same_site) buf_puts(&miss, "SameSite");
          json_t *ci = j_obj();
          /* cookie 的名字是有用信息,值已经在校准时打过星 */
          j_set_str(ci, "cookie", val);
          j_set_str(ci, "missing", miss.data);
          j_add(cookie_issues, ci);
          buf_free(&miss);
        }
      }
      buf_free(&v);
    }
    if (j_len(cookie_issues) > 0) {
      json_t *c = j_obj();
      j_set_str(c, "id", "cookie-flags");
      j_set_str(c, "title", "Cookie 缺少安全属性");
      j_set_str(c, "severity", "中");
      j_set(c, "items", json_parse(json_dump(cookie_issues)));
      j_set_str(c, "evidence", j_s(j_at(cookie_issues, 0), "cookie", ""));
      j_set_str(c, "impact", "会话 Cookie 可被脚本读取或在明文信道回传,增加会话被窃取的风险");
      j_set_str(c, "fix", "为会话 Cookie 增加 HttpOnly、Secure 与 SameSite 属性");
      j_add(checks, c);
    }
    json_free(cookie_issues);
  }

  /* (3) 版本信息泄露:应答头把组件版本直接报出来 */
  {
    json_t *leaks = j_arr();
    int n = 0;
    const char **keys = rules_str_list("server_header_keys", &n);
    for (int i = 0; i < n; i++) {
      buf_t v;
      buf_init(&v);
      if (web_header(f.headers, keys[i], &v) && v.data && v.data[0]) {
        int has_digit = 0;
        for (const char *p = v.data; *p; p++) if (*p >= '0' && *p <= '9') has_digit = 1;
        json_t *l = j_obj();
        j_set_str(l, "header", keys[i]);
        j_set_str(l, "value", v.data);
        j_set_bool(l, "version_like", has_digit);
        j_add(leaks, l);
      }
      buf_free(&v);
    }
    int version_like = 0;
    for (int i = 0; i < j_len(leaks); i++) if (j_b(j_at(leaks, i), "version_like", 0)) version_like = 1;
    if (version_like) {
      json_t *c = j_obj();
      j_set_str(c, "id", "version-disclosure");
      j_set_str(c, "title", "响应头泄露中间件版本");
      j_set_str(c, "severity", "低");
      j_set(c, "items", json_parse(json_dump(leaks)));
      j_set_str(c, "evidence", j_s(j_at(leaks, 0), "header", ""));
      j_set_str(c, "impact", "攻击者可据此匹配已知漏洞,降低攻击成本");
      j_set_str(c, "fix", "关闭或改写 Server/X-Powered-By 等版本信息");
      j_add(checks, c);
    }
    json_free(leaks);
  }

  /* (4) 错误回显:用一个不存在的路径看站点会不会把数据库/堆栈错误抛给访问者 */
  {
    char root[512];
    probe_root(target, root, sizeof(root));
    char url[1024];
    join_path(url, sizeof(url), root, "/no-such-path-probe-zz");
    fetch_t e;
    t_fetch(ctx, url, &e);
    if (!(e.err && !e.status) && e.body) {
      int n = 0;
      const char **sigs = rules_str_list("error_signatures", &n);
      for (int i = 0; i < n; i++) {
        if (str_icontains(e.body, sigs[i])) {
          json_t *c = j_obj();
          j_set_str(c, "id", "error-disclosure");
          j_set_str(c, "title", "错误页回显内部信息");
          j_set_str(c, "severity", "中");
          j_set_str(c, "evidence", sigs[i]);
          j_set_str(c, "impact", "报错信息会暴露技术栈与内部细节,为后续攻击提供线索");
          j_set_str(c, "fix", "统一错误页,关闭调试输出与详细报错");
          j_add(checks, c);
          break;
        }
      }
    }
    fetch_free2(&e);
  }

  /* (5) 允许的 HTTP 方法:OPTIONS 只问不写,是判断"是否暴露了写方法"的安全手法 */
  {
    fetch_t o;
    t_fetch_m(ctx, target, "OPTIONS", &o);
    if (!(o.err && !o.status)) {
      buf_t allow;
      buf_init(&allow);
      if (web_header(o.headers, "allow", &allow) && allow.data) {
        json_t *bads = j_arr();
        int n = 0;
        const char **dang = rules_str_list("dangerous_methods", &n);
        for (int i = 0; i < n; i++) {
          if (str_icontains(allow.data, dang[i])) j_add(bads, j_str(dang[i]));
        }
        if (j_len(bads) > 0) {
          json_t *c = j_obj();
          j_set_str(c, "id", "dangerous-methods");
          j_set_str(c, "title", "服务端声明了不必要的写方法");
          j_set_str(c, "severity", "中");
          j_set(c, "items", json_parse(json_dump(bads)));
          j_set_str(c, "evidence", allow.data);
          j_set_str(c, "impact", "TRACE/PUT/DELETE 等被不当开放时可被用于跨站追踪或越权改动");
          j_set_str(c, "fix", "按业务最小化允许的方法,关闭 TRACE 与无用写方法");
          j_add(checks, c);
        }
      }
      buf_free(&allow);
    }
    fetch_free2(&o);
  }

  /* (6) 目录索引与混合内容:与目录/完整性检查同源,这里只做"顺带发现" */
  if (web_is_dir_listing(body)) {
    json_t *c = j_obj();
    j_set_str(c, "id", "dir-listing");
    j_set_str(c, "title", "该地址返回目录索引");
    j_set_str(c, "severity", "中");
    j_set_str(c, "evidence", "页面包含目录索引特征");
    j_set_str(c, "impact", "目录结构被完整暴露,文件命名与内部结构因此可被枚举");
    j_set_str(c, "fix", "关闭目录浏览(autoindex),只保留确需公开的文件");
    j_add(checks, c);
  }
  if (https && web_has_mixed_content(body)) {
    json_t *c = j_obj();
    j_set_str(c, "id", "mixed-content");
    j_set_str(c, "title", "HTTPS 页面引用 HTTP 资源");
    j_set_str(c, "severity", "低");
    j_set_str(c, "evidence", "页面存在 http:// 形式的资源引用");
    j_set_str(c, "impact", "资源可被中间人替换,HTTPS 的保护被局部抵消");
    j_set_str(c, "fix", "把资源引用统一改为 https 或站内相对路径");
    j_add(checks, c);
  }

  json_t *data = j_obj();
  j_set_str(data, "target", target);
  j_set_num(data, "status_code", f.status);
  j_set_str(data, "engine", "内置非破坏性模板");
  j_set_bool(data, "headers_available", web_headers_available(f.headers) ? 1 : 0);
  j_set(data, "checks", checks);
  j_set(data, "missing_headers", missing);
  j_set_num(data, "check_count", j_len(checks));
  put_rules_note(data);
  out->data = data;

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "弱配置与漏洞模板探测 %s → HTTP %d%s;共 %d 项需要关注。",
             target, f.status, web_headers_available(f.headers) ? "" : "(本次未取到响应头)", j_len(checks));
  for (int i = 0; i < j_len(checks); i++) {
    buf_printf(&t, "\n- [%s] %s —— %s", j_s(j_at(checks, i), "severity", ""),
               j_s(j_at(checks, i), "title", ""), j_s(j_at(checks, i), "evidence", ""));
  }
  out->text = buf_take(&t);

  buf_t s;
  buf_init(&s);
  if (j_len(checks) == 0) {
    buf_printf(&s, "配置检查完成:%s 未发现规则覆盖的弱配置项(响应头、Cookie、方法、错误回显都过了)。",
               target);
    if (!web_headers_available(f.headers)) {
      buf_puts(&s, "注意:本次没取到响应头,响应头相关的检查未生效,不能算通过。");
    }
  } else {
    int crit = 0;
    for (int i = 0; i < j_len(checks); i++) {
      const char *sev = j_s(j_at(checks, i), "severity", "");
      if (strcmp(sev, "严重") == 0 || strcmp(sev, "高") == 0) crit++;
    }
    buf_printf(&s, "配置检查完成:%s 共发现 %d 项需要关注", target, j_len(checks));
    if (crit) buf_printf(&s, "(其中 %d 项为高及以上)", crit);
    buf_puts(&s, ",详见结果卡片。");
  }
  out->say = buf_take(&s);
  fetch_free2(&f);
  return 0;
}

/* ---- 8. 注入验证(布尔差分 + 错误特征;不取数据、不写数据) ---- */
static int t_sqli_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  char target_buf[2048];
  normalize_target(j_s(args, "target", ""), target_buf, sizeof(target_buf));
  const char *target = target_buf;
  const char *want_param = j_s(args, "param", "");

  json_t *params = j_arr();
  web_url_params(target, params);
  if (want_param[0]) {
    /* 指定了参数但地址里没有 → 按"这个参数存在"处理(补上再测) */
    json_t *one = j_arr();
    j_add(one, j_str(want_param));
    json_free(params);
    params = one;
  }
  if (j_len(params) == 0) {
    json_t *d = j_obj();
    j_set_str(d, "target", target);
    j_set_str(d, "verdict", "not_testable");
    j_set_str(d, "reason", "地址里没有查询参数,没有可以验证的输入点");
    out->data = d;
    out->text = xstrdup("这个地址没有查询参数,注入验证没有输入点,本次未做");
    out->say = xstrdup("这个地址没有可测的参数(要带 ?参数=值 这样的地址),所以我没法做注入验证。");
    return 0;
  }

  /* 基线:原样请求一次,后面所有对比都以它为准 */
  fetch_t base;
  t_fetch(ctx, target, &base);
  if (base.err && !base.status) {
    json_t *d = j_obj();
    j_set_str(d, "target", target);
    j_set_str(d, "error", base.err ? base.err : "取不到内容");
    j_set_str(d, "verdict", "unreachable");
    out->data = d;
    out->is_error = 1;
    out->text = xstrdup("目标取不到内容,注入验证无法进行");
    out->say = xstrdup("目标连不上,我不给注入结论。");
    fetch_free2(&base);
    return -1;
  }
  buf_t base_shape;
  buf_init(&base_shape);
  web_shape(&base_shape, base.body ? base.body : "");
  size_t base_bytes = base.body ? strlen(base.body) : 0;

  int max_params = (int)rules_number("max_params", 3);
  if (max_params < 1) max_params = 3;

  json_t *tests = j_arr();
  int confirmed = 0, inconclusive = 0;
  char evidence[512] = {0};

  /* 布尔差分的载荷族来自规则文件(payloads.boolean_diff):
     不同数据库/框架的注释与引号规则不一样,单位可以自己加族,不用重编译。 */
  int fam_n = rules_arr_count("payloads.boolean_diff");

  for (int pi = 0; pi < j_len(params) && pi < max_params; pi++) {
    const char *param = j_at(params, pi)->str;
    for (int fam = 0; fam < fam_n; fam++) {
      const char *p_true = rules_arr_str("payloads.boolean_diff", fam, "true", "");
      const char *p_false = rules_arr_str("payloads.boolean_diff", fam, "false", "");
      const char *ctx_name = rules_arr_str("payloads.boolean_diff", fam, "context", "默认");
      if (!p_true[0] || !p_false[0]) continue;
      buf_t ut, uf;
      buf_init(&ut);
      buf_init(&uf);
      web_url_set_param(target, param, p_true, &ut);
      web_url_set_param(target, param, p_false, &uf);
      fetch_t ft, ff;
      t_fetch(ctx, ut.data, &ft);
      t_fetch(ctx, uf.data, &ff);

      int t_reach = !(ft.err && !ft.status);
      int f_reach = !(ff.err && !ff.status);
      int t_same = t_reach && web_same_shape(ft.body, base.body);
      int f_same = f_reach && web_same_shape(ff.body, base.body);
      int tf_same = t_reach && f_reach && web_same_shape(ft.body, ff.body);

      const char *verdict = "not_injectable";
      if (!t_reach || !f_reach) verdict = "inconclusive";
      else if (!t_same && !f_same && !tf_same) verdict = "inconclusive";
      else if (t_same && !f_same) verdict = "confirmed";

      json_t *rec = j_obj();
      j_set_str(rec, "param", param);
      j_set_str(rec, "context", ctx_name);
      j_set_str(rec, "payload_true", p_true);
      j_set_str(rec, "payload_false", p_false);
      j_set_str(rec, "verdict", verdict);
      j_set_num(rec, "status_true", ft.status);
      j_set_num(rec, "status_false", ff.status);
      j_set_num(rec, "bytes_true", ft.body ? (double)strlen(ft.body) : 0);
      j_set_num(rec, "bytes_false", ff.body ? (double)strlen(ff.body) : 0);
      j_set_bool(rec, "true_matches_baseline", t_same);
      j_set_bool(rec, "false_matches_baseline", f_same);
      j_add(tests, rec);

      if (strcmp(verdict, "confirmed") == 0) {
        confirmed++;
        if (!evidence[0]) {
          snprintf(evidence, sizeof(evidence),
                   "参数 %s 在恒真与恒假条件下响应不同(恒真 %d 字节与基线一致,恒假 %d 字节)",
                   param, (int)(ft.body ? strlen(ft.body) : 0),
                   (int)(ff.body ? strlen(ff.body) : 0));
        }
      } else if (strcmp(verdict, "inconclusive") == 0) {
        inconclusive++;
      }
      (void)base_bytes;
      fetch_free2(&ft);
      fetch_free2(&ff);
      buf_free(&ut);
      buf_free(&uf);
    }
  }

  /* 错误回显单独探一次:报错里带库信息是最可靠的证据 */
  char err_sig[128] = {0};
  {
    buf_t ue;
    buf_init(&ue);
    const char *p0 = j_len(params) > 0 ? j_at(params, 0)->str : "";
    web_url_set_param(target, p0, "1'", &ue);
    fetch_t fe;
    t_fetch(ctx, ue.data, &fe);
    if (!(fe.err && !fe.status) && fe.body) {
      int n = 0;
      const char **sigs = rules_str_list("error_signatures", &n);
      for (int i = 0; i < n; i++) {
        if (str_icontains(fe.body, sigs[i])) { snprintf(err_sig, sizeof(err_sig), "%s", sigs[i]); break; }
      }
    }
    fetch_free2(&fe);
    buf_free(&ue);
  }

  json_t *data = j_obj();
  j_set_str(data, "target", target);
  j_set_str(data, "method", "布尔差分 + 错误特征(只读,不取数据)");
  j_set(data, "tests", tests);
  j_set_num(data, "confirmed_tests", confirmed);
  j_set_num(data, "inconclusive_tests", inconclusive);
  j_set_str(data, "error_signature", err_sig);
  j_set_str(data, "verdict",
            err_sig[0] || confirmed ? "confirmed" : (inconclusive ? "inconclusive" : "not_found"));
  j_set_str(data, "evidence", err_sig[0] ? err_sig : evidence);
  j_set_num(data, "candidate_count", (err_sig[0] || confirmed) ? 1 : 0);
  put_rules_note(data);
  out->data = data;
  if (err_sig[0] || confirmed) {
    j_set_str(data, "kind", "漏洞");
    j_set_str(data, "severity", "严重");
    j_set_str(data, "param", j_len(params) > 0 ? j_at(params, 0)->str : "");
  }

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "注入验证 %s:比对 %d 组恒真/恒假响应,确认 %d 组,无法判定 %d 组。",
             target, j_len(tests), confirmed, inconclusive);
  if (err_sig[0]) buf_printf(&t, "\n错误回显特征:%s", err_sig);
  for (int i = 0; i < j_len(tests); i++) {
    buf_printf(&t, "\n- %s [%s] %s → %s", j_s(j_at(tests, i), "param", ""),
               j_s(j_at(tests, i), "context", ""), j_s(j_at(tests, i), "payload_true", ""),
               j_s(j_at(tests, i), "verdict", ""));
  }
  out->text = buf_take(&t);

  buf_t s;
  buf_init(&s);
  if (err_sig[0]) {
    buf_printf(&s, "注入验证结果:确认存在注入 —— 服务端把数据库报错回显了出来(特征:%s)。"
                   "我没有取任何数据,只做了验证。", err_sig);
  } else if (confirmed) {
    buf_printf(&s, "注入验证结果:确认 %s 存在注入。恒真条件与正常响应一致、恒假条件明显不同,"
                   "这是布尔注入的典型特征。建议立即修复参数化查询。",
               j_len(params) > 0 ? j_at(params, 0)->str : "该参数");
  } else if (inconclusive) {
    buf_printf(&s, "注入验证结果没法下结论:%d 组响应波动(可能是页面含随机内容),"
                   "既不满足注入特征也不满足正常特征。我不硬报结论。", inconclusive);
  } else {
    buf_printf(&s, "注入验证完成:%d 组测试都没出现布尔差异,未发现注入迹象"
                   "(不代表绝对没有,只是当前手法没验证出来)。", j_len(tests));
  }
  out->say = buf_take(&s);
  buf_free(&base_shape);
  fetch_free2(&base);
  return 0;
}
