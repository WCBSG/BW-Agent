/* tool_common.cpp —— 工具公共手法
 *
 * 这个文件只包含这一个工具的实现(以及只被它使用的辅助函数)。
 * 公共手法(取数、URL 归一、软 404 校准)在 tool_common.cpp;
 * 注册表与协议在 src\main\tools.cpp 与 src\main\tool_entry.cpp。
 */
#include "tool_api.h"

int do_fetch(tool_ctx_t *ctx, const char *url, const char *method,
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

int scope_ok(tool_ctx_t *ctx, const char *url) {
  if (!ctx->io.in_scope) return 1;   /* 没有边界判定的通道(自检替身):不预筛 */
  return ctx->io.in_scope(ctx->io.userdata, url);
}

/* ---------- 本机信息与设置:公共小工具 ---------- */

/* 模型/人两边都能读的一行值:字符串不加引号,其它用紧凑 JSON */
void value_text(buf_t *out, json_t *v) {
  if (!v) {
    buf_puts(out, "(未设置)");
    return;
  }
  if (v->type == J_STR) {
    buf_puts(out, v->str ? v->str : "");
    return;
  }
  if (v->type == J_NULL) {
    buf_puts(out, "null");
    return;
  }
  char *d = json_dump(v);
  buf_puts(out, d ? d : "");
  free(d);
}

/* 把一份规则域里的键名列出来(保存后告诉用户"这次改了哪几个键") */
void join_keys(buf_t *out, json_t *obj) {
  if (!obj || obj->type != J_OBJ) return;
  for (int i = 0; i < obj->count; i++) {
    if (!obj->keys[i]) continue;
    if (out->len) buf_puts(out, "、");
    buf_puts(out, obj->keys[i]);
  }
}

/* 写设置的统一留痕。为什么每次都要留:模型改的东西也必须可追溯,
   出问题时能回答"这条规则是什么时候、被谁改掉的"。 */
void settings_audit(tool_ctx_t *ctx, const char *action, const char *target,
                           const char *detail) {
  if (!ctx || !ctx->store) return;
  store_audit((store_t *)ctx->store, action, target ? target : "", 1,
              detail ? detail : "", ctx->task_id, ctx->run_id);
}

/* 对象型参数:模型可能直接给一个对象,也可能给一段 JSON 文本;两种都收。
   返回的副本由调用方 json_free(不借出 argv 里的指针,省得后面谁改了原对象)。 */
json_t *obj_arg(json_t *args, const char *key) {
  json_t *v = j_get(args, key);
  if (!v) return NULL;
  if (v->type == J_OBJ || v->type == J_ARR) {
    char *d = json_dump(v);
    json_t *cp = d ? json_parse(d) : NULL;
    free(d);
    return cp;
  }
  if (v->type == J_STR && v->str && v->str[0]) return json_parse(v->str);
  return NULL;
}

/* 单个值:数字/布尔/对象原样用;字符串先当 JSON 试一下,不行才按纯文本 */
json_t *value_arg(json_t *args, const char *key) {
  json_t *v = j_get(args, key);
  if (!v) return NULL;
  if (v->type == J_STR) {
    json_t *parsed = (v->str && v->str[0]) ? json_parse(v->str) : NULL;
    return parsed ? parsed : j_str(v->str ? v->str : "");
  }
  char *d = json_dump(v);
  json_t *cp = d ? json_parse(d) : NULL;
  free(d);
  return cp;
}

/* "probing.timeout_ms" → 顶层键 "probing"(规则按顶层键分域) */
int top_key_of(const char *path, char *out, size_t cap) {
  if (!path || !*path || !out || cap == 0) return 0;
  const char *dot = strchr(path, '.');
  size_t n = dot ? (size_t)(dot - path) : strlen(path);
  if (n == 0 || n >= cap) return 0;
  memcpy(out, path, n);
  out[n] = 0;
  return 1;
}

/* 按 a.b.c 设值,中间层不存在就补一个空对象。
   为什么要它:规则一域里的值常常是嵌套的(探测参数整块是一层对象),
   而按域保存是"整键替换" —— 直接提交 {probing:{timeout_ms:x}} 会把
   max_paths/max_dirs 一起抹掉。所以先在现有内容上打点,再整键提交。 */
int deep_set(json_t *root, const char *path, json_t *value) {
  if (!root || root->type != J_OBJ || !path || !*path) return 0;
  const char *dot = strchr(path, '.');
  if (!dot) {
    j_set(root, path, value);
    return 1;
  }
  char head[128];
  size_t n = (size_t)(dot - path);
  if (n == 0 || n >= sizeof(head)) return 0;
  memcpy(head, path, n);
  head[n] = 0;
  json_t *child = j_get(root, head);
  if (!child || child->type != J_OBJ) {
    child = j_obj();
    j_set(root, head, child);       /* 接管所有权;child 指针本身不变 */
  }
  return deep_set(child, dot + 1, value);
}

/* 失败回包:错误要能被模型读懂,也要能被人看见 */
int settings_fail(tool_result_t *out, buf_t *msg) {
  out->is_error = 1;
  out->text = buf_take(msg);
  out->say = xstrdup("这个设置我没有改动。");
  return -1;
}

/* 正则验枪口(agent.exe regextest 用):把一条自定义正则拿去试。
   规则是数据,数据写错不该靠猜 —— 这里直接告诉你它匹配到了哪一段。 */

/* 脱敏:保留头尾,中间星号(报告可能外传,不能留明文) */
void mask_into(buf_t *out, const char *s, int len) {
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

int scan_text_into(tool_ctx_t *ctx, const char *text, json_t *hits) {
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

  /* 出厂规则之外,再按"本单位定义"扫一遍。
     两套口径是叠加的:出厂规则负责通用泄露形态(证件号/私钥/凭据),
     本单位定义负责只有这家才有的关键词、样例与正则。 */
  {
    char kind[64], sev[16], masked[160];
    if (profile_scan_text(text, kind, sizeof(kind), sev, sizeof(sev), masked, sizeof(masked))) {
      json_t *h = j_obj();
      j_set_str(h, "kind", kind);
      j_set_str(h, "severity", sev);
      j_set_str(h, "masked", masked);
      j_set_str(h, "rule", "本单位敏感信息定义");
      j_add(hits, h);
      count++;
    }
  }

  (void)ctx;
  return count;
}

/* ---- 3. 资产发现 ---- */
int looks_like_html(const char *ct) {
  return !ct || !*ct || str_icontains(ct, "html") || str_icontains(ct, "text/plain");
}

/* 从 HTML 里抠链接:只认我们关心的几类属性 */
void extract_links(const char *html, json_t *out) {
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

const char *classify_kind(const char *url) {
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

/* ---- URL 处理:爬虫要会跟相对链接,而且要守住"本次巡检范围"这个子路径 ---- */

/* 取 URL 的路径+查询(到主机名之后为止) */
void url_path_query(const char *url, char *out, size_t cap) {
  const char *p = strstr(url, "://");
  p = p ? strchr(p + 3, '/') : strchr(url, '/');
  snprintf(out, cap, "%s", p && p[0] ? p : "/");
}

/* 取"协议://主机[:端口]" */
void url_origin(const char *url, char *out, size_t cap) {
  const char *scheme = strstr(url, "://");
  const char *hoststart = scheme ? scheme + 3 : url;
  size_t n = (size_t)(hoststart - url) + strcspn(hoststart, "/?#");
  if (n >= cap) n = cap - 1;
  memcpy(out, url, n);
  out[n] = 0;
}

/* 归一化路径:折叠 ./ ../ 与重复的 /(不处理查询串) */
void path_normalize(const char *in, char *out, size_t cap) {
  char tmp[2048];
  snprintf(tmp, sizeof(tmp), "%s", in && in[0] ? in : "/");
  char *q = strpbrk(tmp, "?#");
  if (q) *q = 0;
  int want_dir = tmp[0] && tmp[strlen(tmp) - 1] == '/';
  const char *seg[128];
  int n = 0;
  for (char *s = tmp; *s;) {
    while (*s == '/') s++;
    if (!*s) break;
    char *e = s + strcspn(s, "/");
    char save = *e;
    *e = 0;
    if (strcmp(s, ".") == 0) {
      /* 当前目录,丢掉 */
    } else if (strcmp(s, "..") == 0) {
      if (n > 0) n--;
    } else if (n < 128) {
      seg[n++] = s;
    }
    if (!save) break;
    s = e + 1;
  }
  buf_t b;
  buf_init(&b);
  for (int i = 0; i < n; i++) {
    buf_putc_(&b, '/');
    buf_puts(&b, seg[i]);
  }
  if (n == 0) buf_putc_(&b, '/');
  else if (want_dir) buf_putc_(&b, '/');
  snprintf(out, cap, "%s", b.data ? b.data : "/");
  buf_free(&b);
}

/* 把链接解析成绝对 URL(按 base_url 所在目录)。解析不了就返回空串。 */
void url_resolve(const char *base_url, const char *link, char *out, size_t cap) {
  out[0] = 0;
  if (!link || !*link) return;
  char origin[512];
  url_origin(base_url, origin, sizeof(origin));
  if (str_startswith(link, "http://") || str_startswith(link, "https://")) {
    snprintf(out, cap, "%s", link);
    return;
  }
  if (str_startswith(link, "//")) {
    const char *scheme_end = strstr(base_url, "://");
    snprintf(out, cap, "%.*s%s", (int)(scheme_end ? scheme_end - base_url : 0), base_url, link);
    return;
  }
  if (link[0] == '#') {                      /* 纯锚点:同一页,不必再取一遍 */
    return;
  }
  if (link[0] == '?') {
    char bq[2048];
    url_path_query(base_url, bq, sizeof(bq));
    char *q = strpbrk(bq, "?#");
    if (q) *q = 0;
    snprintf(out, cap, "%s%s%s", origin, bq, link);
    return;
  }
  char base_path[2048];
  url_path_query(base_url, base_path, sizeof(base_path));
  char *q = strpbrk(base_path, "?#");
  if (q) *q = 0;
  char joined[2048];
  if (link[0] == '/') {
    snprintf(joined, sizeof(joined), "%s", link);
  } else {
    /* 相对链接的基准是"当前页面的目录":/l1/index.html + news.html = /l1/news.html */
    char *slash = strrchr(base_path, '/');
    size_t dlen = slash ? (size_t)(slash - base_path) + 1 : 1;
    if (dlen >= sizeof(joined)) dlen = sizeof(joined) - 1;
    memcpy(joined, base_path, dlen);
    joined[dlen] = 0;
    snprintf(joined + dlen, sizeof(joined) - dlen, "%s", link);
  }
  char norm[2048];
  path_normalize(joined, norm, sizeof(norm));
  snprintf(out, cap, "%s%s", origin, norm);
}

/* 目标路径是否落在本次巡检范围内(按"段"比较,/l1 不误伤 /l10) */
int path_in_scope(const char *path, const char *scope) {
  if (!scope || !scope[0] || strcmp(scope, "/") == 0) return 1;
  size_t pl = strlen(scope), ql = path ? strlen(path) : 0;
  if (ql < pl) return 0;
  if (strncmp(path, scope, pl) != 0) return 0;
  if (scope[pl - 1] == '/') return 1;
  return path[pl] == 0 || path[pl] == '/' || path[pl] == '?';
}

/* ================= 通用探测基础设施 =================
   下面这层是所有"探测类"工具共用的手法。刻意不含任何具体站点的知识:
   判断依据全部来自"这次取回来的内容",而不是"我记得这个站有什么"。 */

void t_fetch_m(tool_ctx_t *ctx, const char *url, const char *method, fetch_t *f) {
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

void t_fetch(tool_ctx_t *ctx, const char *url, fetch_t *f) {
  t_fetch_m(ctx, url, "GET", f);
}

void fetch_free2(fetch_t *f) {
  free(f->headers);
  free(f->body);
  free(f->err);
  f->headers = f->body = f->err = NULL;
}

/* 站点根(协议 + 主机 + 端口):路径探测必须以它为基准。
   注意:模型可能只给"example.com"这种写法,所以先补协议再取根 —— 直接拿裸域名去
   请求会得到一个不明不白的失败,那不是站点的问题,是我们没把地址准备好。 */
/* 探测根:协议+主机+端口,再加"目标里给出的子路径"。
   子路径不能丢 —— 靶场每关挂在 /l1 … /l6 下,丢了路径就变成从首页开始探测,
   既不属于授权范围,也检不到关卡里的东西。 */
void probe_root(const char *url, char *out, size_t cap) {
  const char *p = url ? url : "";
  const char *scheme = strstr(p, "://");
  const char *hoststart = scheme ? scheme + 3 : p;
  const char *end = hoststart + strcspn(hoststart, "/?#");
  size_t path_len = 0;
  if (*end == '/') {
    while (end[path_len] && end[path_len] != '?' && end[path_len] != '#') path_len++;
    while (path_len > 0 && end[path_len - 1] == '/') path_len--;
  }
  if (!scheme) {
    int n = snprintf(out, cap, "https://%.*s%.*s", (int)(end - p), p, (int)path_len, end);
    if (n < 0) out[0] = 0;
    return;
  }
  size_t n = (size_t)(end - p) + path_len;
  if (n >= cap) n = cap - 1;
  memcpy(out, p, n);
  out[n] = 0;
}

/* 工具入口的统一归一:没有协议就补 https(只补,不改用户明确写的协议) */
void normalize_target(const char *in, char *out, size_t cap) {
  const char *s = in ? in : "";
  while (*s == ' ' || *s == '"') s++;
  if (strstr(s, "://")) snprintf(out, cap, "%s", s);
  else snprintf(out, cap, "https://%s", s);
  char *e = out + strlen(out);
  while (e > out && (e[-1] == ' ' || e[-1] == '"')) *--e = 0;
}

void join_path(char *out, size_t cap, const char *root, const char *path) {
  size_t n = strlen(root);
  while (n > 0 && root[n - 1] == '/') n--;
  if (path && path[0] == '/') snprintf(out, cap, "%.*s%s", (int)n, root, path);
  else snprintf(out, cap, "%.*s/%s", (int)n, root, path ? path : "");
}

/* ---- 软 404 校准:先看清"这个站没有这个文件时长什么样" ----
   这是所有路径探测的前提。很多站点对不存在的路径返回 200 + 自定义错误页,
   不先校准就会把一片"首页/错误页"当成"一堆敏感文件"。 */
void calib_free(calib_t *c) { buf_free(&c->shape); }

void calib_run(tool_ctx_t *ctx, const char *root, calib_t *c) {
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
int calib_matches(const calib_t *c, int status, const char *body) {
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
void link_analysis(const char *body, const char *own_host, json_t *hosts,
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
void put_rules_note(json_t *data) {
  j_set_str(data, "rules_source", rules_source());
  j_set_bool(data, "rules_from_file", rules_from_file());
}
