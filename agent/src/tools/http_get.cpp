/* http_get.cpp —— 让模型自己"看"一个授权内的地址
 *
 * 扫描脚本只能按预设清单取数;智能体要能顺着线索自己往下看:
 * 读一个页面的状态、关键响应头、标题、正文片段与外链,再决定下一步做什么。
 * 只做只读请求,边界由取数通道统一校验(池外不发)。
 */
#include "tool_api.h"

static int ci_prefix(const char *s, const char *lit, size_t n) {
  for (size_t i = 0; i < n; i++) {
    char a = s[i];
    if (!a) return 0;
    if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
    if (a != lit[i]) return 0;
  }
  return 1;
}

/* 从原始响应头里挑出"看得懂、用得上"的那几行 —— 整块头又长又吵 */
static void pick_headers(const char *raw, buf_t *out, json_t *data) {
  static const char *keys[] = {"server",
                               "x-powered-by",
                               "content-type",
                               "x-frame-options",
                               "content-security-policy",
                               "strict-transport-security",
                               "x-content-type-options",
                               "referrer-policy",
                               "permissions-policy",
                               "access-control-allow-origin",
                               "allow",
                               "location"};
  int cookies = 0;
  const char *line = raw ? raw : "";
  while (*line) {
    const char *eol = strchr(line, '\r');
    if (!eol) eol = strchr(line, '\n');
    size_t n = eol ? (size_t)(eol - line) : strlen(line);
    if (n > 0 && n < 512) {
      for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); k++) {
        size_t kn = strlen(keys[k]);
        if (n > kn && line[kn] == ':' && ci_prefix(line, keys[k], kn)) {
          if (out->len) buf_puts(out, "; ");
          buf_putn(out, line, n);
          break;
        }
      }
      if (n > 11 && ci_prefix(line, "set-cookie", 10) && line[10] == ':') cookies++;
    }
    if (!eol) break;
    line = eol + 1;
    while (*line == '\n') line++;
  }
  if (cookies) {
    buf_printf(out, "set-cookie×%d; ", cookies);
    j_set_num(data, "set_cookie", cookies);
  }
}

/* 正文 → 可读文本:去掉脚本/样式与标签,压掉重复空白 */
static void html_to_text(const char *html, buf_t *out, int max_bytes) {
  const char *p = html;
  int in_tag = 0, last_space = 0;
  while (*p && (int)out->len < max_bytes) {
    if (ci_prefix(p, "<script", 7) || ci_prefix(p, "<style", 6)) {
      const char *close = strstr(p, ">");
      const char *end = close ? strstr(close, "</") : NULL;
      p = end ? end : (close ? close + 1 : p + 1);
      continue;
    }
    if (*p == '<') { in_tag = 1; p++; continue; }
    if (*p == '>') {
      in_tag = 0;
      if (!last_space && out->len) {
        buf_putc_(out, ' ');
        last_space = 1;
      }
      p++;
      continue;
    }
    if (in_tag) { p++; continue; }
    if (*p == '\r' || *p == '\n' || *p == '\t' || *p == ' ') {
      if (!last_space && out->len) {
        buf_putc_(out, ' ');
        last_space = 1;
      }
      p++;
      continue;
    }
    last_space = 0;
    buf_putc_(out, *p);
    p++;
  }
  if (*p) buf_puts(out, " …(后略)");
}

/* 只留第一个 <title> 的内容 */
static void page_title(const char *html, char *out, size_t cap) {
  out[0] = 0;
  const char *s = html ? strstr(html, "<title") : NULL;
  if (!s) return;
  s = strchr(s, '>');
  if (!s) return;
  s++;
  const char *e = strstr(s, "</title");
  if (!e) return;
  size_t n = (size_t)(e - s);
  if (n >= cap) n = cap - 1;
  memcpy(out, s, n);
  out[n] = 0;
  for (char *q = out; *q; q++) {
    if (*q == '\r' || *q == '\n' || *q == '\t') *q = ' ';
  }
}

/* 取 Content-Type 的值(没有就返回空串) */
static void content_type_of(const char *raw, char *out, size_t cap) {
  out[0] = 0;
  const char *line = raw ? raw : "";
  while (*line) {
    const char *eol = strchr(line, '\r');
    if (!eol) eol = strchr(line, '\n');
    size_t n = eol ? (size_t)(eol - line) : strlen(line);
    if (n > 13 && ci_prefix(line, "content-type:", 13)) {
      const char *v = line + 13;
      size_t k = n - 13;
      while (k > 0 && (*v == ' ' || *v == '\t')) { v++; k--; }
      if (k >= cap) k = cap - 1;
      memcpy(out, v, k);
      out[k] = 0;
      return;
    }
    if (!eol) break;
    line = eol + 1;
    while (*line == '\n') line++;
  }
}

int t_http_get(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  const char *raw = j_s(args, "url", "");
  if (!raw[0]) raw = j_s(args, "target", "");
  char url[2048];
  normalize_target(raw, url, sizeof(url));
  if (!url[0]) {
    out->is_error = 1;
    out->text = xstrdup("缺少 url 参数。");
    out->say = xstrdup("不知道该取哪个地址。");
    return -1;
  }
  /* 先问边界:不拦下来的话,一次越池请求会把整轮判成越权并中止 */
  if (!scope_ok(ctx, url)) {
    buf_t t;
    buf_init(&t);
    buf_printf(&t, "%s 不在本轮可访问范围,已跳过(不影响其他检查)。", url);
    if (ctx && ctx->domain_count > 0) buf_printf(&t, "本轮焦点是 %s。", ctx->domains[0]);
    out->text = buf_take(&t);
    out->say = xstrdup("这个地址不在授权范围,跳过。");
    return 0;
  }

  const char *method = j_s(args, "method", "GET");
  int max_bytes = (int)j_n(args, "max_bytes", 2400);
  if (max_bytes < 200) max_bytes = 200;
  if (max_bytes > 8000) max_bytes = 8000;

  fetch_t f;
  t_fetch_m(ctx, url, method, &f);
  json_t *data = j_obj();
  out->data = data;
  j_set_str(data, "url", url);
  j_set_num(data, "status", f.status);

  buf_t t;
  buf_init(&t);
  if (f.err && *f.err) {
    buf_printf(&t, "%s %s → 取数失败:%s", method, url, f.err);
    out->text = buf_take(&t);
    out->is_error = 1;
    out->say = xstrdup("这个地址没取到。");
    fetch_free2(&f);
    return 0;
  }

  buf_t hs;
  buf_init(&hs);
  pick_headers(f.headers, &hs, data);
  buf_printf(&t, "%s %s → %d\n", method, url, f.status);
  if (hs.len) buf_printf(&t, "关键响应头:%s\n", hs.data);
  buf_free(&hs);

  char ct[128];
  content_type_of(f.headers, ct, sizeof(ct));

  size_t blen = f.body ? strlen(f.body) : 0;
  j_set_num(data, "bytes", (double)blen);
  if (f.body && *f.body) {
    int is_html = looks_like_html(ct) || strstr(f.body, "<html") || strstr(f.body, "<!DOCTYPE");
    if (is_html) {
      char title[256];
      page_title(f.body, title, sizeof(title));
      if (title[0]) {
        j_set_str(data, "title", title);
        buf_printf(&t, "标题:%s\n", title);
      }
      json_t *links = j_arr();
      extract_links(f.body, links);
      if (j_len(links)) {
        buf_puts(&t, "页面里的链接:");
        int shown = 0;
        for (int i = 0; i < j_len(links) && shown < 16; i++) {
          json_t *v = j_at(links, i);
          if (!v || v->type != J_STR || !v->str || !v->str[0]) continue;
          char abs[2048];
          url_resolve(url, v->str, abs, sizeof(abs));
          buf_printf(&t, " %s", abs);
          shown++;
        }
        buf_puts(&t, "\n");
        j_set_num(data, "link_count", j_len(links));
      }
      json_free(links);
    }
    buf_t text;
    buf_init(&text);
    if (is_html) html_to_text(f.body, &text, max_bytes);
    else buf_putn(&text, f.body, blen < (size_t)max_bytes ? blen : (size_t)max_bytes);
    buf_printf(&t, "正文(%d 字节,截到 %d):\n%s\n", (int)blen, max_bytes,
               text.data ? text.data : "");
    buf_free(&text);
  } else {
    buf_puts(&t, "(响应体为空)\n");
  }

  out->text = buf_take(&t);
  out->say = xstrdup("我读一下这个地址。");
  fetch_free2(&f);
  return 0;
}
