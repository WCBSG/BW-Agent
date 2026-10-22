/* webutil.cpp —— 通用网页处理件实现。 */
#include "webutil.h"

#include <bcrypt.h>
#include <ctype.h>

#include "rules.h"      /* 判定用的标记串来自规则文件(markers.*) */

/* ================= 指纹 ================= */
int sha256_hex(const char *data, size_t len, char *out, size_t cap) {
  if (!out || cap < 65) return -1;
  BCRYPT_ALG_HANDLE alg = NULL;
  BCRYPT_HASH_HANDLE hash = NULL;
  unsigned char digest[32];
  int ok = -1;
  if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0) {
    if (BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0) == 0) {
      BCryptHashData(hash, (PUCHAR)data, (ULONG)len, 0);
      BCryptFinishHash(hash, digest, sizeof(digest), 0);
      BCryptDestroyHash(hash);
      ok = 0;
    }
    BCryptCloseAlgorithmProvider(alg, 0);
  }
  if (ok != 0) {
    /* 拿不到指纹就如实写出来,绝不返回一个像指纹的假串 */
    snprintf(out, cap, "unavailable");
    return -1;
  }
  hex_encode(digest, sizeof(digest), out, cap);
  return 0;
}

/* ================= 正文归一 ================= */
static int is_space_c(char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

static void web_norm_impl(buf_t *out, const char *body, int kill_digits) {
  if (!body) return;
  const char *p = body;
  int last_space = 1;                 /* 开头视作空白:顺便把首尾空白吃掉 */
  while (*p) {
    if (p[0] == '<' && p[1] == '!' && p[2] == '-' && p[3] == '-') {   /* 注释整段丢掉 */
      const char *e = strstr(p + 4, "-->");
      p = e ? e + 3 : p + strlen(p);
      continue;
    }
    unsigned char c = (unsigned char)*p;
    if (is_space_c((char)c)) {
      if (!last_space) { buf_putc_(out, ' '); last_space = 1; }
      p++;
      continue;
    }
    if (kill_digits && isdigit(c)) {           /* 数字串 → 单个 # */
      if (out->len == 0 || out->data[out->len - 1] != '#') buf_putc_(out, '#');
      last_space = 0;
      while (isdigit((unsigned char)*p)) p++;
      continue;
    }
    buf_putc_(out, (char)c);
    last_space = 0;
    p++;
  }
  /* 尾部空白:上面"折叠"时可能留下一个尾空格 */
  while (out->len > 0 && out->data[out->len - 1] == ' ') out->data[--out->len] = 0;
}

void web_norm_text(buf_t *out, const char *body) { web_norm_impl(out, body, 0); }
void web_shape(buf_t *out, const char *body) { web_norm_impl(out, body, 1); }

int web_same_shape(const char *a, const char *b) {
  if (!a || !b) return 0;
  buf_t x, y;
  buf_init(&x);
  buf_init(&y);
  web_shape(&x, a);
  web_shape(&y, b);
  int same = (strcmp(x.data ? x.data : "", y.data ? y.data : "") == 0);
  buf_free(&x);
  buf_free(&y);
  return same;
}

int web_body_hash(const char *body, char *out, size_t cap) {
  buf_t n;
  buf_init(&n);
  web_norm_text(&n, body ? body : "");
  int rc = sha256_hex(n.data ? n.data : "", n.len, out, cap);
  buf_free(&n);
  return rc;
}

void web_title(const char *body, char *out, size_t cap) {
  if (cap) out[0] = 0;
  if (!body) return;
  const char *p = body;
  while ((p = strchr(p, '<')) != NULL) {
    if ((p[1] == 't' || p[1] == 'T') && str_icase_find(p, "<title")) {
      const char *gt = strchr(p, '>');
      if (!gt) return;
      const char *end = str_icase_find(gt, "</title>");
      const char *stop = end ? end : gt + 1 + strcspn(gt + 1, "<");
      size_t n = (size_t)(stop - (gt + 1));
      if (n > cap - 1) n = cap - 1;
      memcpy(out, gt + 1, n);
      out[n] = 0;
      char *t = str_trim(out);
      if (t != out) memmove(out, t, strlen(t) + 1);
      return;
    }
    p++;
  }
}

/* ================= 响应头 ================= */
/* 逐行扫描原始响应头。found 回调拿到的 name/value 都是去空格后的片段。 */
typedef void (*hdr_cb_t)(const char *name, size_t nlen, const char *value,
                         size_t vlen, void *ud);

static void headers_walk(const char *raw, hdr_cb_t cb, void *ud) {
  if (!raw) return;
  const char *p = raw;
  while (*p) {
    const char *eol = strchr(p, '\n');
    size_t len = eol ? (size_t)(eol - p) : strlen(p);
    if (len && p[len - 1] == '\r') len--;
    if (len > 0 && !(len >= 5 && str_icase_find(p, "HTTP/"))) {   /* 跳过状态行 */
      const char *colon = static_cast<const char *>(memchr(p, ':', len));
      if (colon) {
        const char *name = p;
        size_t nlen = (size_t)(colon - p);
        const char *val = colon + 1;
        size_t vlen = len - (size_t)(val - p);
        while (nlen > 0 && is_space_c(name[nlen - 1])) nlen--;
        while (vlen > 0 && is_space_c(*val)) { val++; vlen--; }
        while (vlen > 0 && is_space_c(val[vlen - 1])) vlen--;
        if (nlen > 0 && nlen <= 64) cb(name, nlen, val, vlen, ud);
      }
    }
    if (!eol) break;
    p = eol + 1;
  }
}

static int hdr_name_eq(const char *name, size_t nlen, const char *want) {
  size_t w = strlen(want);
  if (nlen != w) return 0;
  for (size_t i = 0; i < nlen; i++) {
    if (tolower((unsigned char)name[i]) != tolower((unsigned char)want[i])) return 0;
  }
  return 1;
}

typedef struct {
  const char *want;
  int idx;        /* -1 = 取全部并连接 */
  int count;      /* 已遇到的同名头个数 */
  int got;        /* web_header_at 是否已取到 */
  buf_t *out;
} hdr_ud_t;

static void hdr_collect(const char *name, size_t nlen, const char *value,
                        size_t vlen, void *ud) {
  hdr_ud_t *h = (hdr_ud_t *)ud;
  if (!hdr_name_eq(name, nlen, h->want)) return;
  if (h->idx >= 0) {
    if (h->count == h->idx && h->out) {
      buf_putn(h->out, value, vlen);
      h->got = 1;
    }
    h->count++;
    return;
  }
  if (h->out) {
    if (h->count > 0) buf_puts(h->out, ", ");
    buf_putn(h->out, value, vlen);
  }
  h->count++;
}

int web_header_count(const char *raw_headers, const char *name) {
  hdr_ud_t h;
  memset(&h, 0, sizeof(h));
  h.want = name;
  h.idx = -1;
  headers_walk(raw_headers, hdr_collect, &h);
  return h.count;
}

int web_header(const char *raw_headers, const char *name, buf_t *out) {
  hdr_ud_t h;
  memset(&h, 0, sizeof(h));
  h.want = name;
  h.idx = -1;
  h.out = out;
  headers_walk(raw_headers, hdr_collect, &h);
  return h.count > 0 ? 1 : 0;
}

int web_header_at(const char *raw_headers, const char *name, int idx, buf_t *out) {
  hdr_ud_t h;
  memset(&h, 0, sizeof(h));
  h.want = name;
  h.idx = idx;
  h.out = out;
  headers_walk(raw_headers, hdr_collect, &h);
  return h.got;
}

int web_headers_available(const char *raw_headers) {
  if (!raw_headers) return 0;
  static const char *PROBE[] = {"content-type", "server", "content-length",
                                "date", "set-cookie"};
  for (size_t i = 0; i < sizeof(PROBE) / sizeof(PROBE[0]); i++) {
    if (web_header_count(raw_headers, PROBE[i]) > 0) return 1;
  }
  return 0;
}

/* 敏感头的值不能原样落盘:会话票据、鉴权串都要去敏 */
static int header_needs_mask(const char *name, size_t nlen) {
  static const char *MASK[] = {"cookie", "set-cookie", "authorization",
                               "proxy-authorization", "x-auth-token", "token"};
  for (size_t i = 0; i < sizeof(MASK) / sizeof(MASK[0]); i++) {
    if (hdr_name_eq(name, nlen, MASK[i])) return 1;
  }
  return 0;
}

static void mask_header_value(const char *name, size_t nlen, const char *val,
                              size_t vlen, buf_t *out) {
  if (!header_needs_mask(name, nlen)) {
    buf_putn(out, val, vlen);
    return;
  }
  /* Set-Cookie: 保留 cookie 名与属性(HttpOnly/Secure/SameSite 要看得见),
     值一律打星;其它鉴权类头整段打星。 */
  const char *eq = static_cast<const char *>(memchr(val, '=', vlen));
  if (hdr_name_eq(name, nlen, "set-cookie") && eq) {
    buf_putn(out, val, (size_t)(eq - val));
    buf_puts(out, "=***");
    const char *semi = static_cast<const char *>(memchr(val, ';', vlen));
    if (semi) buf_putn(out, semi, vlen - (size_t)(semi - val));
    return;
  }
  buf_puts(out, "***");
  (void)nlen;
}

typedef struct { json_t *out; } hdr_json_ud_t;

static void hdr_to_json(const char *name, size_t nlen, const char *value,
                        size_t vlen, void *ud) {
  hdr_json_ud_t *h = (hdr_json_ud_t *)ud;
  char *key = xstrndup(name, nlen);
  buf_t val;
  buf_init(&val);
  mask_header_value(name, nlen, value, vlen, &val);
  /* 已有同名键就追加成数组(Set-Cookie 常见多条) */
  json_t *exist = j_get(h->out, key);
  if (!exist) {
    j_set_str(h->out, key, val.data ? val.data : "");
  } else if (exist->type == J_STR) {
    json_t *arr = j_arr();
    j_add(arr, j_str(exist->str ? exist->str : ""));
    j_add(arr, j_str(val.data ? val.data : ""));
    j_set(h->out, key, arr);
  } else if (exist->type == J_ARR) {
    j_add(exist, j_str(val.data ? val.data : ""));
  }
  buf_free(&val);
  free(key);
}

json_t *web_headers_json(const char *raw_headers) {
  json_t *o = j_obj();
  hdr_json_ud_t ud;
  ud.out = o;
  headers_walk(raw_headers, hdr_to_json, &ud);
  return o;
}

/* ================= 网页结构判断 ================= */
/* 判定用的标记串来自规则文件(markers.dir_listing / markers.login_password_field):
   不同的服务器/网关长得不一样,单位可以自己加,不用改代码。 */
int web_is_dir_listing(const char *body) {
  if (!body) return 0;
  int n = rules_arr_count("markers.dir_listing");
  int marker = 0;
  for (int i = 0; i < n; i++) {
    const char *m = rules_arr_str("markers.dir_listing", i, "", "");
    if (!m[0]) m = rules_arr_str("markers.dir_listing", i, "mark", "");
    if (m[0] && str_icase_find(body, m)) { marker = 1; break; }
  }
  if (!marker) return 0;
  /* 光有一句话不算:必须真的列出了可点的条目 */
  if (!str_icase_find(body, "<a href=") && !str_icase_find(body, "href='")) return 0;
  return 1;
}

void web_dir_listing_entries(const char *body, json_t *out, int max) {
  if (!body) return;
  const char *p = body;
  while ((p = str_icase_find(p, "href=")) != NULL && j_len(out) < max) {
    p += 5;
    char quote = *p;
    if (quote != '"' && quote != '\'') continue;
    p++;
    const char *end = strchr(p, quote);
    if (!end) break;
    size_t n = (size_t)(end - p);
    if (n > 0 && n < 300) {
      char *href = xstrndup(p, n);
      int skip = strstr(href, "..") != NULL || href[0] == '?' ||
                 str_startswith(href, "http://") || str_startswith(href, "https://") ||
                 str_startswith(href, "/");
      if (!skip) j_add(out, j_str(href));
      free(href);
    }
    p = end;
  }
}

int web_has_password_form(const char *body) {
  if (!body) return 0;
  /* 口令字段名同样在规则里(markers.login_password_field),默认 password */
  char field[64];
  snprintf(field, sizeof(field), "%s",
           rules_arr_str("markers", 0, "login_password_field", "password"));
  const char *p = body;
  while ((p = str_icase_find(p, "type=")) != NULL) {
    p += 5;
    char q = *p;
    if (q == '"' || q == '\'') {
      const char *end = strchr(p + 1, q);
      if (!end) break;
      char val[32];
      size_t n = (size_t)(end - p - 1);
      if (n >= sizeof(val)) n = sizeof(val) - 1;
      memcpy(val, p + 1, n);
      val[n] = 0;
      if (str_icase_find(val, field)) return 1;
      p = end;
      continue;
    }
    if (str_icase_find(p, field)) return 1;
  }
  return 0;
}

int web_has_mixed_content(const char *body) {
  if (!body) return 0;
  static const char *ATTRS[] = {"src=\"http://", "src='http://", "href=\"http://",
                                "href='http://", "action=\"http://", "action='http://"};
  for (size_t i = 0; i < sizeof(ATTRS) / sizeof(ATTRS[0]); i++) {
    if (str_icase_find(body, ATTRS[i])) return 1;
  }
  return 0;
}

/* ================= URL ================= */
void web_url_parts(const char *url, char *host, size_t hcap, char *path, size_t pcap) {
  if (host && hcap) host[0] = 0;
  if (path && pcap) path[0] = 0;
  if (!url) return;
  const char *p = strstr(url, "://");
  p = p ? p + 3 : url;
  const char *slash = strpbrk(p, "/?#");
  size_t hlen = slash ? (size_t)(slash - p) : strlen(p);
  if (host && hcap) {
    if (hlen >= hcap) hlen = hcap - 1;
    memcpy(host, p, hlen);
    host[hlen] = 0;
  }
  if (path && pcap && slash) snprintf(path, pcap, "%s", slash);
}

void web_url_encode(const char *s, buf_t *out) {
  static const char *HEX = "0123456789ABCDEF";
  for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++) {
    unsigned char c = *p;
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') buf_putc_(out, (char)c);
    else {
      buf_putc_(out, '%');
      buf_putc_(out, HEX[c >> 4]);
      buf_putc_(out, HEX[c & 0x0F]);
    }
  }
}

/* 拆成 base(含 ?)/query/fragment 三段 */
static void split_query(const char *url, buf_t *base, buf_t *query, buf_t *frag) {
  const char *hash = strchr(url ? url : "", '#');
  size_t end = hash ? (size_t)(hash - url) : strlen(url ? url : "");
  const char *q = static_cast<const char *>(memchr(url ? url : "", '?', end));
  if (q) {
    buf_putn(base, url, (size_t)(q - url));
    buf_putn(query, q + 1, end - (size_t)(q + 1 - url));
  } else {
    buf_putn(base, url, end);
  }
  if (hash) buf_puts(frag, hash);
}

void web_url_set_param(const char *url, const char *key, const char *value, buf_t *out) {
  buf_t base, query, frag;
  buf_init(&base);
  buf_init(&query);
  buf_init(&frag);
  split_query(url, &base, &query, &frag);

  buf_puts(out, base.data ? base.data : "");
  buf_putc_(out, '?');
  int replaced = 0, written = 0;
  const char *p = query.data ? query.data : "";
  while (*p) {
    const char *amp = strchr(p, '&');
    size_t len = amp ? (size_t)(amp - p) : strlen(p);
    if (len > 0) {
      const char *eq = static_cast<const char *>(memchr(p, '=', len));
      size_t klen = eq ? (size_t)(eq - p) : len;
      char *k = xstrndup(p, klen);
      if (str_ieq(k, key)) {
        if (written) buf_putc_(out, '&');
        buf_puts(out, key);
        buf_putc_(out, '=');
        web_url_encode(value, out);
        written = 1;
        replaced = 1;
      } else {
        if (written) buf_putc_(out, '&');
        buf_putn(out, p, len);
        written = 1;
      }
      free(k);
    }
    if (!amp) break;
    p = amp + 1;
  }
  if (!replaced) {
    if (written) buf_putc_(out, '&');
    buf_puts(out, key);
    buf_putc_(out, '=');
    web_url_encode(value, out);
  }
  if (frag.data) buf_puts(out, frag.data);
  buf_free(&base);
  buf_free(&query);
  buf_free(&frag);
}

void web_url_params(const char *url, json_t *out) {
  const char *q = strchr(url ? url : "", '?');
  if (!q) return;
  const char *p = q + 1;
  while (*p) {
    const char *amp = strchr(p, '&');
    size_t len = amp ? (size_t)(amp - p) : strlen(p);
    const char *eq = static_cast<const char *>(memchr(p, '=', len));
    size_t klen = eq ? (size_t)(eq - p) : len;
    if (klen > 0 && klen < 64) {
      char *k = xstrndup(p, klen);
      int dup = 0;
      for (int i = 0; i < j_len(out); i++) {
        if (j_at(out, i)->str && strcmp(j_at(out, i)->str, k) == 0) { dup = 1; break; }
      }
      if (!dup) j_add(out, j_str(k));
      free(k);
    }
    if (!amp) break;
    p = amp + 1;
  }
}

int web_url_get_param(const char *url, const char *key, buf_t *out) {
  const char *q = strchr(url ? url : "", '?');
  if (!q) return 0;
  const char *p = q + 1;
  while (*p) {
    const char *amp = strchr(p, '&');
    size_t len = amp ? (size_t)(amp - p) : strlen(p);
    const char *eq = static_cast<const char *>(memchr(p, '=', len));
    size_t klen = eq ? (size_t)(eq - p) : len;
    char *k = xstrndup(p, klen);
    int hit = str_ieq(k, key);
    free(k);
    if (hit) {
      if (eq) buf_putn(out, eq + 1, len - klen - 1);
      return 1;
    }
    if (!amp) break;
    p = amp + 1;
  }
  return 0;
}

/* ================= 链接 ================= */
void web_extract_links(const char *html, json_t *out) {
  if (!html) return;
  static const char *ATTRS[] = {"href=", "src=", "action=", "data-src=", "poster="};
  for (size_t a = 0; a < sizeof(ATTRS) / sizeof(ATTRS[0]); a++) {
    const char *p = html;
    while ((p = str_icase_find(p, ATTRS[a])) != NULL) {
      p += strlen(ATTRS[a]);
      char quote = *p;
      const char *start = p;
      const char *end = NULL;
      if (quote == '"' || quote == '\'') {
        start = p + 1;
        end = strchr(start, quote);
      } else {
        end = start + strcspn(start, " \t\r\n>");
      }
      if (!end) break;
      size_t n = (size_t)(end - start);
      if (n > 0 && n < 1024) {
        char *link = xstrndup(start, n);
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

int web_count_icase(const char *hay, const char *needle) {
  if (!hay || !needle || !*needle) return 0;
  size_t nl = strlen(needle);
  int n = 0;
  const char *p = hay;
  while ((p = str_icase_find(p, needle)) != NULL) {
    n++;
    p += nl;
  }
  return n;
}
