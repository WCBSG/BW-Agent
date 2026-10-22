/* json.cpp —— 极简 JSON 实现。
   递归下降解析,不依赖任何第三方库。字符串按 UTF-8 原样保留,
   \uXXXX 转义会还原成 UTF-8(中文常以这种形式出现)。 */
#include "json.h"

/* ================= 构造 / 释放 ================= */
static json_t *j_new(jtype_t t) {
  json_t *j = (json_t *)xcalloc(1, sizeof(json_t));
  j->type = t;
  return j;
}

json_t *j_null(void) { return j_new(J_NULL); }

json_t *j_bool(int v) {
  json_t *j = j_new(J_BOOL);
  j->b = v ? 1 : 0;
  return j;
}

json_t *j_num(double v) {
  json_t *j = j_new(J_NUM);
  j->num = v;
  return j;
}

json_t *j_str(const char *s) {
  json_t *j = j_new(J_STR);
  j->str = xstrdup(s ? s : "");
  return j;
}

json_t *j_arr(void) { return j_new(J_ARR); }
json_t *j_obj(void) { return j_new(J_OBJ); }

static void j_push(json_t *container, const char *key, json_t *value) {
  if (container->count >= container->cap) {
    container->cap = container->cap ? container->cap * 2 : 8;
    container->items = (json_t **)xrealloc(container->items,
                                           sizeof(json_t *) * (size_t)container->cap);
    if (container->type == J_OBJ) {
      container->keys = (char **)xrealloc(container->keys,
                                          sizeof(char *) * (size_t)container->cap);
    }
  }
  if (container->type == J_OBJ) container->keys[container->count] = xstrdup(key ? key : "");
  container->items[container->count] = value;
  container->count++;
}

/* 改一个键的值:已经有就**原地替换**(不能追加 —— 追加会让同一个键出现两次,
   读的时候拿到的是旧值,而序列化出来又是两份,是最难查的那类 bug)。
   没有才追加。key 为 NULL 表示数组追加。 */
void j_set(json_t *obj, const char *key, json_t *value) {
  if (!obj || obj->type != J_OBJ || !value) return;
  if (key) {
    for (int i = 0; i < obj->count; i++) {
      if (obj->keys[i] && strcmp(obj->keys[i], key) == 0) {
        json_free(obj->items[i]);          /* 换新值就不留旧值 */
        obj->items[i] = value;
        return;
      }
    }
  }
  j_push(obj, key, value);
}

void j_add(json_t *arr, json_t *value) {
  if (!arr || arr->type != J_ARR || !value) return;
  j_push(arr, NULL, value);
}

void j_set_str(json_t *obj, const char *key, const char *value) { j_set(obj, key, j_str(value)); }
void j_set_num(json_t *obj, const char *key, double value) { j_set(obj, key, j_num(value)); }
void j_set_bool(json_t *obj, const char *key, int value) { j_set(obj, key, j_bool(value)); }
void j_set_null(json_t *obj, const char *key) { j_set(obj, key, j_null()); }

void json_free(json_t *j) {
  if (!j) return;
  for (int i = 0; i < j->count; i++) json_free(j->items[i]);
  if (j->keys) {
    for (int i = 0; i < j->count; i++) free(j->keys[i]);
    free(j->keys);
  }
  free(j->items);
  free(j->str);
  free(j);
}

/* ================= 解析 ================= */
typedef struct {
  const char *p;
  const char *end;
  int depth;
  int ok;
} parser_t;

#define JSON_MAX_DEPTH 64

static void skip_ws(parser_t *ps) {
  while (ps->p < ps->end &&
         (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r')) {
    ps->p++;
  }
}

static void utf8_encode(buf_t *b, unsigned int cp) {
  if (cp == 0) return;
  if (cp < 0x80) {
    buf_putc_(b, (char)cp);
  } else if (cp < 0x800) {
    buf_putc_(b, (char)(0xC0 | (cp >> 6)));
    buf_putc_(b, (char)(0x80 | (cp & 0x3F)));
  } else if (cp < 0x10000) {
    buf_putc_(b, (char)(0xE0 | (cp >> 12)));
    buf_putc_(b, (char)(0x80 | ((cp >> 6) & 0x3F)));
    buf_putc_(b, (char)(0x80 | (cp & 0x3F)));
  } else {
    buf_putc_(b, (char)(0xF0 | (cp >> 18)));
    buf_putc_(b, (char)(0x80 | ((cp >> 12) & 0x3F)));
    buf_putc_(b, (char)(0x80 | ((cp >> 6) & 0x3F)));
    buf_putc_(b, (char)(0x80 | (cp & 0x3F)));
  }
}

static int hex4(const char *p, unsigned int *out) {
  unsigned int v = 0;
  for (int i = 0; i < 4; i++) {
    char c = p[i];
    v <<= 4;
    if (c >= '0' && c <= '9') v |= (unsigned int)(c - '0');
    else if (c >= 'a' && c <= 'f') v |= (unsigned int)(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F') v |= (unsigned int)(c - 'A' + 10);
    else return -1;
  }
  *out = v;
  return 0;
}

/* 解析字符串字面量(当前字符应是引号),返回 xmalloc 的 UTF-8 串 */
static char *parse_string_raw(parser_t *ps) {
  if (ps->p >= ps->end || *ps->p != '"') { ps->ok = 0; return NULL; }
  ps->p++;
  buf_t b;
  buf_init(&b);
  while (ps->p < ps->end) {
    unsigned char c = (unsigned char)*ps->p;
    if (c == '"') { ps->p++; return buf_take(&b); }
    if (c == '\\') {
      ps->p++;
      if (ps->p >= ps->end) break;
      char e = *ps->p++;
      switch (e) {
        case '"':  buf_putc_(&b, '"');  break;
        case '\\': buf_putc_(&b, '\\'); break;
        case '/':  buf_putc_(&b, '/');  break;
        case 'b':  buf_putc_(&b, '\b'); break;
        case 'f':  buf_putc_(&b, '\f'); break;
        case 'n':  buf_putc_(&b, '\n'); break;
        case 'r':  buf_putc_(&b, '\r'); break;
        case 't':  buf_putc_(&b, '\t'); break;
        case 'u': {
          unsigned int cp = 0;
          if (ps->p + 4 > ps->end || hex4(ps->p, &cp) != 0) { ps->ok = 0; buf_free(&b); return NULL; }
          ps->p += 4;
          /* 代理对:高位 D800-DBFF 后面跟低位 DC00-DFFF,合成一个码点 */
          if (cp >= 0xD800 && cp <= 0xDBFF && ps->p + 6 <= ps->end &&
              ps->p[0] == '\\' && ps->p[1] == 'u') {
            unsigned int lo = 0;
            if (hex4(ps->p + 2, &lo) == 0 && lo >= 0xDC00 && lo <= 0xDFFF) {
              cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
              ps->p += 6;
            }
          }
          utf8_encode(&b, cp);
          break;
        }
        default: ps->ok = 0; buf_free(&b); return NULL;
      }
    } else {
      buf_putc_(&b, (char)c);
      ps->p++;
    }
  }
  ps->ok = 0;
  buf_free(&b);
  return NULL;
}

static json_t *parse_value(parser_t *ps);

static json_t *parse_array(parser_t *ps) {
  json_t *arr = j_arr();
  ps->p++;                 /* 跳过 [ */
  skip_ws(ps);
  if (ps->p < ps->end && *ps->p == ']') { ps->p++; return arr; }
  while (ps->p < ps->end) {
    json_t *v = parse_value(ps);
    if (!ps->ok) { json_free(arr); return NULL; }
    j_add(arr, v);
    skip_ws(ps);
    if (ps->p < ps->end && *ps->p == ',') { ps->p++; skip_ws(ps); continue; }
    if (ps->p < ps->end && *ps->p == ']') { ps->p++; return arr; }
    ps->ok = 0;
    break;
  }
  json_free(arr);
  return NULL;
}

static json_t *parse_object(parser_t *ps) {
  json_t *obj = j_obj();
  ps->p++;                 /* 跳过 { */
  skip_ws(ps);
  if (ps->p < ps->end && *ps->p == '}') { ps->p++; return obj; }
  while (ps->p < ps->end) {
    char *key = parse_string_raw(ps);
    if (!ps->ok) { free(key); json_free(obj); return NULL; }
    skip_ws(ps);
    if (ps->p >= ps->end || *ps->p != ':') { free(key); ps->ok = 0; json_free(obj); return NULL; }
    ps->p++;
    skip_ws(ps);
    json_t *v = parse_value(ps);
    if (!ps->ok) { free(key); json_free(obj); return NULL; }
    j_set(obj, key, v);
    free(key);
    skip_ws(ps);
    if (ps->p < ps->end && *ps->p == ',') { ps->p++; skip_ws(ps); continue; }
    if (ps->p < ps->end && *ps->p == '}') { ps->p++; return obj; }
    ps->ok = 0;
    break;
  }
  json_free(obj);
  return NULL;
}

static json_t *parse_value(parser_t *ps) {
  if (++ps->depth > JSON_MAX_DEPTH) { ps->ok = 0; return NULL; }
  skip_ws(ps);
  if (ps->p >= ps->end) { ps->ok = 0; ps->depth--; return NULL; }

  char c = *ps->p;
  json_t *out = NULL;

  if (c == '{') {
    out = parse_object(ps);
  } else if (c == '[') {
    out = parse_array(ps);
  } else if (c == '"') {
    char *s = parse_string_raw(ps);
    if (ps->ok) { out = j_str(s ? s : ""); }
    free(s);
  } else if (strncmp(ps->p, "true", 4) == 0) {
    ps->p += 4; out = j_bool(1);
  } else if (strncmp(ps->p, "false", 5) == 0) {
    ps->p += 5; out = j_bool(0);
  } else if (strncmp(ps->p, "null", 4) == 0) {
    ps->p += 4; out = j_null();
  } else {
    /* 数字:手写扫描,不需要 locale,也不会把 1e5 解析坏 */
    const char *start = ps->p;
    if (*ps->p == '-' || *ps->p == '+') ps->p++;
    while (ps->p < ps->end && ((*ps->p >= '0' && *ps->p <= '9') || *ps->p == '.' ||
                               *ps->p == 'e' || *ps->p == 'E' || *ps->p == '+' || *ps->p == '-')) {
      ps->p++;
    }
    if (ps->p == start) { ps->ok = 0; ps->depth--; return NULL; }
    char tmp[64];
    size_t n = (size_t)(ps->p - start);
    if (n >= sizeof(tmp)) n = sizeof(tmp) - 1;
    memcpy(tmp, start, n);
    tmp[n] = 0;
    out = j_num(atof(tmp));
  }
  ps->depth--;
  return out;
}

json_t *json_parse_n(const char *text, size_t len) {
  if (!text) return NULL;
  parser_t ps;
  ps.p = text;
  ps.end = text + len;
  ps.depth = 0;
  ps.ok = 1;
  json_t *j = parse_value(&ps);
  if (!ps.ok) { json_free(j); return NULL; }
  return j;
}

json_t *json_parse(const char *text) {
  return text ? json_parse_n(text, strlen(text)) : NULL;
}

char *json_unescape(const char *s, size_t n, size_t *out_len) {
  parser_t ps;
  buf_t tmp;
  buf_init(&tmp);
  buf_putc_(&tmp, '"');
  buf_putn(&tmp, s, n);
  buf_putc_(&tmp, '"');
  ps.p = tmp.data;
  ps.end = tmp.data + tmp.len;
  ps.depth = 0;
  ps.ok = 1;
  char *out = parse_string_raw(&ps);
  buf_free(&tmp);
  if (out_len) *out_len = out ? strlen(out) : 0;
  return out;
}

/* ================= 读写 ================= */
static json_t *obj_find(json_t *obj, const char *key) {
  if (!obj || obj->type != J_OBJ || !key) return NULL;
  for (int i = 0; i < obj->count; i++) {
    if (obj->keys[i] && strcmp(obj->keys[i], key) == 0) return obj->items[i];
  }
  return NULL;
}

json_t *j_get(json_t *obj, const char *key) { return obj_find(obj, key); }

const char *j_s(json_t *obj, const char *key, const char *fallback) {
  json_t *v = obj_find(obj, key);
  if (!v) return fallback;
  if (v->type == J_STR) return v->str;
  if (v->type == J_NULL) return fallback;
  return fallback;
}

double j_n(json_t *obj, const char *key, double fallback) {
  json_t *v = obj_find(obj, key);
  if (!v) return fallback;
  if (v->type == J_NUM) return v->num;
  if (v->type == J_BOOL) return v->b ? 1 : 0;
  if (v->type == J_STR && v->str && *v->str) return atof(v->str);
  return fallback;
}

int j_b(json_t *obj, const char *key, int fallback) {
  json_t *v = obj_find(obj, key);
  if (!v) return fallback;
  if (v->type == J_BOOL) return v->b;
  if (v->type == J_NUM) return v->num != 0;
  if (v->type == J_STR) return j_b(v, "", 0) || (v->str && (!strcmp(v->str, "1") || str_ieq(v->str, "true")));
  return fallback;
}

json_t *j_at(json_t *arr, int index) {
  if (!arr || arr->type != J_ARR || index < 0 || index >= arr->count) return NULL;
  return arr->items[index];
}

int j_len(json_t *a) { return a ? a->count : 0; }

/* 路径取值:支持 "a.b[0].c" 这种写法,决策解析时很好用 */
json_t *j_path(json_t *root, const char *path) {
  if (!root || !path) return NULL;
  json_t *cur = root;
  const char *p = path;
  buf_t key;
  buf_init(&key);
  while (*p && cur) {
    if (*p == '.') {
      p++;
      if (key.len) { cur = (cur->type == J_OBJ) ? obj_find(cur, key.data) : NULL; buf_clear(&key); }
    } else if (*p == '[') {
      if (key.len) { cur = (cur->type == J_OBJ) ? obj_find(cur, key.data) : NULL; buf_clear(&key); }
      p++;
      int idx = atoi(p);
      while (*p && *p != ']') p++;
      if (*p == ']') p++;
      cur = (cur && cur->type == J_ARR) ? j_at(cur, idx) : NULL;
    } else {
      buf_putc_(&key, *p);
      p++;
    }
  }
  if (cur && key.len && cur->type == J_OBJ) cur = obj_find(cur, key.data);
  else if (cur && key.len && cur->type == J_ARR) cur = j_at(cur, atoi(key.data));
  buf_free(&key);
  return cur;
}

const char *j_path_s(json_t *root, const char *path, const char *fallback) {
  json_t *v = j_path(root, path);
  return (v && v->type == J_STR) ? v->str : fallback;
}

/* ================= 序列化 ================= */
static void write_number(buf_t *out, double v) {
  /* 整数不带小数点:token 计数、状态码这类字段更干净 */
  if (v == (double)(long long)v && v < 1e15 && v > -1e15) {
    buf_printf(out, "%lld", (long long)v);
  } else {
    char tmp[40];
    snprintf(tmp, sizeof(tmp), "%.6g", v);
    buf_puts(out, tmp);
  }
}

static void json_write_inner(buf_t *out, json_t *j, int indent, int level);

static void write_indent(buf_t *out, int indent, int level) {
  if (indent <= 0) return;
  buf_putc_(out, '\n');
  for (int i = 0; i < indent * level; i++) buf_putc_(out, ' ');
}

void json_write(buf_t *out, json_t *j) { json_write_inner(out, j, 0, 0); }

static void json_write_inner(buf_t *out, json_t *j, int indent, int level) {
  if (!j) { buf_puts(out, "null"); return; }
  switch (j->type) {
    case J_NULL: buf_puts(out, "null"); break;
    case J_BOOL: buf_puts(out, j->b ? "true" : "false"); break;
    case J_NUM:  write_number(out, j->num); break;
    case J_STR:  buf_json_str(out, j->str); break;
    case J_ARR:
      buf_putc_(out, '[');
      for (int i = 0; i < j->count; i++) {
        if (i) buf_putc_(out, ',');
        if (indent > 0) write_indent(out, indent, level + 1);
        json_write_inner(out, j->items[i], indent, level + 1);
      }
      if (indent > 0 && j->count) write_indent(out, indent, level);
      buf_putc_(out, ']');
      break;
    case J_OBJ:
      buf_putc_(out, '{');
      for (int i = 0; i < j->count; i++) {
        if (i) buf_putc_(out, ',');
        if (indent > 0) write_indent(out, indent, level + 1);
        buf_json_str(out, j->keys[i]);
        buf_putc_(out, ':');
        if (indent > 0) buf_putc_(out, ' ');
        json_write_inner(out, j->items[i], indent, level + 1);
      }
      if (indent > 0 && j->count) write_indent(out, indent, level);
      buf_putc_(out, '}');
      break;
  }
}

char *json_dump(json_t *j) {
  buf_t b;
  buf_init(&b);
  json_write(&b, j);
  return buf_take(&b);
}

char *json_dump_pretty(json_t *j) {
  buf_t b;
  buf_init(&b);
  json_write_inner(&b, j, 2, 0);
  return buf_take(&b);
}

const char *j_type_name(jtype_t t) {
  switch (t) {
    case J_NULL: return "null";
    case J_BOOL: return "bool";
    case J_NUM:  return "number";
    case J_STR:  return "string";
    case J_ARR:  return "array";
    case J_OBJ:  return "object";
  }
  return "?";
}
