/* regex.c —— 极简正则引擎的实现(回溯式,见 regex.h 的能力清单)。
 *
 * 结构:正则解析成一棵树 —— 序列(rx_seq)里放节点,分组/分支各自持有子序列;
 * 匹配时对每个节点"贪婪收集 + 逐级回溯",所以 [A-Za-z0-9.-]+\.[A-Za-z]{2,} 这种
 * "先贪婪后回退"的形状才匹配得对。这正是上一版(不回溯 + 用下标表示组)踩的两个坑:
 *   ① 量词重复时取错了原子 → {n} / {n,} 判断错误;
 *   ② 贪婪吃掉点号后判失败却不回退 → 邮箱、私钥头这类形状"本该命中却不命中"。
 * 这两个 bug 都是被 `agent.exe regextest` 抓出来的 —— 规则是数据,数据必须能当场验。
 */
#include "regex.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RX_MAX_STEPS 1024      /* 单个节点最多重复多少次(防御灾难性回溯) */
#define RX_MAX_DEPTH 24        /* 分组嵌套上限 */

typedef enum {
  N_CHAR, N_ANY, N_CLASS, N_GROUP, N_ALT,
  N_ANCHOR_S, N_ANCHOR_E, N_LOOKBEHIND_NOT_DIGIT, N_LOOKAHEAD_NOT_DIGIT
} node_kind;

typedef struct rx_seq {
  int *items;
  int n;
} rx_seq;

typedef struct {
  node_kind kind;
  char ch;                        /* N_CHAR 的字面量;\d \w \s 的简写字母 */
  int min, max;                   /* 量词 */
  int cls_start, cls_len, cls_neg;
  rx_seq *seq;                    /* N_GROUP */
  rx_seq **alts;
  int alt_n;                      /* N_ALT */
} rx_node;

struct rx_pattern {
  char *pat;
  rx_node *nodes;
  int n;
  int icase;
  char errmsg[160];
  rx_seq *top;
};

/* ================= 小工具 ================= */
static rx_seq *seq_new(void) { return (rx_seq *)calloc(1, sizeof(rx_seq)); }

static int seq_push(rx_seq *s, int idx) {
  int *items = (int *)realloc(s->items, sizeof(int) * (size_t)(s->n + 1));
  if (!items) return 0;
  s->items = items;
  s->items[s->n++] = idx;
  return 1;
}

static void seq_free(rx_seq *s) {
  if (!s) return;
  free(s->items);
  free(s);
}

static void set_error(rx_pattern *re, const char *why) {
  if (!re->errmsg[0]) snprintf(re->errmsg, sizeof(re->errmsg), "%s", why);
}

static int node_add(rx_pattern *re, node_kind kind) {
  rx_node *nodes = (rx_node *)realloc(re->nodes, sizeof(rx_node) * (size_t)(re->n + 1));
  if (!nodes) { set_error(re, "内存不足"); return -1; }
  re->nodes = nodes;
  rx_node *nd = &re->nodes[re->n];
  memset(nd, 0, sizeof(*nd));
  nd->kind = kind;
  nd->min = 1;
  nd->max = 1;
  return re->n++;
}

/* 转义字符:\t \n \r \f \v 这类控制字符(类内与类外都要认) */
static int escape_char(char e) {
  switch (e) {
    case 't': return '\t';
    case 'n': return '\n';
    case 'r': return '\r';
    case 'f': return '\f';
    case 'v': return '\v';
    default:  return -1;
  }
}

/* 字符类(类体内支持转义与 a-z 范围) */
static int class_match(const char *p, int plen, char c, int icase) {
  for (int i = 0; i < plen; i++) {
    if (p[i] == '\\' && i + 1 < plen) {
      char e = p[i + 1];
      int hit;
      int esc = escape_char(e);
      if (e == 'd') hit = isdigit((unsigned char)c);
      else if (e == 'w') hit = isalnum((unsigned char)c) || c == '_';
      else if (e == 's') hit = (c == ' ' || c == '\t' || c == '\n' || c == '\r');
      else if (esc >= 0) hit = ((unsigned char)c == (unsigned char)esc);
      else hit = icase ? (tolower((unsigned char)c) == tolower((unsigned char)e)) : (c == e);
      if (hit) return 1;
      i++;
      continue;
    }
    if (i + 2 < plen && p[i + 1] == '-') {
      unsigned char lo = (unsigned char)p[i], hi = (unsigned char)p[i + 2];
      unsigned char v = (unsigned char)c;
      if (icase) { lo = (unsigned char)tolower(lo); hi = (unsigned char)tolower(hi);
                   v = (unsigned char)tolower(v); }
      if (v >= lo && v <= hi) return 1;
      i += 2;
      continue;
    }
    if (icase ? (tolower((unsigned char)c) == tolower((unsigned char)p[i])) : (c == p[i])) return 1;
  }
  return 0;
}

/* ================= 解析 ================= */
typedef struct { rx_pattern *re; const char *p; int depth; } parser_t;

static rx_seq *parse_alt(parser_t *ps);

static rx_seq *parse_seq(parser_t *ps) {
  if (ps->depth++ > RX_MAX_DEPTH) { set_error(ps->re, "分组嵌套过深"); return NULL; }
  rx_seq *s = seq_new();
  if (!s) { set_error(ps->re, "内存不足"); return NULL; }
  while (*ps->p && *ps->p != ')' && *ps->p != '|') {
    rx_pattern *re = ps->re;
    char c = *ps->p;
    int idx = -1;

    if (c == '.') { ps->p++; idx = node_add(re, N_ANY); }
    else if (c == '^') { ps->p++; idx = node_add(re, N_ANCHOR_S); }
    else if (c == '$') { ps->p++; idx = node_add(re, N_ANCHOR_E); }
    else if (c == '\\') {
      if (!ps->p[1]) { set_error(re, "正则以 \\ 结尾"); seq_free(s); return NULL; }
      char e = ps->p[1];
      ps->p += 2;
      if (e == 'd' || e == 'w' || e == 's') {
        idx = node_add(re, N_CLASS);
        if (idx >= 0) re->nodes[idx].ch = e;
      } else {
        int esc = escape_char(e);
        idx = node_add(re, N_CHAR);
        if (idx >= 0) re->nodes[idx].ch = (esc >= 0) ? (char)esc : e;
      }
    } else if (c == '[') {
      const char *start = ps->p + 1;
      int neg = 0;
      if (*start == '^') { neg = 1; start++; }
      const char *q = start;
      while (*q && *q != ']') { if (*q == '\\' && q[1]) q++; q++; }
      if (*q != ']') { set_error(re, "字符类缺少 ]"); seq_free(s); return NULL; }
      idx = node_add(re, N_CLASS);
      if (idx >= 0) {
        re->nodes[idx].cls_start = (int)(start - re->pat);
        re->nodes[idx].cls_len = (int)(q - start);
        re->nodes[idx].cls_neg = neg;
      }
      ps->p = q + 1;
    } else if (c == '(') {
      ps->p++;
      if (strncmp(ps->p, "?:", 2) == 0) ps->p += 2;
      else if (strncmp(ps->p, "?i)", 3) == 0) { re->icase = 1; ps->p += 3; }
      else if (strncmp(ps->p, "?<![0-9])", 9) == 0) { ps->p += 9; idx = node_add(re, N_LOOKBEHIND_NOT_DIGIT); }
      else if (strncmp(ps->p, "?![0-9])", 8) == 0) { ps->p += 8; idx = node_add(re, N_LOOKAHEAD_NOT_DIGIT); }
      else if (ps->p[0] == '?') {
        set_error(re, "不支持这种 (?...) 写法(只认 (?i) (?<![0-9]) (?![0-9]) (?: )");
        seq_free(s);
        return NULL;
      } else {
        rx_seq *inner = parse_alt(ps);
        if (!inner) { seq_free(s); return NULL; }
        if (*ps->p == ')') ps->p++;
        else { seq_free(inner); set_error(re, "分组缺少 )"); seq_free(s); return NULL; }
        idx = node_add(re, N_GROUP);
        if (idx >= 0) re->nodes[idx].seq = inner;
        else seq_free(inner);
      }
    } else {
      ps->p++;
      idx = node_add(re, N_CHAR);
      if (idx >= 0) re->nodes[idx].ch = c;
    }

    if (idx < 0) { seq_free(s); return NULL; }

    /* 量词 */
    char q = *ps->p;
    int min = 1, max = 1, has_q = 0;
    if (q == '*') { min = 0; max = 1 << 20; ps->p++; has_q = 1; }
    else if (q == '+') { min = 1; max = 1 << 20; ps->p++; has_q = 1; }
    else if (q == '?') { min = 0; max = 1; ps->p++; has_q = 1; }
    else if (q == '{') {
      const char *r = ps->p + 1;
      if (isdigit((unsigned char)*r)) {
        int lo = atoi(r), hi = lo;
        while (*r && *r != '}') { if (*r == ',') { hi = atoi(r + 1); if (!hi) hi = 1 << 20; } r++; }
        if (*r != '}') { set_error(re, "量词缺少 }"); seq_free(s); return NULL; }
        min = lo; max = hi; ps->p = r + 1; has_q = 1;
      }
    }
    if (has_q) {
      if (max > RX_MAX_STEPS) max = RX_MAX_STEPS;
      re->nodes[idx].min = min;
      re->nodes[idx].max = max;
    }
    if (!seq_push(s, idx)) { set_error(re, "内存不足"); seq_free(s); return NULL; }
  }
  ps->depth--;
  return s;
}

static rx_seq *parse_alt(parser_t *ps) {
  rx_seq *first = parse_seq(ps);
  if (!first) return NULL;
  if (*ps->p != '|') return first;

  rx_pattern *re = ps->re;
  rx_seq **alts = (rx_seq **)calloc(1, sizeof(rx_seq *));
  if (!alts) { seq_free(first); set_error(re, "内存不足"); return NULL; }
  int n = 0;
  alts[n++] = first;
  while (*ps->p == '|') {
    ps->p++;
    rx_seq *next = parse_seq(ps);
    if (!next) break;
    rx_seq **tmp = (rx_seq **)realloc(alts, sizeof(rx_seq *) * (size_t)(n + 1));
    if (!tmp) { seq_free(next); break; }
    alts = tmp;
    alts[n++] = next;
  }
  int idx = node_add(re, N_ALT);
  if (idx < 0) {
    for (int i = 0; i < n; i++) seq_free(alts[i]);
    free(alts);
    return NULL;
  }
  re->nodes[idx].alts = alts;
  re->nodes[idx].alt_n = n;
  rx_seq *holder = seq_new();
  if (!holder) return NULL;
  seq_push(holder, idx);
  return holder;
}

/* ================= 释放 ================= */
static void seq_free_owned(rx_pattern *re, rx_seq *s) {
  (void)re;
  seq_free(s);
}

void rx_free(rx_pattern *re) {
  if (!re) return;
  for (int i = 0; i < re->n; i++) {
    if (re->nodes[i].kind == N_GROUP && re->nodes[i].seq) {
      seq_free_owned(re, re->nodes[i].seq);
    } else if (re->nodes[i].kind == N_ALT) {
      for (int k = 0; k < re->nodes[i].alt_n; k++) seq_free_owned(re, re->nodes[i].alts[k]);
      free(re->nodes[i].alts);
    }
  }
  if (re->top) seq_free_owned(re, re->top);
  free(re->nodes);
  free(re->pat);
  free(re);
}

/* ================= 匹配 ================= */
static int seq_match(const rx_pattern *re, const rx_seq *s, int si, const char *text, int pos);

/* 匹配"一次"该节点(不含量词的重复) */
static int node_once(const rx_pattern *re, int idx, const char *text, int pos) {
  const rx_node *n = &re->nodes[idx];
  char c = text[pos];
  switch (n->kind) {
    case N_CHAR:
      if (!c) return -1;
      if (re->icase ? (tolower((unsigned char)c) == tolower((unsigned char)n->ch))
                    : (c == n->ch)) return pos + 1;
      return -1;
    case N_ANY:
      if (!c || c == '\n') return -1;
      return pos + 1;
    case N_CLASS: {
      if (!c) return -1;
      int hit;
      if (n->cls_len == 0 && (n->ch == 'd' || n->ch == 'w' || n->ch == 's')) {
        if (n->ch == 'd') hit = isdigit((unsigned char)c);
        else if (n->ch == 'w') hit = isalnum((unsigned char)c) || c == '_';
        else hit = (c == ' ' || c == '\t' || c == '\n' || c == '\r');
      } else {
        hit = class_match(re->pat + n->cls_start, n->cls_len, c, re->icase);
      }
      if (n->cls_neg ? hit : !hit) return -1;
      return pos + 1;
    }
    case N_GROUP:
      return seq_match(re, n->seq, 0, text, pos);
    case N_ANCHOR_S:
      return (pos == 0) ? pos : -1;
    case N_ANCHOR_E:
      return (text[pos] == 0) ? pos : -1;
    case N_LOOKBEHIND_NOT_DIGIT:
      return (pos > 0 && isdigit((unsigned char)text[pos - 1])) ? -1 : pos;
    case N_LOOKAHEAD_NOT_DIGIT:
      return isdigit((unsigned char)text[pos]) ? -1 : pos;
    case N_ALT: {
      for (int k = 0; k < n->alt_n; k++) {
        int r = seq_match(re, n->alts[k], 0, text, pos);
        if (r >= 0) return r;
      }
      return -1;
    }
    default:
      return -1;
  }
}

/* 节点 + 量词:先贪婪收集所有可能的结束位置,再从长到短回溯 */
static int node_match(const rx_pattern *re, int idx, const rx_seq *s, int si,
                      const char *text, int pos) {
  const rx_node *n = &re->nodes[idx];
  int min = n->min > 0 ? n->min : 0;
  int max = n->max > 0 ? n->max : 1;
  int ends[RX_MAX_STEPS + 2];
  int cnt = 0;
  int cur = pos;
  ends[cnt++] = cur;
  for (int k = 0; k < max && cnt <= RX_MAX_STEPS; k++) {
    int e = node_once(re, idx, text, cur);
    if (e < 0) break;
    ends[cnt++] = e;
    if (e == cur) break;                 /* 零宽节点:重复没有意义 */
    cur = e;
  }
  for (int k = cnt - 1; k >= min; k--) {
    int r = seq_match(re, s, si + 1, text, ends[k]);
    if (r >= 0) return r;
  }
  return -1;
}

static int seq_match(const rx_pattern *re, const rx_seq *s, int si, const char *text, int pos) {
  if (!s || si >= s->n) return pos;
  return node_match(re, s->items[si], s, si, text, pos);
}

int rx_search(const rx_pattern *re, const char *text, int *out_off, int *out_len) {
  if (!re || !text || !re->top) return 0;
  for (int i = 0; ; i++) {
    int end = seq_match(re, re->top, 0, text, i);
    if (end >= 0) {
      if (out_off) *out_off = i;
      if (out_len) *out_len = end - i;
      return 1;
    }
    if (!text[i]) break;
  }
  return 0;
}

rx_pattern *rx_compile(const char *pattern, char *err, size_t err_cap) {
  if (err && err_cap) err[0] = 0;
  if (!pattern) return NULL;
  rx_pattern *re = (rx_pattern *)calloc(1, sizeof(rx_pattern));
  if (!re) return NULL;
  re->pat = strdup(pattern);
  if (!re->pat) { free(re); return NULL; }

  parser_t ps;
  ps.re = re;
  ps.p = re->pat;
  ps.depth = 0;
  if (strncmp(ps.p, "(?i)", 4) == 0) { re->icase = 1; ps.p += 4; }
  rx_seq *top = parse_alt(&ps);
  if (!top || re->errmsg[0] || *ps.p) {
    if (top) seq_free_owned(re, top);
    if (err && err_cap) {
      snprintf(err, err_cap, "%s", re->errmsg[0] ? re->errmsg
                             : (*ps.p ? "正则尾部有未配对的内容" : "正则语法错误"));
    }
    rx_free(re);
    return NULL;
  }
  re->top = top;
  return re;
}

int rx_find(const char *pattern, const char *text, int *out_off, int *out_len,
            char *err, size_t err_cap) {
  rx_pattern *re = rx_compile(pattern, err, err_cap);
  if (!re) return 0;
  int hit = rx_search(re, text, out_off, out_len);
  rx_free(re);
  return hit;
}