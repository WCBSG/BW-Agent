/* rules.cpp —— 规则层实现:data/rules.json 优先,读不到就用内置通用默认规则。
 *
 * 关键设计:内置默认规则本身就是一段 JSON 文本,和外部文件**同一套 schema**,
 * 所以只有一条代码路径 —— 不会出现"内置一套逻辑、外部一套逻辑"的分叉。
 */
#include "rules.h"

#include "res.h"
#include "rules_domains.h"

#include <cctype>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

static json_t *g_root = NULL;
static char g_source[512] = {0};
static int g_from_file = 0;

/* ---------- 载入 ----------
   生效规则 = 数据目录 rules\ 的 6 个域文件;
   某域缺失或写坏时,该域的键回落到 exe 内置的出厂规则(rules_lookup 双层查找)。 */
static json_t *g_factory = NULL;        /* 出厂规则(内置数据,双层查找的第二层) */
static char *g_factory_text = NULL;
void rules_init(const char *base_dir) {
  (void)base_dir;
  if (g_root) return;

  /* 出厂规则 = exe 内置的 6 个域文件 */
  if (!g_factory && res_load_text("data/rules.json", &g_factory_text, NULL)) {
    g_factory = json_parse(g_factory_text);
    if (g_factory) {
      log_debug("[规则] 出厂规则已载入(%d 字节)", (int)strlen(g_factory_text));
    }
  }

  /* 数据目录 rules\ 的 6 个域文件;缺的按出厂规则生成 */
  {
    char err[256] = {0};
    int made = rules_domains_generate(err, sizeof(err));
    if (made < 0) log_warn("[规则] 分域规则生成失败:%s", err[0] ? err : "未知原因");
    else if (made > 0) log_info("[规则] 已在数据目录生成 %d 个分域规则文件(rules\\)", made);

    char *merr = NULL;
    json_t *merged = rules_domains_load_merged(NULL, 0);
    if (merged) {
      g_root = merged;
      char dir[MAX_PATH * 2];
      rules_domain_dir(dir, sizeof(dir));
      snprintf(g_source, sizeof(g_source), "%s\\*.json", dir);
      g_from_file = 1;
      log_info("[规则] 已载入分域规则 %s\\(%d 个域)", dir, rules_domain_count());
      return;
    }
    (void)merr;
  }
  /* ② 没读到分域文件时用出厂规则 */
  if (g_factory) {
    g_root = json_parse(g_factory_text);     /* 生效的那份要是独立副本,免得被改动 */
    g_from_file = 0;
    snprintf(g_source, sizeof(g_source),
             "exe 内置规则(自带;数据目录的 rules\\ 分域文件会覆盖它)");
    log_info("[规则] 使用 exe 内置规则(%d 字节)", (int)strlen(g_factory_text));
  }
}

/* ---------- 字符串数组(借出,懒加载缓存) ----------
   原来这里是"定长 8 槽"的 C 数组,超过就静默 return NULL —— 实际有 9 个键在用,
   第 9 个(通常是 weak_passwords)会被当成"没有条目",弱口令检测悄悄失效。
   换成 unordered_map 后上限不存在;每个条目自己持有两份数据:
     · owned : std::vector<std::string>,拥有字符串本体
     · view  : std::vector<const char*>,借给调用方(缓冲区稳定,不随扩容失效)
   对外签名仍是 const char **,调用方的代码一行都不用改。 */
struct rules_list_t {
  std::vector<std::string> owned;
  std::vector<const char *> view;
  int count = 0;
};
static std::unordered_map<std::string, rules_list_t> g_lists;

void rules_shutdown(void) {
  json_free(g_root);
  g_root = NULL;
  json_free(g_factory);
  g_factory = NULL;
  free(g_factory_text);
  g_factory_text = NULL;
  /* 数组缓存也要清:否则热加载后会继续用"旧规则"的缓存 */
  g_lists.clear();
  g_source[0] = 0;
  g_from_file = 0;
}

const char *rules_source(void) { return g_source; }
int rules_from_file(void) { return g_from_file; }
json_t *rules_root(void) { return g_root; }
/* 出厂规则的 JSON 文本(导出给使用者照着改:它就是我们内置的那一份) */
const char *rules_default_json(void) {
  return g_factory_text ? g_factory_text : "{\"version\":\"1\"}";
}

/* ---------- 双层查找:先生效规则,再出厂规则 ---------- */
static json_t *rules_lookup(const char *path) {
  json_t *v = (g_root && path) ? j_path(g_root, path) : NULL;
  if (!v && g_factory && path) v = j_path(g_factory, path);
  return v;
}

/* ---------- 字符串数组(借出,懒加载缓存) ---------- */
const char **rules_str_list(const char *key, int *count) {
  if (count) *count = 0;
  if (!key) return NULL;

  auto it = g_lists.find(key);
  if (it != g_lists.end()) {
    if (count) *count = it->second.count;
    return it->second.view.data();
  }

  json_t *arr = rules_lookup(key);
  if (!arr || arr->type != J_ARR) return NULL;

  rules_list_t entry;
  entry.count = j_len(arr);
  entry.owned.reserve((size_t)entry.count);
  for (int i = 0; i < entry.count; i++) {
    json_t *node = j_at(arr, i);
    entry.owned.emplace_back(node && node->type == J_STR ? node->str : "");
  }
  entry.view.reserve(entry.owned.size());
  for (const std::string &s : entry.owned) entry.view.push_back(s.c_str());

  auto res = g_lists.emplace(key, std::move(entry));
  if (count) *count = res.first->second.count;
  return res.first->second.view.data();
}

/* ---------- 通用数组读法(结构化的那几段配置) ----------
   rules.json 里长这样:
     "patterns": { "sensitive": [ {"kind":"身份证","pattern":"...","severity":"严重"}, ... ] }
   用法:rules_arr_count("patterns.sensitive") / rules_arr_str(..., i, "pattern", "")
   同样走双层查找:生效规则里没有这一项就用出厂值。 */
int rules_arr_count(const char *path) {
  json_t *arr = rules_lookup(path);
  return (arr && arr->type == J_ARR) ? j_len(arr) : 0;
}

const char *rules_arr_str(const char *path, int index, const char *field, const char *def) {
  json_t *arr = rules_lookup(path);
  json_t *it = (arr && arr->type == J_ARR) ? j_at(arr, index) : NULL;
  if (!it) return def;
  if (!field || !*field) return (it->type == J_STR) ? it->str : def;
  json_t *v = j_get(it, field);
  return (v && v->type == J_STR) ? v->str : def;
}

double rules_arr_num(const char *path, int index, const char *field, double def) {
  json_t *arr = rules_lookup(path);
  json_t *it = (arr && arr->type == J_ARR) ? j_at(arr, index) : NULL;
  if (!it) return def;
  json_t *v = field && *field ? j_get(it, field) : it;
  if (!v) return def;
  if (v->type == J_NUM) return v->num;
  if (v->type == J_BOOL) return v->b ? 1 : 0;
  return def;
}

/* 严重度排序:等级名 → 序号(严重 4 / 高 3 …)。等级表在规则里(severity_levels),
   所以单位可以自己改叫法或加等级,不用动代码。 */
int rules_severity_rank(const char *name, int def) {
  if (!name) return def;
  int n = rules_arr_count("severity_levels");
  for (int i = 0; i < n; i++) {
    const char *lv = rules_arr_str("severity_levels", i, "name", "");
    if (lv[0] && strcmp(lv, name) == 0) {
      return (int)rules_arr_num("severity_levels", i, "rank", def);
    }
  }
  return def;
}

/* 取一个字符串配置项(支持点号路径,如 alerts.channel_immediate;双层查找) */
const char *rules_text(const char *path, const char *def) {
  json_t *v = rules_lookup(path);
  if (v && v->type == J_STR && v->str[0]) return v->str;
  return def;
}

static double rules_num_raw(const char *key, double fallback) {
  char path[128];
  snprintf(path, sizeof(path), "probing.%s", key);
  json_t *v = rules_lookup(path);
  if (!v) v = rules_lookup(key);
  return (v && v->type == J_NUM) ? v->num : fallback;
}

double rules_number(const char *key, double fallback) {
  return rules_num_raw(key, fallback);
}

int rules_flag(const char *key, int fallback) {
  json_t *v = rules_lookup(key);
  return (v && v->type == J_BOOL) ? v->b : fallback;
}

/* ---------- 内容特征匹配 ---------- */
/* 忽略大小写的后缀/前缀判断(文件名大小写在不同系统上不一定一致) */
static int ends_icase(const char *s, const char *suffix) {
  size_t ls = strlen(s), lf = strlen(suffix);
  if (lf > ls) return 0;
  return str_ieq(s + (ls - lf), suffix);
}

static int starts_icase(const char *s, const char *prefix) {
  for (size_t i = 0; prefix[i]; i++) {
    if (!s[i]) return 0;
    if (tolower((unsigned char)s[i]) != tolower((unsigned char)prefix[i])) return 0;
  }
  return 1;
}

static int str_in_list_icase(const char *s, json_t *arr, const char **matched) {
  for (int i = 0; i < j_len(arr); i++) {
    json_t *it = j_at(arr, i);
    if (!it || it->type != J_STR) continue;
    if (str_icontains(s, it->str)) {
      if (matched) *matched = it->str;
      return 1;
    }
  }
  return 0;
}

static int suffix_in_list_icase(const char *s, json_t *arr) {
  for (int i = 0; i < j_len(arr); i++) {
    json_t *it = j_at(arr, i);
    if (!it || it->type != J_STR) continue;
    if (ends_icase(s, it->str)) return 1;
  }
  return 0;
}

static int prefix_in_list_icase(const char *s, json_t *arr, const char **matched) {
  for (int i = 0; i < j_len(arr); i++) {
    json_t *it = j_at(arr, i);
    if (!it || it->type != J_STR) continue;
    if (starts_icase(s, it->str)) {
      if (matched) *matched = it->str;
      return 1;
    }
  }
  return 0;
}

int rules_sig_match(const char *path, const char *body, rules_sig_t *out) {
  if (!g_root) return -1;
  json_t *sigs = rules_lookup("signatures");
  const char *text = body ? body : "";
  size_t bytes = strlen(text);
  /* "这是不是一个 HTML 页面"只取前 4KB 判断就够 */
  char head[4096];
  size_t hn = bytes < sizeof(head) - 1 ? bytes : sizeof(head) - 1;
  memcpy(head, text, hn);
  head[hn] = 0;

  for (int i = 0; i < j_len(sigs); i++) {
    json_t *s = j_at(sigs, i);
    if (!s || s->type != J_OBJ) continue;

    json_t *minb = j_get(s, "min_bytes");
    if (minb && minb->type == J_NUM && (double)bytes < minb->num) continue;

    json_t *not_any = j_get(s, "body_not_any");
    if (not_any && not_any->type == J_ARR && not_any->count > 0) {
      if (str_in_list_icase(head, not_any, NULL)) continue;
    }

    json_t *psuf = j_get(s, "path_suffix_any");
    if (psuf && psuf->type == J_ARR) {
      if (!path || !suffix_in_list_icase(path, psuf)) continue;
    }
    json_t *pcon = j_get(s, "path_contains_any");
    if (pcon && pcon->type == J_ARR) {
      if (!path || !str_in_list_icase(path, pcon, NULL)) continue;
    }

    const char *hit = NULL;
    json_t *pany = j_get(s, "body_any");
    if (pany && pany->type == J_ARR) {
      if (!str_in_list_icase(text, pany, &hit)) continue;
    }
    json_t *ppre = j_get(s, "body_prefix_any");
    if (ppre && ppre->type == J_ARR) {
      char small[64];
      size_t sn = bytes < sizeof(small) - 1 ? bytes : sizeof(small) - 1;
      memcpy(small, text, sn);
      small[sn] = 0;
      const char *hs = str_trim(small);
      if (!prefix_in_list_icase(hs, ppre, &hit)) continue;
    }

    if (out) {
      out->name = j_s(s, "name", "未命名特征");
      out->kind = j_s(s, "kind", "敏感信息");
      out->severity = j_s(s, "severity", "中");
      out->tag = j_s(s, "tag", out->name);
      out->evidence = hit ? hit : "";
    }
    return 0;
  }
  return -1;
}

/* ---------- 弱配置期望头 ---------- */
int rules_weak_header_count(void) {
  if (!g_root) return 0;
  json_t *arr = rules_lookup("weak_headers");
  return (arr && arr->type == J_ARR) ? j_len(arr) : 0;
}

const char *rules_weak_header(int index, const char *field, const char *fallback) {
  if (!g_root) return fallback;
  json_t *arr = rules_lookup("weak_headers");
  json_t *it = j_at(arr, index);
  if (!it) return fallback;
  json_t *v = j_get(it, field);
  if (!v) return fallback;
  if (v->type == J_STR) return v->str;
  if (v->type == J_NUM) return fallback;      /* 数字用 rules_weak_header_num */
  return fallback;
}

int rules_weak_header_num(int index, const char *field, int fallback) {
  if (!g_root) return fallback;
  json_t *arr = rules_lookup("weak_headers");
  json_t *it = j_at(arr, index);
  json_t *v = it ? j_get(it, field) : NULL;
  return (v && v->type == J_NUM) ? (int)v->num : fallback;
}
