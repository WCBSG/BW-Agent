/* rules_domains.cpp —— 规则的 6 个域:定义、生成、读取、保存。
 *
 * 一份规则里 20 个顶层键,按"谁在用、谁负责"归成 6 域(见下)。这个表是唯一事实来源:
 * 界面按它分组、保存按它校验、拆文件按它落盘 —— 三处不会再各写一份清单然后走偏。
 */
#include "rules_domains.h"

#include "res.h"
#include "rules.h"

/* ---------- 域的划分 ----------
   注意:order 有意义 —— 界面按这个顺序排,读起来是"先定口径,再看探测,最后告警"。 */
static const rules_domain_t g_domains[] = {
    {"detect", "检测口径", "detect.json",
     "版本、严重等级、内容特征、响应头、注入载荷、弱口令:判什么、按什么等级算"},
    {"sensitive", "敏感信息", "sensitive.json",
     "正文里出现即命中的识别规则(内置正则方言)"},
    {"probe", "探测参数", "probe.json",
     "每轮探多少、等多久,以及会去尝试的落点与目录"},
    {"alert", "告警与推送", "alert.json",
     "什么等级进告警、走哪个渠道"},
    {"org", "单位口径", "org.json",
     "本单位的关键词、文件类型、版本泄露头、错误回显与可疑域名后缀"},
    {"page", "页面与篡改", "page.json",
     "目录索引与口令字段的标记,以及外链数量阈值"},
};

static const int g_domain_count = (int)(sizeof(g_domains) / sizeof(g_domains[0]));

/* 每个域收哪些顶层键。表的顺序也决定了写文件时键的先后(人读起来稳定) */
typedef struct {
  const char *domain;
  const char *keys[8];      /* 以 NULL 结尾 */
} domain_keys_t;

static const domain_keys_t g_keys[] = {
    {"detect",
     {"version", "note", "severity_levels", "signatures", "weak_headers", "payloads",
      "weak_passwords", NULL}},
    {"sensitive", {"patterns", NULL}},
    {"probe", {"probing", "sensitive_paths", "dir_candidates", NULL}},
    {"alert", {"alerts", NULL}},
    {"org",
     {"profile_keywords", "profile_file_types", "server_header_keys", "error_signatures",
      "dangerous_methods", "suspicious_tlds", NULL}},
    {"page", {"markers", "tamper", NULL}},
};

static const char *const *keys_of(const char *id) {
  for (size_t i = 0; i < sizeof(g_keys) / sizeof(g_keys[0]); i++) {
    if (str_ieq(g_keys[i].domain, id)) return g_keys[i].keys;
  }
  return NULL;
}

int rules_domain_count(void) { return g_domain_count; }

const rules_domain_t *rules_domain_at(int i) {
  return (i >= 0 && i < g_domain_count) ? &g_domains[i] : NULL;
}

const rules_domain_t *rules_domain_find(const char *id) {
  if (!id || !*id) return NULL;
  for (int i = 0; i < g_domain_count; i++) {
    if (str_ieq(g_domains[i].id, id)) return &g_domains[i];
  }
  return NULL;
}

const rules_domain_t *rules_domain_of_key(const char *key) {
  if (!key || !*key) return NULL;
  for (int i = 0; i < g_domain_count; i++) {
    const char *const *keys = keys_of(g_domains[i].id);
    for (int k = 0; keys && keys[k]; k++) {
      if (strcmp(keys[k], key) == 0) return &g_domains[i];
    }
  }
  return NULL;
}

void rules_domain_dir(char *out, size_t cap) {
  if (!out || cap == 0) return;
  app_data_path(out, cap, "rules");
}

static void domain_path(const char *file, char *out, size_t cap) {
  char dir[MAX_PATH * 2];
  rules_domain_dir(dir, sizeof(dir));
  path_join(out, cap, dir, file);
}

/* 深拷贝:j_set 接管所有权,直接塞同一个节点会被释放两次 */
static json_t *copy_node(json_t *v) {
  if (!v) return NULL;
  char *dump = json_dump(v);
  if (!dump) return NULL;
  json_t *cp = json_parse(dump);
  free(dump);
  return cp;
}

/* 出厂规则:直接读 mkres 打包进来的分域文件 data/rules/<file>.json。
 * 这样仓库里只有这 6 个文件 —— 不再有一份"大 rules.json"和它们并存,
 * 也就不会出现"同一个键两处都有值、到底哪份生效"的解释不清。 */
static json_t *factory_domain(const char *id, char *err, size_t errcap) {
  const rules_domain_t *d = rules_domain_find(id);
  if (!d) {
    if (err) snprintf(err, errcap, "不认识的规则域:%s", id ? id : "");
    return NULL;
  }
  char res[128];
  snprintf(res, sizeof(res), "data/rules/%s", d->file);
  size_t len = 0;
  char *text = NULL;
  if (!res_load_text(res, &text, &len) || !text) {
    if (err) snprintf(err, errcap, "exe 内置的出厂规则读不到(%s)", res);
    free(text);
    return NULL;
  }
  json_t *raw = json_parse(text);
  free(text);
  if (!raw) {
    if (err) snprintf(err, errcap, "出厂规则 %s 不是合法 JSON", res);
    return NULL;
  }

  /* 只留这个域自己的键:文件里写错位置的键会被丢掉,而不是悄悄生效 */
  const char *const *keys = keys_of(id);
  json_t *dom = j_obj();
  for (int i = 0; keys && keys[i]; i++) {
    json_t *v = j_get(raw, keys[i]);
    if (!v) continue;
    json_t *cp = copy_node(v);
    if (cp) j_set(dom, keys[i], cp);
  }
  json_free(raw);
  return dom;
}

/* 出厂规则的完整视图(6 个域拼起来)。规则层用它当"双层查找"的第二层。 */
json_t *rules_domains_factory(void) {
  json_t *all = j_obj();
  for (int i = 0; i < g_domain_count; i++) {
    json_t *dom = factory_domain(g_domains[i].id, NULL, 0);
    if (!dom) continue;
    for (int k = 0; k < dom->count; k++) {
      json_t *v = j_get(dom, dom->keys[k]);
      json_t *cp = copy_node(v);
      if (cp) j_set(all, dom->keys[k], cp);
    }
    json_free(dom);
  }
  return all;
}

static int write_domain_file(const char *id, json_t *dom, char *err, size_t errcap) {
  const rules_domain_t *d = rules_domain_find(id);
  if (!d) {
    if (err) snprintf(err, errcap, "不认识的规则域:%s", id ? id : "");
    return -1;
  }
  char dir[MAX_PATH * 2], path[MAX_PATH * 4];
  rules_domain_dir(dir, sizeof(dir));
  ensure_dir(dir);
  domain_path(d->file, path, sizeof(path));
  char *text = json_dump_pretty(dom);
  if (!text) {
    if (err) snprintf(err, errcap, "生成 %s 的内容失败", d->file);
    return -1;
  }
  int rc = file_write_all(path, text, strlen(text));
  free(text);
  if (rc != 0) {
    if (err) snprintf(err, errcap, "%s 写入失败(检查是否被别的程序占用)", path);
    return -1;
  }
  return 0;
}

int rules_domains_generate(char *err, size_t errcap) {
  if (err && errcap) err[0] = 0;
  char dir[MAX_PATH * 2], path[MAX_PATH * 4];
  rules_domain_dir(dir, sizeof(dir));
  ensure_dir(dir);

  int made = 0;
  for (int i = 0; i < g_domain_count; i++) {
    domain_path(g_domains[i].file, path, sizeof(path));
    if (file_size(path) >= 0) continue;          /* 已经有了就不动 */
    json_t *dom = factory_domain(g_domains[i].id, err, errcap);
    if (!dom) return -1;
    int rc = write_domain_file(g_domains[i].id, dom, err, errcap);
    json_free(dom);
    if (rc != 0) return -1;
    made++;
  }
  return made;
}

json_t *rules_domains_load_merged(char *err, size_t errcap) {
  if (err && errcap) err[0] = 0;
  /* 起点用出厂规则:某个域文件缺了,也不会让检测凭空失效 */
  json_t *merged = rules_domains_factory();
  if (!merged) merged = j_obj();

  for (int i = 0; i < g_domain_count; i++) {
    char path[MAX_PATH * 4];
    domain_path(g_domains[i].file, path, sizeof(path));
    size_t len = 0;
    char *text = file_read_all(path, &len);
    if (!text) continue;
    json_t *dom = json_parse(text);
    free(text);
    if (!dom) {
      /* 单个域写坏了不该让整份规则失效:跳过它,用出厂值 */
      log_warn("[规则] %s 解析失败,这一域暂用出厂值", path);
      continue;
    }
    const char *const *keys = keys_of(g_domains[i].id);
    for (int k = 0; keys && keys[k]; k++) {
      json_t *v = j_get(dom, keys[k]);
      if (!v) continue;
      json_t *cp = copy_node(v);
      if (cp) j_set(merged, keys[k], cp);
    }
    json_free(dom);
  }
  return merged;
}

json_t *rules_domains_read(const char *id, char *err, size_t errcap) {
  if (err && errcap) err[0] = 0;
  const rules_domain_t *d = rules_domain_find(id);
  if (!d) {
    if (err) snprintf(err, errcap, "不认识的规则域:%s", id ? id : "");
    return NULL;
  }
  char dir[MAX_PATH * 2], path[MAX_PATH * 4];
  rules_domain_dir(dir, sizeof(dir));
  ensure_dir(dir);
  domain_path(d->file, path, sizeof(path));

  size_t len = 0;
  char *text = file_read_all(path, &len);
  if (!text) {
    /* 文件还没生成:直接给出厂值,别让界面空着 */
    return factory_domain(id, err, errcap);
  }
  json_t *dom = json_parse(text);
  free(text);
  if (!dom) {
    if (err) snprintf(err, errcap, "%s 的 JSON 写坏了(先修好或删掉它,程序会重新生成)", d->file);
    return NULL;
  }
  return dom;
}

int rules_domains_save(const char *id, json_t *patch, char *err, size_t errcap) {
  if (err && errcap) err[0] = 0;
  const rules_domain_t *d = rules_domain_find(id);
  if (!d) {
    if (err) snprintf(err, errcap, "不认识的规则域:%s", id ? id : "");
    return -1;
  }
  if (!patch || patch->type != J_OBJ) {
    if (err) snprintf(err, errcap, "需要 %s 这一个域的对象", id);
    return -1;
  }

  /* 以现有内容为底:界面只改几个字段时,没提交的键不该被抹掉 */
  json_t *dom = rules_domains_read(id, err, errcap);
  if (!dom) return -1;

  const char *const *keys = keys_of(id);
  int touched = 0;
  for (int k = 0; keys && keys[k]; k++) {
    json_t *v = j_get(patch, keys[k]);
    if (!v) continue;
    json_t *cp = copy_node(v);
    if (!cp) continue;
    j_set(dom, keys[k], cp);          /* j_set 接管所有权,同键会被替换 */
    touched++;
  }
  if (touched == 0) {
    json_free(dom);
    if (err) snprintf(err, errcap, "提交的内容里没有属于「%s」的字段", d->title);
    return -1;
  }
  int rc = write_domain_file(id, dom, err, errcap);
  json_free(dom);
  return rc;
}

int rules_domains_save_all(json_t *root, char *err, size_t errcap) {
  if (err && errcap) err[0] = 0;
  if (!root || root->type != J_OBJ) {
    if (err) snprintf(err, errcap, "需要 rules 对象");
    return -1;
  }
  for (int i = 0; i < g_domain_count; i++) {
    json_t *dom = j_obj();
    const char *const *keys = keys_of(g_domains[i].id);
    for (int k = 0; keys && keys[k]; k++) {
      json_t *v = j_get(root, keys[k]);
      if (!v) continue;
      json_t *cp = copy_node(v);
      if (cp) j_set(dom, keys[k], cp);
    }
    if (j_len(dom) == 0) { json_free(dom); continue; }   /* 这一域没内容:不动它 */
    int rc = write_domain_file(g_domains[i].id, dom, err, errcap);
    json_free(dom);
    if (rc != 0) return -1;
  }
  return 0;
}
