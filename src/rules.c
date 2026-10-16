/* rules.c —— 规则层实现:data/rules.json 优先,读不到就用内置通用默认规则。
 *
 * 关键设计:内置默认规则本身就是一段 JSON 文本,和外部文件**同一套 schema**,
 * 所以只有一条代码路径 —— 不会出现"内置一套逻辑、外部一套逻辑"的分叉。
 */
#include "rules.h"

#include "res.h"

#include <ctype.h>

static json_t *g_root = NULL;
static char g_source[512] = {0};
static int g_from_file = 0;
static char *g_default_text = NULL;      /* exe 内置规则文本(借出给 json_parse,退出时释放) */

/* ---------- 内置默认规则(通用,不含任何具体站点信息) ---------- */
static const char DEFAULT_RULES[] =
"{\n"
"  \"version\": \"1\",\n"
"  \"note\": \"站点知识全在这里:常见误发布路径、内容特征、期望的安全响应头、错误回显特征。\",\n"
"  \"probing\": {\n"
"    \"max_paths\": 40,\n"
"    \"max_dirs\": 40,\n"
"    \"max_params\": 3,\n"
"    \"timeout_ms\": 20000,\n"
"    \"similar_bytes\": 64,\n"
"    \"similar_ratio\": 0.06\n"
"  },\n"
"  \"sensitive_paths\": [\n"
"    \"/.env\", \"/.env.bak\", \"/.env.save\", \"/config/.env\", \"/portal/.env\",\n"
"    \"/.git/config\", \"/.git/HEAD\", \"/.svn/entries\", \"/.hg/hgrc\", \"/.DS_Store\",\n"
"    \"/backup.sql\", \"/db.sql\", \"/dump.sql\", \"/database.sql\", \"/www.sql\",\n"
"    \"/backup.zip\", \"/www.zip\", \"/web.zip\", \"/site.tar.gz\",\n"
"    \"/index.php.bak\", \"/config.php.bak\", \"/web.config.bak\", \"/config.yml.bak\",\n"
"    \"/application.yml\", \"/application.properties\", \"/config.json\", \"/.npmrc\",\n"
"    \"/phpinfo.php\", \"/info.php\", \"/WEB-INF/web.xml\", \"/META-INF/MANIFEST.MF\",\n"
"    \"/id_rsa\", \"/.ssh/id_rsa\", \"/private.key\", \"/error.log\", \"/debug.log\"\n"
"  ],\n"
"  \"dir_candidates\": [\n"
"    \"/uploads/\", \"/upload/\", \"/files/\", \"/download/\", \"/downloads/\",\n"
"    \"/backup/\", \"/bak/\", \"/db/\", \"/database/\", \"/data/\", \"/log/\", \"/logs/\",\n"
"    \"/temp/\", \"/tmp/\", \"/cache/\", \"/static/\", \"/assets/\", \"/public/\",\n"
"    \"/admin/\", \"/manage/\", \"/manager/\", \"/system/\", \"/console/\", \"/druid/\",\n"
"    \"/phpmyadmin/\", \"/adminer.php\", \"/wp-admin/\", \"/actuator/\", \"/swagger-ui.html\"\n"
"  ],\n"
"  \"signatures\": [\n"
"    {\"name\": \"配置文件泄露\", \"kind\": \"敏感信息\", \"severity\": \"严重\",\n"
"     \"tag\": \"config-secrets\",\n"
"     \"body_any\": [\"DB_PASSWORD=\", \"DB_HOST=\", \"DB_USER=\", \"REDIS_PASSWORD=\",\n"
"                  \"SECRET_KEY=\", \"APP_KEY=\", \"AWS_SECRET_ACCESS_KEY\"],\n"
"     \"body_not_any\": [\"<html\", \"<!doctype\"], \"min_bytes\": 20},\n"
"    {\"name\": \"数据库备份文件\", \"kind\": \"敏感信息\", \"severity\": \"严重\",\n"
"     \"tag\": \"sql-dump\",\n"
"     \"body_any\": [\"INSERT INTO\", \"CREATE TABLE\", \"DROP TABLE\", \"MySQL dump\",\n"
"                  \"PostgreSQL database dump\"],\n"
"     \"body_not_any\": [\"<html\", \"<!doctype\"], \"min_bytes\": 64},\n"
"    {\"name\": \"私钥文件\", \"kind\": \"敏感信息\", \"severity\": \"严重\",\n"
"     \"tag\": \"private-key\",\n"
"     \"body_any\": [\"BEGIN RSA PRIVATE KEY\", \"BEGIN PRIVATE KEY\",\n"
"                  \"BEGIN OPENSSH PRIVATE KEY\", \"BEGIN EC PRIVATE KEY\"]},\n"
"    {\"name\": \"版本库元数据\", \"kind\": \"敏感信息\", \"severity\": \"高\",\n"
"     \"tag\": \"vcs-metadata\",\n"
"     \"body_any\": [\"[core]\", \"repositoryformatversion\", \"ref: refs/\",\n"
"                  \"svn:wc:\", \"<wc-entries\"]},\n"
"    {\"name\": \"数据库连接配置\", \"kind\": \"敏感信息\", \"severity\": \"高\",\n"
"     \"tag\": \"db-uri\",\n"
"     \"body_any\": [\"jdbc:mysql\", \"jdbc:postgresql\", \"mongodb://\", \"redis://\",\n"
"                  \"mysql://\", \"postgres://\"],\n"
"     \"body_not_any\": [\"<html\", \"<!doctype\"], \"min_bytes\": 16},\n"
"    {\"name\": \"源码备份\", \"kind\": \"敏感信息\", \"severity\": \"高\", \"tag\": \"source-backup\",\n"
"     \"path_suffix_any\": [\".bak\", \".old\", \".orig\", \".save\", \".swp\", \".tmp\", \"~\"],\n"
"     \"body_any\": [\"<?php\", \"#include\", \"package \", \"<configuration\", \"function \"],\n"
"     \"min_bytes\": 64},\n"
"    {\"name\": \"归档文件\", \"kind\": \"敏感信息\", \"severity\": \"中\", \"tag\": \"archive\",\n"
"     \"body_prefix_any\": [\"PK\"], \"min_bytes\": 512},\n"
"    {\"name\": \"环境信息页\", \"kind\": \"敏感信息\", \"severity\": \"中\", \"tag\": \"phpinfo\",\n"
"     \"body_any\": [\"PHP Version =>\", \"<title>phpinfo()</title>\"]},\n"
"    {\"name\": \"日志文件\", \"kind\": \"敏感信息\", \"severity\": \"中\", \"tag\": \"log-file\",\n"
"     \"path_suffix_any\": [\".log\"],\n"
"     \"body_any\": [\"ERROR\", \"WARN\", \"Exception\", \"INFO \"], \"min_bytes\": 512},\n"
"    {\"name\": \"Java 应用配置清单\", \"kind\": \"敏感信息\", \"severity\": \"中\",\n"
"     \"tag\": \"java-web-config\", \"path_suffix_any\": [\"web.xml\", \"MANIFEST.MF\"],\n"
"     \"body_any\": [\"<web-app\", \"Manifest-Version\"]}\n"
"  ],\n"
"  \"weak_headers\": [\n"
"    {\"name\": \"strict-transport-security\", \"title\": \"未启用 HSTS\", \"severity\": \"中\",\n"
"     \"only_https\": 1,\n"
"     \"impact\": \"首次访问或证书异常时容易被降级劫持\",\n"
"     \"fix\": \"在 HTTPS 站点启用 HSTS 并设置合理的 max-age\"},\n"
"    {\"name\": \"content-security-policy\", \"title\": \"缺少内容安全策略(CSP)\", \"severity\": \"中\",\n"
"     \"impact\": \"对脚本注入缺少第二道拦截\",\n"
"     \"fix\": \"按业务梳理资源白名单后逐步启用 CSP\"},\n"
"    {\"name\": \"x-content-type-options\", \"title\": \"缺少 MIME 嗅探防护\", \"severity\": \"低\",\n"
"     \"impact\": \"浏览器可能把非脚本内容当脚本执行\",\n"
"     \"fix\": \"增加 X-Content-Type-Options: nosniff\"},\n"
"    {\"name\": \"x-frame-options\", \"title\": \"缺少点击劫持防护\", \"severity\": \"低\",\n"
"     \"impact\": \"页面可被第三方框架嵌入用于诱导点击\",\n"
"     \"fix\": \"增加 X-Frame-Options: SAMEORIGIN 或 CSP 的 frame-ancestors\"},\n"
"    {\"name\": \"referrer-policy\", \"title\": \"缺少引用来源策略\", \"severity\": \"信息\",\n"
"     \"impact\": \"外跳时可能把内部地址带出去\",\n"
"     \"fix\": \"增加 Referrer-Policy: strict-origin-when-cross-origin\"},\n"
"    {\"name\": \"permissions-policy\", \"title\": \"缺少浏览器特性策略\", \"severity\": \"信息\",\n"
"     \"impact\": \"摄像头、定位等浏览器特性未被约束\",\n"
"     \"fix\": \"按需增加 Permissions-Policy\"}\n"
"  ],\n"
"  \"profile_keywords\": [\"身份证\", \"内部文件\", \"测试账号\", \"数据库口令\"],\n"
"  \"profile_file_types\": [\".env\", \".sql\", \".bak\", \".zip\", \".log\", \".config\", \".yml\"],\n"
"  \"server_header_keys\": [\"server\", \"x-powered-by\", \"x-aspnet-version\",\n"
"                          \"x-aspnetmvc-version\", \"x-generator\", \"x-runtime\", \"via\"],\n"
"  \"error_signatures\": [\"sql syntax\", \"you have an error in your sql\",\n"
"                        \"warning: mysql\", \"mysqli_\", \"pg_query\", \"postgresql query failed\",\n"
"                        \"ora-0\", \"oracle error\", \"sqlite3_\", \"unclosed quotation mark\",\n"
"                        \"odbc sql server driver\", \"system.data.sqlclient\", \"jdbc.exception\",\n"
"                        \"traceback (most recent call last)\", \"fatal error:\", \"notice: undefined\",\n"
"                        \"warning: include\", \"microsoft ole db provider\"],\n"
"  \"dangerous_methods\": [\"PUT\", \"DELETE\", \"TRACE\", \"PATCH\", \"CONNECT\", \"COPY\", \"MOVE\"],\n"
"  \"suspicious_tlds\": [\".xyz\", \".top\", \".cc\", \".biz\", \".click\", \".work\", \".win\",\n"
"                       \".bid\", \".loan\", \".review\", \".gq\", \".cf\", \".tk\", \".ml\", \".su\"],\n"
"  \"tamper\": {\"report_external_hosts\": 8}\n"
"}\n";

/* ---------- 载入 ---------- */
/* 规则查找顺序(前面的优先):
     ① 数据目录里的 rules.json   —— 用户在 ~\.bw_agent\rules.json 里改,最直观
     ② exe 目录及其上级的 data\rules.json —— 源码仓库/绿色目录的放法
     ③ exe 内置的那一份          —— 单文件交付时的兜底
     ④ 编译进代码的默认规则      —— 最后兜底 */
static const char *CANDIDATES_REL[] = {"data\\rules.json", "..\\data\\rules.json",
                                       "..\\..\\data\\rules.json"};

void rules_init(const char *base_dir) {
  if (g_root) return;
  const char *base = (base_dir && *base_dir) ? base_dir : "";

  /* ① 数据目录 */
  char user_rules[MAX_PATH * 2];
  app_data_path(user_rules, sizeof(user_rules), "rules.json");
  {
    size_t len = 0;
    char *text = file_read_all(user_rules, &len);
    if (text) {
      json_t *j = json_parse(text);
      if (j && j_get(j, "signatures")) {
        g_root = j;
        g_from_file = 1;
        snprintf(g_source, sizeof(g_source), "%s", user_rules);
        log_info("[规则] 已载入 %s", user_rules);
        free(text);
        return;
      }
      json_free(j);
      log_warn("[规则] %s 解析失败或缺 signatures,继续找下一个", user_rules);
      free(text);
    }
  }

  /* ② exe 目录附近 */
  for (size_t i = 0; i < sizeof(CANDIDATES_REL) / sizeof(CANDIDATES_REL[0]) && !g_root; i++) {
    char path[MAX_PATH * 2];
    snprintf(path, sizeof(path), "%s%s", base, CANDIDATES_REL[i]);
    size_t len = 0;
    char *text = file_read_all(path, &len);
    if (!text) continue;
    json_t *j = json_parse(text);
    if (j && j_get(j, "signatures")) {
      g_root = j;
      g_from_file = 1;
      snprintf(g_source, sizeof(g_source), "%s", path);
      log_info("[规则] 已载入 %s", path);
    } else {
      json_free(j);
      log_warn("[规则] %s 解析失败或缺 signatures,继续找下一个", path);
    }
    free(text);
  }
  if (!g_root) {
    /* 磁盘上没有规则文件时,用 exe 内置的那一份(与出厂 data\rules.json 相同),
       这样单文件拷贝出去、旁边什么都没有,也能按完整定义工作。 */
    if (res_load_text("data/rules.json", &g_default_text, NULL)) {
      g_root = json_parse(g_default_text);
      if (g_root && j_get(g_root, "signatures")) {
        g_from_file = 0;
        snprintf(g_source, sizeof(g_source), "exe 内置规则(自带;在数据目录放 rules.json 即可覆盖)");
        log_info("[规则] 使用 exe 内置规则(%d 字节)", (int)strlen(g_default_text));
      } else {
        json_free(g_root);
        g_root = NULL;
      }
    }
  }
  if (!g_root) {
    g_root = json_parse(DEFAULT_RULES);
    g_from_file = 0;
    snprintf(g_source, sizeof(g_source), "内置默认规则(未找到外部规则文件)");
    log_info("[规则] 使用内置默认规则");
  }
}

void rules_shutdown(void) {
  json_free(g_root);
  g_root = NULL;
  free(g_default_text);
  g_default_text = NULL;
}

const char *rules_source(void) { return g_source; }
int rules_from_file(void) { return g_from_file; }
json_t *rules_root(void) { return g_root; }
const char *rules_default_json(void) { return DEFAULT_RULES; }

/* ---------- 字符串数组(借出,懒加载缓存) ---------- */
typedef struct { char *key; char **items; int count; } list_cache_t;
static list_cache_t g_lists[8];
static int g_list_n = 0;

const char **rules_str_list(const char *key, int *count) {
  if (count) *count = 0;
  if (!g_root || !key) return NULL;
  for (int i = 0; i < g_list_n; i++) {
    if (strcmp(g_lists[i].key, key) == 0) {
      if (count) *count = g_lists[i].count;
      return (const char **)g_lists[i].items;
    }
  }
  json_t *arr = j_get(g_root, key);
  if (!arr || arr->type != J_ARR) return NULL;
  if (g_list_n >= (int)(sizeof(g_lists) / sizeof(g_lists[0]))) return NULL;
  list_cache_t *c = &g_lists[g_list_n++];
  c->key = xstrdup(key);
  c->count = j_len(arr);
  c->items = (char **)xcalloc((size_t)(c->count > 0 ? c->count : 1), sizeof(char *));
  for (int i = 0; i < c->count; i++) {
    json_t *it = j_at(arr, i);
    c->items[i] = xstrdup(it && it->type == J_STR ? it->str : "");
  }
  if (count) *count = c->count;
  return (const char **)c->items;
}

static double rules_num_raw(const char *key, double fallback) {
  if (!g_root) return fallback;
  char path[128];
  snprintf(path, sizeof(path), "probing.%s", key);
  json_t *v = j_path(g_root, path);
  if (!v) v = j_get(g_root, key);
  return (v && v->type == J_NUM) ? v->num : fallback;
}

double rules_number(const char *key, double fallback) {
  return rules_num_raw(key, fallback);
}

int rules_flag(const char *key, int fallback) {
  if (!g_root) return fallback;
  json_t *v = j_path(g_root, key);
  if (!v) v = j_get(g_root, key);
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
  json_t *sigs = j_get(g_root, "signatures");
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
  json_t *arr = j_get(g_root, "weak_headers");
  return (arr && arr->type == J_ARR) ? j_len(arr) : 0;
}

const char *rules_weak_header(int index, const char *field, const char *fallback) {
  if (!g_root) return fallback;
  json_t *arr = j_get(g_root, "weak_headers");
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
  json_t *arr = j_get(g_root, "weak_headers");
  json_t *it = j_at(arr, index);
  json_t *v = it ? j_get(it, field) : NULL;
  return (v && v->type == J_NUM) ? (int)v->num : fallback;
}
