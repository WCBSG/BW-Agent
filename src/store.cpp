/* store.cpp —— 落盘层实现。
   形态严格照抄 domain.md §11:结果类 JSONL 追加,配置/记录类一对象一文件。
   "只追加"的代价是同一 id 会留下多行,所以读的时候要取最后一行(store_all 已处理)。 */
#include "store.h"

#include <cctype>
#include <string>
#include <unordered_set>

struct store {
  char dir[MAX_PATH * 2];
  CRITICAL_SECTION lock;
};

/* 集合名 → 编号前缀(与合同 fixtures 完全一致) */
typedef struct { const char *name; const char *prefix; int jsonl; } coll_t;
static const coll_t COLLECTIONS[] = {
    {"findings", "F", 1},     {"assets", "A", 1},      {"alerts", "AL", 1},
    {"testcases", "TC", 1},   {"tasks", "T", 0},       {"profiles", "SP", 0},
    {"baselines", "B", 0},    {"diffs", "D", 0},       {"runs", "RUN", 0},
    {"reports", "R", 0},      {"evals", "EV", 0},      {"automations", "AUTO", 0},
};

static const coll_t *coll_find(const char *name) {
  for (size_t i = 0; i < sizeof(COLLECTIONS) / sizeof(COLLECTIONS[0]); i++) {
    if (str_ieq(COLLECTIONS[i].name, name)) return &COLLECTIONS[i];
  }
  return NULL;
}

store_t *store_open(const char *data_dir) {
  store_t *s = (store_t *)xcalloc(1, sizeof(store_t));
  snprintf(s->dir, sizeof(s->dir), "%s", data_dir ? data_dir : "data");
  InitializeCriticalSection(&s->lock);
  ensure_dir(s->dir);
  char sub[MAX_PATH * 2];
  path_join(sub, sizeof(sub), s->dir, "snapshots");
  ensure_dir(sub);
  return s;
}

void store_close(store_t *s) {
  if (!s) return;
  DeleteCriticalSection(&s->lock);
  free(s);
}

const char *store_dir(store_t *s) { return s ? s->dir : ""; }

/* 集合对应的路径 */
static void coll_path(store_t *s, const coll_t *c, char *out, size_t cap) {
  if (c->jsonl) {
    char name[MAX_PATH];
    snprintf(name, sizeof(name), "%s.jsonl", c->name);
    path_join(out, cap, s->dir, name);
  } else {
    path_join(out, cap, s->dir, c->name);
  }
}

/* 从 "F-0007" 里抠出数字 */
static long id_number(const char *id, const char *prefix) {
  if (!id) return 0;
  size_t lp = strlen(prefix);
  const char *p = id;
  if (str_startswith(id, prefix) && id[lp] == '-') p = id + lp + 1;
  long v = 0;
  int any = 0;
  for (; *p; p++) {
    if (!isdigit((unsigned char)*p)) break;
    v = v * 10 + (*p - '0');
    any = 1;
  }
  return any ? v : 0;
}

char *store_next_id(store_t *s, const char *collection) {
  const coll_t *c = coll_find(collection);
  if (!c) return xstrdup("X-0001");
  long max_n = 0;

  if (c->jsonl) {
    char path[MAX_PATH * 2];
    coll_path(s, c, path, sizeof(path));
    size_t len = 0;
    char *text = file_read_all(path, &len);
    if (text) {
      char **lines = NULL;
      int n = str_split(text, '\n', &lines, 0);
      for (int i = 0; i < n; i++) {
        char *line = str_trim(lines[i]);
        if (!line[0]) continue;
        json_t *o = json_parse(line);
        if (o) {
          long v = id_number(j_s(o, "id", ""), c->prefix);
          if (v > max_n) max_n = v;
          json_free(o);
        }
      }
      str_free_list(lines, n);
      free(text);
    }
  } else {
    char dir[MAX_PATH * 2];
    coll_path(s, c, dir, sizeof(dir));
    /* 走 fs_list_files(std::filesystem):中文文件名不再"看不见" */
    for (const std::string &name : fs_list_files(dir, ".json")) {
      std::string stem = name;
      size_t dot = stem.rfind('.');
      if (dot != std::string::npos) stem.resize(dot);
      long v = id_number(stem.c_str(), c->prefix);
      if (v > max_n) max_n = v;
    }
  }
  char out[64];
  snprintf(out, sizeof(out), "%s-%04ld", c->prefix, max_n + 1);
  return xstrdup(out);
}

int store_append(store_t *s, const char *collection, json_t *obj) {
  const coll_t *c = coll_find(collection);
  if (!c || !c->jsonl || !obj) return -1;
  char path[MAX_PATH * 2];
  coll_path(s, c, path, sizeof(path));
  char *line = json_dump(obj);
  buf_t b;
  buf_init(&b);
  buf_puts(&b, line);
  buf_putc_(&b, '\n');
  EnterCriticalSection(&s->lock);
  ensure_dir(s->dir);              /* 只保证"集合所在目录"存在,不拿文件路径去建目录 */
  int rc = file_append(path, b.data, b.len);
  LeaveCriticalSection(&s->lock);
  buf_free(&b);
  free(line);
  return rc;
}

int store_save(store_t *s, const char *collection, json_t *obj) {
  const coll_t *c = coll_find(collection);
  if (!c || c->jsonl || !obj) return -1;
  const char *id = j_s(obj, "id", "");
  if (!id[0]) return -1;
  char dir[MAX_PATH * 2], path[MAX_PATH * 4], name[MAX_PATH];
  coll_path(s, c, dir, sizeof(dir));
  snprintf(name, sizeof(name), "%s.json", id);
  path_join(path, sizeof(path), dir, name);
  char *line = json_dump(obj);
  EnterCriticalSection(&s->lock);
  ensure_dir(dir);
  int rc = file_write_all(path, line, strlen(line));
  LeaveCriticalSection(&s->lock);
  free(line);
  return rc;
}

json_t *store_all(store_t *s, const char *collection) {
  const coll_t *c = coll_find(collection);
  json_t *arr = j_arr();
  if (!c) return arr;

  if (c->jsonl) {
    char path[MAX_PATH * 2];
    coll_path(s, c, path, sizeof(path));
    size_t len = 0;
    char *text = file_read_all(path, &len);
    if (!text) return arr;

    /* 文件是"只追加"的,同一个 id 会留下多个版本 —— 从后往前挑,
       每个 id 只保留最后一次出现的那份(那才是最新状态)。
       原来这里对每个 id 线性扫一遍已收集的列表(O(n²));换成 unordered_set
       边挑边记,1 万条发现也只是毫秒级。
       顺便去掉一次深拷贝:命中的节点直接从 raw 里"摘下来"交给 arr,
       所以 raw->items[i] 置空,之后 json_free(raw) 不会重复释放。 */
    json_t *raw = j_arr();
    char **lines = NULL;
    int n = str_split(text, '\n', &lines, 0);
    for (int i = 0; i < n; i++) {
      char *line = str_trim(lines[i]);
      if (!line[0]) continue;
      json_t *o = json_parse(line);
      if (o) j_add(raw, o);
    }
    str_free_list(lines, n);
    free(text);

    std::unordered_set<std::string> seen;
    seen.reserve((size_t)j_len(raw));
    for (int i = j_len(raw) - 1; i >= 0; i--) {
      json_t *o = j_at(raw, i);
      if (!o) continue;
      const char *id = j_s(o, "id", "");
      if (!seen.insert(id).second) continue;      /* 已经有更新的版本了 */
      raw->items[i] = NULL;                       /* 所有权转移给 arr */
      j_add(arr, o);
    }
    json_free(raw);

    /* 上面是从后往前挑的,顺序反了 —— 反转回来,保持"先发现在前" */
    for (int i = 0, k = j_len(arr) - 1; i < k; i++, k--) {
      json_t *tmp = arr->items[i];
      arr->items[i] = arr->items[k];
      arr->items[k] = tmp;
    }
    return arr;
  }

  char dir[MAX_PATH * 2];
  coll_path(s, c, dir, sizeof(dir));
  for (const std::string &name : fs_list_files(dir, ".json")) {
    char path[MAX_PATH * 4];
    path_join(path, sizeof(path), dir, name.c_str());
    size_t len = 0;
    char *text = file_read_all(path, &len);
    if (text) {
      char *line = str_trim(text);
      json_t *o = json_parse(line);
      if (o) j_add(arr, o);
      free(text);
    }
  }
  return arr;
}

json_t *store_get(store_t *s, const char *collection, const char *id) {
  json_t *all = store_all(s, collection);
  json_t *hit = NULL;
  for (int i = 0; i < j_len(all); i++) {
    if (strcmp(j_s(j_at(all, i), "id", ""), id ? id : "") == 0) {
      char *tmp = json_dump(j_at(all, i));
      json_free(hit);
      hit = json_parse(tmp);
      free(tmp);
    }
  }
  json_free(all);
  return hit;
}

int store_delete(store_t *s, const char *collection, const char *id) {
  const coll_t *c = coll_find(collection);
  if (!s || !c || c->jsonl || !id || !id[0]) return -1;
  char dir[MAX_PATH * 2], path[MAX_PATH * 4], name[MAX_PATH];
  coll_path(s, c, dir, sizeof(dir));
  snprintf(name, sizeof(name), "%s.json", id);
  path_join(path, sizeof(path), dir, name);
  wchar_t *w = u8_to_w(path);
  EnterCriticalSection(&s->lock);
  int rc = (w && DeleteFileW(w)) ? 0 : -1;
  LeaveCriticalSection(&s->lock);
  free(w);
  return rc;
}

json_t *store_find(store_t *s, const char *collection, const char *key, const char *value) {
  json_t *all = store_all(s, collection);
  json_t *arr = j_arr();
  for (int i = 0; i < j_len(all); i++) {
    json_t *o = j_at(all, i);
    if (strcmp(j_s(o, key, ""), value ? value : "") == 0) {
      char *tmp = json_dump(o);
      j_add(arr, json_parse(tmp));
      free(tmp);
    }
  }
  json_free(all);
  return arr;
}

/* ================= 更新既有发现(只追加,读时取最后一行) ================= */
int store_update_finding(store_t *s, json_t *finding) {
  if (!s || !finding) return -1;
  const char *id = j_s(finding, "id", "");
  if (!id[0]) return -1;
  return store_append(s, "findings", finding);
}

json_t *store_findings_of_task(store_t *s, const char *task_id) {
  json_t *all = store_all(s, "findings");
  if (!task_id || !task_id[0]) return all;
  json_t *out = j_arr();
  for (int i = 0; i < j_len(all); i++) {
    json_t *f = j_at(all, i);
    if (strcmp(j_s(f, "task_id", ""), task_id) == 0) {
      j_add(out, json_parse(json_dump(f)));
    }
  }
  json_free(all);
  return out;
}

/* ================= 业务对象:任务 / 定义 / 资产 / 运行 =================
   这些对象是"这次巡检为什么合法、按什么口径、跑了什么"的凭据,
   报告与历史页都从这里取,避免把结论写成"只有我知道"。 */
char *store_ensure_profile(store_t *s, const char *name, json_t *keywords,
                           json_t *file_types, json_t *samples) {
  if (!s) return NULL;
  json_t *all = store_all(s, "profiles");
  json_t *exist = NULL;
  for (int i = 0; i < j_len(all); i++) {
    if (strcmp(j_s(j_at(all, i), "name", ""), name ? name : "") == 0) exist = j_at(all, i);
  }
  char *id = NULL;
  if (exist) {
    id = xstrdup(j_s(exist, "id", ""));
  } else {
    id = store_next_id(s, "profiles");
    json_t *p = j_obj();
    j_set_str(p, "id", id);
    j_set_str(p, "name", name ? name : "默认敏感信息定义");
    j_set(p, "keywords", keywords ? json_parse(json_dump(keywords)) : j_arr());
    j_set_str(p, "regex_note", "正则与内容特征由规则层维护:见 data/rules.json 的 signatures");
    j_set(p, "file_types", file_types ? json_parse(json_dump(file_types)) : j_arr());
    j_set(p, "samples", samples ? json_parse(json_dump(samples)) : j_arr());
    store_save(s, "profiles", p);
    json_free(p);
  }
  json_free(all);
  return id;
}

char *store_ensure_task(store_t *s, const char **domains, int count, const char *name,
                        const char *profile_id) {
  if (!s) return NULL;
  char key[512];
  key[0] = 0;
  for (int i = 0; i < count && i < 8; i++) {
    if (i) strncat_s(key, sizeof(key), ",", _TRUNCATE);
    strncat_s(key, sizeof(key), domains[i], _TRUNCATE);
  }
  json_t *all = store_all(s, "tasks");
  for (int i = 0; i < j_len(all); i++) {
    json_t *t = j_at(all, i);
    json_t *ad = j_get(t, "authorized_domains");
    if (j_len(ad) != count) continue;
    int same = 1;
    for (int k = 0; k < count && same; k++) {
      if (strcmp(j_at(ad, k)->str, domains[k]) != 0) same = 0;
    }
    if (same) {
      char *id = xstrdup(j_s(t, "id", ""));
      json_free(all);
      return id;
    }
  }

  char *id = store_next_id(s, "tasks");
  char ts[40];
  now_iso(ts, sizeof(ts));
  json_t *t = j_obj();
  j_set_str(t, "id", id);
  j_set_str(t, "name", name ? name : key);
  json_t *ad = j_arr();
  for (int i = 0; i < count; i++) j_add(ad, j_str(domains[i]));
  j_set(t, "authorized_domains", ad);
  buf_t scope;
  buf_init(&scope);
  buf_printf(&scope, "仅授权域名 %s;只做只读检查(GET/HEAD/OPTIONS),不做写入与利用;"
                     "限速 2 QPS,全程审计留痕", key);
  j_set_str(t, "scope", scope.data);
  j_set_str(t, "cycle", "手动");
  j_set_null(t, "cron");
  j_set_str(t, "sensitive_profile_id", profile_id ? profile_id : "");
  j_set_str(t, "status", "running");
  j_set_str(t, "created_at", ts);
  j_set_str(t, "last_run_at", "");
  j_set_str(t, "next_run_at", "");
  store_save(s, "tasks", t);
  json_free(t);
  buf_free(&scope);
  json_free(all);
  return id;
}

int store_upsert_asset(store_t *s, const char *task_id, const char *url, const char *kind,
                       int status_code, int depth, const char *parent_url) {
  if (!s || !url || !url[0]) return -1;
  char ts[40];
  now_iso(ts, sizeof(ts));
  json_t *all = store_all(s, "assets");
  json_t *exist = NULL;
  for (int i = 0; i < j_len(all); i++) {
    if (strcmp(j_s(j_at(all, i), "url", ""), url) == 0) exist = j_at(all, i);
  }
  if (exist) {
    /* 资产是"底账":同一地址只更新 last_seen 与最新状态码,不重复记条目 */
    json_t *a = json_parse(json_dump(exist));
    j_set_str(a, "last_seen", ts);
    j_set_num(a, "status_code", status_code);
    if (kind && kind[0]) j_set_str(a, "kind", kind);
    store_append(s, "assets", a);
    json_free(a);
  } else {
    char *id = store_next_id(s, "assets");
    json_t *a = j_obj();
    j_set_str(a, "id", id);
    j_set_str(a, "task_id", task_id ? task_id : "");
    j_set_str(a, "url", url);
    j_set_str(a, "kind", kind && kind[0] ? kind : "页面");
    j_set_num(a, "status_code", status_code);
    j_set_num(a, "depth", depth);
    if (parent_url && parent_url[0]) j_set_str(a, "parent_url", parent_url);
    else j_set_null(a, "parent_url");
    j_set_str(a, "first_seen", ts);
    j_set_str(a, "last_seen", ts);
    store_append(s, "assets", a);
    json_free(a);
    free(id);
  }
  json_free(all);
  return 0;
}

/* 当前这一轮的触发来源。默认「手动」,周期巡检线程在跑之前改成「周期巡检」。 */
static char g_trigger[32] = "手动";

void store_set_trigger(const char *label) {
  snprintf(g_trigger, sizeof(g_trigger), "%s", (label && *label) ? label : "手动");
}
const char *store_trigger_label(void) { return g_trigger; }

char *store_run_start(store_t *s, const char *task_id, const char *triggered_by,
                      const char *scope) {
  if (!s) return NULL;
  char *id = store_next_id(s, "runs");
  char ts[40];
  now_iso(ts, sizeof(ts));
  json_t *r = j_obj();
  j_set_str(r, "id", id);
  j_set_str(r, "task_id", task_id ? task_id : "");
  j_set_str(r, "triggered_by", triggered_by ? triggered_by : "手动");
  j_set_str(r, "scope", (scope && *scope) ? scope : "full");
  j_set_str(r, "status", "running");
  j_set_str(r, "started_at", ts);
  j_set_str(r, "finished_at", "");
  j_set_num(r, "pages_found", 0);
  j_set_num(r, "tools_called", 0);
  j_set_num(r, "findings_new", 0);
  j_set_str(r, "error", "");
  store_save(s, "runs", r);
  json_free(r);
  return id;
}

int store_run_finish(store_t *s, const char *run_id, const char *status, int pages_found,
                     int tools_called, int findings_new, const char *error) {
  if (!s || !run_id || !run_id[0]) return -1;
  json_t *r = store_get(s, "runs", run_id);
  if (!r) r = j_obj();
  char ts[40];
  now_iso(ts, sizeof(ts));
  if (!j_s(r, "id", "")[0]) j_set_str(r, "id", run_id);
  j_set_str(r, "status", status ? status : "done");
  j_set_str(r, "finished_at", ts);
  j_set_num(r, "pages_found", pages_found);
  j_set_num(r, "tools_called", tools_called);
  j_set_num(r, "findings_new", findings_new);
  j_set_str(r, "error", error ? error : "");
  int rc = store_save(s, "runs", r);
  json_free(r);
  return rc;
}

/* ================= 运行索引 ================= */
int store_link_run(store_t *s, const char *run_id, const char *finding_id, int is_new) {
  if (!s || !run_id || !run_id[0] || !finding_id || !finding_id[0]) return -1;
  json_t *row = j_obj();
  char ts[40];
  now_iso(ts, sizeof(ts));
  j_set_str(row, "run_id", run_id);
  j_set_str(row, "finding_id", finding_id);
  j_set_bool(row, "first_in_run", is_new);
  j_set_str(row, "seen_at", ts);
  char path[MAX_PATH * 2];
  path_join(path, sizeof(path), s->dir, "run_findings.jsonl");
  char *line = json_dump(row);
  buf_t b;
  buf_init(&b);
  buf_puts(&b, line);
  buf_putc_(&b, '\n');
  int rc = file_append(path, b.data, b.len);
  buf_free(&b);
  free(line);
  json_free(row);
  return rc;
}

json_t *store_findings_of_run(store_t *s, const char *run_id) {
  json_t *out = j_arr();
  char path[MAX_PATH * 2];
  path_join(path, sizeof(path), s->dir, "run_findings.jsonl");
  size_t len = 0;
  char *text = file_read_all(path, &len);
  if (!text) return out;
  json_t *ids = j_arr();
  char **lines = NULL;
  int n = str_split(text, '\n', &lines, 0);
  for (int i = 0; i < n; i++) {
    char *line = str_trim(lines[i]);
    if (!line[0]) continue;
    json_t *o = json_parse(line);
    if (!o) continue;
    if (strcmp(j_s(o, "run_id", ""), run_id) == 0) {
      const char *fid = j_s(o, "finding_id", "");
      int dup = 0;
      for (int k = 0; k < j_len(ids); k++) {
        if (strcmp(j_at(ids, k)->str, fid) == 0) { dup = 1; break; }
      }
      if (!dup && fid[0]) j_add(ids, j_str(fid));
    }
    json_free(o);
  }
  str_free_list(lines, n);
  free(text);

  for (int i = 0; i < j_len(ids); i++) {
    json_t *f = store_get(s, "findings", j_at(ids, i)->str);
    if (f) j_add(out, f);
  }
  json_free(ids);
  return out;
}

/* ================= 审计 / 转录 ================= */
void store_audit(store_t *s, const char *action, const char *target, int allowed,
                 const char *detail, const char *task_id, const char *run_id) {
  if (!s) return;
  json_t *row = j_obj();
  char ts[40];
  now_iso(ts, sizeof(ts));
  j_set_str(row, "time", ts);
  j_set_str(row, "actor", "agent-c");
  j_set_str(row, "action", action ? action : "");
  j_set_str(row, "target", target ? target : "");
  j_set_str(row, "task_id", task_id ? task_id : "");
  j_set_str(row, "run_id", run_id ? run_id : "");
  j_set_bool(row, "allowed", allowed);
  j_set_str(row, "detail", detail ? detail : "");
  char path[MAX_PATH * 2];
  path_join(path, sizeof(path), s->dir, "audit.jsonl");
  char *line = json_dump(row);
  buf_t b;
  buf_init(&b);
  buf_puts(&b, line);
  buf_putc_(&b, '\n');
  file_append(path, b.data, b.len);
  buf_free(&b);
  free(line);
  json_free(row);
}

int store_transcript(store_t *s, const char *session_id, json_t *event) {
  if (!s || !event) return -1;
  char dir[MAX_PATH * 2], name[MAX_PATH], path[MAX_PATH * 4];
  path_join(dir, sizeof(dir), s->dir, "transcripts");
  ensure_dir(dir);
  snprintf(name, sizeof(name), "%s.jsonl", session_id && *session_id ? session_id : "default");
  path_join(path, sizeof(path), dir, name);
  char *line = json_dump(event);
  buf_t b;
  buf_init(&b);
  buf_puts(&b, line);
  buf_putc_(&b, '\n');
  int rc = file_append(path, b.data, b.len);
  buf_free(&b);
  free(line);
  return rc;
}

/* ================= 快照 ================= */
char *store_write_snapshot(store_t *s, const char *id, const char *content) {
  char dir[MAX_PATH * 2], path[MAX_PATH * 4], name[MAX_PATH];
  path_join(dir, sizeof(dir), s->dir, "snapshots");
  ensure_dir(dir);
  char safe[MAX_PATH];
  snprintf(safe, sizeof(safe), "%s", id ? id : "snap");
  for (char *p = safe; *p; p++) {
    if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_' && *p != '.') *p = '_';
  }
  snprintf(name, sizeof(name), "%s.html", safe);
  path_join(path, sizeof(path), dir, name);
  file_write_all(path, content ? content : "", strlen(content ? content : ""));
  char *ref = (char *)xmalloc(MAX_PATH);
  snprintf(ref, MAX_PATH, "snapshots/%s", name);
  return ref;
}

char *store_read_snapshot(store_t *s, const char *content_ref) {
  if (!s || !content_ref || !content_ref[0]) return NULL;
  char path[MAX_PATH * 4];
  snprintf(path, sizeof(path), "%s\\snapshots\\%s", s->dir,
           content_ref + (str_startswith(content_ref, "snapshots/") ? 10 : 0));
  return file_read_all(path, NULL);
}

/* ================= 证据去敏 ================= */
/* 报告可能外传,所以落盘前就把个人信息与凭据打掉 */
void mask_evidence(buf_t *out, const char *text) {
  if (!text) return;
  size_t n = strlen(text);
  for (size_t i = 0; i < n;) {
    /* 手机号:1[3-9] + 9 位数字 */
    if (text[i] == '1' && i + 11 <= n && text[i + 1] >= '3' && text[i + 1] <= '9' &&
        (i == 0 || !isdigit((unsigned char)text[i - 1]))) {
      int ok = 1;
      for (int k = 2; k < 11; k++) if (!isdigit((unsigned char)text[i + k])) { ok = 0; break; }
      if (ok && (i + 11 == n || !isdigit((unsigned char)text[i + 11]))) {
        buf_putn(out, text + i, 3);
        buf_puts(out, "****");
        buf_putn(out, text + i + 7, 4);
        i += 11;
        continue;
      }
    }
    /* 邮箱:xxx@yyy.zz 的本地部分留一位 */
    if (text[i] == '@' && i > 0) {
      size_t start = i;
      while (start > 0 && (isalnum((unsigned char)text[start - 1]) ||
                           text[start - 1] == '.' || text[start - 1] == '_' ||
                           text[start - 1] == '%' || text[start - 1] == '+' ||
                           text[start - 1] == '-')) {
        start--;
      }
      size_t end = i + 1;
      while (end < n && (isalnum((unsigned char)text[end]) || text[end] == '.' ||
                         text[end] == '-')) {
        end++;
      }
      if (end > i + 1 && strchr(text + i, '.')) {
        /* 已经写过 start..i 段?为了简单:从"已写位置"里回退 */
        if (out->len >= i - start) {
          out->len -= (i - start);
          out->data[out->len] = 0;
        }
        buf_putc_(out, text[start]);
        buf_puts(out, "***");
        buf_putn(out, text + i, end - i);
        i = end;
        continue;
      }
    }
    buf_putc_(out, text[i]);
    i++;
  }
}

/* ================= 发现入库(去重 + 状态机) ================= */
char *store_upsert_finding(store_t *s, const finding_in_t *in, int *is_new) {
  if (is_new) *is_new = 0;
  if (!s || !in) return NULL;

  /* dedup_key = 工具|目标|问题指纹 —— 三段都稳定,换个日期也一样 */
  buf_t dedup;
  buf_init(&dedup);
  {
    const char *t = in->target ? in->target : "";
    const char *sep = strstr(t, "://");
    buf_printf(&dedup, "%s|%s|%s", in->source_tool ? in->source_tool : "unknown",
               sep ? sep + 3 : t, in->dedup_tag ? in->dedup_tag : "generic");
  }

  char ts[40];
  now_iso(ts, sizeof(ts));

  /* 找同键的既有发现 */
  json_t *all = store_all(s, "findings");
  json_t *existing = NULL;
  for (int i = 0; i < j_len(all); i++) {
    if (strcmp(j_s(j_at(all, i), "dedup_key", ""), dedup.data) == 0) {
      existing = j_at(all, i);
      break;
    }
  }

  char *id = NULL;
  if (existing) {
    /* 复现了:只更新 last_seen(不新增)—— 这是合同明确要求的 */
    id = xstrdup(j_s(existing, "id", ""));
    if (strcmp(j_s(existing, "last_seen", ""), ts) != 0) {
      json_t *copy = json_parse(json_dump(existing));
      j_set_str(copy, "last_seen", ts);
      /* 之前被标成"已修复"的又复现 → 退回 confirmed,别自作主张说已修好 */
      if (strcmp(j_s(copy, "status", ""), "fixed") == 0) j_set_str(copy, "status", "confirmed");
      store_append(s, "findings", copy);
      json_free(copy);
    }
    if (in->run_id) store_link_run(s, in->run_id, id, 0);
  } else {
    id = store_next_id(s, "findings");
    json_t *f = j_obj();
    j_set_str(f, "id", id);
    j_set_str(f, "task_id", in->task_id ? in->task_id : "");
    j_set_str(f, "run_id", in->run_id ? in->run_id : "");
    j_set_str(f, "kind", in->kind ? in->kind : "弱配置");
    j_set_str(f, "severity", in->severity ? in->severity : "信息");
    j_set_str(f, "title", in->title ? in->title : "");
    j_set_str(f, "target", in->target ? in->target : "");
    {
      buf_t masked;
      buf_init(&masked);
      mask_evidence(&masked, in->evidence ? in->evidence : "");
      j_set_str(f, "evidence", masked.data);
      buf_free(&masked);
    }
    j_set_str(f, "impact", in->impact ? in->impact : "");
    j_set_str(f, "fix", in->fix ? in->fix : "");
    j_set_str(f, "source_tool", in->source_tool ? in->source_tool : "");
    j_set_str(f, "status", "new");
    j_set_str(f, "dedup_key", dedup.data);
    j_set_str(f, "first_seen", ts);
    j_set_str(f, "last_seen", ts);
    j_set(f, "retests", j_arr());
    store_append(s, "findings", f);
    json_free(f);
    if (is_new) *is_new = 1;
    if (in->run_id) store_link_run(s, in->run_id, id, 1);
  }

  json_free(all);
  buf_free(&dedup);
  return id;
}
