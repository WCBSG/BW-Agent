/* thread_store.cpp —— 对话存储(chat\<id>.jsonl,只追加)。
   消息 / 事件 / 元数据同文件,用 type 区分;同文件最后一条 meta 就是最新状态。 */
#include "thread_store.h"

#include <algorithm>
#include <string>
#include <vector>

#include "store.h"

namespace {

char g_root[MAX_PATH * 2] = {0};
CRITICAL_SECTION g_lock;
bool g_lock_ready = false;

void lock_init() {
  if (g_lock_ready) return;
  InitializeCriticalSection(&g_lock);
  g_lock_ready = true;
}

/* 会话 id 要能当目录名:只留字母数字与 - _ */
void safe_id(const char *in, char *out, size_t cap) {
  size_t n = 0;
  for (const char *p = in; p && *p && n + 1 < cap; p++) {
    unsigned char c = (unsigned char)*p;
    out[n++] = (isalnum(c) || c == '-' || c == '_' || c == '.') ? (char)c : '_';
  }
  out[n] = 0;
  if (!n) snprintf(out, cap, "default");
}

/* 对话目录:一个对话一个 jsonl 文件 —— <数据目录>\chat\<对话id>.jsonl
   为什么是"一个文件"而不是"一个目录":对话是给人翻的,能直接双击打开、
   能整份拷走、也能被 fs_read 按行读。事件与元数据同文件不同 type,靠 type 区分。 */
void chat_dir(char *out, size_t cap) {
  snprintf(out, cap, "%s\\chat", g_root);
}

void chat_file(const char *tid, char *out, size_t cap) {
  char safe[128];
  safe_id(tid, safe, sizeof(safe));
  char d[MAX_PATH * 2];
  chat_dir(d, sizeof(d));
  snprintf(out, cap, "%s\\%s.jsonl", d, safe);
}

void messages_path(const char *tid, char *out, size_t cap) { chat_file(tid, out, cap); }
void events_path(const char *tid, char *out, size_t cap) { chat_file(tid, out, cap); }
void meta_path(const char *tid, char *out, size_t cap) { chat_file(tid, out, cap); }

/* 追加一行 JSON(带换行),失败返回 -1 */
int append_line(const char *path, json_t *obj) {
  char *line = json_dump(obj);
  if (!line) return -1;
  buf_t b;
  buf_init(&b);
  buf_puts(&b, line);
  buf_putc_(&b, '\n');
  int rc = file_append(path, b.data, b.len);
  buf_free(&b);
  free(line);
  return rc;
}

/* 逐行读 jsonl,对每一行回调;坏行直接跳过(半行是崩溃的正常产物) */
template <typename Fn>
void for_each_line(const char *path, Fn fn) {
  size_t len = 0;
  char *text = file_read_all(path, &len);
  if (!text) return;
  char **lines = NULL;
  int n = str_split(text, '\n', &lines, 0);
  for (int i = 0; i < n; i++) {
    char *ln = str_trim(lines[i]);
    if (!ln[0]) continue;
    json_t *o = json_parse(ln);
    if (!o) continue;
    fn(o);
    json_free(o);
  }
  str_free_list(lines, n);
  free(text);
}

/* meta 不存在时用索引里的那一行兜底 —— 让列表页永远有东西可显示 */
/* 一个对话的元数据 = 该文件里最后一条 type=meta 的记录 */
json_t *read_meta(const char *tid) {
  char mp[MAX_PATH * 4];
  meta_path(tid, mp, sizeof(mp));
  json_t *last = NULL;
  for_each_line(mp, [&](json_t *o) {
    if (strcmp(j_s(o, "type", "meta"), "meta") != 0) return;
    if (last) json_free(last);
    char *d = json_dump(o);
    last = d ? json_parse(d) : NULL;
    free(d);
  });
  return last ? last : j_obj();
}

/* 元数据只追加:同文件里最后一条 meta 说了算 */
void save_meta(json_t *meta) {
  if (!meta) return;
  const char *tid = j_s(meta, "id", "");
  if (!tid[0]) return;
  char d[MAX_PATH * 2], mp[MAX_PATH * 4];
  chat_dir(d, sizeof(d));
  ensure_dir(d);
  meta_path(tid, mp, sizeof(mp));
  j_set_num(meta, "schema", THREAD_SCHEMA);
  j_set_str(meta, "type", "meta");
  append_line(mp, meta);
}

void touch_updated(json_t *meta) {
  char ts[40];
  now_iso(ts, sizeof(ts));
  j_set_str(meta, "updated_at", ts);
}

}  // namespace

void thread_store_init(const char *data_dir) {
  lock_init();
  snprintf(g_root, sizeof(g_root), "%s", data_dir ? data_dir : "");
  if (!g_root[0]) return;
  char d[MAX_PATH * 2];
  snprintf(d, sizeof(d), "%s\\chat", g_root);
  ensure_dir(d);
}

json_t *thread_ensure(const char *thread_id, const char *title) {
  if (!thread_id || !*thread_id || !g_root[0]) return j_obj();
  lock_init();
  EnterCriticalSection(&g_lock);
  json_t *meta = read_meta(thread_id);
  if (!j_s(meta, "id", "")[0]) {
    char ts[40];
    now_iso(ts, sizeof(ts));
    j_set_str(meta, "id", thread_id);
    j_set_str(meta, "title", (title && *title) ? title : "未命名对话");
    j_set_str(meta, "created_at", ts);
    j_set_str(meta, "updated_at", ts);
    j_set_num(meta, "message_count", 0);
    j_set_num(meta, "last_seq", 0);
    j_set_bool(meta, "archived", 0);
    j_set_bool(meta, "pinned", 0);
    j_set_num(meta, "schema", THREAD_SCHEMA);
    save_meta(meta);
  }
  LeaveCriticalSection(&g_lock);
  return meta;
}

json_t *thread_blocks_text(const char *text) {
  json_t *blocks = j_arr();
  json_t *b = j_obj();
  j_set_str(b, "type", "text");
  j_set_str(b, "text", text ? text : "");
  j_add(blocks, b);
  return blocks;
}

json_t *thread_append(const char *thread_id, const char *role, json_t *blocks,
                      json_t *usage, const char *parent_id) {
  json_t *msg = j_obj();
  if (!thread_id || !*thread_id || !g_root[0]) {
    json_free(blocks);
    return msg;
  }
  lock_init();
  EnterCriticalSection(&g_lock);

  json_t *meta = read_meta(thread_id);
  int last_seq = (int)j_n(meta, "last_seq", 0);
  int seq = last_seq + 1;

  char ts[40];
  now_iso(ts, sizeof(ts));
  char id[64];
  snprintf(id, sizeof(id), "%s-m%04d", j_s(meta, "id", thread_id), seq);

  j_set_str(msg, "id", id);
  j_set_num(msg, "seq", seq);
  j_set_str(msg, "thread_id", thread_id);
  j_set_str(msg, "role", role ? role : "user");
  if (blocks && blocks->type == J_ARR) {
    j_set(msg, "blocks", blocks);       /* 所有权交给消息对象 */
    blocks = NULL;
  } else {
    if (blocks) json_free(blocks);
    j_set(msg, "blocks", j_arr());
  }
  j_set_str(msg, "created_at", ts);
  if (parent_id && *parent_id) j_set_str(msg, "parent_id", parent_id);
  else if (seq > 1) {
    char pid[64];
    snprintf(pid, sizeof(pid), "%s-m%04d", j_s(meta, "id", thread_id), last_seq);
    j_set_str(msg, "parent_id", pid);
  }
  if (usage) j_set(msg, "usage", usage);

  j_set_str(msg, "type", "message");
  char mp[MAX_PATH * 4];
  messages_path(thread_id, mp, sizeof(mp));
  char d[MAX_PATH * 2];
  chat_dir(d, sizeof(d));
  ensure_dir(d);
  append_line(mp, msg);

  j_set_num(meta, "message_count", (double)((int)j_n(meta, "message_count", 0) + 1));
  j_set_num(meta, "last_seq", (double)seq);
  /* 首条用户消息顺手当标题:列表里"未命名对话"一片是很难认的 */
  const char *cur_title = j_s(meta, "title", "");
  if (role && strcmp(role, "user") == 0 &&
      (!cur_title[0] || strcmp(cur_title, "未命名对话") == 0)) {
    const char *first = "";
    json_t *bs = j_get(msg, "blocks");
    if (bs && j_len(bs) > 0) first = j_s(j_at(bs, 0), "text", "");
    if (first[0]) {
      char title[120];
      size_t n = u8_prefix(first, 48);
      /* 标题只取第一行 */
      for (size_t i = 0; i < n; i++) {
        if (first[i] == '\n' || first[i] == '\r') { n = i; break; }
      }
      n = u8_prefix(first, n);
      memcpy(title, first, n);
      title[n] = 0;
      j_set_str(meta, "title", title);
    }
  }
  touch_updated(meta);
  save_meta(meta);
  json_free(meta);

  LeaveCriticalSection(&g_lock);
  return msg;
}

void thread_append_event(const char *thread_id, json_t *event) {
  if (!thread_id || !*thread_id || !event || !g_root[0]) {
    if (event) json_free(event);
    return;
  }
  lock_init();
  EnterCriticalSection(&g_lock);
  char d[MAX_PATH * 2], p[MAX_PATH * 4];
  chat_dir(d, sizeof(d));
  ensure_dir(d);
  events_path(thread_id, p, sizeof(p));
  if (!j_s(event, "at", "")[0]) {
    char ts[40];
    now_iso(ts, sizeof(ts));
    j_set_str(event, "at", ts);
  }
  append_line(p, event);
  LeaveCriticalSection(&g_lock);
  json_free(event);
}

json_t *thread_list() {
  json_t *out = j_arr();
  if (!g_root[0]) return out;
  lock_init();
  EnterCriticalSection(&g_lock);

  /* 目录就是唯一的事实来源:chat\<id>.jsonl,读最后一条 meta */
  char dir[MAX_PATH * 2];
  chat_dir(dir, sizeof(dir));
  std::vector<std::string> files = fs_list_files(dir, ".jsonl");
  for (const std::string &fn : files) {
    if (str_ieq(fn.c_str(), "index.jsonl")) continue;
    std::string tid = fn.substr(0, fn.size() > 6 ? fn.size() - 6 : fn.size());
    json_t *meta = read_meta(tid.c_str());
    if (!j_s(meta, "id", "")[0]) j_set_str(meta, "id", tid.c_str());
    j_add(out, meta);
  }
  LeaveCriticalSection(&g_lock);

  int n = j_len(out);
  std::vector<json_t *> items;
  for (int i = 0; i < n; i++) items.push_back(j_at(out, i));
  std::stable_sort(items.begin(), items.end(), [](json_t *a, json_t *b) {
    int pa = j_b(a, "pinned", 0), pb = j_b(b, "pinned", 0);
    if (pa != pb) return pa > pb;
    return std::string(j_s(a, "updated_at", "")) > std::string(j_s(b, "updated_at", ""));
  });
  json_t *sorted = j_arr();
  for (json_t *it : items) j_add(sorted, j_clone(it));
  json_free(out);
  return sorted;
}

json_t *thread_messages(const char *thread_id, int limit) {
  json_t *arr = j_arr();
  if (!thread_id || !*thread_id || !g_root[0]) return arr;
  lock_init();
  EnterCriticalSection(&g_lock);
  char p[MAX_PATH * 4];
  messages_path(thread_id, p, sizeof(p));
  for_each_line(p, [&](json_t *o) {
    const char *ty = j_s(o, "type", "message");
    if (strcmp(ty, "message") != 0) return;      /* meta / event 不混进消息列表 */
    j_add(arr, j_clone(o));
  });
  LeaveCriticalSection(&g_lock);

  int n = j_len(arr);
  if (limit > 0 && n > limit) {
    /* 只要最近的 N 条,但要保持顺序 */
    json_t *tail = j_arr();
    for (int i = n - limit; i < n; i++) j_add(tail, j_clone(j_at(arr, i)));
    json_free(arr);
    return tail;
  }
  return arr;
}

json_t *thread_get(const char *thread_id) {
  if (!thread_id || !*thread_id || !g_root[0]) return j_obj();
  lock_init();
  EnterCriticalSection(&g_lock);
  json_t *m = read_meta(thread_id);
  LeaveCriticalSection(&g_lock);
  return m;
}

int thread_set_title(const char *thread_id, const char *title) {
  if (!thread_id || !*thread_id || !title) return -1;
  lock_init();
  EnterCriticalSection(&g_lock);
  json_t *meta = thread_ensure(thread_id, NULL);
  j_set_str(meta, "title", title);
  touch_updated(meta);
  save_meta(meta);
  json_free(meta);
  LeaveCriticalSection(&g_lock);
  return 0;
}

int thread_set_flags(const char *thread_id, int archived, int pinned) {
  if (!thread_id || !*thread_id) return -1;
  lock_init();
  EnterCriticalSection(&g_lock);
  json_t *meta = thread_ensure(thread_id, NULL);
  j_set_bool(meta, "archived", archived ? 1 : 0);
  j_set_bool(meta, "pinned", pinned ? 1 : 0);
  touch_updated(meta);
  save_meta(meta);
  json_free(meta);
  LeaveCriticalSection(&g_lock);
  return 0;
}

int thread_delete(const char *thread_id) {
  if (!thread_id || !*thread_id || !g_root[0]) return -1;
  char f[MAX_PATH * 4];
  chat_file(thread_id, f, sizeof(f));
  wchar_t *w = u8_to_w(f);
  if (w) { DeleteFileW(w); free(w); }
  /* 老版本是 threads/<id>/ 目录,一并清掉 */
  char safe[128];
  safe_id(thread_id, safe, sizeof(safe));
  char old[MAX_PATH * 2];
  snprintf(old, sizeof(old), "%s\\threads\\%s", g_root, safe);
  if (file_size(old) >= 0) fs_remove_tree(old);
  return 0;
}
