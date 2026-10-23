/* thread_store.cpp —— 对话存储 v2(结构见 thread_store.h)。
 *
 * 落盘原则只有两条:
 *   ① 消息与事件是"只追加"的流水,写坏了最多丢最后一行;
 *   ② meta 与 index 是可以从流水重建的派生数据 —— 所以放在最前面写,
 *      坏了大不了重建一次,不影响历史。
 */
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

void index_path(char *out, size_t cap) {
  snprintf(out, cap, "%s\\chat\\index.jsonl", g_root);
}

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

/* index 是流水:同一 tid 后面的行覆盖前面的。读完得到 tid → 最新一行 */
json_t *index_snapshot() {
  json_t *map = j_obj();
  char path[MAX_PATH * 4];
  index_path(path, sizeof(path));
  for_each_line(path, [&](json_t *o) {
    const char *tid = j_s(o, "thread_id", "");
    if (!tid[0]) return;
    char *dump = json_dump(o);
    json_t *copy = dump ? json_parse(dump) : NULL;
    free(dump);
    if (copy) j_set(map, tid, copy);   /* j_set 接管所有权 */
  });
  return map;
}

/* meta 不存在时用索引里的那一行兜底 —— 让列表页永远有东西可显示 */
json_t *meta_or_index(const char *tid) {
  char mp[MAX_PATH * 4];
  meta_path(tid, mp, sizeof(mp));
  json_t *last = NULL;
  for_each_line(mp, [&](json_t *o) {
    const char *ty = j_s(o, "type", "meta");
    if (strcmp(ty, "meta") != 0) return;
    if (last) json_free(last);
    char *d = json_dump(o);
    last = d ? json_parse(d) : NULL;
    free(d);
  });
  if (last) return last;
  json_t *map = index_snapshot();
  json_t *row = j_get(map, tid);
  json_t *copy = row ? json_parse(json_dump(row)) : NULL;
  json_free(map);
  return copy ? copy : j_obj();
}

/* meta 与 index 一起更新:meta 是权威快照,index 追加一行便于快速列表 */
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
  json_t *row = j_obj();
  j_set_str(row, "thread_id", tid);
  j_set_str(row, "title", j_s(meta, "title", ""));
  j_set_str(row, "created_at", j_s(meta, "created_at", ""));
  j_set_str(row, "updated_at", j_s(meta, "updated_at", ""));
  j_set_num(row, "message_count", j_n(meta, "message_count", 0));
  j_set_num(row, "last_seq", j_n(meta, "last_seq", 0));
  j_set_bool(row, "archived", j_b(meta, "archived", 0));
  j_set_bool(row, "pinned", j_b(meta, "pinned", 0));
  char ip[MAX_PATH * 4];
  index_path(ip, sizeof(ip));
  append_line(ip, row);
  json_free(row);
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
  json_t *meta = meta_or_index(thread_id);
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

  json_t *meta = meta_or_index(thread_id);
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
      size_t n = 0;
      for (const char *p = first; *p && n + 1 < sizeof(title); p++) {
        if (*p == '\n' || *p == '\r') break;
        title[n++] = *p;
        if (n >= 48) break;
      }
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

  /* 以目录为准(有 meta 就一定在列表里),再用索引补上没来得及写 meta 的 */
  char root[MAX_PATH * 2];
  snprintf(root, sizeof(root), "%s\\threads", g_root);
  std::vector<std::string> ids;
  {
    std::vector<std::string> dirs = fs_list_dirs(root);
    for (const std::string &d : dirs) ids.push_back(d);
  }
  {
    size_t len = 0;    char ip[MAX_PATH * 4];
    index_path(ip, sizeof(ip));
    char *text = file_read_all(ip, &len);
    if (text) {
      char **lines = NULL;
      int n = str_split(text, '\n', &lines, 0);
      for (int i = 0; i < n; i++) {
        char *ln = str_trim(lines[i]);
        if (!ln[0]) continue;
        json_t *o = json_parse(ln);
        if (!o) continue;
        const char *tid = j_s(o, "thread_id", "");
        if (tid[0] && std::find(ids.begin(), ids.end(), tid) == ids.end()) ids.push_back(tid);
        json_free(o);
      }
      str_free_list(lines, n);
      free(text);
    }
  }

  for (const std::string &tid : ids) {
    json_t *meta = meta_or_index(tid.c_str());
    if (!j_s(meta, "id", "")[0]) j_set_str(meta, "id", tid.c_str());
    j_add(out, meta);      /* 所有权交给数组 */
  }
  LeaveCriticalSection(&g_lock);

  /* 排序:置顶在前,其次按更新时间倒序 */
  int n = j_len(out);
  std::vector<json_t *> items;
  for (int i = 0; i < n; i++) items.push_back(j_at(out, i));
  std::stable_sort(items.begin(), items.end(), [](json_t *a, json_t *b) {
    int pa = j_b(a, "pinned", 0), pb = j_b(b, "pinned", 0);
    if (pa != pb) return pa > pb;
    return std::string(j_s(a, "updated_at", "")) > std::string(j_s(b, "updated_at", ""));
  });
  json_t *sorted = j_arr();
  for (json_t *it : items) {
    j_add(sorted, json_parse(json_dump(it)));   /* 深拷贝,m 的所有权仍在 out */
  }
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
    j_add(arr, json_parse(json_dump(o)));
  });
  LeaveCriticalSection(&g_lock);

  int n = j_len(arr);
  if (limit > 0 && n > limit) {
    /* 只要最近的 N 条,但要保持顺序 */
    json_t *tail = j_arr();
    for (int i = n - limit; i < n; i++) j_add(tail, json_parse(json_dump(j_at(arr, i))));
    json_free(arr);
    return tail;
  }
  return arr;
}

json_t *thread_get(const char *thread_id) {
  if (!thread_id || !*thread_id || !g_root[0]) return j_obj();
  lock_init();
  EnterCriticalSection(&g_lock);
  json_t *m = meta_or_index(thread_id);
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


/* 老结构(threads/<id>/{messages,events}.jsonl + meta.json)迁进 chat/<id>.jsonl。
   幂等:迁完写一个 .migrated 标记,下次直接跳过。 */
static int migrate_threads_dir(void) {
  char dir[MAX_PATH * 2];
  snprintf(dir, sizeof(dir), "%s\\threads", g_root);
  std::vector<std::string> subs = fs_list_dirs(dir);
  int moved = 0;
  for (size_t i = 0; i < subs.size(); i++) {
    char one[MAX_PATH * 2];
    snprintf(one, sizeof(one), "%s\\%s", dir, subs[i].c_str());
    char marker[MAX_PATH * 4];
    snprintf(marker, sizeof(marker), "%s\\.migrated", one);
    if (file_size(marker) >= 0) continue;

    char dst[MAX_PATH * 4];
    chat_file(subs[i].c_str(), dst, sizeof(dst));
    if (file_size(dst) < 0) {
      /* 消息、事件、meta 依次追加进同一个文件 */
      const char *parts[2] = {"messages.jsonl", "events.jsonl"};
      for (int k = 0; k < 2; k++) {
        char src[MAX_PATH * 4];
        snprintf(src, sizeof(src), "%s\\%s", one, parts[k]);
        size_t len = 0;
        char *text = file_read_all(src, &len);
        if (!text) continue;
        /* 老消息没有 type 字段:补一个,读的时候才不会漏 */
        char **lines = NULL;
        int n = str_split(text, '\n', &lines, 0);
        for (int j = 0; j < n; j++) {
          char *ln = str_trim(lines[j]);
          if (!ln[0]) continue;
          json_t *o = json_parse(ln);
          if (!o) continue;
          if (!j_s(o, "type", "")[0]) j_set_str(o, "type", k == 0 ? "message" : "event");
          append_line(dst, o);
          json_free(o);
        }
        str_free_list(lines, n);
        free(text);
      }
      char msrc[MAX_PATH * 4];
      snprintf(msrc, sizeof(msrc), "%s\\meta.json", one);
      size_t len = 0;
      char *text = file_read_all(msrc, &len);
      if (text) {
        json_t *o = json_parse(text);
        free(text);
        if (o) {
          j_set_str(o, "type", "meta");
          append_line(dst, o);
          json_free(o);
        }
      }
    }
    wchar_t *w = u8_to_w(marker);
    if (w) {
      HANDLE h = CreateFileW(w, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
      if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
      free(w);
    }
    moved++;
  }
  return moved;
}

int thread_migrate_legacy() {
  if (!g_root[0]) return 0;
  int from_threads = migrate_threads_dir();
  if (from_threads > 0) log_info("[对话] 已把 %d 个旧会话迁到 chat/ 单文件结构", from_threads);
  char legacy[MAX_PATH * 2];
  snprintf(legacy, sizeof(legacy), "%s\\transcripts", g_root);
  std::vector<std::string> files = fs_list_files(legacy, ".jsonl");
  int migrated = 0;
  for (const std::string &fn : files) {
    std::string sid = fn.substr(0, fn.size() > 6 ? fn.size() - 6 : fn.size());
    char path[MAX_PATH * 4];
    snprintf(path, sizeof(path), "%s\\%s", legacy, fn.c_str());
    json_t *meta = thread_ensure(sid.c_str(), NULL);
    bool fresh = (j_n(meta, "message_count", 0) == 0 && j_n(meta, "last_seq", 0) == 0);
    json_free(meta);
    if (!fresh) continue;                    /* 已经迁过,别重复 */

    int count = 0;
    size_t len = 0;
    char *text = file_read_all(path, &len);
    if (!text) continue;
    char **lines = NULL;
    int n = str_split(text, '\n', &lines, 0);
    for (int i = 0; i < n; i++) {
      char *ln = str_trim(lines[i]);
      if (!ln[0]) continue;
      json_t *o = json_parse(ln);
      if (!o) continue;
      const char *role = j_s(o, "role", "user");
      const char *body = j_s(o, "text", "");
      json_t *blocks = thread_blocks_text(body);
      json_t *msg = thread_append(sid.c_str(), role, blocks, NULL, NULL);
      json_free(msg);
      const char *ts = j_s(o, "time", "");
      (void)ts;
      json_free(o);
      count++;
    }
    str_free_list(lines, n);
    free(text);
    if (count > 0) {
      char done[MAX_PATH * 4];
      snprintf(done, sizeof(done), "%s.migrated", path);
      wchar_t *w1 = u8_to_w(path), *w2 = u8_to_w(done);
      if (w1 && w2) MoveFileExW(w1, w2, MOVEFILE_REPLACE_EXISTING);
      free(w1);
      free(w2);
      migrated++;
      log_info("[对话] 已把 %s 迁到 threads/ 新结构(%d 条消息)", sid.c_str(), count);
    }
  }
  return migrated;
}
