/* session_store.cpp —— v3 会话存储:快照 + 补丁,只追加。
   读的时候把整份日志重放到内存里,写的时候只追加一行。
   会话数量与长度都不大(一个人一天几十轮),重放代价可以忽略;
   换来的是"任何时刻断电都不丢已经写下的东西"。 */
#include "session_store.h"

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

/* 会话 id 要能当文件名:只留字母数字与 - _ . */
void safe_id(const char *in, char *out, size_t cap) {
  size_t n = 0;
  for (const char *p = in; p && *p && n + 1 < cap; p++) {
    unsigned char c = (unsigned char)*p;
    out[n++] = (isalnum(c) || c == '-' || c == '_' || c == '.') ? (char)c : '_';
  }
  out[n] = 0;
  if (!n) snprintf(out, cap, "default");
}

void chat_dir(char *out, size_t cap) {
  snprintf(out, cap, "%s\\chat", g_root);
}

void sess_file(const char *id, char *out, size_t cap) {
  char safe[128];
  safe_id(id, safe, sizeof(safe));
  char d[MAX_PATH * 2];
  chat_dir(d, sizeof(d));
  snprintf(out, cap, "%s\\%s.jsonl", d, safe);
}

void artifact_dir(char *out, size_t cap) {
  snprintf(out, cap, "%s\\chat\\artifacts", g_root);
}

int append_op(const char *path, json_t *op) {
  char *line = json_dump(op);
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

/* 逐行读(jsonl);坏行跳过 —— 崩溃时最后半行是正常产物,不该让整个会话读不出来 */
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

/* ---------- 路径操作:["turns",0,"response"] ---------- */

/* 键数组里的元素是 JSON 字符串或数字;直接读 ->str,
   不能用 j_s()(那个是"从对象里按名取值",对字符串节点返回空串)。 */
static const char *key_str(json_t *k) {
  return (k && k->type == J_STR && k->str) ? k->str : "";
}

/* 取"父容器"和最后一段键;数组下标用数字键表示 */
bool walk_to_parent(json_t *root, json_t *keys, json_t **parent, const char **last_key, int *last_idx) {
  if (!root || !keys || j_len(keys) == 0) return false;
  json_t *cur = root;
  int n = j_len(keys);
  for (int i = 0; i < n - 1; i++) {
    json_t *k = j_at(keys, i);
    if (!cur || !k) return false;
    if (k->type == J_NUM) {
      if (cur->type != J_ARR) return false;
      cur = j_at(cur, (int)k->num);
    } else {
      if (cur->type != J_OBJ) return false;
      cur = j_get(cur, key_str(k));
    }
  }
  if (!cur) return false;
  *parent = cur;
  json_t *k = j_at(keys, n - 1);
  if (!k) return false;
  if (k->type == J_NUM) { *last_idx = (int)k->num; *last_key = NULL; }
  else { *last_idx = -1; *last_key = key_str(k); }
  return true;
}

void apply_patch(json_t *root, json_t *keys, json_t *value, int append_mode) {
  json_t *parent = NULL;
  const char *key = NULL;
  int idx = -1;
  if (!walk_to_parent(root, keys, &parent, &key, &idx)) return;
  if (append_mode) {
    if (parent->type == J_ARR) {
      /* ["turns",0,"steps"] + append:数组追加一项 */
      j_add(parent, j_clone(value));
      return;
    }
    /* 末键指向一个对象里的数组:往里追加 */
    if (!key) return;
    json_t *arr = j_get(parent, key);
    if (!arr || arr->type != J_ARR) {
      j_set(parent, key, j_arr());
      arr = j_get(parent, key);
    }
    j_add(arr, j_clone(value));
    return;
  }
  if (parent->type == J_ARR) {
    /* 数组元素替换:就地写 */
    if (idx >= 0 && idx < j_len(parent)) {
      json_free(parent->items[idx]);
      parent->items[idx] = j_clone(value);
    }
    return;
  }
  if (!key) return;
  j_set(parent, key, j_clone(value));
}

/* 重放整个文件,返回会话对象;文件不存在返回 NULL */
json_t *replay(const char *id) {
  char p[MAX_PATH * 4];
  sess_file(id, p, sizeof(p));
  if (file_size(p) < 0) return NULL;
  json_t *sess = NULL;
  for_each_line(p, [&](json_t *o) {
    int kind = (int)j_n(o, "kind", 1);
    json_t *v = j_get(o, "v");
    if (kind == 0) {
      if (sess) json_free(sess);
      sess = v ? j_clone(v) : j_obj();
      return;
    }
    if (!sess || !v) return;
    json_t *keys = j_get(o, "k");
    if (!keys || keys->type != J_ARR) return;
    apply_patch(sess, keys, v, kind == 2);
  });
  return sess;
}

json_t *new_session_obj(const char *id, const char *title) {
  json_t *s = j_obj();
  char ts[40];
  now_iso(ts, sizeof(ts));
  j_set_num(s, "schema", SESSION_SCHEMA);
  j_set_str(s, "id", id);
  j_set_str(s, "title", (title && *title) ? title : "未命名会话");
  j_set_str(s, "created_at", ts);
  j_set_str(s, "updated_at", ts);
  j_set_bool(s, "archived", 0);
  j_set_bool(s, "pinned", 0);
  json_t *input = j_obj();
  j_set_str(input, "draft", "");
  j_set(input, "attachments", j_arr());
  j_set_str(input, "approval", "ask");
  j_set_str(input, "model", "");
  j_set(s, "input", input);
  j_set(s, "turns", j_arr());
  return s;
}

/* 会话头:不含 turns(列表页只需要这些) */
json_t *head_of(json_t *sess) {
  json_t *h = j_obj();
  static const char *keys[] = {"schema", "id", "title", "created_at", "updated_at",
                               "archived", "pinned", "input", "turn_count", "last_turn"};
  for (const char *k : keys) {
    json_t *v = j_get(sess, k);
    if (v) j_set(h, k, j_clone(v));
  }
  j_set_num(h, "turn_count", j_len(j_get(sess, "turns")));
  return h;
}

/* 把"更新时刻"推进到 now 并落盘(补丁形式,不重写整份) */
void touch(json_t *sess) {
  char ts[40];
  now_iso(ts, sizeof(ts));
  j_set_str(sess, "updated_at", ts);
}

}  // namespace

void sess_init(const char *data_dir) {
  lock_init();
  snprintf(g_root, sizeof(g_root), "%s", data_dir ? data_dir : "");
  if (!g_root[0]) return;
  char d[MAX_PATH * 2];
  chat_dir(d, sizeof(d));
  ensure_dir(d);
  artifact_dir(d, sizeof(d));
  ensure_dir(d);

  /* 旧格式(v2:message/meta 混写)不再读了 —— 挪到 chat\legacy\,
     既不丢用户的历史文件,也不会让列表里冒出读不懂的条目。 */
  std::vector<std::string> files = fs_list_files(d, ".jsonl");
  for (const std::string &fn : files) {
    char fp[MAX_PATH * 4];
    snprintf(fp, sizeof(fp), "%s\\%s", d, fn.c_str());
    long sz = file_size(fp);
    if (sz <= 0) continue;
    FILE *f = fopen(fp, "rb");
    if (!f) continue;
    char head[64] = {0};
    size_t got = fread(head, 1, sizeof(head) - 1, f);
    fclose(f);
    if (got == 0) continue;
    if (strstr(head, "\"kind\"")) continue;         /* 已经是 v3 */
    char legacy[MAX_PATH * 2];
    snprintf(legacy, sizeof(legacy), "%s\\legacy", d);
    ensure_dir(legacy);
    char dst[MAX_PATH * 4];
    snprintf(dst, sizeof(dst), "%s\\%s", legacy, fn.c_str());
    MoveFileExA(fp, dst, MOVEFILE_REPLACE_EXISTING);
    log_info("[会话] 旧格式转录已移到 chat\\legacy\\:%s", fn.c_str());
  }
}

json_t *sess_blocks_text(const char *text) {
  json_t *blocks = j_arr();
  json_t *b = j_obj();
  j_set_str(b, "type", "text");
  j_set_str(b, "text", text ? text : "");
  j_add(blocks, b);
  return blocks;
}

/* 确保会话文件存在(不在就写快照),返回文件路径 */
static void ensure_snapshot(const char *id, char *path, size_t cap) {
  char d[MAX_PATH * 2];
  chat_dir(d, sizeof(d));
  ensure_dir(d);
  sess_file(id, path, cap);
  if (file_size(path) >= 0) return;
  json_t *sess = new_session_obj(id, NULL);
  json_t *snap = j_obj();
  j_set_num(snap, "kind", 0);
  j_set(snap, "v", j_clone(sess));
  append_op(path, snap);
  json_free(snap);
  json_free(sess);
}

json_t *sess_ensure(const char *id, const char *title) {
  if (!id || !*id || !g_root[0]) return j_obj();
  lock_init();
  EnterCriticalSection(&g_lock);
  json_t *sess = replay(id);
  if (!sess) {
    sess = new_session_obj(id, title);
    char p[MAX_PATH * 4];
    sess_file(id, p, sizeof(p));
    char d[MAX_PATH * 2];
    chat_dir(d, sizeof(d));
    ensure_dir(d);
    json_t *op = j_obj();
    j_set_num(op, "kind", 0);
    j_set(op, "v", j_clone(sess));
    append_op(p, op);
    json_free(op);
  }
  json_t *h = head_of(sess);
  json_free(sess);
  LeaveCriticalSection(&g_lock);
  return h;
}

json_t *sess_get(const char *id) {
  if (!id || !*id || !g_root[0]) return j_obj();
  lock_init();
  EnterCriticalSection(&g_lock);
  json_t *sess = replay(id);
  LeaveCriticalSection(&g_lock);
  return sess ? sess : j_obj();
}

int sess_set_title(const char *id, const char *title) {
  if (!id || !*id || !title || !g_root[0]) return -1;
  lock_init();
  EnterCriticalSection(&g_lock);
  json_t *sess = replay(id);
  int rc = -1;
  if (sess) {
    j_set_str(sess, "title", title);
    touch(sess);
    char p[MAX_PATH * 4];
    sess_file(id, p, sizeof(p));
    json_t *op = j_obj();
    j_set_num(op, "kind", 1);
    json_t *k = j_arr();
    j_add(k, j_str("title"));
    j_set(op, "k", k);
    j_set_str(op, "v", title);
    rc = append_op(p, op);
    json_free(op);
    json_free(sess);
  }
  LeaveCriticalSection(&g_lock);
  return rc;
}

int sess_set_flags(const char *id, int archived, int pinned) {
  if (!id || !*id || !g_root[0]) return -1;
  lock_init();
  EnterCriticalSection(&g_lock);
  json_t *sess = replay(id);
  int rc = -1;
  if (sess) {
    char p[MAX_PATH * 4];
    sess_file(id, p, sizeof(p));
    for (int pass = 0; pass < 2; pass++) {
      const char *key = pass == 0 ? "archived" : "pinned";
      int val = pass == 0 ? archived : pinned;
      if (val < 0) continue;
      json_t *op = j_obj();
      j_set_num(op, "kind", 1);
      json_t *k = j_arr();
      j_add(k, j_str(key));
      j_set(op, "k", k);
      j_set_bool(op, "v", val);
      rc = append_op(p, op);
      json_free(op);
    }
    json_free(sess);
  }
  LeaveCriticalSection(&g_lock);
  return rc;
}

int sess_delete(const char *id) {
  if (!id || !*id || !g_root[0]) return -1;
  lock_init();
  EnterCriticalSection(&g_lock);
  char f[MAX_PATH * 4];
  sess_file(id, f, sizeof(f));
  wchar_t *w = u8_to_w(f);
  int rc = -1;
  if (w) {
    rc = DeleteFileW(w) ? 0 : -1;
    free(w);
  }
  /* 产物目录按会话 id 前缀命名,一并清掉 */
  char ad[MAX_PATH * 2];
  artifact_dir(ad, sizeof(ad));
  std::vector<std::string> files = fs_list_files(ad, ".txt");
  char safe[128];
  safe_id(id, safe, sizeof(safe));
  std::string prefix = std::string(safe) + "-";
  for (const std::string &fn : files) {
    if (fn.rfind(prefix, 0) == 0) {
      char fp[MAX_PATH * 4];
      snprintf(fp, sizeof(fp), "%s\\%s", ad, fn.c_str());
      wchar_t *wf = u8_to_w(fp);
      if (wf) { DeleteFileW(wf); free(wf); }
    }
  }
  LeaveCriticalSection(&g_lock);
  return rc;
}

int sess_set_input(const char *id, json_t *input) {
  if (!id || !*id || !input || !g_root[0]) {
    if (input) json_free(input);
    return -1;
  }
  lock_init();
  EnterCriticalSection(&g_lock);
  char p[MAX_PATH * 4];
  ensure_snapshot(id, p, sizeof(p));   /* 新会话先写草稿也要能存住 */
  json_t *op = j_obj();
  j_set_num(op, "kind", 1);
  json_t *k = j_arr();
  j_add(k, j_str("input"));
  j_set(op, "k", k);
  j_set(op, "v", input);               /* 所有权转移 */
  input = NULL;
  int rc = append_op(p, op);
  json_free(op);
  if (input) json_free(input);
  LeaveCriticalSection(&g_lock);
  return rc;
}

int sess_set_context(const char *id, json_t *ctx) {
  if (!id || !*id || !ctx || !g_root[0]) {
    if (ctx) json_free(ctx);
    return -1;
  }
  lock_init();
  EnterCriticalSection(&g_lock);
  char p[MAX_PATH * 4];
  ensure_snapshot(id, p, sizeof(p));
  json_t *op = j_obj();
  j_set_num(op, "kind", 1);
  json_t *k = j_arr();
  j_add(k, j_str("context"));
  j_set(op, "k", k);
  j_set(op, "v", ctx);
  ctx = NULL;
  int rc = append_op(p, op);
  json_free(op);
  LeaveCriticalSection(&g_lock);
  return rc;
}

json_t *sess_list(void) {
  json_t *out = j_arr();
  if (!g_root[0]) return out;
  lock_init();
  EnterCriticalSection(&g_lock);
  char dir[MAX_PATH * 2];
  chat_dir(dir, sizeof(dir));
  std::vector<std::string> files = fs_list_files(dir, ".jsonl");
  std::vector<json_t *> heads;
  for (const std::string &fn : files) {
    std::string id = fn.substr(0, fn.size() > 6 ? fn.size() - 6 : fn.size());
    json_t *sess = replay(id.c_str());
    if (!sess) continue;
    heads.push_back(head_of(sess));
    json_free(sess);
  }
  LeaveCriticalSection(&g_lock);

  std::stable_sort(heads.begin(), heads.end(), [](json_t *a, json_t *b) {
    int pa = j_b(a, "pinned", 0), pb = j_b(b, "pinned", 0);
    if (pa != pb) return pa > pb;
    return std::string(j_s(a, "updated_at", "")) > std::string(j_s(b, "updated_at", ""));
  });
  for (json_t *h : heads) j_add(out, h);
  return out;
}

/* ---------- 一轮 ---------- */

int sess_begin_turn(const char *id, json_t *user_blocks, json_t *request) {
  if (!id || !*id || !g_root[0]) {
    if (user_blocks) json_free(user_blocks);
    if (request) json_free(request);
    return -1;
  }
  lock_init();
  EnterCriticalSection(&g_lock);
  char p[MAX_PATH * 4];
  char d[MAX_PATH * 2];
  chat_dir(d, sizeof(d));
  ensure_dir(d);
  sess_file(id, p, sizeof(p));

  json_t *sess = replay(id);
  if (!sess) {
    sess = new_session_obj(id, NULL);
    json_t *snap = j_obj();
    j_set_num(snap, "kind", 0);
    j_set(snap, "v", j_clone(sess));
    append_op(p, snap);
    json_free(snap);
  }

  int index = j_len(j_get(sess, "turns"));
  int seq = index + 1;

  char ts[40];
  now_iso(ts, sizeof(ts));
  json_t *turn = j_obj();
  char tid[64];
  snprintf(tid, sizeof(tid), "t-%04d", seq);
  j_set_str(turn, "turnId", tid);
  j_set_num(turn, "seq", seq);
  j_set_str(turn, "status", "running");
  j_set_str(turn, "started_at", ts);

  /* 标题在把 blocks 交出去之前取,免得后面还要从已释放的对象里读 */
  const char *first_text = "";
  if (user_blocks && user_blocks->type == J_ARR && j_len(user_blocks) > 0) {
    first_text = j_s(j_at(user_blocks, 0), "text", "");
  }

  json_t *user = j_obj();
  if (user_blocks && user_blocks->type == J_ARR) {
    j_set(user, "blocks", user_blocks);
    user_blocks = NULL;
  } else {
    j_set(user, "blocks", j_arr());
  }
  j_set(turn, "user", user);
  if (request) j_set(turn, "request", request);
  request = NULL;
  j_set(turn, "steps", j_arr());

  json_t *op = j_obj();
  j_set_num(op, "kind", 2);
  json_t *k = j_arr();
  j_add(k, j_str("turns"));
  j_set(op, "k", k);
  j_set(op, "v", turn);
  int rc = append_op(p, op);
  json_free(op);

  /* 首轮:拿第一句话当标题(列表里一片"未命名会话"很难认) */
  if (seq == 1 && first_text && *first_text) {
    const char *cur = j_s(sess, "title", "");
    if (!cur[0] || strcmp(cur, "未命名会话") == 0) {
      char t[120];
      size_t n = u8_prefix(first_text, 48);
      for (size_t i = 0; i < n; i++) {
        if (first_text[i] == '\n' || first_text[i] == '\r') { n = i; break; }
      }
      n = u8_prefix(first_text, n);
      memcpy(t, first_text, n);
      t[n] = 0;
      json_t *top = j_obj();
      j_set_num(top, "kind", 1);
      json_t *tk = j_arr();
      j_add(tk, j_str("title"));
      j_set(top, "k", tk);
      j_set_str(top, "v", t);
      append_op(p, top);
      json_free(top);
    }
  }

  /* updated_at 跟着动 */
  json_t *top = j_obj();
  j_set_num(top, "kind", 1);
  json_t *tk = j_arr();
  j_add(tk, j_str("updated_at"));
  j_set(top, "k", tk);
  j_set_str(top, "v", ts);
  append_op(p, top);
  json_free(top);

  json_free(sess);
  if (user_blocks) json_free(user_blocks);
  if (request) json_free(request);
  LeaveCriticalSection(&g_lock);
  return rc == 0 ? index : -1;
}

int sess_turn_add_step(const char *id, int index, json_t *step) {
  if (!id || !*id || index < 0 || !step || !g_root[0]) {
    if (step) json_free(step);
    return -1;
  }
  char p[MAX_PATH * 4];
  sess_file(id, p, sizeof(p));
  json_t *op = j_obj();
  j_set_num(op, "kind", 2);
  json_t *k = j_arr();
  j_add(k, j_str("turns"));
  j_add(k, j_num(index));
  j_add(k, j_str("steps"));
  j_set(op, "k", k);
  j_set(op, "v", step);
  lock_init();
  EnterCriticalSection(&g_lock);
  int rc = append_op(p, op);
  LeaveCriticalSection(&g_lock);
  json_free(op);
  return rc;
}

int sess_turn_patch(const char *id, int index, const char *key, json_t *value) {
  if (!id || !*id || index < 0 || !key || !value || !g_root[0]) {
    if (value) json_free(value);
    return -1;
  }
  char p[MAX_PATH * 4];
  sess_file(id, p, sizeof(p));
  json_t *op = j_obj();
  j_set_num(op, "kind", 1);
  json_t *k = j_arr();
  j_add(k, j_str("turns"));
  j_add(k, j_num(index));
  j_add(k, j_str(key));
  j_set(op, "k", k);
  j_set(op, "v", value);
  lock_init();
  EnterCriticalSection(&g_lock);
  int rc = append_op(p, op);
  LeaveCriticalSection(&g_lock);
  json_free(op);
  return rc;
}

int sess_step_patch(const char *id, int index, int step_index, const char *key, json_t *value) {
  if (!id || !*id || index < 0 || step_index < 0 || !key || !value || !g_root[0]) {
    if (value) json_free(value);
    return -1;
  }
  char p[MAX_PATH * 4];
  sess_file(id, p, sizeof(p));
  json_t *op = j_obj();
  j_set_num(op, "kind", 1);
  json_t *k = j_arr();
  j_add(k, j_str("turns"));
  j_add(k, j_num(index));
  j_add(k, j_str("steps"));
  j_add(k, j_num(step_index));
  j_add(k, j_str(key));
  j_set(op, "k", k);
  j_set(op, "v", value);
  lock_init();
  EnterCriticalSection(&g_lock);
  int rc = append_op(p, op);
  LeaveCriticalSection(&g_lock);
  json_free(op);
  return rc;
}

int sess_turn_finish(const char *id, int index, json_t *response, const char *status) {
  if (!id || !*id || index < 0 || !g_root[0]) {
    if (response) json_free(response);
    return -1;
  }
  char p[MAX_PATH * 4];
  sess_file(id, p, sizeof(p));
  char ts[40];
  now_iso(ts, sizeof(ts));
  lock_init();
  EnterCriticalSection(&g_lock);
  int rc = 0;
  if (response) {
    json_t *op = j_obj();
    j_set_num(op, "kind", 1);
    json_t *k = j_arr();
    j_add(k, j_str("turns"));
    j_add(k, j_num(index));
    j_add(k, j_str("response"));
    j_set(op, "k", k);
    j_set(op, "v", response);          /* 所有权转移 */
    response = NULL;
    rc = append_op(p, op);
    json_free(op);
  }
  /* status / finished_at 一起写 */
  for (int pass = 0; pass < 2; pass++) {
    json_t *op = j_obj();
    j_set_num(op, "kind", 1);
    json_t *k = j_arr();
    j_add(k, j_str("turns"));
    j_add(k, j_num(index));
    j_add(k, j_str(pass == 0 ? "status" : "finished_at"));
    j_set(op, "k", k);
    if (pass == 0) j_set_str(op, "v", status ? status : "complete");
    else j_set_str(op, "v", ts);
    rc |= append_op(p, op);
    json_free(op);
  }
  /* 会话级 updated_at */
  json_t *top = j_obj();
  j_set_num(top, "kind", 1);
  json_t *tk = j_arr();
  j_add(tk, j_str("updated_at"));
  j_set(top, "k", tk);
  j_set_str(top, "v", ts);
  append_op(p, top);
  json_free(top);
  LeaveCriticalSection(&g_lock);
  if (response) json_free(response);
  return rc;
}

char *sess_artifact_write(const char *id, const char *tag, const char *text, size_t len) {
  if (!id || !*id || !text || !g_root[0]) return NULL;
  char d[MAX_PATH * 2];
  artifact_dir(d, sizeof(d));
  ensure_dir(d);
  char safe[128], safe_tag[64];
  safe_id(id, safe, sizeof(safe));
  safe_id(tag ? tag : "out", safe_tag, sizeof(safe_tag));
  char name[256];
  snprintf(name, sizeof(name), "%s-%s.txt", safe, safe_tag);
  char p[MAX_PATH * 4];
  snprintf(p, sizeof(p), "%s\\%s", d, name);
  if (file_write_all(p, text, len) != 0) return NULL;
  char *rel = (char *)xmalloc(strlen("artifacts/") + strlen(name) + 1);
  snprintf(rel, strlen("artifacts/") + strlen(name) + 1, "artifacts/%s", name);
  return rel;
}

char *sess_artifact_read(const char *rel_path, size_t *len) {
  if (!rel_path || !*rel_path || !g_root[0]) return NULL;
  char p[MAX_PATH * 4];
  snprintf(p, sizeof(p), "%s\\chat\\%s", g_root, rel_path);
  return file_read_all(p, len);
}
