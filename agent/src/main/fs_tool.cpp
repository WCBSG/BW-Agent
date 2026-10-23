/* fs_tool.cpp —— 让模型能读写本机文件的三个工具。
 *
 * 为什么要有:巡检要看的东西有一大半在本地 —— nuclei 导出的结果、导出的日志、
 * 人自己整理的资产/授权表、上一次的基线。没有读文件的能力,这些内容只能靠人手粘
 * 给模型;没有写文件的能力,模型好不容易归并出来的结论还得人再抄一遍。
 *
 * 安全边界(硬性,不提供任何"放宽"的开关):
 *   1. 读只能碰两个根:数据目录、程序所在目录。别处一律拒绝。
 *   2. 写只能落在数据目录里 —— 程序目录里是 exe 与内置数据,改坏了就起不来了。
 *   3. 路径先规范化成绝对路径再比对前缀,`..\..\` 这类穿越在规范化阶段就被吃掉,
 *      所以"前缀看起来像"不会被用来骗过检查。
 *   4. 覆盖写之前先留一份 .bak;不提供删除 —— 要删请人自己删。
 *
 * 这些限制写死在代码里而不是规则里:规则是可以被模型改的,边界不行。
 */
#include "tools.h"

#include <windows.h>

#include "json.h"

/* ================= 路径规范化与边界判定 ================= */

/* 把用户给的路径变成不带 .. 的绝对路径。相对路径按数据目录算(最常用的那个)。 */
static int abs_path(const char *raw, wchar_t *out, size_t cap) {
  if (!raw || !*raw) return 0;
  char tmp[MAX_PATH * 2];
  snprintf(tmp, sizeof(tmp), "%s", raw);
  for (char *p = tmp; *p; p++) {
    if (*p == '/') *p = '\\';
  }
  wchar_t *wrel = u8_to_w(tmp);
  if (!wrel) return 0;

  /* 相对路径的基准:数据目录(exe 所在目录在多数交付里是只读位置,不适合当默认落点) */
  wchar_t *bw = u8_to_w(app_data_dir());
  if (!bw) {
    free(wrel);
    return 0;
  }

  wchar_t combined[MAX_PATH * 4];
  size_t clen = wcslen(wrel);
  if (clen >= 2 && wrel[1] == L':') {
    wcsncpy(combined, wrel, MAX_PATH * 4 - 1);
    combined[MAX_PATH * 4 - 1] = 0;
  } else if (wrel[0] == L'\\') {
    /* 根相对(单个反斜杠):按数据目录所在盘补全,而不是当成"绝对路径" */
    wcsncpy(combined, bw, 2);              /* 保留 "C:" */
    combined[2] = 0;
    wcsncat(combined, wrel, MAX_PATH * 4 - wcslen(combined) - 1);
  } else {
    wcsncpy(combined, bw, MAX_PATH * 4 - 1);
    combined[MAX_PATH * 4 - 1] = 0;
    size_t n = wcslen(combined);
    if (n && combined[n - 1] != L'\\') wcsncat(combined, L"\\", 1);
    wcsncat(combined, wrel, MAX_PATH * 4 - wcslen(combined) - 1);
  }
  free(wrel);
  free(bw);

  /* GetFullPathName 会消掉 . 与 ..,但不会要求文件存在 —— 正好用于"写入前"判边界 */
  wchar_t full[MAX_PATH * 4];
  DWORD got = GetFullPathNameW(combined, (DWORD)(sizeof(full) / sizeof(full[0])), full, NULL);
  if (got == 0 || got >= sizeof(full) / sizeof(full[0])) return 0;
  /* 去掉末尾多余的反斜杠("C:\a\" 与 "C:\a") */
  size_t len = wcslen(full);
  while (len > 3 && full[len - 1] == L'\\') full[--len] = L'\0';
  if (len + 1 > cap) return 0;
  wcscpy(out, full);
  return 1;
}

/* a 是不是落在 root 里面(root 自己也算) */
static int under_root(const wchar_t *path, const char *root_u8) {
  wchar_t *rw = u8_to_w(root_u8);
  if (!rw) return 0;
  wchar_t root[MAX_PATH * 4];
  DWORD got = GetFullPathNameW(rw, (DWORD)(sizeof(root) / sizeof(root[0])), root, NULL);
  free(rw);
  if (got == 0) return 0;
  size_t n = wcslen(root);
  while (n > 3 && root[n - 1] == L'\\') root[--n] = L'\0';
  if (_wcsnicmp(path, root, n) != 0) return 0;
  return path[n] == L'\0' || path[n] == L'\\';
}

/* 读允许:数据目录 + 程序目录 + 调用方额外给的一个根(独立工具 exe 用)。
   写允许:只有数据目录。 */
static char g_extra_root[MAX_PATH * 4];

void fs_tool_set_extra_root(const char *dir) {
  if (!dir || !*dir) {
    g_extra_root[0] = 0;
    return;
  }
  snprintf(g_extra_root, sizeof(g_extra_root), "%s", dir);
}

static int check_allowed(const wchar_t *full, int for_write, char *err, size_t err_cap) {
  if (for_write) {
    if (under_root(full, app_data_dir())) return 1;
    snprintf(err, err_cap, "只能往数据目录里写(%s),程序目录是只读的", app_data_dir());
    return 0;
  }
  if (under_root(full, app_data_dir())) return 1;
  if (under_root(full, app_dir())) return 1;
  if (g_extra_root[0] && under_root(full, g_extra_root)) return 1;
  snprintf(err, err_cap, "只能读数据目录(%s)或程序目录(%s)下的文件", app_data_dir(),
           app_dir());
  return 0;
}

/* ================= 读 =================
   协议:{ "path": "...", "startline": 0, "endline": 100 }
   行号从 0 开始、两端都算(endline 省略 = 读到文件末尾)。
   为什么按行而不是按字节:模型看到的是行,报给人看的也是行("第 40 行有个敏感字段"),
   用字节偏移会让它每次都要自己换算,还会把一行切成两半。 */
static void split_lines(const char *data, size_t len, int *total_out) {
  int total = 0;
  if (len == 0) {
    *total_out = 0;
    return;
  }
  for (size_t i = 0; i < len; i++) {
    if (data[i] == '\n') total++;
  }
  if (data[len - 1] != '\n') total++;
  *total_out = total;
}

int fs_tool_read(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  (void)ctx;
  const char *raw = j_s(args, "path", "");
  wchar_t full[MAX_PATH * 4];
  char err[512];
  if (!abs_path(raw, full, sizeof(full) / sizeof(full[0]))) {
    out->is_error = 1;
    out->text = xstrdup("路径看不懂(空路径或太长)");
    return -1;
  }
  if (!check_allowed(full, 0, err, sizeof(err))) {
    out->is_error = 1;
    out->text = xstrdup(err);
    return -1;
  }

  char u8[MAX_PATH * 4];
  char *p8 = w_to_u8(full);
  if (!p8) {
    out->is_error = 1;
    out->text = xstrdup("路径编码转换失败");
    return -1;
  }
  snprintf(u8, sizeof(u8), "%s", p8);
  free(p8);

  long sz = file_size(u8);
  if (sz < 0) {
    buf_t b;
    buf_init(&b);
    buf_printf(&b, "读不到这个文件:%s(不存在或没有权限)", u8);
    out->is_error = 1;
    out->text = b.data;
    return -1;
  }
  if (sz > 64 * 1024 * 1024) {
    out->is_error = 1;
    out->text = xstrdup("文件超过 64MB,不整份读进内存;请用 fs_list 看目录,或先切分/导出成小文件");
    return -1;
  }

  size_t len = 0;
  char *data = file_read_all(u8, &len);
  if (!data) {
    out->is_error = 1;
    out->text = xstrdup("文件打不开");
    return -1;
  }
  if (memchr(data, '\0', len)) {
    out->is_error = 1;
    out->text = xstrdup("这是二进制文件,不做文本读取");
    free(data);
    return -1;
  }

  int total = 0;
  split_lines(data, len, &total);

  int start = (int)j_n(args, "startline", 0);
  int end = (int)j_n(args, "endline", -1);
  if (start < 0) start = 0;
  if (end < 0) end = total - 1;
  if (end < start) {
    int t = start;
    start = end;
    end = t;
  }
  if (start > total - 1) start = total > 0 ? total - 1 : 0;

  /* 一次最多给 5000 行 / 512KB:够模型看明白一段,又不至于把上下文塞满 */
  const int kMaxLines = 5000;
  const size_t kMaxBytes = 512 * 1024;
  int stop = end;
  int capped_lines = 0;
  if (stop - start + 1 > kMaxLines) {
    stop = start + kMaxLines - 1;
    capped_lines = 1;
  }

  buf_t body;
  buf_init(&body);
  size_t sofar = 0;
  int line_no = 0;
  int emitted = 0;
  int capped_bytes = 0;
  size_t pos = 0;
  while (pos <= len && line_no <= stop) {
    size_t eol = pos;
    while (eol < len && data[eol] != '\n') eol++;
    if (line_no >= start) {
      size_t n = eol - pos;
      while (n > 0 && data[pos + n - 1] == '\r') n--;
      if (sofar + n + 1 > kMaxBytes) {
        capped_bytes = 1;
        break;
      }
      buf_putn(&body, data + pos, n);
      buf_putc_(&body, '\n');
      sofar += n + 1;
      emitted++;
    }
    if (eol >= len) break;
    pos = eol + 1;
    line_no++;
  }

  int last = start + (emitted > 0 ? emitted - 1 : 0);
  buf_t b;
  buf_init(&b);
  if (total == 0) {
    buf_printf(&b, "文件 %s 是空的(0 行)\n", u8);
  } else {
    buf_printf(&b, "文件 %s 的第 %d 到 %d 行(共 %d 行)\n", u8, start, last, total);
    if (capped_lines || capped_bytes) {
      buf_printf(&b, "这段已是单次上限;要接着看就从 startline=%d 开始\n", last + 1);
    }
    buf_puts(&b, "----\n");
    buf_putn(&b, body.data ? body.data : "", body.len);
    buf_puts(&b, "----\n");
  }

  out->data = j_obj();
  j_set_str(out->data, "path", u8);
  j_set_num(out->data, "totalLines", (double)total);
  j_set_num(out->data, "startLine", (double)start);
  j_set_num(out->data, "endLine", (double)last);
  j_set_bool(out->data, "truncated", (capped_lines || capped_bytes));
  {
    char *seg = (char *)xmalloc(body.len + 1);
    memcpy(seg, body.data ? body.data : "", body.len);
    seg[body.len] = 0;
    j_set_str(out->data, "content", seg);
    free(seg);
  }
  buf_free(&body);
  free(data);
  out->text = b.data;
  return 0;
}

/* ================= 列目录 ================= */
int fs_tool_list(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  (void)ctx;
  const char *raw = j_s(args, "path", "");
  wchar_t full[MAX_PATH * 4];
  char err[512];
  if (!abs_path(raw[0] ? raw : ".", full, sizeof(full) / sizeof(full[0]))) {
    out->is_error = 1;
    out->text = xstrdup("路径看不懂");
    return -1;
  }
  if (!check_allowed(full, 0, err, sizeof(err))) {
    out->is_error = 1;
    out->text = xstrdup(err);
    return -1;
  }
  char *dir8 = w_to_u8(full);
  if (!dir8) {
    out->is_error = 1;
    out->text = xstrdup("路径编码转换失败");
    return -1;
  }

  std::vector<std::string> dirs = fs_list_dirs(dir8);
  std::vector<std::string> files = fs_list_files(dir8, NULL);

  buf_t b;
  buf_init(&b);
  buf_printf(&b, "目录 %s:%d 个子目录,%d 个文件\n", dir8, (int)dirs.size(), (int)files.size());
  json_t *arr = j_arr();
  for (size_t i = 0; i < dirs.size() && i < 200; i++) {
    buf_printf(&b, "  [目录] %s/\n", dirs[i].c_str());
    json_t *o = j_obj();
    j_set_str(o, "name", dirs[i].c_str());
    j_set_str(o, "type", "dir");
    j_add(arr, o);
  }
  for (size_t i = 0; i < files.size() && i < 500; i++) {
    char one[MAX_PATH * 4];
    snprintf(one, sizeof(one), "%s\\%s", dir8, files[i].c_str());
    long sz = file_size(one);
    buf_printf(&b, "  [文件] %s(%ld 字节)\n", files[i].c_str(), sz < 0 ? 0 : sz);
    json_t *o = j_obj();
    j_set_str(o, "name", files[i].c_str());
    j_set_str(o, "type", "file");
    j_set_num(o, "size", (double)(sz < 0 ? 0 : sz));
    j_add(arr, o);
  }
  if (files.empty() && dirs.empty()) buf_puts(&b, "  (空目录)\n");

  out->data = j_obj();
  j_set_str(out->data, "path", dir8);
  j_set(out->data, "entries", arr);
  free(dir8);
  out->text = b.data;
  return 0;
}

/* ================= 写 ================= */
int fs_tool_write(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  (void)ctx;
  const char *raw = j_s(args, "path", "");
  const char *content = j_s(args, "content", "");
  int append = (int)j_b(args, "append", 0);
  wchar_t full[MAX_PATH * 4];
  char err[512];
  if (!abs_path(raw, full, sizeof(full) / sizeof(full[0]))) {
    out->is_error = 1;
    out->text = xstrdup("路径看不懂(空路径或太长)");
    return -1;
  }
  if (!check_allowed(full, 1, err, sizeof(err))) {
    out->is_error = 1;
    out->text = xstrdup(err);
    return -1;
  }
  char *p8 = w_to_u8(full);
  if (!p8) {
    out->is_error = 1;
    out->text = xstrdup("路径编码转换失败");
    return -1;
  }
  char target[MAX_PATH * 4];
  snprintf(target, sizeof(target), "%s", p8);
  free(p8);

  /* 目标目录不存在就建 —— 但只在数据目录内(前面已经保证) */
  char parent[MAX_PATH * 4];
  path_dir_of(target, parent, sizeof(parent));
  ensure_dir(parent);

  size_t clen = strlen(content);
  int existed = file_size(target) >= 0;

  if (!append && existed) {
    /* 覆盖前留一份:模型写坏一版还能捡回来,不需要人记得先备份 */
    size_t old_len = 0;
    char *old = file_read_all(target, &old_len);
    if (old) {
      char bak[MAX_PATH * 4];
      snprintf(bak, sizeof(bak), "%s.bak", target);
      file_write_all(bak, old, old_len);
      free(old);
    }
  }

  int rc = append ? file_append(target, content, clen) : file_write_all(target, content, clen);
  if (rc != 0) {
    out->is_error = 1;
    out->text = xstrdup("写不进去(磁盘满或没有权限)");
    return -1;
  }

  buf_t b;
  buf_init(&b);
  buf_printf(&b, "已%s %s(%lu 字节%s)\n", append ? "追加到" : "写入", target,
             (unsigned long)clen, (!append && existed) ? ",原内容已备份为同名 .bak" : "");
  out->data = j_obj();
  j_set_str(out->data, "path", target);
  j_set_num(out->data, "bytes", (double)clen);
  j_set_bool(out->data, "appended", append);
  j_set_bool(out->data, "backup", (!append && existed));
  out->text = b.data;
  return 0;
}
