/* fs_read.cpp —— 按行读本机文本文件。
 *
 * 协议:{ "path": "...", "startline": 0, "endline": 100 }
 * 行号 0 基、两端都算;省略 endline 读到文件末尾。
 * 边界:只能读数据目录与程序目录,写只能写数据目录(理由见 fs_common.cpp)。
 */
#include "tool_api.h"

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
