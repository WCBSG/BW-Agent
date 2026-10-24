/* fs_write.cpp —— 写数据目录里的文件。
 * 协议:{ "path": "...", "content": "...", "append": false }
 * 覆盖前留同名 .bak;不提供删除 —— 要删请人自己删。
 */
#include "tool_api.h"

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
