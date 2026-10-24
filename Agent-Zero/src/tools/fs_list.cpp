/* fs_list.cpp —— 列目录:子目录、文件、大小。
 * 协议:{ "path": "." }
 */
#include "tool_api.h"

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
