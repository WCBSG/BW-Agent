/* res.cpp —— 资源加载:磁盘优先、exe 内置兜底;首次运行把出厂数据铺到数据目录。 */
#include "res.h"

#include "embed.h"

int res_load_text(const char *name, char **out, size_t *out_len) {
  if (out) *out = NULL;
  if (out_len) *out_len = 0;
  if (!name) return 0;

  /* 1) 磁盘(相对当前工作目录) */
  size_t len = 0;
  char *data = file_read_all(name, &len);
  if (data) {
    if (out) *out = data; else free(data);
    if (out_len) *out_len = len;
    return 1;
  }

  /* 2) exe 内置 */
  const char *builtin = NULL;
  size_t blen = 0;
  if (embed_lookup(name, &builtin, &blen)) {
    if (out) {
      char *copy = (char *)xmalloc(blen + 1);
      memcpy(copy, builtin, blen);
      copy[blen] = 0;
      *out = copy;
    }
    if (out_len) *out_len = blen;
    return 1;
  }
  return 0;
}

int res_exists(const char *name) {
  if (!name) return 0;
  long sz = file_size(name);
  if (sz >= 0) return 1;
  const char *d = NULL;
  size_t l = 0;
  return embed_lookup(name, &d, &l);
}

/* 把内置 data/<子目录>/ 铺到数据目录:配置类缺了才补,可执行文件每次都覆盖 */
static int spill_dir(const char *res_prefix, const char *dst_dir) {
  int written = 0;
  int total = embed_count();
  size_t plen = strlen(res_prefix);
  for (int i = 0; i < total; i++) {
    const char *nm = embed_name_at(i);
    if (!nm || strncmp(nm, res_prefix, plen) != 0) continue;
    const char *data = NULL;
    size_t len = 0;
    if (!embed_lookup(nm, &data, &len)) continue;

    char rel[MAX_PATH * 2];
    snprintf(rel, sizeof(rel), "%s", nm + plen);
    for (char *p = rel; *p; p++) if (*p == '/') *p = '\\';
    char dst[MAX_PATH * 2];
    snprintf(dst, sizeof(dst), "%s\\%s", dst_dir, rel);

    int is_bin = str_endswith(rel, ".exe") || str_endswith(rel, ".dll");
    if (!is_bin && file_size(dst) >= 0) continue;
    char parent[MAX_PATH * 2];
    path_dir_of(dst, parent, sizeof(parent));
    ensure_dir(parent);
    if (file_write_all(dst, data, len) == 0) written++;
  }
  return written;
}

int res_bootstrap_data_dir(void) {
  const char *ddir = app_data_dir();
  ensure_dir(ddir);
  int written = 0;
  char path[MAX_PATH * 2];
  app_data_path(path, sizeof(path), "rules");
  ensure_dir(path);
  written += spill_dir("data/rules/", path);

  /* 工具声明、技能目录、MCP 清单:同样随 exe 打包,
     首次运行时铺到数据目录 —— 使用者打开就能改,改完不用重新编译。 */
  app_data_path(path, sizeof(path), "tools");
  ensure_dir(path);
  written += spill_dir("data/tools/", path);

  app_data_path(path, sizeof(path), "skills");
  ensure_dir(path);
  written += spill_dir("data/skills/", path);

  app_data_path(path, sizeof(path), "mcp.json");
  if (file_size(path) < 0) {
    const char *data = NULL;
    size_t len = 0;
    if (embed_lookup("data/mcp.json", &data, &len)) {
      if (file_write_all(path, data, len) == 0) written++;
    }
  }

  if (written > 0) {
    log_info("[数据目录] 首次运行:已写入 %d 个可改文件到 %s", written, ddir);
  }
  return written;
}
