/* res.cpp —— 资源加载:磁盘优先,内置兜底。
 *
 * 交付给用户的是一个 exe,里面已经带了界面与默认规则;但如果旁边存在同名文件
 * (比如用户想换一套界面、或改规则调检测范围),就优先用磁盘上的那份。
 * 这样"单文件可用"和"可定制"两件事不冲突。
 */
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

/* 把内置的 data/<子目录>/ 资源铺到数据目录:已存在的文件不覆盖(改过的内容不能被冲掉)。
   资源名用 / 分隔,落盘时换回 Windows 的 \。 */
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
    for (char *p = rel; *p; p++) {
      if (*p == '/') *p = '\\';
    }
    char dst[MAX_PATH * 2];
    snprintf(dst, sizeof(dst), "%s\\%s", dst_dir, rel);

    /* 配置文件:已存在就不覆盖(使用者改过的东西不能被冲掉)。
       可执行文件:程序升级时必须换成新的,否则旧工具 exe 会一直跑下去。 */
    int is_bin = str_endswith(rel, ".exe") || str_endswith(rel, ".dll");
    if (!is_bin && file_size(dst) >= 0) continue;

    char parent[MAX_PATH * 2];
    path_dir_of(dst, parent, sizeof(parent));
    ensure_dir(parent);
    if (file_write_all(dst, data, len) == 0) {
      written++;
      log_info("[数据目录] 铺开 %s", dst);
    }
  }
  return written;
}

int res_bootstrap_data_dir(void) {
  const char *ddir = app_data_dir();
  ensure_dir(ddir);
  int written = 0;
  char path[MAX_PATH * 2];
  /* 早期版本会往数据目录里丢一份「使用说明.txt」。那份说明早就过时了,
     留着只会让人按旧内容去改配置。这里做一次清理:见到就删。 */
  app_data_path(path, sizeof(path), "使用说明.txt");
  if (file_size(path) >= 0) {
    wchar_t *w = u8_to_w(path);
    if (w) {
      if (DeleteFileW(w)) log_info("[数据目录] 已清理过时的 使用说明.txt");
      free(w);
    }
  }

  /* 规则按 6 个域分发在 data\rules\ 里:整目录铺开,缺哪个域就用打包的那份补上。
     老版本的单文件 rules.json 不再生成 —— 两处各有一份值时"哪份生效"说不清。 */
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

  /* 如果程序旁边(或开发目录里)放着一份测试集,顺手带一份到数据目录 ——
     作为自建回归用例;它不用于对外报效果指标(那该由评测方按统一评测集算)。 */
  app_data_path(path, sizeof(path), "testcases.jsonl");
  if (file_size(path) < 0) {
    size_t len = 0;
    char side[MAX_PATH * 2];
    snprintf(side, sizeof(side), "%sdata\\testcases.jsonl", app_dir());
    char *txt = file_read_all(side, &len);
    if (!txt) {
      /* exe 就在 data 目录里时(开发时的 build\ 形态)再往上找一层 */
      snprintf(side, sizeof(side), "%s..\\data\\testcases.jsonl", app_dir());
      txt = file_read_all(side, &len);
    }
    if (txt) {
      if (file_write_all(path, txt, len) == 0) written++;
      free(txt);
    }
  }
  if (written > 0) {
    log_info("[数据目录] 首次运行:已写入 %d 个可改文件到 %s", written, ddir);
  }
  return written;
}
