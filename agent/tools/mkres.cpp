/* mkres.c —— 构建期小工具:把界面、默认规则、工具声明、技能目录打包成一份 C 数组。
 *
 * 用法:  mkres <输出.c> <名字=文件> [<名字=文件> ...] [@前缀=目录 ...]
 * 例:    mkres build\resources.cpp ui/index.html=ui/index.html data/rules.json=data\rules.json
 *        mkres build\resources.cpp @data/skills/=data\skills
 *
 * 为什么要有这个:交付目标是"一个 exe 双击就能用",所以界面和默认数据必须在
 * 可执行文件里,而不是依赖旁边的目录。用 C 数组而不是资源段,是为了不依赖
 * objcopy/rc 之类的外部工具 —— 只要 gcc 就能编出来。
 *
 * `@前缀=目录` 会把目录整棵打进资源里,资源名 = 前缀 + 相对路径(用 / 分隔),
 * 这样技能可以带自己的 scripts/,工具也可以一个工具一个文件。
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#ifdef _WIN32
#include <windows.h>
#endif

/* 把"名字"变成合法的 C 标识符后缀(里面可能有 / 或 . ) */
static void ident_of(const char *name, char *out, size_t cap) {
  size_t j = 0;
  for (size_t i = 0; name[i] && j + 1 < cap; i++) {
    char c = name[i];
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
      out[j++] = c;
    } else {
      out[j++] = '_';
    }
  }
  out[j] = 0;
}

static int write_one(FILE *out, const char *name, const char *path) {
  FILE *in = fopen(path, "rb");
  if (!in) {
    fprintf(stderr, "[mkres] 打不开: %s\n", path);
    return -1;
  }
  char id[256];
  ident_of(name, id, sizeof(id));
  fprintf(out, "/* %s(来自 %s) */\n", name, path);
  fprintf(out, "static const unsigned char res_%s[] = {\n  ", id);
  unsigned long total = 0;
  int c, col = 0;
  while ((c = fgetc(in)) != EOF) {
    fprintf(out, "%u,", (unsigned char)c);
    total++;
    if (++col == 20) {
      fprintf(out, "\n  ");
      col = 0;
    }
  }
  fprintf(out, "\n};\n\n");
  fclose(in);
  fprintf(stderr, "[mkres] %-18s <- %s(%lu 字节)\n", name, path, total);
  return 0;
}

typedef struct { char *name; char *path; } entry_t;

#define MAX_ENT 8192
static entry_t g_ent[MAX_ENT];
static int g_n = 0;

static char *xdup(const char *s) {
  size_t n = strlen(s) + 1;
  char *p = (char *)malloc(n);
  if (p) memcpy(p, s, n);
  return p;
}

static void push(const char *name, const char *path) {
  if (g_n >= MAX_ENT) {
    fprintf(stderr, "[mkres] 资源超过 %d 个,停了\n", MAX_ENT);
    exit(3);
  }
  for (int i = 0; i < g_n; i++) {
    if (strcmp(g_ent[i].name, name) == 0) {
      fprintf(stderr, "[mkres] 资源名重复: %s\n", name);
      exit(2);
    }
  }
  g_ent[g_n].name = xdup(name);
  g_ent[g_n].path = xdup(path);
  g_n++;
}

/* 目录整棵收进来。资源名用 '/' 分隔,和 exe 里查表时写的一致。 */
static void walk_dir(const char *prefix, const char *rel, const char *full) {
#ifdef _WIN32
  char pat[1024];
  snprintf(pat, sizeof(pat), "%s\\*", full);
  WIN32_FIND_DATAA fd;
  HANDLE h = FindFirstFileA(pat, &fd);
  if (h == INVALID_HANDLE_VALUE) {
    fprintf(stderr, "[mkres] 目录读不了: %s\n", full);
    return;
  }
  do {
    if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
    char child_full[1024], child_rel[1024];
    snprintf(child_full, sizeof(child_full), "%s\\%s", full, fd.cFileName);
    if (rel[0]) snprintf(child_rel, sizeof(child_rel), "%s/%s", rel, fd.cFileName);
    else snprintf(child_rel, sizeof(child_rel), "%s", fd.cFileName);
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      walk_dir(prefix, child_rel, child_full);
    } else {
      char nm[1024];
      snprintf(nm, sizeof(nm), "%s%s", prefix, child_rel);
      push(nm, child_full);
    }
  } while (FindNextFileA(h, &fd));
  FindClose(h);
#else
  (void)prefix; (void)rel; (void)full;
#endif
}

static int cmp_ent(const void *a, const void *b) {
  return strcmp(((const entry_t *)a)->name, ((const entry_t *)b)->name);
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "用法: mkres <输出.cpp> <名字=文件> [<名字=文件> ...] [@前缀=目录 ...]\n");
    return 2;
  }
  for (int i = 2; i < argc; i++) {
    if (argv[i][0] == '@') {
      char *eq = strchr(argv[i], '=');
      if (!eq) {
        fprintf(stderr, "[mkres] 目录参数格式不对(应为 @前缀=目录): %s\n", argv[i]);
        return 2;
      }
      *eq = 0;
      char prefix[512];
      snprintf(prefix, sizeof(prefix), "%s", argv[i] + 1);
      walk_dir(prefix, "", eq + 1);
      *eq = '=';
    } else {
      char *eq = strchr(argv[i], '=');
      if (!eq) {
        fprintf(stderr, "[mkres] 参数格式不对(应为 名字=文件): %s\n", argv[i]);
        return 2;
      }
      *eq = 0;
      push(argv[i], eq + 1);
      *eq = '=';
    }
  }
  if (g_n == 0) {
    fprintf(stderr, "[mkres] 一个资源都没有,检查一下参数\n");
    return 2;
  }
  qsort(g_ent, (size_t)g_n, sizeof(g_ent[0]), cmp_ent);

  FILE *body = tmpfile();
  if (!body) return 3;
  char **ids = (char **)calloc((size_t)g_n, sizeof(char *));
  if (!ids) return 3;
  for (int i = 0; i < g_n; i++) {
    ids[i] = (char *)calloc(256, 1);
    if (!ids[i]) return 3;
    ident_of(g_ent[i].name, ids[i], 256);
    if (write_one(body, g_ent[i].name, g_ent[i].path) != 0) return 1;
  }

  FILE *out = fopen(argv[1], "wb");
  if (!out) {
    fprintf(stderr, "[mkres] 写不了输出文件: %s\n", argv[1]);
    return 1;
  }
  fprintf(out,
          "/* resources.cpp —— 由 tools/mkres.cpp 自动生成,请勿手改。\n"
          "   内容:界面三件套 + 默认规则 + 工具声明 + 内置技能。\n"
          "   改了 ui/ 或 data/ 下的东西后重新构建即可。 */\n"
          "#include \"embed.h\"\n#include <cstring>\n\n");
  rewind(body);
  int c;
  while ((c = fgetc(body)) != EOF) fputc(c, out);
  fclose(body);

  fprintf(out, "typedef struct { const char *name; const unsigned char *data; "
               "unsigned long len; } res_t;\n");
  fprintf(out, "static const res_t RES[] = {\n");
  for (int i = 0; i < g_n; i++) {
    fprintf(out, "  {\"%s\", res_%s, sizeof(res_%s)},\n", g_ent[i].name, ids[i], ids[i]);
  }
  fprintf(out, "};\n\n");
  fprintf(out,
          "int embed_count(void) { return (int)(sizeof(RES) / sizeof(RES[0])); }\n\n"
          "const char *embed_name_at(int i) {\n"
          "  if (i < 0 || i >= embed_count()) return NULL;\n"
          "  return RES[i].name;\n"
          "}\n\n"
          "int embed_lookup(const char *name, const char **data, size_t *len) {\n"
          "  if (!name) return 0;\n"
          "  for (int i = 0; i < embed_count(); i++) {\n"
          "    if (strcmp(RES[i].name, name) == 0) {\n"
          "      if (data) *data = (const char *)RES[i].data;\n"
          "      if (len) *len = (size_t)RES[i].len;\n"
          "      return 1;\n"
          "    }\n"
          "  }\n"
          "  return 0;\n"
          "}\n");
  fclose(out);
  fprintf(stderr, "[mkres] 已写出 %s(%d 个资源)\n", argv[1], g_n);
  return 0;
}
