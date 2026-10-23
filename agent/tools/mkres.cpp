/* mkres.c —— 构建期小工具:把界面与默认规则打包成一份 C 数组。
 *
 * 用法:  mkres <输出.c> <名字=文件> [<名字=文件> ...]
 * 例:    mkres build\resources.cpp ui/index.html=ui\index.html data/rules.json=data\rules.json
 *
 * 为什么要有这个:交付目标是"一个 exe 双击就能用",所以界面和默认规则必须在
 * 可执行文件里,而不是依赖旁边的目录。用 C 数组而不是资源段,是为了不依赖
 * objcopy/rc 之类的外部工具 —— 只要 gcc 就能编出来。
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>

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

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "用法: mkres <输出.cpp> <名字=文件> [<名字=文件> ...]\n");
    return 2;
  }
  char **names = (char **)calloc((size_t)(argc - 2), sizeof(char *));
  char **ids = (char **)calloc((size_t)(argc - 2), sizeof(char *));
  if (!names || !ids) return 3;
  FILE *body = tmpfile();
  if (!body) return 3;

  int n = 0;
  for (int i = 2; i < argc; i++) {
    char *eq = strchr(argv[i], '=');
    if (!eq) {
      fprintf(stderr, "[mkres] 参数格式不对(应为 名字=文件): %s\n", argv[i]);
      return 2;
    }
    *eq = 0;
    /* 名字要留副本:argv 里那个 '=' 待会儿要还原,不能直接拿它当资源名 */
    names[n] = (char *)calloc(strlen(argv[i]) + 1, 1);
    if (!names[n]) return 3;
    strcpy(names[n], argv[i]);
    ids[n] = (char *)calloc(256, 1);
    if (!ids[n]) return 3;
    ident_of(names[n], ids[n], 256);
    if (write_one(body, names[n], eq + 1) != 0) return 1;
    n++;
    *eq = '=';
  }

  FILE *out = fopen(argv[1], "wb");
  if (!out) {
    fprintf(stderr, "[mkres] 写不了输出文件: %s\n", argv[1]);
    return 1;
  }
  fprintf(out,
          "/* resources.cpp —— 由 tools/mkres.cpp 自动生成,请勿手改。\n"
          "   内容:界面三件套 + 默认规则。改了 ui/ 或 data/rules.json 后重新构建即可。 */\n"
          "#include \"embed.h\"\n#include <cstring>\n\n");
  rewind(body);
  int c;
  while ((c = fgetc(body)) != EOF) fputc(c, out);
  fclose(body);

  fprintf(out, "typedef struct { const char *name; const unsigned char *data; "
               "unsigned long len; } res_t;\n");
  fprintf(out, "static const res_t RES[] = {\n");
  for (int i = 0; i < n; i++) {
    fprintf(out, "  {\"%s\", res_%s, sizeof(res_%s)},\n", names[i], ids[i], ids[i]);
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
  fprintf(stderr, "[mkres] 已写出 %s(%d 个资源)\n", argv[1], n);
  return 0;
}
