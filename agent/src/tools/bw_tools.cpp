/* bw_tools.cpp —— 内置工具的统一宿主:一个 exe 承载全部工具。
 *
 * 为什么合成一个程序:
 *   拆成 15 个 exe 时,每个都背着一份静态运行库与引擎,合计十几 MB,
 *   而每个工具自己的代码只有几 KB。合成一个之后,交付里只有这一份。
 *
 * 调用方式(与 tool_entry.cpp 的协议完全一致):
 *   bw_tools.exe fs_read '{"path":"rules.json","startline":0,"endline":40}'
 *   echo {"tool":"fs_read","args":{...},"context":{"data_dir":"..."}} | bw_tools.exe
 *   bw_tools.exe --list                 列出它能跑的所有工具
 *
 * 返回:
 *   {"text":"给模型看的文本","say":"给人的汇报","data":{...},"is_error":false}
 *
 * 每个工具的实现仍是一个独立源文件(src\tools\<名字>.cpp),
 * 只是不再各自编成一个 exe —— 能力边界靠"注册表里有没有它"来划,不靠进程个数。
 */
#include <windows.h>

#include <cstdio>
#include <cstring>

#include "approval.h"
#include "common.h"
#include "json.h"
#include "llm.h"
#include "net.h"
#include "rules.h"
#include "store.h"
#include "tool_api.h"
#include "tools.h"

/* 从 stdin 读完整请求(调用方写完就关,不会挂住) */
static char *read_stdin_all(size_t *out_len) {
  buf_t b;
  buf_init(&b);
  HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
  char chunk[4096];
  DWORD got = 0;
  while (h && h != INVALID_HANDLE_VALUE &&
         ReadFile(h, chunk, sizeof(chunk), &got, NULL) && got > 0) {
    buf_putn(&b, chunk, got);
    if (b.len > 4 * 1024 * 1024) break;
  }
  if (out_len) *out_len = b.len;
  return buf_take(&b);
}

static void set_env(const wchar_t *name, const char *value) {
  if (!value || !*value) return;
  wchar_t *w = u8_to_w(value);
  if (w) {
    SetEnvironmentVariableW(name, w);
    free(w);
  }
}

static void write_result(tool_result_t *r, int rc) {
  json_t *o = j_obj();
  j_set_str(o, "text", r->text ? r->text : "");
  if (r->say) j_set_str(o, "say", r->say);
  if (r->data) {
    char *d = json_dump(r->data);
    if (d) {
      json_t *copy = json_parse(d);
      if (copy) j_set(o, "data", copy);
      free(d);
    }
  }
  j_set_bool(o, "is_error", (r->is_error || rc != 0) ? 1 : 0);
  char *txt = json_dump(o);
  if (txt) {
    fputs(txt, stdout);
    fputc('\n', stdout);
    fflush(stdout);
    free(txt);
  }
  json_free(o);
}

static int print_list(void) {
  for (int i = 0; i < tools_count(); i++) {
    tool_t *t = tools_get(i);
    if (!t) continue;
    printf("%-24s %s\n", t->name, t->description ? t->description : "");
  }
  return 0;
}

int main(int argc, char **argv) {
  SetConsoleOutputCP(65001);
  SetConsoleCP(65001);
  /* 这个进程是给机器读的:日志会混进 stdout,把 JSON 结果淹掉 */
  log_set_level(LOG_ERROR);

  if (argc > 1 && (str_ieq(argv[1], "--list") || str_ieq(argv[1], "-l"))) {
    tools_init();
    return print_list();
  }

  /* ---------- 1. 读请求 ---------- */
  char tool[64] = {0};
  json_t *args = NULL;
  json_t *req = NULL;
  char *input = NULL;

  if (argc > 1 && argv[1][0] != '{') snprintf(tool, sizeof(tool), "%s", argv[1]);
  if (argc > 2 && argv[2][0] == '{') args = json_parse(argv[2]);
  else if (argc > 1 && argv[1][0] == '{') args = json_parse(argv[1]);

  if (!args || !tool[0]) {
    size_t len = 0;
    input = read_stdin_all(&len);
    if (input && *input) req = json_parse(input);
    if (req) {
      const char *t = j_s(req, "tool", "");
      if (t[0]) snprintf(tool, sizeof(tool), "%s", t);
      json_t *a = j_get(req, "args");
      if (!args && a) {
        char *d = json_dump(a);
        args = d ? json_parse(d) : NULL;
        free(d);
      }
      json_t *ctxj = j_get(req, "context");
      if (ctxj) {
        /* 必须在任何模块初始化之前设好:数据目录会被缓存 */
        set_env(L"BW_AGENT_HOME", j_s(ctxj, "data_dir", ""));
        const char *extra = j_s(ctxj, "app_dir", "");
        if (extra[0]) fs_tool_set_extra_root(extra);
      }
    }
  }
  if (!args) args = j_obj();

  if (!tool[0]) {
    json_t *o = j_obj();
    j_set_str(o, "text",
              "没有指定工具。用法:bw_tools <工具名> '<JSON 参数>';"
              "或 echo {\"tool\":\"...\",\"args\":{...}} | bw_tools;bw_tools --list 看全部");
    j_set_bool(o, "is_error", 1);
    char *txt = json_dump(o);
    if (txt) { fputs(txt, stdout); fputc('\n', stdout); free(txt); }
    json_free(o);
    json_free(args);
    json_free(req);
    free(input);
    return 1;
  }

  /* ---------- 2. 初始化到"工具能用"为止 ---------- */
  rules_init(app_dir());
  tools_init();
  store_t *store = store_open(app_data_dir());
  llm_init(app_dir());
  net_init();
  approval_load();

  {
    char pool_path[MAX_PATH * 2];
    app_data_path(pool_path, sizeof(pool_path), "pool.json");
    net_pool_load_file(pool_path);
  }

  /* ---------- 3. 跑工具 ---------- */
  tool_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.io = *net_io_impl();
  ctx.store = store;
  ctx.task_id = "TOOL";

  buf_t note;
  buf_init(&note);
  ctx.note = &note;

  const char *target = j_s(args, "target", "");
  if (!target[0]) target = j_s(args, "url", "");
  char host[256] = {0};
  if (target[0]) {
    net_host_of(target, host, sizeof(host));
    if (host[0]) net_align_base_from(target);
  }
  const char *doms[1];
  int nd = 0;
  if (host[0]) {
    doms[0] = host;
    nd = 1;
  }
  ctx.domains = nd ? doms : NULL;
  ctx.domain_count = nd;
  net_set_scope(ctx.task_id, nd ? doms : NULL, nd);

  tool_result_t r;
  memset(&r, 0, sizeof(r));
  int rc = tools_run_builtin(&ctx, tool, args, &r);

  write_result(&r, rc);

  free(r.text);
  free(r.say);
  json_free(r.data);
  buf_free(&note);
  json_free(args);
  json_free(req);
  free(input);

  store_close(store);
  net_shutdown();
  rules_shutdown();
  return rc == 0 ? 0 : 1;
}
