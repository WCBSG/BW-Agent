/* toolhost.cpp —— 工具宿主:主程序以 `agent.exe toolhost` 形态充当"工具进程"。
 *
 * 协议(见 docs/工具协议.md):
 *   stdin  {"tool":"fs_read","args":{...},"context":{"data_dir":"...","app_dir":"..."}}
 *   stdout {"text":"...","say":"...","data":{...},"is_error":false}
 *
 * 不再单独编译 bw_tools.exe:工具实现本来就在主程序里,再打包一份纯属重复。
 */
#include <windows.h>

#include <cstdio>
#include <cstring>

#include "agent.h"
#include "common.h"
#include "json.h"
#include "net.h"
#include "rules.h"
#include "store.h"
#include "tool_api.h"
#include "tools.h"

static char *read_stdin_all(size_t *out_len) {
  buf_t b;
  buf_init(&b);
  HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
  char chunk[4096];
  DWORD got = 0;
  while (h && h != INVALID_HANDLE_VALUE &&
         ReadFile(h, chunk, sizeof(chunk) - 1, &got, NULL) && got > 0) {
    buf_putn(&b, chunk, got);
    if (b.len > 4 * 1024 * 1024) break;
  }
  if (out_len) *out_len = b.len;
  return buf_take(&b);
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

int toolhost_run(const char *tool_arg) {
  SetConsoleOutputCP(65001);
  SetConsoleCP(65001);
  /* stdout 只放结果 JSON:日志一律丢掉(文件日志另有 log_open) */
  freopen("NUL", "w", stderr);
  log_set_level(LOG_ERROR);

  char tool[64] = {0};
  if (tool_arg && *tool_arg) snprintf(tool, sizeof(tool), "%s", tool_arg);

  json_t *args = NULL;
  json_t *req = NULL;
  size_t len = 0;
  char *input = read_stdin_all(&len);
  if (input && *input) {
    req = json_parse(input);
    if (req) {
      const char *t = j_s(req, "tool", "");
      if (!tool[0] && t[0]) snprintf(tool, sizeof(tool), "%s", t);
      json_t *a = j_get(req, "args");
      if (a) {
        char *d = json_dump(a);
        args = d ? json_parse(d) : NULL;
        free(d);
      }
      json_t *ctx = j_get(req, "context");
      const char *dd = ctx ? j_s(ctx, "data_dir", "") : "";
      if (dd[0]) {
        wchar_t *w = u8_to_w(dd);
        if (w) { SetEnvironmentVariableW(L"BW_AGENT_HOME", w); free(w); }
      }
      const char *app = ctx ? j_s(ctx, "app_dir", "") : "";
      if (app[0]) fs_tool_set_extra_root(app);
    }
  }
  if (!args) args = j_obj();

  if (!tool[0]) {
    json_t *o = j_obj();
    j_set_str(o, "text", "没有指定工具(请求里缺少 tool 字段)");
    j_set_bool(o, "is_error", 1);
    char *txt = json_dump(o);
    if (txt) { fputs(txt, stdout); fputc('\n', stdout); free(txt); }
    json_free(o);
    json_free(args);
    json_free(req);
    free(input);
    return 1;
  }

  rules_init(app_dir());
  tools_init();
  store_t *store = store_open(app_data_dir());
  net_init();

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
  if (host[0]) { doms[0] = host; nd = 1; }
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
