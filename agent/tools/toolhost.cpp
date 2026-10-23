/* toolhost.cpp —— 独立工具进程(make 每个内置工具都有自己的 exe)。
 *
 * 为什么要把工具做成独立进程:
 *   1. 能力"可替换":一个工具就是一个目录(声明 + 入口 exe),换掉 exe 就换了实现,
 *      主程序不需要重新编译。这在作品赛的验收里很重要 —— 评委会看到能力是数据化的。
 *   2. 崩溃隔离:探测类工具会跑网络与第三方程序(nuclei),它挂了不该拖垮智能体。
 *   3. 可单独验收:直接双击/命令行喂一段 JSON 就能看这个工具做了什么判断。
 *
 * 调用协议(与 tool_entry.cpp 完全一致):
 *   bwtool.exe fs_read '{"path":"rules.json","startline":0,"endline":40}'
 *   echo {"tool":"fs_read","args":{...},"context":{"data_dir":"..."}} | bwtool.exe
 * 返回:
 *   {"text":"给模型看的文本","say":"给人的汇报","data":{...},"is_error":false}
 *
 * 这个文件被编进每一个工具 exe:编译时用 -DTOOL_NAME=\"<名字>\" 把名字定死,
 * 所以即使被人改名成别的文件,它也还是那个工具。
 */
#include <windows.h>

#include <cstdio>
#include <cstring>

#include "agent.h"
#include "approval.h"
#include "common.h"
#include "fs_tool.h"
#include "json.h"
#include "llm.h"
#include "llm_provider.h"
#include "net.h"
#include "profile.h"
#include "rules.h"
#include "skills.h"
#include "store.h"
#include "tools.h"

#ifndef TOOL_NAME
#define TOOL_NAME "fs_read"
#endif

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


int main(int argc, char **argv) {
  SetConsoleOutputCP(65001);
  SetConsoleCP(65001);
  /* 工具进程是给机器读的:日志会成为 stdout 上的噪声,把 JSON 结果淹掉 */
  log_set_level(LOG_ERROR);

  /* ---------- 1. 先把请求读进来 ----------
     数据目录、程序目录都由调用方在 context 里给出:工具进程自己不知道"智能体装在哪",
     而且必须在初始化任何模块之前把 BW_AGENT_HOME 设好(它会被缓存)。 */
  json_t *req = NULL;
  char *input = NULL;

  json_t *args = NULL;
  if (argc > 1 && argv[1][0] == '{') {
    args = json_parse(argv[1]);
  }
  if (!args) {
    size_t len = 0;
    input = read_stdin_all(&len);
    if (input && *input) req = json_parse(input);
    if (req) {
      json_t *a = j_get(req, "args");
      if (a) {
        char *d = json_dump(a);
        args = d ? json_parse(d) : NULL;
        free(d);
      }
    }
  }
  if (!args) args = j_obj();

  const char *tool = TOOL_NAME;
  {
    /* 请求里写了 tool 且与本 exe 不符时,以本 exe 的名字为准 ——
       exe 是自己是谁的唯一权威,免得调用方传错名字. */
    json_t *ctxj = req ? j_get(req, "context") : NULL;
    if (ctxj) {
      set_env(L"BW_AGENT_HOME", j_s(ctxj, "data_dir", ""));
      const char *extra = j_s(ctxj, "app_dir", "");
      if (extra[0]) fs_tool_set_extra_root(extra);
      /* 命令行直跑(参数形态)时用不到 context,这里不强制 */
    }
  }

  /* ---------- 2. 初始化到"工具能用"为止 ----------
     顺序与主程序一致:先规则,再工具表,再存储,最后网络。 */
  rules_init(app_dir());
  tools_init();
  skills_init();
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

  /* 授权范围:目标来自参数,池子给边界。和主程序里一条工具调用的处境一样。 */
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
