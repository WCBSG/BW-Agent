/* ext.cpp —— 可扩展层实现:外部工具 / 技能包 / MCP 服务器。
 *
 * 设计取向(照 Claude Code 那套"用户目录里的配置就能加能力"的思路,但落地成 C):
 *
 * 1) 外部工具:tools\<名字>.json
 *    {
 *      "name": "whois_lookup",              // 工具名(模型看到的就是它)
 *      "description": "查域名注册信息",      // 说明书,模型据此决定用不用
 *      "schema": { ...JSON Schema... },      // 参数形状(可省)
 *      "command": "whois $target",           // 命令行;$参数名 会被替换进来
 *      "timeout_ms": 20000,
 *      "allow": true                         // 不开这个不执行,只登记
 *    }
 *
 * 2) 技能包:skills\<名字>.md —— 用 Markdown 写"什么时候用、怎么一步步做"。
 *    带 front-matter:
 *      ---
 *      name: 上线前自查
 *      title: 上线前自查
 *      when: 用户说"上线前帮我过一遍"时用
 *      tools: site_crawl,sensitive_file_probe
 *      command:                    (可选;留空就是纯方法论文本)
 *      allow: true                  (有 command 时才需要)
 *      ---
 *      (正文 = 步骤说明,会喂给模型)
 *
 * 3) MCP 服务器:mcp.json
 *    { "servers": [ { "name": "demo", "command": "...", "cwd": "...", "allow": true } ] }
 *    启动时握手 initialize → tools/list,把每个工具登记成 mcp__<server>__<tool>;
 *    调用时走 tools/call,结果(文本块)作为工具输出。
 *
 * 没有第三方依赖:进程用 CreateProcess + 匿名管道,JSON 用自己的解析器。
 */
#include "ext.h"

#include <ctype.h>

#include "json.h"
#include "res.h"
#include "rules.h"
#include "skills.h"
#include "store.h"
#include "tools.h"

/* ================= 外部工具 ================= */

typedef struct {
  char *name;
  char *description;
  char *schema;          /* 归一成字符串,交给工具注册表 */
  char *command;
  char *kind;
  char *workdir;
  int timeout_ms;
  int allow;
  char *source_file;
} ext_tool_t;

typedef struct {
  char *name;
  char *title;
  char *when;
  char *purpose;
  char *tools;
  char *body;            /* Markdown 正文 */
  char *command;         /* 有命令的技能是真执行 */
  int timeout_ms;
  int allow;
  char *source_file;
} ext_skill_t;

typedef struct {
  char *name;
  int pid;               /* 子进程 pid(退出时清理) */
  HANDLE hwrite, hread;  /* stdin / stdout 管道 */
  char *pending_buf;     /* 读缓冲(尚未凑成一条消息) */
  int initialized;
  int allow;
  json_t *tools;         /* tools/list 的缓存(只读借出) */
} mcp_server_t;

static ext_tool_t *g_etools = NULL;
static int g_etool_count = 0;
static ext_skill_t *g_eskills = NULL;
static int g_eskill_count = 0;
static mcp_server_t *g_mcp = NULL;
static int g_mcp_count = 0;
static int g_mcp_tool_count = 0;

const char *ext_dir(char *out, size_t cap, const char *child) {
  if (!child || !*child) return app_data_path(out, cap, "");
  char rel[MAX_PATH];
  snprintf(rel, sizeof(rel), "%s", child);
  return app_data_path(out, cap, rel);
}

/* 列目录里指定扩展名的文件(返回 UTF-8 全路径数组)。
   必须用宽字符版 API:窄字符版会把中文文件名按 ANSI 代码页读出来,
   再当 UTF-8 去打开就失败了 —— 用户的扩展文件名叫"示例-xxx.json"是很自然的事。 */
static int list_files(const char *dir, const char *ext, char ***out) {
  if (out) *out = NULL;
  char **list = NULL;
  int n = 0;
  wchar_t wdir[MAX_PATH * 2];
  wchar_t wpattern[MAX_PATH * 2];
  char *u8dir = NULL;

  u8dir = xstrdup(dir ? dir : "");
  wchar_t *w = u8_to_w(u8dir);
  if (!w) { free(u8dir); return 0; }
  swprintf(wdir, MAX_PATH * 2, L"%s", w);
  swprintf(wpattern, MAX_PATH * 2, L"%s\\*%S", w, ext ? ext : "");
  free(w);

  WIN32_FIND_DATAW fd;
  HANDLE h = FindFirstFileW(wpattern, &fd);
  if (h == INVALID_HANDLE_VALUE) { free(u8dir); return 0; }
  do {
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
    char *name = w_to_u8(fd.cFileName);
    if (!name) continue;
    char full[MAX_PATH * 2];
    snprintf(full, sizeof(full), "%s\\%s", u8dir, name);
    free(name);
    list = (char **)xrealloc(list, sizeof(char *) * (size_t)(n + 1));
    list[n++] = xstrdup(full);
  } while (FindNextFileW(h, &fd));
  FindClose(h);
  free(u8dir);
  if (out) *out = list;
  else str_free_list(list, n);
  return n;
}

/* ---------- 进程执行(捕获 stdout)---------- */
/* 把命令交给 cmd 解释一遍:这样 .cmd/.bat/.ps1、管道、重定向都能用
   (用户写的配置就跟他自己在命令行里敲的一样);已经写了 cmd 的就不再包一层。 */
static char *shell_wrap(const char *cmdline) {
  if (!cmdline || !*cmdline) return NULL;
  const char *p = cmdline;
  while (*p == ' ' || *p == '\t') p++;
  if (_strnicmp(p, "cmd ", 4) == 0 || _strnicmp(p, "cmd.exe", 7) == 0 ||
      _strnicmp(p, "cmd/", 4) == 0 || _strnicmp(p, "cmd\\", 4) == 0) {
    return xstrdup(cmdline);
  }
  buf_t b;
  buf_init(&b);
  /* /d 跳过 AutoRun,/s 让 "..." 里的内容原样执行(命令行里带引号时才不会被拆坏) */
  buf_puts(&b, "cmd.exe /d /s /c \"");
  buf_puts(&b, cmdline);
  buf_putc_(&b, '"');
  return buf_take(&b);
}

/* 跑一条命令,把 stdout+stderr 收回来。成功 0;失败 -1 并给出原因。 */
static int run_capture(const char *cmdline, const char *workdir, int timeout_ms,
                       char **out_text, int *out_exit) {
  if (out_text) *out_text = NULL;
  if (out_exit) *out_exit = -1;
  if (!cmdline || !*cmdline) return -1;

  SECURITY_ATTRIBUTES sa;
  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;

  HANDLE rd = NULL, wr = NULL;
  if (!CreatePipe(&rd, &wr, &sa, 0)) return -1;
  SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW si;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdOutput = wr;
  si.hStdError = wr;
  si.hStdInput = NULL;

  PROCESS_INFORMATION pi;
  memset(&pi, 0, sizeof(pi));

  char *wrapped = shell_wrap(cmdline);
  wchar_t *wcmd = wrapped ? u8_to_w(wrapped) : NULL;
  wchar_t *wdir = workdir && *workdir ? u8_to_w(workdir) : NULL;
  free(wrapped);
  if (!wcmd) { CloseHandle(rd); CloseHandle(wr); return -1; }

  BOOL ok = CreateProcessW(NULL, wcmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                           NULL, wdir, &si, &pi);
  free(wcmd);
  free(wdir);
  CloseHandle(wr);
  if (!ok) {
    CloseHandle(rd);
    return -1;
  }

  buf_t acc;
  buf_init(&acc);
  DWORD deadline = GetTickCount() + (DWORD)(timeout_ms > 0 ? timeout_ms : 20000);
  int timed_out = 0;
  char chunk[4096];
  for (;;) {
    DWORD avail = 0;
    if (PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL) && avail > 0) {
      DWORD got = 0;
      if (!ReadFile(rd, chunk, sizeof(chunk) - 1, &got, NULL) || got == 0) break;
      chunk[got] = 0;
      buf_putn(&acc, chunk, got);
      if (acc.len > 512 * 1024) break;          /* 别被失控输出拖死 */
      continue;
    }
    DWORD w = WaitForSingleObject(pi.hProcess, 60);
    if (w == WAIT_OBJECT_0) {
      /* 进程结束:把管道里剩下的读完 */
      DWORD got = 0;
      while (PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL) && avail > 0 &&
             ReadFile(rd, chunk, sizeof(chunk) - 1, &got, NULL) && got > 0) {
        chunk[got] = 0;
        buf_putn(&acc, chunk, got);
        if (acc.len > 512 * 1024) break;
      }
      break;
    }
    if (GetTickCount() > deadline) { timed_out = 1; TerminateProcess(pi.hProcess, 1); break; }
  }

  DWORD code = 0;
  GetExitCodeProcess(pi.hProcess, &code);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  CloseHandle(rd);

  if (out_text) *out_text = buf_take(&acc);
  else buf_free(&acc);
  if (out_exit) *out_exit = (int)code;
  return timed_out ? -2 : 0;
}

/* 对外暴露"跑一条命令收输出"的能力:外部工具、技能包与内置的开源工具编排共用同一套
   进程/管道实现,免得两处超时与回收逻辑各写一遍。 */
int ext_run_capture(const char *cmdline, const char *workdir, int timeout_ms,
                    char **out_text, int *out_exit) {
  return run_capture(cmdline, workdir, timeout_ms, out_text, out_exit);
}

/* ---------- 参数替换:$name / ${name} ---------- */
static void expand_cmd(buf_t *out, const char *tmpl, json_t *args) {
  for (const char *p = tmpl; *p; p++) {
    if (*p != '$') { buf_putc_(out, *p); continue; }
    int braced = (p[1] == '{');
    const char *start = p + (braced ? 2 : 1);
    const char *end = start;
    while (*end && (isalnum((unsigned char)*end) || *end == '_')) end++;
    if (end == start) { buf_putc_(out, '$'); continue; }
    char key[64];
    size_t n = (size_t)(end - start);
    if (n >= sizeof(key)) n = sizeof(key) - 1;
    memcpy(key, start, n);
    key[n] = 0;
    json_t *v = args ? j_get(args, key) : NULL;
    if (v && v->type == J_STR) {
      /* 参数是外部输入:加引号并按 cmd 规则转义,避免拼出第二条命令 */
      buf_putc_(out, '"');
      for (const char *s = v->str; *s; s++) {
        if (*s == '"' || *s == '\\' || *s == '&' || *s == '|' || *s == '<' ||
            *s == '>' || *s == '^' || *s == '%') {
          buf_putc_(out, '\\');
        }
        buf_putc_(out, *s);
      }
      buf_putc_(out, '"');
    } else if (v && (v->type == J_NUM || v->type == J_BOOL)) {
      char tmp[64];
      if (v->type == J_NUM) snprintf(tmp, sizeof(tmp), "%.0f", v->num);
      else snprintf(tmp, sizeof(tmp), "%s", v->b ? "true" : "false");
      buf_puts(out, tmp);
    }
    p = braced ? end : end - 1;
  }
}

/* 外部工具的执行入口(注册表里指向它) */
static int ext_tool_run(tool_ctx_t *ctx, const char *ext_name, json_t *args,
                        tool_result_t *out);

/* ================= 技能包(Markdown) ================= */
static char *read_file_utf8(const char *path) {
  size_t len = 0;
  char *text = file_read_all(path, &len);
  /* 记事本/PowerShell 存 UTF-8 会带 BOM,而 JSON 解析器不认它 —— 这里统一剥掉。
     (用户用记事本改配置是很正常的事,不能因此把配置当"不存在") */
  if (text && len >= 3 && (unsigned char)text[0] == 0xEF &&
      (unsigned char)text[1] == 0xBB && (unsigned char)text[2] == 0xBF) {
    memmove(text, text + 3, len - 3);
    text[len - 3] = 0;
  }
  return text;
}

/* 解析 front-matter(--- 开头的一段 key: value),正文原样返回 */
static void parse_front_matter(char *text, ext_skill_t *sk, char **body_out) {
  char *body = text;
  if (str_startswith(text, "---")) {
    char *nl = strchr(text, '\n');
    if (nl) {
      char *p = nl + 1;
      char *end = strstr(p, "\n---");
      if (end) {
        *end = 0;
        body = end + 4;
        while (*body == '\r' || *body == '\n') body++;
        /* 逐行 key: value */
        char **lines = NULL;
        int n = str_split(p, '\n', &lines, 0);
        for (int i = 0; i < n; i++) {
          char *line = str_trim(lines[i]);
          if (!line[0] || line[0] == '#') continue;
          char *colon = strchr(line, ':');
          if (!colon) continue;
          *colon = 0;
          char *k = str_trim(line);
          char *v = str_trim(colon + 1);
          /* 去掉可能的两端引号 */
          size_t vl = strlen(v);
          if (vl >= 2 && ((v[0] == '"' && v[vl - 1] == '"') || (v[0] == '\'' && v[vl - 1] == '\''))) {
            v[vl - 1] = 0;
            v++;
          }
          if (str_ieq(k, "name")) sk->name = xstrdup(v);
          else if (str_ieq(k, "title")) sk->title = xstrdup(v);
          else if (str_ieq(k, "when")) sk->when = xstrdup(v);
          else if (str_ieq(k, "purpose")) sk->purpose = xstrdup(v);
          else if (str_ieq(k, "tools")) sk->tools = xstrdup(v);
          else if (str_ieq(k, "command")) sk->command = xstrdup(v);
          else if (str_ieq(k, "timeout_ms")) sk->timeout_ms = atoi(v);
          else if (str_ieq(k, "allow")) sk->allow = str_ieq(v, "true") || strcmp(v, "1") == 0;
        }
        str_free_list(lines, n);
      }
    }
  }
  *body_out = xstrdup(body);
}

static int load_skills_dir(const char *dir) {
  char **files = NULL;
  int total = list_files(dir, ".md", &files);
  int n = 0;
  int overridden = 0;
  for (int i = 0; i < total; i++) {
    const char *path = files[i];
    char *text = read_file_utf8(path);
    if (!text) continue;
    /* 记事本存的 UTF-8 常带 BOM,不剥掉的话 front-matter 的 "---" 匹配不到 */
    char *p_text = text;
    if ((unsigned char)p_text[0] == 0xEF && (unsigned char)p_text[1] == 0xBB &&
        (unsigned char)p_text[2] == 0xBF) {
      p_text += 3;
    }
    ext_skill_t sk;
    memset(&sk, 0, sizeof(sk));
    sk.timeout_ms = 20000;
    char *body = NULL;
    parse_front_matter(p_text, &sk, &body);
    free(text);
    if (!sk.name || !sk.name[0]) {
      char base[MAX_PATH];
      snprintf(base, sizeof(base), "%s", path);
      const char *slash = strrchr(base, '\\');
      char *fname = (char *)(slash ? slash + 1 : base);
      char *dot = strrchr(fname, '.');
      if (dot) *dot = 0;
      free(sk.name);
      sk.name = xstrdup(fname);
    }
    if (!sk.title) sk.title = xstrdup(sk.name);
    if (!sk.when) sk.when = xstrdup(sk.title);
    if (!sk.purpose) sk.purpose = xstrdup(sk.when);

    /* 数据目录里这些文件是程序自己导出的"内置技能说明"。
       同名内置技能存在时:用使用者改过的文字覆盖说明(实现仍是内置的,改文字改不了行为);
       这样既不会出现两个同名技能,也不会让使用者的修改石沉大海。 */
    if (!sk.command || !sk.command[0]) {
      if (skills_override_text(sk.name, sk.title, sk.purpose, sk.when, sk.tools)) {
        overridden++;
        free(sk.name); free(sk.title); free(sk.purpose); free(sk.when); free(sk.tools);
        free(sk.source_file);
        free(body);
        continue;
      }
    }

    sk.body = body;
    sk.source_file = xstrdup(path);
    g_eskills = (ext_skill_t *)xrealloc(g_eskills, sizeof(ext_skill_t) * (size_t)(g_eskill_count + 1));
    g_eskills[g_eskill_count++] = sk;
    n++;
  }
  str_free_list(files, total);
  if (overridden > 0) {
    log_info("[扩展] 数据目录里有 %d 个技能说明被采用(改的是说明文字,行为仍是内置实现)",
             overridden);
  }
  return n;
}

/* 技能包注册进技能表:带 command 的会真执行(run 走 ext 执行器) */
static int ext_skill_index(const char *name);

/* ================= 外部工具(JSON 清单) ================= */
static int load_tools_dir(const char *dir) {
  char **files = NULL;
  int total = list_files(dir, ".json", &files);
  int n = 0;
  for (int i = 0; i < total; i++) {
    const char *path = files[i];
    char *text = read_file_utf8(path);
    if (!text) continue;
    json_t *j = json_parse(text);
    free(text);
    if (!j) continue;

    /* 支持一个文件里放一个对象或一个数组(便于一次写多个) */
    json_t *list = (j->type == J_ARR) ? j : NULL;
    int cnt = list ? j_len(list) : 1;
    for (int k = 0; k < cnt; k++) {
      json_t *o = list ? j_at(list, k) : j;
      const char *name = j_s(o, "name", "");
      const char *cmd = j_s(o, "command", "");
      if (!name[0] || !cmd[0]) continue;
      ext_tool_t t;
      memset(&t, 0, sizeof(t));
      t.name = xstrdup(name);
      t.description = xstrdup(j_s(o, "description", "外部工具(用户自定义)"));
      json_t *sc = j_get(o, "schema");
      t.schema = sc ? json_dump(sc) : xstrdup("{\"type\":\"object\",\"properties\":{}}");
      t.command = xstrdup(cmd);
      t.kind = xstrdup(j_s(o, "kind", "外部工具"));
      t.workdir = xstrdup(j_s(o, "workdir", ""));
      t.timeout_ms = (int)j_n(o, "timeout_ms", 20000);
      t.allow = j_b(o, "allow", 0);
      t.source_file = xstrdup(path);
      g_etools = (ext_tool_t *)xrealloc(g_etools, sizeof(ext_tool_t) * (size_t)(g_etool_count + 1));
      g_etools[g_etool_count++] = t;
      n++;
    }
    json_free(j);
  }
  str_free_list(files, total);
  return n;
}

/* ================= MCP(stdio, JSON-RPC 2.0) ================= */
static int mcp_launch(mcp_server_t *s, const char *command, const char *cwd) {
  SECURITY_ATTRIBUTES sa;
  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;

  HANDLE in_rd = NULL, in_wr = NULL, out_rd = NULL, out_wr = NULL;
  if (!CreatePipe(&in_rd, &in_wr, &sa, 0)) return -1;
  if (!CreatePipe(&out_rd, &out_wr, &sa, 0)) { CloseHandle(in_rd); CloseHandle(in_wr); return -1; }
  SetHandleInformation(in_wr, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(out_rd, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW si;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdInput = in_rd;
  si.hStdOutput = out_wr;
  /* stderr 不能并进协议管道:服务端打的日志会把 JSON 流冲坏。
     直接让它跟着本程序的 stderr 走 —— 用户在控制台能看到,协议仍然是干净的。 */
  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

  PROCESS_INFORMATION pi;
  memset(&pi, 0, sizeof(pi));
  char *wrapped = shell_wrap(command);
  wchar_t *wcmd = wrapped ? u8_to_w(wrapped) : NULL;
  wchar_t *wdir = (cwd && *cwd) ? u8_to_w(cwd) : NULL;
  free(wrapped);
  BOOL ok = wcmd && CreateProcessW(NULL, wcmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                                   NULL, wdir, &si, &pi);
  free(wcmd);
  free(wdir);
  CloseHandle(in_rd);
  CloseHandle(out_wr);
  if (!ok) {
    CloseHandle(in_wr);
    CloseHandle(out_rd);
    return -1;
  }
  s->pid = (int)pi.dwProcessId;
  s->hwrite = in_wr;
  s->hread = out_rd;
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return 0;
}

/* 发一条 JSON-RPC 消息(按 MCP stdio 规范:一行一条 JSON) */
static int mcp_send(mcp_server_t *s, json_t *msg) {
  if (!s->hwrite) return -1;
  char *body = json_dump(msg);
  if (!body) return -1;
  /* MCP stdio 规范:一行一条 JSON(官方 Python/Node SDK 都按这个来)。
     行内不能有裸换行,json_dump 本来就不换行。 */
  int ok = 1;
  DWORD wrote = 0;
  size_t n = strlen(body);
  if (!WriteFile(s->hwrite, body, (DWORD)n, &wrote, NULL) || wrote != (DWORD)n) ok = 0;
  if (ok && (!WriteFile(s->hwrite, "\n", 1, &wrote, NULL) || wrote != 1)) ok = 0;
  FlushFileBuffers(s->hwrite);
  free(body);
  return ok ? 0 : -1;
}

/* 收一条消息。两种分帧都认:
     - 换行分帧(MCP stdio 规范:一行一条 JSON,官方 SDK 都是这样)
     - Content-Length 头分帧(有些服务端按 LSP 风格写)
   谁先出现按谁解析,所以接第三方服务器时不会因为分帧不同而"连不上"。 */
static json_t *mcp_recv(mcp_server_t *s, int timeout_ms) {
  if (!s->hread) return NULL;
  buf_t acc;
  buf_init(&acc);
  if (s->pending_buf && *s->pending_buf) {
    buf_puts(&acc, s->pending_buf);
    free(s->pending_buf);
    s->pending_buf = NULL;
  }

  DWORD deadline = GetTickCount() + (DWORD)(timeout_ms > 0 ? timeout_ms : 8000);
  char chunk[2048];

  while (GetTickCount() < deadline) {
    const char *data = acc.data ? acc.data : "";
    /* 先跳过可能的空行 */
    while (*data == '\r' || *data == '\n') data++;

    if (data[0] == '{') {
      /* 换行分帧:凑齐一整行就是一条消息 */
      const char *nl = strchr(data, '\n');
      if (nl) {
        json_t *j = json_parse_n(data, (size_t)(nl - data));
        size_t consumed = (size_t)(nl - acc.data) + 1;
        if (acc.len > consumed) s->pending_buf = xstrdup(acc.data + consumed);
        buf_free(&acc);
        return j;
      }
    } else if (!strncmp(data, "Content-Length:", 15) || !strncmp(data, "content-length:", 15)) {
      const char *hdr_end = strstr(data, "\r\n\r\n");
      if (hdr_end) {
        long need = atol(data + 15);
        size_t body_start = (size_t)(hdr_end + 4 - acc.data);
        if ((long)(acc.len - body_start) >= need) {
          json_t *j = json_parse_n(acc.data + body_start, (size_t)need);
          size_t consumed = body_start + (size_t)need;
          if (acc.len > consumed) s->pending_buf = xstrdup(acc.data + consumed);
          buf_free(&acc);
          return j;
        }
      }
    }

    DWORD avail = 0;
    if (PeekNamedPipe(s->hread, NULL, 0, NULL, &avail, NULL) && avail > 0) {
      DWORD got = 0;
      DWORD want = avail < sizeof(chunk) - 1 ? avail : (DWORD)(sizeof(chunk) - 1);
      if (ReadFile(s->hread, chunk, want, &got, NULL) && got > 0) {
        chunk[got] = 0;
        buf_putn(&acc, chunk, got);
        continue;
      }
    }
    Sleep(20);
  }
  if (acc.len) s->pending_buf = buf_take(&acc);
  else buf_free(&acc);
  return NULL;
}

static int mcp_call(mcp_server_t *s, const char *method, json_t *params, int id,
                    json_t **out_result) {
  json_t *req = j_obj();
  j_set_str(req, "jsonrpc", "2.0");
  j_set_num(req, "id", id);
  j_set_str(req, "method", method);
  if (params) j_set(req, "params", params);
  else json_free(params);
  int rc = mcp_send(s, req);
  json_free(req);
  if (rc != 0) return -1;

  /* 读到 id 匹配的那条(可能先来通知) */
  for (int i = 0; i < 50; i++) {
    json_t *msg = mcp_recv(s, 10000);
    if (!msg) return -1;
    if (j_n(msg, "id", -1) == id) {
      json_t *err = j_get(msg, "error");
      json_t *res = j_get(msg, "result");
      if (err) {
        json_free(msg);
        return -2;
      }
      if (out_result) *out_result = res ? json_parse(json_dump(res)) : NULL;
      json_free(msg);
      return 0;
    }
    json_free(msg);
  }
  return -1;
}

static int mcp_start(mcp_server_t *s) {
  json_t *params = j_obj();
  json_t *info = j_obj();
  j_set_str(info, "name", "bw-agent");
  j_set_str(info, "version", "1.0.0");
  j_set(info, "capabilities", j_obj());
  json_t *ci = j_obj();
  j_set_str(ci, "protocolVersion", "2024-11-05");
  j_set(ci, "clientInfo", info);
  j_set(ci, "capabilities", j_obj());
  json_free(params);
  params = ci;
  int rc = mcp_call(s, "initialize", params, 1, NULL);
  if (rc != 0) return -1;
  /* 按规范回一条 initialized 通知 */
  json_t *note = j_obj();
  j_set_str(note, "jsonrpc", "2.0");
  j_set_str(note, "method", "notifications/initialized");
  mcp_send(s, note);
  json_free(note);
  s->initialized = 1;

  json_t *res = NULL;
  if (mcp_call(s, "tools/list", j_obj(), 2, &res) != 0 || !res) {
    log_warn("[扩展] MCP 服务器 %s 的 tools/list 没有正常返回", s->name);
    return -1;
  }
  json_t *tools = j_get(res, "tools");
  s->tools = tools ? json_parse(json_dump(tools)) : j_arr();
  json_free(res);
  return 0;
}

static void mcp_shutdown_all(void) {
  for (int i = 0; i < g_mcp_count; i++) {
    if (g_mcp[i].hwrite) { CloseHandle(g_mcp[i].hwrite); g_mcp[i].hwrite = NULL; }
    if (g_mcp[i].hread) { CloseHandle(g_mcp[i].hread); g_mcp[i].hread = NULL; }
    if (g_mcp[i].pid) {
      HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)g_mcp[i].pid);
      if (h) { TerminateProcess(h, 0); CloseHandle(h); }
      g_mcp[i].pid = 0;
    }
  }
}

void ext_shutdown(void) { mcp_shutdown_all(); }

static int load_mcp_config(const char *path) {
  char *text = read_file_utf8(path);
  if (!text) return 0;
  json_t *j = json_parse(text);
  free(text);
  if (!j) return 0;
  json_t *servers = j_get(j, "servers");
  int n = 0;
  for (int i = 0; i < j_len(servers); i++) {
    json_t *o = j_at(servers, i);
    const char *name = j_s(o, "name", "");
    const char *cmd = j_s(o, "command", "");
    if (!name[0] || !cmd[0]) continue;
    int allow = j_b(o, "allow", 0);
    mcp_server_t s;
    memset(&s, 0, sizeof(s));
    s.name = xstrdup(name);
    s.allow = allow;
    s.pending_buf = NULL;
    s.tools = j_arr();
    if (allow) {
      if (mcp_launch(&s, cmd, j_s(o, "cwd", "")) == 0 && mcp_start(&s) == 0) {
        g_mcp_tool_count += j_len(s.tools);
        log_info("[扩展] MCP 服务器 %s 已连接,%d 个工具", name, j_len(s.tools));
      } else {
        log_warn("[扩展] MCP 服务器 %s 连接失败(命令:%s)", name, cmd);
      }
    } else {
      log_warn("[扩展] MCP 服务器 %s 未启用(清单里 allow 不为 true)", name);
    }
    g_mcp = (mcp_server_t *)xrealloc(g_mcp, sizeof(mcp_server_t) * (size_t)(g_mcp_count + 1));
    g_mcp[g_mcp_count++] = s;
    n++;
  }
  json_free(j);
  return n;
}

/* MCP 工具执行:mcp__<server>__<tool> */
static int mcp_find_tool(const char *full_name, mcp_server_t **srv_out, const char **tool_out) {
  if (!str_startswith(full_name, "mcp__")) return 0;
  const char *rest = full_name + 5;
  const char *sep = strstr(rest, "__");
  if (!sep) return 0;
  char sname[128];
  size_t sl = (size_t)(sep - rest);
  if (sl >= sizeof(sname)) sl = sizeof(sname) - 1;
  memcpy(sname, rest, sl);
  sname[sl] = 0;
  const char *tname = sep + 2;
  for (int i = 0; i < g_mcp_count; i++) {
    if (str_ieq(g_mcp[i].name, sname)) {
      for (int k = 0; k < j_len(g_mcp[i].tools); k++) {
        if (strcmp(j_s(j_at(g_mcp[i].tools, k), "name", ""), tname) == 0) {
          if (srv_out) *srv_out = &g_mcp[i];
          if (tool_out) *tool_out = tname;
          return 1;
        }
      }
    }
  }
  return 0;
}

static int mcp_run(tool_ctx_t *ctx, const char *full_name, json_t *args, tool_result_t *out) {
  (void)ctx;
  mcp_server_t *srv = NULL;
  const char *tname = NULL;
  if (!mcp_find_tool(full_name, &srv, &tname)) {
    out->is_error = 1;
    out->text = xstrdup("没有这个 MCP 工具");
    out->say = xstrdup("没有这个 MCP 工具。");
    return -1;
  }
  json_t *params = j_obj();
  j_set_str(params, "name", tname);
  j_set(params, "arguments", args ? json_parse(json_dump(args)) : j_obj());
  json_t *res = NULL;
  int mrc = mcp_call(srv, "tools/call", params, 3, &res);
  if (mrc != 0 || !res) {
    log_warn("[扩展] MCP %s 调用 %s 失败(rc=%d%s)", srv->name, tname, mrc,
             mrc == -2 ? ",服务器返回 error" : "");
    out->is_error = 1;
    out->text = xstrdup("MCP 工具调用失败(服务器无响应或返回错误)");
    out->say = xstrdup("MCP 工具没能调用成功。");
    return -1;
  }
  /* 结果格式:{ content: [ {type:"text", text:"..."} ], isError?: bool } */
  buf_t text;
  buf_init(&text);
  json_t *content = j_get(res, "content");
  for (int i = 0; i < j_len(content); i++) {
    json_t *c = j_at(content, i);
    const char *t = j_s(c, "text", "");
    if (t[0]) {
      if (text.len) buf_putc_(&text, '\n');
      buf_puts(&text, t);
    }
  }
  int is_err = j_b(res, "isError", 0);
  out->text = buf_take(&text);
  if (!out->text) out->text = xstrdup("(空结果)");
  out->data = json_parse(json_dump(res));
  out->is_error = is_err;
  buf_t say;
  buf_init(&say);
  buf_printf(&say, "%s 返回:%s", full_name, out->text);
  out->say = buf_take(&say);
  json_free(res);
  return is_err ? -1 : 0;
}

/* ================= 外部工具/技能 执行 ================= */
static int ext_tool_index(const char *name) {
  for (int i = 0; i < g_etool_count; i++) {
    if (str_ieq(g_etools[i].name, name)) return i;
  }
  return -1;
}

static int ext_skill_index(const char *name) {
  for (int i = 0; i < g_eskill_count; i++) {
    if (str_ieq(g_eskills[i].name, name)) return i;
  }
  return -1;
}

static int ext_tool_run(tool_ctx_t *ctx, const char *ext_name, json_t *args,
                        tool_result_t *out) {
  (void)ctx;
  int idx = ext_tool_index(ext_name);
  if (idx < 0) return -1;
  ext_tool_t *t = &g_etools[idx];
  if (!t->allow) {
    out->is_error = 1;
    out->text = xstrdup("这个工具没有启用(清单里 allow 不为 true)");
    out->say = xstrdup("工具未启用,需要在该工具的 json 里把 allow 设为 true。");
    return -1;
  }
  buf_t cmd;
  buf_init(&cmd);
  expand_cmd(&cmd, t->command, args);
  char *text = NULL;
  int code = -1;
  int rc = run_capture(cmd.data, t->workdir[0] ? t->workdir : NULL, t->timeout_ms, &text, &code);
  json_t *data = j_obj();
  j_set_str(data, "command", cmd.data);
  j_set_num(data, "exit_code", code);
  j_set_str(data, "source", t->source_file);
  buf_free(&cmd);

  if (rc != 0) {
    out->is_error = 1;
    buf_t b;
    buf_init(&b);
    buf_printf(&b, "外部工具执行失败(%s)", rc == -2 ? "超时" : "无法启动");
    out->text = buf_take(&b);
    out->say = xstrdup(out->text);
    out->data = data;
    free(text);
    return -1;
  }
  /* 结果可能很长:截断到 8KB 再交给模型 */
  size_t len = strlen(text ? text : "");
  if (len > 8192) {
    text[8192] = 0;
    buf_t b;
    buf_init(&b);
    buf_printf(&b, "%s\n…(输出过长已截断,共 %lu 字节)", text, (unsigned long)len);
    free(text);
    text = buf_take(&b);
  }
  out->text = text ? text : xstrdup("(无输出)");
  out->data = data;
  buf_t say;
  buf_init(&say);
  buf_printf(&say, "%s 执行完成(退出码 %d):%s", t->name, code, out->text);
  out->say = buf_take(&say);
  out->is_error = (code != 0);
  return out->is_error ? -1 : 0;
}

static int ext_skill_run(tool_ctx_t *ctx, const char *ext_name, skill_result_t *out) {
  (void)ctx;
  int idx = ext_skill_index(ext_name);
  if (idx < 0) return -1;
  ext_skill_t *s = &g_eskills[idx];
  json_t *data = j_obj();
  j_set_str(data, "skill", s->name);
  j_set_str(data, "title", s->title);
  j_set_str(data, "source", s->source_file);
  j_set_bool(data, "external", 1);
  j_set_str(data, "steps", s->body ? s->body : "");
  out->data = data;

  if (s->command && s->command[0]) {
    if (!s->allow) {
      /* 命令没开:正文里的步骤照样是能力(纯方法论),只是如实说明"这条命令没跑" */
      buf_t b;
      buf_init(&b);
      buf_printf(&b, "【%s】按下面的步骤做(来自技能包 %s);它的命令没有启用,本次只给方法不执行命令:\n%s",
                 s->title, s->name, s->body ? s->body : "");
      out->summary = buf_take(&b);
      j_set_bool(data, "command_skipped", 1);
      return 0;
    }
    char *text = NULL;
    int code = -1;
    int rc = run_capture(s->command, NULL, s->timeout_ms ? s->timeout_ms : 20000, &text, &code);
    j_set_num(data, "exit_code", code);
    if (rc != 0) {
      out->is_error = 1;
      out->summary = xstrdup("技能包的命令执行失败(无法启动或超时)。");
      free(text);
      return -1;
    }
    buf_t b;
    buf_init(&b);
    buf_printf(&b, "【%s】执行完成(退出码 %d):\n%s", s->title, code, text ? text : "");
    out->summary = buf_take(&b);
    free(text);
    out->is_error = (code != 0);
    return out->is_error ? -1 : 0;
  }

  buf_t b;
  buf_init(&b);
  buf_printf(&b, "【%s】按下面的步骤做(来自技能包 %s):\n%s", s->title, s->name,
             s->body ? s->body : "");
  out->summary = buf_take(&b);
  return 0;
}

/* ================= 注册进工具表 / 技能表 ================= */
/* 适配器:注册表里存的是"一个函数指针",而外部能力可能有很多个,
   所以用 ctx->current_tool 知道自己这次是谁 —— 不需要给每个外部工具单独造闭包。 */
static int ext_tool_adapter(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  if (mcp_find_tool(ctx->current_tool ? ctx->current_tool : "", NULL, NULL)) {
    return mcp_run(ctx, ctx->current_tool, args, out);
  }
  return ext_tool_run(ctx, ctx->current_tool ? ctx->current_tool : "", args, out);
}

static int ext_skill_adapter(tool_ctx_t *ctx, json_t *args, skill_result_t *out) {
  (void)args;
  return ext_skill_run(ctx, ctx->current_tool ? ctx->current_tool : "", out);
}

void ext_register_all(void) {
  for (int i = 0; i < g_etool_count; i++) {
    ext_tool_t *t = &g_etools[i];
    /* 未启用的不登记:能力清单里只出现"现在真的能跑"的东西(和 MCP 的口径一致),
       否则界面与模型都会看到一个点了没反应的按钮。日志里告诉人怎么开。 */
    if (!t->allow) {
      log_warn("[扩展] 外部工具 %s 未启用(在 %s 里把 allow 改成 true 才会出现在能力清单)",
               t->name, t->source_file);
      continue;
    }
    tools_register_external(t->name, t->description, t->schema, t->kind,
                            t->source_file, ext_tool_adapter);
  }
  for (int i = 0; i < g_eskill_count; i++) {
    ext_skill_t *s = &g_eskills[i];
    skills_register_external(s->name, s->title, s->purpose, s->when, s->tools,
                             ext_skill_adapter);
  }
  for (int i = 0; i < g_mcp_count; i++) {
    mcp_server_t *s = &g_mcp[i];
    for (int k = 0; k < j_len(s->tools); k++) {
      json_t *t = j_at(s->tools, k);
      const char *tname = j_s(t, "name", "");
      if (!tname[0]) continue;
      char full[256];
      snprintf(full, sizeof(full), "mcp__%s__%s", s->name, tname);
      char desc[1024];
      snprintf(desc, sizeof(desc), "[MCP:%s] %s", s->name,
               j_s(t, "description", "外部 MCP 工具"));
      char *schema = json_dump(j_get(t, "inputSchema"));
      tools_register_external(full, desc, schema ? schema : "", "MCP", s->name,
                              ext_tool_adapter);
      free(schema);
    }
  }
}

/* ================= 首次运行:把内置技能落到数据目录,让人看得见、改得动 =================
   不放"示例文件":能力清单里本来就有的技能,才是使用者真正要读、要改的东西。
   每个内置技能导出一份 Markdown(名字=技能名),里面的说明文字改了之后会被采用
   (实现仍在程序里,所以改文字不会把程序改坏)。工具与 MCP 的格式写在「使用说明.txt」里,
   使用者照着自己建文件即可,程序不会替他生成空壳。 */
static void write_skill_md(const char *file, skill_t *sk) {
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "\xEF\xBB\xBF");     /* 带 BOM:记事本能正确认出 UTF-8 */
  buf_puts(&b, "---\r\n");
  buf_printf(&b, "name: %s\r\n", sk->name);
  buf_printf(&b, "title: %s\r\n", sk->title ? sk->title : sk->name);
  buf_printf(&b, "purpose: %s\r\n", sk->purpose ? sk->purpose : "");
  buf_printf(&b, "when: %s\r\n", sk->when ? sk->when : "");
  buf_printf(&b, "tools: %s\r\n", sk->tools ? sk->tools : "");
  buf_puts(&b, "---\r\n\r\n");
  buf_printf(&b, "【%s】%s\r\n\r\n", sk->title ? sk->title : sk->name,
             sk->purpose ? sk->purpose : "");
  buf_printf(&b, "什么时候用:%s\r\n\r\n", sk->when ? sk->when : "");
  buf_puts(&b,
      "这个技能由程序内置实现,上面三段文字是决策时用的说明 ——\r\n"
      "按本单位自己的叫法改就生效(改完重启程序),不会改变它的实际动作,\r\n"
      "所以放心改:改坏了把本文件删掉,程序会回到出厂说明。\r\n"
      "\r\n"
      "想让它额外执行一条命令(例如调内部平台的接口):加上\r\n"
      "    command: 你的命令\r\n"
      "    allow: true\r\n"
      "此时它变成\"命令型\"能力,上面的文字会连同命令输出一起作为结论。\r\n");
  file_write_all(file, b.data, b.len);
  buf_free(&b);
}

/* 内置技能改过名/被删掉时,数据目录里那份旧说明会作为"外部技能"继续被载入 ——
   使用者看到的就是一个早就没有实现的技能。这里按名字清掉这些过时的导出文件。 */
static void drop_deprecated_skills(const char *dir) {
  static const char *GONE[] = {"skill_evaluate", NULL};   /* → skill_evidence */
  for (int i = 0; GONE[i]; i++) {
    char file[MAX_PATH * 2];
    snprintf(file, sizeof(file), "%s\\%s.md", dir, GONE[i]);
    if (file_size(file) < 0) continue;
    wchar_t *w = u8_to_w(file);
    if (w) {
      DeleteFileW(w);
      free(w);
    }
  }
}

/* 导出内置技能说明(已存在的文件不覆盖 —— 使用者改过的内容不能被程序冲掉) */
static int export_builtin_skills(void) {
  char dir[MAX_PATH * 2];
  ext_dir(dir, sizeof(dir), "skills");
  ensure_dir(dir);
  drop_deprecated_skills(dir);
  int written = 0;
  int total = skills_count();
  for (int i = 0; i < total; i++) {
    skill_t *sk = skills_get(i);
    if (!sk || !sk->name) continue;
    char file[MAX_PATH * 2];
    snprintf(file, sizeof(file), "%s\\%s.md", dir, sk->name);
    if (file_size(file) >= 0) continue;
    write_skill_md(file, sk);
    written++;
  }
  return written;
}

void ext_bootstrap(void) {
  char path[MAX_PATH * 2];

  /* 工具与 MCP 的目录只建好、不放东西:使用者按「使用说明.txt」里的格式自己加 */
  ext_dir(path, sizeof(path), "tools");
  ensure_dir(path);

  export_builtin_skills();
}


/* ================= 对外接口 ================= */
/* 列目录:给界面"配置编辑"复用同一套宽字符实现(中文文件名不能走 ANSI) */
int ext_list_files(const char *dir, const char *ext, char ***out) {
  return list_files(dir, ext, out);
}

int ext_load_all(void) {
  char dir[MAX_PATH * 2];
  int n = 0;

  ext_dir(dir, sizeof(dir), "tools");
  n += load_tools_dir(dir);
  ext_dir(dir, sizeof(dir), "skills");
  n += load_skills_dir(dir);
  ext_dir(dir, sizeof(dir), "mcp.json");
  n += load_mcp_config(dir);

  if (g_etool_count || g_eskill_count || g_mcp_count) {
    log_info("[扩展] 外部工具 %d 个、技能包 %d 个、MCP 服务器 %d 个(共 %d 个外部工具)",
             g_etool_count, g_eskill_count, g_mcp_count, g_mcp_tool_count);
  }
  return n;
}

void ext_stats(int *tools, int *skills, int *mcp, int *mcp_tools) {
  if (tools) *tools = g_etool_count;
  if (skills) *skills = g_eskill_count;
  if (mcp) *mcp = g_mcp_count;
  if (mcp_tools) *mcp_tools = g_mcp_tool_count;
}
