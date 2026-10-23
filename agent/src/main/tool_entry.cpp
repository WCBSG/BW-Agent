/* tool_entry.cpp —— 外部入口的执行层(进程 / HTTP)。
 * 详见 tool_entry.h 里的声明格式与两种协议。
 *
 * 进程实现自己一套(不复用 ext.cpp 的 run_capture),因为这里要往 stdin 写调用 JSON,
 * 而 ext 那套只收 stdout。超时与回收的逻辑保持一致:到点就 TerminateProcess,
 * 输出上限 512KB,不让失控的插件拖死主进程。
 */
#include "tool_entry.h"

#include <windows.h>
#include <winhttp.h>

#include <string>
#include <vector>

#include "common.h"
#include "tools.h"

typedef struct {
  char *name;
  char type[16];      /* exec / http */
  char *path;         /* exec:入口命令 */
  char *args;         /* exec:参数数组的 JSON 文本(可空) */
  char *cwd;
  char *url;
  char protocol[16];  /* argv / json-stdio / json */
  int timeout_ms;
} entry_t;

static std::vector<entry_t *> g_entries;

static void entry_free(entry_t *e) {
  if (!e) return;
  free(e->name);
  free(e->path);
  free(e->args);
  free(e->cwd);
  free(e->url);
  free(e);
}

void tool_entry_reset(void) {
  for (size_t i = 0; i < g_entries.size(); i++) entry_free(g_entries[i]);
  g_entries.clear();
}

int tool_entry_count(void) { return (int)g_entries.size(); }

static entry_t *entry_find(const char *name) {
  if (!name || !*name) return NULL;
  for (size_t i = 0; i < g_entries.size(); i++) {
    if (str_ieq(g_entries[i]->name, name)) return g_entries[i];
  }
  return NULL;
}

/* ================= 声明解析 ================= */

static int file_exists(const char *p) { return p && *p && file_size(p) >= 0; }

/* 把 ~/x 与相对路径解析成绝对路径(UTF-8)。
   origin 是声明文件本身,相对路径按它所在目录算 —— 这样一个工具目录可以整体搬动。 */
static void resolve_rel(const char *raw, const char *origin, char *out, size_t cap) {
  if (!raw || !*raw) {
    out[0] = 0;
    return;
  }
  if (raw[0] == '~') {
    const char *rest = raw + 1;
    while (*rest == '/' || *rest == '\\') rest++;
    app_data_path(out, cap, rest);
    return;
  }
  if (raw[1] == ':' || raw[0] == '\\' || raw[0] == '/') {
    snprintf(out, cap, "%s", raw);
    return;
  }
  char dir[MAX_PATH * 2];
  if (origin && *origin) path_dir_of(origin, dir, sizeof(dir));
  else snprintf(dir, sizeof(dir), "%s", app_data_dir());
  char rel[MAX_PATH * 2];
  snprintf(rel, sizeof(rel), "%s", raw);
  for (char *q = rel; *q; q++) {
    if (*q == '/') *q = '\\';
  }
  snprintf(out, cap, "%s\\%s", dir, rel);
}

/* 同目录里的入口:list_file\list_file.json 旁边放 list_file.exe —— 目录即工具。 */
static int find_sibling_entry(const char *origin, const char *name, const char *impl, char *out,
                              size_t cap) {
  if (!origin || !*origin) return 0;
  char dir[MAX_PATH * 2];
  path_dir_of(origin, dir, sizeof(dir));
  static const char *kExt[] = {".exe", ".cmd", ".bat", NULL};
  const char *stems[2];
  stems[0] = (impl && *impl) ? impl : name;
  stems[1] = name;
  for (int s = 0; s < 2; s++) {
    if (!stems[s] || !*stems[s]) continue;
    if (s == 1 && str_ieq(stems[1], stems[0])) continue;
    for (int i = 0; kExt[i]; i++) {
      char p[MAX_PATH * 2];
      snprintf(p, sizeof(p), "%s\\%s%s", dir, stems[s], kExt[i]);
      if (file_exists(p)) {
        snprintf(out, cap, "%s", p);
        return 1;
      }
    }
  }
  return 0;
}

int tool_entry_parse(json_t *spec, const char *origin) {
  if (!spec || spec->type != J_OBJ) return -1;

  const char *name = j_s(spec, "name", "");
  if (!name[0]) return 0;

  json_t *en = j_get(spec, "entry");
  const char *impl = j_s(spec, "impl", "");
  char path[MAX_PATH * 2];
  path[0] = 0;
  const char *type = NULL;
  const char *proto = NULL;
  int timeout_ms = 30000;
  const char *url = NULL;
  const char *cwd = "";
  json_t *args = NULL;

  if (en && en->type == J_OBJ) {
    type = j_s(en, "type", "");
    proto = j_s(en, "protocol", "");
    url = j_s(en, "url", "");
    cwd = j_s(en, "cwd", "");
    timeout_ms = (int)j_n(en, "timeout_ms", 30000);
    args = j_get(en, "args");
    const char *p = j_s(en, "path", "");
    /* 只有"像路径"的才拼目录:反斜杠、盘符、~ 开头或可执行后缀都算路径;
       `cmd /c echo` 这种命令行(带 / 参数)不能当路径,否则会被拼成
       `\cmd /c echo`,运行时变成"找不到路径"。 */
    if (p[0] && (strchr(p, '\\') || p[0] == '~' || p[1] == ':' ||
                 str_endswith(p, ".exe") || str_endswith(p, ".cmd") ||
                 str_endswith(p, ".bat"))) {
      resolve_rel(p, origin, path, sizeof(path));
    } else if (p[0]) {
      snprintf(path, sizeof(path), "%s", p);
    }
  }

  /* 没写 entry 时,按"目录即工具"的约定找入口:
       1) 显式 source(~/tools/x/x.exe)
       2) 声明文件旁边的 <impl>.exe / <name>.exe
     都没有才当作内置实现(impl 命中 g_prims,由 tools.cpp 处理)。 */
  if (!path[0] && !url) {
    const char *src = j_s(spec, "source", "");
    char cand[MAX_PATH * 2];
    cand[0] = 0;
    if (src[0] && (src[0] == '~' || strchr(src, '/') || strchr(src, '\\') ||
                   str_endswith(src, ".exe") || str_endswith(src, ".cmd") ||
                   str_endswith(src, ".bat"))) {
      resolve_rel(src, origin, cand, sizeof(cand));
      if (file_exists(cand)) snprintf(path, sizeof(path), "%s", cand);
    }
    if (!path[0]) find_sibling_entry(origin, name, impl, path, sizeof(path));
    if (path[0] && !type) type = "exec";
  }

  if (!type || (!str_ieq(type, "exec") && !str_ieq(type, "http"))) {
    /* builtin:交给 tools.cpp 的 g_prims */
    return 0;
  }
  if (str_ieq(type, "exec") && !path[0]) {
    log_warn("[工具] %s 声明是外部入口,但找不到可执行文件(看了 entry.path、source、同目录)", origin);
    return -1;
  }
  if (str_ieq(type, "http") && (!url || !url[0])) {
    log_warn("[工具] %s 的入口是 http,但没写 url", origin);
    return -1;
  }
  if (entry_find(name)) return 1;                  /* 重名:先到先得 */

  entry_t *e = (entry_t *)xmalloc(sizeof(entry_t));
  memset(e, 0, sizeof(*e));
  e->name = xstrdup(name);
  snprintf(e->type, sizeof(e->type), "%s", type);
  e->path = xstrdup(path);
  e->url = xstrdup(url ? url : "");
  e->cwd = xstrdup(cwd);
  e->timeout_ms = timeout_ms;
  if (e->timeout_ms < 1000) e->timeout_ms = 1000;
  if (e->timeout_ms > 600000) e->timeout_ms = 600000;

  if (!proto || !*proto) proto = j_s(spec, "protocol", "");
  if (!proto[0]) proto = str_ieq(e->type, "http") ? "json" : "json-stdio";
  snprintf(e->protocol, sizeof(e->protocol), "%s", proto);

  if (!args) args = j_get(spec, "args");
  if (args) {
    char *txt = json_dump(args);
    e->args = txt ? txt : xstrdup("[]");
  } else {
    e->args = xstrdup("[]");
  }

  g_entries.push_back(e);
  log_info("[工具] 入口已登记:%s(%s / %s)", e->name, e->type, e->protocol);
  return 1;
}

/* ================= 参数展开:$name / ${name} =================
   与外部命令工具同一套规则:字符串参数加引号并按 cmd 规则转义,
   避免使用者填进来的值拼出第二条命令。 */
static void expand_argv(buf_t *out, const char *tmpl, json_t *args) {
  for (const char *p = tmpl; *p; p++) {
    if (*p != '$') {
      buf_putc_(out, *p);
      continue;
    }
    int braced = (p[1] == '{');
    const char *start = p + (braced ? 2 : 1);
    const char *end = start;
    while (*end && (isalnum((unsigned char)*end) || *end == '_')) end++;
    if (end == start) {
      buf_putc_(out, '$');
      continue;
    }
    char key[64];
    size_t n = (size_t)(end - start);
    if (n >= sizeof(key)) n = sizeof(key) - 1;
    memcpy(key, start, n);
    key[n] = 0;
    json_t *v = args ? j_get(args, key) : NULL;
    if (v && v->type == J_STR) {
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

/* 入口命令:是数据目录里真有的文件就补成绝对路径并加引号,
   否则原样当命令用(允许 "powershell -File x.ps1" 这种写法)。 */
static void resolve_entry(const char *path, char *out, size_t cap) {
  if (!path || !*path) {
    out[0] = 0;
    return;
  }
  if (path[0] && path[1] == ':') {
    snprintf(out, cap, "\"%s\"", path);
    return;
  }
  char cand[MAX_PATH * 2];
  app_data_path(cand, sizeof(cand), path);
  if (file_size(cand) >= 0) {
    snprintf(out, cap, "\"%s\"", cand);
    return;
  }
  snprintf(out, cap, "%s", path);
}

/* 拼完整命令行:入口 + 声明里的固定参数(逐个展开) */
static char *build_cmdline(const entry_t *e, json_t *args) {
  char base[MAX_PATH * 2 + 8];
  resolve_entry(e->path, base, sizeof(base));

  buf_t b;
  buf_init(&b);
  buf_puts(&b, base);

  json_t *arr = e->args ? json_parse(e->args) : NULL;
  for (int i = 0; arr && i < j_len(arr); i++) {
    json_t *v = j_at(arr, i);
    buf_putc_(&b, ' ');
    if (v && v->type == J_STR) expand_argv(&b, v->str, args);
  }
  json_free(arr);
  return buf_take(&b);
}

/* ================= 进程执行 ================= */

static int run_proc(const char *cmdline, const char *workdir, const char *stdin_data,
                    int timeout_ms, char **out_text, int *out_exit) {
  if (out_text) *out_text = NULL;
  if (out_exit) *out_exit = -1;
  if (!cmdline || !*cmdline) return -1;

  SECURITY_ATTRIBUTES sa;
  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;

  HANDLE in_rd = NULL, in_wr = NULL, out_rd = NULL, out_wr = NULL;
  if (!CreatePipe(&in_rd, &in_wr, &sa, 0)) return -1;
  SetHandleInformation(in_wr, HANDLE_FLAG_INHERIT, 0);
  if (!CreatePipe(&out_rd, &out_wr, &sa, 0)) {
    CloseHandle(in_rd);
    CloseHandle(in_wr);
    return -1;
  }
  SetHandleInformation(out_rd, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW si;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdInput = in_rd;
  si.hStdOutput = out_wr;
  si.hStdError = out_wr;

  PROCESS_INFORMATION pi;
  memset(&pi, 0, sizeof(pi));

  /* 与外部命令工具一致:交给 cmd 解释,这样 .bat/.cmd/.ps1 与管道都能用 */
  buf_t wrapped;
  buf_init(&wrapped);
  const char *p = cmdline;
  while (*p == ' ' || *p == '\t') p++;
  if (_strnicmp(p, "cmd ", 4) == 0 || _strnicmp(p, "cmd.exe", 7) == 0) {
    buf_puts(&wrapped, cmdline);
  } else {
    buf_puts(&wrapped, "cmd.exe /d /s /c \"");
    buf_puts(&wrapped, cmdline);
    buf_putc_(&wrapped, '"');
  }

  wchar_t *wcmd = u8_to_w(wrapped.data);
  wchar_t *wdir = workdir && *workdir ? u8_to_w(workdir) : NULL;
  buf_free(&wrapped);
  if (!wcmd) {
    CloseHandle(in_rd); CloseHandle(in_wr);
    CloseHandle(out_rd); CloseHandle(out_wr);
    return -1;
  }

  BOOL ok = CreateProcessW(NULL, wcmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, wdir, &si, &pi);
  free(wcmd);
  free(wdir);
  CloseHandle(in_rd);
  CloseHandle(out_wr);
  if (!ok) {
    CloseHandle(in_wr);
    CloseHandle(out_rd);
    return -1;
  }

  if (stdin_data && *stdin_data) {
    size_t left = strlen(stdin_data);
    const char *q = stdin_data;
    while (left > 0) {
      DWORD wrote = 0;
      if (!WriteFile(in_wr, q, (DWORD)left, &wrote, NULL) || wrote == 0) break;
      q += wrote;
      left -= wrote;
    }
  }
  CloseHandle(in_wr);        /* 关掉写端,子进程才看得到 EOF */

  buf_t acc;
  buf_init(&acc);
  DWORD deadline = GetTickCount() + (DWORD)(timeout_ms > 0 ? timeout_ms : 30000);
  int timed_out = 0;
  char chunk[4096];
  for (;;) {
    DWORD avail = 0;
    if (PeekNamedPipe(out_rd, NULL, 0, NULL, &avail, NULL) && avail > 0) {
      DWORD got = 0;
      if (!ReadFile(out_rd, chunk, sizeof(chunk) - 1, &got, NULL) || got == 0) break;
      chunk[got] = 0;
      buf_putn(&acc, chunk, got);
      if (acc.len > 512 * 1024) break;
      continue;
    }
    DWORD w = WaitForSingleObject(pi.hProcess, 60);
    if (w == WAIT_OBJECT_0) {
      DWORD got = 0;
      while (PeekNamedPipe(out_rd, NULL, 0, NULL, &avail, NULL) && avail > 0 &&
             ReadFile(out_rd, chunk, sizeof(chunk) - 1, &got, NULL) && got > 0) {
        chunk[got] = 0;
        buf_putn(&acc, chunk, got);
        if (acc.len > 512 * 1024) break;
      }
      break;
    }
    if (GetTickCount() > deadline) {
      timed_out = 1;
      TerminateProcess(pi.hProcess, 1);
      break;
    }
  }

  DWORD code = 0;
  GetExitCodeProcess(pi.hProcess, &code);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  CloseHandle(out_rd);

  if (out_text) *out_text = buf_take(&acc);
  else buf_free(&acc);
  if (out_exit) *out_exit = (int)code;
  return timed_out ? -2 : 0;
}

/* ================= HTTP 端点 =================
   这里刻意不走 net.cpp 的巡检通道:那是"访问被检目标",要过授权池与限速;
   这是"调用使用者自己配的工具",属于本机能力。 */
static int http_post_json(const char *url, const char *body, size_t body_len, int timeout_ms,
                          char **out_text, int *out_status, char *err, size_t errcap) {
  if (out_text) *out_text = NULL;
  if (out_status) *out_status = 0;
  wchar_t *wurl = u8_to_w(url);
  if (!wurl) {
    snprintf(err, errcap, "端点地址编码失败");
    return -1;
  }

  URL_COMPONENTS uc;
  memset(&uc, 0, sizeof(uc));
  uc.dwStructSize = sizeof(uc);
  uc.dwHostNameLength = (DWORD)-1;
  uc.dwUrlPathLength = (DWORD)-1;
  uc.dwExtraInfoLength = (DWORD)-1;
  if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) {
    free(wurl);
    snprintf(err, errcap, "端点地址看不懂:%s", url);
    return -1;
  }
  std::wstring host(uc.lpszHostName, uc.dwHostNameLength);
  std::wstring path(uc.lpszUrlPath, uc.dwUrlPathLength);
  if (uc.lpszExtraInfo && uc.dwExtraInfoLength) {
    path.append(uc.lpszExtraInfo, uc.dwExtraInfoLength);
  }
  if (path.empty()) path = L"/";

  HINTERNET session = WinHttpOpen(L"BwAgentToolEntry/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!session) {
    free(wurl);
    snprintf(err, errcap, "WinHTTP 初始化失败");
    return -1;
  }
  WinHttpSetTimeouts(session, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

  HINTERNET conn = WinHttpConnect(session, host.c_str(), uc.nPort, 0);
  if (!conn) {
    WinHttpCloseHandle(session);
    free(wurl);
    snprintf(err, errcap, "连不上端点主机");
    return -1;
  }
  DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
  HINTERNET req = WinHttpOpenRequest(conn, L"POST", path.c_str(), NULL, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
  int rc = -1;
  if (req) {
    const wchar_t *hdr = L"Content-Type: application/json; charset=utf-8\r\n";
    if (WinHttpSendRequest(req, hdr, (DWORD)-1L, (LPVOID)body, (DWORD)body_len,
                           (DWORD)body_len, 0) &&
        WinHttpReceiveResponse(req, NULL)) {
      DWORD status = 0, slen = sizeof(status);
      WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                          WINHTTP_HEADER_NAME_BY_INDEX, &status, &slen, WINHTTP_NO_HEADER_INDEX);
      if (out_status) *out_status = (int)status;

      buf_t acc;
      buf_init(&acc);
      char chunk[4096];
      DWORD got = 0;
      while (WinHttpReadData(req, chunk, sizeof(chunk) - 1, &got) && got > 0) {
        chunk[got] = 0;
        buf_putn(&acc, chunk, got);
        if (acc.len > 512 * 1024) break;
      }
      if (out_text) *out_text = buf_take(&acc);
      else buf_free(&acc);
      rc = 0;
    } else {
      snprintf(err, errcap, "HTTP 请求失败(%lu)", (unsigned long)GetLastError());
    }
    WinHttpCloseHandle(req);
  } else {
    snprintf(err, errcap, "打不开请求");
  }
  WinHttpCloseHandle(conn);
  WinHttpCloseHandle(session);
  free(wurl);
  return rc;
}

/* ================= 结果解析 =================
   应答既可以是约定好的结果 JSON,也可以就是一段纯文本(很多现成脚本懒得包 JSON)。 */
static void apply_result(const char *raw, tool_result_t *out) {
  json_t *o = raw ? json_parse(raw) : NULL;
  if (o && o->type == J_OBJ && j_get(o, "text")) {
    const char *t = j_s(o, "text", "");
    const char *say = j_s(o, "say", "");
    out->text = xstrdup(t[0] ? t : "(外部工具没有返回文本)");
    if (say[0]) out->say = xstrdup(say);
    json_t *d = j_get(o, "data");
    if (d) {
      char *dt = json_dump(d);
      out->data = dt ? json_parse(dt) : NULL;
      free(dt);
    }
    out->is_error = j_b(o, "is_error", 0) ? 1 : 0;
    json_free(o);
    return;
  }
  json_free(o);
  out->text = xstrdup(raw && *raw ? raw : "(无输出)");
  out->is_error = 0;
}

/* ================= 执行 ================= */

int tool_entry_run(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  const char *name = ctx && ctx->current_tool ? ctx->current_tool : "";
  entry_t *e = entry_find(name);
  if (!e) {
    out->is_error = 1;
    out->text = xstrdup("找不到这个工具的入口声明(可能刚被删掉,重新加载一次扩展即可)");
    return -1;
  }

  /* 请求体:工具的"调用协议" */
  buf_t req;
  buf_init(&req);
  buf_puts(&req, "{\"tool\":");
  buf_json_str(&req, e->name);
  buf_puts(&req, ",\"args\":");
  if (args) json_write(&req, args);
  else buf_puts(&req, "{}");
  buf_puts(&req, ",\"context\":{\"data_dir\":");
  buf_json_str(&req, app_data_dir());
  buf_puts(&req, ",\"app_dir\":");
  buf_json_str(&req, app_dir());
  buf_puts(&req, ",\"cwd\":");
  buf_json_str(&req, e->cwd[0] ? e->cwd : app_data_dir());
  buf_puts(&req, ",\"readonly\":");
  buf_puts(&req, "false}}");

  char *text = NULL;
  int code = -1;
  char err[512];
  err[0] = 0;

  if (str_ieq(e->type, "http")) {
    int status = 0;
    int rc = http_post_json(e->url, req.data, req.len, e->timeout_ms, &text, &status, err,
                            sizeof(err));
    buf_free(&req);
    if (rc != 0) {
      out->is_error = 1;
      out->text = xstrdup(err[0] ? err : "HTTP 端点调用失败");
      return -1;
    }
    apply_result(text, out);
    free(text);
    if (status < 200 || status >= 300) {
      out->is_error = 1;
      buf_t b;
      buf_init(&b);
      buf_printf(&b, "端点返回 HTTP %d\n%s", status, out->text ? out->text : "");
      free(out->text);
      out->text = buf_take(&b);
      return -1;
    }
    return out->is_error ? -1 : 0;
  }

  /* exec */
  char *cmd = build_cmdline(e, args);
  const char *workdir = e->cwd[0] ? e->cwd : app_data_dir();
  int json_proto = str_ieq(e->protocol, "json-stdio");
  int rc = run_proc(cmd, workdir, json_proto ? req.data : NULL, e->timeout_ms, &text, &code);
  json_t *data = j_obj();
  j_set_str(data, "command", cmd);
  j_set_num(data, "exit_code", code);
  j_set_str(data, "protocol", e->protocol);
  buf_free(&req);

  if (rc != 0) {
    out->is_error = 1;
    buf_t b;
    buf_init(&b);
    buf_printf(&b, "外部工具执行失败(%s)", rc == -2 ? "超时" : "无法启动");
    out->text = buf_take(&b);
    out->data = data;
    free(cmd);
    free(text);
    return -1;
  }
  free(cmd);

  if (json_proto) {
    apply_result(text, out);
    free(text);
    if (!out->data) out->data = data;
    else {
      j_set_str(out->data, "command", j_s(data, "command", ""));
      j_set_num(out->data, "exit_code", code);
      json_free(data);
    }
  } else {
    out->text = (text && *text) ? text : xstrdup("(无输出)");
    out->data = data;
  }
  if (code != 0) out->is_error = 1;
  return out->is_error ? -1 : 0;
}
