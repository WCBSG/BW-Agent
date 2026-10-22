/* common.cpp —— 基础件实现:动态缓冲、内存、UTF-8、时间、日志、文本、路径。
   只用 Windows 自带的 kernel32 / UCRT。 */
#include "common.h"

#include <shellapi.h>   /* CommandLineToArgvW —— 从原始命令行取参数用 */
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <exception>

/* ================= 动态缓冲区 ================= */
void buf_init(buf_t *b) {
  b->cap = 256;
  b->len = 0;
  b->data = (char *)xmalloc(b->cap);
  b->data[0] = 0;
}

void buf_free(buf_t *b) {
  free(b->data);
  b->data = NULL;
  b->len = b->cap = 0;
}

void buf_clear(buf_t *b) {
  b->len = 0;
  if (b->data) b->data[0] = 0;
}

void buf_reserve(buf_t *b, size_t extra) {
  if (b->len + extra + 1 <= b->cap) return;
  while (b->len + extra + 1 > b->cap) b->cap = b->cap ? b->cap * 2 : 256;
  b->data = (char *)xrealloc(b->data, b->cap);
}

void buf_putn(buf_t *b, const char *s, size_t n) {
  if (!s || !n) return;
  buf_reserve(b, n);
  memcpy(b->data + b->len, s, n);
  b->len += n;
  b->data[b->len] = 0;
}

void buf_puts(buf_t *b, const char *s) {
  if (s) buf_putn(b, s, strlen(s));
}

void buf_putc_(buf_t *b, char c) {
  buf_reserve(b, 1);
  b->data[b->len++] = c;
  b->data[b->len] = 0;
}

void buf_printf(buf_t *b, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int need = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (need <= 0) return;
  buf_reserve(b, (size_t)need);
  va_start(ap, fmt);
  vsnprintf(b->data + b->len, (size_t)need + 1, fmt, ap);
  va_end(ap);
  b->len += (size_t)need;
}

void buf_json_str(buf_t *b, const char *s) {
  buf_putc_(b, '"');
  if (s) {
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
      switch (*p) {
        case '"':  buf_puts(b, "\\\""); break;
        case '\\': buf_puts(b, "\\\\"); break;
        case '\n': buf_puts(b, "\\n"); break;
        case '\r': buf_puts(b, "\\r"); break;
        case '\t': buf_puts(b, "\\t"); break;
        case '\b': buf_puts(b, "\\b"); break;
        case '\f': buf_puts(b, "\\f"); break;
        default:
          if (*p < 0x20) {
            buf_printf(b, "\\u%04x", *p);
          } else {
            /* >=0x80 的字节原样输出:我们的源数据本来就是 UTF-8,不必转义 */
            buf_putc_(b, (char)*p);
          }
      }
    }
  }
  buf_putc_(b, '"');
}

char *buf_take(buf_t *b) {
  char *out = b->data;
  b->data = NULL;
  b->len = b->cap = 0;
  return out;
}

/* ================= 编码 ================= */

void b64_encode(const unsigned char *src, size_t len, buf_t *out) {
  static const char *tab =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t i = 0;
  while (i + 2 < len) {
    unsigned int v = ((unsigned)src[i] << 16) | ((unsigned)src[i + 1] << 8) | src[i + 2];
    buf_putc_(out, tab[(v >> 18) & 63]);
    buf_putc_(out, tab[(v >> 12) & 63]);
    buf_putc_(out, tab[(v >> 6) & 63]);
    buf_putc_(out, tab[v & 63]);
    i += 3;
  }
  if (i + 1 == len) {
    unsigned int v = (unsigned)src[i] << 16;
    buf_putc_(out, tab[(v >> 18) & 63]);
    buf_putc_(out, tab[(v >> 12) & 63]);
    buf_puts(out, "==");
  } else if (i + 2 == len) {
    unsigned int v = ((unsigned)src[i] << 16) | ((unsigned)src[i + 1] << 8);
    buf_putc_(out, tab[(v >> 18) & 63]);
    buf_putc_(out, tab[(v >> 12) & 63]);
    buf_putc_(out, tab[(v >> 6) & 63]);
    buf_putc_(out, '=');
  }
}

void hex_encode(const unsigned char *src, size_t len, char *out, size_t cap) {
  static const char *tab = "0123456789abcdef";
  size_t o = 0;
  for (size_t i = 0; i < len && o + 3 < cap; i++) {
    out[o++] = tab[src[i] >> 4];
    out[o++] = tab[src[i] & 15];
  }
  if (cap) out[o < cap ? o : cap - 1] = 0;
}

/* ================= 内存 ================= */
void *xmalloc(size_t n) {
  void *p = malloc(n ? n : 1);
  if (!p) { fprintf(stderr, "out of memory (%zu)\n", n); exit(2); }
  return p;
}

void *xcalloc(size_t n, size_t sz) {
  void *p = calloc(n ? n : 1, sz ? sz : 1);
  if (!p) { fprintf(stderr, "out of memory\n"); exit(2); }
  return p;
}

void *xrealloc(void *p, size_t n) {
  void *q = realloc(p, n ? n : 1);
  if (!q) { fprintf(stderr, "out of memory\n"); exit(2); }
  return q;
}

char *xstrdup(const char *s) {
  if (!s) return NULL;
  size_t n = strlen(s);
  char *out = (char *)xmalloc(n + 1);
  memcpy(out, s, n + 1);
  return out;
}

char *xstrndup(const char *s, size_t n) {
  if (!s) return NULL;
  size_t len = 0;
  while (len < n && s[len]) len++;
  char *out = (char *)xmalloc(len + 1);
  memcpy(out, s, len);
  out[len] = 0;
  return out;
}

/* ================= UTF-8 <-> UTF-16 ================= */
wchar_t *u8_to_w(const char *s) {
  if (!s) return NULL;
  int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
  if (n <= 0) return NULL;
  wchar_t *w = (wchar_t *)xcalloc((size_t)n + 1, sizeof(wchar_t));
  MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
  return w;
}

/* 把一个宽串(可能不是 NUL 结尾)转成 UTF-8 */
char *w_to_u8_alloc(const wchar_t *w, int chars) {
  if (!w) return NULL;
  int n = WideCharToMultiByte(CP_UTF8, 0, w, chars, NULL, 0, NULL, NULL);
  if (n < 0) n = 0;
  char *out = (char *)xmalloc((size_t)n + 1);
  if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w, chars, out, n, NULL, NULL);
  out[n] = 0;
  return out;
}

char *w_to_u8(const wchar_t *w) {
  return w ? w_to_u8_alloc(w, -1) : NULL;
}

/* ================= 时间 ================= */
static long long filetime_to_ms(FILETIME ft) {
  /* FILETIME 是 1601-01-01 起的 100ns;换成 Unix 毫秒需要减去 1970 的偏移 */
  ULARGE_INTEGER u;
  u.LowPart = ft.dwLowDateTime;
  u.HighPart = ft.dwHighDateTime;
  return (long long)(u.QuadPart / 10000ULL) - 11644473600000LL;
}

void ms_to_iso(long long ms, char *out, size_t cap) {
  time_t secs = (time_t)(ms / 1000);
  int milli = (int)(ms % 1000);
  if (milli < 0) { milli += 1000; secs -= 1; }
  struct tm tm_utc;
  gmtime_s(&tm_utc, &secs);
  snprintf(out, cap, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
           tm_utc.tm_year + 1900, tm_utc.tm_mon + 1, tm_utc.tm_mday,
           tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec, milli);
}

void now_iso(char *out, size_t cap) {
  ms_to_iso(now_ms(), out, cap);
}

void now_iso_at(FILETIME ft, char *out, size_t cap) {
  ms_to_iso(filetime_to_ms(ft), out, cap);
}

long long now_ms(void) {
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  return filetime_to_ms(ft);
}

/* ================= 日志 ================= */
static FILE *g_log_file = NULL;
static log_level_t g_log_level = LOG_INFO;
static CRITICAL_SECTION g_log_lock;
static int g_log_lock_ready = 0;

void console_init(void) {
  /* 控制台切到 UTF-8,否则中文日志会变问号 */
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);
  /* 换成 C++ 之后,STL 容器/字符串在内存不足时会抛异常。我们用不到异常处理,
     所以显式兜住:把原因写进日志(双击运行时没有控制台,这是唯一线索),再退出。 */
  std::set_terminate([]() {
    log_error("程序因未捕获的 C++ 异常终止(通常是内存不足)。日志见数据目录 agent.log");
    std::abort();
  });
}

/* 把标准流重新指向控制台(GUI 子系统程序默认没有标准流指向,printf 会丢) */
static void bind_std_streams(void) {
  freopen("CONOUT$", "w", stdout);
  freopen("CONOUT$", "w", stderr);
  freopen("CONIN$", "r", stdin);
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);
}

int app_console_init(int want_window) {
  if (GetConsoleWindow() != NULL) {                  /* 已经挂着自己的控制台 */
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    return 1;
  }
  /* --debug:明确要一个看得见的窗口,那就自己开一个(不管外面的句柄指向哪里) */
  if (want_window && AllocConsole()) {
    bind_std_streams();
    printf("—— 调试窗口(--debug):运行日志与提示都显示在这里 ——\n\n");
    return 1;
  }
  /* 标准流已经可用(管道 / 重定向到文件 / 继承来的控制台句柄):照用,别抢过来 */
  HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);
  HANDLE herr = GetStdHandle(STD_ERROR_HANDLE);
  if ((hout && hout != INVALID_HANDLE_VALUE) || (herr && herr != INVALID_HANDLE_VALUE)) return 1;
  if (AttachConsole(ATTACH_PARENT_PROCESS)) {        /* 句柄没继承,但父进程有控制台 */
    bind_std_streams();
    return 1;
  }
  return 0;                                          /* 静默:日志写文件 */
}

char **app_argv_from_command_line(int *argc_out) {
  if (argc_out) *argc_out = 0;
  LPWSTR wcmd = GetCommandLineW();
  if (!wcmd) return NULL;
  int n = 0;
  LPWSTR *wargv = CommandLineToArgvW(wcmd, &n);
  if (!wargv) return NULL;
  char **argv = (char **)xmalloc(sizeof(char *) * (size_t)(n + 1));
  for (int i = 0; i < n; i++) {
    char *u8 = w_to_u8(wargv[i]);
    argv[i] = u8 ? u8 : xstrdup("");
  }
  argv[n] = NULL;
  LocalFree(wargv);
  if (argc_out) *argc_out = n;
  return argv;
}

void free_argv(int argc, char **argv) {
  if (!argv) return;
  for (int i = 0; i < argc; i++) free(argv[i]);
  free(argv);
}

void app_fix_argv_encoding(int argc, char **argv) {
  UINT acp = GetACP();
  if (acp == CP_UTF8) return;                 /* 已经是 UTF-8,不用动 */
  for (int i = 0; i < argc; i++) {
    if (!argv[i] || !*argv[i]) continue;
    /* 已经是合法 UTF-8 就不动它(避免二次转换把内容搞坏) */
    wchar_t *probe = u8_to_w(argv[i]);
    if (probe) {
      char *back = w_to_u8(probe);
      int same = back && strcmp(back, argv[i]) == 0;
      free(probe);
      free(back);
      if (same) continue;
    }
    int need = MultiByteToWideChar(acp, 0, argv[i], -1, NULL, 0);
    if (need <= 0) continue;
    wchar_t *w = (wchar_t *)xmalloc((size_t)need * sizeof(wchar_t));
    MultiByteToWideChar(acp, 0, argv[i], -1, w, need);
    char *u8 = w_to_u8(w);
    free(w);
    if (!u8) continue;
    /* 换指针,不原地改写 —— argv 的那块内存大小未知,覆盖会踩内存 */
    argv[i] = xstrdup(u8);
    free(u8);
  }
}

/* 路径含中文时必须走宽字符接口:fopen 用 ANSI 代码页,遇到中文路径会直接失败。
   本项目的路径就带中文(作品目录名),所以这里统一封一层 —— 踩过一次坑就固化下来。 */
static FILE *fopen_utf8(const char *path, const wchar_t *mode) {
  wchar_t *w = u8_to_w(path);
  if (!w) return NULL;
  FILE *fp = _wfopen(w, mode);
  free(w);
  return fp;
}

void log_open(const char *path) {
  if (!g_log_lock_ready) {
    InitializeCriticalSection(&g_log_lock);
    g_log_lock_ready = 1;
  }
  if (path) {
    char dir[MAX_PATH];
    path_dir_of(path, dir, sizeof(dir));
    ensure_dir(dir);           /* 先把日志所在目录建出来,否则 fopen 会失败 */
    /* 超过 2MB 就轮转一份(留 agent.log.1)—— 长期挂着跑也不会撑爆磁盘 */
    long sz = file_size(path);
    if (sz > 2 * 1024 * 1024) {
      char old_path[MAX_PATH * 2];
      snprintf(old_path, sizeof(old_path), "%s.1", path);
      wchar_t *wfrom = u8_to_w(path);
      wchar_t *wto = u8_to_w(old_path);
      if (wfrom && wto) {
        DeleteFileW(wto);      /* 老的那份直接覆盖 */
        MoveFileW(wfrom, wto);
      }
      free(wfrom);
      free(wto);
    }
    g_log_file = fopen_utf8(path, L"a");
    /* 新建的日志文件先写个 UTF-8 BOM:记事本才会认成 UTF-8,中文日志才不乱码 */
    if (g_log_file && sz < 0) fwrite("\xEF\xBB\xBF", 1, 3, g_log_file);
  }
}

void log_close(void) {
  if (g_log_file) { fclose(g_log_file); g_log_file = NULL; }
}

void log_set_level(log_level_t level) { g_log_level = level; }

void log_write(log_level_t level, const char *fmt, ...) {
  if (level < g_log_level) return;
  static const char *names[] = {"DEBUG", "INFO", "WARN", "ERROR"};

  char ts[40];
  now_iso(ts, sizeof(ts));

  buf_t line;
  buf_init(&line);
  buf_printf(&line, "[%s] %-5s ", ts, names[level]);
  va_list ap;
  va_start(ap, fmt);
  int need = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (need > 0) {
    buf_reserve(&line, (size_t)need + 2);
    va_start(ap, fmt);
    vsnprintf(line.data + line.len, (size_t)need + 1, fmt, ap);
    va_end(ap);
    line.len += (size_t)need;
  }
  buf_puts(&line, "\n");

  if (g_log_lock_ready) EnterCriticalSection(&g_log_lock);
  fputs(line.data, stderr);
  fflush(stderr);
  if (g_log_file) {
    fputs(line.data, g_log_file);
    fflush(g_log_file);
  }
  if (g_log_lock_ready) LeaveCriticalSection(&g_log_lock);
  buf_free(&line);
}

/* ================= 文本工具 ================= */
int str_ieq(const char *a, const char *b) {
  if (!a || !b) return a == b;
  return _stricmp(a, b) == 0;
}

int str_startswith(const char *s, const char *prefix) {
  if (!s || !prefix) return 0;
  size_t n = strlen(prefix);
  return strncmp(s, prefix, n) == 0;
}

int str_endswith(const char *s, const char *suffix) {
  if (!s || !suffix) return 0;
  size_t ls = strlen(s), lf = strlen(suffix);
  return ls >= lf && strcmp(s + ls - lf, suffix) == 0;
}

char *str_trim(char *s) {
  if (!s) return s;
  while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
  size_t n = strlen(s);
  while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n')) {
    s[--n] = 0;
  }
  return s;
}

int str_contains(const char *hay, const char *needle) {
  return hay && needle && strstr(hay, needle) != NULL;
}

static char *lower_dup(const char *s) {
  char *out = xstrdup(s);
  for (char *p = out; *p; p++) *p = (char)tolower((unsigned char)*p);
  return out;
}

int str_icontains(const char *hay, const char *needle) {
  if (!hay || !needle) return 0;
  char *h = lower_dup(hay), *n = lower_dup(needle);
  int hit = strstr(h, n) != NULL;
  free(h); free(n);
  return hit;
}

/* 忽略大小写找到"第一次出现的位置"(返回 hay 里的指针,便于从命中处往后继续扫)。
   str_icontains 只回答"有没有",这个回答"在哪" —— 抽取链接/标签时要连着扫。 */
const char *str_icase_find(const char *hay, const char *needle) {
  if (!hay || !needle || !*needle) return NULL;
  size_t nl = strlen(needle);
  for (const char *p = hay; *p; p++) {
    size_t i = 0;
    while (i < nl && p[i] &&
           tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
      i++;
    }
    if (i == nl) return p;
  }
  return NULL;
}

int str_split(const char *s, char sep, char ***out, int max_parts) {
  *out = NULL;
  if (!s) return 0;
  int cap = 8;
  char **list = (char **)xcalloc((size_t)cap, sizeof(char *));
  int n = 0;
  const char *start = s;
  for (const char *p = s;; p++) {
    if (*p == sep || *p == 0) {
      /* 需要更多槽位就扩容 —— 之前这里固定只分配 1 个,多段会踩坏堆 */
      if (n + 1 >= cap) {
        int new_cap = cap * 2;
        list = (char **)xrealloc(list, sizeof(char *) * (size_t)new_cap);
        for (int i = cap; i < new_cap; i++) list[i] = NULL;
        cap = new_cap;
      }
      if (max_parts > 0 && n == max_parts - 1) {
        list[n++] = xstrdup(start);      /* 最后一段把剩下的全吃下 */
        break;
      }
      list[n++] = xstrndup(start, (size_t)(p - start));
      if (*p == 0) break;
      start = p + 1;
      if (max_parts > 0 && n >= max_parts) break;
    }
  }
  *out = list;
  return n;
}

void str_free_list(char **list, int n) {
  if (!list) return;
  for (int i = 0; i < n; i++) free(list[i]);
  free(list);
}

/* ================= 路径 ================= */
static char g_app_dir[MAX_PATH] = {0};
static char g_app_exe[MAX_PATH] = {0};

void app_init_paths(void) {
  /* 必须用宽字符版 API:窄字符版走 ANSI 代码页,中文路径会变成乱码 */
  wchar_t wexe[MAX_PATH] = {0};
  GetModuleFileNameW(NULL, wexe, MAX_PATH);
  char *u8 = w_to_u8(wexe);
  if (u8) {
    strncpy_s(g_app_exe, MAX_PATH, u8, _TRUNCATE);
    free(u8);
  }
  strncpy_s(g_app_dir, MAX_PATH, g_app_exe, _TRUNCATE);
  char *slash1 = strrchr(g_app_dir, '\\');
  char *slash2 = strrchr(g_app_dir, '/');
  char *slash = (slash2 > slash1) ? slash2 : slash1;
  if (slash) *(slash + 1) = 0;
}

const char *app_dir(void) { return g_app_dir; }
const char *app_exe(void) { return g_app_exe; }

/* 数据目录:C:\Users\<用户名>\.bw_agent
   为什么放用户目录:交付的是一个 exe,用户可能把它放在桌面、下载目录、U 盘里 ——
   数据(发现、报告、快照、审计)落在用户目录里更符合 Windows 习惯,
   也不会因为 exe 所在目录只读/被清理而丢数据。BW_AGENT_HOME 可以改到别处。 */
static char g_data_dir[MAX_PATH * 2] = {0};

static void make_data_default(char *out, size_t cap) {
  char *home = NULL;
  size_t hlen = 0;
  char *env = getenv("USERPROFILE");
  if (env && *env) {
    home = xstrdup(env);
  } else {
    const char *drive = getenv("HOMEDRIVE");
    const char *path = getenv("HOMEPATH");
    if (drive && path) {
      hlen = strlen(drive) + strlen(path) + 1;
      home = (char *)xmalloc(hlen);
      snprintf(home, hlen, "%s%s", drive, path);
    } else {
      home = xstrdup(app_dir());          /* 兜底:退回 exe 目录 */
      if (home[0] && home[strlen(home) - 1] == '\\') home[strlen(home) - 1] = 0;
    }
  }
  snprintf(out, cap, "%s\\.bw_agent\\", home);
  free(home);
  (void)hlen;
}

const char *app_data_dir(void) {
  if (g_data_dir[0]) return g_data_dir;
  const char *override = getenv("BW_AGENT_HOME");
  if (override && *override) {
    snprintf(g_data_dir, sizeof(g_data_dir), "%s", override);
  } else {
    make_data_default(g_data_dir, sizeof(g_data_dir));
  }
  return g_data_dir;
}

const char *app_data_path(char *out, size_t cap, const char *child) {
  const char *base = app_data_dir();
  size_t n = strlen(base);
  while (n > 0 && (base[n - 1] == '\\' || base[n - 1] == '/')) n--;   /* 去掉结尾分隔符 */
  if (!child || !*child) snprintf(out, cap, "%.*s", (int)n, base);
  else snprintf(out, cap, "%.*s\\%s", (int)n, base, child);
  return out;
}

void path_dir_of(const char *path, char *out, size_t cap) {
  strncpy_s(out, cap, path ? path : "", _TRUNCATE);
  char *slash = strrchr(out, '\\');
  char *slash2 = strrchr(out, '/');
  if (slash2 > slash) slash = slash2;
  if (slash) *(slash + 1) = 0;
}

int path_join(char *out, size_t cap, const char *dir, const char *name) {
  if (!dir || !name) return -1;
  size_t n = strlen(dir);
  int need_sep = (n > 0 && dir[n - 1] != '\\' && dir[n - 1] != '/');
  return snprintf(out, cap, "%s%s%s", dir, need_sep ? "\\" : "", name) > 0 ? 0 : -1;
}

void ensure_dir(const char *dir) {
  if (!dir || !*dir) return;
  char tmp[MAX_PATH * 2];
  strncpy_s(tmp, sizeof(tmp), dir, _TRUNCATE);
  for (char *p = tmp; *p; p++) if (*p == '/') *p = '\\';

  /* 判断传进来是目录还是文件:有扩展名的最后一段当文件名,先剥掉 */
  /* 参数一律当目录:逐级创建。
     (曾经这里有个"最后一段带点就当文件名先剥掉"的启发式 —— 结果 `.bw_agent`
     这种带点的目录名被当成文件,目录根本没建出来,后续写入全部失败。宁可不猜。)
     用宽字符版 API:目录名可能是中文(数据目录下就有 skills\、tools\ 这类)。 */
  for (char *p = tmp + 3; *p; p++) {
    if (*p == '\\') {
      *p = 0;
      wchar_t *w = u8_to_w(tmp);
      if (w) { CreateDirectoryW(w, NULL); free(w); }
      *p = '\\';
    }
  }
  wchar_t *w = u8_to_w(tmp);
  if (w) { CreateDirectoryW(w, NULL); free(w); }
}

long file_size(const char *path) {
  /* 必须宽字符版:窄字符版按 ANSI 代码页解释文件名,中文名会被判成"不存在" */
  if (!path) return -1;
  wchar_t *w = u8_to_w(path);
  if (!w) return -1;
  WIN32_FILE_ATTRIBUTE_DATA fad;
  BOOL ok = GetFileAttributesExW(w, GetFileExInfoStandard, &fad);
  free(w);
  if (!ok) return -1;
  LARGE_INTEGER li;
  li.HighPart = fad.nFileSizeHigh;
  li.LowPart = fad.nFileSizeLow;
  return (long)li.QuadPart;
}

char *file_read_all(const char *path, size_t *out_len) {
  FILE *fp = fopen_utf8(path, L"rb");
  if (!fp) return NULL;
  fseek(fp, 0, SEEK_END);
  long n = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  if (n < 0) { fclose(fp); return NULL; }
  char *data = (char *)xmalloc((size_t)n + 1);
  size_t got = fread(data, 1, (size_t)n, fp);
  fclose(fp);
  data[got] = 0;
  if (out_len) *out_len = got;
  return data;
}

int file_write_all(const char *path, const char *data, size_t len) {
  FILE *fp = fopen_utf8(path, L"wb");
  if (!fp) return -1;
  size_t put = fwrite(data, 1, len, fp);
  fclose(fp);
  return put == len ? 0 : -1;
}

int file_append(const char *path, const char *data, size_t len) {
  FILE *fp = fopen_utf8(path, L"ab");
  if (!fp) return -1;
  size_t put = fwrite(data, 1, len, fp);
  fclose(fp);
  return put == len ? 0 : -1;
}
/* ---------- 目录遍历(统一走宽字符 Win32) ----------
   为什么收口到这里:项目里踩过最久的一类 bug 就是"A 版 Win32 API 不认中文文件名"
   (FindFirstFileA / file_size(A) / CreateDirectoryA)。现在只保留**一套宽字符实现**,
   UTF-8 → UTF-16 由 u8_to_w 完成,调用方再也不用选 A 还是 W。
   (早期版本用过 std::filesystem,功能对但把 exe 从 582KB 撑到 1.5MB,
    换回 W 版后同样只有一条代码路径,体积几乎不增。) */
std::vector<std::string> fs_list_files(const char *dir, const char *ext) {
  std::vector<std::string> out;
  if (!dir || !*dir) return out;
  char pattern[MAX_PATH * 2];
  snprintf(pattern, sizeof(pattern), "%s\\*", dir);
  wchar_t *wpat = u8_to_w(pattern);
  if (!wpat) return out;
  WIN32_FIND_DATAW fd;
  HANDLE h = FindFirstFileW(wpat, &fd);
  free(wpat);
  if (h == INVALID_HANDLE_VALUE) return out;
  const std::string want_ext = ext ? ext : "";
  do {
    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
    char *name8 = w_to_u8(fd.cFileName);
    if (!name8) continue;
    std::string name = name8;
    free(name8);
    if (!want_ext.empty() && !str_endswith(name.c_str(), want_ext.c_str())) continue;
    out.push_back(name);
  } while (FindNextFileW(h, &fd));
  FindClose(h);
  std::sort(out.begin(), out.end());   /* 顺序稳定,便于复现与测试 */
  return out;
}

std::vector<std::string> fs_list_dirs(const char *dir) {
  std::vector<std::string> out;
  if (!dir || !*dir) return out;
  char pattern[MAX_PATH * 2];
  snprintf(pattern, sizeof(pattern), "%s\\*", dir);
  wchar_t *wpat = u8_to_w(pattern);
  if (!wpat) return out;
  WIN32_FIND_DATAW fd;
  HANDLE h = FindFirstFileW(wpat, &fd);
  free(wpat);
  if (h == INVALID_HANDLE_VALUE) return out;
  do {
    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
    char *name8 = w_to_u8(fd.cFileName);
    if (!name8) continue;
    out.push_back(name8);
    free(name8);
  } while (FindNextFileW(h, &fd));
  FindClose(h);
  std::sort(out.begin(), out.end());
  return out;
}

void fs_remove_tree(const char *dir) {  if (!dir || !*dir) return;
  /* 先递归删子项,再删自己;删不掉就算了(文件被占用等),不抛异常、不中断 */
  char pattern[MAX_PATH * 2];
  snprintf(pattern, sizeof(pattern), "%s\\*", dir);
  wchar_t *wpat = u8_to_w(pattern);
  if (wpat) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(wpat, &fd);
    free(wpat);
    if (h != INVALID_HANDLE_VALUE) {
      do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        char *name8 = w_to_u8(fd.cFileName);
        if (!name8) continue;
        char child[MAX_PATH * 2];
        snprintf(child, sizeof(child), "%s\\%s", dir, name8);
        free(name8);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
          fs_remove_tree(child);
        } else {
          wchar_t *wfile = u8_to_w(child);
          if (wfile) { DeleteFileW(wfile); free(wfile); }
        }
      } while (FindNextFileW(h, &fd));
      FindClose(h);
    }
  }
  wchar_t *wdir = u8_to_w(dir);
  if (wdir) { RemoveDirectoryW(wdir); free(wdir); }
}
