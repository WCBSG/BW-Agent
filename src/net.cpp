/* net.cpp —— WinHTTP 取数 + 合规三件事(授权/限速/审计)。
   为什么用 WinHTTP 而不是 WinINet:WinHTTP 不依赖 IE 设置、可指定 TLS、
   更适合服务型程序(这正是智能体后端的形态)。 */
#include "net.h"

#include "rules.h"
#include "tools.h"

#include <winhttp.h>

/* ================= 状态 ================= */
static HINTERNET g_session = NULL;
static int g_readonly = 0;

/* 授权范围(**按线程隔离**)、越界标记、目标基准地址,都放在线程本地。
   为什么必须隔离:服务端可能同时跑多个会话,而"这一轮的授权范围"是合规硬边界。
   共用一份的话,A 会话的越界会记到 B 头上、B 的目标会放行 A 的请求 —— 这是安全问题,
   不是体验问题。每个会话线程各自持有一份,谁也别想串味。
   用一个小对象持有,连接线程退出时自动释放,不留悬挂指针。 */
struct thread_scope_t {
  char task_id[64] = {0};
  char *domains[32] = {NULL};
  int count = 0;
  int violation = 0;
  char target_base[512] = {0};

  ~thread_scope_t() {
    for (int i = 0; i < count; i++) free(domains[i]);
  }
  void set(const char *tid, const char **d, int n) {
    for (int i = 0; i < count; i++) free(domains[i]);
    count = 0;
    snprintf(task_id, sizeof(task_id), "%s", tid ? tid : "");
    if (d && n > 0) {
      int cap = (int)(sizeof(domains) / sizeof(domains[0]));
      for (int i = 0; i < n && count < cap; i++) domains[count++] = xstrdup(d[i]);
    }
  }
};

static thread_local thread_scope_t g_scope;

/* 授权池:允许访问的主机白名单。池子非空时它就是唯一边界 ——
   "这一轮看哪个站"只是焦点,不是边界;越池即拒,并置 violation 让循环立刻收束。
   池子是**全进程共享的策略**(一个部署一套策略),读取时加锁。 */
static char **g_pool = NULL;
static int g_pool_count = 0;

static int host_allowed(const char *host, int port, const char *path);   /* 边界判定,实现在下方 */

static char g_audit_path[MAX_PATH * 2] = {0};
static double g_qps = 2.0;
static long long g_last_ms = 0;            /* 单主机限速:简化成全局节流 */
static CRITICAL_SECTION g_net_lock;
static int g_lock_ready = 0;
static int g_http_calls = 0;

/* 把 WinHTTP 的错误码翻成"能指导下一步动作"的话。
   巡检里最常见的就是这几类:连不上、域名解析不了、证书不对、被中间设备拦。
   只说"失败"对手上没有工具的人没有意义。 */
static char *net_error_text(DWORD err, const char *phase) {
  buf_t b;
  buf_init(&b);
  const char *hint = NULL;
  switch (err) {
    case ERROR_WINHTTP_NAME_NOT_RESOLVED: hint = "域名解析不了,检查域名是否写错或 DNS"; break;
    case ERROR_WINHTTP_CANNOT_CONNECT: hint = "连不上端口,检查服务是否在跑、端口是否正确"; break;
    case ERROR_WINHTTP_TIMEOUT: hint = "请求超时,站点慢或被防火墙丢弃"; break;
    case ERROR_WINHTTP_SECURE_FAILURE: hint = "TLS 证书校验没通过,检查证书是否过期或自签"; break;
    case ERROR_WINHTTP_INVALID_SERVER_RESPONSE: hint = "响应格式不合规,可能是中间设备拦截或站点异常"; break;
    case ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED: hint = "站点要求客户端证书"; break;
    case ERROR_WINHTTP_CONNECTION_ERROR: hint = "连接被重置,可能是防火墙或 WAF 拦截"; break;
    default: hint = "网络层错误,可先用浏览器确认该地址是否可达"; break;
  }
  buf_printf(&b, "%s失败(err=%lu:%s)", phase ? phase : "请求", err, hint);
  return buf_take(&b);
}

static void net_lock_init(void) {
  if (!g_lock_ready) {
    InitializeCriticalSection(&g_net_lock);
    g_lock_ready = 1;
  }
}

/* ---------- 连接计数(实测用) ----------
   说明:一开始这里做过"连接句柄缓存复用",但 A/B 实测(见 netbench)显示
   WinHTTP 会话本身已经维护连接池,缓存句柄在回环与真实站点上都没有可测量的收益,
   所以**没有采纳** —— 只留下计数与基准命令,让"有没有变慢/变快"随时能测。
   真正起作用的是上面的自动解压(检出正确性)与限速/重试策略。 */
static volatile LONG g_conn_created = 0;

int  net_conn_created(void) { return (int)g_conn_created; }
void net_reset_counters(void) { InterlockedExchange(&g_conn_created, 0); }


void net_init(void) {
  net_lock_init();
  if (!g_session) {
    g_session = WinHttpOpen(L"SecInspectAgent/1.0 (non-destructive; C edition)",
                            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_session) {
      log_error("WinHTTP 会话创建失败 (err=%lu)", GetLastError());
    } else {
      /* 自动解压:站点开了 gzip/br 时正文是压缩流,不解压就"看不见内容",
         内容特征判定会大面积漏检 —— 这不是性能优化,是检出正确性。 */
      DWORD decompress = WINHTTP_DECOMPRESSION_FLAG_ALL;
      WinHttpSetOption(g_session, WINHTTP_OPTION_DECOMPRESSION, &decompress,
                       sizeof(decompress));
    }
  }
}

void net_shutdown(void) {
  if (g_session) { WinHttpCloseHandle(g_session); g_session = NULL; }
  g_scope.set("", NULL, 0);
  net_lock_init();
  EnterCriticalSection(&g_net_lock);
  if (g_pool) { str_free_list(g_pool, g_pool_count); g_pool = NULL; g_pool_count = 0; }
  LeaveCriticalSection(&g_net_lock);
}

void net_set_readonly(int on) { g_readonly = on ? 1 : 0; }

void net_set_scope(const char *task_id, const char **domains, int count) {
  g_scope.set(task_id, domains, count);
}

void net_set_audit_path(const char *path) {
  strncpy_s(g_audit_path, sizeof(g_audit_path), path ? path : "", _TRUNCATE);
}

/* ---------- 授权池 ---------- */
void net_pool_set(const char **entries, int count) {
  net_lock_init();
  EnterCriticalSection(&g_net_lock);
  if (g_pool) { str_free_list(g_pool, g_pool_count); g_pool = NULL; }
  g_pool_count = 0;
  if (entries && count > 0) {
    g_pool = (char **)xcalloc((size_t)count, sizeof(char *));
    for (int i = 0; i < count; i++) g_pool[i] = xstrdup(entries[i]);
    g_pool_count = count;
  }
  LeaveCriticalSection(&g_net_lock);
}

int net_pool_count(void) {
  EnterCriticalSection(&g_net_lock);
  int n = g_pool_count;
  LeaveCriticalSection(&g_net_lock);
  return n;
}

/* 从 pool.json 载入授权池。命令行、技能直跑、常驻服务都走这一个入口 ——
   边界只有一份,不能因为"这次不是从界面点的"就松掉。 */
int net_pool_load_file(const char *path) {
  if (!path || !*path) return -1;
  size_t len = 0;
  char *text = file_read_all(path, &len);
  if (!text) return -1;
  json_t *root = json_parse(text);
  free(text);
  if (!root) return -1;
  json_t *hosts = j_get(root, "hosts");
  const char *list[512];
  int n = 0;
  for (int i = 0; i < j_len(hosts) && n < 512; i++) {
    json_t *v = j_at(hosts, i);
    if (!v) continue;
    if (v->type == J_STR && v->str) list[n++] = v->str;
    else if (v->type == J_OBJ) {
      const char *h = j_s(v, "host", "");
      if (h[0]) list[n++] = h;
    }
  }
  net_pool_set(list, n);
  json_free(root);
  return n;
}

int net_pool_has(const char *host, int port, const char *path) {
  if (!host || !*host) return 0;
  return host_allowed(host, port, path);
}

int net_scope_violation(void) { return g_scope.violation; }
void net_scope_violation_clear(void) { g_scope.violation = 0; }

void net_set_rate_limit(double qps) { g_qps = (qps > 0) ? qps : 2.0; }

/* 叫停信号:指向循环持有的那个标志。请求前看一眼,这样"停止"点下去,
   正在跑的那一轮会在下一次请求前就撒手,而不是跑完整个技能才停。 */
static thread_local volatile LONG *g_cancel_flag = NULL;

void net_set_cancel(volatile LONG *flag) { g_cancel_flag = flag; }
int net_cancelled(void) { return (g_cancel_flag && *g_cancel_flag) ? 1 : 0; }void net_set_target_base(const char *base) {
  strncpy_s(g_scope.target_base, sizeof(g_scope.target_base), base ? base : "", _TRUNCATE);
  char *t = str_trim(g_scope.target_base);
  if (t != g_scope.target_base) memmove(g_scope.target_base, t, strlen(t) + 1);
}

/* 把 URL 的"协议+端口"换成 target base 的(仅当主机名相同)。
   为什么需要:本地靶站跑在 http://127.0.0.1:8081 这类端口上,而用户/模型只会说
   "127.0.0.1" —— 不对齐就会去请求 443 端口,然后误判成"站点不可达"。 */
void net_align_url(const char *url, char *out, size_t cap) {
  const char *base = g_scope.target_base;
  if (!base[0] || !url || !*url) {
    snprintf(out, cap, "%s", url ? url : "");
    return;
  }
  char base_host[256], url_host[256];
  net_host_of(base, base_host, sizeof(base_host));
  net_host_of(url, url_host, sizeof(url_host));
  if (!str_ieq(base_host, url_host)) {
    snprintf(out, cap, "%s", url);
    return;
  }
  /* target base 的"协议 + 主机 + 端口"这一段(authority),原 URL 只保留路径与查询 */
  const char *scheme_end = strstr(base, "://");
  size_t scheme_len = scheme_end ? (size_t)(scheme_end - base) + 3 : 0;
  const char *auth = base + scheme_len;
  size_t auth_len = 0;
  while (auth[auth_len] && auth[auth_len] != '/' && auth[auth_len] != '?' &&
         auth[auth_len] != '#') {
    auth_len++;
  }
  /* 原 URL 的路径 */
  const char *path = strstr(url, "://");
  path = path ? strchr(path + 3, '/') : NULL;
  snprintf(out, cap, "%.*s%.*s%s", (int)scheme_len, base, (int)auth_len, auth,
           path ? path : "/");
}

/* ================= 主机与授权 ================= */
void net_host_of(const char *url, char *out, size_t cap) {
  out[0] = 0;
  if (!url) return;
  const char *p = strstr(url, "://");
  p = p ? p + 3 : url;
  size_t i = 0;
  while (p[i] && p[i] != '/' && p[i] != '?' && p[i] != '#' && i < cap - 1) {
    out[i] = (char)tolower((unsigned char)p[i]);
    i++;
  }
  out[i] = 0;
  char *at = strchr(out, '@');            /* 去掉 user:pass@ */
  if (at) memmove(out, at + 1, strlen(at));
  char *colon = strchr(out, ':');         /* 去掉端口 */
  if (colon) *colon = 0;
}

int net_host_port_of(const char *in, char *host_out, size_t hcap) {
  if (host_out && hcap) host_out[0] = 0;
  if (!in) return 0;
  net_host_of(in, host_out, hcap);
  const char *p = strstr(in, "://");
  p = p ? p + 3 : in;
  const char *end = p + strcspn(p, "/?#");
  const char *colon = NULL;
  for (const char *q = p; q < end; q++) if (*q == ':') colon = q;
  if (!colon || colon + 1 >= end) return 0;
  int port = 0;
  for (const char *q = colon + 1; q < end; q++) {
    if (*q < '0' || *q > '9') return 0;
    port = port * 10 + (*q - '0');
    if (port > 65535) return 0;
  }
  return port;
}

void net_align_base_from(const char *host_or_url) {
  char host[256];
  int port = net_host_port_of(host_or_url, host, sizeof(host));
  if (port <= 0 || !host[0]) return;
  char base[320];
  snprintf(base, sizeof(base), "%s://%s:%d", port == 443 ? "https" : "http", host, port);
  net_set_target_base(base);
  log_info("[目标] 目标地址带端口,巡检请求对齐到 %s", base);
}

int net_same_host(const char *a, const char *b) {  char ha[256], hb[256];
  net_host_of(a, ha, sizeof(ha));
  net_host_of(b, hb, sizeof(hb));
  return ha[0] && strcmp(ha, hb) == 0;
}

/* 池内条目 → 结构化。支持四种写法:
     exp.com           允许这个主机(任意端口)
     exp.com:8443      允许这个主机的指定端口
     !exp.com          不允许这个主机(优先于允许)
     !exp.com/admin/   不允许这个主机的这个路径前缀
   路径只对 deny 有意义(allow 的作用域始终是整个主机),这样匹配规则一眼能懂。 */
typedef struct {
  int deny;
  char host[256];
  int port;
  char path[512];
} pool_entry_t;

static int pool_parse_entry(const char *raw, pool_entry_t *out) {
  memset(out, 0, sizeof(*out));
  if (!raw || !*raw) return -1;
  const char *p = raw;
  if (*p == '!') { out->deny = 1; p++; }
  if (!*p) return -1;
  char body[768];
  snprintf(body, sizeof(body), "%s", p);
  char *slash = strchr(body, '/');
  if (slash) {
    snprintf(out->path, sizeof(out->path), "%s", slash);   /* 保留前导 / */
    *slash = 0;
    if (!out->path[0]) snprintf(out->path, sizeof(out->path), "/");
  }
  if (!body[0]) return -1;
  out->port = net_host_port_of(body, out->host, sizeof(out->host));
  if (!out->host[0]) return -1;
  return 0;
}

static int entry_matches(const char *entry, const char *host, int port, const char *path) {
  pool_entry_t e;
  if (pool_parse_entry(entry, &e) != 0) return 0;
  if (e.port > 0 && port > 0 && e.port != port) return 0;

  int host_hit = str_ieq(host, e.host);
  if (!host_hit) {
    size_t lh = strlen(host), ld = strlen(e.host);
    if (lh > ld && str_ieq(host + (lh - ld), e.host) && host[lh - ld - 1] == '.') host_hit = 1;
  }
  if (!host_hit) return 0;

  if (e.path[0]) {
    /* 路径按"段边界"匹配:/admin/ 命中 /admin/users.json 与 /admin 本身;
       /admin 命中 /admin 与 /admin/x,但**不**命中 /administrator ——
       前缀匹配不做到这个程度就会误伤。 */
    const char *q = path && path[0] ? path : "/";
    size_t pl = strlen(e.path);
    int hit = 0;
    if (strncmp(q, e.path, pl) == 0) {
      hit = (e.path[pl - 1] == '/') ? 1
                                    : (q[pl] == 0 || q[pl] == '/' || q[pl] == '?' || q[pl] == '#');
    } else if (e.path[pl - 1] == '/' && pl > 1 && strncmp(q, e.path, pl - 1) == 0) {
      char next = q[pl - 1];
      hit = (next == 0 || next == '/' || next == '?' || next == '#');
    }
    if (!hit) return 0;
  }
  return 1;
}

/* 判定:先看有没有命中"不允许",再看有没有命中"允许"。
   池子非空时,既不命中允许也不命中不允许 —— 一律拒(默认关门)。 */
static int host_allowed(const char *host, int port, const char *path) {
  if (!host || !*host) return 0;
  EnterCriticalSection(&g_net_lock);
  int have_pool = g_pool_count > 0;
  int denied = 0, allowed = 0;
  if (have_pool) {
    for (int i = 0; i < g_pool_count; i++) {
      pool_entry_t e;
      if (pool_parse_entry(g_pool[i], &e) != 0) continue;
      if (!entry_matches(g_pool[i], host, port, path)) continue;
      if (e.deny) denied = 1;
      else allowed = 1;
    }
  }
  LeaveCriticalSection(&g_net_lock);
  if (have_pool) return denied ? 0 : allowed;

  for (int i = 0; i < g_scope.count; i++) {
    if (entry_matches(g_scope.domains[i], host, port, path)) return 1;
  }
  return 0;
}

/* ================= 审计 ================= */
void net_audit(const char *action, const char *target, int allowed, const char *detail,
               const char *run_id) {
  if (!g_audit_path[0]) return;
  json_t *row = j_obj();
  char ts[40];
  now_iso(ts, sizeof(ts));
  j_set_str(row, "time", ts);
  j_set_str(row, "actor", "agent-c");
  j_set_str(row, "action", action ? action : "");
  j_set_str(row, "target", target ? target : "");
  j_set_str(row, "task_id", g_scope.task_id);
  j_set_str(row, "run_id", run_id ? run_id : "");
  j_set_bool(row, "allowed", allowed);
  j_set_str(row, "detail", detail ? detail : "");
  char *line = json_dump(row);
  buf_t out;
  buf_init(&out);
  buf_puts(&out, line);
  buf_putc_(&out, '\n');
  file_append(g_audit_path, out.data, out.len);
  buf_free(&out);
  free(line);
  json_free(row);
}

/* ================= 限速 ================= */
static void rate_wait(void) {
  net_lock_init();
  EnterCriticalSection(&g_net_lock);
  long long now = now_ms();
  long long min_gap = (long long)(1000.0 / g_qps);
  long long wait = g_last_ms + min_gap - now;
  if (wait > 0) {
    LeaveCriticalSection(&g_net_lock);
    Sleep((DWORD)wait);
    EnterCriticalSection(&g_net_lock);
    now = now_ms();
  }
  g_last_ms = now;
  g_http_calls++;
  LeaveCriticalSection(&g_net_lock);
}

int net_http_calls(void) { return g_http_calls; }

/* ================= 请求 ================= */
static void parse_url(const char *url, wchar_t *host, size_t host_cap,
                      wchar_t *path, size_t path_cap, int *https, INTERNET_PORT *port) {
  wchar_t *wurl = u8_to_w(url);
  URL_COMPONENTS uc;
  memset(&uc, 0, sizeof(uc));
  uc.dwStructSize = sizeof(uc);
  uc.dwHostNameLength = (DWORD)-1;
  uc.dwUrlPathLength = (DWORD)-1;
  uc.dwExtraInfoLength = (DWORD)-1;
  *https = 0;
  *port = 0;
  host[0] = 0;
  wcscpy_s(path, path_cap, L"/");

  if (wurl && WinHttpCrackUrl(wurl, 0, 0, &uc)) {
    if (uc.lpszHostName) {
      size_t n = uc.dwHostNameLength < host_cap - 1 ? uc.dwHostNameLength : host_cap - 1;
      wcsncpy_s(host, host_cap, uc.lpszHostName, n);
    }
    *https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    *port = uc.nPort;
    /* 路径 + 查询串:WinHttpCrackUrl 把二者分开了,要自己拼回去 */
    size_t used = 0;
    if (uc.lpszUrlPath && uc.dwUrlPathLength) {
      wcsncpy_s(path, path_cap, uc.lpszUrlPath, uc.dwUrlPathLength);
      used = uc.dwUrlPathLength;
    }
    if (uc.lpszExtraInfo && uc.dwExtraInfoLength && used < path_cap - 1) {
      wcsncat_s(path, path_cap, uc.lpszExtraInfo,
                path_cap - used - 1 < uc.dwExtraInfoLength ? path_cap - used - 1 : uc.dwExtraInfoLength);
    }
  }
  free(wurl);
}

void net_request(const char *url, const char *method, const char *content_type,
                 const char *body, size_t body_len, http_resp_t *resp) {
  memset(resp, 0, sizeof(*resp));
  long long t0 = now_ms();
  if (!url || !*url) {
    resp->error = xstrdup("空 URL");
    return;
  }
  /* 先做地址对齐(目标真实在哪个协议/端口),再做授权校验 */
  char aligned[2048];
  net_align_url(url, aligned, sizeof(aligned));
  url = aligned;

  if (!g_session) net_init();
  if (!g_session) {
    resp->error = xstrdup("WinHTTP 未初始化");
    return;
  }

  const char *m = method ? method : "GET";
  if (g_readonly && !str_ieq(m, "GET") && !str_ieq(m, "HEAD")) {
    resp->error = xstrdup("只读模式:只允许 GET/HEAD(非破坏性要求)");
    net_audit("fetch", url, 0, "只读模式拒绝非只读方法", NULL);
    return;
  }

  /* —— 合规第 1 道:授权校验。不在池内,连请求都不发 ——
     池子非空时以池子为唯一边界;"本轮目标"只是焦点,越界也照样拒。 */
  char host_u8[256];
  net_host_of(url, host_u8, sizeof(host_u8));
  char host_only[256];
  int url_port = net_host_port_of(url, host_only, sizeof(host_only));
  /* 路径也要参与判定:池子里的 !host/admin/ 只拦那个前缀,不拦整站 */
  char url_path[1024] = "/";
  {
    const char *scheme = strstr(url, "://");
    const char *p = scheme ? strchr(scheme + 3, '/') : strchr(url, '/');
    if (p && p[0]) {
      size_t n = strlen(p);
      if (n >= sizeof(url_path)) n = sizeof(url_path) - 1;
      memcpy(url_path, p, n);
      url_path[n] = 0;
      char *q = strpbrk(url_path, "?#");
      if (q) *q = 0;
    }
  }
  int pooled = net_pool_count() > 0;
  /* 池子空、本轮也没有授权范围 ⇒ 没有任何边界可言,一律不发。
     "什么都没配"绝不能等价于"什么都能访问"。 */  if (!pooled && g_scope.count == 0) {
    resp->error = xstrdup("还没有授权目标:先把主机加进授权池");
    g_scope.violation = 1;
    net_audit("authorize", url, 0, resp->error, NULL);
    return;
  }
  if (!host_allowed(host_u8, url_port, url_path)) {
    buf_t e;
    buf_init(&e);
    if (pooled) buf_printf(&e, "目标 %s 不在授权池内", host_u8);
    else buf_printf(&e, "目标 %s 不在授权域名内", host_u8);
    resp->error = buf_take(&e);
    /* 越权就是越权:置标记,让决策循环下一步立刻收束,而不是继续试别的路径 */
    g_scope.violation = 1;
    net_audit("authorize", url, 0, resp->error, NULL);
    log_warn("[合规] 拒绝越权目标: %s", url);
    return;
  }

  /* —— 合规第 2 道:限速 —— */
  if (net_cancelled()) {
    resp->error = xstrdup("本轮已被叫停,不再发请求");
    return;
  }
  rate_wait();

  wchar_t whost[256], wpath[2048];
  int https = 0;
  INTERNET_PORT port = 0;
  parse_url(url, whost, 256, wpath, 2048, &https, &port);

  HINTERNET conn = WinHttpConnect(g_session, whost, port, 0);
  InterlockedIncrement(&g_conn_created);
  if (!conn) {
    buf_t e;
    buf_init(&e);
    buf_printf(&e, "连接 %ls 失败 (err=%lu)", whost, GetLastError());
    resp->error = buf_take(&e);
  } else {
    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    LPCWSTR accept_types[] = {L"*/*", NULL};
    HINTERNET req = WinHttpOpenRequest(conn, u8_to_w(m), wpath, NULL,
                                       WINHTTP_NO_REFERER, accept_types, flags);
    if (!req) {
      resp->error = xstrdup("创建请求失败");
    } else {
      DWORD timeout = (DWORD)rules_number("timeout_ms", 20000);
      if (timeout < 3000) timeout = 3000;
      if (timeout > 120000) timeout = 120000;
      WinHttpSetOption(req, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
      WinHttpSetOption(req, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
      WinHttpSetOption(req, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
      /* 站点常因 UA/语言偏好返回不同内容(有的直接 403),所以带一个正常 UA。
         不伪装成浏览器:诚实上报身份,便于站点侧追溯。 */
      const wchar_t *ua = L"SecInspectAgent/1.0 (non-destructive security inspection)";
      WinHttpSetOption(req, WINHTTP_OPTION_USER_AGENT, (LPVOID)ua,
                       (DWORD)(wcslen(ua) * sizeof(wchar_t)));
      /* 重定向按系统策略自动跟(默认策略在部分机器上被改坏过,这里显式指定,
         避免"站点把 http 跳到 https,智能体却只看到 301"这种情况)。 */
      DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
      WinHttpSetOption(req, WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy,
                       sizeof(redirect_policy));

      LPCWSTR hdrs = content_type && (str_ieq(m, "POST") || str_ieq(m, "PUT"))
                         ? L"Content-Type: application/json\r\n"
                         : WINHTTP_NO_ADDITIONAL_HEADERS;
      BOOL ok = WinHttpSendRequest(req, hdrs, (DWORD)-1L,
                                   (LPVOID)(body_len ? body : NULL), (DWORD)body_len,
                                   (DWORD)body_len, 0);
      if (!ok) {
        DWORD e1 = GetLastError();
        resp->error = net_error_text(e1, "发送请求");
      } else if (!WinHttpReceiveResponse(req, NULL)) {
        DWORD e2 = GetLastError();
        /* 有的站点/中间设备对首个请求回一个非标准响应(常见 err=12152):
           协议本身允许重试,所以重发一次再下结论。 */
        if (e2 == ERROR_WINHTTP_INVALID_SERVER_RESPONSE) {
          log_warn("[网络] %s 首次响应异常(err=12152),按协议重试一次", url);
          if (WinHttpSendRequest(req, hdrs, (DWORD)-1L, (LPVOID)(body_len ? body : NULL),
                                 (DWORD)body_len, (DWORD)body_len, 0) &&
              WinHttpReceiveResponse(req, NULL)) {
            e2 = 0;
          }
        }
        if (e2) resp->error = net_error_text(e2, "接收响应");
      }
      if (!resp->error) {
        DWORD status = 0, len = sizeof(status);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &len, WINHTTP_NO_HEADER_INDEX);
        resp->status = (int)status;

        /* —— 响应头:弱配置(安全响应头、Cookie 属性、版本泄露)只能由此判断 —— */
        {
          DWORD hlen = 0;
          WinHttpQueryHeaders(req, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                              WINHTTP_HEADER_NAME_BY_INDEX, NULL, &hlen,
                              WINHTTP_NO_HEADER_INDEX);
          if (hlen > 0) {
            wchar_t *wbuf = (wchar_t *)xmalloc(hlen + sizeof(wchar_t));
            if (WinHttpQueryHeaders(req, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                    WINHTTP_HEADER_NAME_BY_INDEX, wbuf, &hlen,
                                    WINHTTP_NO_HEADER_INDEX)) {
              resp->headers = w_to_u8(wbuf);
            }
            free(wbuf);
          }
        }

        buf_t acc;
        buf_init(&acc);
        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(req, &avail) && avail > 0) {
          if (acc.len > 4 * 1024 * 1024) break;      /* 上限 4MB,别被大文件拖死 */
          char *chunk = (char *)xmalloc(avail + 1);
          DWORD got = 0;
          if (!WinHttpReadData(req, chunk, avail, &got) || got == 0) { free(chunk); break; }
          chunk[got] = 0;
          buf_putn(&acc, chunk, got);
          free(chunk);
        }
        resp->body = buf_take(&acc);
        resp->body_len = resp->body ? strlen(resp->body) : 0;
      }
      WinHttpCloseHandle(req);
    }
    WinHttpCloseHandle(conn);
  }

  resp->ms = (int)(now_ms() - t0);
  /* —— 合规第 3 道:审计。成功失败都要留痕 —— */
  {
    buf_t d;
    buf_init(&d);
    buf_printf(&d, "%s %d %dms%s%s", m, resp->status, resp->ms,
               resp->error ? " err=" : "", resp->error ? resp->error : "");
    net_audit("fetch", url, resp->error ? 0 : 1, d.data, NULL);
    buf_free(&d);
  }
}

void http_resp_free(http_resp_t *r) {
  if (!r) return;
  free(r->headers);
  free(r->body);
  free(r->error);
  r->headers = NULL;
  r->body = NULL;
  r->error = NULL;
}

/* 基准:同一个 URL 连打 n 次,返回平均耗时(ms)。
   为什么单独做一个命令:连接复用这类优化的收益必须能当场量出来,
   否则"优化过了"只是说法。它临时把限速放开(只读 GET,只对自己的授权目标用)。 */
int net_bench(const char *url, int n, int *out_conns, int *out_requests) {
  if (n <= 0) n = 10;
  double saved_qps = g_qps;
  g_qps = 100000.0;                     /* 基准期间不限速 */
  net_reset_counters();
  int before_calls = g_http_calls;
  long long t0 = now_ms();
  int ok = 0;
  for (int i = 0; i < n; i++) {
    http_resp_t resp;
    memset(&resp, 0, sizeof(resp));
    net_request(url, "GET", NULL, NULL, 0, &resp);
    if (!resp.error && resp.status > 0) ok++;
    http_resp_free(&resp);
  }  long long dt = now_ms() - t0;
  int conns = (int)g_conn_created;
  int reqs = g_http_calls - before_calls;
  g_qps = saved_qps;
  if (out_conns) *out_conns = conns;
  if (out_requests) *out_requests = reqs;
  if (ok == 0) {
    printf("一次都没成功:目标不可达或未授权(%s)\n", url);
    return -1;
  }
  printf("  请求 %d 次(成功 %d),实际建连 %d 条,总耗时 %lld ms,平均 %.0f ms/次\n",
         reqs, ok, conns, dt, reqs > 0 ? (double)dt / reqs : 0.0);
  return (int)(dt / (reqs > 0 ? reqs : 1));
}

/* ================= 依赖端点的 POST(模型 / 告警投递) =================
   为什么要单独一个:恒脑要 appKey/sign 两个自定义头,net_request 的头是固定的。
   它们指向的是"我们的依赖",不是被检目标,所以不套被检目标的授权/只读限制;
   但失败同样要留审计 —— 调用不通必须能查。 */
static void post_json_ex(const char *url, const char *headers, int timeout_ms,
                         const char *body, net_stream_fn cb, void *ud,
                         http_resp_t *resp, const char *audit_tag) {
  memset(resp, 0, sizeof(*resp));
  long long t0 = now_ms();
  if (!g_session) net_init();
  if (!g_session) { resp->error = xstrdup("WinHTTP 未初始化"); return; }

  wchar_t whost[256], wpath[2048];
  int https = 0;
  INTERNET_PORT port = 0;
  parse_url(url, whost, 256, wpath, 2048, &https, &port);

  HINTERNET conn = WinHttpConnect(g_session, whost, port, 0);
  if (!conn) {
    resp->error = xstrdup("连接服务失败");
  } else {
    HINTERNET req = WinHttpOpenRequest(conn, L"POST", wpath, NULL,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       https ? WINHTTP_FLAG_SECURE : 0);
    if (!req) {
      resp->error = xstrdup("创建请求失败");
    } else {
      DWORD timeout = (DWORD)(timeout_ms > 0 ? timeout_ms : 20000);
      /* 三个超时都要设:只设接收超时的话,对端"接了但不回"或"连不上"都会
         把整个会话挂在一次调用上 —— 实测恒脑被 WAF 拦时就出现过一次调用卡 80 秒。
         等响应头这一段要给足时间(模型服务首字节常常要几秒),
         收到头之后的每一片读故意切成 800ms:这样"停止"不必等到整段超时才生效,
         总时长仍由 deadline 兜住。 */
      DWORD conn_to = 8000, send_to = 15000;
      DWORD hdr_to = timeout < 20000 ? timeout : 20000;
      WinHttpSetOption(req, WINHTTP_OPTION_CONNECT_TIMEOUT, &conn_to, sizeof(conn_to));
      WinHttpSetOption(req, WINHTTP_OPTION_SEND_TIMEOUT, &send_to, sizeof(send_to));
      WinHttpSetOption(req, WINHTTP_OPTION_RECEIVE_TIMEOUT, &hdr_to, sizeof(hdr_to));
      DWORD deadline = GetTickCount() + timeout;
      const wchar_t *whdrs = headers && headers[0] ? u8_to_w(headers) : NULL;
      BOOL ok = WinHttpSendRequest(req, whdrs ? whdrs : WINHTTP_NO_ADDITIONAL_HEADERS,
                                   whdrs ? (DWORD)-1L : 0,
                                   (LPVOID)body, (DWORD)strlen(body),
                                   (DWORD)strlen(body), 0);
      if (whdrs) free((void *)whdrs);
      if (!ok) {
        buf_t e;
        buf_init(&e);
        buf_printf(&e, "发送失败 (err=%lu)", GetLastError());
        resp->error = buf_take(&e);
      } else if (!WinHttpReceiveResponse(req, NULL)) {
        /* 带上错误码:是超时、被重置还是证书问题,一眼能分清 ——
           只说"接收响应失败"等于让人猜。 */
        buf_t e;
        buf_init(&e);
        buf_printf(&e, "接收响应失败 (err=%lu)", GetLastError());
        resp->error = buf_take(&e);
      } else {
        DWORD status = 0, len = sizeof(status);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &len, WINHTTP_NO_HEADER_INDEX);
        resp->status = (int)status;
        /* 响应头到手,读正文改成小片超时:这样"停止"能在 1 秒内生效 */
        DWORD slice = 800;
        WinHttpSetOption(req, WINHTTP_OPTION_RECEIVE_TIMEOUT, &slice, sizeof(slice));
        buf_t acc;
        buf_init(&acc);
        for (;;) {
          /* 用户点了"停止"就别再等模型了:每片最多 800ms,响应是及时的。
             以前这里只在"下一次请求之前"才看停止标,模型正在吐字时就只能干等。 */
          if (net_cancelled()) {
            resp->error = xstrdup("本轮已被叫停");
            break;
          }
          DWORD avail = 0;
          if (!WinHttpQueryDataAvailable(req, &avail)) {
            DWORD err = GetLastError();
            if (err == ERROR_WINHTTP_TIMEOUT) {
              if ((long)(GetTickCount() - deadline) < 0) continue;   /* 只是这一片没数据 */
              /* 到点了:一个字都没收到才算失败。已经收到完整正文、只是对端
                 不肯关连接(SSE 常见)是正常收尾,不能报错。 */
              if (acc.len == 0) resp->error = xstrdup("等待模型响应超时");
              break;
            }
            if (!resp->error) {
              buf_t e;
              buf_init(&e);
              buf_printf(&e, "读取响应失败 (err=%lu)", err);
              resp->error = buf_take(&e);
            }
            break;
          }
          if (avail == 0) break;
          if (acc.len > 8 * 1024 * 1024) break;
          char *chunk = (char *)xmalloc(avail + 1);
          DWORD got = 0;
          if (!WinHttpReadData(req, chunk, avail, &got) || got == 0) { free(chunk); break; }
          chunk[got] = 0;
          /* 边收边回调:模型分几段发,界面就分几段显示,
             不必等整段响应落地才"啪"地出现一大坨文字。
             回调说"收完了"(SSE 的 [DONE])就直接断开,不再等对端关连接。 */
          if (cb && cb(ud, chunk, got)) { buf_putn(&acc, chunk, got); free(chunk); break; }
          buf_putn(&acc, chunk, got);
          free(chunk);
        }
        resp->body = buf_take(&acc);
        resp->body_len = resp->body ? strlen(resp->body) : 0;
      }
      WinHttpCloseHandle(req);
    }
    WinHttpCloseHandle(conn);
  }
  resp->ms = (int)(now_ms() - t0);
  {
    buf_t d;
    buf_init(&d);
    buf_printf(&d, "POST %d %dms%s%s", resp->status, resp->ms,
               resp->error ? " err=" : "", resp->error ? resp->error : "");
    net_audit(audit_tag ? audit_tag : "post", url, resp->error ? 0 : 1, d.data, NULL);
    buf_free(&d);
  }
}

void hn_http_post(const char *url, const char *app_key, const char *sign,
                  const char *body, http_resp_t *resp) {
  hn_http_post_stream(url, app_key, sign, body, NULL, NULL, resp);
}

/* 带增量回调的版本:给"边收边显示"用。resp 仍然拿完整响应体,
   解析逻辑不用写两份 —— 回调只负责把新到的那一段顺手播出去。 */
void hn_http_post_stream(const char *url, const char *app_key, const char *sign,
                         const char *body, net_stream_fn cb, void *ud,
                         http_resp_t *resp) {
  buf_t hdrs;
  buf_init(&hdrs);
  buf_printf(&hdrs, "Content-Type: application/json\r\nappKey: %s\r\nsign: %s\r\n"
                    "ext: child_preview:0;reason:1\r\n",
             app_key ? app_key : "", sign ? sign : "");
  post_json_ex(url, hdrs.data, 45000, body, cb, ud, resp, "llm");
  buf_free(&hdrs);
}

void net_post_stream(const char *url, const char *headers, int timeout_ms,
                     const char *body, net_stream_fn cb, void *ud, http_resp_t *resp) {
  post_json_ex(url, headers, timeout_ms, body, cb, ud, resp, "post");
}

/* 取一段外部文本(市场里的技能/工具定义)。
   为什么不做成 net_request:那条路是"对被检目标发请求",要过授权池、限速、只读三道闸;
   这里取的是使用者自己填的下载地址,属于依赖获取。但同样限制协议、限制大小、留审计 ——
   一个能任意读本地文件或拉超大响应的"导入"按钮,本身就是个洞。 */
int net_get_text(const char *url, char **out, size_t *out_len, char *err, size_t errcap) {
  if (out) *out = NULL;
  if (out_len) *out_len = 0;
  if (err && errcap) err[0] = 0;
  if (!url || !*url) {
    if (err) snprintf(err, errcap, "缺少地址");
    return -1;
  }
  if (!str_startswith(url, "http://") && !str_startswith(url, "https://")) {
    if (err) snprintf(err, errcap, "只接受 http:// 或 https:// 地址");
    return -1;
  }
  if (!g_session) net_init();
  if (!g_session) {
    if (err) snprintf(err, errcap, "WinHTTP 未初始化");
    return -1;
  }

  wchar_t whost[256], wpath[2048];
  int https = 0;
  INTERNET_PORT port = 0;
  parse_url(url, whost, 256, wpath, 2048, &https, &port);

  int rc = -1;
  HINTERNET conn = WinHttpConnect(g_session, whost, port, 0);
  if (!conn) {
    if (err) snprintf(err, errcap, "连接失败");
  } else {
    HINTERNET req = WinHttpOpenRequest(conn, L"GET", wpath, NULL,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       https ? WINHTTP_FLAG_SECURE : 0);
    if (!req) {
      if (err) snprintf(err, errcap, "创建请求失败");
    } else {
      DWORD conn_to = 8000, recv_to = 20000;
      WinHttpSetOption(req, WINHTTP_OPTION_CONNECT_TIMEOUT, &conn_to, sizeof(conn_to));
      WinHttpSetOption(req, WINHTTP_OPTION_RECEIVE_TIMEOUT, &recv_to, sizeof(recv_to));
      if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0) ||
          !WinHttpReceiveResponse(req, NULL)) {
        if (err) snprintf(err, errcap, "下载失败(err=%lu)", GetLastError());
      } else {
        DWORD status = 0, slen = sizeof(status);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &slen, WINHTTP_NO_HEADER_INDEX);
        if (status != 200) {
          if (err) snprintf(err, errcap, "服务器返回 HTTP %lu", status);
        } else {
          buf_t acc;
          buf_init(&acc);
          DWORD avail = 0;
          int too_big = 0;
          while (WinHttpQueryDataAvailable(req, &avail) && avail > 0) {
            if (acc.len > 512 * 1024) { too_big = 1; break; }
            char *chunk = (char *)xmalloc(avail + 1);
            DWORD got = 0;
            if (!WinHttpReadData(req, chunk, avail, &got) || got == 0) { free(chunk); break; }
            chunk[got] = 0;
            buf_putn(&acc, chunk, got);
            free(chunk);
          }
          if (too_big) {
            if (err) snprintf(err, errcap, "文件超过 512KB,不像是一份技能/工具定义");
            buf_free(&acc);
          } else {
            *out = buf_take(&acc);
            if (out_len) *out_len = *out ? strlen(*out) : 0;
            rc = 0;
          }
        }
      }
      WinHttpCloseHandle(req);
    }
    WinHttpCloseHandle(conn);
  }
  {
    buf_t d;
    buf_init(&d);
    buf_printf(&d, "GET %s%s%s", rc == 0 ? "ok" : "fail",
               rc == 0 ? "" : " ", rc == 0 ? "" : (err ? err : ""));
    net_audit("import", url, rc == 0 ? 1 : 0, d.data, NULL);
    buf_free(&d);
  }
  return rc;
}

/* 告警投递:只发到使用者自己配的 webhook(rules.json 的 alerts.webhook),
   与"巡检目标"无关,因此不参与授权池判定;带 Bearer 令牌可选。 */
void net_webhook_post(const char *url, const char *token, const char *body,
                      http_resp_t *resp) {
  buf_t hdrs;
  buf_init(&hdrs);
  buf_puts(&hdrs, "Content-Type: application/json\r\n");
  if (token && token[0]) buf_printf(&hdrs, "Authorization: Bearer %s\r\n", token);
  post_json_ex(url, hdrs.data, 15000, body, NULL, NULL, resp, "notify");
  buf_free(&hdrs);
}

/* ================= 给工具层的取数通道 =================
   工具不直接碰 WinHTTP,只拿到这个回调 —— 这样"授权/限速/审计"就不可能被绕过。 */
static int io_fetch(void *ud, const char *url, const char *method,
                    int *status, char **body, size_t *body_len, char **err) {
  (void)ud;
  http_resp_t r;
  net_request(url, method, NULL, NULL, 0, &r);
  if (status) *status = r.status;
  if (r.error) {
    if (err) *err = xstrdup(r.error);
    if (body) *body = NULL;
    if (body_len) *body_len = 0;
    http_resp_free(&r);
    return -1;
  }
  if (body) *body = r.body;                  /* 所有权交给调用方 */
  else free(r.body);
  if (body_len) *body_len = r.body_len;
  if (err) *err = NULL;
  free(r.error);
  return 0;
}

/* 完整版取数:额外把响应头交出去(弱配置检查要用) */
static int io_fetch_ex(void *ud, const char *url, const char *method, int *status,
                       char **headers, char **body, size_t *body_len, char **err) {
  (void)ud;
  http_resp_t r;
  net_request(url, method, NULL, NULL, 0, &r);
  if (status) *status = r.status;
  if (r.error) {
    if (err) *err = xstrdup(r.error);
    if (headers) *headers = NULL;
    if (body) *body = NULL;
    if (body_len) *body_len = 0;
    http_resp_free(&r);
    return -1;
  }
  if (headers) *headers = r.headers; else free(r.headers);
  if (body) *body = r.body; else free(r.body);
  if (body_len) *body_len = r.body_len;
  if (err) *err = NULL;
  free(r.error);
  return 0;
}

tools_io_t *net_io_impl(void) {
  static tools_io_t io;
  io.fetch = io_fetch;
  io.fetch_ex = io_fetch_ex;
  io.userdata = NULL;
  return &io;
}

void *net_io(void) { return net_io_impl(); }
