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

static char g_task_id[64] = {0};
static char **g_domains = NULL;
static int g_domain_count = 0;

static char g_audit_path[MAX_PATH * 2] = {0};
static char g_target_base[512] = {0};
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
  if (g_domains) { str_free_list(g_domains, g_domain_count); g_domains = NULL; g_domain_count = 0; }
}

void net_set_readonly(int on) { g_readonly = on ? 1 : 0; }

void net_set_scope(const char *task_id, const char **domains, int count) {
  net_lock_init();
  EnterCriticalSection(&g_net_lock);
  if (g_domains) { str_free_list(g_domains, g_domain_count); g_domains = NULL; }
  g_domain_count = 0;
  if (domains && count > 0) {
    g_domains = (char **)xcalloc((size_t)count, sizeof(char *));
    for (int i = 0; i < count; i++) g_domains[i] = xstrdup(domains[i]);
    g_domain_count = count;
  }
  strncpy_s(g_task_id, sizeof(g_task_id), task_id ? task_id : "", _TRUNCATE);
  LeaveCriticalSection(&g_net_lock);
}

void net_set_audit_path(const char *path) {
  strncpy_s(g_audit_path, sizeof(g_audit_path), path ? path : "", _TRUNCATE);
}

void net_set_rate_limit(double qps) { g_qps = (qps > 0) ? qps : 2.0; }

void net_set_target_base(const char *base) {
  strncpy_s(g_target_base, sizeof(g_target_base), base ? base : "", _TRUNCATE);
  char *t = str_trim(g_target_base);
  if (t != g_target_base) memmove(g_target_base, t, strlen(t) + 1);
}

/* 把 URL 的"协议+端口"换成 target base 的(仅当主机名相同)。
   为什么需要:演示靶站跑在 http://127.0.0.1:8899,而用户/模型只会说
   "127.0.0.1" —— 不对齐就会去请求 443 端口,然后误判成"站点不可达"。 */
void net_align_url(const char *url, char *out, size_t cap) {
  if (!g_target_base[0] || !url || !*url) {
    snprintf(out, cap, "%s", url ? url : "");
    return;
  }
  char base_host[256], url_host[256];
  net_host_of(g_target_base, base_host, sizeof(base_host));
  net_host_of(url, url_host, sizeof(url_host));
  if (!str_ieq(base_host, url_host)) {
    snprintf(out, cap, "%s", url);
    return;
  }
  /* target base 的"协议 + 主机 + 端口"这一段(authority),原 URL 只保留路径与查询 */
  const char *scheme_end = strstr(g_target_base, "://");
  size_t scheme_len = scheme_end ? (size_t)(scheme_end - g_target_base) + 3 : 0;
  const char *auth = g_target_base + scheme_len;
  size_t auth_len = 0;
  while (auth[auth_len] && auth[auth_len] != '/' && auth[auth_len] != '?' &&
         auth[auth_len] != '#') {
    auth_len++;
  }
  /* 原 URL 的路径 */
  const char *path = strstr(url, "://");
  path = path ? strchr(path + 3, '/') : NULL;
  snprintf(out, cap, "%.*s%.*s%s", (int)scheme_len, g_target_base, (int)auth_len, auth,
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

/* 授权域名匹配:精确匹配,或"授权的是子域"(x.cn 授权后可访问 a.x.cn)。
   这是从宽还是从严的取舍:为了演示方便放行子域,但会在审计里如实记录。 */
static int host_allowed(const char *host) {
  if (!host || !*host) return 0;
  for (int i = 0; i < g_domain_count; i++) {
    const char *d = g_domains[i];
    if (str_ieq(host, d)) return 1;
    size_t lh = strlen(host), ld = strlen(d);
    if (lh > ld && str_ieq(host + (lh - ld), d) && host[lh - ld - 1] == '.') return 1;
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
  j_set_str(row, "task_id", g_task_id);
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
  /* 先做地址对齐(演示靶站的协议/端口),再做授权校验 */
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

  /* —— 合规第 1 道:授权校验。不在授权域名内,连请求都不发 —— */
  char host_u8[256];
  net_host_of(url, host_u8, sizeof(host_u8));
  if (g_domain_count > 0 && !host_allowed(host_u8)) {
    buf_t e;
    buf_init(&e);
    buf_printf(&e, "目标 %s 不在授权域名内", host_u8);
    resp->error = buf_take(&e);
    net_audit("authorize", url, 0, resp->error, NULL);
    log_warn("[合规] 拒绝未授权目标: %s", url);
    return;
  }

  /* —— 合规第 2 道:限速 —— */
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

/* ================= 模型端点专用 POST =================
   为什么要单独一个:恒脑要 appKey/sign 两个自定义头,net_request 的头是固定的。
   它指向的是"我们的依赖",不是被检目标,所以不套被检目标的授权/只读限制;
   但失败同样要留审计 —— 调用不通必须能查。 */
void hn_http_post(const char *url, const char *app_key, const char *sign,
                  const char *body, http_resp_t *resp) {
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
    resp->error = xstrdup("连接模型服务失败");
  } else {
    HINTERNET req = WinHttpOpenRequest(conn, L"POST", wpath, NULL,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       https ? WINHTTP_FLAG_SECURE : 0);
    if (!req) {
      resp->error = xstrdup("创建请求失败");
    } else {
      DWORD timeout = 90000;   /* 模型可能要几十秒,给足 */
      WinHttpSetOption(req, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

      buf_t hdrs;
      buf_init(&hdrs);
      buf_printf(&hdrs, "Content-Type: application/json\r\nappKey: %s\r\nsign: %s\r\n"
                        "ext: child_preview:0;reason:1\r\n",
                 app_key ? app_key : "", sign ? sign : "");

      BOOL ok = WinHttpSendRequest(req, u8_to_w(hdrs.data), (DWORD)-1L,
                                   (LPVOID)body, (DWORD)strlen(body),
                                   (DWORD)strlen(body), 0);
      buf_free(&hdrs);
      if (!ok) {
        buf_t e;
        buf_init(&e);
        buf_printf(&e, "发送失败 (err=%lu)", GetLastError());
        resp->error = buf_take(&e);
      } else if (!WinHttpReceiveResponse(req, NULL)) {
        resp->error = xstrdup("接收响应失败");
      } else {
        DWORD status = 0, len = sizeof(status);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &len, WINHTTP_NO_HEADER_INDEX);
        resp->status = (int)status;
        buf_t acc;
        buf_init(&acc);
        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(req, &avail) && avail > 0) {
          if (acc.len > 8 * 1024 * 1024) break;
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
  {
    buf_t d;
    buf_init(&d);
    buf_printf(&d, "POST %d %dms%s%s", resp->status, resp->ms,
               resp->error ? " err=" : "", resp->error ? resp->error : "");
    net_audit("llm", url, resp->error ? 0 : 1, d.data, NULL);
    buf_free(&d);
  }
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
