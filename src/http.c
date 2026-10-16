/* http.c —— 内置本地 HTTP + SSE 服务的实现。
 * 只用 winsock2,不引第三方库。连接按需起线程:SSE 是长连接,
 * 不能让它把其它请求(界面要取 html/css/js)堵在门外。
 */
#include "http.h"

#include <ctype.h>
#include <stdio.h>

static SOCKET g_listen = INVALID_SOCKET;
static volatile LONG g_stop = 0;
static int g_running = 0;
static char g_err[256] = "";
static struct sockaddr_in g_bound;

/* ================= 小工具 ================= */

static int send_all(SOCKET s, const char *data, size_t len) {
  size_t sent = 0;
  while (sent < len) {
    int n = send(s, data + sent, (int)(len - sent), 0);
    if (n <= 0) return 0;
    sent += (size_t)n;
  }
  return 1;
}

static int send_str(SOCKET s, const char *data) {
  return send_all(s, data, strlen(data));
}

char *http_url_decode(const char *s) {
  size_t n = strlen(s);
  char *out = (char *)xmalloc(n + 1);
  size_t o = 0;
  for (size_t i = 0; i < n; i++) {
    if (s[i] == '%' && i + 2 < n && isxdigit((unsigned char)s[i + 1]) &&
        isxdigit((unsigned char)s[i + 2])) {
      int hi = s[i + 1] <= '9' ? s[i + 1] - '0' : (s[i + 1] | 32) - 'a' + 10;
      int lo = s[i + 2] <= '9' ? s[i + 2] - '0' : (s[i + 2] | 32) - 'a' + 10;
      out[o++] = (char)((hi << 4) | lo);
      i += 2;
    } else if (s[i] == '+') {
      out[o++] = ' ';
    } else {
      out[o++] = s[i];
    }
  }
  out[o] = 0;
  return out;
}

const char *http_query(const http_req_t *req, const char *key, char *out, size_t cap,
                       const char *def) {
  size_t klen = strlen(key);
  const char *p = req->query;
  while (p && *p) {
    const char *eq = strchr(p, '=');
    const char *amp = strchr(p, '&');
    size_t seg = amp ? (size_t)(amp - p) : strlen(p);
    if (eq && (size_t)(eq - p) == klen && strncmp(p, key, klen) == 0) {
      char raw[1024];
      size_t vlen = seg - klen - 1;
      if (vlen >= sizeof(raw)) vlen = sizeof(raw) - 1;
      memcpy(raw, eq + 1, vlen);
      raw[vlen] = 0;
      char *dec = http_url_decode(raw);
      snprintf(out, cap, "%s", dec);
      free(dec);
      return out;
    }
    if (!amp) break;
    p = amp + 1;
  }
  snprintf(out, cap, "%s", def ? def : "");
  return out;
}

/* ================= 应答 ================= */

static const char *status_text(int code) {
  switch (code) {
    case 200: return "OK";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 500: return "Internal Server Error";
    default:  return "OK";
  }
}

static void send_head(http_res_t *res, int status, const char *ctype, long len) {
  if (res->header_sent) return;
  char h[512];
  int n = snprintf(h, sizeof(h),
                   "HTTP/1.1 %d %s\r\n"
                   "Content-Type: %s\r\n"
                   "Content-Length: %ld\r\n"
                   "Cache-Control: no-store\r\n"
                   "Connection: close\r\n"
                   "\r\n",
                   status, status_text(status), ctype, len);
  if (!send_all(res->sock, h, (size_t)n)) res->aborted = 1;
  res->header_sent = 1;
  res->status = status;
}

void http_res_text(http_res_t *res, int status, const char *ctype, const char *body) {
  size_t n = body ? strlen(body) : 0;
  send_head(res, status, ctype, (long)n);
  if (n && !send_all(res->sock, body, n)) res->aborted = 1;
}

void http_res_bytes(http_res_t *res, int status, const char *ctype, const char *data,
                    size_t len) {
  send_head(res, status, ctype, (long)len);
  if (len && !send_all(res->sock, data, len)) res->aborted = 1;
}

void http_res_json(http_res_t *res, int status, const char *json) {
  http_res_text(res, status, "application/json; charset=utf-8", json);
}

void http_res_404(http_res_t *res) {
  http_res_text(res, 404, "application/json; charset=utf-8",
                "{\"ok\":false,\"error\":\"not found\"}");
}

/* ================= SSE ================= */

int http_sse_begin(http_res_t *res) {
  if (res->header_sent) return !res->aborted;
  const char *h =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/event-stream; charset=utf-8\r\n"
      "Cache-Control: no-cache, no-transform\r\n"
      "Connection: keep-alive\r\n"
      "X-Accel-Buffering: no\r\n"
      "\r\n";
  if (!send_str(res->sock, h)) {
    res->aborted = 1;
    return 0;
  }
  res->header_sent = 1;
  res->status = 200;
  return 1;
}

int http_sse_json(http_res_t *res, const char *json) {
  if (res->aborted) return 0;
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "data: ");
  buf_puts(&b, json ? json : "{}");
  buf_puts(&b, "\n\n");
  int ok = send_all(res->sock, b.data, b.len);
  buf_free(&b);
  if (!ok) {
    res->aborted = 1;
    return 0;
  }
  return 1;
}

/* ================= 请求解析 ================= */

/* 读一行(到 \r\n),返回长度;超时/断开返回 -1 */
static int recv_line(SOCKET s, char *out, size_t cap) {
  size_t o = 0;
  while (o + 1 < cap) {
    char c;
    int n = recv(s, &c, 1, 0);
    if (n <= 0) return -1;
    if (c == '\n') {
      if (o && out[o - 1] == '\r') o--;
      out[o] = 0;
      return (int)o;
    }
    out[o++] = c;
  }
  out[o] = 0;
  return (int)o;
}

/* 把请求填进 req;返回 0 失败(对端断开或格式非法) */
static int parse_request(SOCKET s, http_req_t *req) {
  char line[2048];
  memset(req, 0, sizeof(*req));
  req->keep_alive = 1;

  if (recv_line(s, line, sizeof(line)) < 0) return 0;
  /* METHOD SP TARGET SP VERSION */
  char *sp1 = strchr(line, ' ');
  if (!sp1) return 0;
  *sp1 = 0;
  snprintf(req->method, sizeof(req->method), "%s", line);
  char *target = sp1 + 1;
  char *sp2 = strchr(target, ' ');
  if (sp2) *sp2 = 0;

  /* 剥掉查询串 */
  char *qm = strchr(target, '?');
  if (qm) {
    snprintf(req->query, sizeof(req->query), "%s", qm + 1);
    *qm = 0;
  }
  snprintf(req->raw_path, sizeof(req->raw_path), "%s", target);
  char *dec = http_url_decode(target);
  snprintf(req->path, sizeof(req->path), "%s", dec);
  free(dec);

  long content_len = 0;
  for (;;) {
    if (recv_line(s, line, sizeof(line)) < 0) return 0;
    if (!line[0]) break;   /* 空行 = 头结束 */
    if (str_icontains(line, "content-length:")) {
      const char *v = strchr(line, ':');
      if (v) content_len = strtol(v + 1, NULL, 10);
    } else if (str_icontains(line, "connection: close")) {
      req->keep_alive = 0;
    }
  }

  if (content_len > 0) {
    if (content_len > 4 * 1024 * 1024) return 0;   /* 本地界面用不到这么大的体 */
    req->body = (char *)xmalloc((size_t)content_len + 1);
    size_t got = 0;
    while (got < (size_t)content_len) {
      int n = recv(s, req->body + got, (int)(content_len - got), 0);
      if (n <= 0) {
        free(req->body);
        req->body = NULL;
        return 0;
      }
      got += (size_t)n;
    }
    req->body[got] = 0;
    req->body_len = got;
  }
  return 1;
}

/* ================= 连接处理 ================= */

typedef struct {
  SOCKET sock;
  http_handler_t handler;
  void *ud;
} conn_ctx_t;

static DWORD WINAPI conn_thread(LPVOID param) {
  conn_ctx_t *ctx = (conn_ctx_t *)param;
  SOCKET s = ctx->sock;
  http_handler_t handler = ctx->handler;
  void *ud = ctx->ud;
  free(ctx);

  DWORD tv = 30000;
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
  int one = 1;
  setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));

  http_req_t req;
  if (parse_request(s, &req)) {
    http_res_t res;
    memset(&res, 0, sizeof(res));
    res.sock = s;
    handler(&req, &res, ud);
    if (req.body) free(req.body);
  }

  /* 关掉发送方向,让对端立刻知道结束了(SSE 尤其重要) */
  shutdown(s, SD_SEND);
  closesocket(s);
  return 0;
}

/* ================= 服务 ================= */

int http_startup(void) {
  WSADATA wsa;
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    snprintf(g_err, sizeof(g_err), "WSAStartup 失败");
    return 0;
  }
  return 1;
}

void http_shutdown(void) {
  http_stop();
  WSACleanup();
}

void http_stop(void) {
  InterlockedExchange(&g_stop, 1);
  if (g_listen != INVALID_SOCKET) {
    closesocket(g_listen);
    g_listen = INVALID_SOCKET;
  }
  g_running = 0;
}

int http_is_running(void) { return g_running; }
const char *http_last_error(void) { return g_err; }

int http_serve(const char *bind_ip, int port, http_handler_t handler, void *ud) {
  if (g_listen != INVALID_SOCKET) {
    snprintf(g_err, sizeof(g_err), "服务已在运行");
    return -1;
  }
  InterlockedExchange(&g_stop, 0);

  g_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (g_listen == INVALID_SOCKET) {
    snprintf(g_err, sizeof(g_err), "创建 socket 失败(code=%d)", WSAGetLastError());
    return -1;
  }
  int one = 1;
  setsockopt(g_listen, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));

  memset(&g_bound, 0, sizeof(g_bound));
  g_bound.sin_family = AF_INET;
  g_bound.sin_port = htons((u_short)port);
  const char *ip = (bind_ip && *bind_ip) ? bind_ip : "127.0.0.1";
  /* 只绑回环:本工具不该被同网段的其他机器访问到 —— 安全边界的第一道 */
  if (strcmp(ip, "127.0.0.1") == 0) {
    g_bound.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  } else if (InetPtonA(AF_INET, ip, &g_bound.sin_addr) != 1) {
    snprintf(g_err, sizeof(g_err), "绑定地址非法:%s", ip);
    closesocket(g_listen);
    g_listen = INVALID_SOCKET;
    return -1;
  }

  if (bind(g_listen, (struct sockaddr *)&g_bound, sizeof(g_bound)) != 0) {
    int e = WSAGetLastError();
    snprintf(g_err, sizeof(g_err),
             "端口 %d 绑定失败(code=%d)%s", port, e,
             (e == WSAEADDRINUSE) ? "(端口已被占用)" : "");
    closesocket(g_listen);
    g_listen = INVALID_SOCKET;
    return -1;
  }
  if (listen(g_listen, 32) != 0) {
    snprintf(g_err, sizeof(g_err), "listen 失败(code=%d)", WSAGetLastError());
    closesocket(g_listen);
    g_listen = INVALID_SOCKET;
    return -1;
  }

  g_running = 1;
  g_err[0] = 0;
  log_info("HTTP 服务已监听 http://%s:%d/", ip, port);

  while (!g_stop) {
    struct sockaddr_in cli;
    int clen = sizeof(cli);
    SOCKET c = accept(g_listen, (struct sockaddr *)&cli, &clen);
    if (c == INVALID_SOCKET) {
      if (g_stop) break;
      continue;
    }
    conn_ctx_t *ctx = (conn_ctx_t *)xmalloc(sizeof(conn_ctx_t));
    ctx->sock = c;
    ctx->handler = handler;
    ctx->ud = ud;
    HANDLE th = CreateThread(NULL, 0, conn_thread, ctx, 0, NULL);
    if (th) {
      CloseHandle(th);
    } else {
      closesocket(c);
      free(ctx);
    }
  }

  g_running = 0;
  if (g_listen != INVALID_SOCKET) {
    closesocket(g_listen);
    g_listen = INVALID_SOCKET;
  }
  return 0;
}
