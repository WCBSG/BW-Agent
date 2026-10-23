/* instance.cpp —— 单实例:同数据目录只留一个服务进程。
 *
 * 两层判据,各管一件事:
 *   · 命名互斥量(Local\BwAgent-<数据目录哈希>)—— "这台的这份数据有没有人在跑"。
 *     进程退出或被强杀时系统自动释放,不会留下打不开的死锁。
 *   · 数据目录下的 instance.json —— "它在哪个端口"。端口会因占用而顺延,
 *     所以不能硬编码 8765。
 *
 * 端口只信探活:首页里带 bw-token 才算我们自己(见 serve.cpp 的首页模板),
 * 光"端口能连上"说明不了什么 —— 8765 上很可能是别的程序。
 *
 * 为什么按数据目录区分:BW_AGENT_HOME 指到别处就是一份独立数据,
 * 演示/测试要能同时开两份;而同一个数据目录同时开两份,SQLite 和
 * audit.jsonl 会互相踩。
 */
#include <winsock2.h>
#include <ws2tcpip.h>

#include "instance.h"

#include "common.h"
#include "json.h"

#include <ctime>

static HANDLE g_mutex = NULL;
static HANDLE g_map = NULL;
static int g_owned = 0;
static char g_note[320] = "";

int instance_owned(void) { return g_owned; }
const char *instance_note(void) { return g_note; }

/* 数据目录哈希:同一份数据 → 同一个互斥量名。大小写不敏感(Windows 路径),
   并且忽略结尾的反斜杠 —— BW_AGENT_HOME 写 `D:\x\.bw_agent` 还是带尾斜杠,
   都必须是同一把锁。 */
static unsigned fnv1a(const char *s) {
  unsigned h = 2166136261u;
  for (const unsigned char *p = (const unsigned char *)s; s && *p; p++) {
    unsigned c = *p;
    if (c >= 'A' && c <= 'Z') c += 32;
    h ^= c;
    h *= 16777619u;
  }
  return h;
}

static unsigned dir_key(void) {
  char buf[MAX_PATH * 2];
  snprintf(buf, sizeof(buf), "%s", app_data_dir());
  size_t n = strlen(buf);
  while (n > 0 && (buf[n - 1] == '\\' || buf[n - 1] == '/')) buf[--n] = 0;
  return fnv1a(buf);
}

/* 共享内存里那 4 个字节:端口。
   为什么不只靠 instance.json:数据目录是用户可改的(BW_AGENT_HOME),
   路径里一旦有中文,写文件会受编码影响;而内核对象只认名字,
   进程一退就自动消失,连"残留脏文件"这种情况都没有。 */
static void port_map_name(wchar_t *out, size_t cap) {
  swprintf(out, cap, L"Local\\BwAgent-Port-%08x", dir_key());
}

/* WSA 的引用计数是配对的:这里 Startup 一次、离开作用域 Cleanup 一次。
   单实例检查发生在 net_init 之前,不能指望别人已经初始化过。 */
struct wsa_guard {
  int ok;
  wsa_guard(void) {
    WSADATA w;
    ok = (WSAStartup(MAKEWORD(2, 2), &w) == 0);
  }
  ~wsa_guard(void) {
    if (ok) WSACleanup();
  }
};

static const char *instance_file(char *out, size_t cap) {
  return app_data_path(out, cap, "instance.json");
}

static int port_free(int port) {
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) return 0;
  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons((u_short)port);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  int ok = (bind(s, (struct sockaddr *)&a, sizeof(a)) == 0);
  closesocket(s);
  return ok;
}

/* 这个端口上是不是我们自己:连上去要一份首页,认里头的 bw-token。
   只读前 4KB —— 首页是静态模板,令牌写在 <meta> 里,一定落在这段。 */
static int probe_ours(int port) {
  if (port <= 0 || port > 65535) return 0;
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) return 0;

  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons((u_short)port);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  u_long nb = 1;
  ioctlsocket(s, FIONBIO, &nb);
  int connected = 0;
  if (connect(s, (struct sockaddr *)&a, sizeof(a)) == 0) {
    connected = 1;
  } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
    fd_set wr;
    FD_ZERO(&wr);
    FD_SET(s, &wr);
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 400 * 1000;
    if (select(0, NULL, &wr, NULL, &tv) > 0) {
      int err = 0, elen = sizeof(err);
      getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &elen);
      connected = (err == 0);
    }
  }
  if (!connected) {
    closesocket(s);
    return 0;
  }
  /* 连接完成之后必须切回阻塞模式:非阻塞 socket 上 recv 会立刻返回
     WSAEWOULDBLOCK,SO_RCVTIMEO 也不生效 —— 会误判成"这不是我们的端口"。 */
  nb = 0;
  ioctlsocket(s, FIONBIO, &nb);

  const char *req = "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
  send(s, req, (int)strlen(req), 0);

  DWORD tv_ms = 900;
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_ms, sizeof(tv_ms));
  char buf[4096];
  int total = 0;
  while (total < (int)sizeof(buf) - 1) {
    int n = recv(s, buf + total, (int)sizeof(buf) - 1 - total, 0);
    if (n <= 0) break;
    total += n;
    buf[total] = 0;                 /* 边收边判,别在没结尾的缓冲上 strstr */
    if (strstr(buf, "bw-token")) break;
  }
  buf[total] = 0;
  closesocket(s);
  return total > 0 && strstr(buf, "bw-token") != NULL;
}

static int read_mapped_port(void) {
  wchar_t name[96];
  port_map_name(name, sizeof(name) / sizeof(name[0]));
  HANDLE m = OpenFileMappingW(FILE_MAP_READ, FALSE, name);
  if (!m) return 0;
  int *v = (int *)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
  int port = 0;
  if (v) {
    port = *v;
    UnmapViewOfFile(v);
  }
  CloseHandle(m);
  return (port > 0 && port <= 65535) ? port : 0;
}

static int read_published_port(void) {
  char path[MAX_PATH * 2];
  instance_file(path, sizeof(path));
  size_t len = 0;
  char *text = file_read_all(path, &len);
  if (!text) return 0;
  json_t *j = json_parse(text);
  free(text);
  if (!j) return 0;
  int port = (int)j_n(j, "port", 0);
  json_free(j);
  return (port > 0 && port <= 65535) ? port : 0;
}

int instance_acquire(void) {
  if (g_owned) return 1;
  wchar_t name[96];
  swprintf(name, 96, L"Local\\BwAgent-%08x", dir_key());
  HANDLE h = CreateMutexW(NULL, FALSE, name);
  if (!h) {
    /* 建不出来就按"没人在跑"处理:宁可多开,也不能让人启动不了 */
    snprintf(g_note, sizeof(g_note), "单实例锁创建失败(code=%lu),本次不限制",
             (unsigned long)GetLastError());
    return 1;
  }
  if (GetLastError() == ERROR_ALREADY_EXISTS) {
    CloseHandle(h);
    snprintf(g_note, sizeof(g_note), "数据目录 %s 下已有实例", app_data_dir());
    return 0;
  }
  g_mutex = h;
  g_owned = 1;
  atexit(instance_unpublish);       /* 正常退出(含 Ctrl+C)时清掉端口记录 */
  snprintf(g_note, sizeof(g_note), "已取得单实例锁");
  return 1;
}

void instance_publish(int port) {
  if (!g_owned || port <= 0 || port > 65535) return;
  wsa_guard wsa;
  /* 端口还被别人占着 → 这次启动会失败并换端口,不值得写进去 */
  if (!port_free(port)) return;

  /* 主通道:命名共享内存(4 字节端口)。进程退出即消失,不受路径编码影响。 */
  if (!g_map) {
    wchar_t name[96];
    port_map_name(name, sizeof(name) / sizeof(name[0]));
    g_map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 64, name);
  }
  if (g_map) {
    int *v = (int *)MapViewOfFile(g_map, FILE_MAP_WRITE, 0, 0, 0);
    if (v) {
      *v = port;
      UnmapViewOfFile(v);
    }
  }

  /* 附一份 instance.json:方便人/脚本直接看当前实例在哪个端口。写不出来不影响功能。 */
  char path[MAX_PATH * 2];
  instance_file(path, sizeof(path));
  json_t *o = j_obj();
  j_set_num(o, "pid", (double)GetCurrentProcessId());
  j_set_num(o, "port", port);
  j_set_str(o, "exe", app_exe());
  j_set_num(o, "startedAt", (double)time(NULL));
  j_set_str(o, "note", "程序自动生成:再次启动时据此找到运行中的界面。删掉也不影响使用。");
  char *text = json_dump_pretty(o);
  if (text) {
    file_write_all(path, text, strlen(text));
    free(text);
  }
  json_free(o);
}

void instance_unpublish(void) {
  if (!g_owned) return;
  /* 共享内存里的端口也清 0:否则下次启动可能拿着一个已经没人听的端口去等 */
  if (g_map) {
    int *v = (int *)MapViewOfFile(g_map, FILE_MAP_WRITE, 0, 0, 0);
    if (v) {
      *v = 0;
      UnmapViewOfFile(v);
    }
  }
  char path[MAX_PATH * 2];
  instance_file(path, sizeof(path));
  wchar_t *w = u8_to_w(path);
  if (w) {
    DeleteFileW(w);
    free(w);
  }
}

int instance_running_port(int wait_ms) {
  wsa_guard wsa;
  int port = read_mapped_port();
  if (port > 0 && probe_ours(port)) return port;
  port = read_published_port();
  if (port > 0 && probe_ours(port)) return port;

  /* 刚启动的那一两秒里端口可能还没开始监听:等一会儿再判 */
  DWORD deadline = GetTickCount() + (DWORD)(wait_ms > 0 ? wait_ms : 0);
  while ((long)(GetTickCount() - deadline) < 0) {
    Sleep(120);
    port = read_mapped_port();
    if (port > 0 && probe_ours(port)) return port;
    port = read_published_port();
    if (port > 0 && probe_ours(port)) return port;
  }

  /* 记录丢了(被人删了 / 上一版没写过):按默认端口段扫一遍,只认自家首页 */
  for (int p = 8765; p <= 8775; p++) {
    if (probe_ours(p)) return p;
  }
  return 0;
}
