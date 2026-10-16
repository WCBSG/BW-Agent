/* ui.c —— 界面宿主的三级降级实现。
 *
 * 探测顺序(可用性优先):
 *   webview  内嵌 WebView2 控件
 *   app      系统 Edge/Chrome 的 --app 应用窗口
 *   browser  系统默认浏览器
 *
 * 环境变量 UI_MODE 可强制指定(auto 为默认),方便答辩时按现场环境切换。
 */
#include "ui.h"

#include "common.h"
#include "http.h"

/* 这两个必须先有 windows.h(common.h 里已经含了)再含 */
#include <shellapi.h>
#include <tlhelp32.h>

static PROCESS_INFORMATION g_pi;
static int g_have_proc = 0;
static char g_mode[32] = "auto";

const char *ui_mode_name(void) { return g_mode; }

/* ---------- 找 Edge / Chrome ---------- */
static int file_exists_w(const wchar_t *p) {
  DWORD a = GetFileAttributesW(p);
  return (a != INVALID_FILE_ATTRIBUTES) && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static int find_chromium(char *out, size_t cap) {
  const char *cands[] = {
      "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
      "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
      "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
      NULL};
  for (int i = 0; cands[i]; i++) {
    wchar_t *w = u8_to_w(cands[i]);
    int ok = w && file_exists_w(w);
    free(w);
    if (ok) {
      snprintf(out, cap, "%s", cands[i]);
      return 1;
    }
  }
  /* 兜底:注册表里找 App Paths */
  HKEY k;
  const char *keys[] = {
      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe",
      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe", NULL};
  for (int i = 0; keys[i]; i++) {
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keys[i], 0, KEY_READ, &k) == ERROR_SUCCESS) {
      char v[1024];
      DWORD sz = sizeof(v), type = 0;
      if (RegQueryValueExA(k, NULL, NULL, &type, (LPBYTE)v, &sz) == ERROR_SUCCESS) {
        RegCloseKey(k);
        snprintf(out, cap, "%s", v);
        return 1;
      }
      RegCloseKey(k);
    }
  }
  return 0;
}

/* ---------- 内嵌 WebView2 ---------- */
/* 内嵌模式的完整实现见 exp/probe.c(受控实验)。
   这里保留开关:能用的机器上设 UI_MODE=webview 即可切回内嵌。
   之所以不默认走内嵌:本机实测 browser 进程在"该创建 renderer 那一瞬"退出,
   窗口会停在纯白。降到 --app 后界面正常可用。 */
static int try_webview(int port) {
  (void)port;
  return 0;   /* 见 ui.h 注释:本机不可用,一律走降级 */
}

/* ---------- --app 应用窗口 ---------- */

/* 递归删目录(尽力而为:失败就留着,不影响功能) */
static void remove_tree(const char *dir) {
  char pattern[MAX_PATH * 2];
  snprintf(pattern, sizeof(pattern), "%s\\*", dir);
  wchar_t *wpat = u8_to_w(pattern);
  if (!wpat) return;
  WIN32_FIND_DATAW fd;
  HANDLE h = FindFirstFileW(wpat, &fd);
  free(wpat);
  if (h != INVALID_HANDLE_VALUE) {
    do {
      if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
      char *name8 = w_to_u8(fd.cFileName);
      char child[MAX_PATH * 2];
      snprintf(child, sizeof(child), "%s\\%s", dir, name8 ? name8 : "");
      free(name8);
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        remove_tree(child);
      } else {
        wchar_t *wfile = u8_to_w(child);
        if (wfile) { DeleteFileW(wfile); free(wfile); }
      }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
  }
  wchar_t *wdir = u8_to_w(dir);
  if (wdir) { RemoveDirectoryW(wdir); free(wdir); }
}

/* 早期版本把浏览器用户目录建在程序旁边(程序目录可能是只读的,而且不该在那儿留垃圾),
   现在挪到用户数据目录下;遇到遗留的那份顺手清掉。 */
static void clean_legacy_profile(void) {
  char legacy[MAX_PATH * 2];
  snprintf(legacy, sizeof(legacy), "%sui-profile", app_dir());
  wchar_t *w = u8_to_w(legacy);
  if (!w) return;
  DWORD attr = GetFileAttributesW(w);
  free(w);
  if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) return;
  remove_tree(legacy);
  log_info("已清理程序旁边遗留的 ui-profile(浏览器数据现在放在用户数据目录下)");
}

/* 我们自己拉起来的那个界面窗口被关掉时,服务也跟着收摊 ——
   双击运行的程序不该在窗口关掉之后还在后台占着端口。
   (--debug 调试时除外:那时窗口只是看板,见 ui_set_stop_on_close) */
static int g_stop_on_close = 1;

void ui_set_stop_on_close(int on) { g_stop_on_close = on ? 1 : 0; }

static DWORD WINAPI watch_thread(LPVOID param) {
  HANDLE h = (HANDLE)param;
  WaitForSingleObject(h, INFINITE);
  if (!g_stop_on_close) {
    log_info("界面窗口已关闭(--debug:服务继续运行,界面地址仍然可用;关掉命令行窗口或按 Ctrl+C 结束)");
    return 0;
  }
  log_info("界面窗口已关闭,服务随之停止");
  http_stop();
  return 0;
}

static void watch_window_close(HANDLE proc) {
  if (!proc) return;
  HANDLE th = CreateThread(NULL, 0, watch_thread, (LPVOID)proc, 0, NULL);
  if (th) CloseHandle(th);
}

/* 这个端口上真的有人在听吗?—— 只有确认了才去开窗口。
   为什么要单独探一下:端口被占时会换端口重试,而上一轮的等待线程可能刚醒过来,
   拿"服务在跑"就开窗口,结果指向的是一个没人听的旧端口(白屏)。 */
static int port_alive(int port) {
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) return 0;
  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons((u_short)port);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  u_long nb = 1;
  ioctlsocket(s, FIONBIO, &nb);
  int ok = 0;
  if (connect(s, (struct sockaddr *)&a, sizeof(a)) == 0) {
    ok = 1;
  } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
    fd_set wr;
    FD_ZERO(&wr);
    FD_SET(s, &wr);
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (select(0, NULL, &wr, NULL, &tv) > 0) {
      int err = 0, elen = sizeof(err);
      getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &elen);
      ok = (err == 0);
    }
  }
  closesocket(s);
  return ok;
}

static int wait_service_ready(int port, int timeout_ms) {
  for (int waited = 0; waited < timeout_ms; waited += 50) {
    if (http_is_running() && port_alive(port)) return 1;
    Sleep(50);
  }
  return 0;
}

static int launch_app_window(const char *exe, int port) {
  char url[128];
  snprintf(url, sizeof(url), "http://127.0.0.1:%d/", port);

  /* 浏览器的用户数据目录放到用户数据目录下(默认 %USERPROFILE%\.bw_agent\ui-profile):
     程序目录可能不可写(U 盘只读、Program Files、网络共享),而且不该在程序旁边留垃圾。 */
  clean_legacy_profile();
  char profile[MAX_PATH * 2];
  app_data_path(profile, sizeof(profile), "ui-profile");
  ensure_dir(profile);

  buf_t cmd;
  buf_init(&cmd);
  buf_puts(&cmd, "\"");
  buf_puts(&cmd, exe);
  buf_puts(&cmd, "\" --app=");
  buf_puts(&cmd, url);
  buf_puts(&cmd, " --user-data-dir=\"");
  buf_puts(&cmd, profile);
  buf_puts(&cmd, "\" --no-first-run --no-default-browser-check");
  buf_puts(&cmd, " --disable-features=msEdgeSidebarV2 --window-size=1280,860");

  wchar_t *wcmd = u8_to_w(cmd.data);
  buf_free(&cmd);
  if (!wcmd) return 0;

  STARTUPINFOW si;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(&g_pi, 0, sizeof(g_pi));
  /* CREATE_NEW_PROCESS_GROUP:将来只关我们自己开的这一个窗口 */
  BOOL ok = CreateProcessW(NULL, wcmd, NULL, NULL, FALSE,
                           CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &g_pi);
  free(wcmd);
  if (ok) {
    g_have_proc = 1;
    snprintf(g_mode, sizeof(g_mode), "app");
    log_info("界面已用 --app 应用窗口打开(%s)", exe);
    watch_window_close(g_pi.hProcess);      /* 窗口关掉 → 服务停掉 */
    return 1;
  }
  log_warn("--app 启动失败(code=%lu)", (unsigned long)GetLastError());
  return 0;
}

/* ---------- 默认浏览器 ---------- */
static int launch_shell(int port) {
  char url[128];
  snprintf(url, sizeof(url), "http://127.0.0.1:%d/", port);
  HINSTANCE h = ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
  if ((INT_PTR)h > 32) {
    snprintf(g_mode, sizeof(g_mode), "browser");
    log_info("界面已用系统默认浏览器打开");
    return 1;
  }
  return 0;
}

/* ---------- 打开界面的线程 ---------- */
static DWORD WINAPI open_thread(LPVOID param) {
  int port = (int)(INT_PTR)param;
  const char *force = getenv("UI_MODE");
  int want_webview = force && str_ieq(force, "webview");
  int want_app = force && str_ieq(force, "app");
  int want_browser = force && str_ieq(force, "browser");
  /* UI_MODE=off/none:只起服务不开窗口(定时任务、无人值守、自动化测试用) */
  if (force && (str_ieq(force, "off") || str_ieq(force, "none"))) {
    snprintf(g_mode, sizeof(g_mode), "off");
    log_info("界面窗口已按要求跳过(UI_MODE=%s),界面地址仍然可用", force);
    return 0;
  }

  /* 等服务真的开始 listen 再开窗口,否则首屏会打不开;
     一直没起来(端口被占等)就别开窗口 —— 免得开一个连不上的白屏 */
  if (!wait_service_ready(port, 3000)) {
    log_warn("服务没有起来(端口 %d),不再打开界面窗口", port);
    return 0;
  }

  if (want_webview && try_webview(port)) return 0;
  if (!want_webview && !want_app && !want_browser) {
    /* auto:先试内嵌,不行就 --app */
    if (try_webview(port)) return 0;
  }

  char exe[MAX_PATH];
  if (!want_browser && find_chromium(exe, sizeof(exe))) {
    if (launch_app_window(exe, port)) return 0;
  }
  launch_shell(port);
  return 0;
}

void ui_open_url_async(int port) {
  HANDLE th = CreateThread(NULL, 0, open_thread, (LPVOID)(INT_PTR)port, 0, NULL);
  if (th) CloseHandle(th);
}

void ui_close(void) {
  if (!g_have_proc) return;
  /* 只关我们自己拉起来的那棵树,用户原本开着的浏览器不受影响 */
  DWORD pid = g_pi.dwProcessId;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32W pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);
    /* 子进程先关 */
    for (int pass = 0; pass < 2; pass++) {
      if (!Process32FirstW(snap, &pe)) break;
      do {
        if (pe.th32ParentProcessID == pid) {
          HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
          if (h) { TerminateProcess(h, 0); CloseHandle(h); }
        }
      } while (Process32NextW(snap, &pe));
      if (pass == 0) {
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (h) { TerminateProcess(h, 0); CloseHandle(h); }
      }
    }
    CloseHandle(snap);
  }
  g_have_proc = 0;
}
