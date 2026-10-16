/* WebView2 受控实验 —— 把"窗口遮挡/隐藏导致 renderer 不创建"这个变量彻底排除。
 *
 * 与之前探针的区别(每处都是针对上次没控住的变量):
 *   ① 窗口位置尺寸写死到屏幕中央,显式 WS_VISIBLE,不用 nCmdShow
 *   ② SetWindowPos(HWND_TOP) + SetForegroundWindow + WS_EX_TOPMOST,让遮挡不可能成立
 *   ③ 每 200ms 采样"属于本进程的 WebView2 后代进程数",看它会不会涨
 *   ④ 把窗口可见性(IsWindowVisible / IsIconic / 矩形 / 是否前台)写进日志作客观证据
 *   ⑤ 客户区尺寸为 0 时兜底一个 800x600(0 尺寸同样会让 renderer 不创建)
 *
 * 日志写 probe.log(不用 stdout:重定向管道会拖住 WebView2 的子进程)。 */
#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <tlhelp32.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <WebView2.h>

typedef HRESULT(STDMETHODCALLTYPE *PFN_CreateEnv)(PCWSTR, PCWSTR,
    ICoreWebView2EnvironmentOptions *,
    ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *);

static PFN_CreateEnv pCreateEnv = NULL;
static ICoreWebView2Environment *g_env = NULL;
static ICoreWebView2Controller *g_ctrl = NULL;
static ICoreWebView2 *g_web = NULL;
static HWND g_hwnd = NULL;
static DWORD g_self_pid = 0;
static volatile LONG g_navStart = 0, g_navDone = 0, g_msg = 0, g_failed = 0;
static int g_peak_descendants = 0;

static FILE *g_log = NULL;
static void logline(const char *fmt, ...) {
  if (!g_log) g_log = fopen("probe.log", "w");
  if (!g_log) return;
  va_list ap;
  va_start(ap, fmt);
  vfprintf(g_log, fmt, ap);
  va_end(ap);
  fputc('\n', g_log);
  fflush(g_log);
}

static wchar_t *u8_to_w(const char *s) {
  if (!s) return NULL;
  int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
  wchar_t *w = (wchar_t *)calloc((size_t)n + 1, sizeof(wchar_t));
  if (w) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
  return w;
}

static void w2u(const wchar_t *w, char *out, int cap) {
  out[0] = 0;
  if (w) WideCharToMultiByte(CP_UTF8, 0, w, -1, out, cap, NULL, NULL);
}

/* 探针是独立小程序,不引项目的 common.c —— 自己带一个忽略大小写比较 */
static int same(const char *a, const char *b) {
  if (!a || !b) return a == b;
  return _stricmp(a, b) == 0;
}

/* ---- 手写 COM 回调样板:QI/AddRef/Release 的签名必须与 vtable 完全一致 ---- */
#define DECL_HANDLER(Obj, Iface, Vtbl)                                       \
  typedef struct Obj { Vtbl *lpVtbl; LONG ref; } Obj;                        \
  static HRESULT STDMETHODCALLTYPE Obj##_QI(Iface *t, REFIID r, void **ppv) { \
    if (!ppv) return E_POINTER;                                              \
    if (IsEqualIID(r, &IID_IUnknown)) { *ppv = t; return S_OK; }              \
    *ppv = NULL; return E_NOINTERFACE;                                       \
  }                                                                          \
  static ULONG STDMETHODCALLTYPE Obj##_AddRef(Iface *t) {                     \
    return (ULONG)InterlockedIncrement(&((Obj *)t)->ref);                     \
  }                                                                          \
  static ULONG STDMETHODCALLTYPE Obj##_Release(Iface *t) {                    \
    return (ULONG)InterlockedDecrement(&((Obj *)t)->ref);                     \
  }

/* ---------- 1. 环境 ---------- */
static HRESULT STDMETHODCALLTYPE Env_Invoke(
    ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *,
    HRESULT, ICoreWebView2Environment *);
DECL_HANDLER(EnvObj, ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler,
             ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandlerVtbl)
static ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandlerVtbl g_envVtbl = {
    EnvObj_QI, EnvObj_AddRef, EnvObj_Release, Env_Invoke};
static EnvObj g_envObj = {&g_envVtbl, 1};

/* ---------- 2. 控制器 ---------- */
static HRESULT STDMETHODCALLTYPE Ctrl_Invoke(
    ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *,
    HRESULT, ICoreWebView2Controller *);
DECL_HANDLER(CtrlObj, ICoreWebView2CreateCoreWebView2ControllerCompletedHandler,
             ICoreWebView2CreateCoreWebView2ControllerCompletedHandlerVtbl)
static ICoreWebView2CreateCoreWebView2ControllerCompletedHandlerVtbl g_ctrlVtbl = {
    CtrlObj_QI, CtrlObj_AddRef, CtrlObj_Release, Ctrl_Invoke};
static CtrlObj g_ctrlObj = {&g_ctrlVtbl, 1};

/* ---------- 3. 导航开始 / 完成 ---------- */
static HRESULT STDMETHODCALLTYPE NavStart_Invoke(
    ICoreWebView2NavigationStartingEventHandler *, ICoreWebView2 *,
    ICoreWebView2NavigationStartingEventArgs *);
DECL_HANDLER(NavStartObj, ICoreWebView2NavigationStartingEventHandler,
             ICoreWebView2NavigationStartingEventHandlerVtbl)
static ICoreWebView2NavigationStartingEventHandlerVtbl g_navStartVtbl = {
    NavStartObj_QI, NavStartObj_AddRef, NavStartObj_Release, NavStart_Invoke};
static NavStartObj g_navStartObj = {&g_navStartVtbl, 1};

static HRESULT STDMETHODCALLTYPE NavDone_Invoke(
    ICoreWebView2NavigationCompletedEventHandler *, ICoreWebView2 *,
    ICoreWebView2NavigationCompletedEventArgs *);
DECL_HANDLER(NavDoneObj, ICoreWebView2NavigationCompletedEventHandler,
             ICoreWebView2NavigationCompletedEventHandlerVtbl)
static ICoreWebView2NavigationCompletedEventHandlerVtbl g_navDoneVtbl = {
    NavDoneObj_QI, NavDoneObj_AddRef, NavDoneObj_Release, NavDone_Invoke};
static NavDoneObj g_navDoneObj = {&g_navDoneVtbl, 1};

/* ---------- 4. 进程失败 / JS 消息 ---------- */
static HRESULT STDMETHODCALLTYPE ProcFail_Invoke(
    ICoreWebView2ProcessFailedEventHandler *, ICoreWebView2 *,
    ICoreWebView2ProcessFailedEventArgs *);
DECL_HANDLER(ProcFailObj, ICoreWebView2ProcessFailedEventHandler,
             ICoreWebView2ProcessFailedEventHandlerVtbl)
static ICoreWebView2ProcessFailedEventHandlerVtbl g_procFailVtbl = {
    ProcFailObj_QI, ProcFailObj_AddRef, ProcFailObj_Release, ProcFail_Invoke};
static ProcFailObj g_procFailObj = {&g_procFailVtbl, 1};

static HRESULT STDMETHODCALLTYPE Msg_Invoke(
    ICoreWebView2WebMessageReceivedEventHandler *, ICoreWebView2 *,
    ICoreWebView2WebMessageReceivedEventArgs *);
DECL_HANDLER(MsgObj, ICoreWebView2WebMessageReceivedEventHandler,
             ICoreWebView2WebMessageReceivedEventHandlerVtbl)
static ICoreWebView2WebMessageReceivedEventHandlerVtbl g_msgVtbl = {
    MsgObj_QI, MsgObj_AddRef, MsgObj_Release, Msg_Invoke};
static MsgObj g_msgObj = {&g_msgVtbl, 1};

/* ================= WebView2 进程计数 =================
   踩过的坑:按"父进程链爬到我们自己"来数,会在 WebView2Loader 这个短命启动器
   退出后断链 —— 进程还活着,却数成 0(我上一版就是这么被误导的)。
   改成"与基线对比":先记下开跑前系统里已有的 msedgewebview2 数量,
   之后的总数减去基线,增量就是我们的。简单且不会断链。 */
static int g_baseline_wv2 = 0;

static int count_all_wv2(void) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return -1;
  int count = 0;
  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(pe);
  if (Process32FirstW(snap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, L"msedgewebview2.exe") == 0) count++;
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return count;
}

static int count_ours(void) {
  int all = count_all_wv2();
  if (all < 0) return -1;
  int delta = all - g_baseline_wv2;
  return delta < 0 ? 0 : delta;
}

/* 把当前 webview 的真实状态抓下来 —— 比等事件更能判断"到底走到哪一步了" */
static void probe_state(const char *stage) {
  if (!g_web) { logline("[web]  %-12s (no webview)", stage); return; }
  LPWSTR title = NULL, src = NULL;
  ICoreWebView2_get_DocumentTitle(g_web, &title);
  ICoreWebView2_get_Source(g_web, &src);
  char t[160] = "", s[320] = "";
  w2u(title, t, sizeof(t));
  w2u(src, s, sizeof(s));
  if (title) CoTaskMemFree(title);
  if (src) CoTaskMemFree(src);
  logline("[web]  %-12s title=\"%s\" source=\"%s\"", stage, t, s);
}

/* 窗口可见性:客观事实,不靠猜 */
static void log_window_state(const char *stage) {
  if (!g_hwnd) { logline("[win]  %-12s (no hwnd)", stage); return; }
  RECT rc = {0};
  GetWindowRect(g_hwnd, &rc);
  logline("[win]  %-12s visible=%d iconic=%d size=%ldx%ld foreground=%d topmost=%d",
          stage, (int)IsWindowVisible(g_hwnd), (int)IsIconic(g_hwnd),
          (long)(rc.right - rc.left), (long)(rc.bottom - rc.top),
          (int)(GetForegroundWindow() == g_hwnd),
          (int)((GetWindowLongW(g_hwnd, GWL_EXSTYLE) & WS_EX_TOPMOST) != 0));
}

/* ================= 回调实现 ================= */
static const char *PAGE =
    "<!doctype html><meta charset=\"utf-8\">"
    "<body style=\"font-family:Segoe UI,Microsoft YaHei;padding:28px\">"
    "<h1 id=h>waiting</h1>"
    "<script>window.onload=function(){"
    "document.getElementById('h').textContent='WebView2 OK: page rendered';"
    "chrome.webview.postMessage({ready:true,who:'page'});"
    "};</script></body>";

static HRESULT STDMETHODCALLTYPE Env_Invoke(
    ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *This,
    HRESULT hr, ICoreWebView2Environment *env) {
  (void)This;
  logline("[api]  environment hr=0x%08lX env=%p", (unsigned long)hr, (void *)env);
  if (FAILED(hr) || !env) return S_OK;
  g_env = env;
  LPWSTR ver = NULL;
  if (SUCCEEDED(ICoreWebView2Environment_get_BrowserVersionString(env, &ver)) && ver) {
    char v[128];
    w2u(ver, v, sizeof(v));
    logline("[api]  browser version = %s", v);
    CoTaskMemFree(ver);
  }
  HRESULT e = ICoreWebView2Environment_CreateCoreWebView2Controller(
      env, g_hwnd, (ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *)&g_ctrlObj);
  logline("[api]  CreateController hwnd=%p hr=0x%08lX", (void *)g_hwnd, (unsigned long)e);
  return S_OK;
}

static HRESULT STDMETHODCALLTYPE Ctrl_Invoke(
    ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *This,
    HRESULT hr, ICoreWebView2Controller *ctrl) {
  (void)This;
  logline("[api]  controller hr=0x%08lX ctrl=%p", (unsigned long)hr, (void *)ctrl);
  if (FAILED(hr) || !ctrl) return S_OK;
  g_ctrl = ctrl;

  HRESULT g = ICoreWebView2Controller_get_CoreWebView2(ctrl, &g_web);
  logline("[api]  get CoreWebView2 hr=0x%08lX web=%p", (unsigned long)g, (void *)g_web);
  if (!g_web) return S_OK;

  EventRegistrationToken tok;
  ICoreWebView2_add_NavigationStarting(
      g_web, (ICoreWebView2NavigationStartingEventHandler *)&g_navStartObj, &tok);
  ICoreWebView2_add_NavigationCompleted(
      g_web, (ICoreWebView2NavigationCompletedEventHandler *)&g_navDoneObj, &tok);
  ICoreWebView2_add_ProcessFailed(
      g_web, (ICoreWebView2ProcessFailedEventHandler *)&g_procFailObj, &tok);
  ICoreWebView2_add_WebMessageReceived(
      g_web, (ICoreWebView2WebMessageReceivedEventHandler *)&g_msgObj, &tok);

  RECT client = {0};
  GetClientRect(g_hwnd, &client);
  logline("[api]  client rect size=%ldx%ld", (long)(client.right - client.left),
          (long)(client.bottom - client.top));
  if (client.right - client.left < 100) {
    client.right = client.left + 800;
    client.bottom = client.top + 600;
    logline("[api]  client rect too small -> fallback 800x600");
  }
  ICoreWebView2Controller_put_Bounds(ctrl, client);
  ICoreWebView2Controller_put_IsVisible(ctrl, TRUE);

  RECT back = {0};
  ICoreWebView2Controller_get_Bounds(ctrl, &back);
  BOOL vis = FALSE;
  ICoreWebView2Controller_get_IsVisible(ctrl, &vis);
  logline("[api]  bounds applied size=%ldx%ld visible=%d",
          (long)(back.right - back.left), (long)(back.bottom - back.top), (int)vis);

  /* 反复顶到最前 —— 让"被遮挡"这个变量不可能成立 */
  SetWindowPos(g_hwnd, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
  SetForegroundWindow(g_hwnd);
  BringWindowToTop(g_hwnd);
  log_window_state("before-nav");

  /* 三种模式,用来把"是初始化就崩"还是"导航才崩"分开:
       nonav   —— 只建环境与控制器,不导航
       tostring—— NavigateToString(内嵌 HTML)
       url     —— Navigate(真实 HTTPS 地址)                    */
  const char *mode = getenv("PROBE_MODE");
  if (!mode || !*mode) mode = "tostring";
  logline("[run]  mode = %s", mode);
  if (same(mode, "nonav")) {
    logline("[api]  (nonav) 跳过导航,只观察进程是否存活");
    return S_OK;
  }
  if (same(mode, "url")) {
    const char *u = getenv("PROBE_URL");
    if (!u || !*u) u = "https://example.com/";
    wchar_t *wurl = u8_to_w(u);
    HRESULT n = ICoreWebView2_Navigate(g_web, wurl);
    free(wurl);
    logline("[api]  Navigate(%.120s) hr=0x%08lX", u, (unsigned long)n);
    return S_OK;
  }
  {
    wchar_t *html = u8_to_w(PAGE);
    HRESULT n = ICoreWebView2_NavigateToString(g_web, html);
    free(html);
    logline("[api]  NavigateToString hr=0x%08lX", (unsigned long)n);
  }
  return S_OK;
}

static HRESULT STDMETHODCALLTYPE NavStart_Invoke(
    ICoreWebView2NavigationStartingEventHandler *This, ICoreWebView2 *sender,
    ICoreWebView2NavigationStartingEventArgs *args) {
  (void)This; (void)sender;
  LPWSTR uri = NULL;
  if (SUCCEEDED(ICoreWebView2NavigationStartingEventArgs_get_Uri(args, &uri)) && uri) {
    char u[256];
    w2u(uri, u, sizeof(u));
    logline("[nav]  << NavigationStarting");
    (void)u;
    CoTaskMemFree(uri);
  }
  InterlockedExchange(&g_navStart, 1);
  return S_OK;
}

static HRESULT STDMETHODCALLTYPE NavDone_Invoke(
    ICoreWebView2NavigationCompletedEventHandler *This, ICoreWebView2 *sender,
    ICoreWebView2NavigationCompletedEventArgs *args) {
  (void)This; (void)sender;
  BOOL ok = FALSE;
  COREWEBVIEW2_WEB_ERROR_STATUS st = COREWEBVIEW2_WEB_ERROR_STATUS_UNKNOWN;
  ICoreWebView2NavigationCompletedEventArgs_get_IsSuccess(args, &ok);
  ICoreWebView2NavigationCompletedEventArgs_get_WebErrorStatus(args, &st);
  logline("[nav]  << NavigationCompleted success=%d webErrorStatus=%d", (int)ok, (int)st);
  InterlockedExchange(&g_navDone, 1);
  return S_OK;
}

static HRESULT STDMETHODCALLTYPE ProcFail_Invoke(
    ICoreWebView2ProcessFailedEventHandler *This, ICoreWebView2 *sender,
    ICoreWebView2ProcessFailedEventArgs *args) {
  (void)This; (void)sender;
  COREWEBVIEW2_PROCESS_FAILED_KIND kind = COREWEBVIEW2_PROCESS_FAILED_KIND_BROWSER_PROCESS_EXITED;
  ICoreWebView2ProcessFailedEventArgs_get_ProcessFailedKind(args, &kind);
  logline("[nav]  !! ProcessFailed kind=%d", (int)kind);
  InterlockedExchange(&g_failed, 1);
  return S_OK;
}

static HRESULT STDMETHODCALLTYPE Msg_Invoke(
    ICoreWebView2WebMessageReceivedEventHandler *This, ICoreWebView2 *sender,
    ICoreWebView2WebMessageReceivedEventArgs *args) {
  (void)This; (void)sender;
  LPWSTR json = NULL;
  if (SUCCEEDED(ICoreWebView2WebMessageReceivedEventArgs_get_WebMessageAsJson(args, &json)) && json) {
    char j[256];
    w2u(json, j, sizeof(j));
    logline("[js]   << postMessage %s", j);
    CoTaskMemFree(json);
    InterlockedExchange(&g_msg, 1);
  }
  return S_OK;
}

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
  if (m == WM_SIZE && g_ctrl) {
    RECT rc = {0};
    GetClientRect(h, &rc);
    ICoreWebView2Controller_put_Bounds(g_ctrl, rc);
    logline("[win]   WM_SIZE -> bounds %ldx%ld", (long)(rc.right - rc.left),
            (long)(rc.bottom - rc.top));
  }
  if (m == WM_DESTROY) { PostQuitMessage(0); return 0; }
  return DefWindowProcW(h, m, w, l);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int show) {
  (void)hPrev; (void)cmd; (void)show;
  g_self_pid = GetCurrentProcessId();
  CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

  logline("================ controlled experiment ================");
  logline("self pid=%lu", (unsigned long)g_self_pid);
  {
    const char *extra = getenv("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS");
    logline("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=%s", extra ? extra : "(unset)");
  }

  HMODULE loader = LoadLibraryA("WebView2Loader.dll");
  if (!loader) { logline("FATAL: LoadLibrary(WebView2Loader.dll) err=%lu", GetLastError()); goto done; }
  pCreateEnv = (PFN_CreateEnv)GetProcAddress(loader, "CreateCoreWebView2EnvironmentWithOptions");
  if (!pCreateEnv) { logline("FATAL: export not found"); goto done; }
  logline("[api]  loader ok");
  /* 先记基线:系统里本来就有别的 WebView2 宿主(如 Windows 搜索),不能算我们的 */
  g_baseline_wv2 = count_all_wv2();
  logline("[proc] baseline msedgewebview2 count = %d", g_baseline_wv2);

  {
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    int ww = 820, wh = 620;
    int wx = (sw - ww) / 2, wy = (sh - wh) / 2;
    logline("[win]  screen=%dx%d -> window at (%d,%d) size %dx%d", sw, sh, wx, wy, ww, wh);

    WNDCLASSW wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"WV2Controlled";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassW(&wc);

    g_hwnd = CreateWindowExW(0, L"WV2Controlled",
                             L"WebView2 controlled experiment",
                             WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                             wx, wy, ww, wh, NULL, NULL, hInst, NULL);
    logline("[win]  CreateWindowEx -> hwnd=%p", (void *)g_hwnd);
    ShowWindow(g_hwnd, SW_SHOWNORMAL);
    UpdateWindow(g_hwnd);
    SetForegroundWindow(g_hwnd);
    BringWindowToTop(g_hwnd);
    log_window_state("created");
  }

  CreateDirectoryW(L"C:\\Temp", NULL);
  CreateDirectoryW(L"C:\\Temp\\wv2exp", NULL);
  {
    HRESULT e = pCreateEnv(NULL, L"C:\\Temp\\wv2exp", NULL,
                           (ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *)&g_envObj);
    logline("[api]  CreateEnv hr=0x%08lX", (unsigned long)e);
  }

  {
    DWORD t0 = GetTickCount();
    int last_count = -1;
    for (;;) {
      MSG msg;
      while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
      }
      DWORD el = GetTickCount() - t0;
      if (el % 200 < 20) {
        int c = count_ours();
        if (c != last_count) {
          logline("[proc] t=%4lums our-webview-procs=%d%s", (unsigned long)el, c,
                  c > 3 ? "   <-- renderer/gpu ready" : "");
          last_count = c;
        }
        if (c > g_peak_descendants) g_peak_descendants = c;
      }
      /* 每秒抓一次 webview 内部状态,看导航到底走到哪一步 */
      if (el > 800 && el % 1000 < 20) {
        char stage[32];
        snprintf(stage, sizeof(stage), "t=%lums", (unsigned long)el);
        probe_state(stage);
      }
      if (el > 12000 && el % 4000 < 20) log_window_state("sampling");
      if (el > 20000) break;
      if (g_msg && g_navDone) {
        logline("[run]  goal reached at t=%lums", (unsigned long)el);
        break;
      }
      Sleep(10);
    }
  }

done:
  logline("[win]  final state:");
  log_window_state("final");
  probe_state("final");
  logline("---------------- verdict ----------------");
  logline("our webview procs peak  = %d  (baseline was %d)",
          g_peak_descendants, g_baseline_wv2);
  logline("NavigationStarting      = %d", (int)g_navStart);
  logline("NavigationCompleted     = %d", (int)g_navDone);
  logline("JS postMessage received = %d", (int)g_msg);
  logline("ProcessFailed           = %d", (int)g_failed);
  if (g_navDone && g_msg) {
    logline("VERDICT: 环境/控制器/渲染进程/导航/JS<->C 通道 全部跑通");
  } else if (g_peak_descendants > 3 && !g_navDone) {
    logline("VERDICT: renderer 已创建且窗口可见置顶,但导航未完成");
    logline("         -> 遮挡/隐藏不是原因;下一步看 source 与 webErrorStatus");
  } else {
    logline("VERDICT: 渲染进程没起来 -> 宿主侧还有变量没控住");
  }
  if (g_log) { fclose(g_log); g_log = NULL; }
  ExitProcess(0);
  return 0;
}

