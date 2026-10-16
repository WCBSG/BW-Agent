/* DPI 感知实验:上一次实验里浏览器日志反复出现
   "failed to set WebView dpi awareness of 2" —— 这是宿主进程的 DPI 感知
   与 WebView2 要求不一致的信号,而它恰好可能让 browser 进程在握手后自行退出。
   这里用三种 DPI 状态各测一遍,看进程存活时间有没有区别。

   三种状态(用 --dpi=xxx 选):
     none        完全不设置(让 WebView2 自己设)
     aware       SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)
     unaware     SetProcessDPIAware 的反面:显式保持 unaware
*/
#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <tlhelp32.h>
#include <shellscalingapi.h>
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
static int g_base = 0;
static FILE *g_log = NULL;

static void logline(const char *fmt, ...) {
  if (!g_log) g_log = fopen("dpi.log", "a");
  if (!g_log) return;
  va_list ap;
  va_start(ap, fmt);
  vfprintf(g_log, fmt, ap);
  va_end(ap);
  fputc('\n', g_log);
  fflush(g_log);
}

static wchar_t *u8_to_w(const char *s) {
  int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
  wchar_t *w = (wchar_t *)calloc((size_t)n + 1, sizeof(wchar_t));
  if (w) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
  return w;
}

static int same(const char *a, const char *b) {
  if (!a || !b) return a == b;
  return _stricmp(a, b) == 0;
}

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

static HRESULT STDMETHODCALLTYPE Env_Invoke(
    ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *, HRESULT,
    ICoreWebView2Environment *);
DECL_HANDLER(EnvObj, ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler,
             ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandlerVtbl)
static ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandlerVtbl g_envVtbl = {
    EnvObj_QI, EnvObj_AddRef, EnvObj_Release, Env_Invoke};
static EnvObj g_envObj = {&g_envVtbl, 1};

static HRESULT STDMETHODCALLTYPE Ctrl_Invoke(
    ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *, HRESULT,
    ICoreWebView2Controller *);
DECL_HANDLER(CtrlObj, ICoreWebView2CreateCoreWebView2ControllerCompletedHandler,
             ICoreWebView2CreateCoreWebView2ControllerCompletedHandlerVtbl)
static ICoreWebView2CreateCoreWebView2ControllerCompletedHandlerVtbl g_ctrlVtbl = {
    CtrlObj_QI, CtrlObj_AddRef, CtrlObj_Release, Ctrl_Invoke};
static CtrlObj g_ctrlObj = {&g_ctrlVtbl, 1};

static int count_wv2(void) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return -1;
  int c = 0;
  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(pe);
  if (Process32FirstW(snap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, L"msedgewebview2.exe") == 0) c++;
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return c;
}

static HRESULT STDMETHODCALLTYPE Env_Invoke(
    ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *This,
    HRESULT hr, ICoreWebView2Environment *env) {
  (void)This;
  logline("[dpi]  env hr=0x%08lX", (unsigned long)hr);
  if (FAILED(hr) || !env) return S_OK;
  g_env = env;
  HRESULT e = ICoreWebView2Environment_CreateCoreWebView2Controller(
      env, g_hwnd, (ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *)&g_ctrlObj);
  logline("[dpi]  CreateController hr=0x%08lX", (unsigned long)e);
  return S_OK;
}

static HRESULT STDMETHODCALLTYPE Ctrl_Invoke(
    ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *This,
    HRESULT hr, ICoreWebView2Controller *ctrl) {
  (void)This;
  logline("[dpi]  controller hr=0x%08lX", (unsigned long)hr);
  if (FAILED(hr) || !ctrl) return S_OK;
  g_ctrl = ctrl;
  ICoreWebView2Controller_get_CoreWebView2(ctrl, &g_web);
  RECT rc = {0, 0, 800, 600};
  ICoreWebView2Controller_put_Bounds(ctrl, rc);
  ICoreWebView2Controller_put_IsVisible(ctrl, TRUE);
  logline("[dpi]  控制器就绪,不导航(只观察进程存活)");
  return S_OK;
}

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
  if (m == WM_DESTROY) { PostQuitMessage(0); return 0; }
  return DefWindowProcW(h, m, w, l);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int show) {
  (void)hPrev; (void)cmd; (void)show;
  const char *mode = getenv("DPI_MODE");
  if (!mode || !*mode) mode = "none";

  CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

  logline("\n================ DPI_MODE=%s ================", mode);
  if (same(mode, "aware")) {
    BOOL ok = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    logline("[dpi]  SetProcessDpiAwarenessContext(V2) -> %d err=%lu", (int)ok, GetLastError());
  } else if (same(mode, "unaware")) {
    BOOL ok = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_UNAWARE);
    logline("[dpi]  SetProcessDpiAwarenessContext(UNAWARE) -> %d err=%lu", (int)ok, GetLastError());
  } else {
    logline("[dpi]  不设置,交给 WebView2 自己处理");
  }

  HMODULE loader = LoadLibraryA("WebView2Loader.dll");
  if (!loader) { logline("[dpi]  FATAL loader err=%lu", GetLastError()); goto done; }
  pCreateEnv = (PFN_CreateEnv)GetProcAddress(loader, "CreateCoreWebView2EnvironmentWithOptions");
  if (!pCreateEnv) { logline("[dpi]  FATAL export"); goto done; }

  {
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"WV2Dpi";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);
    g_hwnd = CreateWindowExW(0, L"WV2Dpi", L"DPI experiment",
                             WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                             200, 150, 900, 680, NULL, NULL, hInst, NULL);
    ShowWindow(g_hwnd, SW_SHOWNORMAL);
    UpdateWindow(g_hwnd);
    SetForegroundWindow(g_hwnd);
  }

  CreateDirectoryW(L"C:\\Temp\\wv2dpi", NULL);
  g_base = count_wv2();
  logline("[dpi]  baseline wv2 = %d", g_base);
  HRESULT e = pCreateEnv(NULL, L"C:\\Temp\\wv2dpi", NULL,
                         (ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *)&g_envObj);
  logline("[dpi]  CreateEnv hr=0x%08lX", (unsigned long)e);

  DWORD t0 = GetTickCount();
  int peak = 0, last = -1;
  for (;;) {
    MSG msg;
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
      TranslateMessage(&msg);
      DispatchMessageW(&msg);
    }
    DWORD el = GetTickCount() - t0;
    if (el % 100 < 15) {
      int c = count_wv2() - g_base;
      if (c < 0) c = 0;
      if (c > peak) peak = c;
      if (c != last) {
        logline("[dpi]  t=%4lums ours=%d", (unsigned long)el, c);
        last = c;
      }
    }
    if (el > 12000) break;
    Sleep(10);
  }

done:
  logline("[dpi]  峰值进程数 = %d   存活到 12 秒 = %s", peak,
          last > 0 ? "是" : "否(已全部退出)");
  if (g_log) { fclose(g_log); g_log = NULL; }
  ExitProcess(0);
  return 0;
}
