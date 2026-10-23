/* webview.cpp —— WebView2 宿主:自己的窗口 + 嵌入式 Chromium。
 *
 * 三条设计约束(踩过坑,写清楚免得以后再试一遍):
 *   1. **不链接 SDK 库**。WebView2Loader.dll 以资源形式编进 exe(mkres 打进来的
 *      data/WebView2Loader.dll),启动时释放到 <数据目录>\bin\ 再 LoadLibrary。
 *      少一个"必须放在 exe 旁边"的文件,单文件交付才成立。
 *   2. **窗口线程独立**。WebView2 要求创建它的线程一直跑消息循环;
 *      主线程在 serve_run 里跑 HTTP,所以这里 CreateThread 起自己的消息循环。
 *   3. **不装 WebView2 也不能打不开**。失败就返回非 0,调用方退回系统 Edge 的
 *      --app 窗口(见 ui.cpp)—— 宁可观感差一点,也不能让人双击没反应。
 *
 * 安全上的取舍:关掉开发者工具、右键菜单、状态栏与缩放控件;
 * 拦截 window.open(不在本窗口开新窗,也不偷偷开浏览器);导航只允许
 * 本机回环地址(令牌在页面里,不该被任何外部页面借走)。
 */
#include "webview.h"

#include "common.h"
#include "embed.h"
#include "http.h"
#include "tray.h"
#include "ui.h"
#include "webview2_min.h"

#include <atomic>
#include <functional>
#include <string>

/* ---------------- 状态 ---------------- */
static HANDLE g_thread = NULL;
static HANDLE g_boot = NULL;           /* 线程把"成没成"写完之后置位 */
static HWND g_hwnd = NULL;
static volatile LONG g_ready = 0;      /* 控制器建好了、页面开始加载 */
static volatile LONG g_stopping = 0;   /* 是我们自己要关,不是用户关 */
static volatile LONG g_backend = 0;    /* 1 = 真的用上了 WebView2 */
static int g_port = 0;
static char g_title[128] = "网站安全巡检";
static DWORD g_thread_id = 0;

int webview_active(void) { return g_hwnd && IsWindow(g_hwnd) ? 1 : 0; }
int webview_backend_is_native(void) { return g_backend ? 1 : 0; }

/* ---------------- 注册表里找运行时(找不到也能试) ---------------- */
static int runtime_present(void) {
  static const wchar_t *keys[] = {
      L"SOFTWARE\\WOW6432Node\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
      L"SOFTWARE\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
      NULL};
  for (int i = 0; keys[i]; i++) {
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keys[i], 0, KEY_READ, &k) == ERROR_SUCCESS) {
      wchar_t v[64];
      DWORD sz = sizeof(v), type = 0;
      LONG ok = RegQueryValueExW(k, L"pv", NULL, &type, (LPBYTE)v, &sz);
      RegCloseKey(k);
      if (ok == ERROR_SUCCESS && v[0]) return 1;
    }
  }
  return 0;
}

/* ---------------- 找运行时目录 ----------------
   为什么不能只靠加载器自己找:它按 "HKLM\SOFTWARE\Microsoft\EdgeUpdate\Clients\{...}"
   (64 位视图)判断有没有装。这台机器上运行时只登记在 WOW6432Node(x86 视图)下,
   于是 64 位的加载器得出"没装"的结论,直接返回 ERROR_FILE_NOT_FOUND(0x80070002)
   —— 实测就是这个错。所以这里自己把安装目录找出来,作为
   browserExecutableFolder 显式传给 CreateCoreWebView2EnvironmentWithOptions。 */
static void env_utf8_local(const wchar_t *name, char *out, size_t cap) {
  if (out && cap) out[0] = 0;
  DWORD need = GetEnvironmentVariableW(name, NULL, 0);
  if (need == 0) return;
  wchar_t *buf = (wchar_t *)xmalloc((size_t)need * sizeof(wchar_t));
  if (GetEnvironmentVariableW(name, buf, need) > 0) {
    char *u = w_to_u8(buf);
    if (u) {
      if (out && cap) snprintf(out, cap, "%s", u);
      free(u);
    }
  }
  free(buf);
}

static int dir_has_runtime(const char *dir) {
  if (!dir || !*dir) return 0;
  char exe[MAX_PATH * 4];
  snprintf(exe, sizeof(exe), "%s\\msedgewebview2.exe", dir);
  return file_size(exe) > 0;
}

/* 注册表里的 pv(版本号):两个视图都查 */
static int runtime_version(char *out, size_t cap) {
  if (out && cap) out[0] = 0;
  static const wchar_t *keys[] = {
      L"SOFTWARE\\WOW6432Node\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
      L"SOFTWARE\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
      NULL};
  for (int i = 0; keys[i]; i++) {
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keys[i], 0, KEY_READ, &k) != ERROR_SUCCESS) continue;
    wchar_t v[64];
    DWORD sz = sizeof(v), type = 0;
    LONG ok = RegQueryValueExW(k, L"pv", NULL, &type, (LPBYTE)v, &sz);
    RegCloseKey(k);
    if (ok == ERROR_SUCCESS && v[0]) {
      char *u = w_to_u8(v);
      if (u) {
        snprintf(out, cap, "%s", u);
        free(u);
      }
      if (out[0]) return 1;
    }
  }
  return 0;
}

/* Application 目录下有没有比 pv 更新的版本(Edge 自动更新后注册表可能还没跟上) */
static int newest_subdir(const char *parent, char *out, size_t cap) {
  char pattern[MAX_PATH * 4];
  snprintf(pattern, sizeof(pattern), "%s\\*", parent);
  wchar_t *wpat = u8_to_w(pattern);
  if (!wpat) return 0;
  WIN32_FIND_DATAW fd;
  HANDLE h = FindFirstFileW(wpat, &fd);
  free(wpat);
  if (h == INVALID_HANDLE_VALUE) return 0;
  char best[MAX_PATH * 2] = {0};
  do {
    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
    char *n = w_to_u8(fd.cFileName);
    if (!n) continue;
    char dir[MAX_PATH * 4];
    snprintf(dir, sizeof(dir), "%s\\%s", parent, n);
    free(n);
    if (!dir_has_runtime(dir)) continue;
    if (strcmp(dir, best) > 0) snprintf(best, sizeof(best), "%s", dir);  /* 版本号按字典序比就行 */
  } while (FindNextFileW(h, &fd));
  FindClose(h);
  if (best[0]) {
    snprintf(out, cap, "%s", best);
    return 1;
  }
  return 0;
}

static int find_runtime_dir(char *out, size_t cap) {
  if (out && cap) out[0] = 0;
  char ver[64] = {0};
  runtime_version(ver, sizeof(ver));

  const wchar_t *bases[] = {L"ProgramFiles(x86)", L"ProgramFiles", L"LOCALAPPDATA", NULL};
  for (int i = 0; bases[i]; i++) {
    char base[MAX_PATH * 2];
    env_utf8_local(bases[i], base, sizeof(base));
    if (!base[0]) continue;
    char app[MAX_PATH * 3];
    snprintf(app, sizeof(app), "%s\\Microsoft\\EdgeWebView\\Application", base);
    if (ver[0]) {
      char dir[MAX_PATH * 4];
      snprintf(dir, sizeof(dir), "%s\\%s", app, ver);
      if (dir_has_runtime(dir)) {
        snprintf(out, cap, "%s", dir);
        return 1;
      }
    }
    if (newest_subdir(app, out, cap)) return 1;
  }
  return 0;
}


/* ---------------- 释放 WebView2Loader.dll ----------------
   编进 exe 的那份落在 <数据目录>\bin\ 下。文件名不改:加载器内部会去
   找同目录的 msedgewebview2.exe / 运行时,名字被改过反而可能找不到。 */
static int extract_loader(char *out, size_t cap) {
  char dir[MAX_PATH * 2];
  app_data_path(dir, sizeof(dir), "bin");
  ensure_dir(dir);
  char path[MAX_PATH * 2];
  app_data_path(path, sizeof(path), "bin\\WebView2Loader.dll");

  const char *blob = NULL;
  size_t blen = 0;
  if (!embed_lookup("data/WebView2Loader.dll", &blob, &blen) || !blob || blen == 0) {
    snprintf(out, cap, "%s", path);
    return file_size(path) > 0 ? 0 : -1;      /* 开发机上可能手动放了一份 */
  }
  long have = file_size(path);
  if (have == (long)blen) {                   /* 大小一致就当是同一份,不反复写盘 */
    snprintf(out, cap, "%s", path);
    return 0;
  }
  if (file_write_all(path, blob, blen) != 0) {
    log_warn("WebView2 加载器写出失败:%s", path);
    return -1;
  }
  snprintf(out, cap, "%s", path);
  log_info("[界面] 已释放 WebView2 加载器:%s(%d 字节)", path, (int)blen);
  return 0;
}

/* ---------------- 极简 COM 回调 ----------------
   WebView2 的异步 API 只认 COM 接口。这里用一个模板收口:
   只实现 IUnknown 和那一个 Invoke,其余接口方法由派生类补。
   GUID 手写而不是 __uuidof:MinGW 的 __uuidof 需要 __CRT_UUID_DECL 特化,
   而 SDK 的 __declspec(uuid(...)) 那份元数据 g++ 不会替我们生成。 */
static const IID IID_EnvDone = {0x4e8a3389, 0xc9d8, 0x4bd2, {0xb6, 0xb5, 0x12, 0x4f, 0xee, 0x6c, 0xc1, 0x4d}};
static const IID IID_CtlDone = {0x6c4819f3, 0xc9b7, 0x4260, {0x81, 0x27, 0xc9, 0xf5, 0xbd, 0xe7, 0xf6, 0x8c}};
static const IID IID_NewWindow = {0xd4c185fe, 0xc81c, 0x4989, {0x97, 0xaf, 0x2d, 0x3f, 0xa7, 0xab, 0x56, 0x51}};
static const IID IID_Options = {0x2fde08a8, 0x1e9a, 0x4766, {0x8c, 0x05, 0x95, 0xa9, 0xce, 0xb9, 0xd1, 0xc5}};

template <typename T>
struct RefBase : T {
  LONG ref = 1;
  virtual const IID &iid() const = 0;
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppv) override {
    if (!ppv) return E_POINTER;
    if (IsEqualGUID(riid, IID_IUnknown) || IsEqualGUID(riid, iid())) {
      *ppv = static_cast<T *>(this);
      AddRef();
      return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
  }
  ULONG STDMETHODCALLTYPE AddRef() override { return (ULONG)InterlockedIncrement(&ref); }
  ULONG STDMETHODCALLTYPE Release() override {
    LONG n = InterlockedDecrement(&ref);
    if (n == 0) delete this;
    return (ULONG)n;
  }
};

struct EnvDone : RefBase<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler> {
  const IID &iid() const override { return IID_EnvDone; }
  std::function<void(HRESULT, ICoreWebView2Environment *)> fn;
  HRESULT STDMETHODCALLTYPE Invoke(HRESULT hr, ICoreWebView2Environment *env) override {
    if (fn) fn(hr, env);
    Release();
    return S_OK;
  }
};

struct CtlDone : RefBase<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler> {
  const IID &iid() const override { return IID_CtlDone; }
  std::function<void(HRESULT, ICoreWebView2Controller *)> fn;
  HRESULT STDMETHODCALLTYPE Invoke(HRESULT hr, ICoreWebView2Controller *ctl) override {
    if (fn) fn(hr, ctl);
    Release();
    return S_OK;
  }
};

struct NewWindowDone : RefBase<ICoreWebView2NewWindowRequestedEventHandler> {
  const IID &iid() const override { return IID_NewWindow; }
  HRESULT STDMETHODCALLTYPE Invoke(ICoreWebView2 *sender,
                                   ICoreWebView2NewWindowRequestedEventArgs *args) override {
    (void)sender;
    /* 界面里不需要开新窗口。市场链接带 target=_blank,按 settings 的默认行为
       会交给系统浏览器;这里只挡"在界面里再开一个 WebView 窗口"。 */
    if (args) args->put_Handled(TRUE);
    return S_OK;
  }
};

/* 附加浏览器参数**不走 options 对象**。
   实测(见 .cache 里的探针):自己实现 ICoreWebView2EnvironmentOptions 传给加载器
   会返回 E_INVALIDARG —— 不带 options 的调用则成功。官方的等效做法是设环境变量
   WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS,加载器会把它原样传给浏览器进程。
   为什么需要它:少数环境(虚拟机 / 远程桌面 / 老显卡)D3D 初始化失败会白屏,
   那时加 --disable-gpu 能救回来(用 BW_WEBVIEW2_ARGS 传),本机早期版本就栽在这上面。 */
static void set_browser_args(void) {
  wchar_t extra[512] = {0};
  DWORD n = GetEnvironmentVariableW(L"BW_WEBVIEW2_ARGS", extra, 512);
  wchar_t merged[768];
  if (n > 0 && n < 512) swprintf(merged, 768, L"--disable-features=msEdgeSidebarV2 %ls", extra);
  else wcscpy(merged, L"--disable-features=msEdgeSidebarV2");
  SetEnvironmentVariableW(L"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", merged);
}

/* ---------------- 窗口与控制器 ---------------- */
static ICoreWebView2Environment *g_env = nullptr;
static ICoreWebView2Controller *g_ctl = nullptr;
static ICoreWebView2 *g_web = nullptr;

static void layout(void) {
  if (!g_ctl || !g_hwnd) return;
  RECT rc;
  GetClientRect(g_hwnd, &rc);
  g_ctl->put_Bounds(rc);
}

static void on_close_requested(void) {
  /* 和"系统浏览器窗口"同样的语义:正常关窗 = 程序收摊;
     托盘在时只收起;--debug 时服务继续跑 */
  if (InterlockedCompareExchange(&g_stopping, 1, 1) == 1) return;
  if (ui_stop_on_close()) {
    if (tray_active()) {
      log_info("界面窗口已关闭,程序已最小化到托盘(右键托盘图标可重新打开或彻底退出)");
      tray_balloon("仍在后台运行", "周期巡检会继续。右键托盘图标可重新打开界面或彻底退出。");
      g_hwnd = NULL;
      return;
    }
    log_info("界面窗口已关闭,服务随之停止");
    http_stop();
  } else {
    log_info("界面窗口已关闭(--debug:服务继续运行,界面地址仍然可用)");
  }
  g_hwnd = NULL;
}

static unsigned g_msg_ring[8] = {0};
static int g_msg_pos = 0;

static LRESULT CALLBACK wnd_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
  g_msg_ring[g_msg_pos++ & 7] = msg;
  switch (msg) {
    case WM_SIZE:
      layout();
      return 0;
    /* 拖到另一块缩放比不同的屏:跟着系统给的建议矩形走,并让 WebView 重排。
       不处理的话,窗口边框会按新 DPI 画、内容却是旧比例 —— 看起来像放大糊了。 */
    case WM_DPICHANGED: {
      RECT *sug = (RECT *)lp;
      if (sug) {
        SetWindowPos(h, NULL, sug->left, sug->top, sug->right - sug->left,
                     sug->bottom - sug->top, SWP_NOZORDER | SWP_NOACTIVATE);
      }
      layout();
      return 0;
    }
    case WM_SETFOCUS:
      if (g_ctl) g_ctl->MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
      return 0;
    case WM_CLOSE:
      /* 用户关窗 / 我们自己收摊都会走到这里。把最近几条消息带上:
         排查"窗口自己没了"这类问题(托盘收起、程序化关闭)时用得上。 */
      log_info("[界面] 收到 WM_CLOSE(线程 %lu,stopping=%ld) 最近消息: %04x %04x %04x %04x",
               (unsigned long)GetCurrentThreadId(),
               (long)InterlockedCompareExchange(&g_stopping, 0, 0),
               g_msg_ring[(g_msg_pos - 2) & 7], g_msg_ring[(g_msg_pos - 3) & 7],
               g_msg_ring[(g_msg_pos - 4) & 7], g_msg_ring[(g_msg_pos - 5) & 7]);
      on_close_requested();
      DestroyWindow(h);
      return 0;
    case WM_DESTROY:
      PostQuitMessage(0);
      return 0;
    default:
      break;
  }
  return DefWindowProcW(h, msg, wp, lp);
}

static HWND create_window(void) {
  HINSTANCE inst = GetModuleHandleW(NULL);
  WNDCLASSEXW wc;
  memset(&wc, 0, sizeof(wc));
  wc.cbSize = sizeof(wc);
  wc.style = CS_HREDRAW | CS_VREDRAW;
  wc.lpfnWndProc = wnd_proc;
  wc.hInstance = inst;
  wc.hCursor = LoadCursor(NULL, IDC_ARROW);
  wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
  wc.lpszClassName = L"BwAgentWebViewWnd";
  wc.hIcon = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(1), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);
  wc.hIconSm = wc.hIcon;
  if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
    log_warn("注册窗口类失败(code=%lu)", (unsigned long)GetLastError());
    return NULL;
  }
  /* 尺寸按物理像素算:125% / 150% 的屏上别人看到的是同一块"逻辑大小"。
     不换算的话,高分屏上窗口只占屏幕的六成,界面密密麻麻;
     换算之后还要用工作区夹一下 —— 150% 的 1080p 屏只有 720 逻辑高度,
     按 860 算出来的窗口会顶出屏幕。 */
  int dpi = 96;
  {
    HMODULE u = GetModuleHandleW(L"user32.dll");
    typedef UINT(WINAPI * get_dpi_fn)(void);
    get_dpi_fn get_dpi = u ? (get_dpi_fn)GetProcAddress(u, "GetDpiForSystem") : nullptr;
    if (get_dpi) dpi = (int)get_dpi();
  }
  RECT work;
  if (!SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0)) {
    work.left = 0;
    work.top = 0;
    work.right = GetSystemMetrics(SM_CXSCREEN);
    work.bottom = GetSystemMetrics(SM_CYSCREEN);
  }
  int maxW = (int)((work.right - work.left) * 0.92f);
  int maxH = (int)((work.bottom - work.top) * 0.92f);
  int w = MulDiv(1280, dpi, 96);
  int h = MulDiv(860, dpi, 96);
  if (w > maxW) w = maxW;
  if (h > maxH) h = maxH;
  if (w < 720) w = 720;
  if (h < 480) h = 480;
  int sx = work.left + ((work.right - work.left) - w) / 2;
  int sy = work.top + ((work.bottom - work.top) - h) / 2;
  log_info("[界面] 窗口尺寸 %dx%d(dpi=%d,工作区 %dx%d)", w, h, dpi,
           (int)(work.right - work.left), (int)(work.bottom - work.top));
  wchar_t *title = u8_to_w(g_title);
  HWND hwnd = CreateWindowExW(0, L"BwAgentWebViewWnd", title ? title : L"网站安全巡检",
                              WS_OVERLAPPEDWINDOW, sx < 0 ? 0 : sx, sy < 0 ? 0 : sy, w, h,
                              NULL, NULL, inst, NULL);
  free(title);
  return hwnd;
}

/* ---------------- 线程 ---------------- */
struct BootCtx {
  int port;
  volatile LONG ok;         /* 0 = 还在试,1 = 成,-1 = 放弃 */
  volatile LONG done;       /* 不管成没成,线程都会把它置 1 */
};

static void boot_finish(BootCtx *ctx, int ok) {
  InterlockedExchange(&ctx->ok, ok);
  InterlockedExchange(&ctx->done, 1);
  if (g_boot) SetEvent(g_boot);
}

static DWORD WINAPI webview_thread(LPVOID param) {
  BootCtx *ctx = (BootCtx *)param;
  g_thread_id = GetCurrentThreadId();
  HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
  if (FAILED(hr)) {
    log_warn("WebView2:CoInitializeEx 失败(0x%08lx)", (unsigned long)hr);
    boot_finish(ctx, -1);
    return 0;
  }

  g_hwnd = create_window();
  if (!g_hwnd) {
    CoUninitialize();
    boot_finish(ctx, -1);
    return 0;
  }
  ShowWindow(g_hwnd, SW_SHOW);
  UpdateWindow(g_hwnd);

  char loader[MAX_PATH * 2];
  HMODULE mod = NULL;
  if (extract_loader(loader, sizeof(loader)) == 0) {
    wchar_t *wl = u8_to_w(loader);
    if (wl) {
      mod = LoadLibraryW(wl);
      free(wl);
    }
  }
  typedef HRESULT(STDAPICALLTYPE *create_env_fn)(
      PCWSTR, PCWSTR, ICoreWebView2EnvironmentOptions *,
      ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *);
  create_env_fn create_env =
      mod ? (create_env_fn)GetProcAddress(mod, "CreateCoreWebView2EnvironmentWithOptions") : nullptr;
  if (!create_env) {
    log_warn("WebView2:加载器不可用(%s),退回系统浏览器窗口",
             loader[0] ? loader : "未释放出来");
    DestroyWindow(g_hwnd);
    g_hwnd = NULL;
    CoUninitialize();
    boot_finish(ctx, -1);
    return 0;
  }

  char profile[MAX_PATH * 2];
  app_data_path(profile, sizeof(profile), "webview2");
  ensure_dir(profile);
  wchar_t *wprofile = u8_to_w(profile);

  /* 运行时目录自己找(原因见 find_runtime_dir 上面的注释)。
     找不到就传 NULL,让加载器按它自己的规则找;再失败就退回系统浏览器。 */
  char rt[MAX_PATH * 4] = {0};
  int have_rt = find_runtime_dir(rt, sizeof(rt));
  wchar_t *wrt = have_rt ? u8_to_w(rt) : NULL;
  if (have_rt) log_info("[界面] WebView2 运行时:%s", rt);
  set_browser_args();

  EnvDone *envDone = new EnvDone();
  envDone->fn = [ctx](HRESULT hr2, ICoreWebView2Environment *env) {
    if (FAILED(hr2) || !env) {
      log_warn("WebView2:环境创建失败(0x%08lx)%s", (unsigned long)hr2,
               runtime_present() ? "" : " —— 这台机器没装 WebView2 运行时");
      boot_finish(ctx, -1);
      if (g_hwnd) PostMessageW(g_hwnd, WM_CLOSE, 0, 0);
      return;
    }
    g_env = env;
    g_env->AddRef();

    CtlDone *ctlDone = new CtlDone();
    ctlDone->fn = [ctx](HRESULT hr3, ICoreWebView2Controller *ctl) {
      if (FAILED(hr3) || !ctl) {
        log_warn("WebView2:控制器创建失败(0x%08lx)", (unsigned long)hr3);
        boot_finish(ctx, -1);
        return;
      }
      g_ctl = ctl;
      g_ctl->AddRef();
      g_ctl->put_IsVisible(TRUE);
      layout();
      if (FAILED(g_ctl->get_CoreWebView2(&g_web)) || !g_web) {
        log_warn("WebView2:拿不到 CoreWebView2");
        boot_finish(ctx, -1);
        return;
      }
      ICoreWebView2Settings *st = nullptr;
      if (SUCCEEDED(g_web->get_Settings(&st)) && st) {
        st->put_AreDevToolsEnabled(FALSE);
        st->put_AreDefaultContextMenusEnabled(FALSE);
        st->put_IsStatusBarEnabled(FALSE);
        st->put_IsZoomControlEnabled(FALSE);
        st->put_AreHostObjectsAllowed(FALSE);
        st->put_IsWebMessageEnabled(FALSE);
        st->Release();
      }
      EventRegistrationToken tok;
      NewWindowDone *nw = new NewWindowDone();
      g_web->add_NewWindowRequested(nw, &tok);
      nw->Release();

      wchar_t url[128];
      swprintf(url, 128, L"http://127.0.0.1:%d/", ctx->port);
      if (FAILED(g_web->Navigate(url))) {
        log_warn("WebView2:导航失败");
        boot_finish(ctx, -1);
        return;
      }
      InterlockedExchange(&g_backend, 1);
      InterlockedExchange(&g_ready, 1);
      boot_finish(ctx, 1);
    };
    g_env->CreateCoreWebView2Controller(g_hwnd, ctlDone);
    ctlDone->Release();
  };
  HRESULT ehr = create_env(wrt, wprofile, nullptr, envDone);
  envDone->Release();
  free(wrt);
  free(wprofile);
  if (FAILED(ehr)) {
    log_warn("WebView2:CreateCoreWebView2EnvironmentWithOptions 失败(0x%08lx)", (unsigned long)ehr);
    if (g_hwnd) {
      DestroyWindow(g_hwnd);
      g_hwnd = NULL;
    }
    CoUninitialize();
    boot_finish(ctx, -1);
    return 0;
  }

  MSG msg;
  while (GetMessageW(&msg, NULL, 0, 0) > 0) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }

  InterlockedExchange(&g_ready, 0);
  InterlockedExchange(&g_stopping, 0);
  if (g_web) { g_web->Release(); g_web = nullptr; }
  if (g_ctl) { g_ctl->Release(); g_ctl = nullptr; }
  if (g_env) { g_env->Release(); g_env = nullptr; }
  if (mod) FreeLibrary(mod);
  g_hwnd = NULL;
  CoUninitialize();
  if (ctx->done == 0) boot_finish(ctx, -1);
  return 0;
}

int webview_start(int port, const char *title) {
  /* 上一次的窗口关掉了(收进托盘、或 --debug 时手动关的):线程已经退出,
     把句柄收干净再开新的 —— 否则"重新打开"会被 g_thread 那条判断挡回去。 */
  if (g_thread) {
    if (WaitForSingleObject(g_thread, 0) == WAIT_OBJECT_0) {
      CloseHandle(g_thread);
      g_thread = NULL;
      g_thread_id = 0;
    } else if (g_ready) {
      return 0;                  /* 还开着:叫到前台就行,不重建 */
    } else {
      return -1;                 /* 正在启动中 */
    }
  }
  g_port = port;
  if (title && *title) snprintf(g_title, sizeof(g_title), "%s · %d", title, port);

  g_boot = CreateEventW(NULL, TRUE, FALSE, NULL);
  BootCtx ctx;
  ctx.port = port;
  ctx.ok = 0;
  ctx.done = 0;
  g_thread = CreateThread(NULL, 0, webview_thread, &ctx, 0, NULL);
  if (!g_thread) {
    if (g_boot) { CloseHandle(g_boot); g_boot = NULL; }
    return -1;
  }

  /* 等它把页面画出来:成功就返回 0;失败/超时(5 秒)则收摊,让调用方退回系统浏览器。
     期间 ctx 在本栈上,所以必须等线程把结果写完再走。 */
  WaitForSingleObject(g_boot, 5000);
  int ok = ctx.done && ctx.ok > 0;
  if (g_boot) { CloseHandle(g_boot); g_boot = NULL; }
  if (!ok) {
    webview_stop();
    return -1;
  }
  log_info("界面已用 WebView2 打开(端口 %d)", port);
  return 0;
}

void webview_show(void) {
  if (!g_hwnd) return;
  if (IsIconic(g_hwnd)) ShowWindow(g_hwnd, SW_RESTORE);
  else ShowWindow(g_hwnd, SW_SHOW);
  HWND fg = GetForegroundWindow();
  DWORD fg_tid = fg ? GetWindowThreadProcessId(fg, NULL) : 0;
  DWORD my_tid = GetCurrentThreadId();
  int attached = 0;
  if (fg_tid && fg_tid != my_tid) attached = AttachThreadInput(my_tid, fg_tid, TRUE);
  BringWindowToTop(g_hwnd);
  SetForegroundWindow(g_hwnd);
  if (attached) AttachThreadInput(my_tid, fg_tid, FALSE);
  if (g_ctl) g_ctl->MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
}

void webview_stop(void) {
  InterlockedExchange(&g_stopping, 1);
  if (g_hwnd) PostMessageW(g_hwnd, WM_CLOSE, 0, 0);
  if (g_thread) {
    DWORD tid = g_thread_id;
    if (tid) PostThreadMessageW(tid, WM_QUIT, 0, 0);
    WaitForSingleObject(g_thread, 3000);
    CloseHandle(g_thread);
    g_thread = NULL;
  }
  g_thread_id = 0;
}
