/* native_ui.cpp —— 原生窗口骨架(N1)。
 *
 * 这一版只做"壳":三栏布局、可拖分隔条、深/浅一致的纸白配色、托盘接管。
 * 不做的事情同样重要:这里不碰业务,不直接调 store / agent / net ——
 * 界面只通过 HTTP 接口和智能体说话,和网页版是同一条边界。
 * 这样即便以后把界面再换一次,后端一行都不用动。
 *
 * 绘制用 GDI+ 双缓冲:圆角、细线、抗锯齿文字都能画,而且 gdiplus.dll
 * 是系统自带(Win7+),不破坏"单文件、零依赖"这条底线。
 */
#include "native_ui.h"

#include <windows.h>
#include <gdiplus.h>
#include <windowsx.h>

#include <string>
#include <vector>

#include "common.h"
#include "http.h"
#include "tray.h"
#include "ui.h"

using namespace Gdiplus;

namespace {

/* ---------- 配色:和网页版同一套纸白,换壳不换性格 ---------- */
const ARGB C_BG        = 0xFFFAF9F6;
const ARGB C_PANEL     = 0xFFFFFFFF;
const ARGB C_LINE      = 0xFFE5E5DF;
const ARGB C_LINE2     = 0xFFD6D6CF;
const ARGB C_INK       = 0xFF191914;
const ARGB C_INK2      = 0xFF4C4C46;
const ARGB C_INK3      = 0xFF74746C;
const ARGB C_ACCENT    = 0xFF0B4C9A;

HWND  g_hwnd = NULL;
HANDLE g_thread = NULL;
DWORD g_tid = 0;
int   g_port = 0;
volatile LONG g_ready = 0;
ULONG_PTR g_gdi_tok = 0;

/* 布局:三栏宽度 + 分隔条。拖动改的是这两个变量,松手落注册表(记事本可改)。 */
int g_side_w = 252;
int g_rail_w = 320;
const int SPLIT_W = 6;

/* 拖动状态:0 无 / 1 左分隔 / 2 右分隔 */
int g_drag = 0;
int g_drag_x = 0;
int g_drag_start = 0;

/* 鼠标悬停的分隔条(0/1/2),用来画高亮 */
int g_hot = 0;

const wchar_t *W(const char *s) {
  static wchar_t buf[8][512];
  static int slot = 0;
  slot = (slot + 1) % 8;
  wchar_t *w = u8_to_w(s ? s : "");
  if (!w) { buf[slot][0] = 0; return buf[slot]; }
  wcsncpy_s(buf[slot], 512, w, _TRUNCATE);
  free(w);
  return buf[slot];
}

void draw_text(Graphics &g, const wchar_t *text, const RectF &box, float size,
               ARGB color, int style, int align, int valign) {
  if (!text || !*text) return;
  FontFamily fam(L"Microsoft YaHei UI");
  Font font(&fam, size, style, UnitPixel);
  StringFormat fmt;
  fmt.SetAlignment((StringAlignment)align);
  fmt.SetLineAlignment((StringAlignment)valign);
  fmt.SetTrimming(StringTrimmingEllipsisCharacter);
  fmt.SetFormatFlags(StringFormatFlagsNoWrap);
  SolidBrush brush{Color(color)};
  g.DrawString(text, -1, &font, box, &fmt, &brush);
}

void fill_rect(Graphics &g, const RectF &r, ARGB color) {
  SolidBrush b{Color(color)};
  g.FillRectangle(&b, r);
}

void line_v(Graphics &g, float x, float y1, float y2, ARGB color) {
  Pen p(Color(color), 1.0f);
  g.DrawLine(&p, x, y1, x, y2);
}

void line_h(Graphics &g, float x1, float y1, float x2, ARGB color) {
  Pen p(Color(color), 1.0f);
  g.DrawLine(&p, x1, y1, x2, y1);
}

/* ---------- 布局计算:三栏 + 两条分隔条 ---------- */
struct layout_t {
  RectF side, left_split, main, right_split, rail;
};

layout_t layout_of(int w, int h) {
  layout_t L;
  int side = g_side_w;
  int rail = g_rail_w;
  /* 侧栏最少给主区留 420px:窗口拉窄时先压侧栏,再压右栏 */
  int min_main = 420;
  if (side + rail + min_main + SPLIT_W * 2 > w) {
    int over = side + rail + min_main + SPLIT_W * 2 - w;
    int cut_rail = over / 2 > rail - 200 ? rail - 200 : over / 2;
    if (cut_rail > 0) { rail -= cut_rail; over -= cut_rail; }
    if (over > 0) side -= over > side - 180 ? side - 180 : over;
  }

  L.side = RectF(0, 0, (REAL)side, (REAL)h);
  L.left_split = RectF((REAL)side, 0, (REAL)SPLIT_W, (REAL)h);
  L.rail = RectF((REAL)(w - rail), 0, (REAL)rail, (REAL)h);
  L.right_split = RectF((REAL)(w - rail - SPLIT_W), 0, (REAL)SPLIT_W, (REAL)h);
  float mx = (REAL)(side + SPLIT_W);
  float mw = (REAL)(w - rail - SPLIT_W) - mx;
  L.main = RectF(mx, 0, mw < 1 ? 1 : mw, (REAL)h);
  return L;
}

/* ---------- 骨架绘制 ---------- */
void draw_splitter(Graphics &g, const RectF &r, int which) {
  float cx = r.X + r.Width / 2.0f;
  bool hot = (g_hot == which);
  line_v(g, cx, r.Y, r.Y + r.Height, hot ? 0xFFB8B8B1 : C_LINE);
}

void draw_side(Graphics &g, const RectF &r) {
  fill_rect(g, r, C_BG);
  line_v(g, r.X + r.Width - 1, r.Y, r.Y + r.Height, C_LINE);

  /* 品牌行 */
  RectF brand(r.X + 14, r.Y + 13, r.Width - 28, 22);
  draw_text(g, L"网站安全巡检", brand, 14.0f, C_INK, FontStyleBold,
            StringAlignmentNear, StringAlignmentCenter);

  /* 主按钮 */
  RectF btn(r.X + 14, r.Y + 47, r.Width - 28, 34);
  SolidBrush btn_fill{Color(0xFFFFFFFF)};
  Pen edge(Color(C_LINE2), 1.0f);
  g.FillRectangle(&btn_fill, btn);
  g.DrawRectangle(&edge, btn);
  draw_text(g, L"＋ 新建巡检", RectF(btn.X + 10, btn.Y, btn.Width - 20, btn.Height),
            13.0f, C_INK, FontStyleRegular, StringAlignmentNear, StringAlignmentCenter);

  /* 分组标题 */
  RectF grp(r.X + 14, r.Y + 96, r.Width - 28, 18);
  draw_text(g, L"进行中", grp, 11.5f, C_INK3, FontStyleRegular,
            StringAlignmentNear, StringAlignmentCenter);

  RectF item(r.X + 10, r.Y + 118, r.Width - 20, 52);
  wchar_t line1[256];
  swprintf(line1, 256, L"暂无对话 · 服务端口 %d", g_port);
  draw_text(g, line1, RectF(item.X + 8, item.Y + 6, item.Width - 16, 18), 12.5f,
            C_INK2, FontStyleRegular, StringAlignmentNear, StringAlignmentCenter);
  draw_text(g, L"说一句话就会出现在这里", RectF(item.X + 8, item.Y + 26, item.Width - 16, 16),
            11.5f, C_INK3, FontStyleRegular, StringAlignmentNear, StringAlignmentCenter);

  /* 底部:授权状态 */
  RectF foot(r.X, r.Y + r.Height - 52, r.Width, 52);
  line_h(g, r.X, foot.Y, r.X + r.Width, C_LINE);
  draw_text(g, L"授权池", RectF(r.X + 14, foot.Y + 8, r.Width - 28, 16), 11.5f,
            C_INK3, FontStyleRegular, StringAlignmentNear, StringAlignmentCenter);
  draw_text(g, L"在设置里添加被检目标", RectF(r.X + 14, foot.Y + 25, r.Width - 28, 16),
            11.5f, C_INK2, FontStyleRegular, StringAlignmentNear, StringAlignmentCenter);
}

void draw_main(Graphics &g, const RectF &r) {
  fill_rect(g, r, C_BG);

  /* 标题栏(不是系统标题栏,只是内容区的一条) */
  RectF head(r.X, r.Y, r.Width, 52);
  line_h(g, r.X, head.Y + head.Height, r.X + r.Width, C_LINE);
  draw_text(g, L"巡检会话", RectF(r.X + 20, head.Y, 240, head.Height), 15.0f, C_INK,
            FontStyleBold, StringAlignmentNear, StringAlignmentCenter);
  draw_text(g, L"原生界面 · 骨架", RectF(r.X + r.Width - 220, head.Y, 200, head.Height),
            11.5f, C_INK3, FontStyleRegular, StringAlignmentFar, StringAlignmentCenter);

  /* 空态 */
  RectF empty(r.X + 20, head.Y + head.Height + 40, r.Width - 40, 60);
  draw_text(g, L"还没有开始", RectF(empty.X, empty.Y, empty.Width, 22), 15.0f, C_INK,
            FontStyleBold, StringAlignmentCenter, StringAlignmentCenter);
  draw_text(g, L"输入要查什么，过程和证据会显示在这里。",
            RectF(empty.X, empty.Y + 26, empty.Width, 20), 12.5f, C_INK3,
            FontStyleRegular, StringAlignmentCenter, StringAlignmentCenter);

  /* 输入区:先画一个真的输入框的样子(交互在 N2 接上) */
  RectF compose(r.X, r.Y + r.Height - 104, r.Width, 104);
  fill_rect(g, compose, 0xFFFAF9F6);
  line_h(g, r.X, compose.Y, r.X + r.Width, C_LINE);
  RectF field(compose.X + 20, compose.Y + 16, compose.Width - 40, 40);
  {
    GraphicsPath path;
    float rad = 8.0f;
    path.AddArc(field.X, field.Y, rad * 2, rad * 2, 180, 90);
    path.AddArc(field.X + field.Width - rad * 2, field.Y, rad * 2, rad * 2, 270, 90);
    path.AddArc(field.X + field.Width - rad * 2, field.Y + field.Height - rad * 2, rad * 2, rad * 2, 0, 90);
    path.AddArc(field.X, field.Y + field.Height - rad * 2, rad * 2, rad * 2, 90, 90);
    path.CloseFigure();
    SolidBrush fill{Color(0xFFFFFFFF)};
    Pen edge(Color(C_LINE2), 1.0f);
    g.FillPath(&fill, &path);
    g.DrawPath(&edge, &path);
  }
  draw_text(g, L"继续追问…", RectF(field.X + 12, field.Y, field.Width - 100, field.Height),
            13.0f, 0xFF9D9D94, FontStyleRegular, StringAlignmentNear, StringAlignmentCenter);

  RectF send(field.X + field.Width - 76, field.Y + 7, 64, 26);
  {
    GraphicsPath p2;
    float rad = 6.0f;
    p2.AddArc(send.X, send.Y, rad * 2, rad * 2, 180, 90);
    p2.AddArc(send.X + send.Width - rad * 2, send.Y, rad * 2, rad * 2, 270, 90);
    p2.AddArc(send.X + send.Width - rad * 2, send.Y + send.Height - rad * 2, rad * 2, rad * 2, 0, 90);
    p2.AddArc(send.X, send.Y + send.Height - rad * 2, rad * 2, rad * 2, 90, 90);
    p2.CloseFigure();
    SolidBrush b{Color(C_INK)};
    g.FillPath(&b, &p2);
  }
  draw_text(g, L"执行", RectF(send.X, send.Y, send.Width, send.Height), 12.5f,
            0xFFFDFCF9, FontStyleBold, StringAlignmentCenter, StringAlignmentCenter);

  draw_text(g, L"这条界面还在搭建中：对话与审批会在下一步接上。",
            RectF(compose.X + 20, compose.Y + 64, compose.Width - 40, 20), 11.5f, C_INK3,
            FontStyleRegular, StringAlignmentNear, StringAlignmentCenter);
}

void draw_rail(Graphics &g, const RectF &r) {
  fill_rect(g, r, C_BG);
  line_v(g, r.X, r.Y, r.Y + r.Height, C_LINE);

  RectF head(r.X, r.Y, r.Width, 44);
  line_h(g, r.X, head.Y + head.Height, r.X + r.Width, C_LINE);
  draw_text(g, L"产物", RectF(r.X + 14, head.Y, 120, head.Height), 12.0f, C_INK3,
            FontStyleRegular, StringAlignmentNear, StringAlignmentCenter);

  float y = head.Y + head.Height + 13;
  const wchar_t *titles[] = {L"报告", L"过程要点", L"本轮留痕", L"边界"};
  const wchar_t *bodies[] = {L"跑完一轮后自动生成", L"执行后按步列出", L"还没有执行过循环",
                             L"授权池 · 只读 · 2 请求/秒"};
  for (int i = 0; i < 4; i++) {
    RectF card(r.X + 13, y, r.Width - 26, 64);
    SolidBrush b{Color(C_PANEL)};
    Pen e(Color(C_LINE2), 1.0f);
    g.FillRectangle(&b, card);
    g.DrawRectangle(&e, card);
    draw_text(g, titles[i], RectF(card.X + 11, card.Y + 8, card.Width - 22, 16), 11.5f,
              C_INK3, FontStyleRegular, StringAlignmentNear, StringAlignmentCenter);
    draw_text(g, bodies[i], RectF(card.X + 11, card.Y + 27, card.Width - 22, 18), 12.5f,
              C_INK2, FontStyleRegular, StringAlignmentNear, StringAlignmentCenter);
    y += 76;
  }
}

void render(HWND hwnd) {
  RECT rc;
  GetClientRect(hwnd, &rc);
  int w = rc.right - rc.left, h = rc.bottom - rc.top;
  if (w <= 0 || h <= 0) return;

  /* 双缓冲:先在位图上画完再一次性贴,拖动分隔条时不闪 */
  HDC hdc = GetDC(hwnd);
  HDC mem = CreateCompatibleDC(hdc);
  HBITMAP bmp = CreateCompatibleBitmap(hdc, w, h);
  HBITMAP old = (HBITMAP)SelectObject(mem, bmp);
  {
    Graphics g(mem);
    g.SetSmoothingMode(SmoothingModeAntiAlias);
    g.SetTextRenderingHint(TextRenderingHintClearTypeGridFit);
    g.SetPixelOffsetMode(PixelOffsetModeHighQuality);
    fill_rect(g, RectF(0, 0, (REAL)w, (REAL)h), C_BG);

    layout_t L = layout_of(w, h);
    draw_side(g, L.side);
    draw_splitter(g, L.left_split, 1);
    draw_main(g, L.main);
    draw_splitter(g, L.right_split, 2);
    draw_rail(g, L.rail);
  }
  BitBlt(hdc, 0, 0, w, h, mem, 0, 0, SRCCOPY);
  SelectObject(mem, old);
  DeleteObject(bmp);
  DeleteDC(mem);
  ReleaseDC(hwnd, hdc);
}

/* 拖动结束后把宽度写进注册表:下次打开还是你调过的样子 */
void save_layout(void) {
  HKEY k;
  if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\BwAgent\\Ui", 0, NULL, 0,
                      KEY_WRITE, NULL, &k, NULL) != ERROR_SUCCESS) return;
  DWORD a = (DWORD)g_side_w, b = (DWORD)g_rail_w;
  RegSetValueExW(k, L"side", 0, REG_DWORD, (const BYTE *)&a, sizeof(a));
  RegSetValueExW(k, L"rail", 0, REG_DWORD, (const BYTE *)&b, sizeof(b));
  RegCloseKey(k);
}

void load_layout(void) {
  HKEY k;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\BwAgent\\Ui", 0, KEY_READ, &k) != ERROR_SUCCESS)
    return;
  DWORD v = 0, sz = sizeof(v), type = 0;
  if (RegQueryValueExW(k, L"side", NULL, &type, (BYTE *)&v, &sz) == ERROR_SUCCESS && v >= 180 &&
      v <= 520)
    g_side_w = (int)v;
  sz = sizeof(v);
  if (RegQueryValueExW(k, L"rail", NULL, &type, (BYTE *)&v, &sz) == ERROR_SUCCESS && v >= 220 &&
      v <= 640)
    g_rail_w = (int)v;
  RegCloseKey(k);
}

int hit_splitter(int x, int y, int w, int h) {
  (void)y;
  (void)h;
  layout_t L = layout_of(w, h);
  if (x >= L.left_split.X - 2 && x <= L.left_split.X + L.left_split.Width + 2) return 1;
  if (x >= L.right_split.X - 2 && x <= L.right_split.X + L.right_split.Width + 2) return 2;
  return 0;
}

void apply_cursor(HWND hwnd, int which) {
  static HCURSOR cur_split = NULL;
  static HCURSOR cur_arrow = NULL;
  if (!cur_split) cur_split = LoadCursor(NULL, IDC_SIZEWE);
  if (!cur_arrow) cur_arrow = LoadCursor(NULL, IDC_ARROW);
  SetCursor(which ? cur_split : cur_arrow);
}

LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_CREATE:
      load_layout();
      return 0;

    case WM_SIZE:
      InvalidateRect(hwnd, NULL, FALSE);
      return 0;

    case WM_ERASEBKGND:
      return 1;                       /* 全部由双缓冲重画,别让系统先刷一遍白 */

    case WM_PAINT: {
      PAINTSTRUCT ps;
      BeginPaint(hwnd, &ps);
      render(hwnd);
      EndPaint(hwnd, &ps);
      return 0;
    }

    case WM_SETCURSOR: {
      GetCursorPos(NULL);
      POINT p;
      GetCursorPos(&p);
      ScreenToClient(hwnd, &p);
      RECT rc;
      GetClientRect(hwnd, &rc);
      apply_cursor(hwnd, hit_splitter(p.x, p.y, rc.right, rc.bottom));
      return TRUE;
    }

    case WM_MOUSEMOVE: {
      int x = GET_X_LPARAM(lp), y = GET_Y_LPARAM(lp);
      RECT rc;
      GetClientRect(hwnd, &rc);
      if (g_drag) {
        int dx = x - g_drag_x;
        if (g_drag == 1) {
          int v = g_drag_start + dx;
          if (v < 180) v = 180;
          if (v > rc.right / 2) v = rc.right / 2;
          g_side_w = v;
        } else if (g_drag == 2) {
          int v = g_drag_start - dx;
          if (v < 220) v = 220;
          if (v > rc.right / 2) v = rc.right / 2;
          g_rail_w = v;
        }
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
      }
      int hot = hit_splitter(x, y, rc.right, rc.bottom);
      if (hot != g_hot) {
        g_hot = hot;
        InvalidateRect(hwnd, NULL, FALSE);
      }
      return 0;
    }

    case WM_LBUTTONDOWN: {
      int x = GET_X_LPARAM(lp), y = GET_Y_LPARAM(lp);
      RECT rc;
      GetClientRect(hwnd, &rc);
      int which = hit_splitter(x, y, rc.right, rc.bottom);
      if (which) {
        g_drag = which;
        g_drag_x = x;
        g_drag_start = (which == 1) ? g_side_w : g_rail_w;
        SetCapture(hwnd);
      }
      return 0;
    }

    case WM_LBUTTONUP:
      if (g_drag) {
        g_drag = 0;
        ReleaseCapture();
        save_layout();
      }
      return 0;

    case WM_CLOSE:
      /* 关窗口 = 收进托盘,不是退出。彻底退出走托盘右键菜单。 */
      ShowWindow(hwnd, SW_HIDE);
      if (tray_active()) {
        tray_balloon("仍在后台运行", "周期巡检会继续。右键托盘图标可重新打开或彻底退出。");
        log_info("原生窗口已收起,程序留在托盘");
      } else {
        http_stop();
        PostQuitMessage(0);
      }
      return 0;

    case WM_DESTROY:
      PostQuitMessage(0);
      return 0;

    default:
      break;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

DWORD WINAPI ui_thread(LPVOID param) {
  (void)param;
  GdiplusStartupInput in;
  if (GdiplusStartup(&g_gdi_tok, &in, NULL) != Ok) {
    log_warn("GDI+ 初始化失败,原生界面不可用");
    return 1;
  }

  WNDCLASSEXW wc;
  memset(&wc, 0, sizeof(wc));
  wc.cbSize = sizeof(wc);
  wc.style = CS_HREDRAW | CS_VREDRAW;
  wc.lpfnWndProc = wnd_proc;
  wc.hInstance = GetModuleHandleW(NULL);
  wc.hCursor = LoadCursor(NULL, IDC_ARROW);
  wc.hbrBackground = NULL;
  wc.lpszClassName = L"BwAgentNativeWnd";
  if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
    GdiplusShutdown(g_gdi_tok);
    return 1;
  }

  int w = 1280, h = 860;
  int sx = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
  int sy = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;
  g_hwnd = CreateWindowExW(0, L"BwAgentNativeWnd", L"网站安全巡检", WS_OVERLAPPEDWINDOW,
                           sx < 0 ? 0 : sx, sy < 0 ? 0 : sy, w, h, NULL, NULL,
                           wc.hInstance, NULL);
  if (!g_hwnd) {
    log_warn("原生窗口创建失败(code=%lu)", GetLastError());
    GdiplusShutdown(g_gdi_tok);
    return 1;
  }

  g_tid = GetCurrentThreadId();
  ShowWindow(g_hwnd, SW_SHOW);
  UpdateWindow(g_hwnd);
  InterlockedExchange(&g_ready, 1);
  log_info("原生窗口已打开(端口 %d)", g_port);

  MSG m;
  while (GetMessageW(&m, NULL, 0, 0) > 0) {
    TranslateMessage(&m);
    DispatchMessageW(&m);
  }

  if (g_hwnd) { DestroyWindow(g_hwnd); g_hwnd = NULL; }
  InterlockedExchange(&g_ready, 0);
  if (g_gdi_tok) { GdiplusShutdown(g_gdi_tok); g_gdi_tok = 0; }
  return 0;
}

}  // namespace

int native_ui_start(int port, const char *title) {
  (void)title;
  if (g_thread) return 0;
  g_port = port;
  g_thread = CreateThread(NULL, 0, ui_thread, NULL, 0, NULL);
  if (!g_thread) return -1;
  for (int i = 0; i < 80 && !g_ready; i++) Sleep(25);
  return g_ready ? 0 : -1;
}

void native_ui_show(void) {
  if (!g_hwnd) return;
  ShowWindow(g_hwnd, SW_SHOW);
  SetForegroundWindow(g_hwnd);
}

int native_ui_active(void) { return g_ready ? 1 : 0; }

void native_ui_stop(void) {
  if (!g_thread) return;
  if (g_tid) PostThreadMessageW(g_tid, WM_QUIT, 0, 0);
  WaitForSingleObject(g_thread, 3000);
  CloseHandle(g_thread);
  g_thread = NULL;
  g_tid = 0;
}
