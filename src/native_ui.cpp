/* native_ui.cpp —— 原生界面宿主(N1 骨架 + N2 对话)。
 *
 * 这里不碰业务:不直接调 store / agent / net —— 界面只通过本地 HTTP 接口
 * 和智能体说话,和网页版是同一条边界。这样即便以后再换一次界面,
 * 后端一行都不用动。
 *
 * 绘制用 GDI+ 双缓冲:圆角、细线、抗锯齿文字都能画,而且 gdiplus.dll
 * 是系统自带(Win7+),不破坏"单文件、零依赖"这条底线。
 *
 * 输入框用系统 EDIT 控件而不是自己收按键:中文输入法(IME)、选区、
 * 复制粘贴、Unicode 这些"看起来简单"的事,系统控件已经做对了。
 */
#include "native_ui.h"

/* winsock2 必须排在 windows.h 前面:反过来的话 windows.h 会先拉进 winsock.h,
   两套定义会撞在一起。 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <gdiplus.h>
#include <windowsx.h>

#include <string>
#include <vector>
#include <cwctype>

#include "common.h"
#include "http.h"
#include "json.h"
#include "serve.h"
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

/* ---------- 对话状态(N2) ----------
   界面读写的只有"给人看的那一份":一条消息 = 谁说的 + 一段文字。
   真正的结构化历史在服务端 threads/ 里,这里不复制一份,免得两处说法不一致。 */
#define WM_APP_SEND     (WM_APP + 1)
#define WM_APP_STOP     (WM_APP + 2)
#define WM_APP_REFRESH  (WM_APP + 3)

enum { ROLE_USER = 0, ROLE_BOT = 1, ROLE_NOTE = 2 };

struct chat_msg_t {
  int kind;
  std::wstring text;
  int live;                      /* 正在流式写入 */
};

CRITICAL_SECTION g_chat_lock;
int g_chat_lock_ready = 0;
std::vector<chat_msg_t> g_chat;
volatile LONG g_busy = 0;        /* 一轮正在跑 */
bool g_follow = true;            /* 贴在底部跟随(用户往上翻就取消) */
int g_scroll_top = 0;
int g_view_h = 0;
int g_total_h = 0;

HWND g_edit = NULL;
WNDPROC g_edit_old = NULL;
HFONT g_edit_font = NULL;

SOCKET g_sock = INVALID_SOCKET;
int g_wsa = 0;
char g_session[64] = "desk-1";

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

/* 主区内部的几块:标题条 / 消息流 / 输入区 / 输入框 / 发送按钮。
   绘制、子控件定位、点击命中都从这里取,三处万一写歪了也只歪一处。 */
struct main_parts_t {
  RectF head, list, compose, field, send;
};

main_parts_t main_parts(const RectF &r) {
  main_parts_t M;
  M.head = RectF(r.X, r.Y, r.Width, 52);
  float compose_h = 104;
  M.compose = RectF(r.X, r.Y + r.Height - compose_h, r.Width, compose_h);
  M.list = RectF(r.X, r.Y + 52, r.Width, r.Height - 52 - compose_h);
  M.field = RectF(M.compose.X + 20, M.compose.Y + 16, M.compose.Width - 40, 40);
  M.send = RectF(M.field.X + M.field.Width - 76, M.field.Y + 7, 64, 26);
  return M;
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
  char l1[128];
  snprintf(l1, sizeof(l1), "会话 %s", g_session);
  draw_text(g, W(l1), RectF(item.X + 8, item.Y + 6, item.Width - 16, 18), 12.5f,
            C_INK2, FontStyleRegular, StringAlignmentNear, StringAlignmentCenter);
  snprintf(l1, sizeof(l1), g_busy ? "正在跑 · 端口 %d" : "空闲 · 端口 %d", g_port);
  draw_text(g, W(l1), RectF(item.X + 8, item.Y + 26, item.Width - 16, 16),
            11.5f, C_INK3, FontStyleRegular, StringAlignmentNear, StringAlignmentCenter);

  /* 底部:授权状态 */
  RectF foot(r.X, r.Y + r.Height - 52, r.Width, 52);
  line_h(g, r.X, foot.Y, r.X + r.Width, C_LINE);
  draw_text(g, L"授权池", RectF(r.X + 14, foot.Y + 8, r.Width - 28, 16), 11.5f,
            C_INK3, FontStyleRegular, StringAlignmentNear, StringAlignmentCenter);
  draw_text(g, L"在设置里添加被检目标", RectF(r.X + 14, foot.Y + 25, r.Width - 28, 16),
            11.5f, C_INK2, FontStyleRegular, StringAlignmentNear, StringAlignmentCenter);
}

/* ---------- 消息流的测量与绘制 ----------
   GDI+ 的 DrawString 自带断行(中文按字断、西文按词断),所以不去自己算字宽:
   自己断行要处理标点避头尾、中英混排、emoji,做不好反而更容易出丑。
   高度用 MeasureString 预先量出来,滚动位置才有依据。 */
float measure_body(Graphics &g, const std::wstring &text, Font *font, float width,
                   StringFormat *fmt) {
  if (text.empty()) return 0;
  RectF box(0, 0, width, 100000);
  RectF out;
  g.MeasureString(text.c_str(), (INT)text.size(), font, box, fmt, &out);
  return out.Height;
}

struct msg_block_t {
  const std::wstring *text;
  int kind;
  float y;        /* 相对消息流顶部的偏移 */
  float h;
};

void draw_chat(Graphics &g, const RectF &r) {
  if (!g_chat_lock_ready) return;
  FontFamily fam(L"Microsoft YaHei UI");
  Font f_label(&fam, 11.0f, FontStyleRegular, UnitPixel);
  Font f_body(&fam, 13.5f, FontStyleRegular, UnitPixel);
  Font f_note(&fam, 12.0f, FontStyleRegular, UnitPixel);
  StringFormat wrap;
  wrap.SetFormatFlags(0);                       /* 允许自动换行 */
  wrap.SetTrimming(StringTrimmingNone);
  StringFormat one;
  one.SetFormatFlags(StringFormatFlagsNoWrap);
  one.SetTrimming(StringTrimmingEllipsisCharacter);

  EnterCriticalSection(&g_chat_lock);
  std::vector<msg_block_t> blocks;
  blocks.reserve(g_chat.size());
  float y = 18.0f;
  float pad = 22.0f;
  float cw = r.Width - pad * 2 - 6;
  if (cw < 60) cw = 60;
  for (size_t i = 0; i < g_chat.size(); i++) {
    msg_block_t b;
    b.text = &g_chat[i].text;
    b.kind = g_chat[i].kind;
    b.y = y;
    float body_w = (b.kind == ROLE_NOTE) ? cw : cw;
    b.h = measure_body(g, g_chat[i].text, b.kind == ROLE_NOTE ? (Font *)&f_note : (Font *)&f_body,
                       body_w, &wrap);
    if (b.h < 18) b.h = 18;
    blocks.push_back(b);
    y += b.h + 6;
    if (g_chat[i].kind == ROLE_NOTE) y += 2;
    y += 16;                                    /* 块间距 */
  }
  g_total_h = (int)y + 12;
  g_view_h = (int)r.Height;

  int max_scroll = g_total_h - g_view_h;
  if (max_scroll < 0) max_scroll = 0;
  if (g_follow) g_scroll_top = max_scroll;
  if (g_scroll_top > max_scroll) g_scroll_top = max_scroll;
  if (g_scroll_top < 0) g_scroll_top = 0;

  if (!g_chat.empty()) {
    g.SetClip(RectF(r.X, r.Y, r.Width, r.Height));
    g.TranslateTransform(0, r.Y - (REAL)g_scroll_top);
    for (size_t i = 0; i < blocks.size(); i++) {
      msg_block_t &b = blocks[i];
      float bx = r.X + pad;
      if (b.kind == ROLE_NOTE) {
        SolidBrush nb{Color(C_INK3)};
        g.DrawString(b.text->c_str(), (INT)b.text->size(), &f_note,
                     RectF(bx + 8, b.y, cw, b.h), &wrap, &nb);
        Pen p(Color(C_LINE2), 1.0f);
        g.DrawLine(&p, bx, b.y + 3, bx, b.y + b.h - 3);
      } else {
        const wchar_t *label = (b.kind == ROLE_USER) ? L"你" : L"智能体";
        draw_text(g, label, RectF(bx, b.y - 16, 120, 16), 11.0f,
                  b.kind == ROLE_USER ? C_INK3 : C_ACCENT, FontStyleRegular,
                  StringAlignmentNear, StringAlignmentCenter);
        SolidBrush bb{Color(b.kind == ROLE_USER ? C_INK : C_INK2)};
        g.DrawString(b.text->c_str(), (INT)b.text->size(), &f_body,
                     RectF(bx, b.y, cw, b.h), &wrap, &bb);
      }
    }
    g.ResetTransform();
    g.ResetClip();
    /* 滚动条:细到不影响阅读,但让人知道"下面还有" */
    if (max_scroll > 0) {
      float track = r.Height - 16;
      float ratio = (float)g_view_h / (float)g_total_h;
      float thumb = track * ratio;
      if (thumb < 24) thumb = 24;
      float pos = (float)g_scroll_top / (float)max_scroll * (track - thumb);
      fill_rect(g, RectF(r.X + r.Width - 6, r.Y + 8 + pos, 3, thumb), 0xFFCFCFC7);
    }
  }
  (void)one;
  LeaveCriticalSection(&g_chat_lock);
}

void draw_main(Graphics &g, const RectF &r) {
  fill_rect(g, r, C_BG);
  main_parts_t M = main_parts(r);

  /* 标题条(不是系统标题栏,只是内容区的一条) */
  line_h(g, r.X, M.head.Y + M.head.Height, r.X + r.Width, C_LINE);
  draw_text(g, L"巡检会话", RectF(r.X + 20, M.head.Y, 240, M.head.Height), 15.0f, C_INK,
            FontStyleBold, StringAlignmentNear, StringAlignmentCenter);
  {
    char st[128];
    if (g_busy)
      snprintf(st, sizeof(st), "正在跑 · %s", g_session);
    else
      snprintf(st, sizeof(st), "端口 %d · %s", g_port, g_session);
    draw_text(g, W(st), RectF(r.X + r.Width - 260, M.head.Y, 240, M.head.Height), 11.5f,
              C_INK3, FontStyleRegular, StringAlignmentFar, StringAlignmentCenter);
  }

  /* 消息流 */
  if (g_chat.empty()) {
    RectF empty(M.list.X + 20, M.list.Y + 40, M.list.Width - 40, 60);
    draw_text(g, L"还没有开始", RectF(empty.X, empty.Y, empty.Width, 22), 15.0f, C_INK,
              FontStyleBold, StringAlignmentCenter, StringAlignmentCenter);
    draw_text(g, L"输入要查什么，过程和证据会显示在这里。",
              RectF(empty.X, empty.Y + 26, empty.Width, 20), 12.5f, C_INK3,
              FontStyleRegular, StringAlignmentCenter, StringAlignmentCenter);
  } else {
    draw_chat(g, M.list);
  }

  /* 输入区 */
  fill_rect(g, M.compose, 0xFFFAF9F6);
  line_h(g, r.X, M.compose.Y, r.X + r.Width, C_LINE);
  {
    GraphicsPath path;
    float rad = 8.0f;
    path.AddArc(M.field.X, M.field.Y, rad * 2, rad * 2, 180, 90);
    path.AddArc(M.field.X + M.field.Width - rad * 2, M.field.Y, rad * 2, rad * 2, 270, 90);
    path.AddArc(M.field.X + M.field.Width - rad * 2, M.field.Y + M.field.Height - rad * 2,
                rad * 2, rad * 2, 0, 90);
    path.AddArc(M.field.X, M.field.Y + M.field.Height - rad * 2, rad * 2, rad * 2, 90, 90);
    path.CloseFigure();
    SolidBrush fill{Color(0xFFFFFFFF)};
    Pen edge(Color(C_LINE2), 1.0f);
    g.FillPath(&fill, &path);
    g.DrawPath(&edge, &path);
  }

  {
    GraphicsPath p2;
    float rad = 6.0f;
    p2.AddArc(M.send.X, M.send.Y, rad * 2, rad * 2, 180, 90);
    p2.AddArc(M.send.X + M.send.Width - rad * 2, M.send.Y, rad * 2, rad * 2, 270, 90);
    p2.AddArc(M.send.X + M.send.Width - rad * 2, M.send.Y + M.send.Height - rad * 2, rad * 2,
              rad * 2, 0, 90);
    p2.AddArc(M.send.X, M.send.Y + M.send.Height - rad * 2, rad * 2, rad * 2, 90, 90);
    p2.CloseFigure();
    SolidBrush b{Color(g_busy ? 0xFF9A9A92 : C_INK)};
    g.FillPath(&b, &p2);
  }
  draw_text(g, g_busy ? L"停止" : L"执行", RectF(M.send.X, M.send.Y, M.send.Width, M.send.Height),
            12.5f, 0xFFFDFCF9, FontStyleBold, StringAlignmentCenter, StringAlignmentCenter);

  draw_text(g, L"Enter 发送 · Esc 停止 · 结果同时记在运行记录里",
            RectF(M.compose.X + 20, M.compose.Y + 64, M.compose.Width - 40, 20), 11.5f, C_INK3,
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

/* ================= 对话:本地 HTTP 客户端 + SSE 直播 =================
 *
 * 为什么不复用 net.cpp:那条通道是"对外取证"用的,带授权池、限速、审计;
 * 对自己的 127.0.0.1 接口去走它,反而要先给自己的地址开白名单。
 * 这里就是进程内对自己端口的一次最简单 GET —— 只认回环地址,不碰外面。
 *
 * 为什么不用 WebView/EventSource:因为这里已经没有浏览器了。SSE 只是一行
 * "data: {json}" 加一个空行,自己读反而更可控(停止、超时、半包都能自己决定)。
 */

std::string urlenc(const char *s) {
  static const char *hex = "0123456789ABCDEF";
  std::string o;
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
        *p == '-' || *p == '_' || *p == '.' || *p == '~') {
      o += (char)*p;
    } else {
      o += '%';
      o += hex[*p >> 4];
      o += hex[*p & 15];
    }
  }
  return o;
}

int net_up(void) {
  if (g_wsa) return 1;
  WSADATA w;
  if (WSAStartup(MAKEWORD(2, 2), &w) != 0) return 0;
  g_wsa = 1;
  return 1;
}

SOCKET open_local(void) {
  if (!net_up()) return INVALID_SOCKET;
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) return s;
  sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons((u_short)g_port);
  a.sin_addr.s_addr = htonl(0x7F000001);      /* 127.0.0.1 */
  if (connect(s, (sockaddr *)&a, sizeof(a)) != 0) {
    closesocket(s);
    return INVALID_SOCKET;
  }
  DWORD tv = 400;
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
  return s;
}

bool send_all_local(SOCKET s, const char *data, int len) {
  int off = 0;
  while (off < len) {
    int n = send(s, data + off, len - off, 0);
    if (n <= 0) return false;
    off += n;
  }
  return true;
}

/* 发一条"发了就不用等回话"的请求(停止、取消这类)。 */
void quick_get(const char *path_query) {
  SOCKET s = open_local();
  if (s == INVALID_SOCKET) return;
  char req[1200];
  int n = snprintf(req, sizeof(req),
                   "GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-BW-Token: %s\r\n"
                   "Connection: close\r\n\r\n",
                   path_query, g_port, serve_token());
  if (n > 0) send_all_local(s, req, n);
  char buf[512];
  recv(s, buf, sizeof(buf), 0);               /* 读一点,让服务端把头写出去 */
  closesocket(s);
}

DWORD WINAPI cancel_thread(LPVOID param) {
  (void)param;
  char path[256];
  snprintf(path, sizeof(path), "/api/cancel?sid=%s&t=%s", g_session, serve_token());
  quick_get(path);
  return 0;
}

/* ---------- 消息流的增补(全在 g_chat_lock 下改) ---------- */
void chat_push(int kind, const std::wstring &text, int live) {
  EnterCriticalSection(&g_chat_lock);
  chat_msg_t m;
  m.kind = kind;
  m.text = text;
  m.live = live;
  g_chat.push_back(m);
  LeaveCriticalSection(&g_chat_lock);
}

void chat_append_u8(const char *text) {
  if (!text || !*text) return;
  wchar_t *w = u8_to_w(text);
  if (!w) return;
  EnterCriticalSection(&g_chat_lock);
  if (!g_chat.empty() && g_chat.back().kind == ROLE_BOT) {
    g_chat.back().text += w;
  } else {
    chat_msg_t m;
    m.kind = ROLE_BOT;
    m.live = 1;
    m.text = w;
    g_chat.push_back(m);
  }
  LeaveCriticalSection(&g_chat_lock);
  free(w);
}

void chat_begin_bot(void) {
  EnterCriticalSection(&g_chat_lock);
  if (g_chat.empty() || g_chat.back().kind != ROLE_BOT || !g_chat.back().live) {
    chat_msg_t m;
    m.kind = ROLE_BOT;
    m.live = 1;
    g_chat.push_back(m);
  }
  LeaveCriticalSection(&g_chat_lock);
}

void chat_end_turn(void) {
  EnterCriticalSection(&g_chat_lock);
  for (size_t i = g_chat.size(); i > 0; i--) g_chat[i - 1].live = 0;
  LeaveCriticalSection(&g_chat_lock);
}

/* 工具卡片:一行灰字。名字放前面,状态跟在后面,长结果不往界面上倒
   (要看全文请去产物/运行记录里看,那里是全的)。 */
void chat_tool_note(const char *tool, const char *status) {
  std::wstring line;
  if (status && strcmp(status, "running") == 0) line = L"⚙ 调用 ";
  else if (status && strcmp(status, "error") == 0) line = L"✗ 失败 ";
  else line = L"✓ 完成 ";
  wchar_t *w = u8_to_w(tool && *tool ? tool : "工具");
  if (w) {
    line += w;
    free(w);
  }
  chat_push(ROLE_NOTE, line, 0);
}

/* 一条 SSE 事件 → 界面上看得见的变化 */
void handle_event(const char *json_text) {
  json_t *j = json_parse(json_text);
  if (!j) return;
  const char *type = j_s(j, "type", "");
  if (strcmp(type, "block_start") == 0) {
    const char *bt = j_s(j, "blockType", "");
    if (strcmp(bt, "tool_use") == 0) chat_tool_note(j_s(j, "toolName", "工具"), "running");
    else chat_begin_bot();
  } else if (strcmp(type, "block_delta") == 0) {
    json_t *d = j_get(j, "delta");
    if (d && strcmp(j_s(d, "type", ""), "text_delta") == 0) chat_append_u8(j_s(d, "text", ""));
  } else if (strcmp(type, "tool_status") == 0) {
    /* running 是"开始执行"的补充说明,已经在卡片上写过了,不再重复刷屏 */
  } else if (strcmp(type, "approval_request") == 0) {
    chat_push(ROLE_NOTE, L"⏸ 有一个动作需要你确认(审批条在 N3 接上)", 0);
  } else if (strcmp(type, "message_stop") == 0) {
    chat_end_turn();
  }
  json_free(j);
}

/* 一轮对话的工人线程:发请求 → 读 SSE → 每个事件改一次界面 */
DWORD WINAPI turn_thread(LPVOID param) {
  std::string *q = (std::string *)param;
  std::string qs = q ? *q : std::string();
  delete q;

  std::string eq = urlenc(qs.c_str());
  std::string line = "/api/chat?q=" + eq + "&sid=" + g_session + "&t=" + serve_token();

  SOCKET s = open_local();
  if (s == INVALID_SOCKET) {
    chat_push(ROLE_NOTE, L"连不上本地服务:端口可能被别的程序占着", 0);
    InterlockedExchange(&g_busy, 0);
    if (g_hwnd) PostMessageW(g_hwnd, WM_APP_REFRESH, 0, 0);
    return 0;
  }
  EnterCriticalSection(&g_chat_lock);
  g_sock = s;
  LeaveCriticalSection(&g_chat_lock);

  std::string head = "GET " + line + " HTTP/1.1\r\nHost: 127.0.0.1:" +
                     std::to_string(g_port) + "\r\nX-BW-Token: " + serve_token() +
                     "\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n";
  if (!send_all_local(s, head.data(), (int)head.size())) {
    closesocket(s);
    g_sock = INVALID_SOCKET;
    chat_push(ROLE_NOTE, L"请求发不出去:服务可能已经停了", 0);
    InterlockedExchange(&g_busy, 0);
    if (g_hwnd) PostMessageW(g_hwnd, WM_APP_REFRESH, 0, 0);
    return 0;
  }

  std::string pending;
  int headers_done = 0, is_sse = 0, idle = 0, aborted = 0;
  char buf[8192];
  for (;;) {
    int got = recv(s, buf, (int)sizeof(buf), 0);
    if (got > 0) {
      idle = 0;
      pending.append(buf, (size_t)got);
    } else if (got == 0) {
      break;                                   /* 服务端收工 */
    } else {
      int e = WSAGetLastError();
      if (e == WSAETIMEDOUT) {
        if (++idle > 1800) break;              /* 12 分钟没动静,当作断了 */
        continue;
      }
      aborted = 1;
      break;
    }

    if (!headers_done) {
      size_t at = pending.find("\r\n\r\n");
      if (at == std::string::npos) continue;
      std::string h = pending.substr(0, at);
      is_sse = h.find("text/event-stream") != std::string::npos;
      pending.erase(0, at + 4);
      headers_done = 1;
    }

    if (!is_sse) {
      if (pending.size() > 8192) pending.resize(8192);   /* 错误应答,别越攒越大 */
      continue;
    }

    size_t at;
    while ((at = pending.find("\n\n")) != std::string::npos) {
      std::string ev = pending.substr(0, at);
      pending.erase(0, at + 2);
      if (ev.compare(0, 6, "data: ") == 0) handle_event(ev.c_str() + 6);
    }
    if (g_hwnd) PostMessageW(g_hwnd, WM_APP_REFRESH, 0, 0);
  }
  closesocket(s);
  g_sock = INVALID_SOCKET;

  if (!is_sse) {
    /* 没开 SSE 说明被服务端挡了(令牌/授权池/参数),把原话读出来给人看 */
    size_t at = pending.find('{');
    if (headers_done && at != std::string::npos) {
      json_t *j = json_parse(pending.c_str() + at);
      if (j) {
        wchar_t *w = u8_to_w(j_s(j, "error", "请求被拒绝"));
        if (w) {
          chat_push(ROLE_NOTE, std::wstring(L"没能开始:") + w, 0);
          free(w);
        }
        json_free(j);
      }
    }
  } else if (aborted) {
    chat_push(ROLE_NOTE, L"这条流断了(服务可能已经退出)", 0);
  }
  chat_end_turn();
  InterlockedExchange(&g_busy, 0);
  if (g_hwnd) PostMessageW(g_hwnd, WM_APP_REFRESH, 0, 0);
  return 0;
}

/* ---------- 输入框与按钮 ---------- */
void layout_children(HWND hwnd) {
  if (!g_edit) return;
  RECT rc;
  GetClientRect(hwnd, &rc);
  layout_t L = layout_of(rc.right, rc.bottom);
  main_parts_t M = main_parts(L.main);
  int x = (int)M.field.X + 12;
  int y = (int)M.field.Y + 7;
  int w = (int)M.field.Width - 24 - 84;
  int h = (int)M.field.Height - 14;
  if (w < 40) w = 40;
  MoveWindow(g_edit, x, y, w, h, TRUE);
}

LRESULT CALLBACK edit_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
  if (msg == WM_KEYDOWN) {
    if (wp == VK_RETURN) {
      PostMessageW(g_hwnd, WM_APP_SEND, 0, 0);
      return 0;
    }
    if (wp == VK_ESCAPE) {
      PostMessageW(g_hwnd, WM_APP_STOP, 0, 0);
      return 0;
    }
  }
  if (msg == WM_CHAR && (wp == 1 || wp == 27)) return 0;   /* 吃掉回车/ESC 的字符 */
  return CallWindowProcW(g_edit_old, h, msg, wp, lp);
}

void submit_turn(HWND hwnd) {
  if (InterlockedCompareExchange(&g_busy, 1, 0) != 0) return;   /* 一轮没跑完,不接新的 */
  if (!g_edit) { InterlockedExchange(&g_busy, 0); return; }
  int len = GetWindowTextLengthW(g_edit);
  if (len <= 0) {
    InterlockedExchange(&g_busy, 0);
    return;
  }
  wchar_t *text = (wchar_t *)malloc(sizeof(wchar_t) * (size_t)(len + 1));
  if (!text) { InterlockedExchange(&g_busy, 0); return; }
  GetWindowTextW(g_edit, text, len + 1);
  SetWindowTextW(g_edit, L"");
  SetFocus(g_edit);

  chat_push(ROLE_USER, text, 0);
  char *u8 = w_to_u8(text);
  free(text);
  g_follow = true;
  InvalidateRect(hwnd, NULL, FALSE);

  std::string *q = new std::string(u8 ? u8 : "");
  free(u8);
  HANDLE th = CreateThread(NULL, 0, turn_thread, q, 0, NULL);
  if (th) CloseHandle(th);
  else {
    delete q;
    chat_push(ROLE_NOTE, L"起不了工作线程", 0);
    InterlockedExchange(&g_busy, 0);
  }
}

void stop_turn(HWND hwnd) {
  if (InterlockedCompareExchange(&g_busy, 1, 1) == 0) return;
  /* 两手一起下:先告诉服务端"这一轮别跑了",再把这条流掐了 ——
     只截断流的话,模型那边可能还在跑。 */
  HANDLE th = CreateThread(NULL, 0, cancel_thread, NULL, 0, NULL);
  if (th) CloseHandle(th);
  EnterCriticalSection(&g_chat_lock);
  SOCKET s = g_sock;
  g_sock = INVALID_SOCKET;
  LeaveCriticalSection(&g_chat_lock);
  if (s != INVALID_SOCKET) {
    shutdown(s, SD_BOTH);
    closesocket(s);
  }
  chat_push(ROLE_NOTE, L"已叫停,正在收尾", 0);
  InvalidateRect(hwnd, NULL, FALSE);
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
      if (!g_chat_lock_ready) {
        InitializeCriticalSection(&g_chat_lock);
        g_chat_lock_ready = 1;
      }
      {
        /* 输入框:系统 EDIT 控件。中文输入法、选区、粘贴都交给它,
           我们只截走 Enter / Esc 两个键。 */
        g_edit_font = CreateFontW(-16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                                  OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                  DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
        g_edit = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                 0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)1001, GetModuleHandleW(NULL),
                                 NULL);
        if (g_edit) {
          SendMessageW(g_edit, WM_SETFONT, (WPARAM)g_edit_font, TRUE);
          SendMessageW(g_edit, EM_SETLIMITTEXT, (WPARAM)4000, 0);
          g_edit_old = (WNDPROC)SetWindowLongPtrW(g_edit, GWLP_WNDPROC, (LONG_PTR)edit_proc);
          layout_children(hwnd);
          SetFocus(g_edit);
        }
      }
      return 0;

    case WM_SIZE:
      layout_children(hwnd);
      InvalidateRect(hwnd, NULL, FALSE);
      return 0;

    case WM_APP_SEND:
      submit_turn(hwnd);
      return 0;

    case WM_APP_STOP:
      stop_turn(hwnd);
      return 0;

    case WM_APP_REFRESH:
      InvalidateRect(hwnd, NULL, FALSE);
      return 0;

    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC: {
      SetBkColor((HDC)wp, RGB(255, 255, 255));
      SetTextColor((HDC)wp, RGB(0x19, 0x19, 0x14));
      return (LRESULT)GetStockObject(WHITE_BRUSH);
    }

    case WM_MOUSEWHEEL: {
      int delta = GET_WHEEL_DELTA_WPARAM(wp);
      int max_scroll = g_total_h - g_view_h;
      if (max_scroll > 0) {
        g_scroll_top -= delta / WHEEL_DELTA * 72;
        if (g_scroll_top < 0) g_scroll_top = 0;
        if (g_scroll_top >= max_scroll) {
          g_scroll_top = max_scroll;
          g_follow = true;                     /* 滚到底就重新跟随 */
        } else {
          g_follow = false;
        }
        InvalidateRect(hwnd, NULL, FALSE);
      }
      return 0;
    }

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
        return 0;
      }
      /* 执行/停止按钮是自己画的,命中也就自己判 */
      {
        layout_t L = layout_of(rc.right, rc.bottom);
        main_parts_t M = main_parts(L.main);
        if (x >= M.send.X && x <= M.send.X + M.send.Width && y >= M.send.Y &&
            y <= M.send.Y + M.send.Height) {
          PostMessageW(hwnd, g_busy ? WM_APP_STOP : WM_APP_SEND, 0, 0);
          return 0;
        }
        if (x >= M.compose.X && x <= M.compose.X + M.compose.Width && y >= M.compose.Y) {
          if (g_edit) SetFocus(g_edit);       /* 点输入区任何地方都落到输入框 */
        }
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
      if (g_busy) stop_turn(hwnd);         /* 别把一轮跑到一半的活丢在后台 */
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
      g_edit = NULL;                     /* 子控件随父窗口一起没了,别留悬空句柄 */
      if (g_edit_font) {
        DeleteObject(g_edit_font);
        g_edit_font = NULL;
      }
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
  if (g_edit) SetFocus(g_edit);
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
