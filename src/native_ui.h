/* native_ui.h —— 原生界面宿主(替代"开一个浏览器窗口")。
 *
 * 为什么要有这一层:
 *   把网页塞进别人的浏览器窗口,终究是"借来的壳" —— 关窗要靠轮询进程、
 *   观感取决于浏览器版本、也没有真正的单窗口。这一层用 Win32 + GDI+
 *   自己画一个窗口,和托盘、服务在同一个进程里。
 *
 * 演进方式(每一片都能跑,网页版随时可切回 UI_MODE=app):
 *   N1 骨架:三栏 + 可拖分隔条 + 托盘接管   ← 当前
 *   N2 对话:输入区、消息流、SSE 直播、停止
 *   N3 审批与侧栏
 *   N4 数据页
 *   N5 设置
 */
#ifndef AGENT_NATIVE_UI_H
#define AGENT_NATIVE_UI_H

/* 起原生窗口(内部起线程跑消息循环,立即返回)。
   port 只用于接口地址的显示与后续 API 调用。成功返回 0。 */
int  native_ui_start(int port, const char *title);
/* 把窗口叫回前台(托盘「打开界面」调它) */
void native_ui_show(void);
/* 关掉窗口并退出消息循环(程序收尾时调) */
void native_ui_stop(void);
/* 窗口线程是否还活着 */
int  native_ui_active(void);

#endif /* AGENT_NATIVE_UI_H */
