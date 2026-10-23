/* webview.h —— 界面宿主:把内置网页显示在一个真正属于自己的窗口里。
 *
 * 为什么是 WebView2:
 *   前一版用的是"系统 Edge 的 --app 窗口"。观感够用,但那是别人的进程 ——
 *   窗口标题/图标/关闭行为都不完全受控,托盘"重新打开"也得靠标题去猜是哪个窗口。
 *   WebView2 是同一套 Chromium 内核的嵌入式控件:窗口是自己的,进程树里
 *   msedgewebview2.exe 只是子进程,关窗口、缩放、置前都能直接做。
 *
 * 不链接任何 SDK 库:WebView2Loader.dll 以资源形式编进 exe,
 * 首次运行时释放到数据目录再 LoadLibrary + GetProcAddress。
 * 所以仍然"交付一个 exe";代价是这台机器需要有 WebView2 运行时
 * (Win10/11 随 Edge 自带;没有时退回系统 Edge 的 --app 窗口,不会打不开)。
 */
#ifndef AGENT_WEBVIEW_H
#define AGENT_WEBVIEW_H

/* 起界面:内部建窗口、起消息循环(在自己的线程里)。成功返回 0。
   port 是本地服务端口。窗口被用户关掉时按 ui_set_stop_on_close 的约定收摊。 */
int  webview_start(int port, const char *title);

/* 把窗口叫到前台(托盘"打开界面"、单实例第二次启动都走这里) */
void webview_show(void);

/* 程序要退出了:关窗口、结束消息循环(可重复调用) */
void webview_stop(void);

/* 窗口还活着(用来决定托盘菜单里显示"打开界面"还是"重新启动") */
int  webview_active(void);

/* 运行时到底用上 WebView2 了没有(日志/自检用):1=用上了,0=退回了系统浏览器 */
int  webview_backend_is_native(void);

#endif /* AGENT_WEBVIEW_H */
