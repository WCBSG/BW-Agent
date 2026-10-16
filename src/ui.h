/* ui.h —— 界面宿主层(可替换的实现)。
 *
 * 界面本身是 ui/ 目录下的普通网页,由内置 HTTP 服务提供。
 * 这一层只解决一件事:**把这个网页显示出来**。三条路,按可用性依次降级:
 *
 *   1. 内嵌 WebView2(控件嵌进本进程窗口)—— 命题原本要的形态;
 *   2. 系统 Edge/Chrome 的 --app 模式 —— 无地址栏的应用窗口,外观几乎一样;
 *   3. 系统默认浏览器打开。
 *
 * 为什么要有降级:嵌入模式依赖 WebView2 运行时能否在本进程里拉起它的
 * browser/renderer 子进程,这一步会受宿主环境的进程限制影响。
 * 本机实测嵌入模式起不来 renderer(取证见 exp/probe.c),
 * 而 --app 模式实测正常 —— 所以降级不是"凑合",是真正可用的形态。
 * 换一台机器如果嵌入模式能用,设 UI_MODE=webview 就走内嵌。
 */
#ifndef AGENT_UI_H
#define AGENT_UI_H

/* 异步打开界面(内部起线程,立即返回,不阻塞服务)
   port = 后端监听端口 */
void ui_open_url_async(int port);

/* 关掉我们自己打开的那个应用窗口(不动用户原本开着的浏览器) */
void ui_close(void);

/* 界面窗口被关掉时,要不要顺手把服务也停掉(默认要)。
   调试时(--debug)设成 0:窗口只是个看板,关了窗口服务继续跑,
   想反复打开界面看结果就不用反复重启程序。 */
void ui_set_stop_on_close(int on);

/* 当前实际生效的显示方式,用于日志/启动横幅 */
const char *ui_mode_name(void);

#endif /* AGENT_UI_H */
