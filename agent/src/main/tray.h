/* tray.h —— 托盘:关掉界面窗口不等于退出程序。
 *
 * 为什么要有这一层:
 *   巡检是个"跑起来就该待在后台"的东西 —— 关掉界面窗口就结束进程,
 *   周期巡检也跟着停了,使用者还得记得重新双击。但"直接消失到后台"更糟:
 *   任务管理器里多一个看不见的进程,用户不知道它在不在、怎么结束它。
 * 所以做成托盘:图标一直在,右键能重新打开界面,也能彻底退出。
 */
#ifndef AGENT_TRAY_H
#define AGENT_TRAY_H

/* 建立托盘图标(在独立线程里跑消息循环,不阻塞调用方)。
   port = 当前服务端口;tip = 悬停提示。成功返回 0。 */
int  tray_start(int port, const char *tip);
/* 弹一条气泡提示(窗口被关掉时告诉用户"我还在托盘里") */
void tray_balloon(const char *title, const char *text);
/* 摘掉图标并结束消息循环(退出前调用) */
void tray_stop(void);
/* 托盘是否已经建起来(决定"关窗口"该退还是该留) */
int  tray_active(void);

#endif /* AGENT_TRAY_H */
