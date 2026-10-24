/* instance.h —— 单实例:同一个数据目录只允许一个服务进程。
 *
 * 双击两次会起两个服务、两个端口、两份托盘图标,而它们读写的是同一份
 * SQLite 与 audit.jsonl —— 保存时互相覆盖,使用者还分不清哪个是真的。
 * 所以第二次启动不再起服务,只把已有的界面叫到前台。
 *
 * 判据分两层:
 *   · 命名互斥量 —— 管"谁在跑"(进程结束/崩溃时系统自动释放,不会留死锁)
 *   · 数据目录下的 instance.json —— 记"在哪个端口"
 * 端口只信探活:问 /api/health,认 "app":"bwagent-zero" 才算自己人
 * (同机可能有同源的另一份实现,它们首页里也有 bw-token —— 只认令牌会认错人)。
 */
#ifndef AGENT_INSTANCE_H
#define AGENT_INSTANCE_H

/* 尝试成为唯一实例。
   返回 1 = 拿到了(可以继续启动服务),0 = 已有实例在跑。 */
int instance_acquire(void);

/* 当前进程是否持有那把锁(多实例模式 / 命令行工具为 0) */
int instance_owned(void);

/* 服务真的开始监听之后调用:把端口写进 <数据目录>\instance.json。
   端口此刻不可绑定时不写(说明这次启动会失败并换端口)。 */
void instance_publish(int port);

/* 退出前删掉 instance.json(进程被强杀时删不掉,靠探活兜底) */
void instance_unpublish(void);

/* 已有实例的端口:先看 instance.json,再探活;给 wait_ms 毫秒等它启动。
   找不到返回 0。 */
int instance_running_port(int wait_ms);

/* 上一次判定的说明(写日志用) */
const char *instance_note(void);

/* 在 [from, to] 里找一个能绑的端口,返回 0 表示全被占用。
   为什么要"先挑再起服务":serve_run 会铺数据、开窗口、挂托盘,
   绑不上再回头重来等于把整套初始化跑第二遍(全局状态与 WebView2 都不支持重入)。
   先挑好端口,只跑一次,失败就是失败。 */
int instance_pick_free_port(int from, int to);

#endif /* AGENT_INSTANCE_H */
