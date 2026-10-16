/* embed.h —— 内置资源:把界面与默认规则直接编进 exe。
 *
 * 为什么要这样:交付给用户的应该只有**一个 exe**,双击就能跑 ——
 * 不能要求"必须把 ui 目录和 data 目录放在旁边"。所以界面三个文件与默认规则
 * 在编译期被"塞进"可执行文件里(见 tools\mkres.c 生成的 build\resources.c)。
 *
 * 优先级:磁盘上的同名文件优先,内置资源兜底。
 * 这样同一个 exe 既能"单文件开箱即用",也允许懂行的人放一份自己的界面/规则覆盖。
 */
#ifndef AGENT_EMBED_H
#define AGENT_EMBED_H

#include <stddef.h>

/* 按名字取内置资源:
      "ui/index.html" / "ui/app.css" / "ui/app.js" / "data/rules.json" / "ui/logo.ico"
   找到返回 1 并把指针与长度写进 out(数据是静态的,不要 free);没有返回 0。 */
int embed_lookup(const char *name, const char **data, size_t *len);

/* 内置资源个数(启动横幅里报一下,让用户知道界面是自带的) */
int embed_count(void);
const char *embed_name_at(int index);

#endif /* AGENT_EMBED_H */
