/* res.h —— 资源加载接口(见 res.c 的实现说明)。
   磁盘优先、内置兜底:单文件 exe 也能跑,想定制就放一份同名文件在旁边。 */
#ifndef AGENT_RES_H
#define AGENT_RES_H

#include "common.h"

/* 读一份文本资源(内部按 UTF-8 原样返回)。
   成功 1 并给出 malloc 出来的内容(调用方 free);找不到 0。 */
int res_load_text(const char *name, char **out, size_t *out_len);

/* 资源是否存在(磁盘或内置) */
int res_exists(const char *name);

/* 首次运行时把"可定制的东西"落到数据目录:
     rules.json    —— 出厂规则(改它就能适配新单位/新目标,不用重编译)
     使用说明.txt  —— 三行说清怎么用、数据在哪、怎么改规则
   已存在的文件一律不覆盖(用户改过的东西不能被程序冲掉)。
   返回写出的文件数。 */
int res_bootstrap_data_dir(void);

#endif /* AGENT_RES_H */
