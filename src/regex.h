/* regex.h —— 极简正则引擎(零依赖,自己写)。
 *
 * 为什么要自己写:规则文件里的判定用正则必须能由使用方自己改(units 各有各的
 * 证件号/工号/内部编号规则),而引第三方库会破坏"单文件、零依赖"这条交付底线。
 *
 * 支持的范围(**故意小,但正确**):
 *   字面量、.      \d \w \s 与转义(\\. \\\\ 等)
 *   字符类 [abc] [a-z] [^0-9](类内支持转义与范围)
 *   分组 ( ) 与非捕获 (?: )   分支 (a|b)
 *   量词 * + ? {n} {n,} {n,m}(贪婪 + 回溯,不会出现"能匹配却匹配不到")
 *   锚点 ^ $
 *   (?i) 忽略大小写前缀
 *   我们实际需要的两种断言:(?<![0-9])(前面不是数字)、(?![0-9])(后面不是数字)
 *
 * 不支持:嵌套量词 {2}{3}、反向引用、环视嵌套、Unicode 属性。
 * 规则写超范围时 rx_compile 会如实返回错误原因(而不是默默不匹配)。
 */
#ifndef AGENT_REGEX_H
#define AGENT_REGEX_H

#include <stddef.h>

/* 编译一条正则(内部节点从堆上分配,用完必须 rx_free) */
typedef struct rx_pattern rx_pattern;
rx_pattern *rx_compile(const char *pattern, char *err, size_t err_cap);
void        rx_free(rx_pattern *re);

/* 在 text 里找第一处匹配。命中返回 1 并给出偏移/长度(字节) */
int rx_search(const rx_pattern *re, const char *text, int *out_off, int *out_len);

/* 一步到位:编译 + 搜索 + 释放(内部用;失败时 err 里有原因) */
int rx_find(const char *pattern, const char *text, int *out_off, int *out_len,
            char *err, size_t err_cap);

#endif /* AGENT_REGEX_H */
