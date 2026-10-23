/* rules_domains.h —— 规则按域存放(替代一个 9KB 的 rules.json)。
 *
 * 为什么拆:
 *   一个 rules.json 装着 20 个顶层键、九千多字节,改"弱口令"和改"告警阈值"
 *   落在同一个文件里 —— 版本库里每次都整篇变动,人也没法只把某一类交给别人看。
 *   拆成 6 个域之后,每个域一个文件,改哪一类就只动那一个。
 *
 * 为什么是 6 个而不是 20 个:
 *   一个键一个文件会碎成一地;按"谁在用、谁负责"分,正好是这 6 份:
 *     检测口径 · 敏感信息 · 探测参数 · 告警与推送 · 单位口径 · 页面与篡改
 *
 * 数据目录布局:
 *   <数据目录>\rules\detect.json
 *                   sensitive.json
 *                   probe.json
 *                   alert.json
 *                   org.json
 *                   page.json
 * 首次启动时由 exe 内置的出厂规则生成;之后以这 6 个文件为准。
 */
#ifndef AGENT_RULES_DOMAINS_H
#define AGENT_RULES_DOMAINS_H

#include "common.h"
#include "json.h"

typedef struct {
  const char *id;        /* detect / sensitive / ... */
  const char *title;     /* 给人看的名字 */
  const char *file;      /* rules\detect.json */
  const char *note;      /* 这一域管什么(界面上一句话说明) */
} rules_domain_t;

int              rules_domain_count(void);
const rules_domain_t *rules_domain_at(int i);
const rules_domain_t *rules_domain_find(const char *id);

/* 数据目录下 rules\ 的绝对路径(不做建目录) */
void rules_domain_dir(char *out, size_t cap);

/* 从出厂规则生成缺失的域文件。返回生成个数;>=0 表示没问题。 */
int rules_domains_generate(char *err, size_t errcap);

/* 把 6 个域文件合并成一份规则(缺失的键用出厂值补)。
   成功返回新对象(调用方负责 json_free),失败返回 NULL。 */
json_t *rules_domains_load_merged(char *err, size_t errcap);

/* 某个域当前的内容(只含该域的键),用于界面按域展示 */
json_t *rules_domains_read(const char *id, char *err, size_t errcap);

/* 保存一个域:patch 里只取属于该域的键,其余忽略。成功返回 0。 */
int rules_domains_save(const char *id, json_t *patch, char *err, size_t errcap);

/* 整份写回:把完整规则按域拆到 6 个文件(界面"一键保存全部"用)。 */
int rules_domains_save_all(json_t *root, char *err, size_t errcap);

/* 该键是否属于某个域(找不到域返回 NULL) */
const rules_domain_t *rules_domain_of_key(const char *key);

#endif /* AGENT_RULES_DOMAINS_H */
