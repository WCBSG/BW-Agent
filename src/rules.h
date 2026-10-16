/* rules.h —— 规则层:所有"站点相关知识"都放在数据里,不写进代码。
 *
 * 为什么要有这一层:同样的检查动作,不同单位关心的文件、特征、等级都不一样。
 * 把知识写成数据(data/rules.json),程序只提供判断手法,就能:
 *   ① 换一个目标不用改代码、不用重编译;
 *   ② 评委可以拿自己的站点和规则验证,而不是只能"跑我准备的那个靶站";
 *   ③ 结论可追溯 —— 报告里能写清"命中的是哪条定义的哪个特征"。
 *
 * 找不到 rules.json 时用内置的通用默认规则(常见误发布文件、通用内容特征、
 * 通用错误回显特征、通用可疑域名后缀),保证零配置也能用。
 */
#ifndef AGENT_RULES_H
#define AGENT_RULES_H

#include "common.h"
#include "json.h"

/* 一条内容特征定义(命中后由技能层决定是否成案) */
typedef struct {
  const char *name;      /* 特征名,如"配置凭据文件" */
  const char *kind;      /* 业务类别:漏洞/弱配置/挂马/篡改/敏感信息 */
  const char *severity;  /* 严重/高/中/低/信息 */
  const char *tag;       /* 指纹标签(去重键用);缺省同 name */
  const char *evidence;  /* 命中的具体片段(写进证据) */
} rules_sig_t;

/* 初始化:base_dir 传程序目录,内部会找 data/rules.json */
void rules_init(const char *base_dir);
void rules_shutdown(void);
/* 规则来源(如实写进报告:"内置默认规则" 或 "data/rules.json") */
const char *rules_source(void);
int  rules_from_file(void);

/* 借出字符串数组(如 sensitive_paths / dir_candidates / error_signatures) */
const char **rules_str_list(const char *key, int *count);

/* 单值(如 max_probe_per_run),取不到用 fallback */
double rules_number(const char *key, double fallback);
int    rules_flag(const char *key, int fallback);

/* 内容特征匹配:命中 0 并填充 out,未命中 -1 */
int rules_sig_match(const char *path, const char *body, rules_sig_t *out);

/* 弱配置期望头(逐条取出;count 为总数) */
int rules_weak_header_count(void);
const char *rules_weak_header(int index, const char *field, const char *fallback);
int rules_weak_header_num(int index, const char *field, int fallback);

/* 原始规则 JSON(界面/报告要展示"用的是哪套规则") */
json_t *rules_root(void);
/* 内置默认规则的 JSON 文本(可以导出成文件让人照着改) */
const char *rules_default_json(void);

#endif /* AGENT_RULES_H */
