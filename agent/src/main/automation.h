/* automation.h —— 周期巡检(定时巡检 + 基线对比 + 变化告警)
 *
 * 命题要求「支持定时巡检、基线对比、告警、复测和报告导出」。
 * 这里的取舍:一条周期规则 = 一个目标 + 一套巡检范围 + 一个周期,
 * 每轮到点做两件事 —— 跑一轮巡检,再把这一轮和上一轮做差分。
 * 差分的结论才叫"变化",凭空比时间戳没有意义。
 *
 * 规则落在 store 的 automations 集合里(一对象一文件),进程重启不会丢;
 * 停机期间错过的周期不再补跑(用户明确要求略过),重启时只把下次时间顺延。
 */
#ifndef AGENT_AUTOMATION_H
#define AGENT_AUTOMATION_H

#include "common.h"
#include "json.h"
#include "store.h"

/* 巡检范围:决定这一轮调哪个技能,而不是让模型自己猜 */
typedef enum {
  AUTO_SCOPE_FULL = 0,     /* 全流程巡检 */
  AUTO_SCOPE_LEAK,         /* 只看敏感信息泄露 */
  AUTO_SCOPE_INTEGRITY,    /* 只看内容完整性(篡改/挂马) */
  AUTO_SCOPE_RECON,        /* 只摸资产底账 */
  AUTO_SCOPE_RETEST,       /* 只复测上一轮没修好的 */
} auto_scope_t;

typedef struct {
  char id[24];
  char name[200];
  char domain[256];
  char scope[24];        /* full | leak | integrity | recon | retest */
  char kind[16];         /* interval | daily | weekly */
  int  every_min;        /* interval:间隔分钟(最小 1) */
  int  at_hour;          /* daily/weekly:定点时 */
  int  at_min;           /* daily/weekly:定点分 */
  int  weekday;          /* weekly:0=周日 … 6=周六 */
  int  enabled;
  int  run_count;
  int  change_count;     /* 累计产出过多少次"有变化"的告警 */
  long long next_at;     /* epoch 秒;0 表示还没算过 */
  char last_run_at[40];
  char last_run_id[24];
  char created_at[40];
  char profile_id[24];   /* 用哪套"本单位敏感信息定义"(空 = 出厂口径) */
  char checks[160];      /* 这一轮做哪些检查(逗号分隔:recon,integrity,leak,retest;
                            空或含 full 表示完整巡检)。它同时是本轮范围签名,基线对比按它配对。 */
} auto_rule_t;

/* 范围 → 给智能体的那句话(它按这句话选技能,不是按名字猜) */
const char *auto_scope_instruction(const char *scope);
const char *auto_scope_label(const char *scope);
/* 把 checks 拼成一句完整指令;checks 为空时按 scope 的预设走 */
void auto_checks_instruction(const char *checks, const char *scope, char *out, size_t cap);
/* 范围签名:同类才能比同类(返回写入 out 的字符串,空 checks → "full") */
void auto_checks_signature(const char *checks, const char *scope, char *out, size_t cap);
/* 界面上给人看的周期描述:"每 6 小时" / "每天 03:00" / "每周一 09:00" */
void auto_cycle_text(const auto_rule_t *r, char *out, size_t cap);

/* 下一次触发时间(epoch 秒)。from 传当前时间即可。 */
long long auto_next_at(const auto_rule_t *r, long long from);

/* JSON ⇄ 结构体(界面用 JSON 传,后端只认结构体) */
void auto_from_json(json_t *o, auto_rule_t *r);
json_t *auto_to_json(const auto_rule_t *r);

/* 校验:域名不能空、周期必须能算出下一次时间。返回 NULL 表示通过,否则返回错误话术。 */
const char *auto_validate(const auto_rule_t *r);

/* 读写。auto_save 遇到空 id 会自动分配;返回 0 成功。 */
int auto_list(store_t *s, auto_rule_t **out, int *count);   /* 调用方 auto_free_list */
void auto_free_list(auto_rule_t *list);
int auto_find(store_t *s, const char *id, auto_rule_t *out);
int auto_save(store_t *s, auto_rule_t *r);
int auto_remove(store_t *s, const char *id);

/* 重启时把已经过期的 next_at 顺延到下一个周期(不补跑) */
int auto_resync(store_t *s, auto_rule_t *list, int count);

/* 取一条到期的规则(最早的),并把它的 next_at 推到下一个周期。
   返回 1 表示拿到了,0 表示暂时没有到期的。 */
int auto_take_due(store_t *s, auto_rule_t *out, long long now);

/* 一轮跑完之后的收尾:
   1) 与同一任务上一次运行做差分(新增 / 已修复 / 仍未修复 / 等级升高)
   2) 有变化就写一条 alert(集合 alerts,kind=周期变化),没有变化就什么都不写
   3) 更新规则的统计
   返回 1 表示写了告警,0 表示这轮没有变化,-1 表示参数不足。 */
int auto_after_run(store_t *s, auto_rule_t *r, const char *run_id);

/* 最近一次运行(按 started_at 最新),给"刚跑完的是哪一份"定位用 */
char *auto_latest_run_of_domain(store_t *s, const char *domain);

#endif /* AGENT_AUTOMATION_H */
