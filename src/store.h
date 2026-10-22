/* store.h —— 落盘层:三册合同要求的文件形态。
   结果类(Finding/Asset/Alert/TestCase)→ JSONL,一行一条,只追加;
   配置/记录类(Task/Profile/Baseline/ScanRun/Report/EvalResult)→ 单对象单文件;
   另有运行索引 / 审计 / 会话转录三份额外台账。
   编号规则:F-0001 / A-0001 / RUN-0001 / R-0001 …… 与合同 fixtures 一致。 */
#ifndef AGENT_STORE_H
#define AGENT_STORE_H

#include "common.h"
#include "json.h"

typedef struct store store_t;

store_t *store_open(const char *data_dir);
void     store_close(store_t *s);
const char *store_dir(store_t *s);

/* 发编号:collections 用复数名(findings/assets/alerts/runs/reports/evals/
   tasks/profiles/baselines/diffs/testcases) */
char *store_next_id(store_t *s, const char *collection);

/* 结果类:追加一行 */
int store_append(store_t *s, const char *collection, json_t *obj);
/* 配置/记录类:一对象一文件(同 id 覆盖) */
int store_save(store_t *s, const char *collection, json_t *obj);
/* 读全部(结果类会去重,同 id 取最后一行) */
json_t *store_all(store_t *s, const char *collection);
json_t *store_get(store_t *s, const char *collection, const char *id);
/* 删除一个"一对象一文件"的记录(周期规则要能被删掉) */
int store_delete(store_t *s, const char *collection, const char *id);
json_t *store_find(store_t *s, const char *collection, const char *key, const char *value);

/* 运行索引:本次运行看到了哪些发现(合同对象只存首次运行,报告要的是"本次") */
int  store_link_run(store_t *s, const char *run_id, const char *finding_id, int is_new);
json_t *store_findings_of_run(store_t *s, const char *run_id);

/* 审计与会话转录 */
void store_audit(store_t *s, const char *action, const char *target, int allowed,
                 const char *detail, const char *task_id, const char *run_id);
int  store_transcript(store_t *s, const char *session_id, json_t *event);

/* 快照:基线存引用不存全文 */
char *store_write_snapshot(store_t *s, const char *id, const char *content);
char *store_read_snapshot(store_t *s, const char *content_ref);

/* —— 业务写入(把"发现"按合同规则入库:去重 + 状态机) ——
   dedup_key 相同则只更新 last_seen,不新增 —— 这是"同一个问题反复扫到"的正解。 */
typedef struct {
  const char *kind;         /* 漏洞/弱配置/挂马/篡改/敏感信息 */
  const char *severity;     /* 严重/高/中/低/信息 */
  const char *title;
  const char *target;
  const char *evidence;     /* 会做去敏 */
  const char *impact;
  const char *fix;
  const char *source_tool;
  const char *dedup_tag;    /* 问题指纹(同工具同目标下唯一即可) */
  const char *task_id;
  const char *run_id;
} finding_in_t;

/* 返回发现 id(xmalloc);is_new 输出是否新发现 */
char *store_upsert_finding(store_t *s, const finding_in_t *in, int *is_new);

/* 更新一条发现(JSONL 只追加:同 id 再写一行,读的时候取最后一行)。
   复测改状态、改 retests 都走这里 —— 发现的正文永远只有一处数据源。 */
int store_update_finding(store_t *s, json_t *finding);
/* 全部发现;task_id 传 NULL/"" 表示不过滤 */
json_t *store_findings_of_task(store_t *s, const char *task_id);

/* —— 业务对象:任务 / 敏感信息定义 / 资产 ——
   任务 = 授权范围 + 用哪套敏感信息定义,是"这次巡检为什么合法、按什么口径"的凭据;
   定义是"生效规则"的快照 —— 报告里能写清"本次用的是哪一版定义"。 */
char *store_ensure_task(store_t *s, const char **domains, int count, const char *name,
                        const char *profile_id);
char *store_ensure_profile(store_t *s, const char *name, json_t *keywords,
                           json_t *file_types, json_t *samples);
/* 资产入库:同 url 只更新 last_seen(底账是"一直都在"的意思,不是每轮重记一遍) */
int   store_upsert_asset(store_t *s, const char *task_id, const char *url, const char *kind,
                         int status_code, int depth, const char *parent_url);
/* 运行记录:开始写一份 running,结束覆盖成 done(对外只用它一份)。
   scope 记的是这一轮"查了什么"(full/leak/integrity/recon/retest) ——
   基线对比必须同类比同类,拿只查泄露的一轮去和完整巡检比,会把没查的项误判成"已修复"。 */
char *store_run_start(store_t *s, const char *task_id, const char *triggered_by,
                      const char *scope);
int   store_run_finish(store_t *s, const char *run_id, const char *status, int pages_found,
                       int tools_called, int findings_new, const char *error);

/* 触发来源标签(「手动」/「周期巡检」)。
   为什么要一个全局:技能里创建运行记录时并不知道"是谁触发的",
   而这个信息恰恰是评审要看的东西(这一轮是人点的还是定时跑的)。 */
void store_set_trigger(const char *label);
const char *store_trigger_label(void);

/* 证据去敏:手机号/邮箱/IP/身份证/卡号/凭据,落盘前就脱敏 */
void mask_evidence(buf_t *out, const char *text);

#endif /* AGENT_STORE_H */
