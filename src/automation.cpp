/* automation.cpp —— 周期巡检的实现。见 automation.h 的取舍说明。 */
#include "automation.h"
#include "net.h"

#include <ctime>
#include <vector>
#include <string>
#include <unordered_map>

/* ================= 小工具 ================= */

static long long now_epoch(void) { return (long long)time(NULL); }

static void epoch_to_iso(long long sec, char *out, size_t cap) {
  ms_to_iso(sec * 1000, out, cap);
}

/* 等级序:数字越大越严重(与规则里的 alerts.min_rank 同一套方向) */
static int sev_rank(const char *sev) {
  if (!sev) return 0;
  if (strcmp(sev, "严重") == 0) return 4;
  if (strcmp(sev, "高") == 0) return 3;
  if (strcmp(sev, "中") == 0) return 2;
  if (strcmp(sev, "低") == 0) return 1;
  return 0;
}

static const char *sev_name(int rank) {
  switch (rank) {
    case 4: return "严重";
    case 3: return "高";
    case 2: return "中";
    case 1: return "低";
    default: return "信息";
  }
}

void auto_cycle_text(const auto_rule_t *r, char *out, size_t cap) {
  if (!r) { snprintf(out, cap, "未设置"); return; }
  if (str_ieq(r->kind, "daily")) {
    snprintf(out, cap, "每天 %02d:%02d", r->at_hour, r->at_min);
  } else if (str_ieq(r->kind, "weekly")) {
    static const char *WD[] = {"周日", "周一", "周二", "周三", "周四", "周五", "周六"};
    int wd = r->weekday % 7;
    if (wd < 0) wd += 7;
    snprintf(out, cap, "每%s %02d:%02d", WD[wd], r->at_hour, r->at_min);
  } else {
    int m = r->every_min > 0 ? r->every_min : 60;
    if (m % 1440 == 0) snprintf(out, cap, "每 %d 天", m / 1440);
    else if (m % 60 == 0) snprintf(out, cap, "每 %d 小时", m / 60);
    else snprintf(out, cap, "每 %d 分钟", m);
  }
}

const char *auto_scope_label(const char *scope) {
  if (!scope) return "全流程巡检";
  if (str_ieq(scope, "leak")) return "敏感信息检查";
  if (str_ieq(scope, "integrity")) return "内容完整性检查";
  if (str_ieq(scope, "recon")) return "资产与页面发现";
  if (str_ieq(scope, "retest")) return "复测未修复项";
  return "全流程巡检";
}

/* 给智能体的指令要写清"只做哪些、不做哪些",否则它会自己发挥。 */
const char *auto_scope_instruction(const char *scope) {
  if (scope && str_ieq(scope, "leak")) {
    return "只做敏感信息检查:按本单位的敏感信息定义查误发布与信息泄露。"
           "不要顺带做漏洞探测、不要猜目录、不要复测其它问题。";
  }
  if (scope && str_ieq(scope, "integrity")) {
    return "只做内容完整性检查:把页面与基线比对,判断是否被篡改、是否被植入恶意外链。"
           "不做敏感文件探测,不做漏洞扫描。";
  }
  if (scope && str_ieq(scope, "recon")) {
    return "只做资产与页面发现:把站点页面、静态资源、接口列成底账,标出发现来源。"
           "不做任何风险判定,不发多余请求。";
  }
  if (scope && str_ieq(scope, "retest")) {
    return "只做复测:对上一轮报告过、还没确认修好的问题重新检查,给出已修复/仍未修复/判不了的结论。"
           "不要新开检查面。";
  }
  return "做一轮完整巡检:先摸清家底,再查内容完整性与敏感信息,最后做配置与漏洞探测,"
         "并把结论归拢成报告。发现目标不可达就立刻停止并如实说明。";
}

/* 一串检查项 → 一句话。顺序固定(资产 → 完整性 → 敏感信息 → 复测),
   这样"只查这两项"的每一轮读起来都是同一个口径。 */
void auto_checks_instruction(const char *checks, const char *scope, char *out, size_t cap) {
  if (!checks || !checks[0]) {
    snprintf(out, cap, "%s", auto_scope_instruction(scope && scope[0] ? scope : "full"));
    return;
  }
  if (str_icontains(checks, "full")) {
    snprintf(out, cap, "%s", auto_scope_instruction("full"));
    return;
  }
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "这一轮只做以下检查,不要顺带做别的:");
  if (str_icontains(checks, "recon")) buf_puts(&b, "① 资产与页面发现(列底账,不做风险判定);");
  if (str_icontains(checks, "integrity")) buf_puts(&b, "② 内容完整性检查(与基线比对,判篡改与恶意外链);");
  if (str_icontains(checks, "leak")) buf_puts(&b, "③ 敏感信息检查(按本单位定义查误发布与泄露);");
  if (str_icontains(checks, "retest")) buf_puts(&b, "④ 复测(只查上一轮还没修好的问题);");
  buf_puts(&b, "最后把这一轮的结论按等级汇总,并说明每一项查了多少、命中多少。");
  snprintf(out, cap, "%s", b.data);
  buf_free(&b);
}

void auto_checks_signature(const char *checks, const char *scope, char *out, size_t cap) {
  /* 没勾检查项 = 按范围预设走;此时签名就是那个预设(leak/full/…),
     不能一律写成 full —— 否则"只查泄露"的一轮会被拿去和完整巡检比。 */
  if (!checks || !checks[0]) {
    snprintf(out, cap, "%s", (scope && scope[0]) ? scope : "full");
    return;
  }
  if (str_icontains(checks, "full")) {
    snprintf(out, cap, "full");
    return;
  }
  /* 同一个集合写成统一顺序,保证"选了同样几项"一定得到同一个签名 */
  buf_t b;
  buf_init(&b);
  static const char *ORDER[] = {"recon", "integrity", "leak", "retest"};
  for (int i = 0; i < 4; i++) {
    if (!str_icontains(checks, ORDER[i])) continue;
    if (b.len) buf_putc_(&b, ',');
    buf_puts(&b, ORDER[i]);
  }
  if (!b.len) {
    buf_free(&b);
    snprintf(out, cap, "%s", (scope && scope[0]) ? scope : "full");
    return;
  }
  snprintf(out, cap, "%s", b.data);
  buf_free(&b);
}

/* ================= 时间推算 ================= */

long long auto_next_at(const auto_rule_t *r, long long from) {
  if (!r) return from + 3600;
  if (str_ieq(r->kind, "daily") || str_ieq(r->kind, "weekly")) {
    time_t base = (time_t)from;
    struct tm lt;
    localtime_s(&lt, &base);
    lt.tm_hour = r->at_hour < 0 ? 0 : (r->at_hour > 23 ? 23 : r->at_hour);
    lt.tm_min = r->at_min < 0 ? 0 : (r->at_min > 59 ? 59 : r->at_min);
    lt.tm_sec = 0;

    if (str_ieq(r->kind, "daily")) {
      time_t cand = mktime(&lt);
      if (cand <= from) {
        lt.tm_mday += 1;
        lt.tm_isdst = -1;
        cand = mktime(&lt);
      }
      return (long long)cand;
    }
    /* weekly:先落到今天的定点,再往后找目标星期几 */
    int want = r->weekday % 7;
    if (want < 0) want += 7;
    time_t cand = mktime(&lt);
    int today = lt.tm_wday % 7;
    int diff = (want - today + 7) % 7;
    if (diff == 0 && cand <= from) diff = 7;
    lt.tm_mday += diff;
    lt.tm_isdst = -1;
    cand = mktime(&lt);
    return (long long)cand;
  }
  /* interval:最小 1 分钟,避免有人填 0 把调度器拖成死循环 */
  int m = r->every_min > 0 ? r->every_min : 60;
  return from + (long long)m * 60;
}

/* ================= JSON ⇄ 结构体 ================= */

void auto_from_json(json_t *o, auto_rule_t *r) {
  memset(r, 0, sizeof(*r));
  if (!o) return;
  snprintf(r->id, sizeof(r->id), "%s", j_s(o, "id", ""));
  snprintf(r->name, sizeof(r->name), "%s", j_s(o, "name", ""));
  snprintf(r->domain, sizeof(r->domain), "%s", j_s(o, "domain", ""));
  snprintf(r->scope, sizeof(r->scope), "%s", j_s(o, "scope", "full"));
  snprintf(r->kind, sizeof(r->kind), "%s", j_s(o, "kind", "interval"));
  r->every_min = (int)j_n(o, "every_min", 360);
  r->at_hour = (int)j_n(o, "at_hour", 3);
  r->at_min = (int)j_n(o, "at_min", 0);
  r->weekday = (int)j_n(o, "weekday", 1);
  r->enabled = j_b(o, "enabled", 1);
  r->run_count = (int)j_n(o, "run_count", 0);
  r->change_count = (int)j_n(o, "change_count", 0);
  r->next_at = (long long)j_n(o, "next_at", 0);
  snprintf(r->last_run_at, sizeof(r->last_run_at), "%s", j_s(o, "last_run_at", ""));
  snprintf(r->last_run_id, sizeof(r->last_run_id), "%s", j_s(o, "last_run_id", ""));
  snprintf(r->created_at, sizeof(r->created_at), "%s", j_s(o, "created_at", ""));
  snprintf(r->profile_id, sizeof(r->profile_id), "%s", j_s(o, "profile_id", ""));
  /* checks 允许是数组(界面多选)也允许是逗号串(命令行/脚本) */
  json_t *ck = j_get(o, "checks");
  r->checks[0] = 0;
  if (ck && ck->type == J_ARR) {
    buf_t b;
    buf_init(&b);
    for (int i = 0; i < ck->count; i++) {
      json_t *v = ck->items[i];
      if (!v || v->type != J_STR || !v->str || !v->str[0]) continue;
      if (b.len) buf_putc_(&b, ',');
      buf_puts(&b, v->str);
      if (b.len > 120) break;
    }
    snprintf(r->checks, sizeof(r->checks), "%s", b.data);
    buf_free(&b);
  } else if (ck && ck->type == J_STR) {
    snprintf(r->checks, sizeof(r->checks), "%s", ck->str);
  }
}

json_t *auto_to_json(const auto_rule_t *r) {
  json_t *o = j_obj();
  j_set_str(o, "id", r->id);
  j_set_str(o, "name", r->name[0] ? r->name : r->domain);
  j_set_str(o, "domain", r->domain);
  j_set_str(o, "scope", r->scope[0] ? r->scope : "full");
  j_set_str(o, "scope_label", auto_scope_label(r->scope));
  j_set_str(o, "kind", r->kind);
  j_set_num(o, "every_min", r->every_min);
  j_set_num(o, "at_hour", r->at_hour);
  j_set_num(o, "at_min", r->at_min);
  j_set_num(o, "weekday", r->weekday);
  j_set_bool(o, "enabled", r->enabled);
  j_set_num(o, "run_count", r->run_count);
  j_set_num(o, "change_count", r->change_count);
  j_set_num(o, "next_at", (double)r->next_at);
  char cycle[64], next_iso[40];
  auto_cycle_text(r, cycle, sizeof(cycle));
  j_set_str(o, "cycle_text", cycle);
  if (r->next_at > 0) { epoch_to_iso(r->next_at, next_iso, sizeof(next_iso)); j_set_str(o, "next_run_at", next_iso); }
  else j_set_str(o, "next_run_at", "");
  j_set_str(o, "last_run_at", r->last_run_at);
  j_set_str(o, "last_run_id", r->last_run_id);
  j_set_str(o, "created_at", r->created_at);
  j_set_str(o, "profile_id", r->profile_id);
  json_t *ck = j_arr();
  if (r->checks[0]) {
    char **parts = NULL;
    int np = str_split(r->checks, ',', &parts, 8);
    for (int i = 0; i < np; i++) {
      char *p = str_trim(parts[i]);
      if (p[0]) j_add(ck, j_str(p));
    }
    str_free_list(parts, np);
  }
  j_set(o, "checks", ck);
  char sig[128];
  auto_checks_signature(r->checks, r->scope, sig, sizeof(sig));
  j_set_str(o, "checks_signature", sig);
  j_set_bool(o, "due", r->enabled && r->next_at > 0 && r->next_at <= now_epoch());
  return o;
}

const char *auto_validate(const auto_rule_t *r) {
  if (!r->domain[0]) return "目标不能为空";
  if (strstr(r->domain, "://") || strchr(r->domain, '/')) return "目标只填主机名(可带端口),不要带协议与路径";
  if (!str_ieq(r->kind, "interval") && !str_ieq(r->kind, "daily") && !str_ieq(r->kind, "weekly")) {
    return "周期类型只能是 interval / daily / weekly";
  }
  if (str_ieq(r->kind, "interval") && (r->every_min < 1 || r->every_min > 60 * 24 * 30)) {
    return "间隔要在 1 分钟到 30 天之间";
  }
  if (str_ieq(r->kind, "daily") || str_ieq(r->kind, "weekly")) {
    if (r->at_hour < 0 || r->at_hour > 23 || r->at_min < 0 || r->at_min > 59) return "定点时间不合法";
  }
  if (!str_ieq(r->scope, "full") && !str_ieq(r->scope, "leak") && !str_ieq(r->scope, "integrity") &&
      !str_ieq(r->scope, "recon") && !str_ieq(r->scope, "retest")) {
    return "巡检范围不在允许的取值里";
  }
  /* checks 里出现不认识的项就直接拒绝:宁可报错,也不"选了个不存在的检查却静默不跑" */
  if (r->checks[0]) {
    char **parts = NULL;
    int np = str_split(r->checks, ',', &parts, 8);
    int ok = 1;
    for (int i = 0; i < np; i++) {
      char *p = str_trim(parts[i]);
      if (!p[0]) continue;
      if (!str_ieq(p, "full") && !str_ieq(p, "recon") && !str_ieq(p, "integrity") &&
          !str_ieq(p, "leak") && !str_ieq(p, "retest")) ok = 0;
    }
    str_free_list(parts, np);
    if (!ok) return "检查项只能从 完整巡检/资产与页面/内容完整性/敏感信息/复测 里选";
  }
  return NULL;
}

/* ================= 读写 ================= */

int auto_list(store_t *s, auto_rule_t **out, int *count) {
  *out = NULL;
  *count = 0;
  json_t *all = store_all(s, "automations");
  int n = j_len(all);
  if (n > 0) {
    auto_rule_t *list = (auto_rule_t *)xcalloc((size_t)n, sizeof(auto_rule_t));
    int k = 0;
    for (int i = 0; i < n; i++) {
      json_t *o = j_at(all, i);
      if (!j_s(o, "id", "")[0]) continue;
      auto_from_json(o, &list[k++]);
    }
    *out = list;
    *count = k;
  }
  json_free(all);
  return 0;
}

void auto_free_list(auto_rule_t *list) { free(list); }

int auto_find(store_t *s, const char *id, auto_rule_t *out) {
  if (!id || !id[0]) return -1;
  json_t *o = store_get(s, "automations", id);
  if (!o) return -1;
  auto_from_json(o, out);
  json_free(o);
  return 0;
}

int auto_save(store_t *s, auto_rule_t *r) {
  if (!s || !r) return -1;
  int is_new = 0;
  if (!r->id[0]) {
    char *id = store_next_id(s, "automations");
    snprintf(r->id, sizeof(r->id), "%s", id);
    free(id);
    is_new = 1;
  }
  if (!r->created_at[0]) now_iso(r->created_at, sizeof(r->created_at));
  if (r->next_at <= 0) r->next_at = auto_next_at(r, now_epoch());
  if (is_new && !r->name[0]) snprintf(r->name, sizeof(r->name), "%s", r->domain);
  json_t *o = auto_to_json(r);
  int rc = store_save(s, "automations", o);
  json_free(o);
  return rc;
}

int auto_remove(store_t *s, const char *id) {
  if (!s || !id || !id[0]) return -1;
  return store_delete(s, "automations", id);
}

int auto_resync(store_t *s, auto_rule_t *list, int count) {
  long long now = now_epoch();
  int fixed = 0;
  for (int i = 0; i < count; i++) {
    auto_rule_t *r = &list[i];
    if (!r->enabled) continue;
    if (r->next_at > 0 && r->next_at > now) continue;
    /* 停机期间错过的周期不再补跑(用户明确要求略过),只把下次时间顺延 */
    r->next_at = auto_next_at(r, now);
    auto_save(s, r);
    fixed++;
  }
  return fixed;
}

int auto_take_due(store_t *s, auto_rule_t *out, long long now) {
  auto_rule_t *list = NULL;
  int n = 0;
  auto_list(s, &list, &n);
  int best = -1;
  long long best_at = 0;
  for (int i = 0; i < n; i++) {
    if (!list[i].enabled) continue;
    if (list[i].next_at <= 0) continue;
    if (list[i].next_at > now) continue;
    if (best < 0 || list[i].next_at < best_at) { best = i; best_at = list[i].next_at; }
  }
  if (best < 0) { auto_free_list(list); return 0; }
  *out = list[best];
  auto_free_list(list);

  /* 先把下次时间推走再交出去:即便这一轮跑崩了,也不会在同一分钟里反复触发 */
  out->next_at = auto_next_at(out, now);
  auto_save(s, out);
  return 1;
}

/* ================= 基线对比 ================= */

/* 发现 → 指纹。dedup_key 是入库时算好的稳定键,没有就退化成"标题|目标"。 */
static std::string finding_key(json_t *f) {
  const char *dk = j_s(f, "dedup_key", "");
  if (dk[0]) return std::string(dk);
  std::string k = j_s(f, "title", "");
  k += "|";
  k += j_s(f, "target", "");
  return k;
}

char *auto_latest_run_of_domain(store_t *s, const char *domain) {
  /* 任务里存的是主机名(授权按主机名校验),规则里可能带端口 —— 比较前先归一。 */
  char host[256];
  net_host_port_of(domain, host, sizeof(host));
  if (!host[0]) snprintf(host, sizeof(host), "%s", domain ? domain : "");
  json_t *runs = store_all(s, "runs");
  json_t *tasks = store_all(s, "tasks");
  const char *best = NULL;
  const char *best_at = NULL;
  for (int i = 0; i < j_len(runs); i++) {
    json_t *r = j_at(runs, i);
    const char *tid = j_s(r, "task_id", "");
    json_t *task = NULL;
    for (int k = 0; k < j_len(tasks); k++) {
      if (strcmp(j_s(j_at(tasks, k), "id", ""), tid) == 0) { task = j_at(tasks, k); break; }
    }
    if (!task) continue;
    json_t *doms = j_get(task, "authorized_domains");
    int hit = 0;
    for (int d = 0; d < j_len(doms); d++) {
      json_t *dv = j_at(doms, d);
      if (!dv || !dv->str) continue;
      if (str_ieq(dv->str, host) || str_ieq(dv->str, domain)) { hit = 1; break; }
    }
    if (!hit) continue;
    const char *at = j_s(r, "started_at", "");
    if (!best_at || strcmp(at, best_at) >= 0) { best_at = at; best = j_s(r, "id", ""); }
  }
  char *out = best ? xstrdup(best) : NULL;
  json_free(runs);
  json_free(tasks);
  return out;
}

/* 取同一任务、同一范围、在当前 run 之前的最近一次运行。
   为什么必须同范围:只查泄露的一轮看不见目录索引,拿它当基线会把没查的项误报成"已修复"。 */
static std::string previous_run_of_task(store_t *s, const char *task_id, const char *run_id,
                                        const char *scope) {
  const char *want = (scope && *scope) ? scope : "full";
  json_t *runs = store_all(s, "runs");
  std::string cur_at;
  for (int i = 0; i < j_len(runs); i++) {
    if (strcmp(j_s(j_at(runs, i), "id", ""), run_id) == 0) { cur_at = j_s(j_at(runs, i), "started_at", ""); break; }
  }
  std::string best, best_at;
  for (int i = 0; i < j_len(runs); i++) {
    json_t *r = j_at(runs, i);
    const char *id = j_s(r, "id", "");
    if (!id[0] || strcmp(id, run_id) == 0) continue;
    if (strcmp(j_s(r, "task_id", ""), task_id) != 0) continue;
    if (!str_ieq(j_s(r, "scope", "full"), want)) continue;
    std::string at = j_s(r, "started_at", "");
    if (!cur_at.empty() && at >= cur_at) continue;
    if (best_at.empty() || at > best_at) { best_at = at; best = id; }
  }
  json_free(runs);
  return best;
}

int auto_after_run(store_t *s, auto_rule_t *r, const char *run_id) {
  if (!s || !r || !run_id || !run_id[0]) return -1;

  json_t *run = store_get(s, "runs", run_id);
  if (!run) return -1;
  char task_id[24];
  snprintf(task_id, sizeof(task_id), "%s", j_s(run, "task_id", ""));
  json_free(run);
  if (!task_id[0]) return -1;

  json_t *cur = store_findings_of_run(s, run_id);
  json_t *prev = NULL;
  char sig[128];
  auto_checks_signature(r->checks, r->scope, sig, sizeof(sig));
  std::string prev_id = previous_run_of_task(s, task_id, run_id, sig);
  if (!prev_id.empty()) prev = store_findings_of_run(s, prev_id.c_str());

  /* 同类范围内没有上一轮 → 这一轮就是基线。不生成告警:
     "第一次跑出来 5 条"不是"新增 5 条",把基线当变化是巡检报告最常见的谎。 */
  if (!prev) {
    r->run_count++;
    char ts0[40];
    now_iso(ts0, sizeof(ts0));
    snprintf(r->last_run_at, sizeof(r->last_run_at), "%s", ts0);
    snprintf(r->last_run_id, sizeof(r->last_run_id), "%s", run_id);
    auto_save(s, r);
    json_free(cur);
    return 2;
  }

  std::unordered_map<std::string, json_t *> cur_map, prev_map;
  for (int i = 0; i < j_len(cur); i++) cur_map[finding_key(j_at(cur, i))] = j_at(cur, i);
  if (prev) for (int i = 0; i < j_len(prev); i++) prev_map[finding_key(j_at(prev, i))] = j_at(prev, i);

  int n_new = 0, n_fixed = 0, n_persist = 0, n_escalated = 0;
  int top_rank = 0;
  json_t *items = j_arr();

  /* 新出现 */
  for (auto &kv : cur_map) {
    if (prev_map.count(kv.first)) continue;
    json_t *f = kv.second;
    int rank = sev_rank(j_s(f, "severity", "信息"));
    if (rank > top_rank && rank >= 2) top_rank = rank;
    n_new++;
    if (j_len(items) < 40) {
      json_t *it = j_obj();
      j_set_str(it, "change", "新增");
      j_set_str(it, "title", j_s(f, "title", ""));
      j_set_str(it, "severity", j_s(f, "severity", ""));
      j_set_str(it, "target", j_s(f, "target", ""));
      j_add(items, it);
    }
  }
  /* 消失 / 复现 / 升级 */
  for (auto &kv : prev_map) {
    json_t *pf = kv.second;
    auto it = cur_map.find(kv.first);
    if (it == cur_map.end()) {
      n_fixed++;
      if (j_len(items) < 40) {
        json_t *o = j_obj();
        j_set_str(o, "change", "本轮未见");
        j_set_str(o, "title", j_s(pf, "title", ""));
        j_set_str(o, "severity", j_s(pf, "severity", ""));
        j_set_str(o, "target", j_s(pf, "target", ""));
        j_add(items, o);
      }
      continue;
    }
    n_persist++;
    int pr = sev_rank(j_s(pf, "severity", "")), cr = sev_rank(j_s(it->second, "severity", ""));
    if (cr > pr) {
      n_escalated++;
      if (cr > top_rank) top_rank = cr;
      if (j_len(items) < 40) {
        json_t *o = j_obj();
        j_set_str(o, "change", "等级升高");
        j_set_str(o, "title", j_s(it->second, "title", ""));
        j_set_str(o, "severity", j_s(it->second, "severity", ""));
        j_set_str(o, "was", sev_name(pr));
        j_add(items, o);
      }
    }
  }

  int wrote = 0;
  if (n_new || n_fixed || n_escalated) {
    char *aid = store_next_id(s, "alerts");
    char ts[40];
    now_iso(ts, sizeof(ts));
    buf_t note, title;
    buf_init(&note);
    buf_init(&title);
    if (n_new) buf_printf(&title, "新增 %d 条", n_new);
    if (n_escalated) { if (title.len) buf_puts(&title, "、"); buf_printf(&title, "等级升高 %d 条", n_escalated); }
    if (n_fixed) { if (title.len) buf_puts(&title, "、"); buf_printf(&title, "%d 条本轮未见", n_fixed); }
    buf_printf(&note, "与上一轮比较:仍未修复 %d 条。", n_persist);
    if (n_fixed) buf_printf(&note, "「本轮未见」只说明这一轮没复现,不等于已修复 —— 要确认请跑复测。");

    json_t *a = j_obj();
    j_set_str(a, "id", aid);
    j_set_str(a, "kind", "周期变化");
    j_set_str(a, "finding_id", "");
    j_set_str(a, "task_id", task_id);
    j_set_str(a, "run_id", run_id);
    j_set_str(a, "auto_id", r->id);
    j_set_str(a, "domain", r->domain);
    j_set_str(a, "triggered_by", "周期巡检");
    j_set_str(a, "channel", "周期巡检");
    j_set_str(a, "severity", sev_name(top_rank >= 2 ? top_rank : 1));
    j_set_str(a, "status", "pending");
    j_set_str(a, "title", title.data);
    j_set_str(a, "target", r->domain);
    j_set_str(a, "note", note.data);
    j_set_str(a, "created_at", ts);
    j_set_num(a, "new", n_new);
    j_set_num(a, "fixed", n_fixed);
    j_set_num(a, "persist", n_persist);
    j_set_num(a, "escalated", n_escalated);
    j_set(a, "items", json_parse(json_dump(items)));
    store_append(s, "alerts", a);
    json_free(a);
    free(aid);
    buf_free(&note);
    buf_free(&title);
    wrote = 1;
  }

  /* 规则的统计与上次运行指针 */
  r->run_count++;
  r->change_count += wrote;
  char ts[40];
  now_iso(ts, sizeof(ts));
  snprintf(r->last_run_at, sizeof(r->last_run_at), "%s", ts);
  snprintf(r->last_run_id, sizeof(r->last_run_id), "%s", run_id);
  auto_save(s, r);

  if (prev) json_free(prev);
  json_free(items);
  json_free(cur);
  return wrote;
}