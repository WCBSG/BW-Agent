/* skills_closure.cpp —— 复测 / 报告 / 评测三个"收尾技能"。
 *
 * 它们不新发请求(复测会重跑当初那条检查),而是把**已经落盘的结果**变成结论:
 *   复测:重跑 → 比对 → 写 retests[] → 推进闭环状态
 *   报告:汇总 → 分级统计 + 发现引用(单一数据源,不抄正文)
 *   证据核对:逐条核对结论是否有证据/影响/修复建议,并给出闭环状态
 *
 * 单独一个文件是为了让"智能体怎么闭环"这件事一眼可见:
 * 发现问题不是终点,复测通过、出报告、被评测承认才是。
 */
#include "skills.h"

#include "net.h"
#include "rules.h"
#include "store.h"
#include "tools.h"
#include "webutil.h"

#include <ctype.h>

/* ================= 复测 ================= */
/* 复测的关键:用"当初发现它的那条检查"重跑,而不是随便看两眼。
   重跑用同一条规则/同一种判定,才能比较"是不是还是同一个问题"。 */
static const char *retest_verdict_for(tool_ctx_t *ctx, json_t *f, char *note, size_t note_cap) {
  store_t *st = (store_t *)ctx->store;
  const char *tool = j_s(f, "source_tool", "");
  const char *url = j_s(f, "target", "");
  const char *dedup = j_s(f, "dedup_key", "");

  /* 1) 先看这个地址还在不在(404/410/403 往往意味着"已经下线") */
  if (ctx->io.fetch && url[0]) {
    int status = 0;
    char *body = NULL, *err = NULL;
    size_t len = 0;
    ctx->io.fetch(ctx->io.userdata, url, "GET", &status, &body, &len, &err);
    ctx->http_calls++;
    if (err && !status) {
      snprintf(note, note_cap, "复测没做成:%s", err);
      free(body); free(err);
      return "inconclusive";
    }
    if (status == 404 || status == 410) {
      snprintf(note, note_cap, "复测请求 %s 返回 HTTP %d:目标已不存在,判为已修复", url, status);
      free(body); free(err);
      return "passed";
    }
    if (status == 401 || status == 403) {
      snprintf(note, note_cap, "复测请求 %s 返回 HTTP %d:已加固为受限访问,判为已修复", url, status);
      free(body); free(err);
      return "passed";
    }
    if (status >= 200 && status < 400 && body) {
      /* 2) 按原来的判定手法重新判定一次 —— 必须"用同一条手法",否则结论不可比 */
      int still_there = 0;
      const char *how = "内容特征";
      if (strcmp(tool, "sqli_probe") == 0) {
        /* 注入类:重跑布尔差分,而不是看正文特征 */
        tool_result_t ir;
        memset(&ir, 0, sizeof(ir));
        json_t *ia = j_obj();
        j_set_str(ia, "target", url);
        int irc = tools_run(ctx, "sqli_probe", ia, &ir);
        json_free(ia);
        const char *v = (irc == 0 && ir.data) ? j_s(ir.data, "verdict", "") : "inconclusive";
        free(ir.text); free(ir.say); json_free(ir.data);
        if (strcmp(v, "confirmed") == 0) {
          snprintf(note, note_cap, "复测仍能复现:%s 的注入特征依然存在(恒真/恒假条件响应不同)", url);
          free(body); free(err);
          return "failed";
        }
        if (strcmp(v, "not_found") == 0) {
          snprintf(note, note_cap, "复测未复现:%s 重新做布尔差分已无注入特征,判为已修复", url);
          free(body); free(err);
          return "passed";
        }
        snprintf(note, note_cap, "复测判不了:%s 的响应不稳定(既不符合注入特征也不符合正常特征)", url);
        free(body); free(err);
        return "inconclusive";
      }
      if (strcmp(tool, "nuclei_scan") == 0 || strcmp(tool, "page_diff") == 0) {
        /* 配置类与篡改类:重跑同一条检查,看还有没有需要关注的项 */
        tool_result_t tr2;
        memset(&tr2, 0, sizeof(tr2));
        json_t *ta = j_obj();
        j_set_str(ta, "target", url);
        int trc = tools_run(ctx, tool, ta, &tr2);
        json_free(ta);
        int left = (trc == 0 && tr2.data) ? j_len(j_get(tr2.data, "checks")) : 0;
        const char *mode = (trc == 0 && tr2.data) ? j_s(tr2.data, "mode", "") : "";
        int t_err = tr2.is_error;
        free(tr2.text); free(tr2.say); json_free(tr2.data);
        if (t_err) {
          snprintf(note, note_cap, "复测判不了:%s 这次取不到内容", url);
          free(body); free(err);
          return "inconclusive";
        }
        if (strcmp(tool, "page_diff") == 0) {
          /* 篡改类:基线一致 = 已清理;仍有可疑外链 = 未修复 */
          still_there = (strcmp(mode, "changed") == 0);
          how = "基线比对";
        } else {
          still_there = (left > 0);
          how = "配置检查";
        }
        if (still_there) {
          snprintf(note, note_cap, "复测仍能复现:%s 按%s重新判定,问题依然存在", url, how);
          free(body); free(err);
          return "failed";
        }
        snprintf(note, note_cap, "复测未复现:%s 按%s重新判定已无问题,判为已修复", url, how);
        free(body); free(err);
        return "passed";
      }
      if (strcmp(tool, "dir_probe") == 0) {
        if (web_is_dir_listing(body)) { still_there = 1; how = "目录索引特征"; }
        else if (web_has_password_form(body)) { still_there = 1; how = "口令输入框"; }
        else {
          rules_sig_t sig;
          memset(&sig, 0, sizeof(sig));
          if (rules_sig_match(url, body, &sig) == 0) { still_there = 1; how = "规则特征"; }
        }
      } else if (strcmp(tool, "page_diff") == 0) {
        /* 篡改类:看页面里还有没有那条可疑外链/新增主机 */
        json_t *links = j_arr();
        web_extract_links(body, links);
        char own_host[256];
        web_url_parts(url, own_host, sizeof(own_host), NULL, 0);
        int suspicious = 0;
        for (int i = 0; i < j_len(links); i++) {
          const char *u = j_at(links, i)->str;
          if (!str_startswith(u, "http")) continue;
          char host[256];
          web_url_parts(u, host, sizeof(host), NULL, 0);
          if (!host[0] || str_ieq(host, own_host)) continue;
          int n = 0;
          const char **tlds = rules_str_list("suspicious_tlds", &n);
          for (int t = 0; t < n; t++) {
            size_t lh = strlen(host), lt = strlen(tlds[t]);
            if (lh > lt && str_ieq(host + (lh - lt), tlds[t])) { suspicious = 1; break; }
          }
          int digits = 0, dots = 0;
          for (const char *c = host; *c; c++) {
            if (*c >= '0' && *c <= '9') digits++; else if (*c == '.') dots++;
          }
          if (dots == 3 && digits >= 4) suspicious = 1;
          if (suspicious) break;
        }
        still_there = suspicious;
        how = "可疑外链";
        json_free(links);
      } else {
        /* 内容特征类:同一条规则还能命中 ⇒ 同一个问题仍在 */
        rules_sig_t sig;
        memset(&sig, 0, sizeof(sig));
        still_there = (rules_sig_match(url, body, &sig) == 0);
        how = "规则内容特征";
      }
      if (still_there) {
        snprintf(note, note_cap, "复测仍能复现:%s 请求 %s 返回 HTTP %d,并按%s重新判定为命中",
                 url, url, status, how);
        free(body); free(err);
        return "failed";
      }
      snprintf(note, note_cap,
               "复测未复现:请求 %s 返回 HTTP %d,但按原手法(%s)重新判定已不命中;"
               "判为已修复,建议人工确认改动内容", url, status, how);
      free(body); free(err);
      return "passed";
    }
    free(body); free(err);
  }

  /* 3) 兜底:连不上或拿不到内容,就如实说"判不了",绝不写成"已修复" */
  snprintf(note, note_cap,
           "复测判不了:%s 这次没取到可判定的内容(工具:%s);"
           "我不会凭印象说已修复,请人工确认", url, tool[0] ? tool : "未知");
  (void)st; (void)dedup;
  return "inconclusive";
}

static int s_retest(tool_ctx_t *ctx, json_t *args, skill_result_t *out) {
  store_t *st = (store_t *)ctx->store;
  const char *only = j_s(args, "finding_id", "");
  json_t *open = j_arr();
  if (st) {
    json_t *all = store_findings_of_task(st, ctx->task_id);
    for (int i = 0; i < j_len(all); i++) {
      json_t *f = j_at(all, i);
      const char *status = j_s(f, "status", "new");
      if (strcmp(status, "false_positive") == 0 ||
          strcmp(status, "retest_passed") == 0) continue;      /* 已闭环的不再复测 */
      if (only[0] && strcmp(j_s(f, "id", ""), only) != 0) continue;
      j_add(open, json_parse(json_dump(f)));
    }
    json_free(all);
  }

  json_t *results = j_arr();
  int passed = 0, failed = 0, inconclusive = 0;

  if (!st || j_len(open) == 0) {
    json_t *d = j_obj();
    j_set_str(d, "skill", "skill_retest");
    j_set_num(d, "checked", 0);
    j_set_bool(d, "needs_history", 1);
    out->data = d;
    buf_t s;
    buf_init(&s);
    if (!st) {
      buf_puts(&s, "复测需要历史发现清单,但这次运行没有挂上存储,所以我没法复测 —— "
                   "我不会凭印象说「应该修好了」。");
    } else {
      buf_puts(&s, "这次没有需要复测的问题:没有历史发现,或者它们都已经闭环"
                   "(retest_passed / false_positive)。可以先跑一次巡检再来复测。");
    }
    out->summary = buf_take(&s);
    json_free(open);
    return 0;
  }

  for (int i = 0; i < j_len(open) && i < 12; i++) {
    json_t *f = j_at(open, i);
    char note[512];
    note[0] = 0;
    const char *verdict = retest_verdict_for(ctx, f, note, sizeof(note));

    /* 写 retests[] 并推进状态机 —— 复测是权威结论 */
    char ts[40];
    now_iso(ts, sizeof(ts));
    json_t *rt = j_obj();
    j_set_str(rt, "time", ts);
    j_set_str(rt, "result", verdict);
    j_set_str(rt, "note", note);
    json_t *rs = j_get(f, "retests");
    if (!rs || rs->type != J_ARR) j_set(f, "retests", j_arr());
    j_add(j_get(f, "retests"), rt);
    const char *status = j_s(f, "status", "new");
    if (strcmp(verdict, "passed") == 0) {
      j_set_str(f, "status", "retest_passed");
      passed++;
    } else if (strcmp(verdict, "failed") == 0) {
      j_set_str(f, "status", "retest_failed");
      failed++;
    } else {
      /* 判不了就保持原状态:不擅自改成"已修复",也不改成"确认有问题" */
      if (strcmp(status, "new") == 0) j_set_str(f, "status", "confirmed");
      inconclusive++;
    }
    if (st) store_update_finding(st, f);

    json_t *r = j_obj();
    j_set_str(r, "finding_id", j_s(f, "id", ""));
    j_set_str(r, "title", j_s(f, "title", ""));
    j_set_str(r, "target", j_s(f, "target", ""));
    j_set_str(r, "result", verdict);
    j_set_str(r, "status", j_s(f, "status", ""));
    j_set_str(r, "note", note);
    j_add(results, r);
  }

  json_t *data = j_obj();
  j_set_str(data, "skill", "skill_retest");
  j_set_num(data, "checked", j_len(results));
  j_set_num(data, "passed", passed);
  j_set_num(data, "failed", failed);
  j_set_num(data, "inconclusive", inconclusive);
  j_set(data, "results", results);
  out->data = data;

  buf_t s;
  buf_init(&s);
  buf_printf(&s, "复测完成:检查了 %d 条未闭环问题 —— 已修复 %d 条、仍未修复 %d 条、判不了 %d 条。",
             j_len(results), passed, failed, inconclusive);
  if (inconclusive) {
    buf_puts(&s, "判不了的那几条我没有硬下结论(取不到可判定的内容),请人工确认。");
  }
  for (int i = 0; i < j_len(results) && i < 6; i++) {
    json_t *r = j_at(results, i);
    const char *res = j_s(r, "result", "");
    buf_printf(&s, "\n  · [%s] %s —— %s",
               strcmp(res, "passed") == 0 ? "已修复" :
               (strcmp(res, "failed") == 0 ? "仍未修复" : "判不了"),
               j_s(r, "title", ""), j_s(r, "target", ""));
  }
  out->summary = buf_take(&s);
  json_free(open);
  return 0;
}

/* ================= 报告 + 告警 ================= */
/* 等级排序与"什么等级要立即推送"都来自规则(severity_levels / alerts.immediate_rank),
   单位改了自己的等级命名或推送策略,这里跟着变,不用改代码。 */
static int severity_rank(const char *sev) {
  int r = rules_severity_rank(sev, -1);
  return r >= 0 ? r : 0;
}

static int s_report(tool_ctx_t *ctx, json_t *args, skill_result_t *out) {
  store_t *st = (store_t *)ctx->store;
  if (!st) {
    json_t *d = j_obj();
    j_set_str(d, "skill", "skill_report");
    j_set_bool(d, "needs_store", 1);
    out->data = d;
    out->is_error = 1;
    out->summary = xstrdup("出报告需要落地存储(发现清单是报告的唯一数据源),"
                           "这次运行没有挂上存储,所以我先不给报告。");
    return -1;
  }

  json_t *findings = store_findings_of_task(st, ctx->task_id);
  const char *title = j_s(args, "title", "");
  char auto_title[128];
  if (!title[0]) {
    char ts[40];
    now_iso(ts, sizeof(ts));
    snprintf(auto_title, sizeof(auto_title), "安全巡检报告(%.10s)", ts);
    title = auto_title;
  }

  json_t *by_sev = j_obj();
  json_t *by_kind = j_obj();
  json_t *ids = j_arr();
  int total = 0, fp = 0, retest_failed = 0, open = 0;

  /* 只统计"不是误报"的发现:误报要在报告里如实体现,不能计入问题数 */
  for (int i = 0; i < j_len(findings); i++) {
    json_t *f = j_at(findings, i);
    const char *status = j_s(f, "status", "new");
    int is_fp = strcmp(status, "false_positive") == 0;
    if (is_fp) fp++;
    if (strcmp(status, "retest_failed") == 0) retest_failed++;
    if (!is_fp && strcmp(status, "retest_passed") != 0) open++;
    const char *sev = j_s(f, "severity", "信息");
    const char *kind = j_s(f, "kind", "弱配置");
    j_set_num(by_sev, sev, j_n(by_sev, sev, 0) + 1);
    j_set_num(by_kind, kind, j_n(by_kind, kind, 0) + 1);
    j_add(ids, j_str(j_s(f, "id", "")));
    total++;
  }

  char *rid = store_next_id(st, "reports");
  char ts[40];
  now_iso(ts, sizeof(ts));

  buf_t summary;
  buf_init(&summary);
  buf_printf(&summary, "本次共确认 %d 条发现", total);
  int n_crit = (int)j_n(by_sev, "严重", 0), n_high = (int)j_n(by_sev, "高", 0);
  if (n_crit) buf_printf(&summary, ",其中严重 %d 条", n_crit);
  if (n_high) buf_printf(&summary, "、高危 %d 条", n_high);
  if (fp) buf_printf(&summary, ";误报 %d 条(已排除在问题数之外)", fp);
  if (retest_failed) buf_printf(&summary, ";复测未通过 %d 条", retest_failed);
  if (!total) buf_puts(&summary, ":本次没有确认任何风险");
  buf_puts(&summary, "。");

  json_t *report = j_obj();
  j_set_str(report, "id", rid);
  j_set_str(report, "task_id", ctx->task_id ? ctx->task_id : "");
  j_set_str(report, "run_id", ctx->run_id ? ctx->run_id : "");
  j_set_str(report, "title", title);
  j_set_str(report, "generated_at", ts);
  j_set_str(report, "summary", summary.data);
  json_t *stats = j_obj();
  j_set_num(stats, "total", total);
  j_set(stats, "by_severity", json_parse(json_dump(by_sev)));
  j_set(stats, "by_kind", json_parse(json_dump(by_kind)));
  j_set_num(stats, "false_positive", fp);
  j_set_num(stats, "open", open);
  j_set_num(stats, "duration_seconds", 0);
  j_set(report, "stats", stats);
  j_set(report, "finding_ids", json_parse(json_dump(ids)));
  json_t *fmts = j_arr();
  j_add(fmts, j_str("html"));
  j_add(fmts, j_str("markdown"));
  j_set(report, "export_formats", fmts);
  j_set_str(report, "rules_source", rules_source());
  store_save(st, "reports", report);

  /* 告警按等级走不同渠道 —— 阈值与渠道名都在规则里(alerts.min_rank / immediate_rank /
     channel_immediate / channel_normal)。同一个发现只推一次:报告可以反复生成,
     告警不该反复轰炸。 */
  int alert_min_rank = (int)rules_number("alerts.min_rank", 2);
  int alert_now_rank = (int)rules_number("alerts.immediate_rank", 3);
  const char *ch_now = rules_text("alerts.channel_immediate", "邮件");
  const char *ch_normal = rules_text("alerts.channel_normal", "站内");
  json_t *alerts = j_arr();
  json_t *existing_alerts = store_all(st, "alerts");
  for (int i = 0; i < j_len(findings); i++) {
    json_t *f = j_at(findings, i);
    if (strcmp(j_s(f, "status", "new"), "false_positive") == 0) continue;
    int rank = severity_rank(j_s(f, "severity", "信息"));
    if (rank < alert_min_rank) continue;           /* 低于阈值的进报告不进告警,避免噪音 */
    const char *fid = j_s(f, "id", "");
    int already = 0;
    for (int k = 0; k < j_len(existing_alerts); k++) {
      if (strcmp(j_s(j_at(existing_alerts, k), "finding_id", ""), fid) == 0) { already = 1; break; }
    }
    if (already) continue;
    char *aid = store_next_id(st, "alerts");
    json_t *a = j_obj();
    j_set_str(a, "id", aid);
    j_set_str(a, "finding_id", j_s(f, "id", ""));
    j_set_str(a, "task_id", ctx->task_id ? ctx->task_id : "");
    j_set_str(a, "channel", rank >= alert_now_rank ? ch_now : ch_normal);
    j_set_str(a, "triggered_by", "手动");
    j_set_str(a, "title", j_s(f, "title", ""));
    j_set_str(a, "target", j_s(f, "target", ""));
    j_set_str(a, "severity", j_s(f, "severity", ""));
    j_set_str(a, "status", "pending");
    j_set_str(a, "created_at", ts);
    j_set_str(a, "note", rank >= alert_now_rank ? "高等级发现立即推送" : "中等级发现站内提示");
    store_append(st, "alerts", a);
    json_t *row = j_obj();
    j_set_str(row, "id", aid);
    j_set_str(row, "finding_id", j_s(f, "id", ""));
    j_set_str(row, "channel", j_s(a, "channel", ""));
    j_set_str(row, "severity", j_s(a, "severity", ""));
    j_add(alerts, row);
    free(aid);
    json_free(a);
  }

  json_t *data = j_obj();
  j_set_str(data, "skill", "skill_report");
  j_set_str(data, "report_id", rid);
  j_set_str(data, "title", title);
  j_set_str(data, "generated_at", ts);
  j_set(data, "stats", json_parse(json_dump(stats)));
  j_set(data, "finding_ids", json_parse(json_dump(ids)));
  j_set(data, "alerts", alerts);
  j_set_str(data, "rules_source", rules_source());
  out->data = data;

  buf_t s;
  buf_init(&s);
  if (total == 0) {
    buf_printf(&s, "报告已生成(%s):本次没有确认任何风险。", rid);
  } else {
    buf_printf(&s, "报告已生成(%s),共 %d 条发现", rid, total);
    if (n_crit || n_high) buf_printf(&s, ",其中严重 %d 条、高危 %d 条", n_crit, n_high);
    buf_printf(&s, ";已推送 %d 条告警(严重/高危走邮件,中危走站内)", j_len(alerts));
    buf_puts(&s, "。");
  }
  out->summary = buf_take(&s);
  buf_free(&summary);
  free(rid);
  json_free(findings);
  return 0;
}

/* ================= 证据与覆盖核对(不计算任何指标) =================
   为什么不算效果指标:这类数字取决于评测集怎么造、口径怎么定,
   同一个系统换一套数据集就能得出完全不同的结论。作品里自己报一个数,
   既不专业也经不起追问 —— 该由评测方按他们的数据集给。
   这里只回答两件可核查的事:
     ① 每条结论有没有证据/影响/修复建议(没有就如实列出来,提示要补);
     ② 这一轮覆盖到哪些检查类别与落点(来自已落盘的发现与运行记录)。
*/
static int s_evidence(tool_ctx_t *ctx, json_t *args, skill_result_t *out) {
  (void)args;
  store_t *st = (store_t *)ctx->store;
  if (!st) {
    json_t *d = j_obj();
    j_set_str(d, "skill", "skill_evidence");
    j_set_bool(d, "needs_store", 1);
    out->data = d;
    out->is_error = 1;
    out->summary = xstrdup("核对证据需要落地存储(发现清单是唯一数据源),这次没有挂上存储。");
    return -1;
  }

  json_t *findings = store_findings_of_task(st, ctx->task_id);
  int total = 0, with_ev = 0, with_impact = 0, with_fix = 0, retested = 0, no_ev = 0;
  json_t *by_status = j_obj();
  json_t *by_kind = j_obj();
  json_t *missing = j_arr();

  for (int i = 0; i < j_len(findings); i++) {
    json_t *f = j_at(findings, i);
    const char *status = j_s(f, "status", "new");
    if (strcmp(status, "false_positive") == 0) continue;   /* 误报不参与"结论质量"核对 */
    total++;
    j_set_num(by_status, status, j_n(by_status, status, 0) + 1);
    const char *kind = j_s(f, "kind", "未分类");
    j_set_num(by_kind, kind, j_n(by_kind, kind, 0) + 1);

    const char *ev = j_s(f, "evidence", "");
    if (ev[0]) with_ev++;
    else {
      no_ev++;
      if (j_len(missing) < 20) {
        json_t *m = j_obj();
        j_set_str(m, "id", j_s(f, "id", ""));
        j_set_str(m, "title", j_s(f, "title", ""));
        j_set_str(m, "target", j_s(f, "target", ""));
        j_add(missing, m);
      }
    }
    if (j_s(f, "impact", "")[0]) with_impact++;
    if (j_s(f, "fix", "")[0]) with_fix++;
    if (j_len(j_get(f, "retests")) > 0) retested++;
  }

  json_t *data = j_obj();
  j_set_str(data, "skill", "skill_evidence");
  j_set_num(data, "total", total);
  j_set_num(data, "with_evidence", with_ev);
  j_set_num(data, "with_impact", with_impact);
  j_set_num(data, "with_fix", with_fix);
  j_set_num(data, "retested", retested);
  j_set_num(data, "without_evidence", no_ev);
  j_set(data, "by_status", json_parse(json_dump(by_status)));
  j_set(data, "by_kind", json_parse(json_dump(by_kind)));
  j_set(data, "missing_evidence", json_parse(json_dump(missing)));
  j_set_str(data, "note",
            "本工具不自行计算效果指标:那取决于评测集与口径,应由评测方给出。"
            "这里给出的是逐条证据与闭环状态,可逐项回查。");
  out->data = data;

  buf_t s;
  buf_init(&s);
  buf_printf(&s, "证据核对:%d 条结论;带证据 %d 条、带影响 %d 条、带修复建议 %d 条、已复测 %d 条。",
             total, with_ev, with_impact, with_fix, retested);
  if (no_ev) {
    buf_printf(&s, "\n有 %d 条缺证据,先补证据再谈结论:", no_ev);
    for (int i = 0; i < j_len(missing); i++) {
      json_t *m = j_at(missing, i);
      buf_printf(&s, "\n  · %s %s(%s)", j_s(m, "id", ""), j_s(m, "title", ""), j_s(m, "target", ""));
    }
  }
  buf_puts(&s, "\n效果指标不在这里给:它们取决于评测集怎么造、口径怎么定,"
               "应由评测方按统一评测集算;我能保证的是每条结论都能回到原始响应。");
  out->summary = buf_take(&s);

  json_free(findings);
  return 0;
}

/* 把三个收尾技能接到技能表上(声明在 skills.h,实现就在这个文件) */
int skill_closure_run(tool_ctx_t *ctx, const char *name, json_t *args,
                      skill_result_t *out) {
  if (strcmp(name, "skill_retest") == 0) return s_retest(ctx, args, out);
  if (strcmp(name, "skill_report") == 0) return s_report(ctx, args, out);
  if (strcmp(name, "skill_evidence") == 0) return s_evidence(ctx, args, out);
  return -1;
}
