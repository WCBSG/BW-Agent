/* sqli_probe.cpp —— 注入验证(布尔差分 + 错误特征;不取数据、不写数据)
 *
 * 这个文件只包含这一个工具的实现(以及只被它使用的辅助函数)。
 * 公共手法(取数、URL 归一、软 404 校准)在 tool_common.cpp;
 * 注册表与协议在 src\main\tools.cpp 与 src\main\tool_entry.cpp。
 */
#include "tool_api.h"

/* ---- 8. 注入验证(布尔差分 + 错误特征;不取数据、不写数据) ---- */
int t_sqli_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  char target_buf[2048];
  normalize_target(j_s(args, "target", ""), target_buf, sizeof(target_buf));
  const char *target = target_buf;
  const char *want_param = j_s(args, "param", "");

  json_t *params = j_arr();
  web_url_params(target, params);
  if (want_param[0]) {
    /* 指定了参数但地址里没有 → 按"这个参数存在"处理(补上再测) */
    json_t *one = j_arr();
    j_add(one, j_str(want_param));
    json_free(params);
    params = one;
  }
  if (j_len(params) == 0) {
    json_t *d = j_obj();
    j_set_str(d, "target", target);
    j_set_str(d, "verdict", "not_testable");
    j_set_str(d, "reason", "地址里没有查询参数,没有可以验证的输入点");
    out->data = d;
    out->text = xstrdup("这个地址没有查询参数,注入验证没有输入点,本次未做");
    out->say = xstrdup("这个地址没有可测的参数(要带 ?参数=值 这样的地址),所以我没法做注入验证。");
    return 0;
  }

  /* 基线:原样请求一次,后面所有对比都以它为准 */
  fetch_t base;
  t_fetch(ctx, target, &base);
  if (base.err && !base.status) {
    json_t *d = j_obj();
    j_set_str(d, "target", target);
    j_set_str(d, "error", base.err ? base.err : "取不到内容");
    j_set_str(d, "verdict", "unreachable");
    out->data = d;
    out->is_error = 1;
    out->text = xstrdup("目标取不到内容,注入验证无法进行");
    out->say = xstrdup("目标连不上,我不给注入结论。");
    fetch_free2(&base);
    return -1;
  }
  buf_t base_shape;
  buf_init(&base_shape);
  web_shape(&base_shape, base.body ? base.body : "");
  size_t base_bytes = base.body ? strlen(base.body) : 0;

  int max_params = (int)rules_number("max_params", 3);
  if (max_params < 1) max_params = 3;

  json_t *tests = j_arr();
  int confirmed = 0, inconclusive = 0;
  char evidence[512] = {0};

  /* 布尔差分的载荷族来自规则文件(payloads.boolean_diff):
     不同数据库/框架的注释与引号规则不一样,单位可以自己加族,不用重编译。 */
  int fam_n = rules_arr_count("payloads.boolean_diff");

  for (int pi = 0; pi < j_len(params) && pi < max_params; pi++) {
    const char *param = j_at(params, pi)->str;
    for (int fam = 0; fam < fam_n; fam++) {
      const char *p_true = rules_arr_str("payloads.boolean_diff", fam, "true", "");
      const char *p_false = rules_arr_str("payloads.boolean_diff", fam, "false", "");
      const char *ctx_name = rules_arr_str("payloads.boolean_diff", fam, "context", "默认");
      if (!p_true[0] || !p_false[0]) continue;
      buf_t ut, uf;
      buf_init(&ut);
      buf_init(&uf);
      web_url_set_param(target, param, p_true, &ut);
      web_url_set_param(target, param, p_false, &uf);
      fetch_t ft, ff;
      t_fetch(ctx, ut.data, &ft);
      t_fetch(ctx, uf.data, &ff);

      int t_reach = !(ft.err && !ft.status);
      int f_reach = !(ff.err && !ff.status);
      int t_same = t_reach && web_same_shape(ft.body, base.body);
      int f_same = f_reach && web_same_shape(ff.body, base.body);
      int tf_same = t_reach && f_reach && web_same_shape(ft.body, ff.body);

      const char *verdict = "not_injectable";
      if (!t_reach || !f_reach) verdict = "inconclusive";
      else if (!t_same && !f_same && !tf_same) verdict = "inconclusive";
      else if (t_same && !f_same) verdict = "confirmed";

      json_t *rec = j_obj();
      j_set_str(rec, "param", param);
      j_set_str(rec, "context", ctx_name);
      j_set_str(rec, "payload_true", p_true);
      j_set_str(rec, "payload_false", p_false);
      j_set_str(rec, "verdict", verdict);
      j_set_num(rec, "status_true", ft.status);
      j_set_num(rec, "status_false", ff.status);
      j_set_num(rec, "bytes_true", ft.body ? (double)strlen(ft.body) : 0);
      j_set_num(rec, "bytes_false", ff.body ? (double)strlen(ff.body) : 0);
      j_set_bool(rec, "true_matches_baseline", t_same);
      j_set_bool(rec, "false_matches_baseline", f_same);
      j_add(tests, rec);

      if (strcmp(verdict, "confirmed") == 0) {
        confirmed++;
        if (!evidence[0]) {
          snprintf(evidence, sizeof(evidence),
                   "参数 %s 在恒真与恒假条件下响应不同(恒真 %d 字节与基线一致,恒假 %d 字节)",
                   param, (int)(ft.body ? strlen(ft.body) : 0),
                   (int)(ff.body ? strlen(ff.body) : 0));
        }
      } else if (strcmp(verdict, "inconclusive") == 0) {
        inconclusive++;
      }
      (void)base_bytes;
      fetch_free2(&ft);
      fetch_free2(&ff);
      buf_free(&ut);
      buf_free(&uf);
    }
  }

  /* 错误回显单独探一次:报错里带库信息是最可靠的证据 */
  char err_sig[128] = {0};
  {
    buf_t ue;
    buf_init(&ue);
    const char *p0 = j_len(params) > 0 ? j_at(params, 0)->str : "";
    web_url_set_param(target, p0, "1'", &ue);
    fetch_t fe;
    t_fetch(ctx, ue.data, &fe);
    if (!(fe.err && !fe.status) && fe.body) {
      int n = 0;
      const char **sigs = rules_str_list("error_signatures", &n);
      for (int i = 0; i < n; i++) {
        if (str_icontains(fe.body, sigs[i])) { snprintf(err_sig, sizeof(err_sig), "%s", sigs[i]); break; }
      }
    }
    fetch_free2(&fe);
    buf_free(&ue);
  }

  json_t *data = j_obj();
  j_set_str(data, "target", target);
  j_set_str(data, "method", "布尔差分 + 错误特征(只读,不取数据)");
  j_set(data, "tests", tests);
  j_set_num(data, "confirmed_tests", confirmed);
  j_set_num(data, "inconclusive_tests", inconclusive);
  j_set_str(data, "error_signature", err_sig);
  j_set_str(data, "verdict",
            err_sig[0] || confirmed ? "confirmed" : (inconclusive ? "inconclusive" : "not_found"));
  j_set_str(data, "evidence", err_sig[0] ? err_sig : evidence);
  j_set_num(data, "candidate_count", (err_sig[0] || confirmed) ? 1 : 0);
  put_rules_note(data);
  out->data = data;
  if (err_sig[0] || confirmed) {
    j_set_str(data, "kind", "漏洞");
    j_set_str(data, "severity", "严重");
    j_set_str(data, "param", j_len(params) > 0 ? j_at(params, 0)->str : "");
  }

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "注入验证 %s:比对 %d 组恒真/恒假响应,确认 %d 组,无法判定 %d 组。",
             target, j_len(tests), confirmed, inconclusive);
  if (err_sig[0]) buf_printf(&t, "\n错误回显特征:%s", err_sig);
  for (int i = 0; i < j_len(tests); i++) {
    buf_printf(&t, "\n- %s [%s] %s → %s", j_s(j_at(tests, i), "param", ""),
               j_s(j_at(tests, i), "context", ""), j_s(j_at(tests, i), "payload_true", ""),
               j_s(j_at(tests, i), "verdict", ""));
  }
  out->text = buf_take(&t);

  buf_t s;
  buf_init(&s);
  if (err_sig[0]) {
    buf_printf(&s, "注入验证结果:确认存在注入 —— 服务端把数据库报错回显了出来(特征:%s)。"
                   "我没有取任何数据,只做了验证。", err_sig);
  } else if (confirmed) {
    buf_printf(&s, "注入验证结果:确认 %s 存在注入。恒真条件与正常响应一致、恒假条件明显不同,"
                   "这是布尔注入的典型特征。建议立即修复参数化查询。",
               j_len(params) > 0 ? j_at(params, 0)->str : "该参数");
  } else if (inconclusive) {
    buf_printf(&s, "注入验证结果没法下结论:%d 组响应波动(可能是页面含随机内容),"
                   "既不满足注入特征也不满足正常特征。我不硬报结论。", inconclusive);
  } else {
    buf_printf(&s, "注入验证完成:%d 组测试都没出现布尔差异,未发现注入迹象"
                   "(不代表绝对没有,只是当前手法没验证出来)。", j_len(tests));
  }
  out->say = buf_take(&s);
  buf_free(&base_shape);
  fetch_free2(&base);
  return 0;
}
