/* password_check.cpp —— 口令强度评估
 *
 * 这个文件只包含这一个工具的实现(以及只被它使用的辅助函数)。
 * 公共手法(取数、URL 归一、软 404 校准)在 tool_common.cpp;
 * 注册表与协议在 src\main\tools.cpp 与 src\main\tool_entry.cpp。
 */
#include "tool_api.h"

/* ---- 2. 口令强度 ---- */
/* 弱口令表来自规则文件(weak_passwords)。表里没有就只按强度规则算分——
   这不是"少了功能",而是"口径跟着规则走":不同单位可以放自己的历史泄露口令表。 */
int t_password_check(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  (void)ctx;
  const char *pw = j_s(args, "password", "");
  int score = 100;
  json_t *issues = j_arr();
  int weak_n = 0;
  const char **weak = rules_str_list("weak_passwords", &weak_n);
  for (int i = 0; i < weak_n; i++) {
    if (str_ieq(pw, weak[i])) {
      j_add(issues, j_str("命中常见弱口令表"));
      score -= 60;
      break;
    }
  }
  size_t len = strlen(pw);
  if (len < 8) { j_add(issues, j_str("长度不足 8 位")); score -= 20; }
  else if (len < 12) { j_add(issues, j_str("建议加长到 12 位以上")); score -= 8; }
  int has_upper = 0, has_lower = 0, has_digit = 0, has_sym = 0;
  for (const char *p = pw; *p; p++) {
    if (isupper((unsigned char)*p)) has_upper = 1;
    else if (islower((unsigned char)*p)) has_lower = 1;
    else if (isdigit((unsigned char)*p)) has_digit = 1;
    else has_sym = 1;
  }
  if (!has_upper) { j_add(issues, j_str("缺大写字母")); score -= 8; }
  if (!has_lower) { j_add(issues, j_str("缺小写字母")); score -= 8; }
  if (!has_digit) { j_add(issues, j_str("缺数字")); score -= 8; }
  if (!has_sym) { j_add(issues, j_str("缺符号")); score -= 8; }
  if (score < 0) score = 0;
  const char *level = score < 50 ? "弱" : (score < 80 ? "中" : "强");

  json_t *data = j_obj();
  j_set_num(data, "score", score);
  j_set_str(data, "level", level);
  j_set(data, "issues", issues);
  out->data = data;

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "等级: %s(%d/100)\n", level, score);
  for (int i = 0; i < j_len(issues); i++) {
    buf_printf(&t, "- %s\n", j_at(issues, i)->str);
  }
  out->text = buf_take(&t);
  buf_t s;
  buf_init(&s);
  buf_printf(&s, "口令评估结果:【%s】(%d/100 分),发现 %d 个问题,详见结果卡片。",
             level, score, j_len(issues));
  out->say = buf_take(&s);
  return 0;
}
