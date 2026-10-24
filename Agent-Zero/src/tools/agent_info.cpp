/* agent_info.cpp —— 智能体自身信息:一次拿全状态
 *
 * 这个文件只包含这一个工具的实现(以及只被它使用的辅助函数)。
 * 公共手法(取数、URL 归一、软 404 校准)在 tool_common.cpp;
 * 注册表与协议在 src\main\tools.cpp 与 src\main\tool_entry.cpp。
 */
#include "tool_api.h"

/* ---- 0-B. 智能体自身的信息 ----
   为什么值得单独一个工具:模型对"自己是谁、现在什么状态"经常瞎猜 ——
   猜数据目录、猜用的是哪家模型、猜已经查了多少条。这里给的都是真值。 */
int t_agent_info(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  (void)args;
  json_t *d = j_obj();
  j_set_str(d, "dataDir", app_data_dir());
  j_set_str(d, "exeDir", app_dir());

  json_t *model = j_obj();
  j_set_str(model, "active", providers_active_id());
  j_set_str(model, "display", providers_display_name());
  j_set_num(model, "configured", providers_count());
  j_set_num(model, "ready", providers_ready_count());
  j_set_bool(model, "usable", providers_ready_count() > 0);
  j_set(d, "model", model);

  char **pool = NULL;
  int pn = net_pool_snapshot(&pool);
  json_t *pallow = j_arr();
  json_t *pdeny = j_arr();
  for (int i = 0; i < pn; i++) {
    const char *e = pool[i];
    if (!e || !e[0]) continue;
    if (e[0] == '!') j_add(pdeny, j_str(e + 1));
    else j_add(pallow, j_str(e));
  }
  json_t *poolj = j_obj();
  j_set(poolj, "allowed", pallow);
  j_set(poolj, "denied", pdeny);
  j_set_num(poolj, "allowed_count", j_len(pallow));
  j_set_num(poolj, "denied_count", j_len(pdeny));
  j_set(d, "pool", poolj);

  json_t *aj = j_obj();
  j_set_str(aj, "active", approval_active_id());
  j_set_str(aj, "mode", approval_mode_text());
  j_set_bool(aj, "allowAll", approval_is_allow_all());
  j_set(d, "approval", aj);

  json_t *rj = j_obj();
  j_set_str(rj, "source", rules_source());
  j_set_bool(rj, "fromFile", rules_from_file());
  json_t *doms = j_arr();
  for (int i = 0; i < rules_domain_count(); i++) {
    const rules_domain_t *dd = rules_domain_at(i);
    if (!dd) continue;
    json_t *o = j_obj();
    j_set_str(o, "id", dd->id);
    j_set_str(o, "title", dd->title);
    j_add(doms, o);
  }
  j_set(rj, "domains", doms);
  j_set(d, "rules", rj);

  json_t *counts = j_obj();
  if (ctx && ctx->store) {
    store_t *s = (store_t *)ctx->store;
    j_set_num(counts, "findings", store_count(s, "findings"));
    j_set_num(counts, "runs", store_count(s, "runs"));
    j_set_num(counts, "assets", store_count(s, "assets"));
    j_set_num(counts, "alerts", store_count(s, "alerts"));
    j_set_num(counts, "automations", store_count(s, "automations"));
  }
  j_set(d, "counts", counts);

  j_set_num(d, "skills", skills_count());
  j_set_num(d, "tools", tools_count());
  out->data = d;

  buf_t t;
  buf_init(&t);
  buf_puts(&t, "BlueWhiteAgent · 本机信息\n");
  buf_printf(&t, "  数据目录 : %s\n", app_data_dir());
  buf_printf(&t, "  当前模型 : %s(%d 家已配置,%d 家可用)\n",
             providers_display_name(), providers_count(), providers_ready_count());
  buf_printf(&t, "  授权池   : %d 个允许目标", j_len(pallow));
  for (int i = 0; i < j_len(pallow) && i < 12; i++) {
    json_t *v = j_at(pallow, i);
    if (v && v->str) buf_printf(&t, " %s", v->str);
  }
  if (j_len(pdeny) > 0) {
    buf_printf(&t, " · %d 条不允许", j_len(pdeny));
  }
  buf_puts(&t, "\n");
  buf_printf(&t, "  审批策略 : %s(%s)\n", approval_mode_text(), approval_active_id());
  buf_printf(&t, "  规则来源 : %s(%d 个域)\n", rules_source(), rules_domain_count());
  if (ctx && ctx->store) {
    store_t *s = (store_t *)ctx->store;
    buf_printf(&t, "  已落盘   : 发现 %d 条 · 运行 %d 次 · 资产 %d 个 · 告警 %d 条 · 周期规则 %d 条\n",
               store_count(s, "findings"), store_count(s, "runs"), store_count(s, "assets"),
               store_count(s, "alerts"), store_count(s, "automations"));
  }
  buf_printf(&t, "  能力     : 技能 %d 个 · 工具 %d 个\n", skills_count(), tools_count());
  buf_puts(&t, "\n这些是当前真实值;要改规则/周期/模型/审批用 settings_set(授权池只能由人在界面里加)。");
  out->text = buf_take(&t);
  out->say = xstrdup("我看了一下自己的状态,见上面的信息。");
  str_free_list(pool, pn);
  return 0;
}
