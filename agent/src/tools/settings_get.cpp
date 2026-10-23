/* settings_get.cpp —— 读设置:规则域 / 审批 / 周期巡检 / 模型 / 本单位定义
 *
 * 这个文件只包含这一个工具的实现(以及只被它使用的辅助函数)。
 * 公共手法(取数、URL 归一、软 404 校准)在 tool_common.cpp;
 * 注册表与协议在 src\main\tools.cpp 与 src\main\tool_entry.cpp。
 */
#include "tool_api.h"

/* ---- 0-C. 读设置 ---- */
int t_settings_get(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  const char *section = j_s(args, "section", "all");
  const char *domain = j_s(args, "domain", "");
  const char *key = j_s(args, "key", "");
  if (!section[0]) section = "all";
  /* 只给了 domain/key 就说明问的是规则:别再把审批/模型一并倒出来 */
  if (str_ieq(section, "all") && (domain[0] || key[0])) section = "rules";
  int all = str_ieq(section, "all");

  json_t *d = j_obj();
  j_set_str(d, "section", section);
  buf_t t;
  buf_init(&t);

  if (all || str_ieq(section, "rules")) {
    if (!domain[0] && key[0]) {
      /* 只问一个键:从"当前生效"的整份规则里取,路径可以是 a.b.c。
         用户问"超时现在是多少""告警门槛是哪一档"最常走这条。 */
      json_t *v = j_path(rules_root(), key);
      if (!v) {
        json_free(d);
        buf_free(&t);
        buf_t m;
        buf_init(&m);
        buf_printf(&m, "规则里没有 %s 这个键(可以先用 section=rules 看各域的键名)", key);
        return settings_fail(out, &m);
      }
      const rules_domain_t *owner = rules_domain_of_key(key);
      if (!owner) {
        char top[128];
        if (top_key_of(key, top, sizeof(top))) owner = rules_domain_of_key(top);
      }
      j_set_str(d, "key", key);
      if (owner) j_set_str(d, "domain", owner->id);
      char *dump = json_dump(v);
      json_t *copy = dump ? json_parse(dump) : NULL;
      free(dump);
      if (copy) j_set(d, "value", copy);
      buf_printf(&t, "规则 %s = ", key);
      value_text(&t, v);
      if (owner) buf_printf(&t, "  (属于 %s 域:%s)", owner->id, owner->title);
      buf_puts(&t, "\n");
    } else if (domain[0]) {
      char err[512] = {0};
      json_t *dom = rules_domains_read(domain, err, sizeof(err));
      if (!dom) {
        json_free(d);
        buf_t m;
        buf_init(&m);
        buf_printf(&m, "读不到规则域 %s:%s", domain, err[0] ? err : "未知原因");
        buf_free(&t);
        return settings_fail(out, &m);
      }
      if (key[0]) {
        /* 单键:从"当前生效"的整份规则里取,路径可以是 a.b.c */
        json_t *v = j_path(rules_root(), key);
        if (!v && dom) v = j_path(dom, key);
        if (!v) {
          json_free(dom);
          json_free(d);
          buf_t m;
          buf_init(&m);
          buf_printf(&m, "规则里没有 %s 这个键", key);
          buf_free(&t);
          return settings_fail(out, &m);
        }
        j_set_str(d, "key", key);
        char *dump = json_dump(v);
        json_t *copy = dump ? json_parse(dump) : NULL;
        free(dump);
        if (copy) j_set(d, "value", copy);
        buf_printf(&t, "规则 %s = ", key);
        value_text(&t, v);
        buf_puts(&t, "\n");
        json_free(dom);
      } else {
        const rules_domain_t *dd = rules_domain_find(domain);
        j_set_str(d, "domain", domain);
        j_set_str(d, "title", dd ? dd->title : domain);
        j_set(d, "rules", dom);
        char *pretty = json_dump_pretty(dom);
        buf_printf(&t, "规则域 %s(%s):\n%s\n", domain, dd ? dd->title : "",
                   pretty ? pretty : "{}");
        free(pretty);
      }
    } else {
      json_t *list = j_arr();
      buf_puts(&t, "规则域:");
      for (int i = 0; i < rules_domain_count(); i++) {
        const rules_domain_t *dd = rules_domain_at(i);
        if (!dd) continue;
        json_t *o = j_obj();
        j_set_str(o, "id", dd->id);
        j_set_str(o, "title", dd->title);
        j_set_str(o, "file", dd->file);
        j_set_str(o, "note", dd->note);
        j_add(list, o);
        buf_printf(&t, " %s(%s)", dd->id, dd->title);
      }
      buf_puts(&t, "\n");
      j_set(d, "domains", list);
      j_set_str(d, "source", rules_source());
    }
  }

  if (all || str_ieq(section, "approval")) {
    json_t *list = approval_list_json();
    buf_puts(&t, "审批策略(★ 为当前生效):\n");
    for (int i = 0; i < j_len(list); i++) {
      json_t *p = j_at(list, i);
      const char *id = j_s(p, "id", "");
      buf_printf(&t, "  %s %s  方式 %s%s%s\n", str_ieq(id, approval_active_id()) ? "★" : "-",
                 j_s(p, "name", id), j_s(p, "mode", ""),
                 j_s(p, "note", "")[0] ? "  · " : "", j_s(p, "note", ""));
    }
    j_set(d, "approval", list);
  }

  if (all || str_ieq(section, "models")) {
    json_t *list = j_arr();
    buf_puts(&t, "模型通道(★ 为当前使用):\n");
    for (int i = 0; i < providers_count(); i++) {
      provider_t *p = provider_at(i);
      if (!p) continue;
      json_t *o = j_obj();
      j_set_str(o, "id", p->id);
      j_set_str(o, "name", p->name);
      j_set_str(o, "kind", provider_kind_name(p->kind));
      j_set_bool(o, "ready", provider_ready(p));
      j_set_bool(o, "enabled", p->enabled);
      j_add(list, o);
      buf_printf(&t, "  %s %s(%s)%s\n", str_ieq(p->id, providers_active_id()) ? "★" : "-",
                 p->name, provider_kind_name(p->kind),
                 provider_ready(p) ? "" : "  · 未就绪");
    }
    j_set(d, "models", list);
  }

  if (all || str_ieq(section, "automation")) {
    store_t *s = (ctx && ctx->store) ? (store_t *)ctx->store : NULL;
    auto_rule_t *rules = NULL;
    int n = 0;
    if (s) auto_list(s, &rules, &n);
    json_t *list = j_arr();
    if (n == 0) {
      buf_puts(&t, "周期巡检:还没有规则\n");
    } else {
      buf_printf(&t, "周期巡检(%d 条):\n", n);
      for (int i = 0; i < n; i++) {
        json_t *o = auto_to_json(&rules[i]);
        j_add(list, o);
        char cyc[64];
        auto_cycle_text(&rules[i], cyc, sizeof(cyc));
        buf_printf(&t, "  - %s  %s  %s  %s%s\n", rules[i].id, rules[i].domain, cyc,
                   auto_scope_label(rules[i].scope), rules[i].enabled ? "" : "(已停用)");
      }
    }
    auto_free_list(rules);
    j_set(d, "automation", list);
  }

  if (all || str_ieq(section, "profile")) {
    json_t *o = j_obj();
    j_set_bool(o, "active", profile_is_active());
    j_set_str(o, "id", profile_active_id());
    j_set_str(o, "name", profile_active_name());
    j_set(d, "profile", o);
    buf_printf(&t, "敏感信息定义: %s\n",
               profile_is_active() ? profile_active_name() : "出厂口径(没有启用自定义定义)");
  }

  out->data = d;
  out->text = buf_take(&t);
  out->say = xstrdup("这些是当前设置。");
  return 0;
}
