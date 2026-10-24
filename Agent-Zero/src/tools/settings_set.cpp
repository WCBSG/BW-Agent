/* settings_set.cpp —— 改设置:规则按域存、审批只能收紧、周期规则目标必须在池内
 *
 * 这个文件只包含这一个工具的实现(以及只被它使用的辅助函数)。
 * 公共手法(取数、URL 归一、软 404 校准)在 tool_common.cpp;
 * 注册表与协议在 src\main\tools.cpp 与 src\main\tool_entry.cpp。
 */
#include "tool_api.h"

/* ---- 0-D. 改设置 ----
   写入的边界(三条,都是为了不让模型给自己扩权):
     ① 授权池只读 —— 往池里加站必须由人在界面上确认授权;
     ② 审批只能换成更严的 —— "全部允许"必须由人点;
     ③ 周期规则的目标必须在授权池内 —— 否则模型能凭空加一个站去周期性地查。
   其余的(检测口径、周期、当前模型)可以改,但每次都写审计。 */
int t_settings_set(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  const char *section = j_s(args, "section", "");
  if (!section[0]) {
    buf_t m;
    buf_init(&m);
    buf_puts(&m, "需要 section:rules / automation / models / approval 之一。");
    return settings_fail(out, &m);
  }

  /* ---------- 规则:按域保存并立即重载 ---------- */
  if (str_ieq(section, "rules")) {
    const char *domain = j_s(args, "domain", "");
    if (!domain[0]) {
      buf_t m;
      buf_init(&m);
      buf_puts(&m, "section=rules 需要 domain。可用的域:");
      for (int i = 0; i < rules_domain_count(); i++) {
        const rules_domain_t *dd = rules_domain_at(i);
        if (dd) buf_printf(&m, " %s", dd->id);
      }
      return settings_fail(out, &m);
    }
    const rules_domain_t *dd = rules_domain_find(domain);
    if (!dd) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "没有 %s 这个域。可用的域:", domain);
      for (int i = 0; i < rules_domain_count(); i++) {
        const rules_domain_t *x = rules_domain_at(i);
        if (x) buf_printf(&m, " %s", x->id);
      }
      return settings_fail(out, &m);
    }

    json_t *patch = obj_arg(args, "patch");
    if (!patch) {
      const char *k = j_s(args, "key", "");
      if (!k[0]) {
        buf_t m;
        buf_init(&m);
        buf_puts(&m, "section=rules 需要 patch(这一域要改的字段),或者 key + value。");
        return settings_fail(out, &m);
      }
      json_t *v = value_arg(args, "value");
      if (!v) {
        buf_t m;
        buf_init(&m);
        buf_printf(&m, "改 %s 需要给 value。", k);
        return settings_fail(out, &m);
      }
      char top[128];
      if (!top_key_of(k, top, sizeof(top))) {
        json_free(v);
        buf_t m;
        buf_init(&m);
        buf_printf(&m, "键名不合法:%s", k);
        return settings_fail(out, &m);
      }
      const char *dot = strchr(k, '.');
      if (dot) {
        /* 嵌套键:在"现有内容"上打点,再整键提交 */
        char err[512] = {0};
        json_t *dom = rules_domains_read(domain, err, sizeof(err));
        if (!dom) {
          json_free(v);
          buf_t m;
          buf_init(&m);
          buf_printf(&m, "读不到规则域 %s:%s", domain, err[0] ? err : "未知原因");
          return settings_fail(out, &m);
        }
        json_t *cur = j_get(dom, top);
        if (!cur || cur->type != J_OBJ) {
          cur = j_obj();
          j_set(dom, top, cur);
        }
        if (!deep_set(cur, dot + 1, v)) {
          json_free(dom);
          buf_t m;
          buf_init(&m);
          buf_printf(&m, "键名不合法:%s", k);
          return settings_fail(out, &m);
        }
        patch = j_obj();
        char *d = json_dump(cur);
        json_t *cp = d ? json_parse(d) : NULL;
        free(d);
        if (cp) j_set(patch, top, cp);
        json_free(dom);
      } else {
        patch = j_obj();
        j_set(patch, k, v);
      }
    }
    if (patch->type != J_OBJ) {
      json_free(patch);
      buf_t m;
      buf_init(&m);
      buf_puts(&m, "patch 要是一个对象,例如 {\"timeout_ms\":15000}。");
      return settings_fail(out, &m);
    }

    /* 只报"这一域认的键",别的键 save 会忽略 —— 提前告诉模型,免得白改 */
    char changed[512] = {0};
    {
      buf_t keys;
      buf_init(&keys);
      join_keys(&keys, patch);
      snprintf(changed, sizeof(changed), "%s", keys.data ? keys.data : "");
      buf_free(&keys);
    }
    char err[512] = {0};
    int rc = rules_domains_save(domain, patch, err, sizeof(err));
    json_free(patch);
    if (rc != 0) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "保存规则域 %s 失败:%s", domain, err[0] ? err : "未知原因");
      return settings_fail(out, &m);
    }
    /* 保存即生效:和界面里点保存走的是同一条路(不重启) */
    rules_shutdown();
    rules_init(app_dir());
    settings_audit(ctx, "修改规则(智能体)", dd->title, changed[0] ? changed : "按域更新");

    json_t *d = j_obj();
    j_set_bool(d, "ok", 1);
    j_set_str(d, "domain", domain);
    j_set_str(d, "title", dd->title);
    j_set_str(d, "source", rules_source());
    out->data = d;
    buf_t t;
    buf_init(&t);
    buf_printf(&t, "已保存规则域 %s(%s)并立即生效。改动的键:%s\n规则来源现在是 %s。",
               domain, dd->title, changed[0] ? changed : "(未指定)", rules_source());
    out->text = buf_take(&t);
    out->say = xstrdup("规则已经按你说的改好并生效了。");
    return 0;
  }

  /* ---------- 周期巡检 ---------- */
  if (str_ieq(section, "automation")) {
    store_t *s = (ctx && ctx->store) ? (store_t *)ctx->store : NULL;
    if (!s) {
      buf_t m;
      buf_init(&m);
      buf_puts(&m, "当前没有存储句柄(命令行/自检环境不支持改周期规则)。");
      return settings_fail(out, &m);
    }
    const char *action = j_s(args, "action", "save");
    char id[24];
    snprintf(id, sizeof(id), "%s", j_s(args, "id", ""));

    if (str_ieq(action, "remove")) {
      if (!id[0]) {
        buf_t m;
        buf_init(&m);
        buf_puts(&m, "删除周期规则需要 id(先用 settings_get section=automation 查到)。");
        return settings_fail(out, &m);
      }
      if (auto_remove(s, id) != 0) {
        buf_t m;
        buf_init(&m);
        buf_printf(&m, "没有找到周期规则 %s", id);
        return settings_fail(out, &m);
      }
      settings_audit(ctx, "删除周期巡检(智能体)", id, "智能体调用 settings_set");
      json_t *d = j_obj();
      j_set_bool(d, "ok", 1);
      j_set_str(d, "removed", id);
      out->data = d;
      out->text = xstrdup("已删除这条周期巡检规则,后续不会再自动跑。");
      out->say = xstrdup("这条周期巡检已经删掉了。");
      return 0;
    }

    json_t *ro = obj_arg(args, "rule");
    if (!ro || ro->type != J_OBJ) {
      json_free(ro);
      buf_t m;
      buf_init(&m);
      buf_puts(&m, "action=save 需要 rule(对象),例如 "
                   "{\"domain\":\"exp.com\",\"scope\":\"full\",\"kind\":\"interval\",\"every_min\":360}。");
      return settings_fail(out, &m);
    }

    /* 改已有规则时只覆盖调用方给出的字段,别把 name/created_at 冲掉 */
    auto_rule_t old;
    memset(&old, 0, sizeof(old));
    int have_old = id[0] && auto_find(s, id, &old) == 0;
    json_t *merged = have_old ? auto_to_json(&old) : j_obj();
    for (int i = 0; i < ro->count; i++) {
      if (!ro->keys[i]) continue;
      char *dump = json_dump(ro->items[i]);
      json_t *cp = dump ? json_parse(dump) : NULL;
      free(dump);
      if (cp) j_set(merged, ro->keys[i], cp);
    }
    json_free(ro);
    if (id[0]) j_set_str(merged, "id", id);

    auto_rule_t r;
    auto_from_json(merged, &r);
    json_free(merged);

    const char *bad = auto_validate(&r);
    if (bad) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "周期规则不合法:%s", bad);
      return settings_fail(out, &m);
    }
    /* 授权边界:周期规则会自己发请求,目标必须是已经有授权的。
       措辞避开 "不在授权池内" —— 那句话是决策循环的硬停止信号。 */
    char host[256] = {0};
    int port = net_host_port_of(r.domain, host, sizeof(host));
    if (!host[0]) snprintf(host, sizeof(host), "%s", r.domain);
    if (!net_pool_has(host, port, "/")) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "目标 %s 还没有被授权,不能建周期规则。"
                     "请让用户在界面的授权池里确认这个主机,再由我来加周期。", r.domain);
      return settings_fail(out, &m);
    }
    int rc = auto_save(s, &r);
    if (rc != 0) {
      buf_t m;
      buf_init(&m);
      buf_puts(&m, "周期规则保存失败(存储写入出错)。");
      return settings_fail(out, &m);
    }
    settings_audit(ctx, have_old ? "修改周期巡检(智能体)" : "新建周期巡检(智能体)", r.domain,
                   r.id);
    char cyc[64];
    auto_cycle_text(&r, cyc, sizeof(cyc));

    json_t *d = auto_to_json(&r);
    out->data = d;
    buf_t t;
    buf_init(&t);
    buf_printf(&t, "%s周期巡检:%s %s %s(%s)。\n到点会自动跑一轮,并与上一轮比差异;有变化才告警。",
               have_old ? "已更新" : "已新建", r.id, r.domain, cyc,
               auto_scope_label(r.scope));
    out->text = buf_take(&t);
    out->say = xstrdup("周期巡检已经设好了。");
    return 0;
  }

  /* ---------- 当前模型 ---------- */
  if (str_ieq(section, "models")) {
    char id[80];
    snprintf(id, sizeof(id), "%s", j_s(args, "id", ""));
    if (!id[0]) {
      buf_t m;
      buf_init(&m);
      buf_puts(&m, "切换模型需要 id(先用 settings_get section=models 看有哪些)。");
      return settings_fail(out, &m);
    }
    provider_t *p = provider_find(id);
    if (!p) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "没有 id 为 %s 的模型通道。", id);
      return settings_fail(out, &m);
    }
    if (!provider_ready(p)) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "模型通道 %s 还没配好(缺地址/密钥,或已被停用),不能切过去。", p->name);
      return settings_fail(out, &m);
    }
    /* 和界面"切换"走同一条路:整份读出来、改 active、校验后落盘 */
    char *dump = providers_json(0);
    json_t *root = dump ? json_parse(dump) : NULL;
    free(dump);
    if (!root) root = j_obj();
    j_set_str(root, "active", id);
    char err[512] = {0};
    int rc = providers_apply(root, err, sizeof(err));
    json_free(root);
    if (rc != 0) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "切换失败:%s", err[0] ? err : "配置没有通过校验");
      return settings_fail(out, &m);
    }
    /* 换了通道要把上一家的失败冷却清掉,否则界面还显示"离线" */
    llm_reset_error();
    settings_audit(ctx, "切换模型通道(智能体)", p->name, id);

    json_t *d = j_obj();
    j_set_bool(d, "ok", 1);
    j_set_str(d, "active", id);
    j_set_str(d, "name", p->name);
    out->data = d;
    buf_t t;
    buf_init(&t);
    buf_printf(&t, "已切换到「%s」(%s)。下一轮决策就用它。", p->name, provider_kind_name(p->kind));
    out->text = buf_take(&t);
    out->say = xstrdup("模型通道已经切过去了。");
    return 0;
  }

  /* ---------- 审批策略:只允许收紧 ---------- */
  if (str_ieq(section, "approval")) {
    char id[32];
    snprintf(id, sizeof(id), "%s", j_s(args, "id", ""));
    if (!id[0]) {
      buf_t m;
      buf_init(&m);
      buf_puts(&m, "切换审批策略需要 id(先用 settings_get section=approval 看有哪些)。");
      return settings_fail(out, &m);
    }
    json_t *list = approval_list_json();
    int found = 0;
    char name[80] = {0}, mode[24] = {0};
    for (int i = 0; i < j_len(list); i++) {
      json_t *p = j_at(list, i);
      if (!str_ieq(j_s(p, "id", ""), id)) continue;
      found = 1;
      snprintf(name, sizeof(name), "%s", j_s(p, "name", id));
      snprintf(mode, sizeof(mode), "%s", j_s(p, "mode", ""));
      break;
    }
    json_free(list);
    if (!found) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "没有 id 为 %s 的审批策略。", id);
      return settings_fail(out, &m);
    }
    if (str_ieq(mode, "allow_all")) {
      buf_t m;
      buf_init(&m);
      buf_puts(&m, "「全部允许」会让我不再逐条问你,这属于放宽限制,必须由人在界面上确认,"
                   "我不替你做这个决定。要收紧的话可以切到更严的策略。");
      return settings_fail(out, &m);
    }
    if (!approval_activate(id)) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "切换到审批策略 %s 失败。", id);
      return settings_fail(out, &m);
    }
    settings_audit(ctx, "切换审批策略(智能体)", name, id);

    json_t *d = j_obj();
    j_set_bool(d, "ok", 1);
    j_set_str(d, "active", id);
    j_set_str(d, "name", name);
    j_set_str(d, "mode", mode);
    out->data = d;
    buf_t t;
    buf_init(&t);
    buf_printf(&t, "审批策略已切成「%s」。之后每个动作都会按这条策略走。", name);
    out->text = buf_take(&t);
    out->say = xstrdup("审批策略已经切好了。");
    return 0;
  }

  /* ---------- 授权池:明确拒绝 ---------- */
  if (str_ieq(section, "pool")) {
    buf_t m;
    buf_init(&m);
    buf_puts(&m, "授权池不能由我改:往池里加一个站等于扩大检查范围,必须由人在界面上确认授权。"
                 "你可以在界面上加好之后告诉我,我再用 pool_list 读最新的清单。");
    return settings_fail(out, &m);
  }

  buf_t m;
  buf_init(&m);
  buf_printf(&m, "不认识的 section:%s。可用:rules / automation / models / approval。", section);
  return settings_fail(out, &m);
}
