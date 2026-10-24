/* pool_list.cpp —— 授权列表:把授权池原样读给模型看
 *
 * 这个文件只包含这一个工具的实现(以及只被它使用的辅助函数)。
 * 公共手法(取数、URL 归一、软 404 校准)在 tool_common.cpp;
 * 注册表与协议在 src\main\tools.cpp 与 src\main\tool_entry.cpp。
 */
#include "tool_api.h"

/* ---- 0. 授权列表(只读,一个请求都不发) ----
   用户说"把授权列表里的站都巡检一遍"时,模型得先知道列表里有什么。
   提示词里已经摊了一份授权池,但那是每轮开始时拍的快照;
   这个工具让它随时能重新问一遍,也让"授权列表"这件事在界面上有据可查。 */
int t_pool_list(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  (void)args;
  char **pool = NULL;
  int n = net_pool_snapshot(&pool);

  json_t *allow = j_arr();
  json_t *deny = j_arr();
  for (int i = 0; i < n; i++) {
    const char *e = pool[i];
    if (!e || !e[0]) continue;
    if (e[0] == '!') j_add(deny, j_str(e + 1));   /* 分类已在数组里,展示时去掉 ! */
    else j_add(allow, j_str(e));
  }
  json_t *data = j_obj();
  j_set(data, "allowed", allow);
  j_set(data, "denied", deny);
  j_set_num(data, "allowed_count", j_len(allow));
  j_set_num(data, "denied_count", j_len(deny));
  if (ctx && ctx->domain_count > 0) j_set_str(data, "focus", ctx->domains[0]);
  out->data = data;

  buf_t t;
  buf_init(&t);
  if (j_len(allow) == 0) {
    if (n == 0) {
      buf_puts(&t, "授权池是空的:任何对外请求都不会发出去。"
                   "先在界面上把要检查的主机加进授权池,再发起巡检。");
    } else {
      buf_puts(&t, "授权池里没有允许的目标(全是 ! 开头的不允许条目):不会对外发任何请求。");
    }
  } else {
    buf_printf(&t, "授权池共 %d 个允许目标", j_len(allow));
    if (ctx && ctx->domain_count > 0) buf_printf(&t, ",本轮焦点是 %s", ctx->domains[0]);
    buf_puts(&t, ":\n");
    for (int i = 0; i < j_len(allow) && i < 100; i++) {
      json_t *v = j_at(allow, i);
      if (v && v->type == J_STR && v->str) buf_printf(&t, "  - %s\n", v->str);
    }
    if (j_len(deny) > 0) {
      buf_puts(&t, "明确不允许(不要访问):\n");
      for (int i = 0; i < j_len(deny) && i < 100; i++) {
        json_t *v = j_at(deny, i);
        if (v && v->type == J_STR && v->str) buf_printf(&t, "  - %s\n", v->str);
      }
    }
    buf_puts(&t, "要巡检多个站点时逐个来:一次只对一个目标调用技能或工具,一个跑完再换下一个。");
  }
  out->text = buf_take(&t);
  out->say = xstrdup(j_len(allow) > 0 ? "我先看一下授权池里有哪些站点。"
                                      : "授权池是空的,一个请求都发不出去。");
  str_free_list(pool, n);
  return 0;
}
