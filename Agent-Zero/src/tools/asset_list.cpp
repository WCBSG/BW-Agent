/* asset_list.cpp —— 把资产底账摊给模型看
 *
 * 站点爬完后,"有哪些页面"只有数据库知道;模型拿不到清单就没法决定
 * 下一步看哪个页面。这个工具只读底账,不发请求。
 */
#include "tool_api.h"

int t_asset_list(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  int limit = (int)j_n(args, "limit", 40);
  if (limit <= 0 || limit > 200) limit = 40;
  const char *want = j_s(args, "kind", "");

  json_t *all = (ctx && ctx->store) ? store_all((store_t *)ctx->store, "assets") : j_arr();
  json_t *items = j_arr();
  for (int i = 0; i < j_len(all); i++) {
    json_t *a = j_at(all, i);
    const char *url = j_s(a, "url", "");
    if (!url[0]) continue;
    const char *kind = j_s(a, "kind", "");
    if (want[0] && !str_ieq(want, kind)) continue;
    json_t *o = j_obj();
    j_set_str(o, "url", url);
    j_set_str(o, "kind", kind);
    j_set_num(o, "status", j_n(a, "status_code", 0));
    j_set_num(o, "depth", j_n(a, "depth", 0));
    const char *parent = j_s(a, "parent_url", "");
    if (parent[0]) j_set_str(o, "from", parent);
    j_add(items, o);
  }
  int total = j_len(items);
  int shown = total < limit ? total : limit;

  json_t *data = j_obj();
  j_set_num(data, "total", total);
  j_set(items, "items", items);
  out->data = data;

  buf_t t;
  buf_init(&t);
  if (!total) {
    buf_puts(&t, "资产底账还是空的:先用 site_crawl 摸一遍站点,再来挑页面。");
  } else {
    buf_printf(&t, "资产底账共 %d 条", total);
    if (want[0]) buf_printf(&t, "(只列 %s)", want);
    buf_puts(&t, ",按发现顺序列出前 ");
    buf_printf(&t, "%d 条:\n", shown);
    for (int i = 0; i < shown; i++) {
      json_t *o = j_at(items, i);
      buf_printf(&t, "  - %s", j_s(o, "url", ""));
      int st = (int)j_n(o, "status", 0);
      if (st) buf_printf(&t, " [%d]", st);
      const char *kind = j_s(o, "kind", "");
      if (kind[0]) buf_printf(&t, " %s", kind);
      const char *from = j_s(o, "from", "");
      if (from[0]) buf_printf(&t, " ← %s", from);
      buf_puts(&t, "\n");
    }
    if (total > shown) buf_puts(&t, "  …(还有更多,用 limit 取) \n");
    buf_puts(&t, "挑值得深看的页面用 http_get 读它的状态、响应头和正文片段。");
  }
  out->text = buf_take(&t);
  out->say = xstrdup(total ? "我先看看已经摸到哪些页面。" : "还没有资产底账,得先爬一遍。");
  json_free(all);
  return 0;
}
