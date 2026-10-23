/* api_automation.cpp —— 周期巡检接口,从 serve.cpp 拆出来的第四块。
 *
 * 数据全部来自 automations 集合;这里只做四件事:
 * 列出来、存一份、删一份、让它"马上跑一次"(把 next_at 拨到现在,交给调度线程)。
 * 「马上跑」不在这里同步执行 —— 否则这个 HTTP 连接要挂着等一整轮巡检。
 * 真正跑的那条线程还在 serve.cpp(它和 agent 生命周期绑在一起)。
 */
#include "serve_ctx.h"

#include "automation.h"
#include "json.h"
/* ================= 周期巡检 =================
 * 数据全部来自 automations 集合;这里只做四件事:
 * 列出来、存一份、删一份、让它"马上跑一次"(把 next_at 拨到现在,交给调度线程)。
 * 「马上跑」不在这里同步执行 —— 否则这个 HTTP 连接要挂着等一整轮巡检。
 */
void api_automation_list(const http_req_t *req, http_res_t *res) {
  (void)req;
  auto_rule_t *list = NULL;
  int n = 0;
  auto_list(serve_store(), &list, &n);
  json_t *arr = j_arr();
  for (int i = 0; i < n; i++) j_add(arr, auto_to_json(&list[i]));
  auto_free_list(list);

  json_t *root = j_obj();
  j_set_bool(root, "ok", 1);
  j_set_num(root, "serverNow", (double)time(NULL));
  j_set(root, "items", arr);
  char *text = json_dump(root);
  http_res_json(res, 200, text);
  free(text);
  json_free(root);
}

void api_automation_post(const http_req_t *req, http_res_t *res) {
  json_t *body = req->body ? json_parse(req->body) : NULL;
  if (!body) {
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"请求体不是合法 JSON\"}");
    return;
  }
  const char *action = j_s(body, "action", "save");
  json_t *body_rule = j_get(body, "rule");
  char id[24];
  snprintf(id, sizeof(id), "%s", j_s(body, "id", ""));
  if (!id[0]) snprintf(id, sizeof(id), "%s", j_s(body_rule, "id", ""));

  if (str_ieq(action, "delete")) {
    int rc = auto_remove(serve_store(), id);
    json_free(body);
    if (rc != 0) { http_res_json(res, 404, "{\"ok\":false,\"error\":\"没有这条周期规则\"}"); return; }
    store_audit(serve_store(), "删除周期巡检", id, 1, "界面操作", serve_task_id(), "");
    http_res_json(res, 200, "{\"ok\":true}");
    return;
  }

  if (str_ieq(action, "run")) {
    auto_rule_t r;
    if (auto_find(serve_store(), id, &r) != 0) {
      json_free(body);
      http_res_json(res, 404, "{\"ok\":false,\"error\":\"没有这条周期规则\"}");
      return;
    }
    r.next_at = (long long)time(NULL);      /* 拨到现在:调度线程下一拍就捡走 */
    auto_save(serve_store(), &r);
    json_free(body);
    store_audit(serve_store(), "立即执行周期巡检", r.domain, 1, "界面点「马上跑一次」", serve_task_id(), "");
    http_res_json(res, 200, "{\"ok\":true,\"queued\":true,\"note\":\"已排进调度队列,几秒内开始;界面会自动刷新\"}");
    return;
  }

  /* save / toggle 都走这里。带 id 时先取出既有规则再做"只覆盖填了的字段" ——
     否则前端只传一个 every_min 就会把 domain 覆盖成空,报"目标不能为空"。 */
  auto_rule_t r;
  json_t *rule = j_get(body, "rule");
  if (!rule) rule = body;
  json_t *merged = NULL;
  if (id[0] && auto_find(serve_store(), id, &r) == 0) {
    merged = auto_to_json(&r);
    for (int i = 0; i < j_len(rule); i++) {
      if (!rule->keys || !rule->keys[i]) continue;
      j_set(merged, rule->keys[i], json_parse(json_dump(rule->items[i])));
    }
    auto_from_json(merged, &r);
    json_free(merged);
  } else {
    auto_from_json(rule, &r);
  }
  if (str_ieq(action, "toggle")) r.enabled = r.enabled ? 0 : 1;

  const char *bad = auto_validate(&r);
  if (bad) {
    json_free(body);
    buf_t b;
    buf_init(&b);
    buf_puts(&b, "{\"ok\":false,\"error\":");
    buf_json_str(&b, bad);
    buf_puts(&b, "}");
    http_res_json(res, 400, b.data);
    buf_free(&b);
    return;
  }

  /* 周期改了就得重算下次时间,否则还按旧的走 */
  r.next_at = auto_next_at(&r, (long long)time(NULL));
  auto_save(serve_store(), &r);
  store_audit(serve_store(), "设置周期巡检", r.domain, 1, r.id, serve_task_id(), "");

  json_t *out = auto_to_json(&r);
  json_t *root = j_obj();
  j_set_bool(root, "ok", 1);
  j_set(root, "item", out);
  char *text = json_dump(root);
  json_free(body);
  http_res_json(res, 200, text);
  free(text);
  json_free(root);
}

