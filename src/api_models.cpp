/* api_models.cpp —— 模型配置接口(从 serve.cpp 拆出来的第二块)。
 *
 * /api/models
 *   GET  列表(密钥只回显后四位)
 *   POST action=save      整份写回(密钥空着或仍是掩码 = 不改)
 *        action=activate  只切换当前使用的那一条
 *        action=test      真发一句话,验证地址和 key 到底通不通
 *        action=delete    删掉一条
 *
 * "测试"单独做一个动作的原因:保存只需要格式合法,通不通只有真发一次才知道;
 * 让用户点一下就能看到"钥匙错了"还是"地址错了",比等到对话时才失败强。
 *
 * 这一块不碰 agent / store / 界面,只和 llm_provider 打交道 ——
 * 所以它是最早被拆出来的,拆的时候一行逻辑都没动。
 */
#include "serve_ctx.h"

#include "json.h"
#include "llm_provider.h"

/* 把内存里的配置拍成 JSON(带密钥明文,只在本机内存里流转) */
static json_t *models_snapshot(void) {
  char *dump = providers_json(0);
  json_t *root = dump ? json_parse(dump) : NULL;
  free(dump);
  return root;
}

/* 统一回包:动作结果 + 最新的整份配置,界面据此一次刷新到位 */
static void models_ok(http_res_t *res, int code, const char *msg) {
  json_t *o = j_obj();
  j_set_bool(o, "ok", code == 200);
  if (msg && *msg) j_set_str(o, code == 200 ? "note" : "error", msg);
  char *dump = providers_json(1);
  if (dump) {
    json_t *cur = json_parse(dump);
    if (cur) j_set(o, "models", cur);
    free(dump);
  }
  char *out = json_dump(o);
  http_res_json(res, code, out);
  free(out);
  json_free(o);
}

void api_models(const http_req_t *req, http_res_t *res) {
  if (strcmp(req->method, "GET") == 0) {
    char *dump = providers_json(1);
    http_res_json(res, 200, dump);
    free(dump);
    return;
  }
  json_t *body = req->body ? json_parse(req->body) : NULL;
  if (!body) {
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"请求体不是合法 JSON\"}");
    return;
  }
  char action[32];
  snprintf(action, sizeof(action), "%s", j_s(body, "action", "save"));
  char id[80];
  snprintf(id, sizeof(id), "%s", j_s(body, "id", ""));
  char err[512] = {0};
  int rc = -1;

  if (str_ieq(action, "test")) {
    if (!id[0]) {
      json_free(body);
      http_res_json(res, 400, "{\"ok\":false,\"error\":\"没指定测哪一条\"}");
      return;
    }
    char detail[1024] = {0};
    long long t0 = now_ms();
    int trc = providers_test(id, detail, sizeof(detail));
    long long ms = now_ms() - t0;
    json_t *o = j_obj();
    j_set_bool(o, "ok", trc == 0);
    j_set_num(o, "ms", (double)ms);
    j_set_str(o, "detail", detail[0] ? detail : (trc == 0 ? "通了" : "没有响应"));
    /* 测试结果本身是"通/不通"两种正常结果,不是请求出错 —— 一律 200,
       界面照 ok 字段渲染。之前通不通用 HTTP 状态码表达,前端只能看到
       "HTTP 400",把"哪一步不通"这句最有用的话丢了。 */
    char *dump = json_dump(o);
    http_res_json(res, 200, dump);
    free(dump);
    json_free(o);
    json_free(body);
    return;
  } else if (str_ieq(action, "save")) {
    rc = providers_apply(body, err, sizeof(err));
  } else if (str_ieq(action, "activate") || str_ieq(action, "delete")) {
    json_t *root = models_snapshot();
    if (!root) root = j_obj();
    int is_delete = str_ieq(action, "delete");
    if (is_delete) {
      json_t *arr = j_get(root, "providers");
      json_t *kept = j_arr();
      int n = arr ? j_len(arr) : 0;
      for (int i = 0; i < n; i++) {
        json_t *it = j_at(arr, i);
        if (!it) continue;
        if (str_ieq(j_s(it, "id", ""), id)) continue;
        char *d = json_dump(it);
        json_t *cp = d ? json_parse(d) : NULL;
        free(d);
        if (cp) j_add(kept, cp);
      }
      j_set(root, "providers", kept);       /* j_set 接管所有权 */
    } else {
      j_set_str(root, "active", id);
    }
    rc = providers_apply(root, err, sizeof(err));
    json_free(root);
  } else {
    snprintf(err, sizeof(err), "不认识的动作:%s", action);
  }
  json_free(body);

  if (rc != 0) {
    char msg[640];
    snprintf(msg, sizeof(msg), "{\"ok\":false,\"error\":\"%s\"}",
             err[0] ? err : "配置没有通过校验");
    http_res_json(res, 400, msg);
    return;
  }
  /* 顶部那盏"在线/离线"灯是缓存出来的 —— 改完模型必须重算,
     否则界面得等到下一次巡检才肯承认"模型已经接上了"。 */
  serve_refresh_status();
  models_ok(res, 200, str_ieq(action, "save") ? "已保存" : "已生效");
}
