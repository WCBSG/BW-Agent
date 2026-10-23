/* api_profiles.cpp —— 本单位敏感信息定义的接口,从 serve.cpp 拆出来的第五块。
 *
 * 一套定义 = 哪些字段算敏感、按什么口径判。界面里存多套、选中一套生效;
 * 生效动作本身(apply_profile)留在 serve.cpp,因为导出与周期巡检也要调它。
 */
#include "serve_ctx.h"

#include "json.h"
#include "profile.h"
#include "regex.h"
/* ================= 本单位敏感信息定义 =================
 * 命题①要求"支持录入……本单位敏感信息定义(关键词、正则、文件类型或样例)"。
 * 这里把"定义"做成可编辑对象:一条定义 = 一组关键词 + 正则 + 文件类型 + 落点 + 样例。
 * 保存前逐条校验:正则必须能编译(否则扫描时会被静默跳过,使用者还以为站点干净),
 * 落点必须以 / 开头且不能带 ..(路径穿越在安全工具里尤其不能有)。
 */
static const char *profile_check_list(json_t *p, const char *key, int max_items, size_t max_len,
                                      char *err, size_t cap) {
  json_t *arr = j_get(p, key);
  if (!arr) return NULL;
  if (arr->type != J_ARR) { snprintf(err, cap, "%s 必须是数组", key); return err; }
  if (arr->count > max_items) { snprintf(err, cap, "%s 最多 %d 条", key, max_items); return err; }
  for (int i = 0; i < arr->count; i++) {
    json_t *v = arr->items[i];
    if (!v || v->type != J_STR) { snprintf(err, cap, "%s 的每一项都必须是字符串", key); return err; }
    if (v->str && strlen(v->str) > max_len) { snprintf(err, cap, "%s 第 %d 条太长(上限 %d 字节)", key, i + 1, (int)max_len); return err; }
  }
  return NULL;
}

static const char *profile_validate(json_t *p, char *err, size_t cap) {
  if (!p || p->type != J_OBJ) { snprintf(err, cap, "定义必须是一个 JSON 对象"); return err; }
  const char *name = j_s(p, "name", "");
  if (!name[0]) { snprintf(err, cap, "名称不能为空"); return err; }
  if (strlen(name) > 64) { snprintf(err, cap, "名称最多 64 字节"); return err; }

  const char *bad = profile_check_list(p, "keywords", 200, 200, err, cap);
  if (bad) return bad;
  bad = profile_check_list(p, "samples", 40, 300, err, cap);
  if (bad) return bad;
  bad = profile_check_list(p, "file_types", 40, 16, err, cap);
  if (bad) return bad;
  bad = profile_check_list(p, "regex", 40, 300, err, cap);
  if (bad) return bad;
  bad = profile_check_list(p, "paths", 80, 300, err, cap);
  if (bad) return bad;

  json_t *regex = j_get(p, "regex");
  for (int i = 0; regex && i < regex->count; i++) {
    const char *pat = regex->items[i]->str;
    if (!pat || !pat[0]) continue;
    char rerr[128] = {0};
    rx_pattern *re = rx_compile(pat, rerr, sizeof(rerr));
    if (!re) {
      snprintf(err, cap, "第 %d 条正则不合法:%s", i + 1, rerr[0] ? rerr : "无法编译");
      return err;
    }
    rx_free(re);
  }
  json_t *paths = j_get(p, "paths");
  for (int i = 0; paths && i < paths->count; i++) {
    const char *path = paths->items[i]->str;
    if (!path || !path[0]) continue;
    if (path[0] != '/') { snprintf(err, cap, "第 %d 个落点必须以 / 开头", i + 1); return err; }
    if (strstr(path, "..")) { snprintf(err, cap, "第 %d 个落点不允许出现 ..", i + 1); return err; }
  }
  json_t *types = j_get(p, "file_types");
  for (int i = 0; types && i < types->count; i++) {
    const char *t = types->items[i]->str;
    if (!t || !t[0]) continue;
    for (const char *q = t; *q; q++) {
      if (*q == '.') continue;               /* 允许写 .env,点会被忽略 */
      if (!isalnum((unsigned char)*q)) {
        snprintf(err, cap, "第 %d 个文件类型只能写字母、数字与点", i + 1);
        return err;
      }
    }
  }
  return NULL;
}

void api_profiles(const http_req_t *req, http_res_t *res) {
  if (strcmp(req->method, "POST") != 0) {
    json_t *all = store_all(serve_store(), "profiles");
    json_t *root = j_obj();
    j_set_bool(root, "ok", 1);
    j_set(root, "items", all);
    char *text = json_dump(root);
    http_res_json(res, 200, text);
    free(text);
    json_free(root);
    return;
  }

  json_t *body = req->body ? json_parse(req->body) : NULL;
  if (!body) { http_res_json(res, 400, "{\"ok\":false,\"error\":\"请求体不是合法 JSON\"}"); return; }
  const char *action = j_s(body, "action", "save");
  const char *id = j_s(body, "id", "");
  json_t *tpl = j_get(body, "profile");
  if (!id[0] && tpl) id = j_s(tpl, "id", "");

  if (str_ieq(action, "delete")) {
    int rc = id[0] ? store_delete(serve_store(), "profiles", id) : -1;
    json_free(body);
    if (rc != 0) { http_res_json(res, 404, "{\"ok\":false,\"error\":\"没有这套定义\"}"); return; }
    http_res_json(res, 200, "{\"ok\":true}");
    return;
  }

  /* 合并式保存:只传改了的那几个字段也不会把其它字段抹掉 */
  json_t *merged = j_obj();
  if (id[0]) {
    json_t *old = store_get(serve_store(), "profiles", id);
    if (old) {
      merged = old;
      if (!j_s(merged, "id", "")[0]) j_set_str(merged, "id", id);
    } else {
      j_set_str(merged, "id", id);
    }
  }
  if (tpl && tpl->type == J_OBJ) {
    for (int i = 0; i < j_len(tpl); i++) {
      if (!tpl->keys || !tpl->keys[i]) continue;
      j_set(merged, tpl->keys[i], json_parse(json_dump(tpl->items[i])));
    }
  }

  char err[256] = {0};
  const char *bad = profile_validate(merged, err, sizeof(err));
  if (bad) {
    json_free(merged);
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
  if (!j_s(merged, "id", "")[0]) {
    char *nid = store_next_id(serve_store(), "profiles");
    j_set_str(merged, "id", nid);
    free(nid);
  }
  char ts[40];
  now_iso(ts, sizeof(ts));
  if (!j_s(merged, "created_at", "")[0]) j_set_str(merged, "created_at", ts);
  j_set_str(merged, "updated_at", ts);
  store_save(serve_store(), "profiles", merged);
  store_audit(serve_store(), "保存敏感信息定义", j_s(merged, "name", ""), 1, j_s(merged, "id", ""), serve_task_id(), "");

  json_t *root = j_obj();
  j_set_bool(root, "ok", 1);
  j_set(root, "item", json_parse(json_dump(merged)));
  char *text = json_dump(root);
  json_free(merged);
  json_free(body);
  http_res_json(res, 200, text);
  free(text);
  json_free(root);
}

