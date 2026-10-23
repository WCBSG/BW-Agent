/* dir_probe.cpp —— 目录探测(目录索引识别 + 入口识别 + 软 404 校准)
 *
 * 这个文件只包含这一个工具的实现(以及只被它使用的辅助函数)。
 * 公共手法(取数、URL 归一、软 404 校准)在 tool_common.cpp;
 * 注册表与协议在 src\main\tools.cpp 与 src\main\tool_entry.cpp。
 */
#include "tool_api.h"

/* ---- 5. 目录探测(目录索引识别 + 入口识别 + 软 404 校准) ---- */
int t_dir_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  char root[512];
  probe_root(j_s(args, "target", ""), root, sizeof(root));

  json_t *dirs = j_arr();
  json_t *given = j_get(args, "dirs");
  if (given && given->type == J_ARR && given->count > 0) {
    for (int i = 0; i < given->count && i < 40; i++) {
      if (j_at(given, i)->type == J_STR) j_add(dirs, j_str(j_at(given, i)->str));
    }
  } else {
    int n = 0;
    const char **list = rules_str_list("dir_candidates", &n);
    int cap = (int)rules_number("max_dirs", 40);
    if (cap < 1) cap = 40;
    for (int i = 0; i < n && i < cap; i++) j_add(dirs, j_str(list[i]));
  }

  calib_t calib;
  calib_run(ctx, root, &calib);

  json_t *listings = j_arr();     /* 目录索引 */
  json_t *entries = j_arr();      /* 疑似管理入口 */
  json_t *exposed = j_arr();      /* 命中内容特征的落点 */
  json_t *restricted = j_arr();   /* 存在但受限(401/403):是有价值的信息 */
  int tested = 0, unreachable = 0, suppressed = 0, reachable = 0;

  for (int i = 0; i < j_len(dirs); i++) {
    const char *dir = j_at(dirs, i)->str;
    char url[1024];
    join_path(url, sizeof(url), root, dir);
    fetch_t f;
    t_fetch(ctx, url, &f);
    tested++;
    if (f.err && !f.status) { unreachable++; fetch_free2(&f); continue; }
    if (f.status == 401 || f.status == 403) {
      json_t *r = j_obj();
      j_set_str(r, "path", dir);
      j_set_num(r, "status", f.status);
      j_add(restricted, r);
      reachable++;
      fetch_free2(&f);
      continue;
    }
    if (f.status < 200 || f.status >= 400) { fetch_free2(&f); continue; }
    if (calib_matches(&calib, f.status, f.body)) { suppressed++; fetch_free2(&f); continue; }
    reachable++;

    const char *body = f.body ? f.body : "";
    char title[160];
    web_title(body, title, sizeof(title));

    if (web_is_dir_listing(body)) {
      json_t *e = j_arr();
      web_dir_listing_entries(body, e, 12);
      json_t *l = j_obj();
      j_set_str(l, "path", dir);
      j_set_str(l, "url", url);
      j_set_str(l, "title", title);
      j_set(l, "entries", e);
      j_add(listings, l);
    } else if (web_has_password_form(body)) {
      json_t *m = j_obj();
      j_set_str(m, "path", dir);
      j_set_str(m, "url", url);
      j_set_str(m, "title", title);
      j_add(entries, m);
    } else {
      rules_sig_t sig;
      memset(&sig, 0, sizeof(sig));
      if (rules_sig_match(dir, body, &sig) == 0) {
        json_t *h = j_obj();
        j_set_str(h, "path", dir);
        j_set_str(h, "url", url);
        j_set_str(h, "signature", sig.name);
        j_set_str(h, "kind", sig.kind);
        j_set_str(h, "severity", sig.severity);
        j_set_str(h, "tag", sig.tag);
        j_set_str(h, "evidence", sig.evidence);
        j_add(exposed, h);
      }
    }
    fetch_free2(&f);
  }

  json_t *data = j_obj();
  j_set_str(data, "target", root);
  j_set_num(data, "tested", tested);
  j_set_num(data, "reachable", reachable);
  j_set_num(data, "suppressed_as_default_page", suppressed);
  j_set_num(data, "unreachable", unreachable);
  j_set_bool(data, "calibrated", calib.valid);
  j_set(data, "directory_listing", listings);
  j_set(data, "entry_points", entries);
  j_set(data, "exposed", exposed);
  j_set(data, "restricted", restricted);
  j_set_num(data, "candidate_count", j_len(listings) + j_len(exposed));
  put_rules_note(data);
  out->data = data;

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "目录探测 %s:试了 %d 个目录,可访问 %d 个,目录索引 %d 个,"
                 "疑似入口 %d 个,受限 %d 个,排除默认页 %d 个。",
             root, tested, reachable, j_len(listings), j_len(entries), j_len(restricted),
             suppressed);
  for (int i = 0; i < j_len(listings); i++) {
    buf_printf(&t, "\n- 目录索引:%s(%d 个条目)", j_s(j_at(listings, i), "path", ""),
               j_len(j_get(j_at(listings, i), "entries")));
  }
  for (int i = 0; i < j_len(entries); i++) {
    buf_printf(&t, "\n- 疑似入口:%s(%s)", j_s(j_at(entries, i), "path", ""),
               j_s(j_at(entries, i), "title", ""));
  }
  out->text = buf_take(&t);

  buf_t s;
  buf_init(&s);
  if (tested > 0 && unreachable == tested) {
    buf_printf(&s, "目录探测没能得出结论:%s 的 %d 个目录全部请求失败。", root, tested);
    out->is_error = 1;
  } else if (j_len(listings) == 0 && j_len(entries) == 0 && j_len(exposed) == 0) {
    buf_printf(&s, "目录探测完成:试了 %d 个常见目录,没有发现目录索引、暴露文件或可访问入口", tested);
    if (j_len(restricted) > 0) buf_printf(&s, "(%d 个目录存在但返回 401/403)", j_len(restricted));
    buf_puts(&s, "。");
  } else {
    buf_printf(&s, "目录探测发现 %d 处目录索引、%d 处疑似管理入口、%d 处暴露文件。",
               j_len(listings), j_len(entries), j_len(exposed));
    for (int i = 0; i < j_len(listings) && i < 4; i++) {
      buf_printf(&s, "\n  · 目录索引 %s", j_s(j_at(listings, i), "path", ""));
    }
    for (int i = 0; i < j_len(entries) && i < 4; i++) {
      buf_printf(&s, "\n  · 疑似入口 %s", j_s(j_at(entries, i), "path", ""));
    }
  }
  out->say = buf_take(&s);
  calib_free(&calib);
  return 0;
}
