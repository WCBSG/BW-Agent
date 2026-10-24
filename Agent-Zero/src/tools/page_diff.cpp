/* page_diff.cpp —— 内容基线比对(首次建基线,之后比差异)
 *
 * 这个文件只包含这一个工具的实现(以及只被它使用的辅助函数)。
 * 公共手法(取数、URL 归一、软 404 校准)在 tool_common.cpp;
 * 注册表与协议在 src\main\tools.cpp 与 src\main\tool_entry.cpp。
 */
#include "tool_api.h"

/* ---- 6. 内容基线比对(首次建基线,之后比差异) ---- */
int t_page_diff(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  char target_buf[1024];
  normalize_target(j_s(args, "target", ""), target_buf, sizeof(target_buf));
  const char *target = target_buf;
  store_t *st = (store_t *)ctx->store;
  fetch_t f;
  t_fetch(ctx, target, &f);
  if (f.err && !f.status) {
    json_t *d = j_obj();
    j_set_str(d, "target", target);
    j_set_str(d, "error", f.err ? f.err : "取不到内容");
    out->data = d;
    out->is_error = 1;    buf_t t;
    buf_init(&t);
    buf_printf(&t, "内容完整性检查没法做:%s 取不到内容(%s)。", target,
               f.err ? f.err : "无响应");
    out->text = buf_take(&t);
    out->say = xstrdup("目标取不到内容,我不给完整性结论。");
    fetch_free2(&f);
    return -1;
  }

  const char *body = f.body ? f.body : "";
  char hash[80];
  web_body_hash(body, hash, sizeof(hash));
  char title[160];
  web_title(body, title, sizeof(title));
  char own_host[256];
  web_url_parts(target, own_host, sizeof(own_host), NULL, 0);
  json_t *hosts = j_arr();
  json_t *suspicious = j_arr();
  link_analysis(body, own_host, hosts, suspicious);

  json_t *data = j_obj();
  j_set_str(data, "target", target);
  j_set_str(data, "content_hash", hash);
  j_set_str(data, "title", title);
  j_set_num(data, "bytes", (double)strlen(body));
  j_set(data, "external_hosts", hosts);
  j_set(data, "suspicious_links", suspicious);


  json_t *prev_list = st ? store_find(st, "baselines", "target", target) : NULL;
  json_t *prev_obj = NULL;
  if (prev_list) {
    /* 同一目标可能采过多次基线:取 captured_at 最新的那份 */
    for (int i = 0; i < j_len(prev_list); i++) {
      if (!prev_obj ||
          strcmp(j_s(j_at(prev_list, i), "captured_at", ""),
                 j_s(prev_obj, "captured_at", "")) > 0) {
        prev_obj = j_at(prev_list, i);
      }
    }
  }
  if (!prev_obj) {
    /* 第一次看这个页面:采基线(存快照引用,不存全文) */
    char *bid = st ? store_next_id(st, "baselines") : xstrdup("B-0000");
    char *ref = st ? store_write_snapshot(st, bid, body) : NULL;
    char ts[40];
    now_iso(ts, sizeof(ts));
    if (st) {
      json_t *b = j_obj();
      j_set_str(b, "id", bid);
      j_set_str(b, "target", target);
      j_set_str(b, "content_hash", hash);
      j_set_str(b, "content_ref", ref ? ref : "");
      j_set_str(b, "title", title);
      j_set_num(b, "bytes", (double)strlen(body));
      j_set_str(b, "captured_at", ts);
      j_set(b, "external_hosts", j_clone(hosts));
      store_save(st, "baselines", b);
      json_free(b);
    }
    j_set_str(data, "mode", "baseline_created");
    j_set_str(data, "baseline_id", bid);
    free(bid);
    free(ref);
    buf_t t;
    buf_init(&t);
    buf_printf(&t, "已为 %s 采集内容基线(指纹 %s,%d 字节,外域主机 %d 个)。"
                   "下次再比对同一地址,才能判断内容是否被改动。",
               target, hash, (int)strlen(body), j_len(hosts));
    out->text = buf_take(&t);
  } else {
    const char *prev_hash = j_s(prev_obj, "content_hash", "");
    json_t *prev_hosts = j_get(prev_obj, "external_hosts");
    json_t *new_hosts = j_arr();
    json_t *gone_hosts = j_arr();
    for (int i = 0; i < j_len(hosts); i++) {
      int found = 0;
      for (int k = 0; k < j_len(prev_hosts); k++) {
        if (str_ieq(j_at(hosts, i)->str, j_at(prev_hosts, k)->str)) { found = 1; break; }
      }
      if (!found) j_add(new_hosts, j_str(j_at(hosts, i)->str));
    }
    for (int k = 0; k < j_len(prev_hosts); k++) {
      int found = 0;
      for (int i = 0; i < j_len(hosts); i++) {
        if (str_ieq(j_at(hosts, i)->str, j_at(prev_hosts, k)->str)) { found = 1; break; }
      }
      if (!found) j_add(gone_hosts, j_str(j_at(prev_hosts, k)->str));
    }
    int changed = strcmp(prev_hash, hash) != 0;
    j_set_str(data, "mode", changed ? "changed" : "unchanged");
    j_set_str(data, "baseline_id", j_s(prev_obj, "id", ""));
    j_set_str(data, "prev_hash", prev_hash);
    j_set(data, "new_external_hosts", new_hosts);
    j_set(data, "removed_external_hosts", gone_hosts);

    if (changed && st) {
      char *did = store_next_id(st, "diffs");
      char ts[40];
      now_iso(ts, sizeof(ts));
      json_t *df = j_obj();
      j_set_str(df, "id", did);
      j_set_str(df, "baseline_id", j_s(prev_obj, "id", ""));
      j_set_str(df, "target", target);
      j_set_str(df, "detected_at", ts);
      j_set_bool(df, "changed", 1);
      j_set_str(df, "hash_before", prev_hash);
      j_set_str(df, "hash_after", hash);
      j_set_num(df, "bytes_before", j_n(prev_obj, "bytes", 0));
      j_set_num(df, "bytes_after", (double)strlen(body));
      j_set_str(df, "title_before", j_s(prev_obj, "title", ""));
      j_set_str(df, "title_after", title);
      j_set(df, "new_external_hosts", j_clone(new_hosts));
      j_set(df, "removed_external_hosts", j_clone(gone_hosts));
      store_save(st, "diffs", df);
      json_free(df);
      j_set_str(data, "diff_id", did);
      free(did);
    }

    buf_t t;
    buf_init(&t);
    if (!changed) {
      buf_printf(&t, "内容未变:%s 的指纹与基线一致(%s)。", target, hash);
    } else {
      buf_printf(&t, "内容已变化:%s 指纹 %s → %s;字节 %d → %d;标题「%s」→「%s」;"
                     "新增外域主机 %d 个,消失 %d 个。",
                 target, prev_hash, hash, (int)j_n(prev_obj, "bytes", 0), (int)strlen(body),
                 j_s(prev_obj, "title", ""), title, j_len(new_hosts), j_len(gone_hosts));
    }
    out->text = buf_take(&t);
  }

  out->data = data;
  buf_t s;
  buf_init(&s);
  if (strcmp(j_s(data, "mode", ""), "baseline_created") == 0) {
    buf_printf(&s, "已采集 %s 的内容基线(指纹 %s)。下次比对才能看出是否被改动。",
               target, hash);
  } else if (strcmp(j_s(data, "mode", ""), "unchanged") == 0) {
    buf_printf(&s, "内容完整性检查完成:%s 与基线一致,未发现改动迹象。", target);
  } else {
    buf_printf(&s, "内容完整性检查发现 %s 的内容与基线不一致(指纹已变)", target);
    if (j_len(j_get(data, "new_external_hosts")) > 0) {
      buf_printf(&s, ",并新增了 %d 个此前没有的外域主机。",
                 j_len(j_get(data, "new_external_hosts")));
    } else {
      buf_puts(&s, "。可能是正常改版,也可能是被改动,需要人工核对改动内容。");
    }
  }
  out->say = buf_take(&s);
  fetch_free2(&f);
  return 0;
}
