/* sensitive_file_probe.cpp —— 敏感文件探测(内容特征判定 + 软 404 校准)
 *
 * 这个文件只包含这一个工具的实现(以及只被它使用的辅助函数)。
 * 公共手法(取数、URL 归一、软 404 校准)在 tool_common.cpp;
 * 注册表与协议在 src\main\tools.cpp 与 src\main\tool_entry.cpp。
 */
#include "tool_api.h"

/* ---- 4. 敏感文件探测(内容特征判定 + 软 404 校准) ---- */
int t_sensitive_file_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  char root[512];
  probe_root(j_s(args, "target", ""), root, sizeof(root));

  json_t *paths = j_arr();
  json_t *given = j_get(args, "paths");
  if (given && given->type == J_ARR && given->count > 0) {
    for (int i = 0; i < given->count && i < 40; i++) {
      if (j_at(given, i)->type == J_STR) j_add(paths, j_str(j_at(given, i)->str));
    }
  } else {
    int n = 0;
    const char **list = rules_str_list("sensitive_paths", &n);
    int cap = (int)rules_number("max_paths", 40);
    if (cap < 1) cap = 40;
    for (int i = 0; i < n && i < cap; i++) j_add(paths, j_str(list[i]));
    /* 本单位自定义落点追加在后面:规则给的是通用清单,单位自己更清楚哪些文件不该放出来 */
    const char *extra[80];
    int ne = profile_active_paths(extra, 80);
    for (int i = 0; i < ne && j_len(paths) < cap + 20; i++) j_add(paths, j_str(extra[i]));
  }

  calib_t calib;
  calib_run(ctx, root, &calib);

  json_t *hits = j_arr();
  json_t *pending = j_arr();        /* 有内容但没匹配到已知特征:如实列成"待确认" */
  int tested = 0, unreachable = 0, suppressed = 0, blocked = 0, out_of_scope = 0;

  for (int i = 0; i < j_len(paths); i++) {
    const char *path = j_at(paths, i)->str;
    char url[1024];
    join_path(url, sizeof(url), root, path);
    /* 先看这道门开不开:被 ! 规则排除的落点不该发请求,
       也不该让一条候选把整轮巡检判成越权 */
    if (!scope_ok(ctx, url)) { out_of_scope++; continue; }
    fetch_t f;
    t_fetch(ctx, url, &f);
    tested++;
    if (f.err && !f.status) {
      unreachable++;
      fetch_free2(&f);
      continue;
    }
    if (f.status == 401 || f.status == 403) { blocked++; fetch_free2(&f); continue; }
    if (f.status != 200 && f.status != 206) { fetch_free2(&f); continue; }
    if (calib_matches(&calib, f.status, f.body)) {
      /* 与站点默认页一致 ⇒ 这个路径其实不存在,只是站点用 200 包了错误页 */
      suppressed++;
      fetch_free2(&f);
      continue;
    }
    rules_sig_t sig;
    memset(&sig, 0, sizeof(sig));
    json_t *hit = j_obj();
    j_set_str(hit, "path", path);
    j_set_str(hit, "url", url);
    j_set_num(hit, "status", f.status);
    j_set_num(hit, "bytes", f.body ? (double)strlen(f.body) : 0);
    char title[160];
    web_title(f.body ? f.body : "", title, sizeof(title));
    j_set_str(hit, "title", title);
    if (rules_sig_match(path, f.body ? f.body : "", &sig) == 0) {
      j_set_str(hit, "signature", sig.name);
      j_set_str(hit, "kind", sig.kind);
      j_set_str(hit, "severity", sig.severity);
      j_set_str(hit, "tag", sig.tag);
      j_set_str(hit, "evidence", sig.evidence);
      j_add(hits, hit);
    } else {
      /* 特征表没认出来,再看是不是命中本单位定义 ——
         这往往才是这家单位真正在意的东西(内部代号、样例片段、自己的正则)。 */
      char pkind[64] = {0}, psev[16] = {0}, pmasked[160] = {0};
      int unit_hit = profile_scan_text(f.body ? f.body : "", pkind, sizeof(pkind),
                                       psev, sizeof(psev), pmasked, sizeof(pmasked));
      int type_hit = profile_type_hit(path);
      if (unit_hit || type_hit) {
        j_set_str(hit, "signature", unit_hit ? "本单位敏感信息定义" : "本单位定义的文件类型");
        j_set_str(hit, "kind", "敏感信息");
        j_set_str(hit, "severity", unit_hit && psev[0] ? psev : "高");
        j_set_str(hit, "tag", "unit-profile");
        buf_t ev;
        buf_init(&ev);
        if (unit_hit) buf_printf(&ev, "正文命中本单位定义(%s),命中片段:%s", pkind, pmasked);
        else buf_printf(&ev, "该文件后缀属于本单位定义的文件类型(%s)", path);
        j_set_str(hit, "evidence", ev.data);
        buf_free(&ev);
        j_add(hits, hit);
      } else {
        j_set_str(hit, "note", "内容与站点默认页不同,但没匹配到已知特征");
        j_add(pending, hit);
      }
    }
    fetch_free2(&f);
  }

  json_t *data = j_obj();
  j_set_str(data, "target", root);
  j_set_num(data, "tested", tested);
  j_set_num(data, "unreachable", unreachable);
  j_set_num(data, "out_of_scope", out_of_scope);
  j_set_num(data, "suppressed_as_default_page", suppressed);
  j_set_num(data, "blocked_401_403", blocked);
  j_set_bool(data, "calibrated", calib.valid);
  j_set_str(data, "calibration_sample", calib.sample);
  j_set(data, "hits", hits);
  j_set(data, "pending", pending);
  j_set_num(data, "hit_count", j_len(hits));
  put_rules_note(data);
  out->data = data;

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "落点探测 %s:试了 %d 个路径,命中 %d 个已知特征,"
                 "因与站点默认页一致而排除 %d 个(疑似不存在),%d 个受限,%d 个连不上。",
             root, tested, j_len(hits), suppressed, blocked, unreachable);
  if (out_of_scope)
    buf_printf(&t, "\n另有 %d 个候选落点被授权池排除,未发起请求。", out_of_scope);
  for (int i = 0; i < j_len(hits); i++) {
    buf_printf(&t, "\n- [%s] %s → %s(证据:%s)", j_s(j_at(hits, i), "severity", ""),
               j_s(j_at(hits, i), "path", ""), j_s(j_at(hits, i), "signature", ""),
               j_s(j_at(hits, i), "evidence", ""));
  }
  out->text = buf_take(&t);

  buf_t s;
  buf_init(&s);
  if (tested == 0 && out_of_scope > 0) {
    buf_printf(&s, "%s 的 %d 个候选落点全部被授权池排除,一个包都没发出去。"
                   "要查这些路径,先检查池子里的 ! 规则。",
               root, out_of_scope);
    out->is_error = 1;
  } else if (tested > 0 && unreachable == tested) {
    buf_printf(&s, "这次没法给结论:%s 的 %d 个落点全部请求失败。"
                   "我没把「连不上」当成「没问题」,请确认站点可达后我再来一次。",
               root, tested);
    out->is_error = 1;
  } else if (j_len(hits) == 0 && j_len(pending) == 0) {
    buf_printf(&s, "按当前定义试了 %d 个常见落点,没有取到敏感内容", tested);
    if (suppressed) buf_printf(&s, "(其中 %d 个返回的是站点默认页,已排除)", suppressed);
    if (blocked) buf_printf(&s, "(%d 个返回 401/403,存在但取不到)", blocked);
    buf_puts(&s, "。未命中不代表绝对没有其他路径。");
  } else {
    buf_printf(&s, "落点探测完成:命中 %d 处,另有 %d 处内容异常但没匹配到已知特征(需人工确认)。",
               j_len(hits), j_len(pending));
    for (int i = 0; i < j_len(hits) && i < 6; i++) {
      buf_printf(&s, "\n  · %s → %s", j_s(j_at(hits, i), "path", ""),
                 j_s(j_at(hits, i), "signature", ""));
    }
  }
  out->say = buf_take(&s);
  calib_free(&calib);
  return 0;
}
