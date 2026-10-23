/* site_crawl.cpp —— 资产与页面发现
 *
 * 这个文件只包含这一个工具的实现(以及只被它使用的辅助函数)。
 * 公共手法(取数、URL 归一、软 404 校准)在 tool_common.cpp;
 * 注册表与协议在 src\main\tools.cpp 与 src\main\tool_entry.cpp。
 */
#include "tool_api.h"

int t_site_crawl(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  char target[1024] = {0};
  normalize_target(j_s(args, "target", ""), target, sizeof(target));
  /* 目标里给了子路径(如 http://host/l1)时:
     ① 补成目录形式 /l1/ —— 否则相对链接会按"上层的文件"解析,全跟丢;
     ② 记下这个子路径作为本次巡检范围,不往范围外爬(越界请求会被取数通道拒掉,
        但爬虫本来就不该主动去踩)。 */
  char scope[1024] = "/";
  {
    char pq[2048];
    url_path_query(target, pq, sizeof(pq));
    char *q = strpbrk(pq, "?#");
    if (q) *q = 0;
    if (pq[0] && strcmp(pq, "/") != 0) {
      size_t n = strlen(target);
      if (target[n - 1] != '/') {
        const char *last = strrchr(pq, '/');
        const char *segname = last ? last + 1 : pq;
        if (!strchr(segname, '.')) snprintf(target + n, sizeof(target) - n, "/");
      }
      char p2[2048];
      url_path_query(target, p2, sizeof(p2));
      q = strpbrk(p2, "?#");
      if (q) *q = 0;
      snprintf(scope, sizeof(scope), "%s", p2);
    }
  }
  int max_depth = (int)j_n(args, "max_depth", 1);
  int max_pages = (int)j_n(args, "max_pages", 12);
  if (max_depth < 0) max_depth = 0;
  if (max_depth > 3) max_depth = 3;
  if (max_pages < 1) max_pages = 1;
  if (max_pages > 60) max_pages = 60;

  /* 队列:BFS,记录深度与父页面(这样"发现树"是可解释的) */
  typedef struct { char *url; int depth; char *parent; } item_t;
  item_t *queue = (item_t *)xcalloc((size_t)max_pages * 4 + 8, sizeof(item_t));
  int qhead = 0, qtail = 0, qcap = max_pages * 4 + 8;
  char **seen = (char **)xcalloc((size_t)max_pages * 4 + 8, sizeof(char *));
  int seen_n = 0;

  queue[qtail].url = xstrdup(target);
  queue[qtail].depth = 0;
  queue[qtail].parent = NULL;
  qtail++;

  json_t *assets = j_arr();
  int fetched = 0, skipped = 0;
  while (qhead < qtail && fetched < max_pages) {
    item_t cur = queue[qhead++];
    /* 去过重的跳过 */
    int dup = 0;
    for (int i = 0; i < seen_n; i++) if (strcmp(seen[i], cur.url) == 0) { dup = 1; break; }
    if (dup) { free(cur.url); free(cur.parent); continue; }
    seen[seen_n++] = xstrdup(cur.url);

    int status = 0;
    char *body = NULL;
    char *err = NULL;
    do_fetch(ctx, cur.url, "GET", &status, &body, &err);
    fetched++;

    const char *kind = classify_kind(cur.url);
    json_t *a = j_obj();
    j_set_str(a, "url", cur.url);
    j_set_str(a, "kind", kind);
    j_set_num(a, "status_code", status);
    j_set_num(a, "depth", cur.depth);
    if (cur.parent) j_set_str(a, "parent_url", cur.parent);
    else j_set_null(a, "parent_url");
    if (err) j_set_str(a, "error", err);
    j_add(assets, a);

    if (body && cur.depth < max_depth && looks_like_html(NULL)) {
      json_t *links = j_arr();
      extract_links(body, links);
      char host[256];
      net_host_of(cur.url, host, sizeof(host));
      for (int i = 0; i < j_len(links); i++) {
        const char *link = j_at(links, i)->str;
        char abs[2048];
        /* 相对链接按"当前页面所在目录"补全:写死 https://主机 会把 http 站点、
           非 80 端口的站点全部跟丢,不展开相对路径又会只剩首页一个资产。 */
        url_resolve(cur.url, link, abs, sizeof(abs));
        if (!abs[0]) continue;
        char lh[256];
        net_host_of(abs, lh, sizeof(lh));
        if (!str_ieq(lh, host)) continue;       /* 只跟同域 */
        char lpq[2048];
        url_path_query(abs, lpq, sizeof(lpq));
        if (!path_in_scope(lpq, scope)) continue;   /* 不往巡检范围外爬 */
        /* 授权池里的 ! 条目也是边界:主动跳过,不去踩那道闸门 */
        if (!scope_ok(ctx, abs)) { skipped++; continue; }
        if (qtail < qcap) {
          queue[qtail].url = xstrdup(abs);
          queue[qtail].depth = cur.depth + 1;
          queue[qtail].parent = xstrdup(cur.url);
          qtail++;
        }
      }
      json_free(links);
    }
    free(body);
    free(err);
    free(cur.url);
    free(cur.parent);
  }
  for (int i = qhead; i < qtail; i++) { free(queue[i].url); free(queue[i].parent); }
  free(queue);
  for (int i = 0; i < seen_n; i++) free(seen[i]);
  free(seen);

  int pages = 0, res = 0, failed = 0;
  for (int i = 0; i < j_len(assets); i++) {
    const char *k = j_s(j_at(assets, i), "kind", "");
    if (strcmp(k, "静态资源") == 0 || strcmp(k, "接口") == 0) res++;
    else pages++;
    if (j_get(j_at(assets, i), "error")) failed++;
  }
  /* 连起点都取不到内容 ⇒ 这次资产发现没有结论,不能报成"0 个资产 = 没问题" */
  int seed_ok = j_len(assets) > 0 && !j_get(j_at(assets, 0), "error");
  json_t *data = j_obj();
  j_set_str(data, "target", target);
  j_set(data, "assets", assets);
  j_set_num(data, "pages", pages);
  j_set_num(data, "resources", res);
  j_set_num(data, "requests", fetched);
  j_set_num(data, "unreachable", failed);
  j_set_num(data, "skipped_out_of_pool", skipped);
  out->data = data;

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "起始:%s\n实际访问 %d 个地址,共记录 %d 个资产(页面 %d、资源/接口 %d)\n",
             target, fetched, j_len(assets), pages, res);
  if (skipped) buf_printf(&t, "另有 %d 个站内链接被授权池的排除规则拦下,未发起请求\n", skipped);
  for (int i = 0; i < j_len(assets) && i < 30; i++) {
    json_t *a = j_at(assets, i);
    buf_printf(&t, "- [%s] %s (HTTP %d, 深度 %d)\n", j_s(a, "kind", ""),
               j_s(a, "url", ""), (int)j_n(a, "status_code", 0), (int)j_n(a, "depth", 0));
  }
  out->text = buf_take(&t);

  buf_t s;
  buf_init(&s);
  if (!seed_ok) {
    out->is_error = 1;
    buf_printf(&s, "资产发现没能得出结论:%s 取不到内容(%s)。"
                   "连起点都打不开,底账就无从谈起 —— 我不会把「查不到」写成「没有资产」。",
               target, j_s(j_at(assets, 0), "error", "无响应"));
  } else {
    buf_printf(&s, "资产发现完成:访问 %d 个地址,记录 %d 个资产(页面 %d、资源与接口 %d)。",
               fetched, j_len(assets), pages, res);
    if (failed) buf_printf(&s, "其中 %d 个地址取不到内容。", failed);
    if (skipped) buf_printf(&s, "另有 %d 个站内链接被授权池排除,已跳过。", skipped);
  }
  out->say = buf_take(&s);
  return seed_ok ? 0 : -1;
}
