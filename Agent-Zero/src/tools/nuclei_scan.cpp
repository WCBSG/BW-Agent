/* nuclei_scan.cpp —— 弱配置 + 漏洞模板(内置检查为底,本机装了 nuclei 就叠加它)
 *
 * 这个文件只包含这一个工具的实现(以及只被它使用的辅助函数)。
 * 公共手法(取数、URL 归一、软 404 校准)在 tool_common.cpp;
 * 注册表与协议在 src\main\tools.cpp 与 src\main\tool_entry.cpp。
 */
#include "tool_api.h"

/* ---- 7. 弱配置 + 漏洞模板(内置检查为底,本机装了 nuclei 就叠加它) ----
 *
 * "调用并编排合规的开源工具"这条如果只写在文档里是空的,所以这里真去调 nuclei:
 *   找 nuclei.exe(exe 同目录 → 数据目录 tools\ → 数据目录 bin\ → PATH)
 *   → 用它跑一轮收窄过的模板 → 把命中并进同一份检查清单 → 交给技能层统一成案。
 *
 * 参数是刻意收窄的,让"编排开源工具"与"非破坏性"同时成立:
 *   -c 1 -rl 2          单并发、2 请求/秒(与内置通道同一档限速)
 *   -tags exposure,misconfig,tech   只跑信息收集与弱配置类模板
 *   -etags intrusive,dos,fuzz,brute-force,headless  排除会改动/压垮目标的那几类
 *   -ni                 关掉 interactsh(不做带外回连,避免把第三方牵进来)
 *   -duc                不在巡检时联网更新模板(不额外往外发包)
 * 找不到 nuclei 或模板没装时,如实说明"这次只有内置检查",不假装跑过。
 */
int find_nuclei(char *out, size_t cap) {
  out[0] = 0;
  char p[MAX_PATH * 2];
  const char *dirs[3] = {app_dir(), NULL, NULL};
  char tools_dir[MAX_PATH * 2];
  char bin_dir[MAX_PATH * 2];
  path_join(tools_dir, sizeof(tools_dir), app_data_dir(), "tools");
  path_join(bin_dir, sizeof(bin_dir), app_data_dir(), "bin");
  dirs[1] = tools_dir;
  dirs[2] = bin_dir;
  for (int i = 0; i < 3; i++) {
    if (!dirs[i] || !dirs[i][0]) continue;
    if (path_join(p, sizeof(p), dirs[i], "nuclei.exe") != 0) continue;
    if (file_size(p) >= 0) {
      snprintf(out, cap, "%s", p);
      return 1;
    }
  }
  /* 最后看 PATH:直接问系统要,比自己拆 PATH 靠谱 */
  wchar_t found[MAX_PATH * 2];
  DWORD n = SearchPathW(NULL, L"nuclei.exe", NULL, MAX_PATH * 2, found, NULL);
  if (n > 0 && n < MAX_PATH * 2) {
    char *u = w_to_u8(found);
    if (u && u[0]) {
      snprintf(out, cap, "%s", u);
      free(u);
      return 1;
    }
    if (u) free(u);
  }
  return 0;
}

/* nuclei 的等级 → 我们用的中文等级(与发现分级同一套词,别出现两套) */
const char *nuclei_severity_cn(const char *in) {
  if (!in) return "低";
  if (str_ieq(in, "critical")) return "严重";
  if (str_ieq(in, "high")) return "高";
  if (str_ieq(in, "medium")) return "中";
  if (str_ieq(in, "low")) return "低";
  return "信息";
}

/* 跑 nuclei 并把命中并入 checks;返回命中条数。没装则返回 -1。 */
int nuclei_merge(const char *target, json_t *checks, int *timed_out) {
  if (timed_out) *timed_out = 0;
  char exe[MAX_PATH * 2];
  if (!find_nuclei(exe, sizeof(exe))) return -1;

  buf_t cmd;
  buf_init(&cmd);
  buf_printf(&cmd,
             "\"%s\" -u \"%s\" -jsonl -silent -nc -duc -ni -c 1 -rl 2 -timeout 8 -retries 1 "
             "-severity low,medium,high,critical -tags exposure,misconfig,tech "
             "-etags intrusive,dos,fuzz,brute-force,headless -stats=false",
             exe, target);

  char *out_text = NULL;
  int code = -1;
  int rc = ext_run_capture(cmd.data, NULL, 60000, &out_text, &code);
  buf_free(&cmd);
  if (timed_out && rc == -2) *timed_out = 1;

  int hits = 0;
  if (out_text) {
    char **lines = NULL;
    int n = str_split(out_text, '\n', &lines, 0);
    for (int i = 0; i < n && hits < 40; i++) {
      char *line = str_trim(lines[i]);
      if (!line[0] || line[0] != '{') continue;
      json_t *o = json_parse(line);
      if (!o) continue;
      const char *tid = j_s(o, "template-id", "");
      json_t *info = j_get(o, "info");
      const char *name = info ? j_s(info, "name", tid) : tid;
      if (!tid[0] && !name[0]) { json_free(o); continue; }

      /* 同一模板打到同一地址只留一条 —— nuclei 会因为多个 matcher 重复报 */
      int dup = 0;
      for (int k = 0; k < j_len(checks); k++) {
        if (str_ieq(j_s(j_at(checks, k), "id", ""), name)) { dup = 1; break; }
      }
      if (dup) { json_free(o); continue; }

      const char *matched = j_s(o, "matched-at", target);
      const char *matcher = j_s(o, "matcher-name", "");
      buf_t ev;
      buf_init(&ev);
      buf_printf(&ev, "%s", matched);
      if (matcher[0]) buf_printf(&ev, " · 匹配 %s", matcher);

      const char *desc = info ? j_s(info, "description", "") : "";
      const char *rem = info ? j_s(info, "remediation", "") : "";
      buf_t impact;
      buf_init(&impact);
      if (desc[0]) {
        buf_puts(&impact, desc);                 /* 模板作者写的影响说明,原样转述 */
        if (impact.len > 240) { impact.data[240] = 0; impact.len = 240; }
      } else {
        buf_puts(&impact, "该模板命中说明目标存在对应组件的已知问题或暴露面");
      }
      buf_t fix;
      buf_init(&fix);
      if (rem[0]) buf_puts(&fix, rem);
      else buf_printf(&fix, "按模板 %s 的说明升级/收敛暴露面后复测", tid);

      json_t *c = j_obj();
      j_set_str(c, "id", name);
      j_set_str(c, "title", name);
      j_set_str(c, "severity", nuclei_severity_cn(info ? j_s(info, "severity", "") : ""));
      j_set_str(c, "evidence", ev.data);
      j_set_str(c, "impact", impact.data);
      j_set_str(c, "fix", fix.data);
      j_set_str(c, "from", "nuclei");
      j_set_str(c, "template", tid);
      j_add(checks, c);
      buf_free(&ev);
      buf_free(&impact);
      buf_free(&fix);
      json_free(o);
      hits++;
    }
    str_free_list(lines, n);
    free(out_text);
  }
  (void)code;
  return hits;
}

int t_nuclei_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  char target_buf[1024];
  normalize_target(j_s(args, "target", ""), target_buf, sizeof(target_buf));
  const char *target = target_buf;
  fetch_t f;
  t_fetch(ctx, target, &f);
  if (f.err && !f.status) {
    json_t *d = j_obj();
    j_set_str(d, "target", target);
    j_set_str(d, "error", f.err ? f.err : "取不到内容");
    out->data = d;
    out->is_error = 1;
    out->text = xstrdup("目标取不到内容,弱配置检查无法进行");
    out->say = xstrdup("目标连不上,这次不给配置结论。");
    fetch_free2(&f);
    return -1;
  }

  int https = str_startswith(target, "https://");
  json_t *checks = j_arr();
  json_t *missing = j_arr();
  const char *body = f.body ? f.body : "";

  /* (1) 期望的安全响应头 —— 缺哪些列哪些,严重度取规则里最高的那一个 */
  if (web_headers_available(f.headers)) {
    int worst = 99;
    static const char *ORDER[] = {"信息", "低", "中", "高", "严重", ""};
    for (int i = 0; i < rules_weak_header_count(); i++) {
      const char *name = rules_weak_header(i, "name", "");
      int only_https = rules_weak_header_num(i, "only_https", 0);
      if (only_https && !https) continue;
      if (web_header_count(f.headers, name) > 0) continue;
      json_t *m = j_obj();
      j_set_str(m, "header", name);
      j_set_str(m, "title", rules_weak_header(i, "title", name));
      j_set_str(m, "severity", rules_weak_header(i, "severity", "低"));
      j_set_str(m, "impact", rules_weak_header(i, "impact", ""));
      j_set_str(m, "fix", rules_weak_header(i, "fix", ""));
      j_add(missing, m);
      for (int s = 0; ORDER[s][0]; s++) {
        if (strcmp(ORDER[s], j_s(m, "severity", "")) == 0 && s < worst) worst = s;
      }
    }
    if (j_len(missing) > 0) {
      buf_t names;
      buf_init(&names);
      for (int i = 0; i < j_len(missing); i++) {
        if (i) buf_puts(&names, "、");
        buf_puts(&names, j_s(j_at(missing, i), "title", ""));
      }
      json_t *c = j_obj();
      j_set_str(c, "id", "weak-headers");
      j_set_str(c, "title", "安全响应头缺失");
      j_set_str(c, "severity", ORDER[worst < 4 ? worst : 0]);
      j_set_num(c, "count", j_len(missing));
      j_set(c, "items", j_clone(missing));
      buf_printf(&names, ";补齐后能挡掉一类常见的浏览器侧攻击");
      j_set_str(c, "evidence", names.data);
      j_set_str(c, "impact", "缺少浏览器侧的安全约束,点击劫持、MIME 嗅探、引用泄露等风险上升");
      j_set_str(c, "fix", "按缺失项逐条补齐响应头,并纳入上线检查");
      j_add(checks, c);
      buf_free(&names);
    }
  }

  /* (2) Cookie 属性:会话票据没加 HttpOnly/Secure 是实打实的风险 */
  {
    json_t *cookie_issues = j_arr();
    int n = web_header_count(f.headers, "set-cookie");
    for (int i = 0; i < n; i++) {
      buf_t v;
      buf_init(&v);
      if (web_header_at(f.headers, "set-cookie", i, &v)) {
        const char *val = v.data ? v.data : "";
        int http_only = str_icontains(val, "httponly");
        int secure = str_icontains(val, "secure");
        int same_site = str_icontains(val, "samesite");
        if (!http_only || (!secure && https) || !same_site) {
          buf_t miss;
          buf_init(&miss);
          if (!http_only) buf_puts(&miss, "HttpOnly ");
          if (!secure && https) buf_puts(&miss, "Secure ");
          if (!same_site) buf_puts(&miss, "SameSite");
          json_t *ci = j_obj();
          /* cookie 的名字是有用信息,值已经在校准时打过星 */
          j_set_str(ci, "cookie", val);
          j_set_str(ci, "missing", miss.data);
          j_add(cookie_issues, ci);
          buf_free(&miss);
        }
      }
      buf_free(&v);
    }
    if (j_len(cookie_issues) > 0) {
      json_t *c = j_obj();
      j_set_str(c, "id", "cookie-flags");
      j_set_str(c, "title", "Cookie 缺少安全属性");
      j_set_str(c, "severity", "中");
      j_set(c, "items", j_clone(cookie_issues));
      j_set_str(c, "evidence", j_s(j_at(cookie_issues, 0), "cookie", ""));
      j_set_str(c, "impact", "会话 Cookie 可被脚本读取或在明文信道回传,增加会话被窃取的风险");
      j_set_str(c, "fix", "为会话 Cookie 增加 HttpOnly、Secure 与 SameSite 属性");
      j_add(checks, c);
    }
    json_free(cookie_issues);
  }

  /* (3) 版本信息泄露:应答头把组件版本直接报出来 */
  {
    json_t *leaks = j_arr();
    int n = 0;
    const char **keys = rules_str_list("server_header_keys", &n);
    for (int i = 0; i < n; i++) {
      buf_t v;
      buf_init(&v);
      if (web_header(f.headers, keys[i], &v) && v.data && v.data[0]) {
        int has_digit = 0;
        for (const char *p = v.data; *p; p++) if (*p >= '0' && *p <= '9') has_digit = 1;
        json_t *l = j_obj();
        j_set_str(l, "header", keys[i]);
        j_set_str(l, "value", v.data);
        j_set_bool(l, "version_like", has_digit);
        j_add(leaks, l);
      }
      buf_free(&v);
    }
    int version_like = 0;
    for (int i = 0; i < j_len(leaks); i++) if (j_b(j_at(leaks, i), "version_like", 0)) version_like = 1;
    if (version_like) {
      json_t *c = j_obj();
      j_set_str(c, "id", "version-disclosure");
      j_set_str(c, "title", "响应头泄露中间件版本");
      j_set_str(c, "severity", "低");
      j_set(c, "items", j_clone(leaks));
      j_set_str(c, "evidence", j_s(j_at(leaks, 0), "header", ""));
      j_set_str(c, "impact", "攻击者可据此匹配已知漏洞,降低攻击成本");
      j_set_str(c, "fix", "关闭或改写 Server/X-Powered-By 等版本信息");
      j_add(checks, c);
    }
    json_free(leaks);
  }

  /* (4) 错误回显:用一个不存在的路径看站点会不会把数据库/堆栈错误抛给访问者 */
  {
    char root[512];
    probe_root(target, root, sizeof(root));
    char url[1024];
    join_path(url, sizeof(url), root, "/no-such-path-probe-zz");
    fetch_t e;
    t_fetch(ctx, url, &e);
    if (!(e.err && !e.status) && e.body) {
      int n = 0;
      const char **sigs = rules_str_list("error_signatures", &n);
      for (int i = 0; i < n; i++) {
        if (str_icontains(e.body, sigs[i])) {
          json_t *c = j_obj();
          j_set_str(c, "id", "error-disclosure");
          j_set_str(c, "title", "错误页回显内部信息");
          j_set_str(c, "severity", "中");
          j_set_str(c, "evidence", sigs[i]);
          j_set_str(c, "impact", "报错信息会暴露技术栈与内部细节,为后续攻击提供线索");
          j_set_str(c, "fix", "统一错误页,关闭调试输出与详细报错");
          j_add(checks, c);
          break;
        }
      }
    }
    fetch_free2(&e);
  }

  /* (5) 允许的 HTTP 方法:OPTIONS 只问不写,是判断"是否暴露了写方法"的安全手法 */
  {
    fetch_t o;
    t_fetch_m(ctx, target, "OPTIONS", &o);
    if (!(o.err && !o.status)) {
      buf_t allow;
      buf_init(&allow);
      if (web_header(o.headers, "allow", &allow) && allow.data) {
        json_t *bads = j_arr();
        int n = 0;
        const char **dang = rules_str_list("dangerous_methods", &n);
        for (int i = 0; i < n; i++) {
          if (str_icontains(allow.data, dang[i])) j_add(bads, j_str(dang[i]));
        }
        if (j_len(bads) > 0) {
          json_t *c = j_obj();
          j_set_str(c, "id", "dangerous-methods");
          j_set_str(c, "title", "服务端声明了不必要的写方法");
          j_set_str(c, "severity", "中");
          j_set(c, "items", j_clone(bads));
          j_set_str(c, "evidence", allow.data);
          j_set_str(c, "impact", "TRACE/PUT/DELETE 等被不当开放时可被用于跨站追踪或越权改动");
          j_set_str(c, "fix", "按业务最小化允许的方法,关闭 TRACE 与无用写方法");
          j_add(checks, c);
        }
      }
      buf_free(&allow);
    }
    fetch_free2(&o);
  }

  /* (6) 目录索引与混合内容:与目录/完整性检查同源,这里只做"顺带发现" */
  if (web_is_dir_listing(body)) {
    json_t *c = j_obj();
    j_set_str(c, "id", "dir-listing");
    j_set_str(c, "title", "该地址返回目录索引");
    j_set_str(c, "severity", "中");
    j_set_str(c, "evidence", "页面包含目录索引特征");
    j_set_str(c, "impact", "目录结构被完整暴露,文件命名与内部结构因此可被枚举");
    j_set_str(c, "fix", "关闭目录浏览(autoindex),只保留确需公开的文件");
    j_add(checks, c);
  }
  if (https && web_has_mixed_content(body)) {
    json_t *c = j_obj();
    j_set_str(c, "id", "mixed-content");
    j_set_str(c, "title", "HTTPS 页面引用 HTTP 资源");
    j_set_str(c, "severity", "低");
    j_set_str(c, "evidence", "页面存在 http:// 形式的资源引用");
    j_set_str(c, "impact", "资源可被中间人替换,HTTPS 的保护被局部抵消");
    j_set_str(c, "fix", "把资源引用统一改为 https 或站内相对路径");
    j_add(checks, c);
  }

  /* 内置检查做完,再叠一层开源工具:nuclei 装了就跑,没装就只报内置结果 */
  int nuclei_timeout = 0;
  int nuclei_hits = nuclei_merge(target, checks, &nuclei_timeout);

  json_t *data = j_obj();
  j_set_str(data, "target", target);
  j_set_num(data, "status_code", f.status);
  j_set_str(data, "engine", nuclei_hits >= 0 ? "内置非破坏性模板 + nuclei 模板"
                                             : "内置非破坏性模板");
  j_set_num(data, "nuclei_hits", nuclei_hits < 0 ? 0 : nuclei_hits);
  j_set_bool(data, "nuclei_used", nuclei_hits >= 0 ? 1 : 0);
  if (nuclei_hits < 0) {
    j_set_str(data, "nuclei_note",
              "本机没找到 nuclei.exe;把 nuclei.exe 放到程序同目录或数据目录的 tools\\ 下,"
              "下次巡检就会自动调用它并归并结果。本次结论只来自内置检查。");
  } else if (nuclei_timeout) {
    j_set_str(data, "nuclei_note", "nuclei 在 60 秒内没跑完,已中止;本次只有已产出的命中。");
  }
  j_set_bool(data, "headers_available", web_headers_available(f.headers) ? 1 : 0);
  j_set(data, "checks", checks);
  j_set(data, "missing_headers", missing);
  j_set_num(data, "check_count", j_len(checks));
  put_rules_note(data);
  out->data = data;

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "弱配置与漏洞模板探测 %s → HTTP %d%s;共 %d 项需要关注。",
             target, f.status, web_headers_available(f.headers) ? "" : "(本次未取到响应头)", j_len(checks));
  if (nuclei_hits > 0) buf_printf(&t, "(其中 %d 项来自 nuclei 模板)", nuclei_hits);
  for (int i = 0; i < j_len(checks); i++) {
    buf_printf(&t, "\n- [%s] %s —— %s", j_s(j_at(checks, i), "severity", ""),
               j_s(j_at(checks, i), "title", ""), j_s(j_at(checks, i), "evidence", ""));
  }
  out->text = buf_take(&t);

  buf_t s;
  buf_init(&s);
  if (j_len(checks) == 0) {
    buf_printf(&s, "配置检查完成:%s 未发现规则覆盖的弱配置项(响应头、Cookie、方法、错误回显都过了)。",
               target);
    if (!web_headers_available(f.headers)) {
      buf_puts(&s, "注意:本次没取到响应头,响应头相关的检查未生效,不能算通过。");
    }
  } else {
    int crit = 0;
    for (int i = 0; i < j_len(checks); i++) {
      const char *sev = j_s(j_at(checks, i), "severity", "");
      if (strcmp(sev, "严重") == 0 || strcmp(sev, "高") == 0) crit++;
    }
    buf_printf(&s, "配置检查完成:%s 共发现 %d 项需要关注", target, j_len(checks));
    if (crit) buf_printf(&s, "(其中 %d 项为高及以上", crit);
    if (crit && nuclei_hits > 0) buf_printf(&s, ",含 nuclei 模板命中 %d 项", nuclei_hits);
    if (crit) buf_puts(&s, ")");
    buf_puts(&s, ",详见结果卡片。");
  }
  out->say = buf_take(&s);
  fetch_free2(&f);
  return 0;
}
