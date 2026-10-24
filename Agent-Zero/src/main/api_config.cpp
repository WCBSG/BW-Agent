/* api_config.cpp —— 规则与配置文件的接口实现(从 serve.cpp 拆出来的第一块)。
 *
 * 这一块管两件相关的事:
 *   /api/settings    规则设置的图形化读写(整份 rules 对象)
 *   /api/config/...  数据目录里那几个"能手改"的文件:rules.json、mcp.json、
 *                    skills\*.md、tools\*.json
 *
 * 安全边界写死在这里(和拆出来之前一模一样,只是换了个文件):
 *   · 只允许数据目录下的白名单文件
 *   · 名字里不许出现 .. / 盘符 / 绝对路径 / 多层目录(只允许"一层子目录 + 文件名")
 *   · 单文件上限 256KB;写之前先备份成 <名字>.bak;JSON 必须先解析通过才落盘
 * 这样"能改配置"和"不能被当成任意文件写入漏洞"两件事同时成立。
 */
#include "serve_ctx.h"

#include "ext.h"
#include "json.h"
#include "rules.h"
#include "rules_domains.h"

#include <string>
#include <vector>

#define CFG_MAX_BYTES (256 * 1024)

/* ================= 规则设置(图形化) =================
   规则按 6 个域分文件存放(见 rules_domains.h)。这里提供三种用法:
     GET  /api/settings                 → 域清单 + 当前生效的整份规则(界面首屏一次取全)
     GET  /api/settings?domain=detect   → 只看一个域
     POST /api/settings {domain, patch} → 保存一个域(只落这一个文件)
     POST /api/settings {rules}         → 整份写回(兼容旧调用,按域拆开落盘)
   按域保存的意义不只是"文件小":改弱口令不会顺手动到告警阈值,
   版本库里也只出现一个文件的差异。 */
void api_rules(const http_req_t *req, http_res_t *res) {
  char dir[MAX_PATH * 2];
  rules_domain_dir(dir, sizeof(dir));

  if (strcmp(req->method, "POST") == 0) {
    json_t *body = req->body ? json_parse(req->body) : NULL;
    if (!body) {
      http_res_json(res, 400, "{\"ok\":false,\"error\":\"请求体不是合法 JSON\"}");
      return;
    }
    /* domain 指向 body 内部,body 释放后就是野指针 —— 先拷一份 */
    char domain[32];
    snprintf(domain, sizeof(domain), "%s", j_s(body, "domain", ""));
    json_t *patch = j_get(body, "patch");
    json_t *rules = j_get(body, "rules");
    char err[512] = {0};
    int rc;
    const char *what = "";

    if (domain[0]) {
      if (!patch || patch->type != J_OBJ) {
        json_free(body);
        http_res_json(res, 400, "{\"ok\":false,\"error\":\"需要 patch 对象(这一域要保存的字段)\"}");
        return;
      }
      const rules_domain_t *d = rules_domain_find(domain);
      char *dump = json_dump(patch);
      rc = rules_domains_save(domain, patch, err, sizeof(err));
      what = d ? d->title : domain;
      free(dump);
    } else if (rules && rules->type == J_OBJ) {
      rc = rules_domains_save_all(rules, err, sizeof(err));
      what = "全部规则";
    } else {
      json_free(body);
      http_res_json(res, 400,
                    "{\"ok\":false,\"error\":\"需要 domain+patch,或者整份 rules\"}");
      return;
    }
    json_free(body);

    if (rc != 0) {
      buf_t e;
      buf_init(&e);
      buf_puts(&e, "{\"ok\":false,\"error\":");
      buf_json_str(&e, err[0] ? err : "规则保存失败");
      buf_puts(&e, "}");
      http_res_json(res, 500, e.data);
      buf_free(&e);
      return;
    }

    /* 写完立刻重载:规则是"改了马上生效"而不是"改完记得重启" */
    rules_shutdown();
    rules_init(app_dir());
    serve_refresh_status();
    serve_audit_line(domain[0] ? "修改规则(按域)" : "修改规则设置", what, "界面保存并重载");

    buf_t b;
    buf_init(&b);
    buf_puts(&b, "{\"ok\":true,\"domain\":");
    buf_json_str(&b, domain);
    buf_puts(&b, ",\"source\":");
    buf_json_str(&b, rules_source());
    buf_puts(&b, "}");
    http_res_json(res, 200, b.data);
    buf_free(&b);
    return;
  }

  /* GET */
  char want[32];
  http_query(req, "domain", want, sizeof(want), "");

  json_t *out = j_obj();
  j_set_bool(out, "ok", 1);
  j_set_str(out, "dir", dir);
  j_set_str(out, "source", rules_source());
  j_set_bool(out, "fromFile", rules_from_file());

  if (want[0]) {
    char err[512] = {0};
    json_t *dom = rules_domains_read(want, err, sizeof(err));
    if (!dom) {
      json_free(out);
      buf_t e;
      buf_init(&e);
      buf_puts(&e, "{\"ok\":false,\"error\":");
      buf_json_str(&e, err[0] ? err : "读不到这一域");
      buf_puts(&e, "}");
      http_res_json(res, 400, e.data);
      buf_free(&e);
      return;
    }
    const rules_domain_t *d = rules_domain_find(want);
    j_set_str(out, "domain", want);
    j_set_str(out, "title", d ? d->title : want);
    j_set_str(out, "note", d ? d->note : "");
    j_set(out, "rules", dom);
    char *text = json_dump(out);
    http_res_json(res, 200, text);
    free(text);
    json_free(out);
    return;
  }

  /* 域清单:界面左侧那一列就是它(顺序也来自这里,不是前端自己写死) */
  json_t *list = j_arr();
  for (int i = 0; i < rules_domain_count(); i++) {
    const rules_domain_t *d = rules_domain_at(i);
    char path[MAX_PATH * 4];
    path_join(path, sizeof(path), dir, d->file);
    long sz = file_size(path);
    json_t *o = j_obj();
    j_set_str(o, "id", d->id);
    j_set_str(o, "title", d->title);
    j_set_str(o, "note", d->note);
    j_set_str(o, "file", d->file);
    j_set_num(o, "size", sz > 0 ? (double)sz : 0);
    j_set_bool(o, "exists", sz >= 0 ? 1 : 0);
    j_add(list, o);
  }
  j_set(out, "domains", list);

  /* 整份规则:起手式/状态卡这些地方还要看"生效的到底是什么",不必再发一次请求 */
  json_t *root = rules_root();
  json_t *copy = root ? j_clone(root) : j_obj();
  j_set(out, "rules", copy ? copy : j_obj());

  char *text = json_dump(out);
  http_res_json(res, 200, text);
  free(text);
  json_free(out);
}

/* ================= 数据目录里的配置文件(前台可编辑) ================= */
static int cfg_allowed(const char *name) {
  if (!name || !*name) return 0;
  size_t len = strlen(name);
  if (len > 128) return 0;
  if (strstr(name, "..") || strchr(name, ':') || name[0] == '\\' || name[0] == '/') return 0;
  int slash = 0;
  for (const char *p = name; *p; p++) {
    if (*p == '\\' || *p == '/') slash++;
  }
  int md = str_endswith(name, ".md");
  int js = str_endswith(name, ".json");
  if (!md && !js) return 0;
  if (slash == 0) {
    /* 旧的 rules.json 不再参与:规则已拆到 rules\ 下,留着入口只会让人改一个不生效的文件 */
    return strcmp(name, "mcp.json") == 0 || strcmp(name, "rules.default.json") == 0;
  }
  /* 技能与工具现在是"一个目录一个":skills\<名字>\SKILL.md、tools\<目录>\<名字>.json。
     所以这里允许到两级,但仍然挡住更深的路径与 ..(越界由 cfg_path 再兜一层)。 */
  if (slash > 2) return 0;
  if (str_startswith(name, "skills\\") || str_startswith(name, "skills/")) return md;
  if (str_startswith(name, "tools\\") || str_startswith(name, "tools/")) return js;
  /* 规则的 6 个分域文件也要能手改(界面改不动的东西,记事本还留一条路) */
  if (str_startswith(name, "rules\\") || str_startswith(name, "rules/")) return js;
  return 0;
}

/* 把白名单名字解析成数据目录下的绝对路径;返回 1 成功 */
static int cfg_path(const char *name, char *out, size_t cap) {
  if (!cfg_allowed(name)) return 0;
  char norm[192];
  snprintf(norm, sizeof(norm), "%s", name);
  for (char *p = norm; *p; p++) if (*p == '/') *p = '\\';
  app_data_path(out, cap, norm);
  return 1;
}

void api_config_list(const http_req_t *req, http_res_t *res) {
  (void)req;
  json_t *arr = j_arr();

  /* 规则不在这里列:它有自己的页面(按域编辑),放在"可编辑文件"里只会让人重复改。
     这里只留真正需要手工编辑的东西:mcp.json、技能说明、外部工具。 */
  const char *fixed[] = {"mcp.json", NULL};
  for (int i = 0; fixed[i]; i++) {
    char path[MAX_PATH * 2];
    app_data_path(path, sizeof(path), fixed[i]);
    long sz = file_size(path);
    json_t *o = j_obj();
    j_set_str(o, "name", fixed[i]);
    j_set_bool(o, "exists", sz >= 0 ? 1 : 0);
    j_set_num(o, "size", sz > 0 ? (double)sz : 0);
    j_set_str(o, "group", "外部能力");
    j_add(arr, o);
  }
  /* 技能:skills\<名字>\SKILL.md(目录形态)与 skills\<名字>.md(旧形态)
     工具:tools\<目录>\<名字>.json(目录形态)与 tools\<名字>.json(旧形态) */
  {
    const char *sub = "skills";
    char dir[MAX_PATH * 2];
    app_data_path(dir, sizeof(dir), sub);
    ensure_dir(dir);

    std::vector<std::string> flat = fs_list_files(dir, ".md");
    for (size_t i = 0; i < flat.size(); i++) {
      char rel[192];
      snprintf(rel, sizeof(rel), "%s\\%s", sub, flat[i].c_str());
      char full[MAX_PATH * 2];
      app_data_path(full, sizeof(full), rel);
      json_t *o = j_obj();
      j_set_str(o, "name", rel);
      j_set_bool(o, "exists", 1);
      j_set_num(o, "size", (double)file_size(full));
      j_set_str(o, "group", "技能");
      j_add(arr, o);
    }
    std::vector<std::string> subs = fs_list_dirs(dir);
    for (size_t i = 0; i < subs.size(); i++) {
      char rel[192];
      snprintf(rel, sizeof(rel), "%s\\%s\\SKILL.md", sub, subs[i].c_str());
      char full[MAX_PATH * 2];
      app_data_path(full, sizeof(full), rel);
      if (file_size(full) < 0) continue;
      json_t *o = j_obj();
      j_set_str(o, "name", rel);
      j_set_bool(o, "exists", 1);
      j_set_num(o, "size", (double)file_size(full));
      j_set_str(o, "group", "技能");
      j_add(arr, o);
    }
  }
  {
    const char *sub = "tools";
    char dir[MAX_PATH * 2];
    app_data_path(dir, sizeof(dir), sub);
    ensure_dir(dir);
    std::vector<std::string> subs = fs_list_dirs(dir);
    for (size_t i = 0; i < subs.size(); i++) {
      char subdir[MAX_PATH * 2];
      snprintf(subdir, sizeof(subdir), "%s\\%s", dir, subs[i].c_str());
      std::vector<std::string> inner = fs_list_files(subdir, ".json");
      for (size_t k = 0; k < inner.size(); k++) {
        char rel[192];
        snprintf(rel, sizeof(rel), "%s\\%s\\%s", sub, subs[i].c_str(), inner[k].c_str());
        char full[MAX_PATH * 2];
        app_data_path(full, sizeof(full), rel);
        json_t *o = j_obj();
        j_set_str(o, "name", rel);
        j_set_bool(o, "exists", 1);
        j_set_num(o, "size", (double)file_size(full));
        j_set_str(o, "group", "工具");
        j_add(arr, o);
      }
    }
    std::vector<std::string> flat = fs_list_files(dir, ".json");
    for (size_t i = 0; i < flat.size(); i++) {
      char rel[192];
      snprintf(rel, sizeof(rel), "%s\\%s", sub, flat[i].c_str());
      char full[MAX_PATH * 2];
      app_data_path(full, sizeof(full), rel);
      json_t *o = j_obj();
      j_set_str(o, "name", rel);
      j_set_bool(o, "exists", 1);
      j_set_num(o, "size", (double)file_size(full));
      j_set_str(o, "group", "工具");
      j_add(arr, o);
    }
  }
  char *dump = json_dump(arr);
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"ok\":true,\"files\":");
  buf_puts(&b, dump);
  buf_puts(&b, "}");
  http_res_json(res, 200, b.data);
  buf_free(&b);
  free(dump);
  json_free(arr);
}

void api_config_get(const http_req_t *req, http_res_t *res) {
  char name[192];
  http_query(req, "name", name, sizeof(name), "");
  char path[MAX_PATH * 2];
  if (!cfg_path(name, path, sizeof(path))) {
    http_res_text(res, 400, "application/json; charset=utf-8",
                  "{\"ok\":false,\"error\":\"只允许编辑数据目录下的 rules\\\\*.json / mcp.json / skills\\\\*.md / tools\\\\*.json\"}");
    return;
  }
  size_t len = 0;
  char *text = file_read_all(path, &len);
  buf_t b;
  buf_init(&b);
  if (!text) {
    buf_puts(&b, "{\"ok\":true,\"exists\":false,\"name\":");
    buf_json_str(&b, name);
    buf_puts(&b, ",\"content\":\"\"}");
  } else {
    if (len > CFG_MAX_BYTES) {
      buf_printf(&b, "{\"ok\":false,\"error\":\"文件超过 %dKB,请用记事本打开\"}", CFG_MAX_BYTES / 1024);
      http_res_json(res, 200, b.data);
      buf_free(&b);
      free(text);
      return;
    }
    buf_puts(&b, "{\"ok\":true,\"exists\":true,\"name\":");
    buf_json_str(&b, name);
    buf_printf(&b, ",\"size\":%d,\"content\":", (int)len);
    buf_json_str(&b, text);
    buf_puts(&b, "}");
    free(text);
  }
  http_res_json(res, 200, b.data);
  buf_free(&b);
}

/* 保存 + 校验规则:JSON 必须能解析(否则不落盘);落盘前留一份 .bak */
void api_config_save(const http_req_t *req, http_res_t *res) {
  json_t *body = req->body ? json_parse(req->body) : NULL;
  const char *name = body ? j_s(body, "name", "") : "";
  const char *content = body ? j_s(body, "content", "") : "";
  if (!body || !name[0]) {
    if (body) json_free(body);
    http_res_text(res, 400, "application/json; charset=utf-8",
                  "{\"ok\":false,\"error\":\"需要 name 与 content\"}");
    return;
  }
  char path[MAX_PATH * 2];
  if (!cfg_path(name, path, sizeof(path))) {
    json_free(body);
    http_res_text(res, 400, "application/json; charset=utf-8",
                  "{\"ok\":false,\"error\":\"文件名不在白名单里\"}");
    return;
  }
  size_t len = strlen(content);
  if (len > CFG_MAX_BYTES) {
    json_free(body);
    http_res_text(res, 400, "application/json; charset=utf-8",
                  "{\"ok\":false,\"error\":\"内容过大(上限 256KB)\"}");
    return;
  }
  int is_json = str_endswith(name, ".json");
  if (is_json) {
    json_t *probe = json_parse(content);
    if (!probe) {
      json_free(body);
      http_res_text(res, 400, "application/json; charset=utf-8",
                    "{\"ok\":false,\"error\":\"JSON 语法不合法,已拒绝保存(检查逗号/引号/括号)\"}");
      return;
    }
    json_free(probe);
  }
  /* 备份上一版:改坏了还能回头 */
  char bak[MAX_PATH * 2];
  snprintf(bak, sizeof(bak), "%s.bak", path);
  if (file_size(path) >= 0) {
    size_t old_len = 0;
    char *old = file_read_all(path, &old_len);
    if (old) {
      file_write_all(bak, old, old_len);
      free(old);
    }
  }
  char dir[MAX_PATH * 2];
  snprintf(dir, sizeof(dir), "%s", path);
  char *slash = strrchr(dir, '\\');
  if (slash) { *slash = 0; ensure_dir(dir); }
  /* 保留原来的换行风格:浏览器 textarea 会把 CRLF 归一成 LF,
     直接写回去会让"只改了一个词"的文件在 git 里整篇 diff。
     策略:原文件用 CRLF 就按 CRLF 写;原文件不存在(新建)按 LF。 */
  int want_crlf = 0;
  if (file_size(path) >= 0) {
    size_t chk_len = 0;
    char *chk = file_read_all(path, &chk_len);
    if (chk) {
      want_crlf = (strstr(chk, "\r\n") != NULL);
      free(chk);
    }
  }
  int rc;
  if (want_crlf && !strstr(content, "\r\n")) {
    buf_t conv;
    buf_init(&conv);
    for (const char *p = content; *p; p++) {
      if (*p == '\n') buf_putc_(&conv, '\r');
      buf_putc_(&conv, *p);
    }
    len = conv.len;
    rc = file_write_all(path, conv.data, conv.len);
    buf_free(&conv);
  } else {
    rc = file_write_all(path, content, len);
  }
  json_free(body);
  buf_t b;
  buf_init(&b);
  if (rc != 0) {
    buf_puts(&b, "{\"ok\":false,\"error\":\"写入失败(检查文件是否被别的程序占用)\"}");
  } else {
    buf_printf(&b, "{\"ok\":true,\"name\":");
    buf_json_str(&b, name);
    buf_printf(&b, ",\"size\":%d,\"backup\":", (int)len);
    buf_json_str(&b, file_size(bak) >= 0 ? "已留 .bak 备份" : "本次无旧版本");
    buf_puts(&b, "}");
    serve_audit_line("界面编辑配置", name, "经界面保存并校验");
  }
  http_res_json(res, 200, b.data);
  buf_free(&b);
}

/* 规则热加载:改完 rules.json 不用重启(技能/工具/MCP 仍需重启,界面会写明) */
void api_reload(const http_req_t *req, http_res_t *res) {
  (void)req;
  rules_shutdown();
  rules_init(app_dir());
  serve_refresh_status();
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"ok\":true,\"rulesSource\":");
  buf_json_str(&b, rules_source());
  buf_puts(&b, "}");
  http_res_json(res, 200, b.data);
  buf_free(&b);
}


/* ================= 规则预设 =================
   GET  /api/rules/preset            → 列出现有预设
   POST /api/rules/preset {action,save|apply|delete, name}
   应用后立刻重载规则,和按域保存同一套处理。 */
void api_rules_preset(const http_req_t *req, http_res_t *res) {
  if (strcmp(req->method, "GET") == 0) {
    json_t *list = NULL;
    char err[256] = {0};
    int n = rules_preset_list(&list, err, sizeof(err));
    json_t *out = j_obj();
    j_set_bool(out, "ok", n >= 0);
    if (n < 0) j_set_str(out, "error", err[0] ? err : "读取预设失败");
    j_set(out, "presets", list ? list : j_arr());
    j_set_str(out, "active", rules_preset_active());
    char *text = json_dump(out);
    http_res_json(res, 200, text);
    free(text);
    json_free(out);
    return;
  }

  json_t *body = req->body ? json_parse(req->body) : NULL;
  if (!body) {
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"请求体不是合法 JSON\"}");
    return;
  }
  char action[24], name[80];
  snprintf(action, sizeof(action), "%s", j_s(body, "action", ""));
  snprintf(name, sizeof(name), "%s", j_s(body, "name", ""));
  json_free(body);

  char err[256] = {0};
  int rc = -1;
  const char *what = "";
  if (str_ieq(action, "save")) { rc = rules_preset_save(name, err, sizeof(err)); what = "保存预设"; }
  else if (str_ieq(action, "apply")) { rc = rules_preset_apply(name, err, sizeof(err)); what = "应用预设"; }
  else if (str_ieq(action, "delete")) { rc = rules_preset_delete(name, err, sizeof(err)); what = "删除预设"; }
  else {
    http_res_json(res, 400, "{\"ok\":false,\"error\":\"action 只能是 save / apply / delete\"}");
    return;
  }

  json_t *out = j_obj();
  j_set_bool(out, "ok", rc >= 0);
  j_set_str(out, "name", name);
  j_set_num(out, "files", rc);
  if (rc < 0) j_set_str(out, "error", err[0] ? err : "操作失败");

  if (rc >= 0 && str_ieq(action, "apply")) {
    rules_shutdown();
    rules_init(app_dir());
    serve_refresh_status();
    serve_audit_line("切换规则预设", name, "界面切换并重载");
  }
  char *text = json_dump(out);
  http_res_json(res, rc >= 0 ? 200 : 500, text);
  free(text);
  json_free(out);
  (void)what;
}
