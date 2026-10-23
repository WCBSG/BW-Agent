/* tools.cpp —— 工具注册表 + 参数校验 + 合规目标解析。
 *
 * 工具是最低层的手:一次取数、一次匹配。它们不懂"业务",只负责"做一次动作并把
 * 结果如实返回"。"这件事该不该做、做完算不算成功"是技能层的事。
 *
 * 所有工具都遵守两条纪律:
 *   1. 只做只读动作(GET/HEAD),不做任何写入、上传、爆破、利用;
 *   2. 目标必须过授权校验(由 net.c 的合规层兜底,工具自己也再查一次)。
 *
 * 例外只有一组:**本机设置类工具**(pool_list / agent_info / settings_get / settings_set)。
 * 它们读写的是这台机器上的配置,不碰被检目标,所以"只读"这条对它们不适用;
 * 但反过来管得更严:授权池只读、审批只能收紧、周期规则的目标必须在授权池内,
 * 每一次写入都留审计 —— 智能体不能靠"改设置"给自己扩权。
 */
#include "tools.h"
#include "regex.h"
#include "profile.h"

#include "approval.h"
#include "automation.h"
#include "embed.h"
#include "ext.h"
#include "fs_tool.h"
#include "llm.h"
#include "llm_provider.h"
#include "net.h"
#include "rules.h"
#include "rules_domains.h"
#include "skills.h"
#include "store.h"
#include "tool_entry.h"
#include "webutil.h"

#include <ctype.h>

static tool_t *g_tools = NULL;      /* 内置表 + 外部追加项 */
static int g_force_builtin = 0;     /* 自检模式:一律走进程内实现(见 tools_set_force_builtin) */
static int g_tool_count = 0;
static int g_tool_cap = 0;

/* ---------- 具体工具的实现(每个都短小、可单测) ---------- */
static int t_sensitive_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
static int t_password_check(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
static int t_site_crawl(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
static int t_pool_list(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
static int t_agent_info(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
static int t_settings_get(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
static int t_settings_set(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
static int t_sensitive_file_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
static int t_dir_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
static int t_page_diff(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
static int t_nuclei_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
static int t_sqli_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out);

/* 目标归一(补协议)与站点根提取:所有探测类工具共用,定义在后面 */
static void normalize_target(const char *in, char *out, size_t cap);
static void probe_root(const char *url, char *out, size_t cap);

/* ================= 工具声明从数据目录装载 =================
   为什么不再把 12 个工具的说明与参数形状写在这个文件里:
     声明是**给人改的**(改措辞、加参数、临时停用),实现才是要编译的代码。
     把声明搬进 agent\data\tools\<name>.json 之后,想调一句话不用重新构建;
     更关键的是,"有哪些能力"变成了一份可以打包、可以对比、可以 diff 的数据。

   一个声明长这样(见 agent/data/tools/*.json):
     { "name": "...", "kind": "内置", "readonly": true,
       "impl": "site_crawl",            <- 指向下面的通用实现表
       "source": "...", "description": "...", "schema": { ... } }

   没写 impl、改写 command 的文件是**外部命令工具**,由 ext.cpp 负责 —— 两种声明
   可以放在同一个目录里,各认各的字段,不会互相干扰。 */

typedef int (*tool_fn)(tool_ctx_t *, json_t *, tool_result_t *);

/* 通用实现表:声明里的 impl 就是这里的键。
   加一个新工具 = 在 data\tools\ 放一份声明 + 在这里加一个实现(或什么都不加,
   直接用已有的实现换一套参数与措辞)。 */
typedef struct {
  const char *impl;
  tool_fn run;
} prim_t;

static const prim_t g_prims[] = {
    {"pool_list", t_pool_list},
    {"agent_info", t_agent_info},
    {"settings_get", t_settings_get},
    {"settings_set", t_settings_set},
    {"sensitive_scan", t_sensitive_scan},
    {"password_check", t_password_check},
    {"site_crawl", t_site_crawl},
    {"sensitive_file_probe", t_sensitive_file_probe},
    {"dir_probe", t_dir_probe},
    {"page_diff", t_page_diff},
    {"nuclei_scan", t_nuclei_scan},
    {"sqli_probe", t_sqli_probe},
    {"fs_read", fs_tool_read},
    {"fs_list", fs_tool_list},
    {"fs_write", fs_tool_write},
};

static tool_fn prim_find(const char *impl) {
  if (!impl || !*impl) return NULL;
  for (size_t i = 0; i < sizeof(g_prims) / sizeof(g_prims[0]); i++) {
    if (str_ieq(g_prims[i].impl, impl)) return g_prims[i].run;
  }
  return NULL;
}

/* 追加一条(内部用):字符串都拷一份 —— 声明文本读完就 free,不能留悬空指针 */
static int tool_push(const char *name, const char *desc, const char *kind, const char *src,
                     int readonly, tool_fn run) {
  if (!name || !*name || !run) return -1;
  if (tools_find(name)) return -1;
  if (g_tool_count >= g_tool_cap) {
    g_tool_cap = g_tool_cap ? g_tool_cap * 2 : 32;
    g_tools = (tool_t *)xrealloc(g_tools, sizeof(tool_t) * (size_t)g_tool_cap);
  }
  tool_t *t = &g_tools[g_tool_count++];
  memset(t, 0, sizeof(*t));
  t->name = xstrdup(name);
  t->description = xstrdup(desc && *desc ? desc : name);
  t->schema = xstrdup("{\"type\":\"object\",\"properties\":{}}");
  t->kind = xstrdup(kind && *kind ? kind : "内置");
  t->source_url = xstrdup(src ? src : "");
  t->readonly = readonly ? 1 : 0;
  t->run = run;
  return 0;
}

/* 解析一份声明。返回 1 = 收下了(或明确判定不属于这里),0 = 文件有问题。 */
static int tool_load_spec_text(const char *text, const char *origin) {
  json_t *o = json_parse(text);
  if (!o) {
    log_warn("[工具] 声明不是合法 JSON,跳过: %s", origin);
    return 0;
  }
  if (o->type != J_OBJ) { json_free(o); return 0; }

  const char *name = j_s(o, "name", "");
  if (!name[0]) { json_free(o); return 0; }

  const char *impl = j_s(o, "impl", "");
  json_t *en = j_get(o, "entry");
  const char *etype = (en && en->type == J_OBJ) ? j_s(en, "type", "") : "";
  if (!impl[0] && str_ieq(etype, "builtin")) impl = j_s(en, "impl", "");

  tool_fn fn = impl[0] ? prim_find(impl) : NULL;

  /* 1) 先看外置入口:声明里写了 entry,或 source / 同目录里真有可执行文件。
        这样"一个目录 = 一个工具"可以直接用,不必再改程序。 */
  if (j_b(o, "allow", 1) && tool_entry_parse(o, origin) == 1) {
    json_t *sc = j_get(o, "schema");
    char *schema_txt = sc ? json_dump(sc) : NULL;
    /* 声明里的 kind 是作者写的用途说明(如「可选调 nuclei」);这里把「内置」换成「外置」,
       因为这一条现在真的是独立进程 —— 界面与日志里不该再显示成内置实现。 */
    char ext_kind[128];
    snprintf(ext_kind, sizeof(ext_kind), "%s", j_s(o, "kind", "外置"));
    if (str_startswith(ext_kind, "内置")) {
      char rest[128];
      snprintf(rest, sizeof(rest), "%s", ext_kind + strlen("内置"));
      snprintf(ext_kind, sizeof(ext_kind), "外置%s", rest);
    }
    int rc = tool_push(name, j_s(o, "description", ""), ext_kind,
                       j_s(o, "source", ""), (int)j_b(o, "readonly", 0), tool_entry_run);
    if (rc == 0 && schema_txt) {
      tool_t *t = tools_find(name);
      if (t) {
        free((void *)t->schema);
        t->schema = schema_txt;
        schema_txt = NULL;
      }
    }
    free(schema_txt);
    json_free(o);
    return 1;
  }

  /* 2) 外置入口不可用(没打包 exe / 被删了)时回落到程序内实现:
        声明里留着 impl,换台机器也不至于整个功能消失。 */
  if (fn) {
    json_t *sc = j_get(o, "schema");
    char *schema_txt = sc ? json_dump(sc) : NULL;
    int rc = tool_push(name, j_s(o, "description", ""), j_s(o, "kind", "内置"),
                       j_s(o, "source", ""), (int)j_b(o, "readonly", 0), fn);
    if (rc == 0 && schema_txt) {
      tool_t *t = tools_find(name);
      if (t) {
        free((void *)t->schema);
        t->schema = schema_txt;
        schema_txt = NULL;
      }
    }
    free(schema_txt);
    json_free(o);
    return 1;
  }

  json_free(o);
  return 1;   /* 既不是入口也不是内置:可能是旧的 command 型声明,留给 ext.cpp */
}

/* 从数据目录装载。两种放法都认:
     <数据目录>\tools\<名字>.json          一个文件一个工具(老形态)
     <数据目录>\tools\<名字>\<名字>.json   一个目录一个工具(声明与入口 exe 同目录)
   目录形态是为了"工具可以是任何东西":声明旁边就是它的 exe,换掉 exe 就换了实现。 */
static int load_specs_dir(const char *dir) {
  int n = 0;

  /* 先认目录形态:一个目录一个工具,声明旁边就是它自己的 exe。
     同名时目录优先 —— 老版本铺出来的平铺 <名字>.json 不该把新形态挤掉。 */
  std::vector<std::string> subs = fs_list_dirs(dir);
  for (const std::string &sub : subs) {
    char subdir[MAX_PATH * 2];
    snprintf(subdir, sizeof(subdir), "%s\\%s", dir, sub.c_str());
    std::vector<std::string> inner = fs_list_files(subdir, ".json");
    for (const std::string &f : inner) {
      char full[MAX_PATH * 2];
      snprintf(full, sizeof(full), "%s\\%s", subdir, f.c_str());
      size_t len = 0;
      char *text = file_read_all(full, &len);
      if (!text) continue;
      n += tool_load_spec_text(text, full);
      free(text);
    }
  }

  /* 再认平铺形态:<数据目录>\tools\<名字>.json */
  std::vector<std::string> files = fs_list_files(dir, ".json");
  for (const std::string &f : files) {
    char full[MAX_PATH * 2];
    snprintf(full, sizeof(full), "%s\\%s", dir, f.c_str());
    size_t len = 0;
    char *text = file_read_all(full, &len);
    if (!text) continue;
    n += tool_load_spec_text(text, full);
    free(text);
  }
  return n;
}

/* 兜底:数据目录里一份声明都没有(第一次运行还没铺开、或者被人清空了),
   直接用 exe 里打包的那份。这样"数据化"不会变成"少了文件就少一半能力"。 */
static int load_specs_embed(void) {
  int total = embed_count();
  int n = 0;
  for (int i = 0; i < total; i++) {
    const char *nm = embed_name_at(i);
    if (!nm || strncmp(nm, "data/tools/", 11) != 0) continue;
    const char *data = NULL;
    size_t len = 0;
    if (!embed_lookup(nm, &data, &len)) continue;
    n += tool_load_spec_text(data, nm);
  }
  return n;
}

/* 内置工具的条数 —— 外部工具追加在它后面,重新加载扩展时回到这个数 */
static int g_builtin_count = 0;

void tools_init(void) {
  /* 幂等:agent_create 也会调它。如果不判重,第二次调用会把外部工具(MCP/命令行工具)
     的注册结果全部抹掉 —— 界面与提示词里就会"少"掉用户自己加的能力。 */
  static int inited = 0;
  if (inited) return;
  inited = 1;

  char dir[MAX_PATH * 2];
  app_data_path(dir, sizeof(dir), "tools");
  ensure_dir(dir);
  int n = load_specs_dir(dir);
  if (n == 0) {
    log_warn("[工具] 数据目录里没有可用的工具声明(%s),改用 exe 内置的那份", dir);
    n = load_specs_embed();
  }
  g_builtin_count = g_tool_count;
  log_info("[工具] 已装载 %d 个声明式工具(声明来自 %s)", g_builtin_count, dir);
}

/* 退回到"只有内置工具"。界面里改完扩展配置后重新加载,用这个把上次登记的外部项清干净 ——
   不清就等于越加越多,同名还会被 tools_find 挡掉。 */
void tools_reset_external(void) { g_tool_count = g_builtin_count; }

/* 追加外部工具(用户在数据目录里定义的命令工具 / MCP 提供的工具)。
   内置的永远排在前面,同名不覆盖内置(tools_find 先命中内置)。 */
int tools_register_external(const char *name, const char *description,
                            const char *schema_json, const char *kind,
                            const char *source_url, int readonly,
                            int (*run)(tool_ctx_t *, json_t *, tool_result_t *)) {
  if (!name || !*name || !run) return -1;
  if (tools_find(name)) return -1;     /* 重名就不加,内置优先 */
  if (g_tool_count >= g_tool_cap) {
    g_tool_cap = g_tool_cap ? g_tool_cap * 2 : 32;
    g_tools = (tool_t *)xrealloc(g_tools, sizeof(tool_t) * (size_t)g_tool_cap);
  }
  tool_t *t = &g_tools[g_tool_count++];
  memset(t, 0, sizeof(*t));
  t->name = xstrdup(name);
  t->description = xstrdup(description ? description : "外部工具");
  t->schema = xstrdup(schema_json && *schema_json ? schema_json
                                                : "{\"type\":\"object\",\"properties\":{}}");
  t->kind = xstrdup(kind && *kind ? kind : "外部工具");
  t->source_url = xstrdup(source_url ? source_url : "");
  t->readonly = readonly ? 1 : 0;
  t->run = run;
  return 0;
}

int tools_count(void) { return g_tool_count; }

int tools_is_readonly(const char *name) {
  tool_t *t = tools_find(name ? name : "");
  return t ? (t->readonly != 0) : 0;
}

tool_t *tools_get(int index) {
  return (index >= 0 && index < g_tool_count) ? &g_tools[index] : NULL;
}

tool_t *tools_find(const char *name) {
  for (int i = 0; i < g_tool_count; i++) {
    if (str_ieq(g_tools[i].name, name)) return &g_tools[i];
  }
  return NULL;
}

json_t *tools_decl_json(void) {
  json_t *arr = j_arr();
  for (int i = 0; i < g_tool_count; i++) {
    tool_t *t = &g_tools[i];
    json_t *o = j_obj();
    j_set_str(o, "name", t->name);
    j_set_str(o, "description", t->description);
    json_t *schema = json_parse(t->schema);
    j_set(o, "input_schema", schema ? schema : j_obj());
    j_set_str(o, "kind", t->kind);
    j_set_str(o, "source_url", t->source_url);
    j_add(arr, o);
  }
  return arr;
}

void tools_manifest(buf_t *out) {
  for (int i = 0; i < g_tool_count; i++) {
    tool_t *t = &g_tools[i];
    buf_printf(out, "- %s —— %s\n", t->name, t->description);
  }
}

/* ================= 参数校验 ================= */
int tools_validate(tool_t *t, json_t *args, buf_t *err) {
  if (!t) {
    if (err) buf_puts(err, "没有这个工具");
    return -1;
  }
  json_t *schema = json_parse(t->schema);
  if (!schema) return 0;                       /* 没 schema 就不校验(不该发生) */
  json_t *required = j_get(schema, "required");
  int bad = 0;
  for (int i = 0; i < j_len(required); i++) {
    json_t *k = j_at(required, i);
    if (!k || k->type != J_STR) continue;
    json_t *v = j_get(args, k->str);
    if (!v || v->type == J_NULL || (v->type == J_STR && (!v->str || !v->str[0]))) {
      if (err) buf_printf(err, "缺少必填参数 %s", k->str);
      bad = 1;
      break;
    }
  }
  if (!bad) {
    /* 类型粗查:模型偶尔把数字写成字符串,这里只拦住明显不对的 */
    json_t *props = j_get(schema, "properties");
    if (props && props->type == J_OBJ) {
      for (int i = 0; i < props->count; i++) {
        const char *key = props->keys[i];
        const char *want = j_s(props->items[i], "type", NULL);
        json_t *got = j_get(args, key);
        if (!want || !got || got->type == J_NULL) continue;
        int ok = (strcmp(want, "string") == 0 && got->type == J_STR) ||
                 (strcmp(want, "integer") == 0 && got->type == J_NUM) ||
                 (strcmp(want, "number") == 0 && got->type == J_NUM) ||
                 (strcmp(want, "boolean") == 0 && got->type == J_BOOL) ||
                 (strcmp(want, "array") == 0 && got->type == J_ARR) ||
                 (strcmp(want, "object") == 0 && got->type == J_OBJ);
        if (!ok) {
          if (err) buf_printf(err, "参数 %s 类型应为 %s", key, want);
          bad = 1;
          break;
        }
      }
    }
  }
  json_free(schema);
  return bad ? -1 : 0;
}

int tools_run(tool_ctx_t *ctx, const char *name, json_t *args, tool_result_t *out) {
  memset(out, 0, sizeof(*out));
  tool_t *t = tools_find(name);
  if (!t) {
    out->text = xstrdup("没有这个工具");
    out->is_error = 1;
    out->say = xstrdup("这个工具不存在,我换个做法。");
    return -1;
  }
  buf_t err;
  buf_init(&err);
  if (tools_validate(t, args, &err) != 0) {
    out->is_error = 1;
    buf_t tb;
    buf_init(&tb);
    buf_printf(&tb, "参数校验失败:%s", err.data);
    out->text = buf_take(&tb);
    buf_t sb;
    buf_init(&sb);
    buf_printf(&sb, "参数没给全(%s),这次先不执行。", err.data);
    out->say = buf_take(&sb);
    buf_free(&err);
    return -1;
  }
  buf_free(&err);
  /* 自检跑的是进程内的假网络层(本地桩服务、假响应头),外部工具进程享受不到。
     所以自检模式下按名字回落到进程内实现 —— 测的是同一份业务判断,不是同一套传输。 */
  if (g_force_builtin) {
    tool_fn fn = prim_find(name);
    if (fn) {
      ctx->current_tool = name;
      int brc = fn(ctx, args, out);
      ctx->current_tool = NULL;
      if (!out->say) out->say = xstrdup(out->text ? out->text : "");
      return brc;
    }
  }
  /* 外部扩展(命令行工具 / MCP)的适配器靠 ctx->current_tool 知道这次调的是谁 */
  ctx->current_tool = name;
  int rc = t->run(ctx, args, out);
  ctx->current_tool = NULL;
  if (!out->say) out->say = xstrdup(out->text ? out->text : "");
  return rc;
}

/* 只走程序内实现:独立工具进程(tools\toolhost.cpp)用它。
   那几个进程里没有注册表,而 tools_run 会按名字找注册表 —— 在工具自己的 exe 里
   注册表里恰好就是"指向它自己"的入口声明,直接调会自己调自己。 */
void tools_set_force_builtin(int on) { g_force_builtin = on ? 1 : 0; }

int tools_run_builtin(tool_ctx_t *ctx, const char *name, json_t *args,
                      tool_result_t *out) {
  memset(out, 0, sizeof(*out));
  tool_fn fn = prim_find(name);
  if (!fn) {
    out->text = xstrdup("这个工具不在程序内实现表里");
    out->is_error = 1;
    out->say = xstrdup("这个工具没有可用的实现,我换个做法。");
    return -1;
  }
  if (!args) args = j_obj();

  ctx->current_tool = name;
  int rc = fn(ctx, args, out);
  ctx->current_tool = NULL;
  return rc;
}

/* ================= 目标与授权 ================= */
void target_resolve(buf_t *out, const char *raw, const char *fallback_host) {
  const char *s = raw;
  if (!s || !*s) s = fallback_host;
  if (!s || !*s) return;
  while (*s == ' ' || *s == '"' || *s == '\'') s++;
  if (*s == '/') {
    buf_puts(out, fallback_host ? fallback_host : "");
    buf_puts(out, s);
    return;
  }
  if (strstr(s, "://")) {
    buf_puts(out, s);
  } else {
    buf_puts(out, "https://");
    buf_puts(out, s);
  }
}

int scope_allows(tool_ctx_t *ctx, const char *url, char **err) {
  char host[256];
  net_host_of(url, host, sizeof(host));
  if (!host[0]) {
    if (err) *err = xstrdup("URL 里没有主机名");
    return 0;
  }
  if (ctx->domain_count == 0) return 1;      /* 没设范围时不拦(单测与本地靶站用) */
  for (int i = 0; i < ctx->domain_count; i++) {
    const char *d = ctx->domains[i];
    if (str_ieq(host, d)) return 1;
    size_t lh = strlen(host), ld = strlen(d);
    if (lh > ld && str_ieq(host + (lh - ld), d) && host[lh - ld - 1] == '.') return 1;
  }
  buf_t b;
  buf_init(&b);
  buf_printf(&b, "目标 %s 不在授权域名内(授权:%s)", host,
             ctx->domain_count ? ctx->domains[0] : "未配置");
  if (err) *err = buf_take(&b);
  else buf_free(&b);
  return 0;
}

/* 取数小包装:统一处理"授权 + 错误 + 限速" */
static int do_fetch(tool_ctx_t *ctx, const char *url, const char *method,
                    int *status, char **body, char **err) {
  if (!ctx->io.fetch) {
    if (err) *err = xstrdup("取数通道未就绪");
    return -1;
  }
  size_t len = 0;
  int rc = ctx->io.fetch(ctx->io.userdata, url, method, status, body, &len, err);
  ctx->http_calls++;
  return rc;
}

/* ================= 工具实现 ================= */

/* ---------- 本机信息与设置:公共小工具 ---------- */

/* 模型/人两边都能读的一行值:字符串不加引号,其它用紧凑 JSON */
static void value_text(buf_t *out, json_t *v) {
  if (!v) {
    buf_puts(out, "(未设置)");
    return;
  }
  if (v->type == J_STR) {
    buf_puts(out, v->str ? v->str : "");
    return;
  }
  if (v->type == J_NULL) {
    buf_puts(out, "null");
    return;
  }
  char *d = json_dump(v);
  buf_puts(out, d ? d : "");
  free(d);
}

/* 把一份规则域里的键名列出来(保存后告诉用户"这次改了哪几个键") */
static void join_keys(buf_t *out, json_t *obj) {
  if (!obj || obj->type != J_OBJ) return;
  for (int i = 0; i < obj->count; i++) {
    if (!obj->keys[i]) continue;
    if (out->len) buf_puts(out, "、");
    buf_puts(out, obj->keys[i]);
  }
}

/* 写设置的统一留痕。为什么每次都要留:模型改的东西也必须可追溯,
   出问题时能回答"这条规则是什么时候、被谁改掉的"。 */
static void settings_audit(tool_ctx_t *ctx, const char *action, const char *target,
                           const char *detail) {
  if (!ctx || !ctx->store) return;
  store_audit((store_t *)ctx->store, action, target ? target : "", 1,
              detail ? detail : "", ctx->task_id, ctx->run_id);
}

/* 对象型参数:模型可能直接给一个对象,也可能给一段 JSON 文本;两种都收。
   返回的副本由调用方 json_free(不借出 argv 里的指针,省得后面谁改了原对象)。 */
static json_t *obj_arg(json_t *args, const char *key) {
  json_t *v = j_get(args, key);
  if (!v) return NULL;
  if (v->type == J_OBJ || v->type == J_ARR) {
    char *d = json_dump(v);
    json_t *cp = d ? json_parse(d) : NULL;
    free(d);
    return cp;
  }
  if (v->type == J_STR && v->str && v->str[0]) return json_parse(v->str);
  return NULL;
}

/* 单个值:数字/布尔/对象原样用;字符串先当 JSON 试一下,不行才按纯文本 */
static json_t *value_arg(json_t *args, const char *key) {
  json_t *v = j_get(args, key);
  if (!v) return NULL;
  if (v->type == J_STR) {
    json_t *parsed = (v->str && v->str[0]) ? json_parse(v->str) : NULL;
    return parsed ? parsed : j_str(v->str ? v->str : "");
  }
  char *d = json_dump(v);
  json_t *cp = d ? json_parse(d) : NULL;
  free(d);
  return cp;
}

/* "probing.timeout_ms" → 顶层键 "probing"(规则按顶层键分域) */
static int top_key_of(const char *path, char *out, size_t cap) {
  if (!path || !*path || !out || cap == 0) return 0;
  const char *dot = strchr(path, '.');
  size_t n = dot ? (size_t)(dot - path) : strlen(path);
  if (n == 0 || n >= cap) return 0;
  memcpy(out, path, n);
  out[n] = 0;
  return 1;
}

/* 按 a.b.c 设值,中间层不存在就补一个空对象。
   为什么要它:规则一域里的值常常是嵌套的(探测参数整块是一层对象),
   而按域保存是"整键替换" —— 直接提交 {probing:{timeout_ms:x}} 会把
   max_paths/max_dirs 一起抹掉。所以先在现有内容上打点,再整键提交。 */
static int deep_set(json_t *root, const char *path, json_t *value) {
  if (!root || root->type != J_OBJ || !path || !*path) return 0;
  const char *dot = strchr(path, '.');
  if (!dot) {
    j_set(root, path, value);
    return 1;
  }
  char head[128];
  size_t n = (size_t)(dot - path);
  if (n == 0 || n >= sizeof(head)) return 0;
  memcpy(head, path, n);
  head[n] = 0;
  json_t *child = j_get(root, head);
  if (!child || child->type != J_OBJ) {
    child = j_obj();
    j_set(root, head, child);       /* 接管所有权;child 指针本身不变 */
  }
  return deep_set(child, dot + 1, value);
}

/* 失败回包:错误要能被模型读懂,也要能被人看见 */
static int settings_fail(tool_result_t *out, buf_t *msg) {
  out->is_error = 1;
  out->text = buf_take(msg);
  out->say = xstrdup("这个设置我没有改动。");
  return -1;
}

/* ---- 0. 授权列表(只读,一个请求都不发) ----
   用户说"把授权列表里的站都巡检一遍"时,模型得先知道列表里有什么。
   提示词里已经摊了一份授权池,但那是每轮开始时拍的快照;
   这个工具让它随时能重新问一遍,也让"授权列表"这件事在界面上有据可查。 */
static int t_pool_list(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  (void)args;
  char **pool = NULL;
  int n = net_pool_snapshot(&pool);

  json_t *allow = j_arr();
  json_t *deny = j_arr();
  for (int i = 0; i < n; i++) {
    const char *e = pool[i];
    if (!e || !e[0]) continue;
    if (e[0] == '!') j_add(deny, j_str(e + 1));   /* 分类已在数组里,展示时去掉 ! */
    else j_add(allow, j_str(e));
  }
  json_t *data = j_obj();
  j_set(data, "allowed", allow);
  j_set(data, "denied", deny);
  j_set_num(data, "allowed_count", j_len(allow));
  j_set_num(data, "denied_count", j_len(deny));
  if (ctx && ctx->domain_count > 0) j_set_str(data, "focus", ctx->domains[0]);
  out->data = data;

  buf_t t;
  buf_init(&t);
  if (j_len(allow) == 0) {
    if (n == 0) {
      buf_puts(&t, "授权池是空的:任何对外请求都不会发出去。"
                   "先在界面上把要检查的主机加进授权池,再发起巡检。");
    } else {
      buf_puts(&t, "授权池里没有允许的目标(全是 ! 开头的不允许条目):不会对外发任何请求。");
    }
  } else {
    buf_printf(&t, "授权池共 %d 个允许目标", j_len(allow));
    if (ctx && ctx->domain_count > 0) buf_printf(&t, ",本轮焦点是 %s", ctx->domains[0]);
    buf_puts(&t, ":\n");
    for (int i = 0; i < j_len(allow) && i < 100; i++) {
      json_t *v = j_at(allow, i);
      if (v && v->type == J_STR && v->str) buf_printf(&t, "  - %s\n", v->str);
    }
    if (j_len(deny) > 0) {
      buf_puts(&t, "明确不允许(不要访问):\n");
      for (int i = 0; i < j_len(deny) && i < 100; i++) {
        json_t *v = j_at(deny, i);
        if (v && v->type == J_STR && v->str) buf_printf(&t, "  - %s\n", v->str);
      }
    }
    buf_puts(&t, "要巡检多个站点时逐个来:一次只对一个目标调用技能或工具,一个跑完再换下一个。");
  }
  out->text = buf_take(&t);
  out->say = xstrdup(j_len(allow) > 0 ? "我先看一下授权池里有哪些站点。"
                                      : "授权池是空的,一个请求都发不出去。");
  str_free_list(pool, n);
  return 0;
}

/* ---- 0-B. 智能体自身的信息 ----
   为什么值得单独一个工具:模型对"自己是谁、现在什么状态"经常瞎猜 ——
   猜数据目录、猜用的是哪家模型、猜已经查了多少条。这里给的都是真值。 */
static int t_agent_info(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  (void)args;
  json_t *d = j_obj();
  j_set_str(d, "dataDir", app_data_dir());
  j_set_str(d, "exeDir", app_dir());

  json_t *model = j_obj();
  j_set_str(model, "active", providers_active_id());
  j_set_str(model, "display", providers_display_name());
  j_set_num(model, "configured", providers_count());
  j_set_num(model, "ready", providers_ready_count());
  j_set_bool(model, "usable", providers_ready_count() > 0);
  j_set(d, "model", model);

  char **pool = NULL;
  int pn = net_pool_snapshot(&pool);
  json_t *pallow = j_arr();
  json_t *pdeny = j_arr();
  for (int i = 0; i < pn; i++) {
    const char *e = pool[i];
    if (!e || !e[0]) continue;
    if (e[0] == '!') j_add(pdeny, j_str(e + 1));
    else j_add(pallow, j_str(e));
  }
  json_t *poolj = j_obj();
  j_set(poolj, "allowed", pallow);
  j_set(poolj, "denied", pdeny);
  j_set_num(poolj, "allowed_count", j_len(pallow));
  j_set_num(poolj, "denied_count", j_len(pdeny));
  j_set(d, "pool", poolj);

  json_t *aj = j_obj();
  j_set_str(aj, "active", approval_active_id());
  j_set_str(aj, "mode", approval_mode_text());
  j_set_bool(aj, "allowAll", approval_is_allow_all());
  j_set(d, "approval", aj);

  json_t *rj = j_obj();
  j_set_str(rj, "source", rules_source());
  j_set_bool(rj, "fromFile", rules_from_file());
  json_t *doms = j_arr();
  for (int i = 0; i < rules_domain_count(); i++) {
    const rules_domain_t *dd = rules_domain_at(i);
    if (!dd) continue;
    json_t *o = j_obj();
    j_set_str(o, "id", dd->id);
    j_set_str(o, "title", dd->title);
    j_add(doms, o);
  }
  j_set(rj, "domains", doms);
  j_set(d, "rules", rj);

  json_t *counts = j_obj();
  if (ctx && ctx->store) {
    store_t *s = (store_t *)ctx->store;
    j_set_num(counts, "findings", store_count(s, "findings"));
    j_set_num(counts, "runs", store_count(s, "runs"));
    j_set_num(counts, "assets", store_count(s, "assets"));
    j_set_num(counts, "alerts", store_count(s, "alerts"));
    j_set_num(counts, "automations", store_count(s, "automations"));
  }
  j_set(d, "counts", counts);

  j_set_num(d, "skills", skills_count());
  j_set_num(d, "tools", tools_count());
  out->data = d;

  buf_t t;
  buf_init(&t);
  buf_puts(&t, "网站安全巡检智能体 · 本机信息\n");
  buf_printf(&t, "  数据目录 : %s\n", app_data_dir());
  buf_printf(&t, "  当前模型 : %s(%d 家已配置,%d 家可用)\n",
             providers_display_name(), providers_count(), providers_ready_count());
  buf_printf(&t, "  授权池   : %d 个允许目标", j_len(pallow));
  for (int i = 0; i < j_len(pallow) && i < 12; i++) {
    json_t *v = j_at(pallow, i);
    if (v && v->str) buf_printf(&t, " %s", v->str);
  }
  if (j_len(pdeny) > 0) {
    buf_printf(&t, " · %d 条不允许", j_len(pdeny));
  }
  buf_puts(&t, "\n");
  buf_printf(&t, "  审批策略 : %s(%s)\n", approval_mode_text(), approval_active_id());
  buf_printf(&t, "  规则来源 : %s(%d 个域)\n", rules_source(), rules_domain_count());
  if (ctx && ctx->store) {
    store_t *s = (store_t *)ctx->store;
    buf_printf(&t, "  已落盘   : 发现 %d 条 · 运行 %d 次 · 资产 %d 个 · 告警 %d 条 · 周期规则 %d 条\n",
               store_count(s, "findings"), store_count(s, "runs"), store_count(s, "assets"),
               store_count(s, "alerts"), store_count(s, "automations"));
  }
  buf_printf(&t, "  能力     : 技能 %d 个 · 工具 %d 个\n", skills_count(), tools_count());
  buf_puts(&t, "\n这些是当前真实值;要改规则/周期/模型/审批用 settings_set(授权池只能由人在界面里加)。");
  out->text = buf_take(&t);
  out->say = xstrdup("我看了一下自己的状态,见上面的信息。");
  str_free_list(pool, pn);
  return 0;
}

/* ---- 0-C. 读设置 ---- */
static int t_settings_get(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  const char *section = j_s(args, "section", "all");
  const char *domain = j_s(args, "domain", "");
  const char *key = j_s(args, "key", "");
  if (!section[0]) section = "all";
  /* 只给了 domain/key 就说明问的是规则:别再把审批/模型一并倒出来 */
  if (str_ieq(section, "all") && (domain[0] || key[0])) section = "rules";
  int all = str_ieq(section, "all");

  json_t *d = j_obj();
  j_set_str(d, "section", section);
  buf_t t;
  buf_init(&t);

  if (all || str_ieq(section, "rules")) {
    if (!domain[0] && key[0]) {
      /* 只问一个键:从"当前生效"的整份规则里取,路径可以是 a.b.c。
         用户问"超时现在是多少""告警门槛是哪一档"最常走这条。 */
      json_t *v = j_path(rules_root(), key);
      if (!v) {
        json_free(d);
        buf_free(&t);
        buf_t m;
        buf_init(&m);
        buf_printf(&m, "规则里没有 %s 这个键(可以先用 section=rules 看各域的键名)", key);
        return settings_fail(out, &m);
      }
      const rules_domain_t *owner = rules_domain_of_key(key);
      if (!owner) {
        char top[128];
        if (top_key_of(key, top, sizeof(top))) owner = rules_domain_of_key(top);
      }
      j_set_str(d, "key", key);
      if (owner) j_set_str(d, "domain", owner->id);
      char *dump = json_dump(v);
      json_t *copy = dump ? json_parse(dump) : NULL;
      free(dump);
      if (copy) j_set(d, "value", copy);
      buf_printf(&t, "规则 %s = ", key);
      value_text(&t, v);
      if (owner) buf_printf(&t, "  (属于 %s 域:%s)", owner->id, owner->title);
      buf_puts(&t, "\n");
    } else if (domain[0]) {
      char err[512] = {0};
      json_t *dom = rules_domains_read(domain, err, sizeof(err));
      if (!dom) {
        json_free(d);
        buf_t m;
        buf_init(&m);
        buf_printf(&m, "读不到规则域 %s:%s", domain, err[0] ? err : "未知原因");
        buf_free(&t);
        return settings_fail(out, &m);
      }
      if (key[0]) {
        /* 单键:从"当前生效"的整份规则里取,路径可以是 a.b.c */
        json_t *v = j_path(rules_root(), key);
        if (!v && dom) v = j_path(dom, key);
        if (!v) {
          json_free(dom);
          json_free(d);
          buf_t m;
          buf_init(&m);
          buf_printf(&m, "规则里没有 %s 这个键", key);
          buf_free(&t);
          return settings_fail(out, &m);
        }
        j_set_str(d, "key", key);
        char *dump = json_dump(v);
        json_t *copy = dump ? json_parse(dump) : NULL;
        free(dump);
        if (copy) j_set(d, "value", copy);
        buf_printf(&t, "规则 %s = ", key);
        value_text(&t, v);
        buf_puts(&t, "\n");
        json_free(dom);
      } else {
        const rules_domain_t *dd = rules_domain_find(domain);
        j_set_str(d, "domain", domain);
        j_set_str(d, "title", dd ? dd->title : domain);
        j_set(d, "rules", dom);
        char *pretty = json_dump_pretty(dom);
        buf_printf(&t, "规则域 %s(%s):\n%s\n", domain, dd ? dd->title : "",
                   pretty ? pretty : "{}");
        free(pretty);
      }
    } else {
      json_t *list = j_arr();
      buf_puts(&t, "规则域:");
      for (int i = 0; i < rules_domain_count(); i++) {
        const rules_domain_t *dd = rules_domain_at(i);
        if (!dd) continue;
        json_t *o = j_obj();
        j_set_str(o, "id", dd->id);
        j_set_str(o, "title", dd->title);
        j_set_str(o, "file", dd->file);
        j_set_str(o, "note", dd->note);
        j_add(list, o);
        buf_printf(&t, " %s(%s)", dd->id, dd->title);
      }
      buf_puts(&t, "\n");
      j_set(d, "domains", list);
      j_set_str(d, "source", rules_source());
    }
  }

  if (all || str_ieq(section, "approval")) {
    json_t *list = approval_list_json();
    buf_puts(&t, "审批策略(★ 为当前生效):\n");
    for (int i = 0; i < j_len(list); i++) {
      json_t *p = j_at(list, i);
      const char *id = j_s(p, "id", "");
      buf_printf(&t, "  %s %s  方式 %s%s%s\n", str_ieq(id, approval_active_id()) ? "★" : "-",
                 j_s(p, "name", id), j_s(p, "mode", ""),
                 j_s(p, "note", "")[0] ? "  · " : "", j_s(p, "note", ""));
    }
    j_set(d, "approval", list);
  }

  if (all || str_ieq(section, "models")) {
    json_t *list = j_arr();
    buf_puts(&t, "模型通道(★ 为当前使用):\n");
    for (int i = 0; i < providers_count(); i++) {
      provider_t *p = provider_at(i);
      if (!p) continue;
      json_t *o = j_obj();
      j_set_str(o, "id", p->id);
      j_set_str(o, "name", p->name);
      j_set_str(o, "kind", provider_kind_name(p->kind));
      j_set_bool(o, "ready", provider_ready(p));
      j_set_bool(o, "enabled", p->enabled);
      j_add(list, o);
      buf_printf(&t, "  %s %s(%s)%s\n", str_ieq(p->id, providers_active_id()) ? "★" : "-",
                 p->name, provider_kind_name(p->kind),
                 provider_ready(p) ? "" : "  · 未就绪");
    }
    j_set(d, "models", list);
  }

  if (all || str_ieq(section, "automation")) {
    store_t *s = (ctx && ctx->store) ? (store_t *)ctx->store : NULL;
    auto_rule_t *rules = NULL;
    int n = 0;
    if (s) auto_list(s, &rules, &n);
    json_t *list = j_arr();
    if (n == 0) {
      buf_puts(&t, "周期巡检:还没有规则\n");
    } else {
      buf_printf(&t, "周期巡检(%d 条):\n", n);
      for (int i = 0; i < n; i++) {
        json_t *o = auto_to_json(&rules[i]);
        j_add(list, o);
        char cyc[64];
        auto_cycle_text(&rules[i], cyc, sizeof(cyc));
        buf_printf(&t, "  - %s  %s  %s  %s%s\n", rules[i].id, rules[i].domain, cyc,
                   auto_scope_label(rules[i].scope), rules[i].enabled ? "" : "(已停用)");
      }
    }
    auto_free_list(rules);
    j_set(d, "automation", list);
  }

  if (all || str_ieq(section, "profile")) {
    json_t *o = j_obj();
    j_set_bool(o, "active", profile_is_active());
    j_set_str(o, "id", profile_active_id());
    j_set_str(o, "name", profile_active_name());
    j_set(d, "profile", o);
    buf_printf(&t, "敏感信息定义: %s\n",
               profile_is_active() ? profile_active_name() : "出厂口径(没有启用自定义定义)");
  }

  out->data = d;
  out->text = buf_take(&t);
  out->say = xstrdup("这些是当前设置。");
  return 0;
}

/* ---- 0-D. 改设置 ----
   写入的边界(三条,都是为了不让模型给自己扩权):
     ① 授权池只读 —— 往池里加站必须由人在界面上确认授权;
     ② 审批只能换成更严的 —— "全部允许"必须由人点;
     ③ 周期规则的目标必须在授权池内 —— 否则模型能凭空加一个站去周期性地查。
   其余的(检测口径、周期、当前模型)可以改,但每次都写审计。 */
static int t_settings_set(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  const char *section = j_s(args, "section", "");
  if (!section[0]) {
    buf_t m;
    buf_init(&m);
    buf_puts(&m, "需要 section:rules / automation / models / approval 之一。");
    return settings_fail(out, &m);
  }

  /* ---------- 规则:按域保存并立即重载 ---------- */
  if (str_ieq(section, "rules")) {
    const char *domain = j_s(args, "domain", "");
    if (!domain[0]) {
      buf_t m;
      buf_init(&m);
      buf_puts(&m, "section=rules 需要 domain。可用的域:");
      for (int i = 0; i < rules_domain_count(); i++) {
        const rules_domain_t *dd = rules_domain_at(i);
        if (dd) buf_printf(&m, " %s", dd->id);
      }
      return settings_fail(out, &m);
    }
    const rules_domain_t *dd = rules_domain_find(domain);
    if (!dd) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "没有 %s 这个域。可用的域:", domain);
      for (int i = 0; i < rules_domain_count(); i++) {
        const rules_domain_t *x = rules_domain_at(i);
        if (x) buf_printf(&m, " %s", x->id);
      }
      return settings_fail(out, &m);
    }

    json_t *patch = obj_arg(args, "patch");
    if (!patch) {
      const char *k = j_s(args, "key", "");
      if (!k[0]) {
        buf_t m;
        buf_init(&m);
        buf_puts(&m, "section=rules 需要 patch(这一域要改的字段),或者 key + value。");
        return settings_fail(out, &m);
      }
      json_t *v = value_arg(args, "value");
      if (!v) {
        buf_t m;
        buf_init(&m);
        buf_printf(&m, "改 %s 需要给 value。", k);
        return settings_fail(out, &m);
      }
      char top[128];
      if (!top_key_of(k, top, sizeof(top))) {
        json_free(v);
        buf_t m;
        buf_init(&m);
        buf_printf(&m, "键名不合法:%s", k);
        return settings_fail(out, &m);
      }
      const char *dot = strchr(k, '.');
      if (dot) {
        /* 嵌套键:在"现有内容"上打点,再整键提交 */
        char err[512] = {0};
        json_t *dom = rules_domains_read(domain, err, sizeof(err));
        if (!dom) {
          json_free(v);
          buf_t m;
          buf_init(&m);
          buf_printf(&m, "读不到规则域 %s:%s", domain, err[0] ? err : "未知原因");
          return settings_fail(out, &m);
        }
        json_t *cur = j_get(dom, top);
        if (!cur || cur->type != J_OBJ) {
          cur = j_obj();
          j_set(dom, top, cur);
        }
        if (!deep_set(cur, dot + 1, v)) {
          json_free(dom);
          buf_t m;
          buf_init(&m);
          buf_printf(&m, "键名不合法:%s", k);
          return settings_fail(out, &m);
        }
        patch = j_obj();
        char *d = json_dump(cur);
        json_t *cp = d ? json_parse(d) : NULL;
        free(d);
        if (cp) j_set(patch, top, cp);
        json_free(dom);
      } else {
        patch = j_obj();
        j_set(patch, k, v);
      }
    }
    if (patch->type != J_OBJ) {
      json_free(patch);
      buf_t m;
      buf_init(&m);
      buf_puts(&m, "patch 要是一个对象,例如 {\"timeout_ms\":15000}。");
      return settings_fail(out, &m);
    }

    /* 只报"这一域认的键",别的键 save 会忽略 —— 提前告诉模型,免得白改 */
    char changed[512] = {0};
    {
      buf_t keys;
      buf_init(&keys);
      join_keys(&keys, patch);
      snprintf(changed, sizeof(changed), "%s", keys.data ? keys.data : "");
      buf_free(&keys);
    }
    char err[512] = {0};
    int rc = rules_domains_save(domain, patch, err, sizeof(err));
    json_free(patch);
    if (rc != 0) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "保存规则域 %s 失败:%s", domain, err[0] ? err : "未知原因");
      return settings_fail(out, &m);
    }
    /* 保存即生效:和界面里点保存走的是同一条路(不重启) */
    rules_shutdown();
    rules_init(app_dir());
    settings_audit(ctx, "修改规则(智能体)", dd->title, changed[0] ? changed : "按域更新");

    json_t *d = j_obj();
    j_set_bool(d, "ok", 1);
    j_set_str(d, "domain", domain);
    j_set_str(d, "title", dd->title);
    j_set_str(d, "source", rules_source());
    out->data = d;
    buf_t t;
    buf_init(&t);
    buf_printf(&t, "已保存规则域 %s(%s)并立即生效。改动的键:%s\n规则来源现在是 %s。",
               domain, dd->title, changed[0] ? changed : "(未指定)", rules_source());
    out->text = buf_take(&t);
    out->say = xstrdup("规则已经按你说的改好并生效了。");
    return 0;
  }

  /* ---------- 周期巡检 ---------- */
  if (str_ieq(section, "automation")) {
    store_t *s = (ctx && ctx->store) ? (store_t *)ctx->store : NULL;
    if (!s) {
      buf_t m;
      buf_init(&m);
      buf_puts(&m, "当前没有存储句柄(命令行/自检环境不支持改周期规则)。");
      return settings_fail(out, &m);
    }
    const char *action = j_s(args, "action", "save");
    char id[24];
    snprintf(id, sizeof(id), "%s", j_s(args, "id", ""));

    if (str_ieq(action, "remove")) {
      if (!id[0]) {
        buf_t m;
        buf_init(&m);
        buf_puts(&m, "删除周期规则需要 id(先用 settings_get section=automation 查到)。");
        return settings_fail(out, &m);
      }
      if (auto_remove(s, id) != 0) {
        buf_t m;
        buf_init(&m);
        buf_printf(&m, "没有找到周期规则 %s", id);
        return settings_fail(out, &m);
      }
      settings_audit(ctx, "删除周期巡检(智能体)", id, "智能体调用 settings_set");
      json_t *d = j_obj();
      j_set_bool(d, "ok", 1);
      j_set_str(d, "removed", id);
      out->data = d;
      out->text = xstrdup("已删除这条周期巡检规则,后续不会再自动跑。");
      out->say = xstrdup("这条周期巡检已经删掉了。");
      return 0;
    }

    json_t *ro = obj_arg(args, "rule");
    if (!ro || ro->type != J_OBJ) {
      json_free(ro);
      buf_t m;
      buf_init(&m);
      buf_puts(&m, "action=save 需要 rule(对象),例如 "
                   "{\"domain\":\"exp.com\",\"scope\":\"full\",\"kind\":\"interval\",\"every_min\":360}。");
      return settings_fail(out, &m);
    }

    /* 改已有规则时只覆盖调用方给出的字段,别把 name/created_at 冲掉 */
    auto_rule_t old;
    memset(&old, 0, sizeof(old));
    int have_old = id[0] && auto_find(s, id, &old) == 0;
    json_t *merged = have_old ? auto_to_json(&old) : j_obj();
    for (int i = 0; i < ro->count; i++) {
      if (!ro->keys[i]) continue;
      char *dump = json_dump(ro->items[i]);
      json_t *cp = dump ? json_parse(dump) : NULL;
      free(dump);
      if (cp) j_set(merged, ro->keys[i], cp);
    }
    json_free(ro);
    if (id[0]) j_set_str(merged, "id", id);

    auto_rule_t r;
    auto_from_json(merged, &r);
    json_free(merged);

    const char *bad = auto_validate(&r);
    if (bad) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "周期规则不合法:%s", bad);
      return settings_fail(out, &m);
    }
    /* 授权边界:周期规则会自己发请求,目标必须是已经有授权的。
       措辞避开 "不在授权池内" —— 那句话是决策循环的硬停止信号。 */
    char host[256] = {0};
    int port = net_host_port_of(r.domain, host, sizeof(host));
    if (!host[0]) snprintf(host, sizeof(host), "%s", r.domain);
    if (!net_pool_has(host, port, "/")) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "目标 %s 还没有被授权,不能建周期规则。"
                     "请让用户在界面的授权池里确认这个主机,再由我来加周期。", r.domain);
      return settings_fail(out, &m);
    }
    int rc = auto_save(s, &r);
    if (rc != 0) {
      buf_t m;
      buf_init(&m);
      buf_puts(&m, "周期规则保存失败(存储写入出错)。");
      return settings_fail(out, &m);
    }
    settings_audit(ctx, have_old ? "修改周期巡检(智能体)" : "新建周期巡检(智能体)", r.domain,
                   r.id);
    char cyc[64];
    auto_cycle_text(&r, cyc, sizeof(cyc));

    json_t *d = auto_to_json(&r);
    out->data = d;
    buf_t t;
    buf_init(&t);
    buf_printf(&t, "%s周期巡检:%s %s %s(%s)。\n到点会自动跑一轮,并与上一轮比差异;有变化才告警。",
               have_old ? "已更新" : "已新建", r.id, r.domain, cyc,
               auto_scope_label(r.scope));
    out->text = buf_take(&t);
    out->say = xstrdup("周期巡检已经设好了。");
    return 0;
  }

  /* ---------- 当前模型 ---------- */
  if (str_ieq(section, "models")) {
    char id[80];
    snprintf(id, sizeof(id), "%s", j_s(args, "id", ""));
    if (!id[0]) {
      buf_t m;
      buf_init(&m);
      buf_puts(&m, "切换模型需要 id(先用 settings_get section=models 看有哪些)。");
      return settings_fail(out, &m);
    }
    provider_t *p = provider_find(id);
    if (!p) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "没有 id 为 %s 的模型通道。", id);
      return settings_fail(out, &m);
    }
    if (!provider_ready(p)) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "模型通道 %s 还没配好(缺地址/密钥,或已被停用),不能切过去。", p->name);
      return settings_fail(out, &m);
    }
    /* 和界面"切换"走同一条路:整份读出来、改 active、校验后落盘 */
    char *dump = providers_json(0);
    json_t *root = dump ? json_parse(dump) : NULL;
    free(dump);
    if (!root) root = j_obj();
    j_set_str(root, "active", id);
    char err[512] = {0};
    int rc = providers_apply(root, err, sizeof(err));
    json_free(root);
    if (rc != 0) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "切换失败:%s", err[0] ? err : "配置没有通过校验");
      return settings_fail(out, &m);
    }
    /* 换了通道要把上一家的失败冷却清掉,否则界面还显示"离线" */
    llm_reset_error();
    settings_audit(ctx, "切换模型通道(智能体)", p->name, id);

    json_t *d = j_obj();
    j_set_bool(d, "ok", 1);
    j_set_str(d, "active", id);
    j_set_str(d, "name", p->name);
    out->data = d;
    buf_t t;
    buf_init(&t);
    buf_printf(&t, "已切换到「%s」(%s)。下一轮决策就用它。", p->name, provider_kind_name(p->kind));
    out->text = buf_take(&t);
    out->say = xstrdup("模型通道已经切过去了。");
    return 0;
  }

  /* ---------- 审批策略:只允许收紧 ---------- */
  if (str_ieq(section, "approval")) {
    char id[32];
    snprintf(id, sizeof(id), "%s", j_s(args, "id", ""));
    if (!id[0]) {
      buf_t m;
      buf_init(&m);
      buf_puts(&m, "切换审批策略需要 id(先用 settings_get section=approval 看有哪些)。");
      return settings_fail(out, &m);
    }
    json_t *list = approval_list_json();
    int found = 0;
    char name[80] = {0}, mode[24] = {0};
    for (int i = 0; i < j_len(list); i++) {
      json_t *p = j_at(list, i);
      if (!str_ieq(j_s(p, "id", ""), id)) continue;
      found = 1;
      snprintf(name, sizeof(name), "%s", j_s(p, "name", id));
      snprintf(mode, sizeof(mode), "%s", j_s(p, "mode", ""));
      break;
    }
    json_free(list);
    if (!found) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "没有 id 为 %s 的审批策略。", id);
      return settings_fail(out, &m);
    }
    if (str_ieq(mode, "allow_all")) {
      buf_t m;
      buf_init(&m);
      buf_puts(&m, "「全部允许」会让我不再逐条问你,这属于放宽限制,必须由人在界面上确认,"
                   "我不替你做这个决定。要收紧的话可以切到更严的策略。");
      return settings_fail(out, &m);
    }
    if (!approval_activate(id)) {
      buf_t m;
      buf_init(&m);
      buf_printf(&m, "切换到审批策略 %s 失败。", id);
      return settings_fail(out, &m);
    }
    settings_audit(ctx, "切换审批策略(智能体)", name, id);

    json_t *d = j_obj();
    j_set_bool(d, "ok", 1);
    j_set_str(d, "active", id);
    j_set_str(d, "name", name);
    j_set_str(d, "mode", mode);
    out->data = d;
    buf_t t;
    buf_init(&t);
    buf_printf(&t, "审批策略已切成「%s」。之后每个动作都会按这条策略走。", name);
    out->text = buf_take(&t);
    out->say = xstrdup("审批策略已经切好了。");
    return 0;
  }

  /* ---------- 授权池:明确拒绝 ---------- */
  if (str_ieq(section, "pool")) {
    buf_t m;
    buf_init(&m);
    buf_puts(&m, "授权池不能由我改:往池里加一个站等于扩大检查范围,必须由人在界面上确认授权。"
                 "你可以在界面上加好之后告诉我,我再用 pool_list 读最新的清单。");
    return settings_fail(out, &m);
  }

  buf_t m;
  buf_init(&m);
  buf_printf(&m, "不认识的 section:%s。可用:rules / automation / models / approval。", section);
  return settings_fail(out, &m);
}

/* ---- 1. 文本敏感信息扫描 ---- */
/* 判定用的正则来自规则文件(patterns.sensitive),匹配交给 src\regex.c 的极简引擎:
   支持字面量、字符类、分组与分支、* + ? {n,m}、^ $、(?i) 与两种 [0-9] 断言,
   带完整回溯 —— 邮箱/私钥头这种"先贪婪后回退"的形状才能正确匹配。
   规则写超范围时,`agent.exe regextest` 会直接告诉你原因。 */

/* 脱敏:保留头尾,中间星号(报告可能外传,不能留明文) */
static void mask_into(buf_t *out, const char *s, int len) {
  if (len <= 4) { for (int i = 0; i < len; i++) buf_putc_(out, '*'); return; }
  buf_putn(out, s, 2);
  for (int i = 2; i < len - 2; i++) buf_putc_(out, '*');
  buf_putn(out, s + len - 2, 2);
}

/* 给"自己写规则"的人用:先拿一条正则试一下它到底匹配什么(见 agent.exe regextest)。
   规则是数据,数据写错了不该靠猜 —— 这个口子让自定义正则当场可验。 */
int tools_regex_first(const char *pattern, const char *text, int *off, int *len) {
  if (!pattern || !text) return 0;
  char err[128];
  return rx_find(pattern, text, off, len, err, sizeof(err));
}

static int scan_text_into(tool_ctx_t *ctx, const char *text, json_t *hits) {
  int count = 0;
  int rules_n = rules_arr_count("patterns.sensitive");
  for (int r = 0; r < rules_n; r++) {
    const char *kind = rules_arr_str("patterns.sensitive", r, "kind", "");
    const char *pattern = rules_arr_str("patterns.sensitive", r, "pattern", "");
    const char *severity = rules_arr_str("patterns.sensitive", r, "severity", "中");
    if (!pattern[0]) continue;                     /* 规则里没写正则就跳过 */
    char rerr[128] = {0};
    rx_pattern *re = rx_compile(pattern, rerr, sizeof(rerr));
    if (!re) {
      /* 规则写错了要如实说,而不是"当成没命中" —— 否则使用者会以为站点干净 */
      log_warn("[规则] 敏感信息正则不合法,已跳过: %s(%s)", pattern, rerr);
      continue;
    }
    const char *scan = text;
    int searched = 0;
    while (searched < 200) {
      int off = 0, len = 0;
      if (!rx_search(re, scan, &off, &len)) break;
      buf_t masked;
      buf_init(&masked);
      mask_into(&masked, scan + off, len);
      json_t *h = j_obj();
      j_set_str(h, "kind", kind[0] ? kind : pattern);
      j_set_str(h, "severity", severity);
      j_set_str(h, "masked", masked.data);
      j_set_str(h, "rule", pattern);
      j_add(hits, h);
      buf_free(&masked);
      count++;
      scan += off + len;
      searched++;
      if (off + len <= 0) break;
    }
    rx_free(re);
  }
  if (rules_n == 0) {
    log_warn("[规则] patterns.sensitive 为空:敏感信息扫描没有可用规则");
  }

  /* 出厂规则之外,再按"本单位定义"扫一遍。
     两套口径是叠加的:出厂规则负责通用泄露形态(证件号/私钥/凭据),
     本单位定义负责只有这家才有的关键词、样例与正则。 */
  {
    char kind[64], sev[16], masked[160];
    if (profile_scan_text(text, kind, sizeof(kind), sev, sizeof(sev), masked, sizeof(masked))) {
      json_t *h = j_obj();
      j_set_str(h, "kind", kind);
      j_set_str(h, "severity", sev);
      j_set_str(h, "masked", masked);
      j_set_str(h, "rule", "本单位敏感信息定义");
      j_add(hits, h);
      count++;
    }
  }

  (void)ctx;
  return count;
}

static int t_sensitive_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  const char *text = j_s(args, "text", "");
  json_t *hits = j_arr();
  int n = scan_text_into(ctx, text, hits);
  json_t *data = j_obj();
  j_set(hits, "hits", hits);
  j_set_num(data, "hit_count", n);
  out->data = data;

  buf_t t;
  buf_init(&t);
  if (n == 0) {
    buf_puts(&t, "未发现敏感信息");
    out->say = xstrdup("这段文本里没发现敏感信息。");
  } else {
    buf_printf(&t, "命中 %d 处敏感信息:\n", n);
    for (int i = 0; i < j_len(hits) && i < 20; i++) {
      json_t *h = j_at(hits, i);
      buf_printf(&t, "- [%s] %s: %s\n", j_s(h, "severity", ""), j_s(h, "kind", ""),
                 j_s(h, "masked", ""));
    }
    buf_t s;
    buf_init(&s);
    buf_printf(&s, "发现 %d 处敏感信息,已在结果卡片中列出(展示时已去敏),建议核实来源后处理。", n);
    out->say = buf_take(&s);
  }
  out->text = buf_take(&t);
  return 0;
}

/* ---- 2. 口令强度 ---- */
/* 弱口令表来自规则文件(weak_passwords)。表里没有就只按强度规则算分——
   这不是"少了功能",而是"口径跟着规则走":不同单位可以放自己的历史泄露口令表。 */
static int t_password_check(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  (void)ctx;
  const char *pw = j_s(args, "password", "");
  int score = 100;
  json_t *issues = j_arr();
  int weak_n = 0;
  const char **weak = rules_str_list("weak_passwords", &weak_n);
  for (int i = 0; i < weak_n; i++) {
    if (str_ieq(pw, weak[i])) {
      j_add(issues, j_str("命中常见弱口令表"));
      score -= 60;
      break;
    }
  }
  size_t len = strlen(pw);
  if (len < 8) { j_add(issues, j_str("长度不足 8 位")); score -= 20; }
  else if (len < 12) { j_add(issues, j_str("建议加长到 12 位以上")); score -= 8; }
  int has_upper = 0, has_lower = 0, has_digit = 0, has_sym = 0;
  for (const char *p = pw; *p; p++) {
    if (isupper((unsigned char)*p)) has_upper = 1;
    else if (islower((unsigned char)*p)) has_lower = 1;
    else if (isdigit((unsigned char)*p)) has_digit = 1;
    else has_sym = 1;
  }
  if (!has_upper) { j_add(issues, j_str("缺大写字母")); score -= 8; }
  if (!has_lower) { j_add(issues, j_str("缺小写字母")); score -= 8; }
  if (!has_digit) { j_add(issues, j_str("缺数字")); score -= 8; }
  if (!has_sym) { j_add(issues, j_str("缺符号")); score -= 8; }
  if (score < 0) score = 0;
  const char *level = score < 50 ? "弱" : (score < 80 ? "中" : "强");

  json_t *data = j_obj();
  j_set_num(data, "score", score);
  j_set_str(data, "level", level);
  j_set(data, "issues", issues);
  out->data = data;

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "等级: %s(%d/100)\n", level, score);
  for (int i = 0; i < j_len(issues); i++) {
    buf_printf(&t, "- %s\n", j_at(issues, i)->str);
  }
  out->text = buf_take(&t);
  buf_t s;
  buf_init(&s);
  buf_printf(&s, "口令评估结果:【%s】(%d/100 分),发现 %d 个问题,详见结果卡片。",
             level, score, j_len(issues));
  out->say = buf_take(&s);
  return 0;
}

/* ---- 3. 资产发现 ---- */
static int looks_like_html(const char *ct) {
  return !ct || !*ct || str_icontains(ct, "html") || str_icontains(ct, "text/plain");
}

/* 从 HTML 里抠链接:只认我们关心的几类属性 */
static void extract_links(const char *html, json_t *out) {
  static const char *attrs[] = {"href=\"", "src=\"", "action=\""};
  for (size_t a = 0; a < sizeof(attrs) / sizeof(attrs[0]); a++) {
    const char *p = html;
    while ((p = strstr(p, attrs[a])) != NULL) {
      p += strlen(attrs[a]);
      const char *end = strchr(p, '"');
      if (!end) break;
      size_t n = (size_t)(end - p);
      if (n > 0 && n < 1024) {
        char *link = xstrndup(p, n);
        if (!str_startswith(link, "javascript:") && !str_startswith(link, "mailto:") &&
            !str_startswith(link, "tel:") && !str_startswith(link, "#") &&
            !str_startswith(link, "data:")) {
          j_add(out, j_str(link));
        }
        free(link);
      }
      p = end;
    }
  }
}

static const char *classify_kind(const char *url) {
  const char *path = strstr(url, "://");
  path = path ? strchr(path + 3, '/') : url;
  if (!path) return "页面";
  const char *dot = strrchr(path, '.');
  const char *q = strchr(path, '?');
  if (q && (!dot || q < dot)) return "接口";
  if (!dot) return str_endswith(path, "/") ? "页面" : "其他";
  if (str_icontains(dot, ".css") || str_icontains(dot, ".js") || str_icontains(dot, ".png") ||
      str_icontains(dot, ".jpg") || str_icontains(dot, ".gif") || str_icontains(dot, ".svg") ||
      str_icontains(dot, ".ico") || str_icontains(dot, ".woff") || str_icontains(dot, ".map")) {
    return "静态资源";
  }
  if (str_icontains(path, "/api/") || str_icontains(path, "/ajax/")) return "接口";
  return "页面";
}

/* ---- URL 处理:爬虫要会跟相对链接,而且要守住"本次巡检范围"这个子路径 ---- */

/* 取 URL 的路径+查询(到主机名之后为止) */
static void url_path_query(const char *url, char *out, size_t cap) {
  const char *p = strstr(url, "://");
  p = p ? strchr(p + 3, '/') : strchr(url, '/');
  snprintf(out, cap, "%s", p && p[0] ? p : "/");
}

/* 取"协议://主机[:端口]" */
static void url_origin(const char *url, char *out, size_t cap) {
  const char *scheme = strstr(url, "://");
  const char *hoststart = scheme ? scheme + 3 : url;
  size_t n = (size_t)(hoststart - url) + strcspn(hoststart, "/?#");
  if (n >= cap) n = cap - 1;
  memcpy(out, url, n);
  out[n] = 0;
}

/* 归一化路径:折叠 ./ ../ 与重复的 /(不处理查询串) */
static void path_normalize(const char *in, char *out, size_t cap) {
  char tmp[2048];
  snprintf(tmp, sizeof(tmp), "%s", in && in[0] ? in : "/");
  char *q = strpbrk(tmp, "?#");
  if (q) *q = 0;
  int want_dir = tmp[0] && tmp[strlen(tmp) - 1] == '/';
  const char *seg[128];
  int n = 0;
  for (char *s = tmp; *s;) {
    while (*s == '/') s++;
    if (!*s) break;
    char *e = s + strcspn(s, "/");
    char save = *e;
    *e = 0;
    if (strcmp(s, ".") == 0) {
      /* 当前目录,丢掉 */
    } else if (strcmp(s, "..") == 0) {
      if (n > 0) n--;
    } else if (n < 128) {
      seg[n++] = s;
    }
    if (!save) break;
    s = e + 1;
  }
  buf_t b;
  buf_init(&b);
  for (int i = 0; i < n; i++) {
    buf_putc_(&b, '/');
    buf_puts(&b, seg[i]);
  }
  if (n == 0) buf_putc_(&b, '/');
  else if (want_dir) buf_putc_(&b, '/');
  snprintf(out, cap, "%s", b.data ? b.data : "/");
  buf_free(&b);
}

/* 把链接解析成绝对 URL(按 base_url 所在目录)。解析不了就返回空串。 */
static void url_resolve(const char *base_url, const char *link, char *out, size_t cap) {
  out[0] = 0;
  if (!link || !*link) return;
  char origin[512];
  url_origin(base_url, origin, sizeof(origin));
  if (str_startswith(link, "http://") || str_startswith(link, "https://")) {
    snprintf(out, cap, "%s", link);
    return;
  }
  if (str_startswith(link, "//")) {
    const char *scheme_end = strstr(base_url, "://");
    snprintf(out, cap, "%.*s%s", (int)(scheme_end ? scheme_end - base_url : 0), base_url, link);
    return;
  }
  if (link[0] == '#') {                      /* 纯锚点:同一页,不必再取一遍 */
    return;
  }
  if (link[0] == '?') {
    char bq[2048];
    url_path_query(base_url, bq, sizeof(bq));
    char *q = strpbrk(bq, "?#");
    if (q) *q = 0;
    snprintf(out, cap, "%s%s%s", origin, bq, link);
    return;
  }
  char base_path[2048];
  url_path_query(base_url, base_path, sizeof(base_path));
  char *q = strpbrk(base_path, "?#");
  if (q) *q = 0;
  char joined[2048];
  if (link[0] == '/') {
    snprintf(joined, sizeof(joined), "%s", link);
  } else {
    /* 相对链接的基准是"当前页面的目录":/l1/index.html + news.html = /l1/news.html */
    char *slash = strrchr(base_path, '/');
    size_t dlen = slash ? (size_t)(slash - base_path) + 1 : 1;
    if (dlen >= sizeof(joined)) dlen = sizeof(joined) - 1;
    memcpy(joined, base_path, dlen);
    joined[dlen] = 0;
    snprintf(joined + dlen, sizeof(joined) - dlen, "%s", link);
  }
  char norm[2048];
  path_normalize(joined, norm, sizeof(norm));
  snprintf(out, cap, "%s%s", origin, norm);
}

/* 目标路径是否落在本次巡检范围内(按"段"比较,/l1 不误伤 /l10) */
static int path_in_scope(const char *path, const char *scope) {
  if (!scope || !scope[0] || strcmp(scope, "/") == 0) return 1;
  size_t pl = strlen(scope), ql = path ? strlen(path) : 0;
  if (ql < pl) return 0;
  if (strncmp(path, scope, pl) != 0) return 0;
  if (scope[pl - 1] == '/') return 1;
  return path[pl] == 0 || path[pl] == '/' || path[pl] == '?';
}

static int t_site_crawl(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
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
  int fetched = 0;
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
  out->data = data;

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "起始:%s\n实际访问 %d 个地址,共记录 %d 个资产(页面 %d、资源/接口 %d)\n",
             target, fetched, j_len(assets), pages, res);
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
  }
  out->say = buf_take(&s);
  return seed_ok ? 0 : -1;
}

/* ================= 通用探测基础设施 =================
   下面这层是所有"探测类"工具共用的手法。刻意不含任何具体站点的知识:
   判断依据全部来自"这次取回来的内容",而不是"我记得这个站有什么"。 */

/* 一次取数(带响应头;拿不到头也照样返回内容,只是不做头相关的判断) */
typedef struct {
  int status;
  char *headers;
  char *body;
  char *err;
} fetch_t;

static void t_fetch_m(tool_ctx_t *ctx, const char *url, const char *method, fetch_t *f) {
  memset(f, 0, sizeof(*f));
  if (ctx->io.fetch_ex) {
    ctx->io.fetch_ex(ctx->io.userdata, url, method, &f->status, &f->headers,
                     &f->body, NULL, &f->err);
  } else if (ctx->io.fetch) {
    ctx->io.fetch(ctx->io.userdata, url, method, &f->status, &f->body, NULL, &f->err);
  } else {
    f->err = xstrdup("取数通道未就绪");
  }
  ctx->http_calls++;
}

static void t_fetch(tool_ctx_t *ctx, const char *url, fetch_t *f) {
  t_fetch_m(ctx, url, "GET", f);
}

static void fetch_free2(fetch_t *f) {
  free(f->headers);
  free(f->body);
  free(f->err);
  f->headers = f->body = f->err = NULL;
}

/* 站点根(协议 + 主机 + 端口):路径探测必须以它为基准。
   注意:模型可能只给"example.com"这种写法,所以先补协议再取根 —— 直接拿裸域名去
   请求会得到一个不明不白的失败,那不是站点的问题,是我们没把地址准备好。 */
/* 探测根:协议+主机+端口,再加"目标里给出的子路径"。
   子路径不能丢 —— 靶场每关挂在 /l1 … /l6 下,丢了路径就变成从首页开始探测,
   既不属于授权范围,也检不到关卡里的东西。 */
static void probe_root(const char *url, char *out, size_t cap) {
  const char *p = url ? url : "";
  const char *scheme = strstr(p, "://");
  const char *hoststart = scheme ? scheme + 3 : p;
  const char *end = hoststart + strcspn(hoststart, "/?#");
  size_t path_len = 0;
  if (*end == '/') {
    while (end[path_len] && end[path_len] != '?' && end[path_len] != '#') path_len++;
    while (path_len > 0 && end[path_len - 1] == '/') path_len--;
  }
  if (!scheme) {
    int n = snprintf(out, cap, "https://%.*s%.*s", (int)(end - p), p, (int)path_len, end);
    if (n < 0) out[0] = 0;
    return;
  }
  size_t n = (size_t)(end - p) + path_len;
  if (n >= cap) n = cap - 1;
  memcpy(out, p, n);
  out[n] = 0;
}

/* 工具入口的统一归一:没有协议就补 https(只补,不改用户明确写的协议) */
static void normalize_target(const char *in, char *out, size_t cap) {
  const char *s = in ? in : "";
  while (*s == ' ' || *s == '"') s++;
  if (strstr(s, "://")) snprintf(out, cap, "%s", s);
  else snprintf(out, cap, "https://%s", s);
  char *e = out + strlen(out);
  while (e > out && (e[-1] == ' ' || e[-1] == '"')) *--e = 0;
}

static void join_path(char *out, size_t cap, const char *root, const char *path) {
  size_t n = strlen(root);
  while (n > 0 && root[n - 1] == '/') n--;
  if (path && path[0] == '/') snprintf(out, cap, "%.*s%s", (int)n, root, path);
  else snprintf(out, cap, "%.*s/%s", (int)n, root, path ? path : "");
}

/* ---- 软 404 校准:先看清"这个站没有这个文件时长什么样" ----
   这是所有路径探测的前提。很多站点对不存在的路径返回 200 + 自定义错误页,
   不先校准就会把一片"首页/错误页"当成"一堆敏感文件"。 */
typedef struct {
  int valid;
  int status;
  size_t bytes;
  buf_t shape;          /* 抹平数字后的正文骨架 */
  char sample[256];     /* 校准用的那个路径(写进报告,可复核) */
} calib_t;

static void calib_free(calib_t *c) { buf_free(&c->shape); }

static void calib_run(tool_ctx_t *ctx, const char *root, calib_t *c) {
  memset(c, 0, sizeof(*c));
  buf_init(&c->shape);
  char url[1024];
  long long rnd = now_ms() % 99991;
  snprintf(c->sample, sizeof(c->sample), "/%s_%lld_%s", "no-such-path", rnd, "zz");
  join_path(url, sizeof(url), root, c->sample);
  fetch_t f;
  t_fetch(ctx, url, &f);
  if (f.err && !f.status) {          /* 连校准都做不了:那就明说"校准失败" */
    c->valid = 0;
    fetch_free2(&f);
    return;
  }
  c->valid = 1;
  c->status = f.status;
  c->bytes = f.body ? strlen(f.body) : 0;
  web_shape(&c->shape, f.body ? f.body : "");
  fetch_free2(&f);
}

/* 这个响应是不是"站点的默认页"(而非真的取到了目标文件) */
static int calib_matches(const calib_t *c, int status, const char *body) {
  if (!c->valid) return 0;
  if (status != c->status) return 0;
  size_t bytes = body ? strlen(body) : 0;
  double diff = (double)bytes > (double)c->bytes ? (double)bytes - (double)c->bytes
                                                : (double)c->bytes - (double)bytes;
  double ratio = c->bytes > 0 ? diff / (double)c->bytes : (bytes ? 1.0 : 0.0);
  if (diff > 64 && ratio > 0.06) return 0;
  buf_t sh;
  buf_init(&sh);
  web_shape(&sh, body ? body : "");
  int same = strcmp(sh.data ? sh.data : "", c->shape.data ? c->shape.data : "") == 0;
  buf_free(&sh);
  return same;
}

/* 外链分析:把页面上的外域主机、可疑落点分开列出来 */
static void link_analysis(const char *body, const char *own_host, json_t *hosts,
                          json_t *suspicious) {
  json_t *links = j_arr();
  web_extract_links(body, links);
  int tld_n = 0;
  const char **tlds = rules_str_list("suspicious_tlds", &tld_n);
  for (int i = 0; i < j_len(links); i++) {
    json_t *l = j_at(links, i);
    if (!l || l->type != J_STR) continue;
    const char *u = l->str;
    if (!str_startswith(u, "http://") && !str_startswith(u, "https://") &&
        !str_startswith(u, "//")) {
      continue;                                  /* 站内相对链接不参与判断 */
    }
    char host[256];
    web_url_parts(str_startswith(u, "//") ? "" : u, host, sizeof(host), NULL, 0);
    if (!host[0] || str_ieq(host, own_host)) continue;
    int dup = 0;
    for (int k = 0; k < j_len(hosts); k++) {
      if (str_ieq(j_at(hosts, k)->str, host)) { dup = 1; break; }
    }
    if (!dup) j_add(hosts, j_str(host));

    int bad = 0;
    for (int t = 0; t < tld_n; t++) {
      size_t lh = strlen(host), lt = strlen(tlds[t]);
      if (lh > lt && str_ieq(host + (lh - lt), tlds[t])) { bad = 1; break; }
    }
    int digits = 0, dots = 0;
    for (const char *c = host; *c; c++) {
      if (*c >= '0' && *c <= '9') digits++;
      else if (*c == '.') dots++;
    }
    if (dots == 3 && digits >= 4) bad = 1;       /* 裸 IP 当落地页 */
    if (bad) {
      int seen = 0;
      for (int k = 0; k < j_len(suspicious); k++) {
        if (str_icontains(j_at(suspicious, k)->str, host)) { seen = 1; break; }
      }
      if (!seen) j_add(suspicious, j_str(u));
    }
  }
  json_free(links);
}

/* 结果里必须写清"用的是哪套定义",否则结论无法复核 */
static void put_rules_note(json_t *data) {
  j_set_str(data, "rules_source", rules_source());
  j_set_bool(data, "rules_from_file", rules_from_file());
}

/* ---- 4. 敏感文件探测(内容特征判定 + 软 404 校准) ---- */
static int t_sensitive_file_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
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
    fetch_t f;
    t_fetch(ctx, url, &f);
    tested++;
    if (f.err && !f.status) {
      /* 被授权池拦下 ≠ 站点连不上:前者是合规闸门生效,必须如实区分 */
      if (strstr(f.err, "授权")) out_of_scope++;
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
  for (int i = 0; i < j_len(hits); i++) {
    buf_printf(&t, "\n- [%s] %s → %s(证据:%s)", j_s(j_at(hits, i), "severity", ""),
               j_s(j_at(hits, i), "path", ""), j_s(j_at(hits, i), "signature", ""),
               j_s(j_at(hits, i), "evidence", ""));
  }
  out->text = buf_take(&t);

  buf_t s;
  buf_init(&s);
  if (tested > 0 && out_of_scope == tested) {
    buf_printf(&s, "%s 不在授权池内:%d 个请求全部被合规通道拦下(一个包都没发出去)。"
                   "这不是站点故障,也不产生任何结论 —— 要查它,先把主机加进授权池。",
               root, tested);
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

/* ---- 5. 目录探测(目录索引识别 + 入口识别 + 软 404 校准) ---- */
static int t_dir_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
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

/* ---- 6. 内容基线比对(首次建基线,之后比差异) ---- */
static int t_page_diff(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
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
      j_set(b, "external_hosts", json_parse(json_dump(hosts)));
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
      j_set(df, "new_external_hosts", json_parse(json_dump(new_hosts)));
      j_set(df, "removed_external_hosts", json_parse(json_dump(gone_hosts)));
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
static int find_nuclei(char *out, size_t cap) {
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
static const char *nuclei_severity_cn(const char *in) {
  if (!in) return "低";
  if (str_ieq(in, "critical")) return "严重";
  if (str_ieq(in, "high")) return "高";
  if (str_ieq(in, "medium")) return "中";
  if (str_ieq(in, "low")) return "低";
  return "信息";
}

/* 跑 nuclei 并把命中并入 checks;返回命中条数。没装则返回 -1。 */
static int nuclei_merge(const char *target, json_t *checks, int *timed_out) {
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

static int t_nuclei_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
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
      j_set(c, "items", json_parse(json_dump(missing)));
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
      j_set(c, "items", json_parse(json_dump(cookie_issues)));
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
      j_set(c, "items", json_parse(json_dump(leaks)));
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
          j_set(c, "items", json_parse(json_dump(bads)));
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

/* ---- 8. 注入验证(布尔差分 + 错误特征;不取数据、不写数据) ---- */
static int t_sqli_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
  char target_buf[2048];
  normalize_target(j_s(args, "target", ""), target_buf, sizeof(target_buf));
  const char *target = target_buf;
  const char *want_param = j_s(args, "param", "");

  json_t *params = j_arr();
  web_url_params(target, params);
  if (want_param[0]) {
    /* 指定了参数但地址里没有 → 按"这个参数存在"处理(补上再测) */
    json_t *one = j_arr();
    j_add(one, j_str(want_param));
    json_free(params);
    params = one;
  }
  if (j_len(params) == 0) {
    json_t *d = j_obj();
    j_set_str(d, "target", target);
    j_set_str(d, "verdict", "not_testable");
    j_set_str(d, "reason", "地址里没有查询参数,没有可以验证的输入点");
    out->data = d;
    out->text = xstrdup("这个地址没有查询参数,注入验证没有输入点,本次未做");
    out->say = xstrdup("这个地址没有可测的参数(要带 ?参数=值 这样的地址),所以我没法做注入验证。");
    return 0;
  }

  /* 基线:原样请求一次,后面所有对比都以它为准 */
  fetch_t base;
  t_fetch(ctx, target, &base);
  if (base.err && !base.status) {
    json_t *d = j_obj();
    j_set_str(d, "target", target);
    j_set_str(d, "error", base.err ? base.err : "取不到内容");
    j_set_str(d, "verdict", "unreachable");
    out->data = d;
    out->is_error = 1;
    out->text = xstrdup("目标取不到内容,注入验证无法进行");
    out->say = xstrdup("目标连不上,我不给注入结论。");
    fetch_free2(&base);
    return -1;
  }
  buf_t base_shape;
  buf_init(&base_shape);
  web_shape(&base_shape, base.body ? base.body : "");
  size_t base_bytes = base.body ? strlen(base.body) : 0;

  int max_params = (int)rules_number("max_params", 3);
  if (max_params < 1) max_params = 3;

  json_t *tests = j_arr();
  int confirmed = 0, inconclusive = 0;
  char evidence[512] = {0};

  /* 布尔差分的载荷族来自规则文件(payloads.boolean_diff):
     不同数据库/框架的注释与引号规则不一样,单位可以自己加族,不用重编译。 */
  int fam_n = rules_arr_count("payloads.boolean_diff");

  for (int pi = 0; pi < j_len(params) && pi < max_params; pi++) {
    const char *param = j_at(params, pi)->str;
    for (int fam = 0; fam < fam_n; fam++) {
      const char *p_true = rules_arr_str("payloads.boolean_diff", fam, "true", "");
      const char *p_false = rules_arr_str("payloads.boolean_diff", fam, "false", "");
      const char *ctx_name = rules_arr_str("payloads.boolean_diff", fam, "context", "默认");
      if (!p_true[0] || !p_false[0]) continue;
      buf_t ut, uf;
      buf_init(&ut);
      buf_init(&uf);
      web_url_set_param(target, param, p_true, &ut);
      web_url_set_param(target, param, p_false, &uf);
      fetch_t ft, ff;
      t_fetch(ctx, ut.data, &ft);
      t_fetch(ctx, uf.data, &ff);

      int t_reach = !(ft.err && !ft.status);
      int f_reach = !(ff.err && !ff.status);
      int t_same = t_reach && web_same_shape(ft.body, base.body);
      int f_same = f_reach && web_same_shape(ff.body, base.body);
      int tf_same = t_reach && f_reach && web_same_shape(ft.body, ff.body);

      const char *verdict = "not_injectable";
      if (!t_reach || !f_reach) verdict = "inconclusive";
      else if (!t_same && !f_same && !tf_same) verdict = "inconclusive";
      else if (t_same && !f_same) verdict = "confirmed";

      json_t *rec = j_obj();
      j_set_str(rec, "param", param);
      j_set_str(rec, "context", ctx_name);
      j_set_str(rec, "payload_true", p_true);
      j_set_str(rec, "payload_false", p_false);
      j_set_str(rec, "verdict", verdict);
      j_set_num(rec, "status_true", ft.status);
      j_set_num(rec, "status_false", ff.status);
      j_set_num(rec, "bytes_true", ft.body ? (double)strlen(ft.body) : 0);
      j_set_num(rec, "bytes_false", ff.body ? (double)strlen(ff.body) : 0);
      j_set_bool(rec, "true_matches_baseline", t_same);
      j_set_bool(rec, "false_matches_baseline", f_same);
      j_add(tests, rec);

      if (strcmp(verdict, "confirmed") == 0) {
        confirmed++;
        if (!evidence[0]) {
          snprintf(evidence, sizeof(evidence),
                   "参数 %s 在恒真与恒假条件下响应不同(恒真 %d 字节与基线一致,恒假 %d 字节)",
                   param, (int)(ft.body ? strlen(ft.body) : 0),
                   (int)(ff.body ? strlen(ff.body) : 0));
        }
      } else if (strcmp(verdict, "inconclusive") == 0) {
        inconclusive++;
      }
      (void)base_bytes;
      fetch_free2(&ft);
      fetch_free2(&ff);
      buf_free(&ut);
      buf_free(&uf);
    }
  }

  /* 错误回显单独探一次:报错里带库信息是最可靠的证据 */
  char err_sig[128] = {0};
  {
    buf_t ue;
    buf_init(&ue);
    const char *p0 = j_len(params) > 0 ? j_at(params, 0)->str : "";
    web_url_set_param(target, p0, "1'", &ue);
    fetch_t fe;
    t_fetch(ctx, ue.data, &fe);
    if (!(fe.err && !fe.status) && fe.body) {
      int n = 0;
      const char **sigs = rules_str_list("error_signatures", &n);
      for (int i = 0; i < n; i++) {
        if (str_icontains(fe.body, sigs[i])) { snprintf(err_sig, sizeof(err_sig), "%s", sigs[i]); break; }
      }
    }
    fetch_free2(&fe);
    buf_free(&ue);
  }

  json_t *data = j_obj();
  j_set_str(data, "target", target);
  j_set_str(data, "method", "布尔差分 + 错误特征(只读,不取数据)");
  j_set(data, "tests", tests);
  j_set_num(data, "confirmed_tests", confirmed);
  j_set_num(data, "inconclusive_tests", inconclusive);
  j_set_str(data, "error_signature", err_sig);
  j_set_str(data, "verdict",
            err_sig[0] || confirmed ? "confirmed" : (inconclusive ? "inconclusive" : "not_found"));
  j_set_str(data, "evidence", err_sig[0] ? err_sig : evidence);
  j_set_num(data, "candidate_count", (err_sig[0] || confirmed) ? 1 : 0);
  put_rules_note(data);
  out->data = data;
  if (err_sig[0] || confirmed) {
    j_set_str(data, "kind", "漏洞");
    j_set_str(data, "severity", "严重");
    j_set_str(data, "param", j_len(params) > 0 ? j_at(params, 0)->str : "");
  }

  buf_t t;
  buf_init(&t);
  buf_printf(&t, "注入验证 %s:比对 %d 组恒真/恒假响应,确认 %d 组,无法判定 %d 组。",
             target, j_len(tests), confirmed, inconclusive);
  if (err_sig[0]) buf_printf(&t, "\n错误回显特征:%s", err_sig);
  for (int i = 0; i < j_len(tests); i++) {
    buf_printf(&t, "\n- %s [%s] %s → %s", j_s(j_at(tests, i), "param", ""),
               j_s(j_at(tests, i), "context", ""), j_s(j_at(tests, i), "payload_true", ""),
               j_s(j_at(tests, i), "verdict", ""));
  }
  out->text = buf_take(&t);

  buf_t s;
  buf_init(&s);
  if (err_sig[0]) {
    buf_printf(&s, "注入验证结果:确认存在注入 —— 服务端把数据库报错回显了出来(特征:%s)。"
                   "我没有取任何数据,只做了验证。", err_sig);
  } else if (confirmed) {
    buf_printf(&s, "注入验证结果:确认 %s 存在注入。恒真条件与正常响应一致、恒假条件明显不同,"
                   "这是布尔注入的典型特征。建议立即修复参数化查询。",
               j_len(params) > 0 ? j_at(params, 0)->str : "该参数");
  } else if (inconclusive) {
    buf_printf(&s, "注入验证结果没法下结论:%d 组响应波动(可能是页面含随机内容),"
                   "既不满足注入特征也不满足正常特征。我不硬报结论。", inconclusive);
  } else {
    buf_printf(&s, "注入验证完成:%d 组测试都没出现布尔差异,未发现注入迹象"
                   "(不代表绝对没有,只是当前手法没验证出来)。", j_len(tests));
  }
  out->say = buf_take(&s);
  buf_free(&base_shape);
  fetch_free2(&base);
  return 0;
}
