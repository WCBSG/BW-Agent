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
#include "tool_api.h"
#include "regex.h"
#include "profile.h"

#include "approval.h"
#include "automation.h"
#include "embed.h"
#include "ext.h"
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

#if defined(TOOL_ENTRY)
/* 工具进程编译时用 -DTOOL_ENTRY=<函数名>:
   这张表里只有它自己 —— 这个 exe 里没有别的工具,也就不会去链接别的实现。 */
static const prim_t g_prims[] = {
    {"self", TOOL_ENTRY},
};
#else
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
#endif

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

