/* tool_api.h —— 工具实现之间共享的东西。
 *
 * 每个工具一个 .cpp(本项目 src\tools\<名字>.cpp),它们之间只通过这里交换:
 *   · 每个工具的入口 t_<名字>(...),注册表按名字找到它;
 *   · 公共手法(取数、URL 归一、软 404 校准、敏感特征扫描),
 *     放在 tool_common.cpp —— 这些是"怎么取",不是"这个工具判什么"。
 *
 * 为什么把实现拆开:
 *   · 一个工具一个文件,Git 上改 A 不会和改 B 冲突;
 *   · 独立工具进程(src\tools\toolhost.cpp)只链接它自己那一个文件,
 *     于是"这个 exe 里到底有哪些能力"是可以从构建脚本一眼看出来的。
 */
#ifndef AGENT_TOOL_API_H
#define AGENT_TOOL_API_H

/* 与原来的单文件相比,这里把各工具用到的头文件集中一次:
   每个工具文件只要 include 这一份,就不会因为"少 include 一个"而编译失败。 */
#include "agent.h"
#include "approval.h"
#include "automation.h"
#include "common.h"
#include "embed.h"
#include "ext.h"
#include "json.h"
#include "llm.h"
#include "llm_provider.h"
#include "net.h"
#include "profile.h"
#include "regex.h"
#include "rules.h"
#include "rules_domains.h"
#include "skills.h"
#include "store.h"
#include "tool_entry.h"
#include "tools.h"
#include "webutil.h"

#include <ctype.h>

/* ================= 公共手法 ================= */

/* 取数小包装:统一处理"授权 + 错误 + 限速" */
int  do_fetch(tool_ctx_t *ctx, const char *url, const char *method, int *status, char **body,
              char **err);

/* 一次取数(带响应头;拿不到头也照样返回内容,只是不做头相关的判断) */
typedef struct {
  int status;
  char *headers;
  char *body;
  char *err;
} fetch_t;
void t_fetch_m(tool_ctx_t *ctx, const char *url, const char *method, fetch_t *f);
void t_fetch(tool_ctx_t *ctx, const char *url, fetch_t *f);
void fetch_free2(fetch_t *f);

/* 站点根:https://a.cn/x/y -> https://a.cn */
void probe_root(const char *url, char *out, size_t cap);
/* 目标归一:补协议、去末尾斜杠 */
void normalize_target(const char *in, char *out, size_t cap);
/* 根 + 相对路径 -> 完整 URL */
void join_path(char *out, size_t cap, const char *root, const char *path);

/* 软 404 校准:先看清"这个站没有这个文件时长什么样" */
typedef struct {
  int valid;
  int status;
  size_t bytes;
  buf_t shape;          /* 抹平数字后的正文骨架 */
  char sample[256];     /* 校准用的那个路径(写进报告,可复核) */
} calib_t;
void calib_free(calib_t *c);
void calib_run(tool_ctx_t *ctx, const char *root, calib_t *c);
int  calib_matches(const calib_t *c, int status, const char *body);

/* 链接分析:把正文里的外链按主机归堆,标出可疑落点(裸 IP / 可疑 TLD) */
void link_analysis(const char *body, const char *own_host, json_t *hosts, json_t *flags);
/* 把"判定依据来自规则文件"这件事写进结果,便于复核 */
void put_rules_note(json_t *data);

/* 网页/URL 小工具 */
int  looks_like_html(const char *ct);
void extract_links(const char *html, json_t *out);
const char *classify_kind(const char *url);
void url_path_query(const char *url, char *out, size_t cap);
void url_origin(const char *url, char *out, size_t cap);
void path_normalize(const char *in, char *out, size_t cap);
void url_resolve(const char *base_url, const char *link, char *out, size_t cap);
int  path_in_scope(const char *path, const char *scope);

/* 敏感特征:按规则里的正则扫一段文本,命中写进 hits(已去敏) */
void mask_into(buf_t *out, const char *s, int len);
int  scan_text_into(tool_ctx_t *ctx, const char *text, json_t *hits);
/* 正则验枪口(agent.exe regextest 用) */
int  tools_regex_first(const char *pattern, const char *text, int *off, int *len);

/* 设置类工具共用的取值/留痕 */
void   value_text(buf_t *out, json_t *v);
void   join_keys(buf_t *out, json_t *obj);
void   settings_audit(tool_ctx_t *ctx, const char *action, const char *target,
                      const char *detail);
json_t *obj_arg(json_t *args, const char *key);
json_t *value_arg(json_t *args, const char *key);
int    top_key_of(const char *path, char *out, size_t cap);
int    deep_set(json_t *root, const char *path, json_t *value);
int    settings_fail(tool_result_t *out, buf_t *msg);

/* ================= 每个工具的入口 =================
   名字与 data\tools\<名字>\<名字>.json 里的 name 一一对应。 */

int t_pool_list(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_agent_info(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_settings_get(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_settings_set(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_sensitive_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_password_check(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_site_crawl(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_sensitive_file_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_dir_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_page_diff(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_nuclei_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int t_sqli_probe(tool_ctx_t *ctx, json_t *args, tool_result_t *out);

/* 文件类工具共用的路径边界(见 fs_common.cpp):三个工具都在同一个边界下工作 */
int  abs_path(const char *raw, wchar_t *out, size_t cap);
int  under_root(const wchar_t *path, const char *root_u8);
int  check_allowed(const wchar_t *full, int for_write, char *err, size_t err_cap);
void split_lines(const char *data, size_t len, int *total_out);

/* 文件类工具(独立实现,见 fs_*.cpp) */
int  fs_tool_read(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int  fs_tool_list(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
int  fs_tool_write(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
void fs_tool_set_extra_root(const char *dir);

#endif /* AGENT_TOOL_API_H */
