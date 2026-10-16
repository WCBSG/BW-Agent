/* webutil.h —— 通用网页处理件(不含任何"某个站点"的知识)。
 *
 * 这里放的是"任何站点都用得上"的判断能力:响应头解析、正文归一与同形比较、
 * 目录索引识别、URL 参数改写、SHA-256 指纹。
 *
 * 为什么单独一层:工具要能对**任意**目标做判断,靠的必须是这些与目标无关的手法
 * (内容特征、软 404 校准、同形比较),而不是"记住某个站点的文件名"。
 */
#ifndef AGENT_WEBUTIL_H
#define AGENT_WEBUTIL_H

#include "common.h"
#include "json.h"

/* ---------- 指纹 ---------- */
/* SHA-256 → 十六进制小写(用系统 bcrypt,零第三方依赖)。成功 0,失败 -1 */
int  sha256_hex(const char *data, size_t len, char *out, size_t cap);
/* 正文指纹:归一化之后再哈希(排版改动不算变化) */
int  web_body_hash(const char *body, char *out, size_t cap);

/* ---------- 正文归一 / 比较 ---------- */
/* 去掉 HTML 注释、把连续空白折成一个空格、去首尾空白。
   保留脚本与样式内容 —— 被注入的脚本正是要发现的东西。 */
void web_norm_text(buf_t *out, const char *body);
/* 在归一基础上,把所有数字串替换成 #:用来抹平时间戳/计数器/随机数。
   布尔注入要靠它 —— 动态页面每次数字都不一样,直接比正文必然误判。 */
void web_shape(buf_t *out, const char *body);
/* 两段正文"同形"(抹平数字后一致) */
int  web_same_shape(const char *a, const char *b);

/* 抠页面标题(失败给空串) */
void web_title(const char *body, char *out, size_t cap);

/* ---------- 响应头 ---------- */
/* 取头值(同名多个用 "," 连接)。找到 1,否则 0 */
int  web_header(const char *raw_headers, const char *name, buf_t *out);
/* 同名头的个数(Set-Cookie 必须逐条看) */
int  web_header_count(const char *raw_headers, const char *name);
/* 取第 idx 个同名头(0 起) */
int  web_header_at(const char *raw_headers, const char *name, int idx, buf_t *out);
/* 原始响应头整块里是否根本没有任何头(用来区分"没有这个头"和"没拿到头") */
int  web_headers_available(const char *raw_headers);
/* 把响应头整理成 JSON 对象(展示用;Cookie 值会做去敏) */
json_t *web_headers_json(const char *raw_headers);

/* ---------- 网页结构判断 ---------- */
/* 目录索引页(各服务器/各语言版本的自动索引特征) */
int  web_is_dir_listing(const char *body);
/* 索引页里列出的条目名(最多 max 个) */
void web_dir_listing_entries(const char *body, json_t *out, int max);
/* 含口令输入框 → 这是登录/管理入口,不是普通页面 */
int  web_has_password_form(const char *body);
/* 页面里引用 http:// 资源(在 https 页面上就是混合内容) */
int  web_has_mixed_content(const char *body);

/* ---------- URL ---------- */
void web_url_parts(const char *url, char *host, size_t hcap, char *path, size_t pcap);
void web_url_encode(const char *s, buf_t *out);
/* 替换/追加一个查询参数(值会被编码) */
void web_url_set_param(const char *url, const char *key, const char *value, buf_t *out);
/* 查询参数名列表(去重) */
void web_url_params(const char *url, json_t *out);
/* 取某个参数的当前值:1 = 有 */
int  web_url_get_param(const char *url, const char *key, buf_t *out);

/* ---------- 链接 ---------- */
/* href/src/action 里的链接(原样,不做相对路径补全) */
void web_extract_links(const char *html, json_t *out);
/* 忽略大小写的出现次数(不重叠) */
int  web_count_icase(const char *hay, const char *needle);

#endif /* AGENT_WEBUTIL_H */
