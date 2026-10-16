/* json.h —— 极简 JSON(零依赖)。
   为什么自己写:评委拿到源码只想跑一个 gcc,不该被第三方库拦住;
   而我们的需求很窄 —— 解析协议事件、工具参数、恒脑返回值,序列化输出。
   不做的事:不保留对象字段顺序以外的格式、不追求极致的错误信息。
   做对的事:严格的字符串转义、UTF-8 原样透传(中文不能坏)。 */
#ifndef AGENT_JSON_H
#define AGENT_JSON_H

#include "common.h"

typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } jtype_t;

typedef struct json json_t;
struct json {
  jtype_t type;
  /* 标量 */
  int b;
  double num;
  char *str;              /* J_STR 的值(UTF-8) */
  /* 数组 / 对象 */
  json_t **items;         /* 数组元素,或对象的值 */
  char **keys;            /* 对象键(数组为 NULL) */
  int count;
  int cap;
};

/* ---------- 解析 ---------- */
json_t *json_parse(const char *text);                                  /* 失败返回 NULL */
json_t *json_parse_n(const char *text, size_t len);
void    json_free(json_t *j);

/* ---------- 构造 ---------- */
json_t *j_null(void);
json_t *j_bool(int v);
json_t *j_num(double v);
json_t *j_str(const char *s);
json_t *j_arr(void);
json_t *j_obj(void);

/* ---------- 读写 ---------- */
void    j_set(json_t *obj, const char *key, json_t *value);   /* 接管 value 所有权 */
void    j_set_str(json_t *obj, const char *key, const char *value);
void    j_set_num(json_t *obj, const char *key, double value);
void    j_set_bool(json_t *obj, const char *key, int value);
void    j_set_null(json_t *obj, const char *key);
void    j_add(json_t *arr, json_t *value);                    /* 追加到数组 */

/* 取值:拿不到时给安全默认(调用方不用到处判空) */
json_t      *j_get(json_t *obj, const char *key);
const char  *j_s(json_t *obj, const char *key, const char *fallback);
double       j_n(json_t *obj, const char *key, double fallback);
int          j_b(json_t *obj, const char *key, int fallback);
json_t      *j_at(json_t *arr, int index);
int          j_len(json_t *arr_or_obj);
/* 按 "a.b.c" 路径取(数组下标写 [n],如 "data.messages[0].content") */
json_t      *j_path(json_t *root, const char *path);
const char  *j_path_s(json_t *root, const char *path, const char *fallback);

/* ---------- 序列化 ---------- */
void  json_write(buf_t *out, json_t *j);           /* 紧凑输出 */
char *json_dump(json_t *j);                        /* 返回 xmalloc 的字符串 */
char *json_dump_pretty(json_t *j);                 /* 带缩进,给人看/落盘 */

/* ---------- 小工具 ---------- */
const char *j_type_name(jtype_t t);
/* 只取字符串内容(不做转义),用于把 JSON 里的一层字符串再解析一次 */
char *json_unescape(const char *s, size_t n, size_t *out_len);

#endif /* AGENT_JSON_H */
