/* io.h —— 取数与回调的公共形状。
   单独一个头是为了打断循环依赖:net.h(取数实现)和 tools.h(取数使用方)都要它,
   而这个形状本身不依赖任何一边。 */
#ifndef AGENT_IO_H
#define AGENT_IO_H

#include "common.h"
#include "json.h"

/* 取数回调:成功后 body/headers 的所有权交给调用方(xmalloc,需 free)。
   实现方(net.c)负责在里面做完授权校验、限速与审计。

   headers 是"原始响应头整块"(CRLF 分隔),做弱配置检查(安全响应头、Cookie 属性、
   版本泄露)必需 —— 这些结论只能从响应头里得出,拿不到头就没法下判断。
   fetch_ex 允许为 NULL:此时工具退回 fetch,并把"本次拿不到响应头"如实写进结果,
   不会假装检查过。 */
typedef struct {
  int (*fetch)(void *ud, const char *url, const char *method,
               int *status, char **body, size_t *body_len, char **err);
  int (*fetch_ex)(void *ud, const char *url, const char *method, int *status,
                  char **headers, char **body, size_t *body_len, char **err);
  void *userdata;
} tools_io_t;

#endif /* AGENT_IO_H */
