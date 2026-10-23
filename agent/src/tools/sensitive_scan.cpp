/* sensitive_scan.cpp —— 文本敏感信息扫描
 *
 * 这个文件只包含这一个工具的实现(以及只被它使用的辅助函数)。
 * 公共手法(取数、URL 归一、软 404 校准)在 tool_common.cpp;
 * 注册表与协议在 src\main\tools.cpp 与 src\main\tool_entry.cpp。
 */
#include "tool_api.h"

int t_sensitive_scan(tool_ctx_t *ctx, json_t *args, tool_result_t *out) {
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
