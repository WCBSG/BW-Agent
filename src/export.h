/* export.h —— 报告导出
 *
 * 命题要求「报告导出」。这里给五种格式,理由各不相同:
 *   markdown —— 给人读、能进 git,证据链最清楚
 *   html     —— 能直接打开、能打印,样式与界面同源
 *   csv      —— 给表格工具做统计(一条发现一行)
 *   docx     —— 给甲方走公文流程(自己拼 OOXML,不依赖 Office)
 *   pdf      —— 定稿交付。中文排版自己不写字体渲染,交给本机 Edge 的
 *               headless 打印(Windows 10/11 自带),拿不到就如实报错
 *
 * 所有格式都从同一份报告 + 同一份发现清单渲染,不各写一套统计逻辑,
 * 否则"pdf 里的数字和页面上的不一样"这种问题永远查不完。
 */
#ifndef AGENT_EXPORT_H
#define AGENT_EXPORT_H

#include "common.h"
#include "store.h"

/* 支持的后缀 */
int export_supported(const char *fmt);

/* 渲染。成功返回 0 并把内容放进 out(调用方 free),失败返回 -1 并写 err。
   report_id 为空时自动取最近一份报告。 */
int export_report(store_t *s, const char *report_id, const char *fmt, buf_t *out,
                  char *err, size_t err_cap);
/* 建议的下载文件名(ASCII,扩展名跟随 fmt) */
void export_filename(const char *report_id, const char *fmt, char *out, size_t cap);

#endif /* AGENT_EXPORT_H */
