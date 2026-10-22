/* profile.h —— 本单位的敏感信息定义(自定义关键词 / 正则 / 文件类型 / 落点 / 样例)
 *
 * 为什么单开一层:规则文件 rules.json 是"出厂口径",而每个单位对"什么算敏感"
 * 有自己的说法 —— 内部工号、项目代号、本地证件号格式、只在自己站点上出现的文件名。
 * 这些不该塞进出厂规则里,也不该写死在代码里。
 *
 * 生效方式很具体,不是"存起来好看":
 *   · keywords —— 正文里出现即算命中(敏感信息扫描与泄露检查都会用)
 *   · regex    —— 同上,自己写正则,由内置引擎执行(先用 regextest 验)
 *   · paths    —— 追加到"要探的落点"里(例如 /backup/db.sql)
 *   · file_types —— 命中的文件后缀属于这些时,等级按"高"处理(本单位认定的敏感类型)
 *   · samples  —— 样例片段;正文里出现样例即命中(最适合"某段固定配置长这样")
 *
 * 同一时刻只有一个定义生效(巡检一轮用一套口径),由调度器/界面设置。
 */
#ifndef AGENT_PROFILE_H
#define AGENT_PROFILE_H

#include "common.h"
#include "json.h"

/* 把一个定义设为当前生效口径(传 NULL 或空对象等于清空)。返回 1 表示已生效。 */
int  profile_set_active(json_t *profile);
void profile_clear_active(void);
int  profile_is_active(void);
const char *profile_active_id(void);
const char *profile_active_name(void);

/* 追加的自定义落点(指针指向内部存储,生效期间有效) */
int profile_active_paths(const char **out, int cap);

/* 正文匹配:命中返回 1,并写出命中类别、等级与去敏后的片段 */
int profile_scan_text(const char *text, char *kind, size_t kind_cap, char *severity,
                      size_t sev_cap, char *masked, size_t masked_cap);

/* 后缀是否属于本单位定义的文件类型(用于等级调整) */
int profile_type_hit(const char *path_or_url);

#endif /* AGENT_PROFILE_H */
