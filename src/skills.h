/* skills.h —— 技能层:智能体的"专业能力"。
 *
 * 技能与工具的区别(这是命题里"智能体"与"扫描脚本"的分水岭):
 *   工具 = 一次动作。            例:敏感文件探测(试一组落点)
 *   技能 = 一件事的完整做法与判定。例:「敏感信息检查」= 先看定义 → 决定试哪些
 *          落点 → 逐个探测 → 按内容特征判真假 → 归纳成有等级/证据/修复建议的结论,
 *          并且**知道什么时候该说"没结论"而不是硬报**。
 */
#ifndef AGENT_SKILLS_H
#define AGENT_SKILLS_H

#include "agent.h"
#include "common.h"
#include "io.h"
#include "json.h"
#include "tools.h"

typedef struct skill skill_t;

/* 技能一次执行的产出 */
typedef struct {
  char *summary;       /* 人话汇报(会作为 on_answer 推给界面) */
  json_t *data;        /* 结构化产出(计数、清单、报告摘要) */
  int is_error;
  int finding_count;   /* 本次新增发现数(报告与告警要用) */
} skill_result_t;

struct skill {
  const char *name;         /* skill_* —— 提示词与规则路由都按这个名字调 */
  const char *title;        /* 中文名(界面/报告用) */
  const char *purpose;      /* 解决什么问题 */
  const char *when;         /* 什么时候该用 —— 决策提示词里给模型看 */
  const char *tools;        /* 用到的工具(逗号分隔,展示与提示词用) */
  int multi_step;           /* 是否需要多轮观察(1 = 内部会多次取数) */
  int (*run)(tool_ctx_t *ctx, json_t *args, skill_result_t *out);
};

void     skills_init(void);
int      skills_count(void);
skill_t *skills_get(int index);
skill_t *skills_find(const char *name);
json_t  *skills_decl_json(void);          /* 技能清单(界面/文档用) */
void     skills_manifest(buf_t *out);     /* 给模型看的技能说明文本 */
int      skills_run(tool_ctx_t *ctx, const char *name, json_t *args,
                    skill_result_t *out);
void     skill_result_free(skill_result_t *r);

/* 收尾三件事(复测 / 报告 / 评测)的实现放在 skills_closure.c:
   它们不新发探查,只把已落盘的结果变成闭环结论。 */
int      skill_closure_run(tool_ctx_t *ctx, const char *name, json_t *args,
                           skill_result_t *out);

/* 追加一个外部技能(用户在数据目录里写的技能包 / Markdown)。
   技能是"能力",所以外部技能也走同一条调度:技能表里能找到就会被模型选中。 */
int      skills_register_external(const char *name, const char *title, const char *purpose,
                                  const char *when, const char *tools,
                                  int (*run)(tool_ctx_t *, json_t *, skill_result_t *));

/* 用训练/使用方写的说明文字覆盖某个技能的描述字段(名字必须已存在)。
   用途:程序会把内置技能导出成数据目录里的 Markdown,使用者按自己单位的叫法改
   "什么时候用/解决什么" 之后,决策提示词里用的就是他改过的文字;实现仍然是内置的,
   改文字不会改行为(也就不会因为改错文字把程序搞坏)。
   返回 1 = 覆盖成功,0 = 没有这个名字。 */
int      skills_override_text(const char *name, const char *title, const char *purpose,
                              const char *when, const char *tools);

#endif /* AGENT_SKILLS_H */
