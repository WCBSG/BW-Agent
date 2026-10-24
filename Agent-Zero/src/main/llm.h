/* llm.h —— 决策层。
 *
 * 这一层只干一件事:**决定下一步做什么**。它不执行工具,也不碰数据。
 * 决策的产出是三选一(见 agent.h 的 decision_t):
 *     act(调工具) / answer(直接回答) / ask(需要用户补充)
 *
 * 具体走哪家厂商由 llm_provider 决定(可以同时配多家,当前用哪家由人在
 * 「设置 → 模型」里选)。一家都没配或调不通,这一轮就停在"模型不可用"并
 * 如实说明原因 —— 不存在关键词规则兜底,那只会让用户看到一段没问过模型的结论。
 */
#ifndef AGENT_LLM_H
#define AGENT_LLM_H

#include "agent.h"
#include "common.h"
#include "json.h"
#include "llm_provider.h"

void llm_init(const char *env_dir);
int  llm_enabled(void);
/* 自检模式:llm_enabled() 恒为 0,循环会走"模型不可用"的收尾分支,不联网 */
void llm_set_test_mode(int on);

/* 最近一次调用模型失败的原因(空串 = 没有失败)。
   用途:界面/命令行说明"为什么这次没查成",而不是只显示"离线"。 */
void        llm_set_last_error(const char *msg);
const char *llm_last_error(void);

/* 换了一条模型通道之后调它:把"上一家失败"的冷却与原因一起清掉。
   不这么做的话,人已经手动切到能用的那家,程序还在为上一家的失败
   冷静两分钟 —— 表现就是"切了也没用"。 */
void llm_reset_error(void);

/* 决策:把"用户输入 + 可用工具/技能 + 已获得的观察"拼成提示词,问模型要决策。
   context 是循环里的观察记录(JSON 数组,可为 NULL)。
   返回 0 成功(decision 已填);非 0 表示失败,调用方应中止本轮并说明原因。

   决策只有一条路:模型。早期有过"模型不通就用关键词规则兜底"的通道,已删掉 ——
   它会让界面显示一段像是智能体给出的结论,其实一次模型都没问过。
   要跑确定性的检查,用户用 / 命令直说。 */
int llm_decide(agent_t *a, const char *user_text, json_t *observations,
               const char *scope_note, decision_t *out);

/* 签名在 llm_provider.h 里声明(它属于"怎么鉴权"的一部分) */

/* 从模型输出里抠出决策 JSON(容错:代码块/前后废话/截断/复读) */
int llm_extract_action(const char *raw, decision_t *out);

/* 自由问答:把 prompt 整段发给模型,拿回纯文本。
   用途:界面里"用大模型生成技能/工具"这类一次性生成,不走决策循环。
   返回 0 成功;非 0 表示模型不可用,提示词留空由调用方自行处理。 */
int llm_ask(const char *prompt, buf_t *out);

#endif /* AGENT_LLM_H */
