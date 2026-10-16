/* llm.h —— 决策层:真模型(恒脑)优先,本地规则兜底。
 *
 * 这一层只干一件事:**决定下一步做什么**。它不执行工具,也不碰数据。
 * 决策的产出是三选一(见 agent.h 的 decision_t):
 *     act(调工具) / answer(直接回答) / ask(需要用户补充)
 * 模型不可用时降级成本地规则路由 —— 断网也能把流程走完,演示不冒烟。
 */
#ifndef AGENT_LLM_H
#define AGENT_LLM_H

#include "agent.h"
#include "common.h"
#include "json.h"

typedef struct {
  char base_url[256];
  char app_key[128];
  char app_secret[128];
  char user_app_key[128];
  char agent_id[128];
  char agent_keyword[128];
  double timeout;
  int enabled;            /* 有 key + secret 才算接了真模型 */
} llm_config_t;

void llm_init(const char *env_dir);
const llm_config_t *llm_config(void);
int  llm_enabled(void);

/* 最近一次调用模型失败的原因(空字符串 = 没有失败)。
   用途:界面/命令行说明"为什么降级到本地规则",而不是只显示"离线可用"。 */
void        llm_set_last_error(const char *msg);
const char *llm_last_error(void);

/* 决策:把"用户输入 + 可用工具/技能 + 已获得的观察"拼成提示词,问模型要决策。
   context 是循环里的观察记录(JSON 数组,可为 NULL)。
   返回 0 成功(decision 已填);非 0 表示失败,调用方应走降级。 */
int llm_decide(agent_t *a, const char *user_text, json_t *observations,
               const char *scope_note, decision_t *out);

/* 本地规则路由(降级通道)。永远可用,纯函数。 */
void rule_decide(const char *user_text, const char *scope_note, decision_t *out);

/* 签名(平台文档的 Python 版实现照抄,密钥用系统 bcrypt 算 HMAC-SHA256) */
void llm_make_sign(const char *app_key, const char *app_secret, char *out, size_t cap);

/* 从模型输出里抠出决策 JSON(容错:代码块/前后废话/截断/复读) */
int llm_extract_action(const char *raw, decision_t *out);

#endif /* AGENT_LLM_H */
