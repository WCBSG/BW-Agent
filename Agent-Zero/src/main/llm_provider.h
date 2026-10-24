/* llm_provider.h —— 模型接入层:一个程序可以配多家厂商,由人挑一家在用。
 *
 * 为什么单独一层:决策循环只关心"给我一段补全",不关心对方是恒脑、OpenAI
 * 还是 Anthropic。把"怎么鉴权、走哪个路径、SSE 长什么样"收在这里,加一家
 * 厂商就只改这一个文件。
 *
 * 三类协议覆盖了市面上的绝大多数:
 *   das       —— 恒脑原生智能体接口(appKey + HMAC-SHA256 签名)
 *   openai    —— OpenAI 兼容的 /chat/completions(DeepSeek、Kimi、通义、
 *                智谱、硅基流动、vLLM、Ollama、OneAPI 网关……都走这条)
 *   anthropic —— Anthropic Messages 接口
 *
 * 配置全在数据目录的 models.json 里,程序不内置任何厂商的密钥和地址。
 */
#ifndef AGENT_LLM_PROVIDER_H
#define AGENT_LLM_PROVIDER_H

#include "common.h"
#include "json.h"

typedef enum {
  PROVIDER_DAS = 0,
  PROVIDER_OPENAI = 1,
  PROVIDER_ANTHROPIC = 2
} provider_kind_t;

#define PROVIDER_MAX 16

typedef struct {
  char id[64];             /* 稳定标识,界面用它定位这一条 */
  char name[80];           /* 显示名,如"恒脑 · 安全助手" */
  int  kind;               /* provider_kind_t */
  char base_url[256];      /* 接口根地址(不含具体方法路径也行) */
  char model[128];         /* 模型名;恒脑留空 */
  char api_key[256];       /* 恒脑填 appKey,别家填 API Key */
  char api_secret[256];    /* 恒脑填 appSecret;别家留空 */
  char user_app_key[128];  /* 恒脑可选 */
  char agent_id[128];      /* 恒脑智能体 ID */
  char agent_keyword[128]; /* 恒脑按关键词找智能体时用 */
  char headers[512];       /* 额外请求头,一行一个 Name: value */
  double timeout_ms;       /* 0 = 默认 45 秒 */
  double temperature;      /* <0 = 不发送 */
  int    max_tokens;       /* 0 = 不发送 */
  int    enabled;          /* 关掉的不参与调用,但配置保留 */
} provider_t;

/* 正文增量回调:模型一边生成,这里一边收到。ud 由调用方给。 */
typedef void (*provider_emit_fn)(void *ud, const char *text);

/* 读 <数据目录>/models.json;没有就按环境变量/.env 里的恒脑配置造一条
   (老用户的配置不至于因为升级而失效),仍然没有就是空列表。 */
void providers_init(void);
int  providers_count(void);
provider_t *provider_at(int i);
provider_t *provider_find(const char *id);
int  providers_active_index(void);
const char *providers_active_id(void);
/* 必填项齐了、且没被关掉 → 可以真调用 */
int  provider_ready(const provider_t *p);
int  providers_ready_count(void);
/* 当前实际会用的那一家(界面顶栏、命令行横幅都显示它);
   一家可用的都没有时返回"还没接模型"。 */
const char *providers_display_name(void);
const char *provider_kind_name(int kind);
int  provider_kind_from_name(const char *name);
const char *providers_path(void);

/* 界面用:mask_secret=1 时密钥只回显后四位(空着表示"不改") */
char *providers_json(int mask_secret);
/* 整份写回:读 root 的 active/providers,校验,落盘并生效。
   返回 0 成功;非 0 时 err 里是给人看的原因(配置保持不变)。 */
int  providers_apply(json_t *root, char *err, size_t errcap);
int  providers_save(void);

/* 一次补全:prompt 进,纯文本出。
   emit 非空时正文增量边收边回调(界面才有"打字"感)。
   返回 0 成功;非 0 时 err 里有原因(网络 / 鉴权 / 空回复)。 */
int provider_chat(const provider_t *p, const char *prompt, provider_emit_fn emit,
                  void *ud, buf_t *out, char *err, size_t errcap);

/* 连通性测试:发一句最短的话,返回 0 = 通了。 */
int providers_test(const char *id, char *detail, size_t detailcap);

/* 签名(恒脑平台文档的实现:毫秒时间戳 + Base64(HMAC-SHA256)) */
void llm_make_sign(const char *app_key, const char *app_secret, char *out, size_t cap);

#endif /* AGENT_LLM_PROVIDER_H */
