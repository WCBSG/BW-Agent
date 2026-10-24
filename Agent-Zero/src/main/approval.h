/* approval.h —— 工具调用的权限审批
 *
 * 主流 Agent 都有一条"动手前先问一句"的闸,而且默认就开着。这里给三种东西:
 *   · 两种内置策略:询问(每个动作都要你点头) / 全部允许(自动跑,但要先看警告)
 *   · 自定义策略:按工具名匹配,逐条指定 允许 / 询问 / 拒绝,可存成预设(自定义策略 1、2…)
 *   · 拒绝不是报错:它作为一条观察交回给模型("这一步没被允许"),
 *     模型据此换路子或老实收束 —— 而不是让整轮崩掉。
 *
 * 策略存在数据目录的 approval.json 里(人可读),当前生效的策略 id 也在里面。
 */
#ifndef AGENT_APPROVAL_H
#define AGENT_APPROVAL_H

#include "common.h"
#include "json.h"

typedef enum {
  APPROVAL_ALLOW = 0,   /* 直接放行 */
  APPROVAL_ASK = 1,     /* 停下等用户点 */
  APPROVAL_DENY = 2,    /* 直接拒绝 */
} approval_action_t;

typedef struct {
  char id[24];
  char name[64];
  char mode[16];        /* ask | allow_all | custom */
  char note[200];
  /* custom 模式下的规则:"工具名模式=动作" 一行一条,例如 sensitive_file_probe=ask */
  char rules[1024];
} approval_policy_t;

/* 读盘 / 落盘(路径由 serve 用 app_data_path 给出) */
void approval_set_path(const char *path);
void approval_load(void);
void approval_save(void);

/* 内置两条默认策略 + 用户预设,拼成一个数组(调用方 json_free) */
json_t *approval_list_json(void);
/* 当前生效的策略 id */
const char *approval_active_id(void);
/* 切换生效策略:成功返回 1 */
int approval_activate(const char *id);
/* 保存(新建或覆盖)一条策略,成功返回 id 副本(调用方 free) */
char *approval_save_policy(json_t *p, char *err, size_t err_cap);
int approval_delete_policy(const char *id);
/* 判定某个动作该怎么走。
   readonly 由工具自己声明(取数、读文件、查授权池这类不改任何东西的动作)。
   "允许只读"策略据此自动放行:只读动作不问,其余照旧询问。 */
approval_action_t approval_decide(const char *tool, int readonly);
/* 当前策略是不是"只允许只读"?界面据此把"会改动东西"的开关标出来 */
int approval_is_readonly_only(void);
/* 当前策略是不是"全部允许"(界面据此显示警告标记) */
int approval_is_allow_all(void);
/* 当前策略的人话描述("询问每一个动作" / "自动放行全部动作" / "自定义") */
const char *approval_mode_text(void);

#endif /* AGENT_APPROVAL_H */
