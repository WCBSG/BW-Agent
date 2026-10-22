/* agent.h —— 智能体的三层结构(工具 / 技能 / 循环)。
 *
 * 为什么专门写这个头:命题要的是"智能体",不是"扫描脚本"。三者的分工是:
 *
 *   tool  原子动作   —— 一次 HTTP 取数、一次正则匹配。无状态、可单测。        (手)
 *   skill 业务技能   —— 有名字、有用途、有"什么时候该用",内部编排若干工具,   (技能)
 *                       真正决定"怎么把一件事做完、怎么算做完了"。
 *   loop  决策循环   —— 感知→规划→行动→观察→反思→收敛。模型负责"选哪个技能、  (大脑)
 *                       参数是什么";程序负责"执行、把观察结果喂回去、判断该不该停"。
 *
 * 关键区别(也是评委最容易看的点):
 *   扫描脚本 = 遍历目标 × 遍历检查项,流程写死;
 *   智能体   = 每拿到一个观察就重新决策一次,可能提前收工、可能追加检查、
 *              可能判定"这次没结论"而不是硬报一条。
 */
#ifndef AGENT_AGENT_H
#define AGENT_AGENT_H

#include "common.h"
#include "json.h"

/* ================= 第一层:工具(tool) ================= */
typedef struct tool_ctx tool_ctx_t;      /* 见 tools.h */

/* 工具执行结果:文本给模型看,结构化给界面渲染 */
typedef struct {
  char *text;          /* 给模型/终端的纯文本结果 */
  json_t *data;        /* 给界面渲染的结构化副本 */
  char *say;           /* 这一轮给用户的最终汇报语(人话) */
  int is_error;
} tool_result_t;

typedef struct tool tool_t;
struct tool {
  const char *name;
  const char *description;      /* 给模型看的说明书:干什么、什么时候用 */
  const char *schema;           /* 参数形状(JSON Schema 子集,字符串形式) */
  const char *kind;             /* "内置" / "开源工具" */
  const char *source_url;       /* 开源工具的项目地址(可溯源) */
  int (*run)(tool_ctx_t *ctx, json_t *args, tool_result_t *out);
};

/* ================= 第二层:技能(skill) =================
   技能不是"工具的换名"。它承载的是**业务判断**:
     · 什么时候该做这件事(when)
     · 做的时候按什么步骤(内部编排若干工具)
     · 什么算成功、什么算"没结论"(判定逻辑)
   一个技能可以调多个工具、可以用程序逻辑组合结果。

   注意:skill_t 的完整定义在 skills.h —— 这里只声明,避免两个头互相 include。 */
typedef struct skill skill_t;

/* ================= 第三层:决策循环(loop) =================
   一次 decide 的结果。模型只能回这三类之一:
     act    选一个技能或工具去执行
     answer 直接给出最终回答(信息够了 / 不需要动手)
     ask    需要用户补充信息(例如没给目标、超出授权范围要确认) */
typedef enum { ACT_ACT, ACT_ANSWER, ACT_ASK } act_kind_t;

typedef struct {
  act_kind_t kind;
  char *tool;            /* ACT_ACT:技能名或工具名 */
  json_t *args;          /* ACT_ACT */
  char *text;            /* ACT_ANSWER / ACT_ASK */
  char *reason;          /* 模型自述的决策理由(可解释性,便于评委看"为什么这么选") */
  char *raw;             /* 模型原始输出,排查用 */
  int from_model;        /* 1=真模型决策;0=本地规则降级 */
} decision_t;

void decision_free(decision_t *d);

/* 循环的可观测状态:每一步都留痕,"为什么停"必须能回答 */
#define MAX_STEPS_DEFAULT 6

typedef struct {
  buf_t transcript;          /* 人类可读的思考/行动流水(评审要看) */
  json_t *steps;             /* 结构化留痕:每步 action/observation */
  int step_count;
  int stop_code;             /* 停止原因编码 */
  char stop_reason[128];     /* 停止原因(人话) */
} loop_state_t;

/* 停止原因:智能体不是跑到步数上限才停,而是"有理由地停" */
enum {
  STOP_NONE = 0,
  STOP_ANSWERED,        /* 给出了最终回答 */
  STOP_NEED_USER,       /* 需要用户补充信息 */
  STOP_NO_PROGRESS,     /* 连续观察到重复结果 —— 再跑也没意义 */
  STOP_BUDGET,          /* 达到步数预算(兜底,报告里要如实说) */
  STOP_OUT_OF_SCOPE,    /* 目标不在授权范围内 */
  STOP_ERROR,           /* 出错且不可恢复 */
  STOP_ANSWERING_ONLY,  /* 本轮是纯问答,不需要动手 */
};

/* 循环的执行环境:工具表、技能表、上下文、界面回推通道 */
typedef struct agent agent_t;

/* 事件回调:把"循环里发生的事情"实时推给界面(流式事件由上层翻译成协议) */
typedef struct {
  void *userdata;
  /* 智能体开始思考(planning) */
  void (*on_thinking)(void *ud, const char *text);
  /* 决定调用某个工具 */
  void (*on_action)(void *ud, const char *tool, json_t *args, const char *reason);
  /* 工具执行中的状态 */
  void (*on_status)(void *ud, const char *tool, const char *status, const char *note);
  /* 拿到观察结果 */
  void (*on_observation)(void *ud, const char *tool, tool_result_t *result);
  /* 最终回答(可能被调用多次:中间答复 + 收尾答复) */
  void (*on_answer)(void *ud, const char *text);
  /* 需要用户补充信息 */
  void (*on_ask)(void *ud, const char *text);
  /* 动手之前的权限审批:返回 1 放行、0 拒绝(拒绝理由写进 reason,调用方 free)。
     不实现(为 NULL)等价于"全部允许" —— 命令行与自检走这条路。 */
  int (*on_approval)(void *ud, const char *tool, json_t *args, char **reason);
} agent_hooks_t;

/* ---------- 生命周期 ---------- */
agent_t *agent_create(const char *session_id);
void     agent_free(agent_t *a);
void     agent_set_hooks(agent_t *a, const agent_hooks_t *hooks);
/* 当前任务的授权域名(合规边界,循环里每次动手前都要过) */
void     agent_set_scope(agent_t *a, const char *task_id, const char **domains, int n);
/* 绑定存储层:技能的"发现入库"要写进去;不绑也能跑,只是不落盘 */
void     agent_set_store(agent_t *a, void *store, const char *run_id);
/* 对话历史(多轮上下文,决定"这轮说的是哪个站"时要用) */
void     agent_add_history(agent_t *a, const char *role, const char *text);

/* ---------- 核心:一轮对话 = 一次完整循环 ---------- */
/* 返回 0 表示循环正常收束;结果通过 hooks 推出去,同时写进 loop_state */
int agent_run_turn(agent_t *a, const char *user_text, loop_state_t *st);

/* ---------- 给外部看的清单 ---------- */
void agent_print_tools(void);
void agent_print_skills(void);
json_t *agent_skill_list_json(void);
json_t *agent_tool_list_json(void);

#endif /* AGENT_AGENT_H */
