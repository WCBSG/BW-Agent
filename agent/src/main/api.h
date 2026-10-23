/* api.h —— 接口的"分域入口"。
 *
 * serve.cpp 只做三件事:开端口、过门禁、按路径把请求转给某个域。
 * 每个域的实现各在一个文件里,想改哪一块就只读那一个文件:
 *
 *   api_config.cpp   规则设置 + 数据目录里的配置文件(白名单/备份/校验)
 *   api_models.cpp   多厂商模型配置(增删改、切当前、连通性测试)
 *
 * 尚未拆出的域(对话/审批/能力/周期巡检/导出)还在 serve.cpp 里 ——
 * 它们和 agent、store、SSE 绑得紧,拆的时候要连状态一起搬,
 * 不能"为了文件短一点"硬切。
 */
#ifndef AGENT_API_H
#define AGENT_API_H

#include "http.h"

/* 规则设置(整份 rules 对象) */
void api_rules(const http_req_t *req, http_res_t *res);
/* 规则预设:list / save / apply / delete */
void api_rules_preset(const http_req_t *req, http_res_t *res);

/* 数据目录里的配置文件:列表 / 读一份 / 存一份 / 热加载规则 */
void api_config_list(const http_req_t *req, http_res_t *res);
void api_config_get(const http_req_t *req, http_res_t *res);
void api_config_save(const http_req_t *req, http_res_t *res);
void api_reload(const http_req_t *req, http_res_t *res);

/* 模型配置 */
void api_models(const http_req_t *req, http_res_t *res);

/* 能力管理:技能 / 工具的列表、保存、删除、市场导入、模型生成 */
void api_caps(const http_req_t *req, http_res_t *res);

/* 周期巡检:列出 / 存一份 / 删一份 / 马上跑一次 */
void api_automation_list(const http_req_t *req, http_res_t *res);
/* 某条定时任务的执行流水(time/<id>/*.jsonl) */
void api_automation_history(const http_req_t *req, http_res_t *res);
void api_automation_post(const http_req_t *req, http_res_t *res);

/* 本单位敏感信息定义 */
void api_profiles(const http_req_t *req, http_res_t *res);

#endif /* AGENT_API_H */
