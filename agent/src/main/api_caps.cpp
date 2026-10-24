/* api_caps.cpp —— 能力管理接口(技能 / 工具,图形化),从 serve.cpp 拆出来的第三块。
 *
 * 加一个技能或工具,不该要求人会写 front-matter、会拼 JSON。这里把同一份落盘文件
 * 用表单生成,并提供两条"不用自己动脑"的路:
 *   · 用大模型生成(给一句话描述,模型产出草稿,人再改)
 *   · 从市场导入(粘贴一段技能/工具文本,校验后落盘)
 * 落盘格式与手写完全一致 —— 想手改随时还能改。
 */
#include "serve_ctx.h"

#include "ext.h"
#include "json.h"
#include "llm.h"
#include "net.h"
#include "skills.h"
#include "tools.h"
/* ================= 能力管理(技能 / 工具,图形化) =================
   目的:加一个技能或工具不该要求人会写 front-matter、会拼 JSON。
   这里把同一份落盘文件用表单生成,并提供两条"不用自己动脑"的路:
     · 用大模型生成(给一句话描述,模型产出草稿,人再改)
     · 从市场导入(粘贴一段技能/工具文本,校验后落盘)
   落盘格式与手写完全一致 —— 想手改随时还能改。 */
void api_caps(const http_req_t *req, http_res_t *res) {
  if (strcmp(req->method, "POST") == 0) {
    json_t *body = req->body ? json_parse(req->body) : NULL;
    if (!body) {
      http_res_json(res, 400, "{\"ok\":false,\"error\":\"请求体不是合法 JSON\"}");
      return;
    }
    const char *action = j_s(body, "action", "");
    /* action 指向 body 内部,body 释放后就成了野指针 —— 先拷一份 */
    char action_copy[64];
    snprintf(action_copy, sizeof(action_copy), "%s", action);
    char err[512] = {0};
    int rc = -1;

    if (str_ieq(action, "save_skill")) {
      rc = ext_save_skill(j_s(body, "name", ""), j_s(body, "title", ""),
                          j_s(body, "purpose", ""), j_s(body, "when", ""),
                          j_s(body, "tools", ""), j_s(body, "body", ""),
                          j_s(body, "command", ""), (int)j_n(body, "allow", 0),
                          (int)j_n(body, "timeout_ms", 20000), err, sizeof(err));
    } else if (str_ieq(action, "save_tool")) {
      rc = ext_save_tool(j_s(body, "name", ""), j_s(body, "description", ""),
                         j_s(body, "command", ""), j_s(body, "schema", ""),
                         j_s(body, "kind", ""), (int)j_n(body, "allow", 0),
                         (int)j_n(body, "timeout_ms", 20000), err, sizeof(err));
    } else if (str_ieq(action, "delete_skill")) {
      rc = ext_delete_skill(j_s(body, "name", ""), err, sizeof(err));
    } else if (str_ieq(action, "delete_tool")) {
      rc = ext_delete_tool(j_s(body, "name", ""), err, sizeof(err));
    } else if (str_ieq(action, "reload")) {
      ext_reload_local();
      rc = 0;
    } else if (str_ieq(action, "fetch")) {
      /* 从市场下载一份定义(只是"取回来看看",不落盘) */
      const char *url = j_s(body, "url", "");
      char *text = NULL;
      size_t len = 0;
      int ok = net_get_text(url, &text, &len, err, sizeof(err));
      json_free(body);
      json_t *o = j_obj();
      j_set_bool(o, "ok", ok == 0);
      if (ok == 0) j_set_str(o, "text", text ? text : "");
      else j_set_str(o, "error", err[0] ? err : "下载失败");
      char *dump = json_dump(o);
      http_res_json(res, ok == 0 ? 200 : 400, dump);
      free(dump);
      json_free(o);
      free(text);
      return;
    } else if (str_ieq(action, "draft")) {
      /* 用大模型起草。模型不可用时如实说明,并给一份能直接用的模板 ——
         不能因为平台 403 就把这条路堵死。 */
      const char *kind = j_s(body, "kind", "skill");
      const char *brief = j_s(body, "brief", "");
      json_t *draft = j_obj();
      int from_model = 0;

      buf_t prompt;
      buf_init(&prompt);
      if (str_ieq(kind, "tool")) {
        buf_puts(&prompt,
            "你在为一个网站安全巡检智能体写「工具」的声明。只输出一个 JSON 对象,不要解释、不要代码块。\n"
            "格式(与程序里 data/tools/<目录>/<名字>.json 一致):\n"
            "{\"name\":\"动词_名词\",\"kind\":\"自建\",\"readonly\":true,\n"
            " \"description\":\"一句话说明它做什么、什么时候用\",\n"
            " \"source\":\"~/tools/<目录>/<程序>.exe\",\n"
            " \"entry\":{\"type\":\"exec\",\"path\":\"~/tools/<目录>/<程序>.exe\",\n"
            "          \"args\":[\"--json\",\"$参数名\"],\"protocol\":\"argv\"},\n"
            " \"schema\":{JSON Schema 对象,描述参数,必填项写进 required},\n"
            " \"timeout_ms\":20000}\n"
            "说明:argv 协议下参数展开进命令行,$参数名 占位,可写 ${参数名:-默认值};\n"
            "若程序读 stdin 的 JSON、写 stdout 的 JSON,改用 \"protocol\":\"json-stdio\"(此时 args 可省)。\n");
        /* 把本机现状告诉它:已有工具名 + 怎么查本机装了什么。
           不把整份清单塞进提示词,只给名字与一条检索途径,够它避免重名与找现成程序。 */
        buf_puts(&prompt, "已有工具:");
        for (int i = 0; i < tools_count() && i < 40; i++) {
          tool_t *tt = tools_get(i);
          if (tt && tt->name) buf_printf(&prompt, "%s%s", i ? "、" : "", tt->name);
        }
        buf_puts(&prompt,
            "。\n"
            "要复用本机已有的命令行程序时,先查这台机器上到底有没有:没有检索工具就直说,"
            "让用户自己填路径;命中的路径写进 source 与 entry.path;查不到就不要编造路径。\n"
            "用户需求:");
      } else if (str_ieq(kind, "mcp")) {
        buf_puts(&prompt,
            "你在写一条 Model Context Protocol(MCP)服务器配置,会被放进 mcp.json 的 mcpServers 里。\n"
            "只输出一个 JSON 对象,不要解释、不要代码块。字段:name(服务器名,小写字母数字连字符)、\n"
            "command(可执行程序,如 npx / uvx / python)、args(字符串数组)、env(可选,字符串到字符串的对象)。\n"
            "只写标准 MCP 服务器的启动方式,不要编造不存在的包。\n用户需求:");
      } else {
        buf_puts(&prompt,
            "你在为一个网站安全巡检智能体写「技能」的定义。只输出一个 JSON 对象,不要解释、不要代码块。\n"
            "字段:name(以 skill_ 开头)、title(中文名)、purpose(解决什么问题,一句话)、\n"
            "when(什么时候该用它,一句话)、tools(用到的工具名,逗号分隔)、body(给模型看的做法说明,Markdown)。\n"
            "可用工具:site_crawl、sensitive_file_probe、dir_probe、page_diff、nuclei_scan、sqli_probe、"
            "sensitive_scan、password_check。\n用户需求:");
      }
      buf_puts(&prompt, brief);
      buf_t out;
      buf_init(&out);
      int ok = llm_ask(prompt.data, &out);
      buf_free(&prompt);
      if (ok == 0) {
        const char *s = out.data ? strstr(out.data, "{") : NULL;
        json_t *parsed = s ? json_parse(s) : NULL;
        if (parsed && parsed->type == J_OBJ) {
          j_set(draft, "draft", parsed);
          from_model = 1;
        } else {
          json_free(parsed);
          j_set_str(draft, "note", "模型返回的内容不是可用的 JSON,已给出模板");
        }
      } else {
        j_set_str(draft, "note", llm_last_error()[0] ? llm_last_error()
                                                     : "模型当前不可用,已给出模板");
      }
      buf_free(&out);
      if (!from_model) {
        json_t *t = j_obj();
        if (str_ieq(kind, "tool")) {
          j_set_str(t, "name", "my_check");
          j_set_str(t, "kind", "自建");
          j_set_bool(t, "readonly", 1);
          j_set_str(t, "description", "调用本机脚本做一次自定义检查(输出即结论依据)");
          j_set_str(t, "source", "~/tools/my_check/my_check.exe");
          json_t *entry = j_obj();
          j_set_str(entry, "type", "exec");
          j_set_str(entry, "path", "~/tools/my_check/my_check.exe");
          json_t *eargs = j_arr();
          j_add(eargs, j_str("--target"));
          j_add(eargs, j_str("$target"));
          j_set(entry, "args", eargs);
          j_set_str(entry, "protocol", "argv");
          j_set_num(entry, "timeout_ms", 20000);
          j_set(t, "entry", entry);
          j_set_str(t, "schema", "{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\"}},\"required\":[\"target\"]}");
        } else if (str_ieq(kind, "mcp")) {
          j_set_str(t, "name", "my-mcp");
          j_set_str(t, "command", "npx");
          json_t *args = j_arr();
          j_add(args, j_str("-y"));
          j_add(args, j_str("@modelcontextprotocol/server-filesystem"));
          j_add(args, j_str("C:\\data"));
          j_set(t, "args", args);
        } else {
          j_set_str(t, "name", "skill_my_check");
          j_set_str(t, "title", "自定义检查");
          j_set_str(t, "purpose", "按本单位的口径做一次针对性检查");
          j_set_str(t, "when", "用户提出这类检查需求时");
          j_set_str(t, "tools", "site_crawl,sensitive_file_probe");
          j_set_str(t, "body", "1. 先用 site_crawl 拿到assets\n2. 对关心的路径做 sensitive_file_probe\n3. 只报有证据的结论");
        }
        j_set(draft, "draft", t);
      }
      j_set_bool(draft, "ok", 1);
      j_set_bool(draft, "fromModel", from_model);
      char *text = json_dump(draft);
      http_res_json(res, 200, text);
      free(text);
      json_free(draft);
      json_free(body);
      return;
    } else {
      json_free(body);
      http_res_json(res, 400, "{\"ok\":false,\"error\":\"未知的 action\"}");
      return;
    }

    json_free(body);
    if (rc != 0) {
      json_t *o = j_obj();
      j_set_bool(o, "ok", 0);
      j_set_str(o, "error", err[0] ? err : "操作失败");
      char *text = json_dump(o);
      http_res_json(res, 400, text);
      free(text);
      json_free(o);
      return;
    }
    ext_reload_local();
    serve_audit_line("修改能力定义", action_copy, "");
    json_t *inv = ext_inventory_json();
    json_t *o = j_obj();
    j_set_bool(o, "ok", 1);
    j_set(o, "ext", inv);
    j_set_num(o, "tools", tools_count());
    j_set_num(o, "skills", skills_count());
    char *text = json_dump(o);
    http_res_json(res, 200, text);
    free(text);
    json_free(o);
    return;
  }

  /* GET:内置 + 外部合成一张清单 */
  json_t *inv = ext_inventory_json();
  json_t *extSkills = j_get(inv, "skills");
  json_t *extTools = j_get(inv, "tools");
  json_t *mcp = j_get(inv, "mcp");

  char dirSkills[MAX_PATH * 2], dirTools[MAX_PATH * 2];
  ext_dir(dirSkills, sizeof(dirSkills), "skills");
  ext_dir(dirTools, sizeof(dirTools), "tools");

  json_t *skills = j_arr();
  for (int i = 0; i < skills_count(); i++) {
    skill_t *sk = skills_get(i);
    if (!sk || !sk->name) continue;
    json_t *o = j_obj();
    j_set_str(o, "name", sk->name);
    j_set_str(o, "title", sk->title ? sk->title : "");
    j_set_str(o, "purpose", sk->purpose ? sk->purpose : "");
    j_set_str(o, "when", sk->when ? sk->when : "");
    j_set_str(o, "tools", sk->tools ? sk->tools : "");
    j_set_str(o, "source", "内置");
    char mdPath[MAX_PATH * 4];
    snprintf(mdPath, sizeof(mdPath), "%s\\%s.md", dirSkills, sk->name);
    if (file_size(mdPath) >= 0) j_set_bool(o, "customized", 1);
    for (int k = 0; k < j_len(extSkills); k++) {
      if (strcmp(j_s(j_at(extSkills, k), "name", ""), sk->name) == 0) {
        j_set_str(o, "source", "技能包");
        j_set_str(o, "file", j_s(j_at(extSkills, k), "file", ""));
        j_set_bool(o, "hasCommand", j_s(j_at(extSkills, k), "command", "")[0] ? 1 : 0);
        j_set_str(o, "body", j_s(j_at(extSkills, k), "body", ""));
        j_set_str(o, "command", j_s(j_at(extSkills, k), "command", ""));
        j_set_bool(o, "allow", j_b(j_at(extSkills, k), "allow", 0));
        break;
      }
    }
    j_add(skills, o);
  }

  json_t *tools = j_arr();
  for (int i = 0; i < tools_count(); i++) {
    tool_t *t = tools_get(i);
    if (!t || !t->name) continue;
    json_t *o = j_obj();
    j_set_str(o, "name", t->name);
    j_set_str(o, "kind", t->kind ? t->kind : "");
    j_set_str(o, "description", t->description ? t->description : "");
    j_set_str(o, "source", "内置");
    j_set_str(o, "sourceUrl", t->source_url ? t->source_url : "");
    if (str_startswith(t->name, "mcp__")) j_set_str(o, "source", "MCP");
    for (int k = 0; k < j_len(extTools); k++) {
      if (strcmp(j_s(j_at(extTools, k), "name", ""), t->name) == 0) {
        j_set_str(o, "source", "外部");
        j_set_str(o, "file", j_s(j_at(extTools, k), "file", ""));
        j_set_str(o, "command", j_s(j_at(extTools, k), "command", ""));
        j_set_str(o, "schema", j_s(j_at(extTools, k), "schema", ""));
        j_set_str(o, "extDescription", j_s(j_at(extTools, k), "description", ""));
        j_set_bool(o, "allow", j_b(j_at(extTools, k), "allow", 0));
        j_set_num(o, "timeout_ms", j_n(j_at(extTools, k), "timeout_ms", 20000));
        break;
      }
    }
    j_add(tools, o);
  }

  int nTools = 0, nSkills = 0, nMCP = 0, nMCPTools = 0;
  ext_stats(&nTools, &nSkills, &nMCP, &nMCPTools);

  json_t *root = j_obj();
  j_set_bool(root, "ok", 1);
  j_set(root, "skills", skills);
  j_set(root, "tools", tools);
  /* j_set 会接管所有权,mcp 是 inv 的子节点 —— 直接交出去,
     紧接着 json_free(inv) 就会把它再释放一次(堆被踩坏,表现为"点保存后服务消失了")。
     所以这里深拷贝一份再交。 */
  {
    char *mcpText = json_dump(mcp);
    json_t *mcpCopy = mcpText ? json_parse(mcpText) : NULL;
    free(mcpText);
    j_set(root, "mcp", mcpCopy ? mcpCopy : j_arr());
  }
  j_set_str(root, "skillsDir", dirSkills);
  j_set_str(root, "toolsDir", dirTools);
  json_t *stats = j_obj();
  j_set_num(stats, "skills", skills_count());
  j_set_num(stats, "tools", tools_count());
  j_set_num(stats, "extSkills", nSkills);
  j_set_num(stats, "extTools", nTools);
  j_set_num(stats, "mcp", nMCP);
  j_set_num(stats, "mcpTools", nMCPTools);
  j_set(root, "stats", stats);
  char *text = json_dump(root);
  http_res_json(res, 200, text);
  free(text);
  json_free(root);
  json_free(inv);
}

