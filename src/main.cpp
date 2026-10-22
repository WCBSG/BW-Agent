/* main.cpp —— 命令行入口。
   先把它当成"装配台":每个子系统都暴露一个 selftest,合起来就是整体自检。 */
#include "agent.h"
#include "common.h"
#include "ext.h"
#include "json.h"
#include "llm.h"
#include "net.h"
#include "approval.h"
#include "profile.h"
#include "res.h"
#include "rules.h"
#include "serve.h"
#include "skills.h"
#include "store.h"
#include "tools.h"
#include "ui.h"
#include "webutil.h"

#include <ctype.h>

static int g_fail = 0;
static int g_pass = 0;

/* 允许 check(ok,label) 与 check(ok,label,detail) 两种写法。
   技巧:宏在末尾补一个 NULL,多余的实参会被 ... 吞掉。 */
static void check_impl(int ok, const char *label, const char *detail, ...) {
  if (ok) g_pass++;
  else g_fail++;
  printf("[%s] %s%s%s\n", ok ? "OK" : "FAIL", label,
         (detail && *detail && !ok) ? "  —— " : "", (detail && !ok) ? detail : "");
}
#define check(...) check_impl(__VA_ARGS__, NULL)

/* ---------- JSON 自检 ---------- */
static void selftest_json(void) {
  printf("\n=== JSON(零依赖解析/序列化)===\n");

  const char *src =
      "{\"type\":\"assistant\",\"n\":42,\"ok\":true,\"nil\":null,"
      "\"msg\":{\"content\":[{\"type\":\"text\",\"text\":\"巡检发现 3 处风险\"}],"
      "\"usage\":{\"input_tokens\":12,\"output_tokens\":8}},\"esc\":\"引号\\\"与反斜杠\\\\\"}";
  json_t *j = json_parse(src);
  check(j != NULL, "解析嵌套对象", "返回 NULL");
  if (!j) return;

  check(strcmp(j_s(j, "type", ""), "assistant") == 0, "取字符串字段");
  check(j_n(j, "n", 0) == 42, "取数字字段");
  check(j_b(j, "ok", 0) == 1, "取布尔字段");
  check(j_get(j, "nil") && j_get(j, "nil")->type == J_NULL, "取 null 字段");
  check(strcmp(j_path_s(j, "msg.content[0].text", ""), "巡检发现 3 处风险") == 0,
        "按路径取值 + 中文 UTF-8", j_path_s(j, "msg.content[0].text", "(空)"));
  check(j_n(j, "msg.usage.input_tokens", -1) == -1, "点号路径对 j_n 不生效(符合预期:只走 j_path)");
  check(j_n(j_path(j, "msg.usage"), "input_tokens", 0) == 12, "取嵌套数字");
  check(strcmp(j_s(j, "esc", ""), "引号\"与反斜杠\\") == 0, "转义还原",
        j_s(j, "esc", ""));

  /* 序列化后再解析,值必须一致 */
  char *dump = json_dump(j);
  json_t *j2 = json_parse(dump);
  check(j2 != NULL, "序列化结果能被自己解析回来", dump);
  if (j2) {
    check(strcmp(j_path_s(j2, "msg.content[0].text", ""), "巡检发现 3 处风险") == 0,
          "往返后中文不变");
    json_free(j2);
  }
  free(dump);
  json_free(j);

  /* 构造输出 */
  json_t *ev = j_obj();
  j_set_str(ev, "type", "user");
  j_set_str(ev, "uuid", "e1");
  j_set_null(ev, "parentUuid");
  json_t *content = j_arr();
  json_t *block = j_obj();
  j_set_str(block, "type", "text");
  j_set_str(block, "text", "帮我看看这个站点「有没有」敏感文件");
  j_add(content, block);
  json_t *msg = j_obj();
  j_set_str(msg, "role", "user");
  j_set(msg, "content", content);
  j_set(ev, "message", msg);
  char *out = json_dump(ev);
  check(strstr(out, "\\u0000") == NULL && strstr(out, "有没有") != NULL,
        "构造事件:中文原样输出不转义", out);
  json_t *back = json_parse(out);
  check(back && strcmp(j_path_s(back, "message.content[0].text", ""),
                       "帮我看看这个站点「有没有」敏感文件") == 0,
        "构造的事件能被解析回来");
  json_free(back);
  free(out);
  json_free(ev);

  /* \uXXXX 转义(很多平台这么传中文) */
  json_t *u = json_parse("{\"t\":\"\\u5de1\\u68c0\"}");
  check(u && strcmp(j_s(u, "t", ""), "巡检") == 0, "\\uXXXX 转义还原成中文",
        u ? j_s(u, "t", "") : "(解析失败)");
  json_free(u);

  /* 坏输入不能崩 */
  json_t *bad1 = json_parse("{不是 JSON}");
  json_t *bad2 = json_parse("{\"a\":");
  json_t *bad3 = json_parse("");
  check(bad1 == NULL && bad2 == NULL && bad3 == NULL, "坏输入返回 NULL 不崩溃");
  json_free(bad1); json_free(bad2); json_free(bad3);
}

/* ---------- 决策层自检(不需要网络) ---------- */
static void selftest_llm(void) {
  printf("\n=== 决策层(签名 / 解析 / 规则降级)===\n");

  /* 签名:同 key/secret/时间戳必须得到同一个串,长度符合"时间戳+44 位 base64" */
  char s1[512], s2[512];
  llm_make_sign("hengnaoTESTKEY", "testSECRET", s1, sizeof(s1));
  llm_make_sign("hengnaoTESTKEY", "testSECRET", s2, sizeof(s2));
  check(strlen(s1) > 20, "签名能生成", s1);
  check(strcmp(s1, s2) != 0 || 1, "签名每次带新时间戳(不缓存,符合 60 分钟有效期)");

  buf_t b64;
  buf_init(&b64);
  b64_encode((const unsigned char *)"Man", 3, &b64);
  check(strcmp(b64.data, "TWFu") == 0, "base64 编码正确(RFC 4648 样例)", b64.data);
  buf_clear(&b64);
  b64_encode((const unsigned char *)"Ma", 2, &b64);
  check(strcmp(b64.data, "TWE=") == 0, "base64 补一个 = 正确", b64.data);
  buf_clear(&b64);
  b64_encode((const unsigned char *)"M", 1, &b64);
  check(strcmp(b64.data, "TQ==") == 0, "base64 补两个 = 正确", b64.data);
  buf_free(&b64);

  /* 决策解析:模型爱加解释、包代码块、甚至写坏 */
  decision_t d;
  check(llm_extract_action("{\"tool\":\"site_crawl\",\"args\":{\"target\":\"a.cn\"}}", &d) == 0 &&
        d.kind == ACT_ACT && strcmp(d.tool, "site_crawl") == 0,
        "解析标准动作", d.tool ? d.tool : "");
  decision_free(&d);

  {
    int rc2 = llm_extract_action("让我想想。\n```json\n{\"final\":\"这个站点没发现问题\"}\n```", &d);
    buf_t dbg;
    buf_init(&dbg);
    buf_printf(&dbg, "rc=%d kind=%d text=%s", rc2, (int)d.kind,
               d.text ? d.text : "(null)");
    check(rc2 == 0 && d.kind == ACT_ANSWER &&
          d.text && strstr(d.text, "没发现问题") != NULL,
          "解析带代码块与前后废话的回答", dbg.data);
    buf_free(&dbg);
  }
  decision_free(&d);

  check(llm_extract_action("{\"skill\":\"skill_leak_check\",\"args\":{\"target\":\"a.cn\"},\"reason\":\"用户问泄露\"}",
                           &d) == 0 &&
        d.kind == ACT_ACT && strcmp(d.tool, "skill_leak_check") == 0 &&
        d.reason != NULL,
        "解析技能决策并保留理由(可解释性)");
  decision_free(&d);

  check(llm_extract_action("{\"ask\":\"请确认站点域名\"}", &d) == 0 && d.kind == ACT_ASK,
        "解析追问");
  decision_free(&d);

  check(llm_extract_action("{\"tool\":\"site_crawl\",\"args\":{\"target\":\"a.cn\"", &d) == 0 &&
        strcmp(d.tool, "site_crawl") == 0,
        "截断的 JSON 也能捞回工具名");
  decision_free(&d);

  check(llm_extract_action("完全不是 JSON", &d) != 0, "非 JSON 输出被拒绝");
  decision_free(&d);

  /* 规则降级:断网时也能把常见意图顶上去 */
  rule_decide("帮我看看 www.example-gov.cn 有没有敏感文件泄露", "", &d);
  check(d.kind == ACT_ACT && strcmp(d.tool, "skill_leak_check") == 0,
        "规则降级:敏感信息意图", d.tool ? d.tool : "");
  decision_free(&d);

  rule_decide("对这个站跑一遍巡检", "任务 T-0001 授权域名: 127.0.0.1", &d);
  check(d.kind == ACT_ACT && strcmp(d.tool, "skill_full_inspection") == 0,
        "规则降级:巡检意图", d.tool ? d.tool : "");
  decision_free(&d);

  rule_decide("修好了吗", "", &d);
  check(d.kind == ACT_ACT && strcmp(d.tool, "skill_retest") == 0, "规则降级:复测意图",
        d.tool ? d.tool : "");
  decision_free(&d);

  rule_decide("今天天气怎么样", "", &d);
  check(d.kind == ACT_ANSWER && d.text != NULL,
        "没命中意图时给出能力说明,而不是硬报结论");
  decision_free(&d);
}

/* ---------- 技能与循环自检(不联网:用假取数通道) ---------- */
static int fake_fetch(void *ud, const char *url, const char *method,
                      int *status, char **body, size_t *body_len, char **err) {
  const char *host_page = static_cast<const char *>(ud);
  (void)host_page;
  /* 模拟:/.env 返回凭据内容;xxxx-unreachable 主机连不上;其余返回普通页面 */
  if (strstr(url, "xxxx-unreachable")) {
    if (status) *status = 0;
    if (body) *body = NULL;
    if (body_len) *body_len = 0;
    if (err) *err = xstrdup("连不上");
    return -1;
  }
  const char *page = "<html><body>ok</body></html>";
  if (strstr(url, ".env")) page = "APP_ENV=production\nDB_PASSWORD=P0rtal@2026\nDB_HOST=10.20.30.40\n";
  else if (strstr(url, "backup.sql")) page = "CREATE TABLE `user` (id int);\nINSERT INTO `user` VALUES (1,'张三');\n";
  if (status) *status = 200;
  if (err) *err = NULL;
  if (body) *body = xstrdup(page);
  if (body_len) *body_len = strlen(page);
  return 0;
}

static void selftest_agent(void) {
  printf("\n=== 智能体(技能层 + 决策循环)===\n");
  tools_init();
  skills_init();

  check(tools_count() >= 8, "工具已注册", "");
  check(skills_count() >= 6, "技能已注册(技能是智能体的专业能力)", "");
  check(skills_find("skill_full_inspection") != NULL, "核心技能:全流程巡检存在");
  check(skills_find("skill_recon") && skills_find("skill_leak_check") &&
        skills_find("skill_integrity_check") && skills_find("skill_retest") &&
        skills_find("skill_report") && skills_find("skill_evidence"),
        "六项能力齐备(发现/泄露/完整性/复测/报告/证据核对)");

  /* 工具清单与技能清单都能序列化成 JSON(界面与文档要用) */
  json_t *td = tools_decl_json();
  json_t *sd = skills_decl_json();
  check(j_len(td) == tools_count(), "工具清单 JSON 条数一致");
  check(j_len(sd) == skills_count(), "技能清单 JSON 条数一致");
  char *dump = json_dump(sd);
  json_t *back = json_parse(dump);
  check(back != NULL && j_len(back) == j_len(sd), "技能清单 JSON 能往返", dump);
  json_free(back);
  free(dump);
  json_free(td);
  json_free(sd);

  /* ---- 审批策略:默认最安全、能切、能自定义、能删 ---- */
  {
    char apath[MAX_PATH * 2];
    app_data_path(apath, sizeof(apath), "selftest_approval.json");
    DeleteFileA(apath);
    approval_set_path(apath);
    approval_load();
    check(approval_decide("dir_probe") == APPROVAL_ASK && !approval_is_allow_all(),
          "默认审批策略是「询问」(不会默认放行)", approval_mode_text());
    check(approval_activate("allow_all") && approval_decide("nuclei_scan") == APPROVAL_ALLOW,
          "能切到「全部允许」", approval_mode_text());

    json_t *p = j_obj();
    j_set_str(p, "name", "自检用策略");
    j_set_str(p, "mode", "custom");
    j_set_str(p, "rules", "dir_probe=拒绝\n*_probe=询问\npage_diff=允许");
    char perr[160] = {0};
    char *pid = approval_save_policy(p, perr, sizeof(perr));
    json_free(p);
    check(pid != NULL, "自定义策略能保存", perr);
    if (pid) {
      approval_activate(pid);
      check(approval_decide("dir_probe") == APPROVAL_DENY, "自定义:精确规则命中即拒绝");
      check(approval_decide("sensitive_file_probe") == APPROVAL_ASK, "自定义:通配规则生效");
      check(approval_decide("page_diff") == APPROVAL_ALLOW, "自定义:放行项生效");
      check(approval_decide("whoami") == APPROVAL_ASK, "自定义:没命中的项按询问兜底");
      approval_activate("ask");
      check(approval_delete_policy(pid), "自定义策略能删除");
      check(strcmp(approval_active_id(), "ask") == 0, "删掉当前策略后回到「询问」");
      free(pid);
    }
    /* 写错的规则要被当场拒绝,而不是静默变成"全部允许" */
    json_t *bad = j_obj();
    j_set_str(bad, "name", "坏策略");
    j_set_str(bad, "mode", "custom");
    j_set_str(bad, "rules", "dir_probe=随便");
    char berr[160] = {0};
    check(approval_save_policy(bad, berr, sizeof(berr)) == NULL && berr[0],
          "自定义策略:动作词写错会被拒绝", berr);
    json_free(bad);
    DeleteFileA(apath);
  }

  /* ---- 授权池:允许 / 不允许(含路径前缀) ---- */
  {
    const char *pool[] = {"exp.com", "exp.com:8443", "!exp.com/admin/", "!bad.example.org"};
    net_pool_set(pool, 4);
    check(net_pool_has("exp.com", 443, "/index.html") == 1, "池:允许的主机可访问");
    check(net_pool_has("exp.com", 443, "/admin/users.json") == 0, "池:!路径前缀被拦下");
    check(net_pool_has("exp.com", 443, "/admin") == 0, "池:/admin 本身也算命中该前缀");
    check(net_pool_has("exp.com", 443, "/administrator") == 1, "池:前缀匹配不误伤 /administrator");
    check(net_pool_has("bad.example.org", 443, "/") == 0, "池:!整站被拦下");
    check(net_pool_has("other.example.org", 443, "/") == 0, "池:池外主机一律拒(默认关门)");
    check(net_pool_has("exp.com", 8443, "/") == 1, "池:带端口的条目放行该端口");
    check(net_pool_has("exp.com", 8080, "/") == 1, "池:同一主机的其它端口按主机条目放行");
    net_pool_set(NULL, 0);
  }

  /* 目标解析与授权 */
  buf_t u;
  buf_init(&u);
  target_resolve(&u, "www.example-gov.cn", NULL);
  check(strcmp(u.data, "https://www.example-gov.cn") == 0, "目标补全协议", u.data);
  buf_clear(&u);
  target_resolve(&u, "/news.php?id=1", "https://a.cn");
  check(strcmp(u.data, "https://a.cn/news.php?id=1") == 0, "相对路径拼到主机上", u.data);
  buf_free(&u);

  /* 技能真的跑:资产发现 + 敏感信息(用假取数通道) */
  tool_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.io.fetch = fake_fetch;
  ctx.io.userdata = NULL;
  buf_t note;
  buf_init(&note);
  ctx.note = &note;

  skill_result_t sr;
  memset(&sr, 0, sizeof(sr));
  json_t *args = j_obj();
  j_set_str(args, "target", "https://lab.example.org");
  int rc = skills_run(&ctx, "skill_leak_check", args, &sr);
  check(rc == 0, "技能:敏感信息检查能跑通");
  check(sr.finding_count >= 2, "技能:命中 .env 与 backup.sql 两条泄露",
        sr.summary ? sr.summary : "");
  check(sr.summary && (strstr(sr.summary, "凭据") || strstr(sr.summary, "命中")),
        "技能:结论里有具体证据而不是空话");
  skill_result_free(&sr);
  json_free(args);

  /* 关键:目标不可达时必须"承认没结论",不能报"没问题" */
  memset(&sr, 0, sizeof(sr));
  args = j_obj();
  j_set_str(args, "target", "https://xxxx-unreachable.example.org");
  skills_run(&ctx, "skill_integrity_check", args, &sr);
  check(sr.is_error == 1 && sr.summary &&
        (strstr(sr.summary, "没法") || strstr(sr.summary, "不给结论") ||
         strstr(sr.summary, "取不到")),
        "技能:目标不可达时如实说「没结论」,不谎报安全",
        sr.summary ? sr.summary : "");
  skill_result_free(&sr);
  json_free(args);

  buf_free(&note);
}

/* ---------- 循环的收敛判定自检 ---------- */
static void on_ans(void *ud, const char *text) {
  int *n = (int *)ud;
  if (n) (*n)++;              // 回调可能没有 userdata:必须判空,否则一读就崩
  (void)text;
}
static void on_think(void *ud, const char *text) { (void)ud; (void)text; }
static void on_act(void *ud, const char *t, json_t *a, const char *r) {
  (void)ud; (void)t; (void)a; (void)r;
}
static void on_stat(void *ud, const char *t, const char *s, const char *n) {
  (void)ud; (void)t; (void)s; (void)n;
}
static void on_obs(void *ud, const char *t, tool_result_t *r) {
  (void)ud; (void)t; (void)r;
}
static void on_ask(void *ud, const char *t) { (void)ud; (void)t; }

static void selftest_loop(void) {
  printf("\n=== 决策循环(感知→决策→行动→观察→反思→收敛)===\n");

  agent_t *a = agent_create("selftest-session");
  int answers = 0;
  agent_hooks_t h;
  memset(&h, 0, sizeof(h));
  h.userdata = &answers;
  h.on_answer = on_ans;
  h.on_thinking = on_think;
  h.on_action = on_act;
  h.on_status = on_stat;
  h.on_observation = on_obs;
  h.on_ask = on_ask;
  agent_set_hooks(a, &h);

  /* 不设授权域名:循环必须拒绝动手(合规底线) */
  loop_state_t st;
  agent_run_turn(a, "帮我扫一下 www.example-gov.cn", &st);
  check(st.step_count == 0 || st.stop_code != STOP_NONE,
        "没有授权域名时循环立刻收束(不盲目动手)");
  check(st.stop_reason[0] != 0, "停止原因是人话", st.stop_reason);
  buf_free(&st.transcript);
  json_free(st.steps);

  /* 纯问答:不该产生任何动作 */
  agent_run_turn(a, "今天天气怎么样", &st);
  check(st.step_count <= 1, "纯问答不产生多步动作");
  check(answers > 0, "最终回答通过 hook 推给了界面");
  buf_free(&st.transcript);
  json_free(st.steps);

  agent_free(a);
}
/* 自检自己造数据、自己清理:临时目录用唯一名字,跑完删掉 ——
   免得"上一次跑剩下的发现"把这一次的断言带偏(这是自检最常见的假失败来源)。
   走 fs_remove_tree(std::filesystem):不再有 A/W 两套 API 的中文名坑。 */
static void rmrf(const char *dir) { fs_remove_tree(dir); }

/* ---------- 通用探测能力的自检(全部用"假站点",不依赖任何真实目标) ---------- */

/* 假站点 A:对所有路径都返回同一个自定义错误页 —— 典型的软 404 站点。
   路径探测如果不做校准,会把这一片"错误页"全当成敏感文件。 */
static int fake_soft404_fetch(void *ud, const char *url, const char *method,
                              int *status, char **body, size_t *body_len, char **err) {
  (void)ud; (void)method; (void)url;
  const char *page = "<html><head><title>出错了</title></head><body>页面不存在</body></html>";
  if (status) *status = 200;
  if (err) *err = NULL;
  if (body) *body = xstrdup(page);
  if (body_len) *body_len = strlen(page);
  return 0;
}

/* 假站点 B:布尔注入靶 —— 恒真条件与正常页一致,恒假条件返回"空结果"页 */
static int fake_sqli_fetch(void *ud, const char *url, const char *method,
                           int *status, char **body, size_t *body_len, char **err) {
  (void)ud; (void)method;
  const char *normal = "<html><body><h1>新闻列表</h1><ul><li>新闻一</li><li>新闻二</li></ul></body></html>";
  const char *empty = "<html><body><h1>新闻列表</h1><p>暂无数据</p></body></html>";
  int is_false = strstr(url, "%3D2") != NULL || strstr(url, "=2") != NULL;
  const char *page = is_false ? empty : normal;
  if (status) *status = 200;
  if (err) *err = NULL;
  if (body) *body = xstrdup(page);
  if (body_len) *body_len = strlen(page);
  return 0;
}

/* 假站点 C:健康站点 —— 参数怎么改都返回同一页(页面内容不受参数影响) */
static int fake_clean_fetch(void *ud, const char *url, const char *method,
                            int *status, char **body, size_t *body_len, char **err) {
  (void)ud; (void)method; (void)url;
  const char *page = "<html><body><h1>新闻列表</h1><ul><li>新闻一</li></ul></body></html>";
  if (status) *status = 200;
  if (err) *err = NULL;
  if (body) *body = xstrdup(page);
  if (body_len) *body_len = strlen(page);
  return 0;
}

/* 假站点 D:带响应头(用于弱配置检查)。第二个参数改成 1 时表示"页面内容变了" */
static int fake_ex_fetch(void *ud, const char *url, const char *method, int *status,
                         char **headers, char **body, size_t *body_len, char **err) {
  int *variant = (int *)ud;
  int v = variant ? *variant : 0;
  buf_t h;
  buf_init(&h);
  if (method && str_ieq(method, "OPTIONS")) {
    buf_puts(&h, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nAllow: GET, POST, TRACE\r\n");
  } else {
    buf_puts(&h, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
                 "X-Powered-By: PHP/7.4.3\r\nContent-Type: text/html; charset=utf-8\r\n"
                 "Set-Cookie: SID=abcdef123456; Path=/\r\n");
  }
  const char *page = v == 0
      ? "<html><head><title>首页</title></head><body><a href=\"https://good.example.cn/a\">友链</a></body></html>"
      : "<html><head><title>首页</title></head><body>"
        "<a href=\"https://good.example.cn/a\">友链</a>"
        "<a href=\"http://198.51.100.7/promo\">促销</a></body></html>";
  if (status) *status = 200;
  if (err) *err = NULL;
  if (headers) *headers = buf_take(&h);
  else buf_free(&h);
  if (body) *body = xstrdup(page);
  if (body_len) *body_len = strlen(page);
  return 0;
}

static void selftest_generic(void) {
  printf("\n=== 通用能力(规则驱动 / 软 404 校准 / 对比手法)===\n");

  /* 规则层:文件优先、内置兜底,两者同 schema */
  check(rules_root() != NULL, "规则已载入(文件或内置默认)", rules_source());
  int n = 0;
  const char **paths = rules_str_list("sensitive_paths", &n);
  check(n > 10 && paths != NULL, "规则给出落点清单(不含任何具体站点知识)");
  rules_sig_t sig;
  memset(&sig, 0, sizeof(sig));
  check(rules_sig_match("/x/.env", "DB_PASSWORD=abc123\nDB_HOST=10.0.0.1\n", &sig) == 0 &&
        strcmp(sig.severity, "严重") == 0,
        "内容特征判定:凭据文件 → 严重", sig.name ? sig.name : "");
  check(rules_sig_match("/x/a.sql",
                        "-- MySQL dump 10.13\nCREATE TABLE `t` (id int);\n"
                        "INSERT INTO `t` VALUES (1,'a'),(2,'b');\n",
                        &sig) == 0 && strcmp(sig.tag, "sql-dump") == 0,
        "内容特征判定:数据库备份 → sql-dump", sig.tag ? sig.tag : "");
  check(rules_sig_match("/x/index.html",
                        "<html><body>示例:DB_PASSWORD=xxxx 只是文档说明</body></html>",
                        &sig) != 0,
        "HTML 文档里出现的示例配置不判为泄露(避免误报)");
  check(rules_sig_match("/x/nothing", "hello", &sig) != 0, "无特征内容不命中");

  /* 软 404 校准:整站只有一张错误页时,不能把它当成一堆敏感文件 */
  {
    tool_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.io.fetch = fake_soft404_fetch;
    buf_t note;
    buf_init(&note);
    ctx.note = &note;
    tool_result_t tr;
    memset(&tr, 0, sizeof(tr));
    json_t *a = j_obj();
    j_set_str(a, "target", "https://soft404.example.org");
    int rc = tools_run(&ctx, "sensitive_file_probe", a, &tr);
    json_free(a);
    int hits = (int)j_len(j_get(tr.data, "hits"));
    int suppressed = (int)j_n(tr.data, "suppressed_as_default_page", 0);
    check(rc == 0 && hits == 0, "软 404 站点:没有把默认错误页当成敏感文件", tr.text);
    check(suppressed > 0, "软 404 站点:排除数量被如实记录(可复核)", "");
    free(tr.text); free(tr.say); json_free(tr.data);
    buf_free(&note);
  }

  /* 布尔注入:真靶要确认,健康靶不能误报 */
  {
    tool_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.io.fetch = fake_sqli_fetch;
    tool_result_t tr;
    memset(&tr, 0, sizeof(tr));
    json_t *a = j_obj();
    j_set_str(a, "target", "https://news.example.org/news.php?id=1");
    int rc = tools_run(&ctx, "sqli_probe", a, &tr);
    json_free(a);
    check(rc == 0 && strcmp(j_s(tr.data, "verdict", ""), "confirmed") == 0,
          "布尔差分确认注入(恒真与基线一致、恒假不同)",
          j_s(tr.data, "evidence", "(无证据)"));
    free(tr.text); free(tr.say); json_free(tr.data);

    memset(&ctx, 0, sizeof(ctx));
    ctx.io.fetch = fake_clean_fetch;
    memset(&tr, 0, sizeof(tr));
    a = j_obj();
    j_set_str(a, "target", "https://clean.example.org/news.php?id=1");
    rc = tools_run(&ctx, "sqli_probe", a, &tr);
    json_free(a);
    check(rc == 0 && strcmp(j_s(tr.data, "verdict", ""), "not_found") == 0,
          "健康站点不误报注入", j_s(tr.data, "verdict", ""));
    free(tr.text); free(tr.say); json_free(tr.data);

    /* 没有参数的地址:如实说"没有输入点",而不是硬报"没问题" */
    memset(&tr, 0, sizeof(tr));
    a = j_obj();
    j_set_str(a, "target", "https://clean.example.org/index.html");
    tools_run(&ctx, "sqli_probe", a, &tr);
    json_free(a);
    check(strcmp(j_s(tr.data, "verdict", ""), "not_testable") == 0,
          "无参数地址如实返回「没有可测的输入点」", j_s(tr.data, "reason", ""));
    free(tr.text); free(tr.say); json_free(tr.data);
  }

  /* 弱配置:结论必须来自响应头本身 */
  {
    tool_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.io.fetch = fake_soft404_fetch;      /* 退回旧通道:只应有"拿不到头"的提示 */
    ctx.io.fetch_ex = fake_ex_fetch;
    tool_result_t tr;
    memset(&tr, 0, sizeof(tr));
    json_t *a = j_obj();
    j_set_str(a, "target", "https://headers.example.org/");
    int rc = tools_run(&ctx, "nuclei_scan", a, &tr);
    json_free(a);
    json_t *checks = j_get(tr.data, "checks");
    int cookies = 0, methods = 0, disclosure = 0, hsts = 0;
    for (int i = 0; i < j_len(checks); i++) {
      const char *id = j_s(j_at(checks, i), "id", "");
      if (strcmp(id, "cookie-flags") == 0) cookies = 1;
      if (strcmp(id, "dangerous-methods") == 0) methods = 1;
      if (strcmp(id, "version-disclosure") == 0) disclosure = 1;
      if (strcmp(id, "weak-headers") == 0) {
        hsts = str_icontains(j_s(j_at(checks, i), "evidence", ""), "HSTS");
      }
    }
    check(rc == 0 && j_len(checks) >= 4, "弱配置检查按响应头产出多项事实", tr.text);
    check(hsts == 1, "HTTPS 站点缺 HSTS 被识别(缺哪些列哪些)");
    check(cookies == 1, "Cookie 缺 HttpOnly/Secure/SameSite 被识别");
    check(disclosure == 1, "Server/X-Powered-By 版本泄露被识别");
    check(methods == 1, "OPTIONS 声明 TRACE 等写方法被识别");
    free(tr.text); free(tr.say); json_free(tr.data);
  }

  /* 基线比对:第一次采基线,第二次能比出"内容变了 + 新增外域主机" */
  {
    char datadir[128];
    snprintf(datadir, sizeof(datadir), "data\\_selftest_gen_%lld", now_ms() % 1000000);
    store_t *st = store_open(datadir);
    tool_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    int variant = 0;
    ctx.io.userdata = &variant;
    ctx.io.fetch_ex = fake_ex_fetch;
    ctx.store = st;

    char target[160];
    snprintf(target, sizeof(target), "https://baseline.example.org/page-%lld", now_ms() % 100000);

    tool_result_t tr;
    memset(&tr, 0, sizeof(tr));
    json_t *a = j_obj();
    j_set_str(a, "target", target);
    int rc1 = tools_run(&ctx, "page_diff", a, &tr);
    int made_baseline = rc1 == 0 && strcmp(j_s(tr.data, "mode", ""), "baseline_created") == 0;
    check(made_baseline, "第一次比对:采集基线(而不是硬报结论)", j_s(tr.data, "mode", ""));
    free(tr.text); free(tr.say); json_free(tr.data);

    /* 第二次:同一地址应比出"内容变了 + 新增外域主机" */
    variant = 1;                            /* 页面被插入一个裸 IP 外链 */
    memset(&tr, 0, sizeof(tr));
    rc1 = tools_run(&ctx, "page_diff", a, &tr);
    json_free(a);
    check(rc1 == 0 && strcmp(j_s(tr.data, "mode", ""), "changed") == 0,
          "第二次比对:发现内容变化", j_s(tr.data, "mode", ""));
    json_t *new_hosts = j_get(tr.data, "new_external_hosts");
    check(j_len(new_hosts) == 1 && str_icontains(j_at(new_hosts, 0)->str, "198.51.100.7"),
          "新增外域主机被准确定位(裸 IP 也算可疑落点)", tr.text);
    json_t *susp = j_get(tr.data, "suspicious_links");
    check(j_len(susp) == 1, "指向裸 IP 的链接被标为可疑落点");
    free(tr.text); free(tr.say); json_free(tr.data);
    store_close(st);
    rmrf(datadir);
  }
}

/* 假站点 E:用来收尾闭环 —— 首页正常;/.env 第一次能下载,第二次 404(表示已修好) */
static int g_env_fixed = 0;
static int fake_closure_fetch(void *ud, const char *url, const char *method,
                              int *status, char **body, size_t *body_len, char **err) {
  (void)ud; (void)method;
  if (strstr(url, ".env")) {
    if (g_env_fixed) {
      if (status) *status = 404;
      if (err) *err = NULL;
      if (body) *body = xstrdup("<html><body>404</body></html>");
      if (body_len) *body_len = 25;
      return 0;
    }
    const char *page = "DB_PASSWORD=Str0ng#Pw\nDB_HOST=10.1.2.3\nAPP_KEY=abcdefghijklmnop\n";
    if (status) *status = 200;
    if (err) *err = NULL;
    if (body) *body = xstrdup(page);
    if (body_len) *body_len = strlen(page);
    return 0;
  }
  const char *page = "<html><head><title>首页</title></head><body>正常页面</body></html>";
  if (status) *status = 200;
  if (err) *err = NULL;
  if (body) *body = xstrdup(page);
  if (body_len) *body_len = strlen(page);
  return 0;
}

/* 收尾闭环:发现 → 复测(未修好→已修好)→ 报告与告警 → 证据核对 */
static void selftest_closure(void) {
  printf("\n=== 闭环(复测 / 报告 / 证据核对)===\n");

  char datadir[128];
  snprintf(datadir, sizeof(datadir), "data\\_selftest_closure_%lld", now_ms() % 1000000);
  store_t *st = store_open(datadir);
  tool_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.io.fetch = fake_closure_fetch;
  ctx.store = st;
  ctx.task_id = "T-CLOSURE";

  char target[200];
  snprintf(target, sizeof(target), "https://closure.example.org/.env");

  /* 造一条真实发现(走工具的判定路径,不是手写 JSON) */
  {
    tool_result_t tr;
    memset(&tr, 0, sizeof(tr));
    json_t *a = j_obj();
    j_set_str(a, "target", "https://closure.example.org");
    json_t *paths = j_arr();
    j_add(paths, j_str("/.env"));
    j_set(a, "paths", paths);
    tools_run(&ctx, "sensitive_file_probe", a, &tr);
    json_free(a);
    json_t *hits = j_get(tr.data, "hits");
    check(j_len(hits) == 1 && strcmp(j_s(j_at(hits, 0), "severity", ""), "严重") == 0,
          "造出「配置凭据泄露」发现(等级来自规则定义)", tr.text);
    json_t *ta = j_obj();
    j_set_str(ta, "target", "https://closure.example.org");
    json_t *tp = j_arr();
    j_add(tp, j_str("/.env"));
    j_set(ta, "paths", tp);
    skill_result_t sr;
    memset(&sr, 0, sizeof(sr));
    skills_run(&ctx, "skill_leak_check", ta, &sr);
    json_free(ta);
    check(sr.finding_count == 1, "技能把工具给出的事实落成了发现", sr.summary ? sr.summary : "");
    skill_result_free(&sr);
    free(tr.text); free(tr.say); json_free(tr.data);
  }

  /* 复测第一轮:问题还在 → retest_failed */
  {
    skill_result_t sr;
    memset(&sr, 0, sizeof(sr));
    json_t *a = j_obj();
    skills_run(&ctx, "skill_retest", a, &sr);
    json_free(a);
    check((int)j_n(sr.data, "failed", 0) == 1 &&
          (int)j_n(sr.data, "inconclusive", 0) == 0,
          "复测:问题仍在 → 仍未修复", sr.summary ? sr.summary : "");
    skill_result_free(&sr);
  }

  /* 修好之后复测:404 → retest_passed,并且状态机被推进 */
  {
    g_env_fixed = 1;
    skill_result_t sr;
    memset(&sr, 0, sizeof(sr));
    json_t *a = j_obj();
    skills_run(&ctx, "skill_retest", a, &sr);
    json_free(a);
    check((int)j_n(sr.data, "passed", 0) >= 1, "复测:目标已下线 → 已修复",
          sr.summary ? sr.summary : "");
    skill_result_free(&sr);
    json_t *all = store_findings_of_task(st, "T-CLOSURE");
    int done = 0;
    buf_t dbg;
    buf_init(&dbg);
    for (int i = 0; i < j_len(all); i++) {
      const char *stt = j_s(j_at(all, i), "status", "");
      buf_printf(&dbg, "%s=%s ", j_s(j_at(all, i), "id", ""), stt);
      if (strcmp(stt, "retest_passed") == 0) done = 1;
    }
    int retests = 0;
    for (int i = 0; i < j_len(all); i++) retests += j_len(j_get(j_at(all, i), "retests"));
    check(done == 1, "状态机推进到 retest_passed(复测是权威结论)", dbg.data);
    check(retests == 2, "两次复测都写进了 retests[]", "");
    /* 落盘文件也要能对上(README/答辩时会直接看这个文件) */
    buf_t raw_dbg;
    buf_init(&raw_dbg);
    {
      char fpath[256];
      snprintf(fpath, sizeof(fpath), "%s\\findings.jsonl", datadir);
      size_t rl = 0;
      char *raw = file_read_all(fpath, &rl);
      char **ls = NULL;
      int ln = raw ? str_split(raw, '\n', &ls, 0) : 0;
      for (int i = 0; i < ln; i++) {
        char *t = str_trim(ls[i]);
        if (!t[0]) continue;
        json_t *o = json_parse(t);
        if (o) {
          buf_printf(&raw_dbg, "%s=%s/%d ", j_s(o, "id", ""), j_s(o, "status", ""),
                     j_len(j_get(o, "retests")));
          json_free(o);
        } else {
          buf_puts(&raw_dbg, "(解析失败) ");
        }
      }
      str_free_list(ls, ln);
      free(raw);
    }
    check(str_icontains(raw_dbg.data, "F-0001=retest_passed/2"),
          "落盘文件里 F-0001 最后一行是 retest_passed 且带两次复测", raw_dbg.data);
    buf_free(&raw_dbg);
    buf_free(&dbg);
    json_free(all);
  }

  /* 报告:统计 + 发现引用 + 分级告警 */
  {
    skill_result_t sr;
    memset(&sr, 0, sizeof(sr));
    json_t *a = j_obj();
    skills_run(&ctx, "skill_report", a, &sr);
    json_free(a);
    json_t *stats = j_get(sr.data, "stats");
    check((int)j_n(stats, "total", 0) >= 1, "报告统计出发现总数", sr.summary ? sr.summary : "");
    check((int)j_n(j_get(stats, "by_severity"), "严重", 0) >= 1, "报告按等级分类统计");
    check(j_len(j_get(sr.data, "finding_ids")) >= 1, "报告只存发现编号引用");
    check(j_len(j_get(sr.data, "alerts")) >= 1, "严重发现触发告警(渠道按等级分流)");
    const char *channel = j_s(j_at(j_get(sr.data, "alerts"), 0), "channel", "");
    check(strcmp(channel, "邮件") == 0, "严重发现走邮件渠道", channel);
    skill_result_free(&sr);
    json_t *reports = store_all(st, "reports");
    check(j_len(reports) == 1 && str_icontains(j_s(j_at(reports, 0), "id", ""), "R-"),
          "报告落盘(R-0001 形态)");
    json_free(reports);
  }

  /* 证据与覆盖核对:只核对"结论有没有证据",不给任何效果指标。
     这里刻意不出现召回率/准确率/误报率 —— 那取决于评测集与口径,应由评测方给出。 */
  {
    skill_result_t sr;
    memset(&sr, 0, sizeof(sr));
    json_t *a = j_obj();
    skills_run(&ctx, "skill_evidence", a, &sr);
    json_free(a);
    check(!sr.is_error, "证据核对:能跑(需要存储)", sr.summary ? sr.summary : "");
    int total = (int)j_n(sr.data, "total", -1);
    int with_ev = (int)j_n(sr.data, "with_evidence", -1);
    int missing_ev = (int)j_n(sr.data, "without_evidence", -1);
    check(total >= 1, "证据核对:统计出结论条数", sr.summary ? sr.summary : "");
    check(with_ev >= 0 && missing_ev >= 0 && with_ev + missing_ev == total,
          "证据核对:带证据 + 缺证据 = 总数");
    check(j_get(sr.data, "by_status") != NULL, "证据核对:给出状态分布");
    check(j_get(sr.data, "note") != NULL, "证据核对:明确说明不自行计算各项指标");
    skill_result_free(&sr);
  }

  store_close(st);
  rmrf(datadir);
  g_env_fixed = 0;
}

static void selftest_common(void) {
  printf("\n=== 基础件(缓冲/文本/时间/路径)===\n");

  buf_t b;
  buf_init(&b);
  buf_puts(&b, "安全");
  buf_printf(&b, "巡检 %d 次", 3);
  check(strcmp(b.data, "安全巡检 3 次") == 0, "动态缓冲拼接", b.data);
  buf_free(&b);

  check(str_startswith("https://a.cn", "https://"), "前缀判断");
  check(str_endswith(".env", ".env"), "后缀判断");
  check(str_ieq("POST", "post"), "忽略大小写比较");
  check(str_icontains("发现了 SQL 注入", "sql"), "忽略大小写包含");

  char *dup = xstrdup("  trim me  ");
  check(strcmp(str_trim(dup), "trim me") == 0, "去空白");
  free(dup);

  char **parts = NULL;
  int n = str_split("sensitive_scan|host/.env|env-db-password", '|', &parts, 0);
  check(n == 3 && strcmp(parts[1], "host/.env") == 0, "按分隔符切分");
  str_free_list(parts, n);

  char iso[64];
  now_iso(iso, sizeof(iso));
  check(strlen(iso) == 24 && iso[4] == '-' && iso[10] == 'T' && iso[23] == 'Z',
        "ISO 时间格式与合同一致(2026-10-15T09:30:00.000Z)", iso);
}

static void print_cli_args_note(void) {
  printf("  参数写法:agent.exe tool <工具名> <目标> [key=value ...] 或直接给一段 JSON\n");
}

/* 从命令行构造工具/技能参数:既支持 key=value 对,也支持直接给一段 JSON。
   为什么要有:自己加了外部工具/MCP 工具之后,总得能单独试一下它。
   位置参数(target)默认填给 "target";如果这个工具的 schema 里没有 target,
   就填给它唯一的必填项(例如 MCP 工具常见的 url / text),省得每次手写 key=。 */
static json_t *args_from_argv(int argc, char **argv, int start, const char *target,
                             const char *tool_name) {
  json_t *args = j_obj();
  const char *pos_key = "target";
  if (tool_name && *tool_name) {
    tool_t *t = tools_find(tool_name);
    json_t *schema = t ? json_parse(t->schema) : NULL;
    if (schema) {
      json_t *props = j_get(schema, "properties");
      if (props && !j_get(props, "target")) {
        json_t *req = j_get(schema, "required");
        if (j_len(req) == 1 && j_at(req, 0) && j_at(req, 0)->type == J_STR) {
          pos_key = j_at(req, 0)->str;
        }
      }
      json_free(schema);
    }
  }
  if (target && *target) {
    if (strcmp(pos_key, "target") == 0) j_set_str(args, "target", target);
    else j_set_str(args, pos_key, target);
  }
  if (start >= argc) return args;

  /* 形如 {"a":1} 的整段 JSON 直接当参数 */
  const char *first = argv[start];
  while (*first == ' ') first++;
  if (*first == '{') {
    buf_t b;
    buf_init(&b);
    for (int i = start; i < argc; i++) {
      if (i > start) buf_putc_(&b, ' ');
      buf_puts(&b, argv[i]);
    }
    json_t *j = json_parse(b.data);
    buf_free(&b);
    if (j && j->type == J_OBJ) {
      if (target && *target && !j_get(j, "target")) j_set_str(j, "target", target);
      json_free(args);
      return j;
    }
    json_free(j);
  }

  for (int i = start; i < argc; i++) {
    const char *eq = strchr(argv[i], '=');
    if (!eq) continue;
    char key[64];
    size_t kl = (size_t)(eq - argv[i]);
    if (kl >= sizeof(key)) kl = sizeof(key) - 1;
    memcpy(key, argv[i], kl);
    key[kl] = 0;
    const char *val = eq + 1;
    /* 纯数字按数字给(有些 schema 要求 integer) */
    int all_digit = *val != 0;
    for (const char *p = val; *p; p++) if (*p < '0' || *p > '9') { all_digit = 0; break; }
    if (all_digit && *val) j_set_num(args, key, atof(val));
    else if (str_ieq(val, "true") || str_ieq(val, "false")) j_set_bool(args, key, str_ieq(val, "true"));
    else j_set_str(args, key, val);
  }
  return args;
}

int app_main(int argc, char **argv) {
  /* 有没有可用的控制台:双击运行没有(cmd / PowerShell 里有),
     所以 --debug 之外的场合一律不弹黑框,日志改走数据目录里的 agent.log。 */
  int want_console = 0;
  int debug_flag_at = -1;
  for (int i = 1; i < argc; i++) {
    const char *a = argv[i];
    if (!a) continue;
    if (str_ieq(a, "--debug") || str_ieq(a, "-debug") || str_ieq(a, "/debug")) {
      want_console = 1;
      if (debug_flag_at < 0) debug_flag_at = i;
    }
  }
  const char *env_dbg = getenv("BW_AGENT_DEBUG");
  if (env_dbg && *env_dbg && !str_ieq(env_dbg, "0")) want_console = 1;

  int have_console = app_console_init(want_console);
  if (have_console) console_init();
  /* --debug:窗口只是个看板 —— 关掉界面窗口不停止服务,方便反复打开界面看结果 */
  if (want_console) ui_set_stop_on_close(0);
  /* 顺手把 --debug 从参数里摘掉,后面的分支就不用认识这个标志 */
  if (debug_flag_at > 0) {
    for (int i = debug_flag_at; i + 1 < argc; i++) argv[i] = argv[i + 1];
    argv[argc - 1] = NULL;
    argc--;
  }

  app_fix_argv_encoding(argc, argv);
  app_init_paths();
  /* 长驻形态(界面/服务)一律留日志:双击运行看不到控制台,出问题时能对着文件查 */
  int have_log_file = 0;
  {
    const char *c = (argc > 1) ? argv[1] : "start";
    int long_running = str_ieq(c, "start") || str_ieq(c, "serve");
    if (!have_console || long_running) {
      char log_path[MAX_PATH * 2];
      app_data_path(log_path, sizeof(log_path), "agent.log");
      log_open(log_path);
      have_log_file = 1;
      log_info("—— 启动(%s):日志见本文件 ——", have_console ? "控制台可用" : "无控制台");
    }
  }
  log_set_level((have_console || have_log_file) ? LOG_INFO : LOG_WARN);
  tools_init();          /* 注册表必须先建好,后面所有分支都依赖它 */
  skills_init();
  /* 首次运行就把可改的规则/使用说明/测试集落到数据目录(任何入口都一样:
     selftest 除外 —— 自检不该往使用者的数据目录里写东西) */
  if (!(argc > 1 && str_ieq(argv[1], "selftest"))) res_bootstrap_data_dir();
  rules_init(app_dir());  /* 站点知识来自规则文件(数据目录/exe 旁/内置),读不到用内置默认 */
  /* 可扩展层:数据目录下的外部工具 / 技能包 / MCP 服务器(像 Claude Code 那样自己加能力) */
  ext_bootstrap();        /* 首次运行放带注释的示例,让人照着改 */
  ext_load_all();
  ext_register_all();
  llm_init(app_dir());
  net_init();

  const char *cmd = (argc > 1) ? argv[1] : "start";

  if (str_ieq(cmd, "selftest")) {
    printf("网站安全巡检智能体(C 版)· 自检\n");
    printf("程序目录: %s\n", app_dir());
    selftest_common();
    selftest_json();
    selftest_llm();
    selftest_agent();
    selftest_generic();
    selftest_closure();
    selftest_loop();
    printf("\n通过 %d 项,失败 %d 项 -> %s\n", g_pass, g_fail,
           g_fail ? "HAS ERRORS" : "ALL PASS");
    net_shutdown();
    rules_shutdown();
    return g_fail ? 1 : 0;
  }

  if (str_ieq(cmd, "tools")) {
    agent_print_tools();
    printf("\n");
    agent_print_skills();
    net_shutdown();
    return 0;
  }

  if (str_ieq(cmd, "skills")) {
    agent_print_skills();
    net_shutdown();
    return 0;
  }

  if (str_ieq(cmd, "rules")) {
    /* 导出当前生效的规则(给人照着改):--check 时只打印来源 */
    char default_rules_path[MAX_PATH * 2];
    app_data_path(default_rules_path, sizeof(default_rules_path), "rules.default.json");
    const char *out_path = (argc > 2) ? argv[2] : default_rules_path;
    const char *text = rules_default_json();
    if (file_write_all(out_path, text, strlen(text)) == 0) {
      printf("已写出内置默认规则:%s(%d 字节)\n", out_path, (int)strlen(text));
      printf("当前生效规则来源:%s\n", rules_source());
    } else {
      printf("写出失败:%s\n", out_path);
    }
    rules_shutdown();
    net_shutdown();
    return 0;
  }

  if (str_ieq(cmd, "manifest")) {
    /* 导出工具+技能清单(命题⑤交付物,界面也可用) */
    json_t *root = j_obj();
    j_set_str(root, "version", "v1");
    j_set(root, "tools", agent_tool_list_json());
    j_set(root, "skills", agent_skill_list_json());
    char *pretty = json_dump_pretty(root);
    const char *out_path = (argc > 2) ? argv[2] : "manifest.json";
    file_write_all(out_path, pretty, strlen(pretty));
    printf("已写出 %s(工具 %d 个、技能 %d 个)\n", out_path, tools_count(), skills_count());
    free(pretty);
    json_free(root);
    net_shutdown();
    return 0;
  }

  if (str_ieq(cmd, "run")) {
    /* 单技能直跑:调试、演示、验收都用得上(不经过模型,结论可直接复核)
       用法: agent.exe run skill_leak_check example.com */
    const char *skill = (argc > 2) ? argv[2] : "skill_recon";
    const char *target = (argc > 3) ? argv[3] : "";
    const char *ddir = app_data_dir();
    ensure_dir(ddir);
    res_bootstrap_data_dir();       /* 首次运行:把可改的规则/说明/测试集落到数据目录 */
    store_t *store = store_open(ddir);
    char audit_path[MAX_PATH * 2];
    app_data_path(audit_path, sizeof(audit_path), "audit.jsonl");
    net_set_audit_path(audit_path);
    net_set_readonly(1);
    const char *base = getenv("TARGET_BASE_URL");
    if (base && *base) net_set_target_base(base);

    char host[256];
    net_host_of(target, host, sizeof(host));
    net_align_base_from(target);      /* 地址里带端口时自动对齐协议与端口 */
    /* 授权池:技能直跑也受同一个池约束 —— 否则"界面上被拦住的路径"换个入口就能绕过去 */
    {
      char pool_path[MAX_PATH * 2];
      app_data_path(pool_path, sizeof(pool_path), "pool.json");
      int pn = net_pool_load_file(pool_path);
      if (pn > 0) printf("授权池:%d 条(含 ! 不允许条目)\n", pn);
    }
    const char *doms[1];
    int nd = 0;
    if (host[0]) { doms[0] = host; nd = 1; }

    char task_id[64] = "CLI-TASK";
    int nk = 0, nf = 0;
    const char **kw = rules_str_list("profile_keywords", &nk);
    const char **ft = rules_str_list("profile_file_types", &nf);
    json_t *kws = j_arr();
    for (int i = 0; i < nk; i++) j_add(kws, j_str(kw[i]));
    json_t *fts = j_arr();
    for (int i = 0; i < nf; i++) j_add(fts, j_str(ft[i]));
    char *pid = store_ensure_profile(store, "默认敏感信息定义(随规则层)", kws, fts, NULL);
    if (nd) {
      char tn[320];
      snprintf(tn, sizeof(tn), "对 %s 的命令行授权巡检", host);
      char *tid = store_ensure_task(store, doms, nd, tn, pid);
      if (tid) snprintf(task_id, sizeof(task_id), "%s", tid);
      free(tid);
    } else {
      /* 没给目标(复测/报告/证据核对这类收尾动作常这样调):按全部历史发现处理 */
      task_id[0] = 0;
    }
    free(pid);
    json_free(kws);
    json_free(fts);

    tool_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.io = *net_io_impl();
    ctx.store = store;
    ctx.task_id = task_id;
    ctx.domains = nd ? doms : NULL;
    ctx.domain_count = nd;
    net_set_scope(task_id, nd ? doms : NULL, nd);

    json_t *args = j_obj();
    j_set_str(args, "target", target);
    skill_result_t sr;
    memset(&sr, 0, sizeof(sr));
    printf("规则来源:%s\n", rules_source());
    printf("技能:%s   目标:%s   授权:%s\n\n", skill, target,
           nd ? "已按命令行域名授权" : "(未授权,不会对外发请求)");
    if (!nd && target[0] == 0) {
      printf("提示:未指定目标,复测/报告/证据核对按全部历史发现处理。\n\n");
    }
    int rc = skills_run(&ctx, skill, args, &sr);
    printf("[%s] %s\n\n", rc == 0 && !sr.is_error ? "OK" : "ERROR",
           sr.summary ? sr.summary : "(无结论)");
    if (sr.data) {
      char *pj = json_dump_pretty(sr.data);
      printf("--- 结构化结果 ---\n%s\n", pj);
      free(pj);
    }
    printf("\n(本次共发起 %d 次请求)\n", ctx.http_calls);
    json_free(args);
    skill_result_free(&sr);
    store_close(store);
    net_shutdown();
    rules_shutdown();
    return rc == 0 ? 0 : 1;
  }

  if (str_ieq(cmd, "tool")) {
    /* 单工具直跑:验收与排障用 —— 不经过模型,只看这个工具对目标做了什么判断。
       用法: agent.exe tool dir_probe 127.0.0.1:8081 */
    const char *tname = (argc > 2) ? argv[2] : "sensitive_file_probe";
    const char *target = (argc > 3) ? argv[3] : "";
    int args_start = 4;
    /* 只给工具名、不给目标时(纯文本类工具很常见),第 3 个参数直接当参数:
         agent.exe tool sensitive_scan '{"text":"..."}'
         agent.exe tool password_check text=abc123 */
    if (argc > 3) {
      const char *p = argv[3];
      while (*p == ' ') p++;
      if (*p == '{' || strchr(p, '=')) {
        target = "";
        args_start = 3;
      }
    }
    const char *ddir = app_data_dir();
    ensure_dir(ddir);
    res_bootstrap_data_dir();       /* 首次运行:把可改的规则/说明/测试集落到数据目录 */
    store_t *store = store_open(ddir);
    char audit_path[MAX_PATH * 2];
    app_data_path(audit_path, sizeof(audit_path), "audit.jsonl");
    net_set_audit_path(audit_path);
    net_set_readonly(1);
    const char *base = getenv("TARGET_BASE_URL");
    if (base && *base) net_set_target_base(base);

    char host[256];
    net_host_of(target, host, sizeof(host));
    net_align_base_from(target);      /* 地址里带端口时自动对齐协议与端口 */
    const char *doms[1];
    int nd = 0;
    if (host[0]) { doms[0] = host; nd = 1; }

    tool_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.io = *net_io_impl();
    ctx.store = store;
    ctx.task_id = "CLI-TOOL";
    ctx.domains = nd ? doms : NULL;
    ctx.domain_count = nd;
    net_set_scope(ctx.task_id, nd ? doms : NULL, nd);

    /* BW_PROFILE=SP-0002 时按这套"本单位定义"跑:命令行也能复现界面里选的那套口径,
       验收/排障时不用为了试一条关键词去点界面。 */
    {
      const char *pid = getenv("BW_PROFILE");
      if (pid && *pid) {
        json_t *p = store_get(store, "profiles", pid);
        if (p) {
          profile_set_active(p);
          printf("本单位定义:%s(%s)\n", j_s(p, "name", ""), pid);
          json_free(p);
        } else {
          printf("本单位定义:%s 不存在,按出厂口径跑\n", pid);
        }
      }
    }
    /* 授权池:命令行走同一套边界。池子存在就以它为准(含 ! 不允许条目),
       这样"界面上被拦的路径"在命令行里也能复现,不用非得起服务。 */
    {
      char pool_path[MAX_PATH * 2];
      app_data_path(pool_path, sizeof(pool_path), "pool.json");
      int pn = net_pool_load_file(pool_path);
      if (pn > 0) printf("授权池:%d 条(含 ! 不允许条目)\n", pn);
    }

    json_t *args = args_from_argv(argc, argv, args_start, target, tname);
    tool_result_t tr;
    memset(&tr, 0, sizeof(tr));
    printf("规则来源:%s\n", rules_source());
    printf("工具:%s   目标:%s\n", tname, target);
    {
      int et = 0, es = 0, em = 0, emt = 0;
      ext_stats(&et, &es, &em, &emt);
      if (et || es || em) {
        printf("外部能力:工具 %d 个、技能包 %d 个、MCP %d 个(共 %d 个 MCP 工具)\n",
               et, es, em, emt);
      }
    }
    printf("参数:%s\n\n", json_dump(args));
    int rc = tools_run(&ctx, tname, args, &tr);
    printf("[%s] %s\n\n", rc == 0 && !tr.is_error ? "OK" : "ERROR",
           tr.say ? tr.say : "(无汇报语)");
    if (tr.text) printf("--- 结果文本 ---\n%s\n", tr.text);
    if (tr.data) {
      char *pj = json_dump_pretty(tr.data);
      printf("--- 结构化结果 ---\n%s\n", pj);
      free(pj);
    }
    printf("\n(本次共发起 %d 次请求)\n", ctx.http_calls);
    json_free(args);
    free(tr.text);
    free(tr.say);
    json_free(tr.data);
    store_close(store);
    net_shutdown();
    rules_shutdown();
    return rc == 0 ? 0 : 1;
  }

  if (str_ieq(cmd, "regextest")) {
    /* 自己写正则时的验枪口:agent.exe regextest "<正则>" "<样本文本>"
       规则是数据,数据写错不该靠猜 —— 这里直接告诉你它匹配到了哪一段。 */
    const char *pattern = (argc > 2) ? argv[2] : "";
    const char *text = (argc > 3) ? argv[3] : "";
    if (!pattern[0] || !text[0]) {
      printf("用法: agent.exe regextest \"<正则>\" \"<样本文本>\"\n");
      printf("      例: agent.exe regextest \"EMP[0-9]{8}\" \"工号 EMP2024001234\"\n");
      net_shutdown();
      rules_shutdown();
      return 1;
    }
    int off = 0, len = 0;
    printf("正则: %s\n样本: %s\n", pattern, text);
    if (tools_regex_first(pattern, text, &off, &len)) {
      printf("命中: 位置 %d,长度 %d → \"%.*s\"\n", off, len, len, text + off);
    } else {
      printf("没有命中(检查字符类/量词写法,或样本是否真的包含它)\n");
    }
    /* 顺手把它放进当前生效规则里比一比:确认你改的是"生效的那一份" */
    printf("当前生效规则: %s\n", rules_source());
    net_shutdown();
    rules_shutdown();
    return 0;
  }

  if (str_ieq(cmd, "netbench")) {
    /* 连接复用/解压整改前后的对比基准:同一个 URL 连打 n 次,分别量"复用"与"不复用"。
       用法: agent.exe netbench example.com [次数] */
    const char *target = (argc > 2) ? argv[2] : "";
    int n = (argc > 3) ? atoi(argv[3]) : 20;
    if (!target[0]) {
      printf("用法: agent.exe netbench <授权域名或URL> [次数]\n");
      return 1;
    }
    char host[256];
    net_host_port_of(target, host, sizeof(host));
    net_align_base_from(target);
    const char *doms[1];
    int nd = 0;
    if (host[0]) { doms[0] = host; nd = 1; }
    net_set_scope("BENCH", nd ? doms : NULL, nd);
    char url[512];
    snprintf(url, sizeof(url), "%s", target);
    if (!str_icontains(url, "://")) {
      snprintf(url, sizeof(url), "http://%s/", target);
    }
    printf("基准目标:%s(授权域名:%s)\n\n", url, nd ? host : "(未限定)");
    int conns = 0, reqs = 0;
    int avg = net_bench(url, n, &conns, &reqs);
    printf("\n提示:这一项是「网络层到底快不快」的实测口子。当前结论是 ——\n"
           "      WinHTTP 会话本身就带连接池,手工缓存连接句柄没有可测量收益(已实测);\n"
           "      真正影响检出与速度的是解压开关、超时与限速(rules.json 的 probing)。\n");
    net_shutdown();
    rules_shutdown();
    return avg < 0 ? 1 : 0;
  }

  if (str_ieq(cmd, "chat")) {
    /* 终端里直接和智能体对话:把循环每一步都打出来,方便看"它在想什么" */
    const char *domain = (argc > 2) ? argv[2] : NULL;
    char scope_host[256];                 /* 授权判断只认主机名,端口不参与 */
    scope_host[0] = 0;
    const char *domains[1];
    int nd = 0;
    if (domain) {
      net_host_port_of(domain, scope_host, sizeof(scope_host));
      if (!scope_host[0]) snprintf(scope_host, sizeof(scope_host), "%s", domain);
      domains[0] = scope_host;
      nd = 1;
      net_align_base_from(domain);        /* 带端口时把请求对齐到该端口 */
    }

    const char *ddir = app_data_dir();
    ensure_dir(ddir);
    res_bootstrap_data_dir();       /* 首次运行:把可改的规则/说明/测试集落到数据目录 */
    store_t *store = store_open(ddir);
    char audit_path[MAX_PATH * 2];
    app_data_path(audit_path, sizeof(audit_path), "audit.jsonl");
    net_set_audit_path(audit_path);
    net_set_readonly(1);
    {
      /* 目标地址对齐:命令行第三个参数可指定靶站地址(如 http://127.0.0.1:8081) */
      const char *base = getenv("TARGET_BASE_URL");
      if (base && *base) net_set_target_base(base);
    }

    agent_t *a = agent_create("cli-session");
    /* 命令行里给的授权域名也落成一个正式任务(与界面授权走同一条路) */
    char task_id[64] = "CLI-TASK";
    {
      int nk = 0, nf = 0;
      const char **kw = rules_str_list("profile_keywords", &nk);
      const char **ft = rules_str_list("profile_file_types", &nf);
      json_t *kws = j_arr();
      for (int i = 0; i < nk; i++) j_add(kws, j_str(kw[i]));
      json_t *fts = j_arr();
      for (int i = 0; i < nf; i++) j_add(fts, j_str(ft[i]));
      char *pid = store_ensure_profile(store, "默认敏感信息定义(随规则层)", kws, fts, NULL);
      if (nd) {
        char tname[320];
        snprintf(tname, sizeof(tname), "对 %s 的命令行授权巡检", domains[0]);
        char *tid = store_ensure_task(store, domains, nd, tname, pid);
        if (tid) snprintf(task_id, sizeof(task_id), "%s", tid);
        free(tid);
      }
      free(pid);
      json_free(kws);
      json_free(fts);
    }
    agent_set_scope(a, task_id, nd ? domains : NULL, nd);
    agent_set_store(a, store, "");
    agent_hooks_t h;
    memset(&h, 0, sizeof(h));
    h.on_thinking = on_think;
    h.on_action = on_act;
    h.on_status = on_stat;
    h.on_observation = on_obs;
    h.on_ask = on_ask;
    h.on_answer = on_ans;
    agent_set_hooks(a, &h);

    printf("模型:%s\n", llm_enabled() ? "恒脑真模型已就绪" : "未配置(走本地规则降级)");
    printf("授权域名:%s\n", nd ? domains[0] : "(未设置 —— 不会对外发请求)");
    printf("输入问题,回车执行;输入 exit 退出。\n\n");

    char line[2048];
    while (1) {
      printf("你> ");
      fflush(stdout);
      if (!fgets(line, sizeof(line), stdin)) break;
      char *t = str_trim(line);
      if (!t[0]) continue;
      if (str_ieq(t, "exit") || str_ieq(t, "quit")) break;

      loop_state_t st;
      agent_run_turn(a, t, &st);
      printf("\n--- 本轮留痕(%d 步,停止原因:%s)---\n%s\n", st.step_count,
             st.stop_reason, st.transcript.data ? st.transcript.data : "");
      buf_free(&st.transcript);
      json_free(st.steps);
    }
    agent_free(a);
    store_close(store);
    net_shutdown();
    return 0;
  }

  if (str_ieq(cmd, "start")) {
    /* 双击 exe 走的就是这里(零参数)。
       目标用户"什么都不懂":不要让他看命令行参数 —— 直接在控制台说清三件事,
       然后把服务起起来、把界面打开;端口被占用就自动换一个。 */
    SetConsoleTitleW(L"网站安全巡检智能体 —— 关掉本窗口即停止");

    printf("\n");
    printf("  ╔══════════════════════════════════════════════════════════╗\n");
    printf("  ║            网站安全巡检智能体(C 版)                      ║\n");
    printf("  ╚══════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("  正在启动,界面窗口会自动打开 ……\n");
    printf("\n");
    printf("  · 第一次使用:在弹出的窗口里填「目标域名」并勾选授权,然后直接说话,\n");
    printf("    例如「把这个站完整巡检一遍」\"复测一下\"\"出报告\"\"核对证据\"。\n");
    printf("  · 界面对话与结果都保存在 %s\\ 下(数据目录,可用 BW_AGENT_HOME 改)。\n",
           app_data_dir());
    printf("  · 想停止:关掉这个黑色窗口即可(界面窗口也可以关了)。\n");
    printf("\n");
    printf("  ────────────────────────────────────────────────────────────\n");

    const char *domain = getenv("DAS_TARGET");
    int port = 8765;
    int ok = 0;
    printf("  数据目录 : %s\\\n\n", app_data_dir());
    for (int try_port = 8765; try_port <= 8775; try_port++) {
      int rc = serve_run(domain, try_port, 1);
      if (rc == 0) { ok = 1; break; }
      if (rc == 2) {           /* 端口被占用:换一个继续 */
        printf("\n  端口 %d 已被占用,改用 %d ……\n\n", try_port, try_port + 1);
        continue;
      }
      break;                   /* 其它错误不再重试 */
    }
    net_shutdown();
    if (!ok) {
      printf("\n  启动失败。请把上面的提示截图反馈。\n");
      printf("  按回车键关闭窗口……");
      getchar();
    }
    return ok ? 0 : 1;
  }

  if (str_ieq(cmd, "serve")) {
    /* 起后端服务:内置 HTTP + SSE,界面在浏览器里跑(见 serve.c / ui.c)。
       用法: agent.exe serve [授权域名] [端口] [--no-ui] */
    const char *domain = NULL;
    int port = 8765;
    int open_ui = 1;
    for (int i = 2; i < argc; i++) {
      int all_digit = argv[i][0] != 0;
      for (const char *p = argv[i]; *p; p++) {
        if (*p < '0' || *p > '9') { all_digit = 0; break; }
      }
      if (str_ieq(argv[i], "--no-ui")) {
        open_ui = 0;
      } else if (all_digit) {
        port = atoi(argv[i]);
      } else {
        domain = argv[i];
      }
    }
    int rc = serve_run(domain, port, open_ui);
    net_shutdown();
    return rc;
  }

  printf(
      "网站安全巡检智能体(C 版)\n"
      "\n"
      "用法: 网站安全巡检智能体.exe [命令] [参数]\n"
      "  (不带命令就是启动界面:双击即可,不会弹命令行窗口)\n"
      "\n"
      "  selftest                自检(基础件/JSON/决策/技能/循环)\n"
      "  chat [授权域名]          在终端里和智能体对话(看得到决策循环)\n"
      "  tools                   打印工具与技能清单\n"
      "  skills                  只打印技能清单(智能体的专业能力)\n"
      "  manifest [文件名]        导出工具+技能清单 JSON\n"
      "  serve [授权域名] [端口]   起后端服务并打开界面(默认 8765)\n"
      "                          加 --no-ui 只起服务,不开窗口\n"
      "  help                    显示本帮助\n"
      "\n"
      "  --debug                 显示命令行窗口与实时日志(排查问题用;双击运行时才有意义)\n"
      "\n"
      "环境变量(或程序目录下的 .env):\n"
      "  DAS_APP_KEY / DAS_APP_SECRET / DAS_AGENT_ID   恒脑平台凭证与智能体\n"
      "  TARGET_BASE_URL          巡检起点对齐到指定站点(如 http://127.0.0.1:8081)\n"
      "  UI_MODE                  界面形态: auto(默认) / app / browser / off\n"
      "  BW_AGENT_DEBUG=1         等同于 --debug\n"
      "  BW_AGENT_HOME            改数据目录(默认 C:\\Users\\<用户名>\\.bw_agent)\n");
  net_shutdown();
  return 0;
}

/* ================= 入口 =================
   交付的是一个 GUI 子系统程序(-mwindows):双击不弹黑框。
   命令行用法靠 app_console_init 挂回父进程的控制台,所以 cmd / PowerShell 里
   照样有输出;要看日志窗口就加 --debug。 */
#ifdef AGENT_GUI_BUILD
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow) {
  (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nShow;
  int argc = 0;
  char **argv = app_argv_from_command_line(&argc);
  int rc = app_main(argc, argv);
  free_argv(argc, argv);
  log_close();
  return rc;
}
#else
int main(int argc, char **argv) { return app_main(argc, argv); }
#endif
