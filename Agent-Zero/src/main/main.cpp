/* main.cpp —— 命令行入口。
   先把它当成"装配台":每个子系统都暴露一个 selftest,合起来就是整体自检。 */
#include "agent.h"
#include "common.h"
#include "ext.h"
#include "instance.h"
#include "json.h"
#include "llm.h"
#include "net.h"
#include "approval.h"
#include "profile.h"
#include "res.h"
#include "rules.h"
#ifndef BW_RELEASE
#include "selftest.h"
#endif
#include "serve.h"
#include "skills.h"
#include "store.h"
#include "tools.h"

int toolhost_run(const char *tool_arg);
#include "ui.h"
#include "webutil.h"

#include <ctype.h>
/* 命令行对话模式的回调:把循环的每一步直接打在控制台上。
   界面走的是 SSE,这里走 stdout —— 同一套钩子,两种观众。 */
static void cli_on_answer(void *ud, const char *text) {
  (void)ud;
  printf("\n%s\n\n", text ? text : "");
}
static void cli_on_thinking(void *ud, const char *text) {
  (void)ud;
  printf("· 思考:%s\n", text ? text : "");
}
static void cli_on_action(void *ud, const char *tool, json_t *args, const char *reason) {
  (void)ud;
  char *dump = args ? json_dump(args) : NULL;
  printf("· 动作:%s %s%s%s\n", tool ? tool : "", dump ? dump : "",
         (reason && *reason) ? "  —— " : "", (reason && *reason) ? reason : "");
  free(dump);
}
static void cli_on_status(void *ud, const char *tool, const char *status, const char *note) {
  (void)ud;
  if (note && *note) printf("· 状态:%s %s —— %s\n", tool ? tool : "", status ? status : "", note);
}
static void cli_on_observation(void *ud, const char *tool, tool_result_t *r) {
  (void)ud;
  const char *first = (r && r->text) ? r->text : "";
  printf("· 观察:%s %s%s\n", tool ? tool : "", (r && r->is_error) ? "[失败] " : "",
         first);
}
static void cli_on_ask(void *ud, const char *text) {
  (void)ud;
  printf("· 需要你补充:%s\n", text ? text : "");
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

/* 高 DPI:必须在任何窗口创建之前声明。
   不声明时 Windows 会把整个窗口当位图拉伸(App 里看到的"字有点糊"就是这个),
   声明了才是按物理像素画。
   优先 per-monitor v2(拖到另一块缩放比不同的屏也不糊),老系统退回系统级。
   清单文件里已经声明过一次,这里是第二道保险(清单被工具链吞掉时仍然生效)。 */
static void set_dpi_aware(void) {
  HMODULE u = GetModuleHandleW(L"user32.dll");
  typedef BOOL(WINAPI * set_ctx_fn)(HANDLE);
  set_ctx_fn set_ctx =
      dll_sym<set_ctx_fn>(u, "SetProcessDpiAwarenessContext");
  if (set_ctx) {
    if (set_ctx((HANDLE)-4)) return;   /* DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 */
    if (set_ctx((HANDLE)-3)) return;   /* DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE */
  }
  SetProcessDPIAware();               /* Vista 起就有 */
}

int app_main(int argc, char **argv) {
  set_dpi_aware();
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
  /* 工具宿主:stdout 只留给结果 JSON,日志别混进来 */
  if (argc > 1 && str_ieq(argv[1], "toolhost")) freopen("NUL", "w", stderr);
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

  /* ---------- 单实例 ----------
     双击两次不该起两个服务:两个端口、两份托盘图标,还读写同一份 SQLite
     与 audit.jsonl。第二份不初始化任何东西,只把已有界面叫到前台然后退出。
     --multi 可以强制多开(同一份数据两条并行演示时要它,知道自己在干什么再用)。
     按数据目录区分:BW_AGENT_HOME 指到别处就是另一份数据,可以同时开。 */
  int allow_multi = 0;
  {
    int w = 1;
    for (int i = 1; i < argc; i++) {
      const char *a = argv[i] ? argv[i] : "";
      if (str_ieq(a, "--multi") || str_ieq(a, "-multi")) {
        allow_multi = 1;
        continue;
      }
      argv[w++] = argv[i];
    }
    argv[w] = NULL;
    argc = w;
  }
  {
    const char *first = (argc > 1) ? argv[1] : "start";
    int long_running = str_ieq(first, "start") || str_ieq(first, "serve");
    if (long_running && !allow_multi && !instance_acquire()) {
      int want_ui = 1;
      const char *um = getenv("UI_MODE");
      if (um && (str_ieq(um, "off") || str_ieq(um, "none"))) want_ui = 0;
      for (int i = 2; i < argc; i++) {
        if (str_ieq(argv[i], "--no-ui")) want_ui = 0;
      }
      int running = instance_running_port(2500);
      if (running > 0) {
        printf("\n  程序已经在运行(端口 %d),本次启动只把它的界面叫到前台。\n", running);
        log_info("检测到已有实例(端口 %d):%s", running, instance_note());
        if (want_ui && ui_show_existing(running) == 0) {
          printf("  没能自动打开界面,请手动访问 http://127.0.0.1:%d/\n", running);
        }
        printf("  想强制再开一个:加 --multi。\n\n");
        return 0;
      }
      printf("\n  程序已经在运行,但没找到它的服务端口(可能正在启动,或已经卡住)。\n"
             "  稍等几秒再试;或在任务管理器里结束它;要强制多开请加 --multi。\n\n");
      log_warn("检测到已有实例但探活失败:%s", instance_note());
      return 1;
    }
  }

  /* 先把出厂数据铺到数据目录,再装工具:
     工具声明里写的是"入口在同目录的 exe",exe 没铺开就认不出入口,能力会悄悄退回内置实现。
     顺序反过来之后,"第一次运行"和"以后每次运行"看到的是同一套能力。
     selftest 除外 —— 自检不该往使用者的数据目录里写东西。
     发布版没有 selftest 子命令,这一支恒为 0。 */
#ifdef BW_RELEASE
  int is_selftest = 0;
#else
  int is_selftest = (argc > 1 && str_ieq(argv[1], "selftest"));
#endif
  if (!is_selftest) res_bootstrap_data_dir();

  tools_init();          /* 注册表必须先建好,后面所有分支都依赖它 */
  skills_init();
  rules_init(app_dir());  /* 站点知识来自规则文件(数据目录/exe 旁/内置),读不到用内置默认 */
  /* 可扩展层:数据目录下的外部工具 / 技能包 / MCP 服务器(像 Claude Code 那样自己加能力) */
  ext_bootstrap();        /* 首次运行放带注释的示例,让人照着改 */
  ext_load_all();
  ext_register_all();
  llm_init(app_dir());
  net_init();

  const char *cmd = (argc > 1) ? argv[1] : "start";

  /* 工具进程形态:供 <数据目录>\tools 里的声明以 "@app" 调回来 */
  if (str_ieq(cmd, "toolhost")) {
    int rc = toolhost_run((argc > 2) ? argv[2] : "");
    net_shutdown();
    rules_shutdown();
    return rc;
  }

#ifdef BW_RELEASE
  /* 发布版没有这几个子命令:明说一句,不要静默退出让人以为跑过了 */
  if (str_ieq(cmd, "selftest") || str_ieq(cmd, "regextest") || str_ieq(cmd, "netbench")) {
    printf("%s 是调试功能,发布版不带。需要它请用 agent-dev.exe(build.bat debug 构建)。\n", cmd);
    net_shutdown();
    rules_shutdown();
    return 1;
  }
#endif

#ifndef BW_RELEASE
  /* 调试版才有:自检、正则验枪口、网络基准。发布版不带这些 —— 
     它们对使用者没有用处,却要把 selftest.cpp 整个编进来。 */
  if (str_ieq(cmd, "selftest")) {
    printf("网站安全巡检智能体(C 版)· 自检\n");
    printf("程序目录: %s\n", app_dir());
    int rc = selftest_run();
    net_shutdown();
    rules_shutdown();
    return rc;
  }
#endif

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
#ifdef BW_RELEASE
    printf("发布版不带 regextest。要验自定义正则,请用调试版(agent-dev.exe)。\n");
    net_shutdown();
    rules_shutdown();
    return 1;
#else
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
#endif
  }

  if (str_ieq(cmd, "netbench")) {
#ifdef BW_RELEASE
    printf("发布版不带 netbench。要看网络层基准,请用调试版(agent-dev.exe)。\n");
    net_shutdown();
    rules_shutdown();
    return 1;
#else
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
#endif
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
    h.on_thinking = cli_on_thinking;
    h.on_action = cli_on_action;
    h.on_status = cli_on_status;
    h.on_observation = cli_on_observation;
    h.on_ask = cli_on_ask;
    h.on_answer = cli_on_answer;
    agent_set_hooks(a, &h);

    printf("模型:%s\n", providers_display_name());
    printf("配置:%s\n", providers_path());
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
       用法: agent.exe serve [授权域名] [端口] [--no-ui]  (也认 --port 8765) */
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
      } else if (str_ieq(argv[i], "--port") && i + 1 < argc) {
        port = atoi(argv[++i]);
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
