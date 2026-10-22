/* res.cpp —— 资源加载:磁盘优先,内置兜底。
 *
 * 交付给用户的是一个 exe,里面已经带了界面与默认规则;但如果旁边存在同名文件
 * (比如用户想换一套界面、或改规则调检测范围),就优先用磁盘上的那份。
 * 这样"单文件可用"和"可定制"两件事不冲突。
 */
#include "res.h"

#include "embed.h"

int res_load_text(const char *name, char **out, size_t *out_len) {
  if (out) *out = NULL;
  if (out_len) *out_len = 0;
  if (!name) return 0;

  /* 1) 磁盘(相对当前工作目录) */
  size_t len = 0;
  char *data = file_read_all(name, &len);
  if (data) {
    if (out) *out = data; else free(data);
    if (out_len) *out_len = len;
    return 1;
  }

  /* 2) exe 内置 */
  const char *builtin = NULL;
  size_t blen = 0;
  if (embed_lookup(name, &builtin, &blen)) {
    if (out) {
      char *copy = (char *)xmalloc(blen + 1);
      memcpy(copy, builtin, blen);
      copy[blen] = 0;
      *out = copy;
    }
    if (out_len) *out_len = blen;
    return 1;
  }
  return 0;
}

int res_exists(const char *name) {
  if (!name) return 0;
  long sz = file_size(name);
  if (sz >= 0) return 1;
  const char *d = NULL;
  size_t l = 0;
  return embed_lookup(name, &d, &l);
}

/* 数据目录里的"使用说明":给不懂命令行的人看的,所以只在记事本里读得懂的大白话 */
static const char README_TXT[] =
    "网站安全巡检智能体 —— 使用说明\r\n"
    "\r\n"
    "一、怎么用\r\n"
    "  1. 双击「网站安全巡检智能体.exe」—— 不会弹命令行窗口(它是界面程序)。\r\n"
    "  2. 等一两秒,界面窗口会自动打开。\r\n"
    "  3. 在界面里点「设置巡检目标」,填目标域名(不在 80/443 端口就写成 域名:端口),\r\n"
    "     勾选「我确认已获得该目标的巡检授权」,保存。\r\n"
    "  4. 直接在输入框里说话,例如:\r\n"
    "        把这个站完整巡检一遍\r\n"
    "        复测一下\r\n"
    "        出报告\r\n"
    "        跑评测\r\n"
    "  5. 关掉界面窗口就是退出程序(服务随之停止,端口自动释放,不会留在后台)。\r\n"
    "  出问题要看日志时的两种办法:\r\n"
    "    · 加 --debug 启动(「网站安全巡检智能体.exe」发送快捷方式里加,或命令行里加),\r\n"
    "      会额外开一个命令行窗口,实时日志显示在那里;\r\n"
    "      --debug 下关掉界面窗口不会停止服务(方便反复打开界面),要结束就关掉那个命令行窗口;\r\n"
    "    · 或者直接看本目录里的 agent.log(UTF-8 文本,记事本能打开)。\r\n"
    "二、数据放在哪\r\n"
    "  全部在本目录(C:\\Users\\<你的用户名>\\.bw_agent)下:\r\n"
    "    findings.jsonl  发现清单     reports\\ 报告     evals\\ 评测结果\r\n"
    "    runs\\ 运行记录   assets.jsonl 资产底账        audit.jsonl 请求审计\r\n"
    "    snapshots\\ 页面快照(用于比对内容是否被改)\r\n"
    "    skills\\ 各技能说明(可改)   tools\\ 自己加的外部工具\r\n"
    "    ui-profile\\ 界面窗口的浏览器数据(自动生成,与程序目录无关)\r\n"
    "    agent.log 运行日志(UTF-8,记事本可读)\r\n"
    "  想换个位置:设环境变量 BW_AGENT_HOME 指向别的目录。\r\n"
    "三、怎么改检测范围(不用重新编译)\r\n"
    "  两种改法:\r\n"
    "   · 界面里改(推荐):左边「配置编辑」页 —— 列出 rules.json / mcp.json / skills\\ / tools\\,\r\n"
    "     选中即可编辑;保存前先校验 JSON 并自动留一份 .bak;改完 rules.json 点「让规则生效」\r\n"
    "     立即生效,不用重启(技能/工具/MCP 要重启,页面会写明)。\r\n"
    "     页面上还有两个市场入口:Skill 市场(SkillsMP) 和 官方 MCP 市场(恒脑),可直接抄格式。\r\n"
    "   · 记事本改:用记事本打开本目录的 rules.json —— 判定口径全在这里,代码里只留判定手法:\r\n"
    "    sensitive_paths  要探测的落点(默认 36 个)\r\n"
    "    dir_candidates   要探测的目录(默认 29 个)\r\n"
    "    signatures       内容特征(特征名/类别/等级/命中条件)\r\n"
    "    weak_headers     期望的安全响应头\r\n"
    "    patterns.sensitive  敏感信息识别正则(身份证/私钥/凭据/手机号/邮箱/IP,按本单位口径增删)\r\n"
    "    weak_passwords      弱口令表(可换成你们的历史泄露口令表)\r\n"
    "    payloads.boolean_diff  布尔差分验证载荷(恒真/恒假成对)\r\n"
    "    markers.dir_listing 目录索引页的识别标记\r\n"
    "    severity_levels / alerts  等级排序、告警阈值与渠道\r\n"
    "  只写要覆盖的几段也行:缺哪一项会自动用出厂值;把文件删掉就回到出厂口径。\r\n"
    "  记事本存的 UTF-8 带 BOM 也能读,不用特意另存。\r\n"
    "  自己写正则不用猜:网站安全巡检智能体.exe regextest \"你的正则\" \"样本文本\"\r\n"
    "    例: regextest \"EMP[0-9]{8}\" \"工号 EMP2024001234\" → 命中: 位置 7,长度 11\r\n"
    "  想看当前生效的是哪一份、出厂规则长什么样:网站安全巡检智能体.exe rules\r\n"
    "四、怎么给智能体加新本事(不用重新编译)\r\n"
    "  skills\\ 目录里每个 .md 是一个技能说明(界面「能力清单」里的那些技能);\r\n"
    "  改里面的「什么时候用 / 解决什么」三段文字就生效(重启程序),改错删掉即可。\r\n"
    "  想加新能力,自己在本目录里建文件:\r\n"
    "    skills\\<技能名>.md        新技能:开头 front-matter 写 name/title/when/purpose/tools,\r\n"
    "                               正文写分几步做;要真执行命令再加 command + allow: true\r\n"
    "    tools\\<工具名>.json       新工具:name/description/schema(参数)/command(命令)/allow\r\n"
    "                               command 里的 $参数名 会被替换成调用参数;整条命令交给 cmd 执行\r\n"
    "    mcp.json                   接 MCP 服务器(stdio,JSON-RPC 2.0):\r\n"
    "                               {\"servers\":[{\"name\":\"x\",\"command\":\"启动命令\",\"allow\":true}]}\r\n"
    "                               连上后它的工具会以 mcp__x__工具名 出现在能力清单里\r\n"
    "  ★ 为了安全,新加的外部工具/技能命令/MCP 都必须在文件里写 allow: true 才会执行。\r\n"
    "  改完重启程序生效;界面「能力清单」页会看到新加的条目(标注外部/MCP)。\r\n"
    "五、跑评测要准备测试集\r\n"
    "  想用「跑评测」看检出效果,把测试集放到本目录的 testcases.jsonl(一行一个用例,\r\n"
    "  每条给出 target / expected / benign)。没有测试集时程序不会编分数,只会说明口径。\r\n"
    "六、接大模型(可选)\r\n"
    "  在本目录放一个 .env 文件,内容照 exe 说明书里的样例填:\r\n"
    "    DAS_BASE_URL=https://www.das-ai.com\r\n"
    "    DAS_APP_KEY=你的appKey\r\n"
    "    DAS_APP_SECRET=你的appSecret\r\n"
    "    DAS_USER_APP_KEY=你的userAppKey\r\n"
    "  不填也能用:程序会走本地规则路由,界面会如实标注当前模式。\r\n"
    "七、合规边界\r\n"
    "  只对已授权的域名发请求;只做只读检查(GET/HEAD/OPTIONS);默认 2 请求/秒限速;\r\n"
    "  每次请求都写进 audit.jsonl;证据落盘前已去敏。\r\n";

int res_bootstrap_data_dir(void) {
  const char *ddir = app_data_dir();
  ensure_dir(ddir);
  int written = 0;
  char path[MAX_PATH * 2];

  app_data_path(path, sizeof(path), "rules.json");
  if (file_size(path) < 0) {
    char *txt = NULL;
    size_t len = 0;
    if (res_load_text("data/rules.json", &txt, &len) && txt) {
      if (file_write_all(path, txt, len) == 0) written++;
      free(txt);
    }
  }

  app_data_path(path, sizeof(path), "使用说明.txt");
  if (file_size(path) < 0) {
    if (file_write_all(path, README_TXT, strlen(README_TXT)) == 0) written++;
  }

  /* 如果程序旁边(或开发目录里)放着一份测试集,顺手带一份到数据目录 —— 这样"跑评测"
     开箱就有数据;没有就什么也不做(测试集本来就是使用方按自己的环境准备的,
     程序不会凭空编一个,否则等于编分数)。 */
  app_data_path(path, sizeof(path), "testcases.jsonl");
  if (file_size(path) < 0) {
    size_t len = 0;
    char side[MAX_PATH * 2];
    snprintf(side, sizeof(side), "%sdata\\testcases.jsonl", app_dir());
    char *txt = file_read_all(side, &len);
    if (!txt) {
      /* exe 就在 data 目录里时(开发时的 build\ 形态)再往上找一层 */
      snprintf(side, sizeof(side), "%s..\\data\\testcases.jsonl", app_dir());
      txt = file_read_all(side, &len);
    }
    if (txt) {
      if (file_write_all(path, txt, len) == 0) written++;
      free(txt);
    }
  }
  if (written > 0) {
    log_info("[数据目录] 首次运行:已写入 %d 个可改文件到 %s", written, ddir);
  }
  return written;
}
