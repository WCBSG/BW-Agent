/* approval.cpp —— 审批策略的存取与判定。见 approval.h。 */
#include "approval.h"

#include <string>
#include <vector>

namespace {

char g_path[MAX_PATH * 2] = {0};
std::string g_active = "ask";        /* 默认:询问。这是最安全的默认值。 */
std::vector<approval_policy_t> g_custom;   /* 用户预设(custom 模式) */

const approval_policy_t kBuiltin[] = {
    {"ask", "询问", "ask", "每个动作都要你允许(默认)", ""},
    {"readonly", "允许只读", "readonly",
     "只读动作(取数/读文件/查清单)自动放行,会改动东西的动作仍然问你", ""},
    {"allow_all", "全部允许", "allow_all", "自动放行全部动作,不再逐条询问", ""},
};

void copy_str(char *dst, size_t cap, const char *src) {
  snprintf(dst, cap, "%s", src ? src : "");
}

approval_policy_t *find_custom(const char *id) {
  for (auto &p : g_custom) {
    if (str_ieq(p.id, id ? id : "")) return &p;
  }
  return NULL;
}

const approval_policy_t *find_any(const char *id) {
  for (const auto &p : kBuiltin) {
    if (str_ieq(p.id, id ? id : "")) return &p;
  }
  return find_custom(id);
}

/* 通配匹配:只支持 * 与 ?(够用,也不会让人写出看不懂的表达式) */
bool glob_match(const char *pat, const char *s) {
  if (!pat || !*pat) return false;
  const char *star = NULL, *ss = NULL;
  while (*s) {
    if (*pat == '?' || *pat == *s) { pat++; s++; }
    else if (*pat == '*') { star = pat++; ss = s; }
    else if (star) { pat = star + 1; s = ++ss; }
    else return false;
  }
  while (*pat == '*') pat++;
  return !*pat;
}

}  // namespace

void approval_set_path(const char *path) { copy_str(g_path, sizeof(g_path), path); }

void approval_load(void) {
  g_custom.clear();
  g_active = "ask";
  if (!g_path[0]) return;
  size_t len = 0;
  char *text = file_read_all(g_path, &len);
  if (!text || !len) { free(text); return; }
  json_t *root = json_parse(text);
  free(text);
  if (!root) return;

  const char *act = j_s(root, "active", "ask");
  if (act[0]) g_active = act;

  json_t *list = j_get(root, "policies");
  for (int i = 0; i < j_len(list); i++) {
    json_t *o = j_at(list, i);
    approval_policy_t p;
    memset(&p, 0, sizeof(p));
    copy_str(p.id, sizeof(p.id), j_s(o, "id", ""));
    copy_str(p.name, sizeof(p.name), j_s(o, "name", ""));
    copy_str(p.mode, sizeof(p.mode), j_s(o, "mode", "custom"));
    copy_str(p.note, sizeof(p.note), j_s(o, "note", ""));
    copy_str(p.rules, sizeof(p.rules), j_s(o, "rules", ""));
    if (p.id[0]) g_custom.push_back(p);
  }
  json_free(root);
}

void approval_save(void) {
  if (!g_path[0]) return;
  json_t *root = j_obj();
  j_set_str(root, "active", g_active.c_str());
  json_t *list = j_arr();
  for (const auto &p : g_custom) {
    json_t *o = j_obj();
    j_set_str(o, "id", p.id);
    j_set_str(o, "name", p.name);
    j_set_str(o, "mode", p.mode);
    j_set_str(o, "note", p.note);
    j_set_str(o, "rules", p.rules);
    j_add(list, o);
  }
  j_set(root, "policies", list);
  char *text = json_dump_pretty(root);
  if (text) {
    /* 只对"所在目录"建目录 —— 之前把文件路径本身传给 ensure_dir,
       结果建出一个叫 approval.json 的目录,写文件永远失败(策略一重启就没了)。 */
    char dir[MAX_PATH * 2];
    snprintf(dir, sizeof(dir), "%s", g_path);
    char *slash = strrchr(dir, '\\');
    if (slash) { *slash = 0; ensure_dir(dir); }
    file_write_all(g_path, text, strlen(text));
  }
  free(text);
  json_free(root);
}

json_t *approval_list_json(void) {
  json_t *arr = j_arr();
  const approval_policy_t *cur = find_any(g_active.c_str());
  for (const auto &p : kBuiltin) {
    json_t *o = j_obj();
    j_set_str(o, "id", p.id);
    j_set_str(o, "name", p.name);
    j_set_str(o, "mode", p.mode);
    j_set_str(o, "note", p.note);
    j_set_bool(o, "builtin", 1);
    j_set_bool(o, "active", cur && str_ieq(cur->id, p.id));
    j_add(arr, o);
  }
  for (const auto &p : g_custom) {
    json_t *o = j_obj();
    j_set_str(o, "id", p.id);
    j_set_str(o, "name", p.name);
    j_set_str(o, "mode", p.mode);
    j_set_str(o, "note", p.note);
    j_set_str(o, "rules", p.rules);
    j_set_bool(o, "builtin", 0);
    j_set_bool(o, "active", cur && str_ieq(cur->id, p.id));
    j_add(arr, o);
  }
  return arr;
}

const char *approval_active_id(void) { return g_active.c_str(); }

int approval_activate(const char *id) {
  if (!find_any(id)) return 0;
  g_active = id;
  approval_save();
  return 1;
}

char *approval_save_policy(json_t *p, char *err, size_t err_cap) {
  if (!p || p->type != J_OBJ) {
    snprintf(err, err_cap, "策略必须是一个对象");
    return NULL;
  }
  const char *name = j_s(p, "name", "");
  if (!name[0]) { snprintf(err, err_cap, "策略需要名字"); return NULL; }
  if (strlen(name) > 40) { snprintf(err, err_cap, "名字最多 40 字节"); return NULL; }
  const char *mode = j_s(p, "mode", "custom");
  if (!str_ieq(mode, "custom")) { snprintf(err, err_cap, "自定义策略的 mode 只能是 custom"); return NULL; }
  const char *rules = j_s(p, "rules", "");

  /* 规则校验:一是动作词得认识,二是工具模式不能是空串 ——
     写错的策略比没有策略更危险(会静默变成"全部允许")。 */
  int rule_count = 0;
  {
    char **lines = NULL;
    int n = str_split(rules, '\n', &lines, 200);
    for (int i = 0; i < n; i++) {
      char *line = str_trim(lines[i]);
      if (!line[0] || line[0] == '#') continue;
      char *eq = strchr(line, '=');
      if (!eq) {
        snprintf(err, err_cap, "第 %d 行要写成 工具名=允许/询问/拒绝", i + 1);
        str_free_list(lines, n);
        return NULL;
      }
      *eq = 0;
      char *tool = str_trim(line);
      char *act = str_trim(eq + 1);
      if (!tool[0]) {
        snprintf(err, err_cap, "第 %d 行缺少工具名", i + 1);
        str_free_list(lines, n);
        return NULL;
      }
      if (!str_ieq(act, "允许") && !str_ieq(act, "询问") && !str_ieq(act, "拒绝") &&
          !str_ieq(act, "allow") && !str_ieq(act, "ask") && !str_ieq(act, "deny")) {
        snprintf(err, err_cap, "第 %d 行的动作只能是 允许/询问/拒绝", i + 1);
        str_free_list(lines, n);
        return NULL;
      }
      rule_count++;
    }
    str_free_list(lines, n);
  }

  std::string id = j_s(p, "id", "");
  if (id.empty()) {
    char buf[24];
    snprintf(buf, sizeof(buf), "custom-%d", (int)g_custom.size() + 1);
    id = buf;
  }
  approval_policy_t *exist = find_custom(id.c_str());
  approval_policy_t *slot = exist;
  if (!slot) {
    g_custom.push_back(approval_policy_t());
    slot = &g_custom.back();
    memset(slot, 0, sizeof(*slot));
  }
  copy_str(slot->id, sizeof(slot->id), id.c_str());
  copy_str(slot->name, sizeof(slot->name), name);
  copy_str(slot->mode, sizeof(slot->mode), "custom");
  copy_str(slot->note, sizeof(slot->note), j_s(p, "note", ""));
  copy_str(slot->rules, sizeof(slot->rules), rules);
  approval_save();
  (void)rule_count;
  return xstrdup(slot->id);
}

int approval_delete_policy(const char *id) {
  if (!id || !id[0]) return 0;
  for (size_t i = 0; i < g_custom.size(); i++) {
    if (!str_ieq(g_custom[i].id, id)) continue;
    g_custom.erase(g_custom.begin() + (long)i);
    if (str_ieq(g_active.c_str(), id)) g_active = "ask";
    approval_save();
    return 1;
  }
  return 0;
}

approval_action_t approval_decide(const char *tool, int readonly) {
  const approval_policy_t *p = find_any(g_active.c_str());
  if (!p) return APPROVAL_ASK;                 /* 策略不见了:退回最安全的一档 */
  if (str_ieq(p->mode, "allow_all")) return APPROVAL_ALLOW;
  if (str_ieq(p->mode, "ask")) return APPROVAL_ASK;
  /* 「允许只读」:只读动作不问,其余按询问走。
     这是"既不想每步点一次、又不敢全放开"的中间档 —— 巡检里绝大多数调用都是只读的。 */
  if (str_ieq(p->mode, "readonly")) return readonly ? APPROVAL_ALLOW : APPROVAL_ASK;

  /* custom:自上而下第一条命中的规则说了算;一条都没命中就"询问"(而不是放行) */
  char **lines = NULL;
  int n = str_split(p->rules, '\n', &lines, 200);
  approval_action_t act = APPROVAL_ASK;
  for (int i = 0; i < n; i++) {
    char *line = str_trim(lines[i]);
    if (!line[0] || line[0] == '#') continue;
    char *eq = strchr(line, '=');
    if (!eq) continue;
    *eq = 0;
    char *pat = str_trim(line);
    char *what = str_trim(eq + 1);
    if (!glob_match(pat, tool ? tool : "")) continue;
    if (str_ieq(what, "允许") || str_ieq(what, "allow")) act = APPROVAL_ALLOW;
    else if (str_ieq(what, "拒绝") || str_ieq(what, "deny")) act = APPROVAL_DENY;
    else act = APPROVAL_ASK;
    break;
  }
  str_free_list(lines, n);
  return act;
}

int approval_is_allow_all(void) {
  const approval_policy_t *p = find_any(g_active.c_str());
  return p && str_ieq(p->mode, "allow_all");
}

const char *approval_mode_text(void) {
  const approval_policy_t *p = find_any(g_active.c_str());
  if (!p) return "询问";
  return p->name;
}

int approval_is_readonly_only(void) {
  const approval_policy_t *p = find_any(g_active.c_str());
  return p && str_ieq(p->mode, "readonly");
}
