/* profile.cpp —— 本单位敏感信息定义的生效口径。见 profile.h。 */
#include "profile.h"

#include "regex.h"

#include <string>
#include <vector>

namespace {

struct active_profile {
  int on = 0;
  std::string id;
  std::string name;
  std::vector<std::string> keywords;
  std::vector<std::string> regex;
  std::vector<std::string> paths;
  std::vector<std::string> file_types;
  std::vector<std::string> samples;
};

active_profile &cur() {
  static active_profile p;
  return p;
}

/* 数组字段读成字符串列表:跳过空串与非字符串,顺手去掉首尾空白 */
void read_list(json_t *obj, const char *key, std::vector<std::string> &out,
               size_t max_items, size_t max_len) {
  out.clear();
  json_t *arr = j_get(obj, key);
  if (!arr || arr->type != J_ARR) return;
  for (int i = 0; i < arr->count && out.size() < max_items; i++) {
    json_t *v = arr->items[i];
    if (!v || v->type != J_STR || !v->str) continue;
    std::string s(v->str);
    size_t b = s.find_first_not_of(" \t\r\n");
    size_t e = s.find_last_not_of(" \t\r\n");
    if (b == std::string::npos) continue;
    s = s.substr(b, e - b + 1);
    if (s.size() > max_len) s.resize(max_len);
    if (!s.empty()) out.push_back(s);
  }
}

/* 页面正文里找一处命中并去敏(保留头尾各一个字,中间打星)。
   注意按 UTF-8 的"字"来切,而不是按字节 —— 否则中文会被切成半个字,
   报告里就出现一串乱码(这个坑踩过一次)。 */
void mask_into(char *out, size_t cap, const std::string &hit) {
  if (cap == 0) return;
  if (hit.size() <= 2) {
    size_t n = hit.size() < cap - 1 ? hit.size() : cap - 1;
    for (size_t i = 0; i < n; i++) out[i] = '*';
    out[n] = 0;
    return;
  }
  size_t head = 1;
  while (head < hit.size() && ((unsigned char)hit[head] & 0xC0) == 0x80) head++;
  size_t tail = hit.size() - 1;
  while (tail > 0 && ((unsigned char)hit[tail] & 0xC0) == 0x80) tail--;

  std::string m = hit.substr(0, head);
  size_t stars = 0;
  for (size_t i = head; i + (hit.size() - tail) < hit.size(); i++) {
    if (((unsigned char)hit[i] & 0xC0) != 0x80) stars++;
  }
  m.append(stars, '*');
  m += hit.substr(tail);
  snprintf(out, cap, "%s", m.c_str());
}

bool contains(const std::string &hay, const std::string &needle) {
  if (needle.empty() || hay.size() < needle.size()) return false;
  return hay.find(needle) != std::string::npos;
}

}  // namespace

int profile_set_active(json_t *profile) {
  active_profile &p = cur();
  p = active_profile();
  if (!profile || profile->type != J_OBJ) return 0;

  p.id = j_s(profile, "id", "");
  p.name = j_s(profile, "name", "");
  read_list(profile, "keywords", p.keywords, 200, 200);
  read_list(profile, "regex", p.regex, 60, 300);
  read_list(profile, "paths", p.paths, 80, 300);
  read_list(profile, "file_types", p.file_types, 60, 20);
  read_list(profile, "samples", p.samples, 60, 300);
  p.on = 1;
  return 1;
}

void profile_clear_active(void) { cur() = active_profile(); }

int profile_is_active(void) { return cur().on; }
const char *profile_active_id(void) { return cur().id.c_str(); }
const char *profile_active_name(void) { return cur().name.c_str(); }

int profile_active_paths(const char **out, int cap) {
  active_profile &p = cur();
  int n = 0;
  for (size_t i = 0; i < p.paths.size() && n < cap; i++) out[n++] = p.paths[i].c_str();
  return n;
}

int profile_scan_text(const char *text, char *kind, size_t kind_cap, char *severity,
                      size_t sev_cap, char *masked, size_t masked_cap) {
  active_profile &p = cur();
  if (!p.on || !text || !text[0]) return 0;
  std::string body(text);
  if (body.size() > 512 * 1024) body.resize(512 * 1024);   /* 只看前 512KB,别把内存吃满 */

  for (const std::string &k : p.keywords) {
    if (!contains(body, k)) continue;
    snprintf(kind, kind_cap, "本单位关键词");
    snprintf(severity, sev_cap, "中");
    mask_into(masked, masked_cap, k);
    return 1;
  }
  for (const std::string &s : p.samples) {
    if (!contains(body, s)) continue;
    snprintf(kind, kind_cap, "本单位样例命中");
    snprintf(severity, sev_cap, "高");
    mask_into(masked, masked_cap, s);
    return 1;
  }
  for (const std::string &r : p.regex) {
    int off = 0, len = 0;
    char err[128] = {0};
    if (!rx_find(r.c_str(), body.c_str(), &off, &len, err, sizeof(err))) continue;
    snprintf(kind, kind_cap, "本单位正则");
    snprintf(severity, sev_cap, "高");
    std::string hit = body.substr((size_t)off, (size_t)len);
    mask_into(masked, masked_cap, hit);
    return 1;
  }
  return 0;
}

int profile_type_hit(const char *path_or_url) {
  active_profile &p = cur();
  if (!p.on || !path_or_url) return 0;
  std::string s(path_or_url);
  size_t q = s.find_first_of("?#");
  if (q != std::string::npos) s.resize(q);
  size_t dot = s.find_last_of('.');
  size_t slash = s.find_last_of('/');
  if (dot == std::string::npos || (slash != std::string::npos && dot < slash)) return 0;
  std::string ext = s.substr(dot + 1);
  for (char &c : ext) c = (char)tolower((unsigned char)c);
  for (const std::string &t : p.file_types) {
    std::string want = t;
    if (!want.empty() && want[0] == '.') want.erase(0, 1);
    for (char &c : want) c = (char)tolower((unsigned char)c);
    if (!want.empty() && ext == want) return 1;
  }
  return 0;
}
