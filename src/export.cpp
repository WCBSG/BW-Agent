/* export.cpp —— 报告导出实现。见 export.h 的说明。 */
#include "export.h"

#include <ctime>
#include <string>
#include <vector>

/* ================= 公共:把报告与发现读成一份数据 ================= */

struct report_t {
  json_t *report;     /* 拥有 */
  json_t *findings;   /* 拥有 */
  char id[24];
  char title[256];
  char generated_at[40];
  char summary[2048];
  char task_id[24];
  int total, open, crit, high, fp;
};

static void report_free(report_t *r) {
  if (!r) return;
  json_free(r->report);
  json_free(r->findings);
  memset(r, 0, sizeof(*r));
}

static int sev_rank(const char *sev) {
  if (!sev) return 0;
  if (strcmp(sev, "严重") == 0) return 4;
  if (strcmp(sev, "高") == 0) return 3;
  if (strcmp(sev, "中") == 0) return 2;
  if (strcmp(sev, "低") == 0) return 1;
  return 0;
}

/* 报告里的 finding_ids 是权威引用清单;按 id 取发现,顺序与报告一致 */
static json_t *collect_findings(store_t *s, json_t *report) {
  json_t *ids = j_get(report, "finding_ids");
  json_t *all = store_all(s, "findings");
  json_t *out = j_arr();
  if (j_len(ids) > 0) {
    for (int i = 0; i < j_len(ids); i++) {
      json_t *idv = j_at(ids, i);
      if (!idv || !idv->str) continue;
      for (int k = 0; k < j_len(all); k++) {
        if (strcmp(j_s(j_at(all, k), "id", ""), idv->str) == 0) {
          j_add(out, json_parse(json_dump(j_at(all, k))));
          break;
        }
      }
    }
  } else {
    const char *task_id = j_s(report, "task_id", "");
    for (int k = 0; k < j_len(all); k++) {
      if (strcmp(j_s(j_at(all, k), "task_id", ""), task_id) == 0) {
        j_add(out, json_parse(json_dump(j_at(all, k))));
      }
    }
  }
  json_free(all);
  return out;
}

static int load_report(store_t *s, const char *report_id, report_t *out) {
  memset(out, 0, sizeof(*out));
  json_t *report = NULL;
  if (report_id && report_id[0]) {
    report = store_get(s, "reports", report_id);
  } else {
    json_t *all = store_all(s, "reports");
    int n = j_len(all);
    if (n > 0) {
      /* 最近的:按 generated_at 取最大 */
      int best = -1;
      const char *best_at = NULL;
      for (int i = 0; i < n; i++) {
        const char *at = j_s(j_at(all, i), "generated_at", "");
        if (!best_at || strcmp(at, best_at) >= 0) { best_at = at; best = i; }
      }
      if (best >= 0) report = json_parse(json_dump(j_at(all, best)));
    }
    json_free(all);
  }
  if (!report) return -1;

  out->report = report;
  out->findings = collect_findings(s, report);
  snprintf(out->id, sizeof(out->id), "%s", j_s(report, "id", "R-0000"));
  snprintf(out->title, sizeof(out->title), "%s", j_s(report, "title", "安全巡检报告"));
  snprintf(out->generated_at, sizeof(out->generated_at), "%s", j_s(report, "generated_at", ""));
  snprintf(out->summary, sizeof(out->summary), "%s", j_s(report, "summary", ""));
  snprintf(out->task_id, sizeof(out->task_id), "%s", j_s(report, "task_id", ""));

  json_t *stats = j_get(report, "stats");
  out->total = (int)j_n(stats, "total", 0);
  out->open = (int)j_n(stats, "open", 0);
  out->fp = (int)j_n(stats, "false_positive", 0);
  json_t *by_sev = j_get(stats, "by_severity");
  out->crit = (int)j_n(by_sev, "严重", 0);
  out->high = (int)j_n(by_sev, "高", 0);
  return 0;
}

/* ================= 文本格式 ================= */

static void md_escape(buf_t *b, const char *s) {
  for (const char *p = s; *p; p++) {
    if (*p == '|') buf_puts(b, "\\|");
    else buf_putc_(b, *p);
  }
}

static void render_md(report_t *r, buf_t *out) {
  buf_printf(out, "# %s\n\n", r->title);
  buf_printf(out, "- 报告编号:%s\n", r->id);
  buf_printf(out, "- 生成时间:%s\n", r->generated_at);
  buf_printf(out, "- 结论:%s\n\n", r->summary);

  buf_puts(out, "## 一、统计\n\n");
  buf_puts(out, "| 等级 | 条数 |\n|---|---|\n");
  json_t *stats = j_get(r->report, "stats");
  json_t *by_sev = j_get(stats, "by_severity");
  static const char *SEV[] = {"严重", "高", "中", "低", "信息"};
  for (int i = 0; i < 5; i++) {
    buf_printf(out, "| %s | %d |\n", SEV[i], (int)j_n(by_sev, SEV[i], 0));
  }
  buf_printf(out, "| 未处理 | %d |\n", r->open);
  if (r->fp) buf_printf(out, "| 误报(不计入问题数) | %d |\n", r->fp);
  buf_puts(out, "\n");

  buf_puts(out, "## 二、发现清单\n\n");
  if (!j_len(r->findings)) {
    buf_puts(out, "本次没有确认任何风险。\n\n");
  } else {
    for (int i = 0; i < j_len(r->findings); i++) {
      json_t *f = j_at(r->findings, i);
      buf_printf(out, "### %d. [%s] %s\n\n", i + 1, j_s(f, "severity", "信息"), j_s(f, "title", ""));
      buf_printf(out, "- 编号:%s\n", j_s(f, "id", ""));
      buf_printf(out, "- 类型:%s\n", j_s(f, "kind", ""));
      buf_printf(out, "- 目标:%s\n", j_s(f, "target", ""));
      buf_printf(out, "- 来源工具:%s\n", j_s(f, "source_tool", ""));
      buf_printf(out, "- 状态:%s\n", j_s(f, "status", "new"));
      const char *ev = j_s(f, "evidence", "");
      if (ev[0]) buf_printf(out, "- 证据:`%s`\n", ev);
      const char *impact = j_s(f, "impact", "");
      if (impact[0]) buf_printf(out, "- 影响:%s\n", impact);
      const char *fix = j_s(f, "fix", "");
      if (fix[0]) buf_printf(out, "- 修复建议:%s\n", fix);
      buf_puts(out, "\n");
    }
  }
  buf_puts(out, "---\n\n本报告由网站安全巡检智能体生成。所有请求都限制在授权域名内,"
                "只用只读方法,全程审计留痕;结论均附原始响应摘录,可回查。\n");
}

static void csv_field(buf_t *b, const char *s) {
  buf_putc_(b, '"');
  for (const char *p = s; *p; p++) {
    if (*p == '"') buf_puts(b, "\"\"");
    else buf_putc_(b, *p);
  }
  buf_putc_(b, '"');
}

static void render_csv(report_t *r, buf_t *out) {
  /* 带 UTF-8 BOM:Excel 不认没有 BOM 的中文 */
  buf_putn(out, "\xEF\xBB\xBF", 3);
  buf_puts(out, "编号,等级,类型,标题,目标,状态,来源工具,证据,修复建议\n");
  for (int i = 0; i < j_len(r->findings); i++) {
    json_t *f = j_at(r->findings, i);
    const char *cols[] = {
        j_s(f, "id", ""), j_s(f, "severity", ""), j_s(f, "kind", ""),
        j_s(f, "title", ""), j_s(f, "target", ""), j_s(f, "status", ""),
        j_s(f, "source_tool", ""), j_s(f, "evidence", ""), j_s(f, "fix", ""),
    };
    for (int c = 0; c < 9; c++) {
      if (c) buf_putc_(out, ',');
      csv_field(out, cols[c]);
    }
    buf_putc_(out, '\n');
  }
}

static void render_json(report_t *r, buf_t *out) {
  json_t *root = j_obj();
  j_set_str(root, "ok", "true");
  j_set(root, "report", json_parse(json_dump(r->report)));
  j_set(root, "findings", json_parse(json_dump(r->findings)));
  char *text = json_dump_pretty(root);
  buf_puts(out, text);
  free(text);
  json_free(root);
}

/* ================= HTML(也是 PDF 的排版源) ================= */

static void html_escape(buf_t *b, const char *s) {
  for (const char *p = s; *p; p++) {
    switch (*p) {
      case '&': buf_puts(b, "&amp;"); break;
      case '<': buf_puts(b, "&lt;"); break;
      case '>': buf_puts(b, "&gt;"); break;
      case '"': buf_puts(b, "&quot;"); break;
      default: buf_putc_(b, *p);
    }
  }
}

static void render_html(report_t *r, buf_t *out) {
  buf_puts(out, "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">");
  buf_puts(out, "<title>");
  html_escape(out, r->title);
  buf_puts(out, "</title><style>");
  /* 打印优先:页边距、分页、不出现彩色块(黑白打印机也要能读) */
  buf_puts(out, "@page{size:A4;margin:18mm 16mm}"
                "body{font:12pt/1.75 'Microsoft YaHei','PingFang SC',sans-serif;color:#1a1a1a;margin:0}"
                "h1{font-size:20pt;margin:0 0 4mm;letter-spacing:-.01em}"
                "h2{font-size:13pt;margin:8mm 0 3mm;padding-bottom:1.5mm;border-bottom:1px solid #d8d8d2}"
                "h3{font-size:11.5pt;margin:6mm 0 2mm;page-break-after:avoid}"
                ".meta{color:#5c5c56;font-size:10pt;line-height:1.9;margin-bottom:6mm}"
                ".meta b{color:#1a1a1a;font-weight:600}"
                "table{border-collapse:collapse;width:100%;font-size:10.5pt;margin:2mm 0 4mm}"
                "th,td{border:1px solid #d8d8d2;padding:1.6mm 2.4mm;text-align:left;vertical-align:top}"
                "th{background:#f4f3ef;font-weight:600}"
                ".sev{font-weight:600;white-space:nowrap}"
                ".kv{font-size:10.5pt;color:#3c3c38;margin:1mm 0}"
                ".kv span{color:#6f6f69}"
                "code{font-family:Consolas,monospace;font-size:10pt;background:#f6f5f1;padding:.4mm 1mm;"
                "border-radius:1mm;word-break:break-all}"
                ".foot{margin-top:10mm;padding-top:3mm;border-top:1px solid #d8d8d2;color:#6f6f69;font-size:9.5pt}"
                "h3{page-break-inside:avoid}");
  buf_puts(out, "</style></head><body>");

  buf_puts(out, "<h1>");
  html_escape(out, r->title);
  buf_puts(out, "</h1><div class=\"meta\">");
  buf_printf(out, "报告编号 <b>%s</b> · 生成时间 <b>%s</b><br>", r->id, r->generated_at);
  buf_puts(out, "结论 <b>");
  html_escape(out, r->summary);
  buf_puts(out, "</b></div>");

  buf_puts(out, "<h2>一、统计</h2><table><tr><th>等级</th><th>条数</th></tr>");
  json_t *stats = j_get(r->report, "stats");
  json_t *by_sev = j_get(stats, "by_severity");
  static const char *SEV[] = {"严重", "高", "中", "低", "信息"};
  for (int i = 0; i < 5; i++) {
    buf_printf(out, "<tr><td>%s</td><td>%d</td></tr>", SEV[i], (int)j_n(by_sev, SEV[i], 0));
  }
  buf_printf(out, "<tr><td>未处理</td><td>%d</td></tr>", r->open);
  if (r->fp) buf_printf(out, "<tr><td>误报(不计入问题数)</td><td>%d</td></tr>", r->fp);
  buf_puts(out, "</table>");

  buf_puts(out, "<h2>二、发现清单</h2>");
  if (!j_len(r->findings)) {
    buf_puts(out, "<p>本次没有确认任何风险。</p>");
  } else {
    for (int i = 0; i < j_len(r->findings); i++) {
      json_t *f = j_at(r->findings, i);
      buf_printf(out, "<h3>%d. [%s] ", i + 1, j_s(f, "severity", "信息"));
      html_escape(out, j_s(f, "title", ""));
      buf_puts(out, "</h3>");
      buf_puts(out, "<div class=\"kv\"><span>编号</span> ");
      html_escape(out, j_s(f, "id", ""));
      buf_puts(out, " · <span>类型</span> ");
      html_escape(out, j_s(f, "kind", ""));
      buf_puts(out, " · <span>状态</span> ");
      html_escape(out, j_s(f, "status", "new"));
      buf_puts(out, "</div><div class=\"kv\"><span>目标</span> ");
      html_escape(out, j_s(f, "target", ""));
      buf_puts(out, "</div>");
      const char *ev = j_s(f, "evidence", "");
      if (ev[0]) {
        buf_puts(out, "<div class=\"kv\"><span>证据</span> <code>");
        html_escape(out, ev);
        buf_puts(out, "</code></div>");
      }
      const char *impact = j_s(f, "impact", "");
      if (impact[0]) {
        buf_puts(out, "<div class=\"kv\"><span>影响</span> ");
        html_escape(out, impact);
        buf_puts(out, "</div>");
      }
      const char *fix = j_s(f, "fix", "");
      if (fix[0]) {
        buf_puts(out, "<div class=\"kv\"><span>修复建议</span> ");
        html_escape(out, fix);
        buf_puts(out, "</div>");
      }
    }
  }
  buf_puts(out, "<div class=\"foot\">本报告由网站安全巡检智能体生成。所有请求都限制在授权域名内,"
                "只用只读方法(GET / HEAD / OPTIONS),全程审计留痕;结论均附原始响应摘录,可回查。</div>");
  buf_puts(out, "</body></html>");
}

/* ================= DOCX(自己拼 OOXML + ZIP) ================= */

static unsigned long crc_table[256];
static int crc_ready = 0;

static void crc_init(void) {
  for (unsigned long i = 0; i < 256; i++) {
    unsigned long c = i;
    for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320UL ^ (c >> 1)) : (c >> 1);
    crc_table[i] = c;
  }
  crc_ready = 1;
}

static unsigned long crc32_of(const char *data, size_t len) {
  if (!crc_ready) crc_init();
  unsigned long c = 0xFFFFFFFFUL;
  for (size_t i = 0; i < len; i++) {
    c = crc_table[(c ^ (unsigned char)data[i]) & 0xFF] ^ (c >> 8);
  }
  return c ^ 0xFFFFFFFFUL;
}

struct zip_file {
  std::string name;
  std::string data;
};

static void put_u16(std::string &s, unsigned v) {
  s.push_back((char)(v & 0xFF));
  s.push_back((char)((v >> 8) & 0xFF));
}
static void put_u32(std::string &s, unsigned long v) {
  s.push_back((char)(v & 0xFF));
  s.push_back((char)((v >> 8) & 0xFF));
  s.push_back((char)((v >> 16) & 0xFF));
  s.push_back((char)((v >> 24) & 0xFF));
}

/* 只用 store(不压缩):报告里最大的是文本,压不压差别不大,
   换来的是"不引入 zlib、代码能一眼看完"。 */
static void zip_build(const std::vector<zip_file> &files, buf_t *out) {
  std::string body;
  struct cd_t { std::string name; unsigned long crc, size, offset; };
  std::vector<cd_t> cd;

  for (const zip_file &f : files) {
    cd_t e;
    e.name = f.name;
    e.crc = crc32_of(f.data.data(), f.data.size());
    e.size = (unsigned long)f.data.size();
    e.offset = (unsigned long)body.size();

    put_u32(body, 0x04034b50);      /* local file header */
    put_u16(body, 20);              /* version needed */
    put_u16(body, 0x0800);          /* flags: UTF-8 名 */
    put_u16(body, 0);               /* method: store */
    put_u16(body, 0); put_u16(body, 0);  /* time/date */
    put_u32(body, e.crc);
    put_u32(body, e.size);
    put_u32(body, e.size);
    put_u16(body, (unsigned)f.name.size());
    put_u16(body, 0);
    body += f.name;
    body += f.data;
    cd.push_back(e);
  }

  unsigned long cd_start = (unsigned long)body.size();
  for (const cd_t &e : cd) {
    put_u32(body, 0x02014b50);      /* central directory */
    put_u16(body, 20); put_u16(body, 20);
    put_u16(body, 0x0800); put_u16(body, 0);
    put_u16(body, 0); put_u16(body, 0);
    put_u32(body, e.crc); put_u32(body, e.size); put_u32(body, e.size);
    put_u16(body, (unsigned)e.name.size());
    put_u16(body, 0); put_u16(body, 0);
    put_u16(body, 0); put_u16(body, 0);
    put_u32(body, 0);
    put_u32(body, e.offset);
    body += e.name;
  }
  unsigned long cd_size = (unsigned long)body.size() - cd_start;
  put_u32(body, 0x06054b50);        /* end of central directory */
  put_u16(body, 0); put_u16(body, 0);
  put_u16(body, (unsigned)cd.size()); put_u16(body, (unsigned)cd.size());
  put_u32(body, cd_size); put_u32(body, cd_start);
  put_u16(body, 0);

  buf_putn(out, body.data(), body.size());
}

static void xml_escape(std::string &s, const char *text) {
  for (const char *p = text; *p; p++) {
    switch (*p) {
      case '&': s += "&amp;"; break;
      case '<': s += "&lt;"; break;
      case '>': s += "&gt;"; break;
      case '"': s += "&quot;"; break;
      case '\'': s += "&apos;"; break;
      default: s.push_back(*p);
    }
  }
}

/* 一个段落:size 单位是半磅(Word 的规矩),bold 传 1 加粗 */
static void docx_para(std::string &x, const char *text, int size, int bold, int space_after) {
  x += "<w:p><w:pPr><w:spacing w:after=\"" + std::to_string(space_after) + "\"/></w:pPr><w:r><w:rPr>";
  x += "<w:rFonts w:ascii=\"Microsoft YaHei\" w:eastAsia=\"Microsoft YaHei\" w:hAnsi=\"Microsoft YaHei\"/>";
  if (bold) x += "<w:b/>";
  x += "<w:sz w:val=\"" + std::to_string(size) + "\"/><w:szCs w:val=\"" + std::to_string(size) + "\"/>";
  x += "</w:rPr><w:t xml:space=\"preserve\">";
  xml_escape(x, text);
  x += "</w:t></w:r></w:p>";
}

static void docx_cell(std::string &x, const char *text, int bold, int width) {
  x += "<w:tc><w:tcPr><w:tcW w:w=\"" + std::to_string(width) + "\" w:type=\"dxa\"/>";
  x += "<w:tcBorders>";
  static const char *SIDES[] = {"top", "left", "bottom", "right"};
  for (int i = 0; i < 4; i++) {
    x += std::string("<w:") + SIDES[i] + " w:val=\"single\" w:sz=\"4\" w:color=\"D8D8D2\"/>";
  }
  x += "</w:tcBorders></w:tcPr><w:p><w:r><w:rPr>";
  x += "<w:rFonts w:ascii=\"Microsoft YaHei\" w:eastAsia=\"Microsoft YaHei\"/>";
  if (bold) x += "<w:b/>";
  x += "<w:sz w:val=\"18\"/></w:rPr><w:t xml:space=\"preserve\">";
  xml_escape(x, text);
  x += "</w:t></w:r></w:p></w:tc>";
}

static void render_docx(report_t *r, buf_t *out) {
  std::string x;
  x += "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
  x += "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body>";

  docx_para(x, r->title, 32, 1, 120);
  char line[512];
  snprintf(line, sizeof(line), "报告编号 %s    生成时间 %s", r->id, r->generated_at);
  docx_para(x, line, 19, 0, 60);
  snprintf(line, sizeof(line), "结论:%s", r->summary);
  docx_para(x, line, 19, 0, 240);

  docx_para(x, "一、统计", 24, 1, 100);
  x += "<w:tbl><w:tblPr><w:tblW w:w=\"0\" w:type=\"auto\"/></w:tblPr>";
  x += "<w:tr>";
  docx_cell(x, "等级", 1, 2400);
  docx_cell(x, "条数", 1, 2400);
  x += "</w:tr>";
  json_t *stats = j_get(r->report, "stats");
  json_t *by_sev = j_get(stats, "by_severity");
  static const char *SEV[] = {"严重", "高", "中", "低", "信息"};
  for (int i = 0; i < 5; i++) {
    snprintf(line, sizeof(line), "%d", (int)j_n(by_sev, SEV[i], 0));
    x += "<w:tr>";
    docx_cell(x, SEV[i], 0, 2400);
    docx_cell(x, line, 0, 2400);
    x += "</w:tr>";
  }
  snprintf(line, sizeof(line), "%d", r->open);
  x += "<w:tr>";
  docx_cell(x, "未处理", 0, 2400);
  docx_cell(x, line, 0, 2400);
  x += "</w:tr>";
  x += "</w:tbl>";
  docx_para(x, "", 12, 0, 120);

  docx_para(x, "二、发现清单", 24, 1, 100);
  if (!j_len(r->findings)) {
    docx_para(x, "本次没有确认任何风险。", 20, 0, 120);
  } else {
    for (int i = 0; i < j_len(r->findings); i++) {
      json_t *f = j_at(r->findings, i);
      snprintf(line, sizeof(line), "%d. [%s] %s", i + 1, j_s(f, "severity", "信息"), j_s(f, "title", ""));
      docx_para(x, line, 21, 1, 60);
      snprintf(line, sizeof(line), "编号:%s    类型:%s    状态:%s",
               j_s(f, "id", ""), j_s(f, "kind", ""), j_s(f, "status", "new"));
      docx_para(x, line, 18, 0, 40);
      snprintf(line, sizeof(line), "目标:%s", j_s(f, "target", ""));
      docx_para(x, line, 18, 0, 40);
      const char *ev = j_s(f, "evidence", "");
      if (ev[0]) {
        snprintf(line, sizeof(line), "证据:%s", ev);
        docx_para(x, line, 17, 0, 40);
      }
      const char *impact = j_s(f, "impact", "");
      if (impact[0]) {
        snprintf(line, sizeof(line), "影响:%s", impact);
        docx_para(x, line, 18, 0, 40);
      }
      const char *fix = j_s(f, "fix", "");
      if (fix[0]) {
        snprintf(line, sizeof(line), "修复建议:%s", fix);
        docx_para(x, line, 18, 0, 160);
      }
    }
  }
  docx_para(x, "本报告由网站安全巡检智能体生成。所有请求都限制在授权域名内,只用只读方法,"
               "全程审计留痕;结论均附原始响应摘录,可回查。", 17, 0, 0);
  x += "<w:sectPr><w:pgSz w:w=\"11906\" w:h=\"16838\"/>"
       "<w:pgMar w:top=\"1134\" w:right=\"1134\" w:bottom=\"1134\" w:left=\"1134\"/></w:sectPr>";
  x += "</w:body></w:document>";

  std::string ct = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
      "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
      "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
      "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
      "<Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-"
      "officedocument.wordprocessingml.document.main+xml\"/>"
      "</Types>";
  std::string rels = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
      "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
      "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/"
      "relationships/officeDocument\" Target=\"word/document.xml\"/>"
      "</Relationships>";

  std::vector<zip_file> files;
  files.push_back({"[Content_Types].xml", ct});
  files.push_back({"_rels/.rels", rels});
  files.push_back({"word/document.xml", x});
  zip_build(files, out);
}

/* ================= PDF(交给本机 Edge 排版打印) ================= */

/* 找浏览器的可执行文件。返回空串表示这台机器没有,前端就只给其它格式。 */
static std::string browser_path(void) {
  const char *cands[] = {
      "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe",
      "%ProgramFiles%\\Microsoft\\Edge\\Application\\msedge.exe",
      "%LOCALAPPDATA%\\Microsoft\\Edge\\Application\\msedge.exe",
      "%ProgramFiles%\\Google\\Chrome\\Application\\chrome.exe",
      "%ProgramFiles(x86)%\\Google\\Chrome\\Application\\chrome.exe",
      "%LOCALAPPDATA%\\Google\\Chrome\\Application\\chrome.exe",
  };
  for (const char *c : cands) {
    char buf[MAX_PATH * 2];
    DWORD n = ExpandEnvironmentStringsA(c, buf, sizeof(buf));
    if (n == 0 || n > sizeof(buf)) continue;
    wchar_t *w = u8_to_w(buf);
    DWORD attr = w ? GetFileAttributesW(w) : INVALID_FILE_ATTRIBUTES;
    free(w);
    if (attr != INVALID_FILE_ATTRIBUTES) return std::string(buf);
  }
  return std::string();
}

static bool run_and_wait(const std::string &cmd, DWORD timeout_ms) {
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  memset(&si, 0, sizeof(si));
  memset(&pi, 0, sizeof(pi));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  std::vector<char> line(cmd.begin(), cmd.end());
  line.push_back('\0');
  if (!CreateProcessA(NULL, line.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    return false;
  }
  DWORD rc = WaitForSingleObject(pi.hProcess, timeout_ms);
  if (rc != WAIT_OBJECT_0) {
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return false;
  }
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return true;
}

static int render_pdf(report_t *r, buf_t *out, char *err, size_t err_cap) {
  std::string exe = browser_path();
  if (exe.empty()) {
    snprintf(err, err_cap, "这台机器没找到 Edge / Chrome,无法在本机把报告排成 PDF;"
                           "可以先用 HTML 导出,在浏览器里 Ctrl+P 存成 PDF");
    return -1;
  }

  char tmp[MAX_PATH * 2];
  DWORD n = GetTempPathA(sizeof(tmp), tmp);
  if (n == 0) { snprintf(err, err_cap, "拿不到临时目录"); return -1; }
  std::string base = tmp;
  if (!base.empty() && base.back() == '\\') base.pop_back();
  char stamp[64];
  snprintf(stamp, sizeof(stamp), "bw_report_%lu_%lld", (unsigned long)GetCurrentProcessId(), now_ms());
  std::string html = base + "\\" + stamp + ".html";
  std::string pdf = base + "\\" + stamp + ".pdf";
  std::string profile = base + "\\" + stamp + "_profile";

  buf_t page;
  buf_init(&page);
  render_html(r, &page);
  int ok = file_write_all(html.c_str(), page.data, page.len);
  buf_free(&page);
  if (ok != 0) { snprintf(err, err_cap, "写临时 HTML 失败"); return -1; }

  std::string url = html;
  for (size_t i = 0; i < url.size(); i++) if (url[i] == '\\') url[i] = '/';
  url = "file:///" + url;

  std::string cmd = "\"" + exe + "\" --headless=new --disable-gpu --no-first-run "
                            "--no-pdf-header-footer --user-data-dir=\"" + profile + "\" "
                            "--print-to-pdf=\"" + pdf + "\" \"" + url + "\"";
  bool ran = run_and_wait(cmd, 45000);

  size_t len = 0;
  char *bytes = ran ? file_read_all(pdf.c_str(), &len) : NULL;
  if (!bytes || len < 5) {
    snprintf(err, err_cap, "浏览器没能生成 PDF(可能是 headless 被策略禁用),"
                           "可以改用 HTML 导出再打印");
    DeleteFileA(html.c_str());
    DeleteFileA(pdf.c_str());
    fs_remove_tree(profile.c_str());
    free(bytes);
    return -1;
  }
  buf_putn(out, bytes, len);
  free(bytes);
  DeleteFileA(html.c_str());
  DeleteFileA(pdf.c_str());
  fs_remove_tree(profile.c_str());
  return 0;
}

/* ================= 对外 ================= */

int export_supported(const char *fmt) {
  if (!fmt) return 0;
  return str_ieq(fmt, "md") || str_ieq(fmt, "markdown") || str_ieq(fmt, "html") ||
         str_ieq(fmt, "csv") || str_ieq(fmt, "json") || str_ieq(fmt, "docx") ||
         str_ieq(fmt, "pdf");
}

void export_filename(const char *report_id, const char *fmt, char *out, size_t cap) {
  const char *ext = "bin";
  const char *f = fmt ? fmt : "";
  if (str_ieq(f, "md") || str_ieq(f, "markdown")) ext = "md";
  else if (str_ieq(f, "html")) ext = "html";
  else if (str_ieq(f, "csv")) ext = "csv";
  else if (str_ieq(f, "json")) ext = "json";
  else if (str_ieq(f, "docx")) ext = "docx";
  else if (str_ieq(f, "pdf")) ext = "pdf";
  snprintf(out, cap, "%s.%s", (report_id && report_id[0]) ? report_id : "report", ext);
}

int export_report(store_t *s, const char *report_id, const char *fmt, buf_t *out,
                  char *err, size_t err_cap) {
  if (err && err_cap) err[0] = 0;
  if (!s || !fmt || !export_supported(fmt)) {
    snprintf(err, err_cap, "不支持的导出格式");
    return -1;
  }
  report_t r;
  if (load_report(s, report_id, &r) != 0) {
    snprintf(err, err_cap, "找不到报告:先跑一轮巡检生成报告,再来导出");
    return -1;
  }
  int rc = 0;
  if (str_ieq(fmt, "md") || str_ieq(fmt, "markdown")) render_md(&r, out);
  else if (str_ieq(fmt, "html")) render_html(&r, out);
  else if (str_ieq(fmt, "csv")) render_csv(&r, out);
  else if (str_ieq(fmt, "json")) render_json(&r, out);
  else if (str_ieq(fmt, "docx")) render_docx(&r, out);
  else if (str_ieq(fmt, "pdf")) rc = render_pdf(&r, out, err, err_cap);
  report_free(&r);
  return rc;
}
