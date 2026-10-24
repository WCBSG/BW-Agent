/* fs_common.cpp —— 文件类工具共用的路径边界(读/列/写三个工具都用它)。
 *
 * 为什么要有:巡检要看的东西有一大半在本地 —— nuclei 导出的结果、导出的日志、
 * 人自己整理的资产/授权表、上一次的基线。没有读文件的能力,这些内容只能靠人手粘
 * 给模型;没有写文件的能力,模型好不容易归并出来的结论还得人再抄一遍。
 *
 * 安全边界(硬性,不提供任何"放宽"的开关):
 *   1. 读只能碰两个根:数据目录、程序所在目录。别处一律拒绝。
 *   2. 写只能落在数据目录里 —— 程序目录里是 exe 与内置数据,改坏了就起不来了。
 *   3. 路径先规范化成绝对路径再比对前缀,`..\..\` 这类穿越在规范化阶段就被吃掉,
 *      所以"前缀看起来像"不会被用来骗过检查。
 *   4. 覆盖写之前先留一份 .bak;不提供删除 —— 要删请人自己删。
 *
 * 这些限制写死在代码里而不是规则里:规则是可以被模型改的,边界不行。
 */
#include "tool_api.h"

#include <windows.h>

#include "json.h"

/* ================= 路径规范化与边界判定 ================= */

/* 把用户给的路径变成不带 .. 的绝对路径。相对路径按数据目录算(最常用的那个)。 */
int abs_path(const char *raw, wchar_t *out, size_t cap) {
  if (!raw || !*raw) return 0;
  char tmp[MAX_PATH * 2];
  snprintf(tmp, sizeof(tmp), "%s", raw);
  for (char *p = tmp; *p; p++) {
    if (*p == '/') *p = '\\';
  }
  wchar_t *wrel = u8_to_w(tmp);
  if (!wrel) return 0;

  /* 相对路径的基准:数据目录(exe 所在目录在多数交付里是只读位置,不适合当默认落点) */
  wchar_t *bw = u8_to_w(app_data_dir());
  if (!bw) {
    free(wrel);
    return 0;
  }

  wchar_t combined[MAX_PATH * 4];
  size_t clen = wcslen(wrel);
  if (clen >= 2 && wrel[1] == L':') {
    wcsncpy(combined, wrel, MAX_PATH * 4 - 1);
    combined[MAX_PATH * 4 - 1] = 0;
  } else if (wrel[0] == L'\\') {
    /* 根相对(单个反斜杠):按数据目录所在盘补全,而不是当成"绝对路径" */
    wcsncpy(combined, bw, 2);              /* 保留 "C:" */
    combined[2] = 0;
    wcsncat(combined, wrel, MAX_PATH * 4 - wcslen(combined) - 1);
  } else {
    wcsncpy(combined, bw, MAX_PATH * 4 - 1);
    combined[MAX_PATH * 4 - 1] = 0;
    size_t n = wcslen(combined);
    if (n && combined[n - 1] != L'\\') wcsncat(combined, L"\\", 1);
    wcsncat(combined, wrel, MAX_PATH * 4 - wcslen(combined) - 1);
  }
  free(wrel);
  free(bw);

  /* GetFullPathName 会消掉 . 与 ..,但不会要求文件存在 —— 正好用于"写入前"判边界 */
  wchar_t full[MAX_PATH * 4];
  DWORD got = GetFullPathNameW(combined, (DWORD)(sizeof(full) / sizeof(full[0])), full, NULL);
  if (got == 0 || got >= sizeof(full) / sizeof(full[0])) return 0;
  /* 去掉末尾多余的反斜杠("C:\a\" 与 "C:\a") */
  size_t len = wcslen(full);
  while (len > 3 && full[len - 1] == L'\\') full[--len] = L'\0';
  if (len + 1 > cap) return 0;
  wcscpy(out, full);
  return 1;
}

/* a 是不是落在 root 里面(root 自己也算) */
int under_root(const wchar_t *path, const char *root_u8) {
  wchar_t *rw = u8_to_w(root_u8);
  if (!rw) return 0;
  wchar_t root[MAX_PATH * 4];
  DWORD got = GetFullPathNameW(rw, (DWORD)(sizeof(root) / sizeof(root[0])), root, NULL);
  free(rw);
  if (got == 0) return 0;
  size_t n = wcslen(root);
  while (n > 3 && root[n - 1] == L'\\') root[--n] = L'\0';
  if (_wcsnicmp(path, root, n) != 0) return 0;
  return path[n] == L'\0' || path[n] == L'\\';
}

/* 读允许:数据目录 + 程序目录 + 调用方额外给的一个根(独立工具 exe 用)。
   写允许:只有数据目录。 */
static char g_extra_root[MAX_PATH * 4];

void fs_tool_set_extra_root(const char *dir) {
  if (!dir || !*dir) {
    g_extra_root[0] = 0;
    return;
  }
  snprintf(g_extra_root, sizeof(g_extra_root), "%s", dir);
}

int check_allowed(const wchar_t *full, int for_write, char *err, size_t err_cap) {
  if (for_write) {
    if (under_root(full, app_data_dir())) return 1;
    snprintf(err, err_cap, "只能往数据目录里写(%s),程序目录是只读的", app_data_dir());
    return 0;
  }
  if (under_root(full, app_data_dir())) return 1;
  if (under_root(full, app_dir())) return 1;
  if (g_extra_root[0] && under_root(full, g_extra_root)) return 1;
  snprintf(err, err_cap, "只能读数据目录(%s)或程序目录(%s)下的文件", app_data_dir(),
           app_dir());
  return 0;
}


/* 行切分:总行数(末尾没有换行也算一行) */
void split_lines(const char *data, size_t len, int *total_out) {
  int total = 0;
  if (len == 0) {
    *total_out = 0;
    return;
  }
  for (size_t i = 0; i < len; i++) {
    if (data[i] == '\n') total++;
  }
  if (data[len - 1] != '\n') total++;
  *total_out = total;
}
