/* 公共头:所有人共用的基础件。
   设计原则:零第三方依赖 —— 只用 Windows 自带的东西,自己写 JSON/字符串/哈希。
   这样评委拿到源码只要一个 gcc 就能编,不需要 pip/npm 那一套。 */
#ifndef AGENT_COMMON_H
#define AGENT_COMMON_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

/* ---------- Win32 句柄的 RAII 包装 ----------
   句柄泄漏在本项目里踩过(HTTP 重试路径有多个 close 出口,漏一个就泄漏)。
   现在把"关闭"绑定到对象生命周期:离开作用域自动关掉。
   注意:句柄是 void*,unique_ptr 的默认删除器会调 delete ——
   所以必须传自定义删除器,下面这个 struct 就是干这个的。 */
struct handle_closer {
  void operator()(void *h) const {
    if (h && h != (void *)INVALID_HANDLE_VALUE) CloseHandle((HANDLE)h);
  }
};
using unique_handle_t = std::unique_ptr<void, handle_closer>;

/* ---------- 动态缓冲区:字符串拼接的基本单元 ---------- */
typedef struct {
  char *data;
  size_t len;
  size_t cap;
} buf_t;

void buf_init(buf_t *b);
void buf_free(buf_t *b);
void buf_clear(buf_t *b);
void buf_reserve(buf_t *b, size_t extra);
void buf_puts(buf_t *b, const char *s);
void buf_putn(buf_t *b, const char *s, size_t n);
void buf_putc_(buf_t *b, char c);
void buf_printf(buf_t *b, const char *fmt, ...);
/* 拼 JSON 字符串字面量:自动转义引号、反斜杠、控制符(UTF-8 中文原样保留) */
void buf_json_str(buf_t *b, const char *s);
char *buf_take(buf_t *b);       /* 交出内部指针,缓冲区复位(调用方负责 free) */

/* ---------- 编码 ---------- */
/* Base64(标准表,带 = 补位)。两处要用:平台接口签名、WebSocket 握手。 */
void b64_encode(const unsigned char *src, size_t len, buf_t *out);
/* 二进制转十六进制小写(用于指纹/哈希的可读化) */
void hex_encode(const unsigned char *src, size_t len, char *out, size_t cap);

/* ---------- 内存小工具 ---------- */
void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t sz);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);

/* ---------- UTF-8 <-> UTF-16(Windows API 要宽字符) ---------- */
wchar_t *u8_to_w(const char *s);
char *w_to_u8(const wchar_t *w);
char *w_to_u8_alloc(const wchar_t *w, int chars);   /* 释放用 free */
/* 最多保留 max_bytes 字节,但不切断多字节字符。返回实际字节数(<= max_bytes)。
   按字节截中文会截出半个字,界面上就是乱码 —— 凡是"摘要/标题"都必须走这里。 */
size_t u8_prefix(const char *s, size_t max_bytes);

/* ---------- 时间 ---------- */
/* 2026-10-15T09:30:00.000Z —— 与三册合同里的 ISO 格式完全一致 */
void now_iso(char *out, size_t cap);
void now_iso_at(FILETIME ft, char *out, size_t cap);
long long now_ms(void);
void ms_to_iso(long long ms, char *out, size_t cap);

/* ---------- 日志 ---------- */
typedef enum { LOG_DEBUG = 0, LOG_INFO, LOG_WARN, LOG_ERROR } log_level_t;
void log_open(const char *path);       /* 传 NULL 只输出到控制台 */
void log_close(void);
void log_set_level(log_level_t level);
void log_write(log_level_t level, const char *fmt, ...);
/* 控制台是 UTF-8 输出,保证中文不打成乱码 */
void console_init(void);

/* ---------- 界面程序的控制台策略 ----------
   交付的 exe 是 GUI 子系统程序:双击时不弹黑框。
   但命令行用法(selftest / run / tool / chat / serve)又必须能看到输出,所以:
     1) 先尝试挂到父进程的控制台(cmd / PowerShell 里运行时输出就回到那个窗口);
     2) 挂不上且 want_window(用户带了 --debug)就自己分配一个控制台窗口;
     3) 都没有 —— 静默模式,日志走文件(见 log_open)。
   返回 1 表示有可用的控制台。 */
int app_console_init(int want_window);

/* 从原始命令行取参数(宽字符 → UTF-8)。
   为什么不用 main(argc,argv):GUI 子系统程序的入口是 WinMain,
   而 CommandLineToArgvW 是唯一能正确处理引号与中文的方式。
   返回的 argv 用 free_argv 释放。 */
char **app_argv_from_command_line(int *argc_out);
void free_argv(int argc, char **argv);

/* ---------- 命令行参数编码 ----------
   Windows 把命令行以"控制台 ANSI 代码页"交给程序(中文系统是 GBK),
   而程序内部一律用 UTF-8。这一步把 argv 就地转成 UTF-8,
   否则 `agent.exe run 技能名` 这种中文参数会被判成"没有这个技能"。 */
void app_fix_argv_encoding(int argc, char **argv);

#define log_debug(...) log_write(LOG_DEBUG, __VA_ARGS__)
#define log_info(...)  log_write(LOG_INFO,  __VA_ARGS__)
#define log_warn(...)  log_write(LOG_WARN,  __VA_ARGS__)
#define log_error(...) log_write(LOG_ERROR, __VA_ARGS__)

/* ---------- 文本工具 ---------- */
int  str_ieq(const char *a, const char *b);            /* 忽略大小写比较 */
int  str_startswith(const char *s, const char *prefix);
int  str_endswith(const char *s, const char *suffix);
char *str_trim(char *s);                              /* 原地去空白 */
int  str_contains(const char *hay, const char *needle);
int  str_icontains(const char *hay, const char *needle);
/* 忽略大小写找第一次出现的位置(返回 hay 内指针),没有返回 NULL */
const char *str_icase_find(const char *hay, const char *needle);
/* 按分隔符切分,返回片段个数,out 里是 xstrdup 出来的(调用方 free_all) */
int  str_split(const char *s, char sep, char ***out, int max_parts);
void str_free_list(char **list, int n);

/* ---------- 路径 ---------- */
void path_dir_of(const char *path, char *out, size_t cap);   /* 取所在目录 */
int  path_join(char *out, size_t cap, const char *dir, const char *name);
void ensure_dir(const char *dir);
long file_size(const char *path);
char *file_read_all(const char *path, size_t *out_len);      /* 读不到返回 NULL */
int  file_write_all(const char *path, const char *data, size_t len);
int  file_append(const char *path, const char *data, size_t len);

/* ---------- 目录遍历(统一走 std::filesystem) ----------
   为什么不让各模块自己调 FindFirstFile:
     · A/W 两个版本混用是踩过的坑(中文文件名在 ANSI 版里直接"看不见");
     · std::filesystem 只有一套 Unicode 语义,这类 bug 从根上不会再有。
   返回文件名(不含目录),按名字排序,方便复现与测试。 */
std::vector<std::string> fs_list_files(const char *dir, const char *ext);
/* 只列子目录名(线程目录这种"一个会话一个文件夹"的形态要用) */
std::vector<std::string> fs_list_dirs(const char *dir);
/* 递归删除目录(尽力而为:删不掉的就留着,不抛异常、不中断) */
void fs_remove_tree(const char *dir);

/* ---------- 全局:程序所在目录(所有相对路径都以它为基准) ---------- */
void app_init_paths(void);
const char *app_dir(void);          /* 如 C:\@Active\网络安全作品赛\build\   */
const char *app_exe(void);

/* ---------- 数据目录(运行数据都放这里) ----------
   默认 C:\Users\<用户名>\.bw_agent —— 交付的是一个 exe,放在哪儿都能跑,
   数据落在用户目录里更符合习惯(不会把 exe 旁边搞乱,也不需要管理员权限)。
   需要隔离/搬家时设环境变量 BW_AGENT_HOME 指到别处即可。 */
const char *app_data_dir(void);
/* 把数据目录拼成"<数据目录>\子项";返回 out */
const char *app_data_path(char *out, size_t cap, const char *child);

#endif /* AGENT_COMMON_H */
