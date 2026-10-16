/* 环境限制探测:我们的进程是不是被放在 Job 对象里、有没有"活进程数上限"。
 *
 * 为什么查这个:受控实验显示 —— WebView2 的 browser 进程起来了、203ms 内
 * 拉起了 renderer/gpu/utility 共 5 个进程,然后在 609ms 时**整棵树一起消失**,
 * 而宿主侧还活着、也没收到 ProcessFailed。
 * 这种"子进程被统一收走"的特征,最典型的原因就是 Job 对象的
 * "活动进程数上限"(JOB_OBJECT_LIMIT_ACTIVE_PROCESS)。
 *
 * MinGW 的 winnt.h 已经提供 Job 对象的结构体与枚举,直接用,别自己重定义。 */
#include <windows.h>
#include <stdio.h>

static double mb(SIZE_T v) { return (double)v / (1024.0 * 1024.0); }

int main(void) {
  SetConsoleOutputCP(CP_UTF8);
  printf("=== 环境限制探测 ===\n");
  printf("pid=%lu\n", (unsigned long)GetCurrentProcessId());

  BOOL in_job = FALSE;
  if (!IsProcessInJob(GetCurrentProcess(), NULL, &in_job)) {
    printf("IsProcessInJob 失败 err=%lu\n", GetLastError());
    return 1;
  }
  printf("\n[作业对象] 当前进程在 Job 里: %s\n", in_job ? "是" : "否");

  /* 读当前进程所属 Job 的限制。手柄传 NULL 表示"当前进程所在 Job"。 */
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli;
  ZeroMemory(&eli, sizeof(eli));
  DWORD ret = 0;
  if (QueryInformationJobObject(NULL, JobObjectExtendedLimitInformation, &eli,
                                sizeof(eli), &ret)) {
    DWORD f = eli.BasicLimitInformation.LimitFlags;
    printf("[作业限制] LimitFlags = 0x%08X\n", (unsigned)f);
    printf("           活动进程数上限 (ACTIVE_PROCESS): %s",
           (f & JOB_OBJECT_LIMIT_ACTIVE_PROCESS) ? "已启用" : "未启用");
    if (f & JOB_OBJECT_LIMIT_ACTIVE_PROCESS) {
      printf("   上限 = %lu", (unsigned long)eli.BasicLimitInformation.ActiveProcessLimit);
    }
    printf("\n");
    printf("           Job 关闭时杀进程 (KILL_ON_JOB_CLOSE): %s\n",
           (f & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) ? "已启用" : "未启用");
    printf("           单进程内存上限: %s",
           (f & JOB_OBJECT_LIMIT_PROCESS_MEMORY) ? "已启用" : "未启用");
    if (f & JOB_OBJECT_LIMIT_PROCESS_MEMORY) printf("   上限 = %.1f MB", mb(eli.ProcessMemoryLimit));
    printf("\n");
    printf("           Job 总内存上限: %s",
           (f & JOB_OBJECT_LIMIT_JOB_MEMORY) ? "已启用" : "未启用");
    if (f & JOB_OBJECT_LIMIT_JOB_MEMORY) printf("   上限 = %.1f MB", mb(eli.JobMemoryLimit));
    printf("\n");
  } else {
    printf("[作业限制] 查询失败 err=%lu(可能不在任何 Job 里)\n", GetLastError());
  }

  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acc;
  ZeroMemory(&acc, sizeof(acc));
  if (QueryInformationJobObject(NULL, JobObjectBasicAccountingInformation, &acc,
                                sizeof(acc), &ret)) {
    printf("[作业统计] 总进程=%lu 活动进程=%lu 已终止=%lu\n",
           (unsigned long)acc.TotalProcesses, (unsigned long)acc.ActiveProcesses,
           (unsigned long)acc.TotalTerminatedProcesses);
  }

  /* 直接实测:连续起 N 个子进程,看第几个起不来 —— 比读限制更有说服力 */
  printf("\n[实测] 连续创建 12 个存活 15 秒的子进程,看能活下几个:\n");
  PROCESS_INFORMATION pi[12];
  int made = 0;
  for (int i = 0; i < 12; i++) {
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    wchar_t cmd[] = L"cmd.exe /c timeout /t 15 /nobreak >nul";
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL,
                       &si, &pi[i])) {
      made++;
      printf("  第 %2d 个: 创建成功 pid=%lu\n", i + 1, (unsigned long)pi[i].dwProcessId);
    } else {
      printf("  第 %2d 个: 创建失败 err=%lu  <-- 可能到上限了\n", i + 1, GetLastError());
      break;
    }
  }
  printf("实测结果: 成功创建 %d 个子进程\n", made);

  Sleep(2000);
  int alive = 0;
  for (int i = 0; i < made; i++) {
    DWORD code = 0;
    if (GetExitCodeProcess(pi[i].hProcess, &code) && code == STILL_ACTIVE) alive++;
    CloseHandle(pi[i].hProcess);
    CloseHandle(pi[i].hThread);
  }
  printf("2 秒后仍存活: %d 个%s\n", alive,
         alive < made ? "   <-- 有子进程被外部收走" : "");

  printf("\n结论:");
  if (made < 12) {
    printf(" Job 对活动进程数有限制(最多约 %d 个)-> WebView2 的多进程会被挤掉。\n", made);
  } else if (alive < made) {
    printf(" 子进程会被外部杀死 -> 与 WebView2 整棵树消失的现象一致。\n");
  } else {
    printf(" 本次没复现出限制,需要换角度(安全软件/沙箱初始化)继续查。\n");
  }
  return 0;
}
