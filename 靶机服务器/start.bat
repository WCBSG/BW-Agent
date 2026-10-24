@echo off
REM ==================================================================
REM  分级靶场 · 一键启动
REM ------------------------------------------------------------------
REM  双击本文件即可：
REM    1. 启动靶场服务器（默认 8081）
REM    2. 打印本机访问地址
REM    3. 另开窗口提示如何自检
REM
REM  为什么用 .bat？—— Windows 下双击就能跑，不用记命令。
REM  真正的逻辑在 serve.py 里；这里只是包一层，方便演示时少打命令。
REM ==================================================================
chcp 65001 >nul
setlocal

cd /d "%~dp0"

echo.
echo   ============================================================
echo     网站安全巡检 · 分级靶场
echo   ============================================================
echo.

REM ---- 找一个可用的 Python ----
set "PY="
where py >nul 2>nul && set "PY=py"
if not defined PY (
  where python >nul 2>nul && set "PY=python"
)
if not defined PY (
  echo   [错误] 没有找到 Python。
  echo          请先安装 Python，或把 python.exe 加入 PATH。
  echo.
  pause
  exit /b 1
)

echo   使用 Python：%PY%
echo.

REM ---- 端口占用检查 ----
echo   检查 8081 端口...
netstat -ano | findstr /r /c:":8081 .*LISTENING" >nul 2>nul
if not errorlevel 1 (
  echo   [警告] 8081 端口已被占用。
  echo          可能是靶场已经在运行了。
  echo          若要用别的端口，请手动执行：  %PY% serve.py --port 9000
  echo.
  pause
  exit /b 1
)

echo   端口可用。
echo.
echo   ------------------------------------------------------------
echo    正在启动靶场服务器（按 Ctrl+C 停止）
echo   ------------------------------------------------------------
echo.
echo    自检（另开一个窗口执行）：
echo        %PY% verify_range.py --port 8081
echo.
echo    重新生成静态资产（改了关卡内容后）：
echo        %PY% build_assets.py
echo.

REM ---- 没装 PHP 时提前提醒，避免以为是靶场坏了 ----
if not exist "C:\Program Files\.tool\php-8.5.10\php-cgi.exe" (
  echo    [提示] 未检测到 PHP，8 个动态漏洞考点会返回 503。
  echo           其余 85 项不受影响。装了 PHP 后自动启用。
  echo.
)

%PY% serve.py --port 8081

echo.
echo   靶场已停止。
pause
endlocal
