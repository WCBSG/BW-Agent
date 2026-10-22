@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem ============================================================
rem  网站安全巡检智能体 · 一键启动
rem
rem  用法:
rem     启动.bat                 直接启动(界面窗口自动打开)
rem     启动.bat 127.0.0.1:8081  指定要巡检的目标后启动
rem
rem  交付给用户的就是一个 exe,数据默认放在 C:\Users\<用户名>\.bw_agent,
rem  所以 exe 放在哪儿都能跑,不会把周围目录搞乱。
rem ============================================================

set "EXE=build\网站安全巡检智能体.exe"
if not exist "%EXE%" set "EXE=build\agent.exe"
if not exist "%EXE%" goto BUILD

if not "%~1"=="" set "DAS_TARGET=%~1"

echo.
echo  正在启动 …… 界面窗口会自动打开;关掉界面窗口即停止服务。
echo  (要看命令行窗口和实时日志,就用 --debug 启动: 网站安全巡检智能体.exe --debug)
echo.
start "" "%EXE%" start
goto END

:BUILD
echo   还没编译过,先编译(需要一个 gcc)……
call build.bat
if errorlevel 1 goto END
echo   编译完成,继续启动……
echo.
start "" "%EXE%" start

:END
endlocal
