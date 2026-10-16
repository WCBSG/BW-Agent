@echo off
chcp 65001 >nul
rem ============================================================
rem  调试版构建:-O0 -g(方便 gdb / 崩溃回溯),其余与 build.bat 一致
rem  产物:build\agent_dbg.exe(界面与出厂规则同样内置;加 --debug 可看日志窗口)
rem  说明:正式交付物仍由 build.bat 产出,本脚本只多出一个调试版,不动正式文件
rem ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "GCC="
where gcc >nul 2>nul && set "GCC=gcc"
if not defined GCC if exist "C:\@Tool\mingw64\bin\gcc.exe" set "GCC=C:\@Tool\mingw64\bin\gcc.exe"
if not defined GCC (
    echo [错误] 找不到 gcc。
    exit /b 2
)

if not exist build mkdir build

rem 内置资源(与 build.bat 同一套:界面 + 出厂规则)
"%GCC%" -std=c11 -O2 -o build\mkres.exe tools\mkres.c
if errorlevel 1 ( echo [失败] mkres 编译失败 & exit /b 1 )
build\mkres.exe build\resources.c ^
    "ui/index.html=ui\index.html" ^
    "ui/app.css=ui\app.css" ^
    "ui/app.js=ui\app.js" ^
    "ui/logo.ico=ui\logo.ico" ^
    "ui/logo.png=ui\logo.png" ^
    "data/rules.json=data\rules.json"
if errorlevel 1 ( echo [失败] 内置资源生成失败 & exit /b 1 )

if exist "third_party\windres.exe" set "WINDRES=third_party\windres.exe"
if not defined WINDRES for %%d in ("%GCC%") do if exist "%%~dpdwindres.exe" set "WINDRES=%%~dpdwindres.exe"
if not defined WINDRES where windres >nul 2>nul && set "WINDRES=windres"
if defined WINDRES "%WINDRES%" -I . -I src -i src\app.rc -o build\app_res.o

set "SRC="
for %%f in (src\*.c) do set "SRC=!SRC! %%f"

echo [构建] 调试版: -O0 -g
"%GCC%" -std=c11 -O0 -g -w -DAGENT_GUI_BUILD -mwindows ^
    -I src -I third_party\webview2 ^
    -o build\agent_dbg.exe !SRC! build\resources.c build\app_res.o ^
    -lws2_32 -lwinhttp -lbcrypt -lcrypt32 -lole32 -loleaut32 -luuid -luser32 -lgdi32 -lshell32 -ladvapi32
if errorlevel 1 ( echo [失败] 编译出错 & exit /b 1 )

echo.
echo [完成] 调试版: build\agent_dbg.exe
echo        自检:  build\agent_dbg.exe selftest
endlocal