@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

rem ============================================================
rem  网站安全巡检智能体 (C 版) · 一键构建
rem  依赖:只用 gcc(MinGW) + Windows 自带 DLL,不需要任何第三方库
rem  产物:build\网站安全巡检智能体.exe(单文件,双击即用)与 build\agent.exe(命令行形态)
rem ============================================================

cd /d "%~dp0"

set "GCC="
where gcc >nul 2>nul && set "GCC=gcc"
if not defined GCC if exist "C:\@Tool\mingw64\bin\gcc.exe" set "GCC=C:\@Tool\mingw64\bin\gcc.exe"
if not defined GCC (
    echo [错误] 找不到 gcc。请安装 MinGW-w64 并把 gcc 放进 PATH,
    echo        或放到 C:\@Tool\mingw64\bin\gcc.exe。
    exit /b 2
)

if not exist build mkdir build

rem ---------- 1. 内置资源:界面与默认规则编进 exe(单文件交付的关键) ----------
rem  mkres 把 ui\ 与 data\rules.json 转成 build\resources.c,所以 exe 不需要旁边的目录也能跑
if not exist "tools\mkres.c" (
    echo [错误] 缺 tools\mkres.c
    exit /b 3
)

set "MKRES=build\mkres.exe"
rem mkres 很小,每次直接重建 —— 比"比较时间戳"可靠(时间戳比较在中文/特殊时区下会骗人)
"%GCC%" -std=c11 -O2 -o "%MKRES%" tools\mkres.c
if errorlevel 1 ( echo [失败] mkres 编译失败 & exit /b 1 )

"%MKRES%" build\resources.c ^
    "ui/index.html=ui\index.html" ^
    "ui/app.css=ui\app.css" ^
    "ui/app.js=ui\app.js" ^
    "ui/logo.ico=ui\logo.ico" ^
    "ui/logo.png=ui\logo.png" ^
    "data/rules.json=data\rules.json"
if errorlevel 1 ( echo [失败] 内置资源生成失败 & exit /b 1 )
if not exist "build\resources.c" ( echo [失败] 没有生成 build\resources.c & exit /b 1 )

rem ---------- 2. 图标与版本信息 ----------
if exist "third_party\windres.exe" set "WINDRES=third_party\windres.exe"
if not defined WINDRES for %%d in ("%GCC%") do if exist "%%~dpdwindres.exe" set "WINDRES=%%~dpdwindres.exe"
if not defined WINDRES where windres >nul 2>nul && set "WINDRES=windres"
if defined WINDRES (
    "%WINDRES%" -I . -I src -i src\app.rc -o build\app_res.o
    if errorlevel 1 ( echo [失败] 图标资源编译失败 & exit /b 1 )
)

set "SRC="
for %%f in (src\*.c) do set "SRC=!SRC! %%f"
set "EXTRA="
if exist "build\app_res.o" set "EXTRA=build\app_res.o"
if exist "build\resources.c" set "EXTRA=!EXTRA! build\resources.c"

echo [构建] %GCC%
echo [构建] 源文件:!SRC!%EXTRA%
echo.

"%GCC%" -std=c11 -O2 -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers ^
    -DAGENT_GUI_BUILD -mwindows ^
    -I src -I third_party\webview2 ^
    -o build\agent.exe !SRC! !EXTRA! ^
    -lws2_32 -lwinhttp -lbcrypt -lcrypt32 -lole32 -loleaut32 -luuid -luser32 -lgdi32 -lshell32 -ladvapi32

if errorlevel 1 (
    echo.
    echo [失败] 编译出错,请看上面的信息。
    exit /b 1
)

rem ---------- 3. 交付用的单文件 exe(带图标与中文名) ----------
copy /y build\agent.exe "build\网站安全巡检智能体.exe" >nul

echo.
echo [完成] 单文件成品: build\网站安全巡检智能体.exe   ^(双击即用^)
echo        命令行工具:  build\agent.exe selftest / run / tool / serve / manifest
