@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

rem ============================================================
rem  网站安全巡检智能体 (C++ 版) · 一键构建
rem  依赖:只用 g++(MinGW, C++20) + Windows 自带 DLL
rem  产物:build\网站安全巡检智能体.exe(单文件,双击即用)与 build\agent.exe(命令行形态)
rem
rem  为什么用 -static:libstdc++ / libgcc / winpthread 全部静态链进来,
rem  否则目标机器缺 DLL 就打不开 —— 单文件交付的底线。
rem ============================================================

cd /d "%~dp0"

set "GXX="
where g++ >nul 2>nul && set "GXX=g++"
if not defined GXX if exist "C:\@Tool\mingw64\bin\g++.exe" set "GXX=C:\@Tool\mingw64\bin\g++.exe"
if not defined GXX (
    echo [错误] 找不到 g++。请安装 MinGW-w64 并把 g++ 放进 PATH,
    echo        或放到 C:\@Tool\mingw64\bin\g++.exe。
    exit /b 2
)

if not exist build mkdir build

rem ---------- 1. 内置资源:界面与默认规则编进 exe(单文件交付的关键) ----------
rem  mkres 把 ui\ 与 data\rules.json 转成 build\resources.cpp,所以 exe 不需要旁边的目录也能跑
if not exist "tools\mkres.cpp" (
    echo [错误] 缺 tools\mkres.cpp
    exit /b 3
)

set "MKRES=build\mkres.exe"
"%GXX%" -std=c++20 -O2 -o "%MKRES%" tools\mkres.cpp
if errorlevel 1 ( echo [失败] mkres 编译失败 & exit /b 1 )

"%MKRES%" build\resources.cpp ^
    "ui/index.html=ui\index.html" ^
    "ui/app.css=ui\app.css" ^
    "ui/app.js=ui\app.js" ^
    "ui/logo.ico=ui\logo.ico" ^
    "ui/logo.png=ui\logo.png" ^
    "data/rules.json=data\rules.json"
if errorlevel 1 ( echo [失败] 内置资源生成失败 & exit /b 1 )
if not exist "build\resources.cpp" ( echo [失败] 没有生成 build\resources.cpp & exit /b 1 )

rem ---------- 2. 图标与版本信息 ----------
if exist "third_party\windres.exe" set "WINDRES=third_party\windres.exe"
if not defined WINDRES for %%d in ("%GXX%") do if exist "%%~dpdwindres.exe" set "WINDRES=%%~dpdwindres.exe"
if not defined WINDRES where windres >nul 2>nul && set "WINDRES=windres"
if defined WINDRES (
    "%WINDRES%" -I . -I src -i src\app.rc -o build\app_res.o
    if errorlevel 1 ( echo [失败] 图标资源编译失败 & exit /b 1 )
)

set "SRC="
for %%f in (src\*.cpp) do set "SRC=!SRC! %%f"
set "EXTRA="
if exist "build\app_res.o" set "EXTRA=build\app_res.o"
if exist "build\resources.cpp" set "EXTRA=!EXTRA! build\resources.cpp"

echo [构建] %GXX%
echo [构建] 源文件:!SRC!%EXTRA%
echo.

"%GXX%" -std=c++20 -O2 -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers ^
    -DAGENT_GUI_BUILD -mwindows -static -s ^
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