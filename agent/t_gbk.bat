@echo off
setlocal enabledelayedexpansion

rem ============================================================
rem  网站安全巡检智能体 (C++ 版) · 一键构建
rem  依赖:只用 g++(MinGW, C++20) + Windows 自带 DLL
rem
rem  产物:
rem    build\网站安全巡检智能体.exe   单文件成品(双击即用)
rem    build\agent.exe                命令行形态
rem    build\tools\<名字>.exe         每个内置工具一个独立进程
rem
rem  本脚本在 agent\ 下,所有相对路径都以它为准(源码 src\main\、界面 ui\、
rem  出厂数据 data\、产物 build\)。根目录的 启动.bat 会转调它。
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
if not exist build\obj mkdir build\obj
if not exist build\tools mkdir build\tools

rem 每个工具一个独立进程:这张表同时决定编哪几个 exe、以及打包进资源的路径。
rem 加一个工具 = 在这里加一行 + 在 data\tools\<名字>\ 放声明。
set "TOOLS=agent_info dir_probe fs_list fs_read fs_write nuclei_scan page_diff password_check pool_list sensitive_file_probe sensitive_scan settings_get settings_set site_crawl sqli_probe"

rem ---------- 1. 构建期小工具 ----------
if not exist "tools\mkres.cpp" (
    echo [错误] 缺 tools\mkres.cpp
    exit /b 3
)
"%GXX%" -std=c++20 -O2 -o build\mkres.exe tools\mkres.cpp
if errorlevel 1 ( echo [失败] mkres 编译失败 & exit /b 1 )

rem ---------- 2. 资源:界面 / 出厂数据 / WebView2 加载器 ----------
rem 工具 exe 走单独的资源文件,免得把 15 个 exe 递归打进主程序自身。
set "WV2LOADER=data\WebView2Loader.dll"
set "WV2RES="
if exist "%WV2LOADER%" set "WV2RES="data/WebView2Loader.dll=%WV2LOADER%""
if not defined WV2RES echo [提示] 没有 %WV2LOADER%,界面将无法内嵌 WebView2

build\mkres.exe build\resources.cpp ^
    "ui/index.html=ui\index.html" ^
    "ui/app.css=ui\app.css" ^
    "ui/app.js=ui\app.js" ^
    "ui/logo.png=ui\logo.png" ^
    "ui/favicon.ico=ui\favicon.ico" ^
    "data/mcp.json=data\mcp.json" ^
    "@data/rules/=data\rules" ^
    "@data/skills/=data\skills" ^
    "@data/tools/=data\tools" %WV2RES%
if errorlevel 1 ( echo [失败] 内置资源生成失败 & exit /b 1 )
if not exist "build\resources.cpp" ( echo [失败] 没有生成 build\resources.cpp & exit /b 1 )

rem 工具进程只需要出厂规则:不带界面、不带 DLL,体积与启动都更小
build\mkres.exe build\resources_core.cpp "@data/rules/=data\rules"
if errorlevel 1 ( echo [失败] 工具资源生成失败 & exit /b 1 )

rem ---------- 3. 图标与版本信息 ----------
if exist "third_party\windres.exe" set "WINDRES=third_party\windres.exe"
if not defined WINDRES for %%d in ("%GXX%") do if exist "%%~dpdwindres.exe" set "WINDRES=%%~dpdwindres.exe"
if not defined WINDRES where windres >nul 2>nul && set "WINDRES=windres"
if defined WINDRES (
    rem --codepage=65001:app.rc 是 UTF-8 存的。不加这一条 windres 按 ANSI 读,
    rem 版本资源里的中文会变成乱码,而 Windows 的通知气泡正是拿它当"应用名"显示。
    "%WINDRES%" --codepage=65001 -I . -I src\main -i src\main\app.rc -o build\app_res.o
    if errorlevel 1 ( echo [失败] 图标资源编译失败 & exit /b 1 )
)

rem ---------- 4. 编译源文件(编一次,链接很多次) ----------
set "CFLAGS=-std=c++20 -O2 -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -I src\main"
set "LIBS=-lws2_32 -lwinhttp -lbcrypt -lcrypt32 -lole32 -loleaut32 -luuid -luser32 -lgdi32 -lshell32 -ladvapi32"

echo [构建] %GXX%
echo [构建] 编译源文件...
set "OBJS="
for %%f in (src\main\*.cpp) do (
    set "OBJ=build\obj\%%~nf.o"
    "%GXX%" %CFLAGS% -c "%%f" -o "!OBJ!"
    if errorlevel 1 ( echo [失败] 编译 %%f & exit /b 1 )
    set "OBJS=!OBJS! !OBJ!"
)

rem ---------- 5. 工具进程:每个工具一个 exe ----------
echo [构建] 链接工具进程...
for %%t in (%TOOLS%) do (
    "%GXX%" %CFLAGS% -DTOOL_NAME=\"%%t\" -c tools\toolhost.cpp -o build\obj\toolhost_%%t.o
    if errorlevel 1 ( echo [失败] 编译工具宿主 %%t & exit /b 1 )
    "%GXX%" -static -s -mwindows -o build\tools\%%t.exe build\obj\toolhost_%%t.o !OBJS! build\resources_core.cpp %LIBS% -static-libgcc -static-libstdc++
    if errorlevel 1 ( echo [失败] 链接工具 %%t & exit /b 1 )
)
echo [构建] 工具进程:%TOOLS%

rem ---------- 6. 主程序 ----------
echo [构建] 链接主程序...
set "EXTRA="
if exist "build\app_res.o" set "EXTRA=build\app_res.o"
set "EXTRA=!EXTRA! build\resources.cpp"
"%GXX%" %CFLAGS% -DAGENT_GUI_BUILD -mwindows -static -s ^
    -o build\agent.exe !OBJS! !EXTRA! %LIBS%
if errorlevel 1 (
    echo.
    echo [失败] 主程序链接失败,请看上面的信息。
    exit /b 1
)

rem ---------- 7. 工具 exe 归位(声明与入口同目录) ----------
for %%t in (%TOOLS%) do (
    if not exist "data\tools\%%t" mkdir "data\tools\%%t"
    copy /y "build\tools\%%t.exe" "data\tools\%%t\%%t.exe" >nul
)

copy /y build\agent.exe "build\网站安全巡检智能体.exe" >nul

echo.
echo [完成] 单文件成品: build\网站安全巡检智能体.exe   ^(双击即用^)
echo        命令行工具:  build\agent.exe selftest / run / tool / serve / manifest
echo        独立工具:    build\tools\^<名字^>.exe
