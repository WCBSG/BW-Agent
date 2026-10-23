@echo off
chcp 65001 >nul
rem ============================================================
rem  调试版构建:-O0 -g(方便 gdb / 崩溃回溯),其余与 build.bat 一致
rem  产物:build\agent_dbg.exe(界面与出厂数据同样内置;加 --debug 可看日志窗口)
rem  说明:正式交付物仍由 build.bat 产出,本脚本只多出一个调试版
rem ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "GXX="
where g++ >nul 2>nul && set "GXX=g++"
if not defined GXX if exist "C:\@Tool\mingw64\bin\g++.exe" set "GXX=C:\@Tool\mingw64\bin\g++.exe"
if not defined GXX (
    echo [错误] 找不到 g++。
    exit /b 2
)

if not exist build mkdir build

"%GXX%" -std=c++20 -O2 -o build\mkres.exe tools\mkres.cpp
if errorlevel 1 ( echo [失败] mkres 编译失败 & exit /b 1 )

set "WV2LOADER=data\WebView2Loader.dll"
set "WV2RES="
if exist "%WV2LOADER%" set "WV2RES="data/WebView2Loader.dll=%WV2LOADER%""
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

build\mkres.exe build\resources_core.cpp "@data/rules/=data\rules"
if errorlevel 1 ( echo [失败] 工具资源生成失败 & exit /b 1 )

if exist "third_party\windres.exe" set "WINDRES=third_party\windres.exe"
if not defined WINDRES for %%d in ("%GXX%") do if exist "%%~dpdwindres.exe" set "WINDRES=%%~dpdwindres.exe"
if not defined WINDRES where windres >nul 2>nul && set "WINDRES=windres"
if defined WINDRES "%WINDRES%" --codepage=65001 -I . -I src\main -i src\main\app.rc -o build\app_res.o

set "SRC="
for %%f in (src\main\*.cpp) do set "SRC=!SRC! %%f"
set "EXTRA="
if exist "build\app_res.o" set "EXTRA=build\app_res.o"
if exist "build\resources.cpp" set "EXTRA=!EXTRA! build\resources.cpp"

"%GXX%" -std=c++20 -O0 -g -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers ^
    -DAGENT_GUI_BUILD -mwindows -static ^
    -I src\main ^
    -o build\agent_dbg.exe !SRC! !EXTRA! ^
    -lws2_32 -lwinhttp -lbcrypt -lcrypt32 -lole32 -loleaut32 -luuid -luser32 -lgdi32 -lshell32 -ladvapi32

if errorlevel 1 ( echo [失败] 调试版编译出错 & exit /b 1 )
echo [完成] 调试版: build\agent_dbg.exe
