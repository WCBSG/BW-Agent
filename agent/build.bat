@echo off
chcp 65001 >nul
rem ============================================================
rem  Website Security Inspection Agent - build script
rem  Requires: g++ (MinGW-w64, C++20) + Windows system DLLs only
rem
rem  Output:
rem    build\<product>.exe       single-file deliverable (name in product.name)
rem    build\agent.exe           console / CLI form
rem    build\bw_tools.exe        all built-in tools in one host process
rem
rem  NOTE: keep this file ASCII-only. A multi-byte character in a .bat
rem  can end with 0x5E and turn into a line-continuation, which breaks
rem  cmd parsing. All Chinese output comes from the program itself.
rem ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "GXX="
where g++ >nul 2>nul && set "GXX=g++"
if not defined GXX if exist "C:\@Tool\mingw64\bin\g++.exe" set "GXX=C:\@Tool\mingw64\bin\g++.exe"
if not defined GXX (
    echo [ERROR] g++ not found. Install MinGW-w64 or put it in C:\@Tool\mingw64\bin.
    exit /b 2
)

if not exist build mkdir build
if not exist build\obj mkdir build\obj
if not exist "data\tools\bw_tools" mkdir "data\tools\bw_tools"

rem ---------- 1. build-time helper ----------
if not exist "tools\mkres.cpp" (
    echo [ERROR] missing tools\mkres.cpp
    exit /b 3
)
"%GXX%" -std=c++20 -O2 -o build\mkres.exe tools\mkres.cpp
if errorlevel 1 ( echo [FAILED] mkres & exit /b 1 )

rem Tool host only needs factory rules: no UI, no DLL.
build\mkres.exe build\resources_core.cpp "@data/rules/=data\rules"
if errorlevel 1 ( echo [FAILED] tool resources & exit /b 1 )

rem ---------- 2. compile sources ----------
set "CFLAGS=-std=c++20 -O2 -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -I src\main -I src\tools"
set "LIBS=-lws2_32 -lwinhttp -lbcrypt -lcrypt32 -lole32 -loleaut32 -luuid -luser32 -lgdi32 -lshell32 -ladvapi32"

echo [BUILD] %GXX%
echo [BUILD] compiling sources...
set "OBJS="
rem Engine objects: src\main\*.cpp except main.cpp (the app entry).
for %%f in (src\main\*.cpp) do (
    set "OBJ=build\obj\%%~nf.o"
    "%GXX%" %CFLAGS% -c "%%f" -o "!OBJ!"
    if errorlevel 1 ( echo [FAILED] compile %%f & exit /b 1 )
    if /i not "%%~nf"=="main" if /i not "%%~nf"=="bw_tools" set "OBJS=!OBJS! !OBJ!"
)
rem Every tool implementation is one file; bw_tools.cpp is the host entry.
for %%f in (src\tools\*.cpp) do (
    set "OBJ=build\obj\tool_%%~nf.o"
    "%GXX%" %CFLAGS% -c "%%f" -o "!OBJ!"
    if errorlevel 1 ( echo [FAILED] compile %%f & exit /b 1 )
    if /i not "%%~nf"=="bw_tools" set "OBJS=!OBJS! !OBJ!"
)

rem ---------- 3. tool host: one exe, all tools ----------
echo [BUILD] linking tool host...
"%GXX%" %CFLAGS% -c src\tools\bw_tools.cpp -o build\obj\bw_tools.o
if errorlevel 1 ( echo [FAILED] compile bw_tools & exit /b 1 )
"%GXX%" -static -s -mwindows %CFLAGS% -o build\bw_tools.exe ^
    build\obj\bw_tools.o !OBJS! build\resources_core.cpp %LIBS%
if errorlevel 1 ( echo [FAILED] link bw_tools & exit /b 1 )
copy /y build\bw_tools.exe "data\tools\bw_tools\bw_tools.exe" >nul

rem ---------- 4. app resources (must include the tool host) ----------
set "WV2LOADER=data\WebView2Loader.dll"
set "WV2RES="
if exist "%WV2LOADER%" set "WV2RES="data/WebView2Loader.dll=%WV2LOADER%""
if not defined WV2RES echo [WARN] %WV2LOADER% not found - embedded WebView2 disabled

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
if errorlevel 1 ( echo [FAILED] app resources & exit /b 1 )
if not exist "build\resources.cpp" ( echo [FAILED] resources.cpp not generated & exit /b 1 )

rem ---------- 5. icon and version info ----------
if exist "third_party\windres.exe" set "WINDRES=third_party\windres.exe"
if not defined WINDRES for %%d in ("%GXX%") do if exist "%%~dpdwindres.exe" set "WINDRES=%%~dpdwindres.exe"
if not defined WINDRES where windres >nul 2>nul && set "WINDRES=windres"
if defined WINDRES (
    rem --codepage=65001: app.rc is UTF-8; without it Chinese version info is garbled.
    "%WINDRES%" --codepage=65001 -I . -I src\main -i src\main\app.rc -o build\app_res.o
    if errorlevel 1 ( echo [FAILED] windres & exit /b 1 )
)

rem ---------- 6. main program ----------
echo [BUILD] linking main program...
set "EXTRA="
if exist "build\app_res.o" set "EXTRA=build\app_res.o"
set "EXTRA=!EXTRA! build\resources.cpp build\obj\main.o"
"%GXX%" %CFLAGS% -DAGENT_GUI_BUILD -mwindows -static -s ^
    -o build\agent.exe !OBJS! !EXTRA! %LIBS%
if errorlevel 1 (
    echo.
    echo [FAILED] link main program
    exit /b 1
)

rem Product file name is kept in product.name (UTF-8) so this script stays ASCII.
set "APPNAME="
for /f "usebackq delims=" %%n in ("product.name") do set "APPNAME=%%n"
if not defined APPNAME set "APPNAME=WebSecAgent"
copy /y build\agent.exe "build\!APPNAME!.exe" >nul

echo.
echo [DONE] single-file build: build\!APPNAME!.exe
echo        CLI:   build\agent.exe selftest / run / tool / serve / manifest
echo        tools: build\bw_tools.exe  (all built-in tools in one process)
