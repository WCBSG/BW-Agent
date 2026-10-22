@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo Starting demo target server (L0: http://127.0.0.1:8890/, L1-L6: 8891-8896) ...
python server.py %*
echo.
echo Server stopped. Press any key to close.
pause >nul
