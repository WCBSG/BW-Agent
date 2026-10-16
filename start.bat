@echo off
rem ASCII 入口:某些终端/PowerShell 调中文文件名会乱码,这里做个纯英文别名。
rem 真正干活的逻辑都在 启动.bat 里,只此一份。
call "%~dp0启动.bat" %*
