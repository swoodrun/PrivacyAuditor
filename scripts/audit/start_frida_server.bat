@echo off
chcp 65001 >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_frida_server.ps1" %*
echo.
pause
