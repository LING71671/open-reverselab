@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0\scripts\codex\launcher_entry.ps1"
set "EXIT_CODE=%ERRORLEVEL%"

echo.
if not "%EXIT_CODE%"=="0" (
  echo LAUNCHER.bat exited with code: %EXIT_CODE%
)
echo.
pause
exit /b %EXIT_CODE%
