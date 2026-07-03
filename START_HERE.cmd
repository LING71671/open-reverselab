@echo off
setlocal
cd /d "%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\misc\start_here.ps1"
set "EXIT_CODE=%ERRORLEVEL%"

echo.
if not "%EXIT_CODE%"=="0" (
  echo ReverseLab first-run helper finished with errors. Exit code: %EXIT_CODE%
) else (
  echo ReverseLab first-run helper finished successfully.
)
echo.
pause
exit /b %EXIT_CODE%
