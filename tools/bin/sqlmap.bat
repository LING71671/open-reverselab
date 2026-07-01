@echo off
set "SQLMAP=%~dp0..\ctf-website\sqlmap\sqlmap.py"
if not exist "%SQLMAP%" (
  echo sqlmap.py not found at "%SQLMAP%".
  echo Run: powershell -ExecutionPolicy Bypass -File scripts\misc\install_tools.ps1 -CTF
  exit /b 1
)
python "%SQLMAP%" %*
