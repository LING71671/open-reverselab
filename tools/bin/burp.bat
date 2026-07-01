@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "BURP_DIR=%~dp0..\ctf-website\burp"
set "BURP_JAR="
for /f "delims=" %%F in ('dir /b /a-d /o-d "%BURP_DIR%\burpsuite*.jar" "%BURP_DIR%\burp*.jar" 2^>nul') do (
  if not defined BURP_JAR set "BURP_JAR=%BURP_DIR%\%%F"
)
if not defined BURP_JAR (
  echo Burp Suite jar not found under "%BURP_DIR%".
  echo Download Burp Community or Professional from PortSwigger and place burpsuite*.jar there.
  exit /b 1
)
java -jar "%BURP_JAR%" %*
