@echo off
rem ============================================================
rem  NetworkChecker launcher
rem  Double-click this file to start. It finds the newest
rem  NetworkChecker_v*.ps1 next to it and runs it with PowerShell.
rem  The script itself asks for administrator rights (UAC).
rem ============================================================
setlocal
cd /d "%~dp0"

set "SCRIPT="
for /f "delims=" %%F in ('dir /b /a-d /o-n "NetworkChecker_v*.ps1" 2^>nul') do (
    set "SCRIPT=%%F"
    goto :found
)

echo.
echo  [!] NetworkChecker_v*.ps1 not found in this folder:
echo      %~dp0
echo.
pause
exit /b 1

:found
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0%SCRIPT%"
exit /b %ERRORLEVEL%
