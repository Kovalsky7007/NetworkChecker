@echo off
rem ============================================================
rem  NetworkChecker launcher
rem  Double-click this file to start. It runs NetworkChecker.ps1
rem  next to it (falls back to the older NetworkChecker_v*.ps1).
rem  The script itself asks for administrator rights (UAC).
rem ============================================================
setlocal
cd /d "%~dp0"

set "SCRIPT="
rem Preferred: the unversioned name.
if exist "%~dp0NetworkChecker.ps1" set "SCRIPT=NetworkChecker.ps1"

rem Fallback: any legacy NetworkChecker_v*.ps1 (newest by name).
if not defined SCRIPT (
    for /f "delims=" %%F in ('dir /b /a-d /o-n "NetworkChecker_v*.ps1" 2^>nul') do (
        set "SCRIPT=%%F"
        goto :found
    )
)

if defined SCRIPT goto :found

echo.
echo  [!] NetworkChecker.ps1 not found in this folder:
echo      %~dp0
echo.
pause
exit /b 1

:found
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0%SCRIPT%"
exit /b %ERRORLEVEL%
