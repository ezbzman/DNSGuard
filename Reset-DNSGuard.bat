@echo off
REM ==========================================================================
REM  Reset-DNSGuard.bat - double-click launcher for Reset-DNSGuard.ps1
REM
REM  Fixes a PC where DNSGuard was removed abnormally (e.g. antivirus deleted
REM  DNSGuard.exe) and left DNS broken. Self-elevates to Administrator, then
REM  runs Reset-DNSGuard.ps1 (must sit in the same folder as this .bat).
REM
REM  Just double-click it and accept the Windows admin prompt.
REM ==========================================================================
setlocal
set "PS1=%~dp0Reset-DNSGuard.ps1"

if not exist "%PS1%" (
    echo ERROR: Reset-DNSGuard.ps1 was not found next to this file.
    echo Keep Reset-DNSGuard.bat and Reset-DNSGuard.ps1 together in the same folder.
    echo.
    pause
    exit /b 1
)

REM --- already elevated? run the script; otherwise relaunch elevated ---------
net session >nul 2>&1
if %errorlevel% equ 0 (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
    echo.
    echo Finished. You can close this window.
    pause
    exit /b %errorlevel%
) else (
    echo Requesting administrator rights...
    powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b 0
)
