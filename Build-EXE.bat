@echo off
REM Builds dist\DNSGuard.exe (single self-contained file, no Python needed on target PCs).
setlocal
cd /d "%~dp0"
where py >nul 2>&1 && (set "PY=py -3") || (set "PY=python")
%PY% -m pip install --upgrade -r requirements.txt || goto :fail
%PY% -m PyInstaller --noconfirm --clean --onefile --noconsole --name DNSGuard ^
  --hidden-import dnslib --hidden-import cryptography ^
  --add-data "assets\wallpaper.jpg;assets" ^
  dnsguard.py || goto :fail
echo.
echo Built: %~dp0dist\DNSGuard.exe
exit /b 0
:fail
echo BUILD FAILED
exit /b 1
