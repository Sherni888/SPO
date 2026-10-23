@echo off
setlocal

:: Elevation check — relaunch as admin if needed
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [SPO] Requesting admin rights...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

echo [SPO] Loading kernel driver...
loader.exe --load spo_drv.sys
if %errorlevel% neq 0 (
    echo [SPO] Driver load failed ^(exit %errorlevel%^). Check iqvw64e.sys is present.
    pause
    exit /b %errorlevel%
)

echo [SPO] Spoofing HWIDs...
spo.exe
if %errorlevel% neq 0 (
    echo [SPO] Spoof failed ^(exit %errorlevel%^).
    pause
    exit /b %errorlevel%
)

echo.
echo [SPO] Done. Reboot recommended for all changes to take effect.
pause
