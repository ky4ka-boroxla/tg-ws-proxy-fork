@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo Python not found in PATH
    exit /b 1
)

if not exist .venv (
    python -m venv .venv || exit /b 1
)
set PY=.venv\Scripts\python.exe

"%PY%" -m pip install -r requirements.txt nuitka || exit /b 1

for /f "delims=" %%v in ('"%PY%" -c "from proxy import __version__ as v; print(v)"') do set APP_VERSION=%%v
set FILE_VERSION=%APP_VERSION%.0

echo A C compiler is required: Visual Studio Build Tools or MinGW64.
echo If none is found, Nuitka will offer to download MinGW64 automatically.
echo.

"%PY%" -m nuitka ^
    --onefile ^
    --assume-yes-for-downloads ^
    --enable-plugin=tk-inter ^
    --windows-console-mode=disable ^
    --windows-icon-from-ico=icon.ico ^
    --include-module=pystray._win32 ^
    --include-package-data=customtkinter ^
    --include-package-data=certifi ^
    --include-data-dir=ui/i18n=ui/i18n ^
    --include-data-files=icon.ico=icon.ico ^
    --company-name=Flowseal ^
    --product-name=TgWsProxy ^
    --file-description="Telegram Desktop WebSocket Bridge Proxy" ^
    --file-version=%FILE_VERSION% ^
    --product-version=%FILE_VERSION% ^
    --output-filename=TgWsProxy.exe ^
    --output-dir=dist ^
    --remove-output ^
    windows.py
if errorlevel 1 exit /b 1

echo.
echo Done: dist\TgWsProxy.exe
endlocal
