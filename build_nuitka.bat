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

set APP_VERSION=
for /f "tokens=2 delims==" %%v in ('findstr /b /c:"__version__" proxy\__init__.py') do set APP_VERSION=%%v
set APP_VERSION=%APP_VERSION: =%
set APP_VERSION=%APP_VERSION:"=%
if "%APP_VERSION%"=="" (
    echo Could not read version from proxy\__init__.py
    exit /b 1
)
set FILE_VERSION=%APP_VERSION%.0
echo Version: %FILE_VERSION%

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
