@echo off
setlocal

cd /d "%~dp0"

echo SBOM Dashboard Launcher
echo Project: %CD%
echo.

if /I "%~1"=="--check" (
    echo Launcher check passed.
    exit /b 0
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating Python virtual environment...
    py -3.10 -m venv .venv 2>nul
    if errorlevel 1 py -3 -m venv .venv 2>nul
    if errorlevel 1 python -m venv .venv
    if errorlevel 1 (
        echo.
        echo Failed to create .venv. Please install Python 3.10 or newer.
        pause
        exit /b 1
    )
)

echo Installing or checking Python packages...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo Failed to install requirements.
    echo If this PC is offline, install the packages from a local wheel cache first.
    pause
    exit /b 1
)

for /f %%P in ('powershell -NoProfile -ExecutionPolicy Bypass -Command "$p=8501; while ($true) { try { $listener=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,$p); $listener.Start(); $listener.Stop(); Write-Output $p; break } catch { $p++ } }"') do set "PORT=%%P"

if "%PORT%"=="" set "PORT=8501"
set "URL=http://127.0.0.1:%PORT%"

echo.
echo Starting SBOM Dashboard...
echo URL: %URL%
echo Close this window to stop the dashboard server.
echo.

start "" powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 3; Start-Process '%URL%'"
".venv\Scripts\python.exe" -m streamlit run app.py --server.address=127.0.0.1 --server.port=%PORT% --server.headless=true --browser.gatherUsageStats=false

echo.
echo Dashboard stopped.
pause
