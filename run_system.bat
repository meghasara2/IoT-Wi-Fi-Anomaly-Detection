@echo off
setlocal enabledelayedexpansion

:: ============================================================================
:: IoT Wi-Fi Network Security & Anomaly Detection - One-Click System Launcher
:: File: run_system.bat
:: Description: Launches BOTH the Backend Collector daemon and the Streamlit
::              SOC Dashboard so live sensor readings appear immediately.
:: ============================================================================

title IoT Wi-Fi Network Security - Complete System Launcher
color 0A

cd /d "%~dp0"

echo =========================================================================
echo       IoT Wi-Fi Network Security and Anomaly Detection System
echo              Complete System Launcher (Collector + Dashboard)
echo =========================================================================
echo.

:: 1. Locate Python executable (check .venv first, then system python)
if exist ".venv\Scripts\python.exe" (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
    set "STREAMLIT_EXE=.venv\Scripts\streamlit.exe"
    echo [INFO] Found virtual environment in .venv
) else (
    where python >nul 2>&1
    if !errorlevel! equ 0 (
        set "PYTHON_EXE=python"
        set "STREAMLIT_EXE=streamlit"
        echo [INFO] Using system Python
    ) else (
        color 0C
        echo [ERROR] Python was not found!
        echo Please install Python 3.10+ or set up a virtual environment in .venv.
        echo.
        pause
        exit /b 1
    )
)

:: 2. Ensure database exists (auto-initialize if missing)
if not exist "data\live_monitoring.db" (
    echo [INFO] Database 'data\live_monitoring.db' not found.
    echo [INFO] Auto-initializing database with default baseline registry...
    "%PYTHON_EXE%" -c "from src.init_live_database import init_live_database; init_live_database('data/live_monitoring.db', seed_defaults=True)"
    if !errorlevel! neq 0 (
        color 0C
        echo [ERROR] Database auto-initialization failed!
        echo.
        pause
        exit /b 1
    )
    echo [OK] Database initialized successfully.
    echo.
)

:: 3. Launch Backend Collector Daemon in a separate terminal window
echo [INFO] Starting Live Ingestion Collector (ESP32 Serial + Wi-Fi Sniffer)...
start "IoT Wi-Fi Ingestion Collector" cmd /k "title IoT Wi-Fi Ingestion Collector && color 0B && cd /d ""%~dp0"" && ""%PYTHON_EXE%"" src\live_collector.py"

:: Allow collector 2 seconds to establish database locks and initial handshake
timeout /t 2 /nobreak >nul

:: 4. Launch Streamlit Frontend Dashboard in this window
echo [INFO] Starting Streamlit SOC Dashboard on http://localhost:8501 ...
echo [INFO] Press Ctrl+C to stop the dashboard.
echo.

if exist "!STREAMLIT_EXE!" (
    "!STREAMLIT_EXE!" run src\live_dashboard.py --server.port 8501
) else (
    "%PYTHON_EXE%" -m streamlit run src\live_dashboard.py --server.port 8501
)

if !errorlevel! neq 0 (
    color 0C
    echo.
    echo [ERROR] Dashboard exited with error code !errorlevel!.
    echo.
    pause
    exit /b !errorlevel!
)

pause
