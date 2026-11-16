@echo off
setlocal enabledelayedexpansion

:: ============================================================================
:: IoT Wi-Fi Network Security & Anomaly Detection - One-Click Frontend Launcher
:: File: run_frontend.bat
:: Description: Boots the Streamlit SOC Live Monitoring Dashboard in one go.
:: ============================================================================

title IoT Wi-Fi Network Security - SOC Live Dashboard
color 0A

:: Navigate to the project root directory
cd /d "%~dp0"

echo =========================================================================
echo       IoT Wi-Fi Network Security and Anomaly Detection System
echo                  SOC Live Monitoring Dashboard
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

:: 3. Launch the Streamlit Frontend Dashboard
echo [INFO] Starting Streamlit SOC Dashboard on http://localhost:8501 ...
echo [INFO] Press Ctrl+C in this terminal window to stop the dashboard.
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
