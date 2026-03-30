@echo off
setlocal
title CIPHER — Starting All Services

echo.
echo  =====================================================
echo   CIPHER — Adaptive Behavioral Defense for LLMs
echo  =====================================================
echo.

:: ── Port Check ────────────────────────────────────────────────────────────
echo [INFO] Looking for conflicting systems...
netstat -ano | findstr :8000 > nul
if %errorlevel% equ 0 (
    echo [WARN] Port 8000 is ALREADY in use. Cleaning up...
    for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8000') do (
        echo [INFO] Terminating old backend (PID %%a)...
        taskkill /F /PID %%a 2>nul
    )
)
netstat -ano | findstr :5173 > nul
if %errorlevel% equ 0 (
    echo [WARN] Port 5173 is ALREADY in use. Cleaning up...
    for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5173') do (
        echo [INFO] Terminating old frontend (PID %%a)...
        taskkill /F /PID %%a 2>nul
    )
)
echo [INFO] Wait for port release...
timeout /t 2 /nobreak > nul

:: ── Backend ──────────────────────────────────────────────────────────────
echo [1/2] Starting FastAPI Backend (cipher-backend)...
echo       URL: http://127.0.0.1:8000
echo       API Docs: http://127.0.0.1:8000/docs
echo.

cd /d "%~dp0cipher-backend"

:: Explicitly check for .venv
if exist ".venv\Scripts\python.exe" (
    echo [INFO] Found virtual environment.
    set PYTHON_EXE=.venv\Scripts\python.exe
) else (
    echo [WARN] No .venv found — using system Python. (Please run pip install requirements.txt)
    set PYTHON_EXE=python
)

:: Running on 127.0.0.1 for highest reliability on Windows
echo [INFO] Launching server window...
start "CIPHER Backend" cmd /k "echo CIPHER FastAPI Backend && %PYTHON_EXE% -m uvicorn main:app --reload --host 127.0.0.1 --port 8000"

:: Wait to ensure server starts
timeout /t 4 /nobreak > nul

:: ── Frontend ─────────────────────────────────────────────────────────────
echo [2/2] Starting React Frontend (cipher-dashboard)...
echo       URL: http://localhost:5173
echo.

cd /d "%~dp0cipher-dashboard"

:: Check if node_modules exists
if not exist "node_modules" (
    echo [INFO] Downloading frontend dependencies...
    npm install
)

start "CIPHER Frontend" cmd /k "echo CIPHER React Dashboard && npm run dev"

:: ── Done ─────────────────────────────────────────────────────────────────
echo.
echo  =====================================================
echo   Both services are starting in separate windows.
echo.
echo   Backend:  http://127.0.0.1:8000
echo   Frontend: http://localhost:5173
echo   Docs:     http://127.0.0.1:8000/docs
echo  =====================================================
echo.
echo  Press any key to open the dashboard...
pause > nul

start http://localhost:5173
