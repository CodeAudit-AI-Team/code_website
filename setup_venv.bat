@echo off
REM =====================================================================
REM  AI Secure Code Intelligence Platform — Virtual Environment Setup
REM  Run this script once to set up the project for the first time.
REM  Usage:  Double-click OR run in terminal:  setup_venv.bat
REM =====================================================================

echo.
echo  ========================================================
echo    AI Secure Code Intelligence Platform - Setup Script
echo  ========================================================
echo.

REM --- Step 1: Create virtual environment ---
echo [1/4] Creating virtual environment (.venv)...
python -m venv .venv
if errorlevel 1 (
    echo  ERROR: Python not found. Install Python 3.10+ from python.org
    pause
    exit /b 1
)
echo       .venv created successfully.
echo.

REM --- Step 2: Activate virtual environment ---
echo [2/4] Activating virtual environment...
call .venv\Scripts\activate.bat
echo       Virtual environment activated.
echo.

REM --- Step 3: Upgrade pip ---
echo [3/4] Upgrading pip...
python -m pip install --upgrade pip
echo.

REM --- Step 4: Install all dependencies ---
echo [4/4] Installing project dependencies from requirements.txt...
pip install -r requirements.txt
echo.

echo  ========================================================
echo    Setup Complete!
echo  ========================================================
echo.
echo  To activate the virtual environment in future sessions:
echo.
echo     .venv\Scripts\activate
echo.
echo  Then run the project using TWO terminal windows:
echo.
echo    Terminal 1 (Backend):
echo       uvicorn backend.api:app --reload
echo.
echo    Terminal 2 (Frontend):
echo       streamlit run frontend/app.py
echo.
echo  Open browser: http://localhost:8501
echo  Login: admin / admin
echo.
pause
