@echo off
title SpamShield Backend
echo ================================
echo   SpamShield - Starting Backend
echo ================================
echo.

cd /d "c:\Users\tyagi\OneDrive\Desktop\IBM\backend"

:: Check if venv exists, if not create it
if not exist "venv\Scripts\activate.bat" (
    echo Creating virtual environment...
    python -m venv venv
    echo Installing dependencies...
    venv\Scripts\pip install -r requirements.txt
)

echo Starting Flask server at http://localhost:5000
echo Press Ctrl+C to stop.
echo.
venv\Scripts\python app.py

pause
