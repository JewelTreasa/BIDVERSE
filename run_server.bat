@echo off
REM BidVerse Django Server Startup Script
REM This script activates the virtual environment and starts the Django server

echo 🚀 Starting BidVerse Django Server...
echo ==================================================

REM Change to backend directory
cd backend

REM Activate virtual environment
echo Activating virtual environment...
call ..\venv\Scripts\activate.bat

REM Check if activation was successful
if %ERRORLEVEL% neq 0 (
    echo ❌ Failed to activate virtual environment!
    pause
    exit /b 1
)

REM Start Django server
echo Starting Django development server...
echo 📱 Frontend: http://127.0.0.1:8000
echo 🔧 Backend API: http://127.0.0.1:8000/api/
echo 👤 Admin: http://127.0.0.1:8000/admin/
echo Press Ctrl+C to stop the server
echo ==================================================

python manage.py runserver
