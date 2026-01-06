# BidVerse Django Server Startup Script
# This script activates the virtual environment and starts the Django server

Write-Host "🚀 Starting BidVerse Django Server..." -ForegroundColor Green
Write-Host "=" * 50 -ForegroundColor Yellow

# Change to backend directory
Set-Location ".\backend"

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Cyan
& "..\.venv\Scripts\activate.ps1"

# Check if activation was successful
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to activate virtual environment!" -ForegroundColor Red
    exit 1
}

# Start Django server
Write-Host "Starting Django development server..." -ForegroundColor Cyan
Write-Host "📱 Frontend: http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "🔧 Backend API: http://127.0.0.1:8000/api/" -ForegroundColor Green
Write-Host "👤 Admin: http://127.0.0.1:8000/admin/" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host "=" * 50 -ForegroundColor Yellow

python manage.py runserver
