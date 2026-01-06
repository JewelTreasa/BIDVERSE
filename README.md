# BidVerse - Agricultural Trading Platform

A modern web platform connecting farmers, buyers, traders, and exporters in the agricultural marketplace.

## Recent Changes - Firebase Removal & Django Authentication

### ✅ Firebase Completely Removed
- Removed all Firebase script imports from HTML files
- Deleted Firebase JavaScript files (firebase-app.js, firebase-api.js, firebase-config.js, config.js)
- Removed Firebase authentication code and event handlers
- Deleted Firebase documentation files
- Removed Node.js dependencies (package.json, node_modules, vite config)

### ✅ Django Authentication Implemented
- Added `social-auth-app-django` for Google OAuth integration
- **Google OAuth configured** with your client credentials
- Updated Django settings with Google OAuth credentials and email configuration
- Created web form views for login, register, and password reset
- Updated URL patterns for authentication endpoints
- Added authentication status checking endpoint

### ✅ UI Preserved
- All HTML/CSS/JS styling remains exactly the same
- Form actions updated to point to Django endpoints
- Google sign-in buttons now link to Django OAuth URLs
- Password reset links updated to Django password reset system

### ✅ Database Migration
- All migrations applied successfully
- Social auth tables created in SQLite database
- Ready for user registration and authentication

## How to Run

### Option 1: Use the Startup Script (Recommended)

```bash
python start_app.py
```

This will:
- Start the Django backend server on port 8000 (serves both API and frontend)
- Open your browser to the homepage
- Provide admin credentials

### Option 1.5: Use Convenience Scripts

For easier development, use these scripts from the project root:

**PowerShell:**
```powershell
.\run_server.ps1
```

**Command Prompt:**
```cmd
run_server.bat
```

These scripts automatically activate the virtual environment and start the server.

### Option 2: Manual Startup

1. **Activate Virtual Environment & Start Django Server:**
   ```powershell
   # Windows PowerShell
   cd "D:\BIDVERSE OUT\backend"
   & "D:\BIDVERSE OUT\.venv\Scripts\activate.ps1"
   python manage.py runserver
   ```

   Or for Command Prompt:
   ```cmd
   cd "D:\BIDVERSE OUT\backend"
   D:\BIDVERSE OUT\.venv\Scripts\activate.bat
   python manage.py runserver
   ```

2. **Open Browser:**
   - Full Application: http://127.0.0.1:8000
   - Admin Panel: http://127.0.0.1:8000/admin/

### Option 3: Development with Separate Frontend

If you want to run the frontend separately for development:

1. **Start Django Backend:**
   ```bash
   cd backend
   python manage.py runserver
   ```

2. **Start Frontend Server:**
   ```bash
   python -m http.server 3000
   ```

3. **Open Browser:**
   - Frontend: http://127.0.0.1:3000
   - Backend API: http://127.0.0.1:8000

## Admin Credentials

- **Email**: admin@example.com
- **Password**: admin123
- **User Type**: ADMIN

## Google OAuth Testing

Your Google OAuth is now configured and ready to test:

1. **Visit**: http://127.0.0.1:8000/login/
2. **Click**: "Continue with Google" button
3. **Sign in** with your Google account
4. **Redirect** back to homepage upon successful authentication

**Note**: Make sure your Google Cloud Console OAuth redirect URI is set to:
`http://127.0.0.1:8000/api/auth/oauth/complete/google-oauth2/`

## Authentication Endpoints

### Web Forms (HTML)
- `GET/POST /login/` - User login form
- `GET/POST /register/` - User registration form
- `GET/POST /forgot-password/` - Password reset request form
- `GET /oauth/login/google-oauth2/` - Google OAuth login

### API Endpoints (JSON)
- `POST /api/auth/login/` - API user login
- `POST /api/auth/register/` - API user registration
- `POST /api/auth/google/` - API Google OAuth login
- `POST /api/auth/password-reset-request/` - API password reset request
- `POST /api/auth/password-reset-confirm/<uidb64>/<token>/` - API password reset confirmation
- `GET /api/auth/check-auth/` - Check authentication status

## Project Structure

```
bidverse-out/
├── backend/                 # Django backend
│   ├── accounts/           # User authentication app
│   ├── bidverse/           # Main Django project
│   ├── db.sqlite3          # SQLite database
│   └── manage.py
├── assets/                 # Static frontend assets
│   ├── css/
│   ├── js/
│   └── images/
├── *.html                  # Frontend HTML pages
├── start_app.py           # Startup script
└── README.md
```

## Features

- ✅ User registration and authentication
- ✅ JWT token-based authentication
- ✅ Google OAuth integration
- ✅ Password reset functionality
- ✅ User roles (Farmer, Buyer, Trader, Exporter, Admin)
- ✅ Responsive frontend design
- ✅ CORS enabled for frontend-backend communication

## Development Notes

- Backend uses Django 5.0+ with Django REST Framework
- Frontend uses vanilla JavaScript with modern ES6 features
- Database: SQLite (development) / MySQL (production-ready)
- Authentication: Django sessions + JWT tokens + Google OAuth
- CORS enabled for cross-origin requests
- Email: SMTP configuration for password reset (Gmail example included)
- Social Auth: Google OAuth 2.0 integration ready
