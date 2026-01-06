# BidVerse Backend

This is the Django backend for the BidVerse Agricultural Commodity Auction System.

## Prerequisites

- Python 3.10+
- MySQL Server

## Setup Instructions

1.  **Navigate to the backend directory:**
    ```bash
    cd "d:\BIDVERSE OUT\backend"
    ```

2.  **Create and activate a virtual environment (optional but recommended):**
    ```bash
    python -m venv venv
    # Windows
    .\venv\Scripts\activate
    # Linux/Mac
    source venv/bin/activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Database:**
    - Open `bidverse/settings.py`.
    - Update the `DATABASES` section with your MySQL credentials (USER, PASSWORD, NAME).
    - Ensure the database `bidverse_db` exists in your MySQL server:
      ```sql
      CREATE DATABASE bidverse_db;
      ```

5.  **Run Migrations:**
    ```bash
    python manage.py makemigrations accounts
    python manage.py migrate
    ```

6.  **Run Server:**
    ```bash
    python manage.py runserver
    ```

## API Endpoints

| Method | Endpoint | Description | Payload |
| :--- | :--- | :--- | :--- |
| POST | `/api/auth/register/` | Register User | `{"email": "...", "password": "...", "phone": "...", "user_type": "FARMER"}` |
| POST | `/api/auth/login/` | Login User | `{"email": "...", "password": "..."}` |
| POST | `/api/auth/google/` | Google Login | `{"access_token": "YOUR_GOOGLE_ACCESS_TOKEN"}` |
| POST | `/api/auth/password-reset-request/` | Reset Req | `{"email": "..."}` |
| POST | `/api/auth/password-reset-confirm/<uid>/<token>/` | Reset Confirm | `{"password": "new_password"}` |

## Configuration Notes
- Update `GOOGLE_CLIENT_ID` in settings.py for Google Login to work.
- For production email sending, update `EMAIL_BACKEND` to SMTP in settings.py.
