#!/usr/bin/env python
import os
import json

def debug_google_oauth_config():
    """Debug Google OAuth configuration issues"""
    print("Google OAuth Configuration Debugger")
    print("=" * 50)

    # Check config.js file
    config_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'js', 'config.js')
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            content = f.read()

        print("PASS: config.js found")

        # Check if client ID is set
        if 'your-actual-google-client-id-here' in content:
            print("FAIL: CLIENT ID NOT SET - Still using placeholder value")
            print("   Fix: Replace 'your-actual-google-client-id-here' with your real Google Client ID")
        elif 'your-google-client-id' in content:
            print("FAIL: CLIENT ID NOT SET - Still using placeholder value")
            print("   Fix: Replace 'your-google-client-id' with your real Google Client ID")
        else:
            print("PASS: Client ID appears to be configured")

        # Check if GOOGLE_CLIENT_ID is in the config
        if 'GOOGLE_CLIENT_ID' in content:
            print("PASS: GOOGLE_CLIENT_ID variable found")
        else:
            print("FAIL: GOOGLE_CLIENT_ID variable missing")

    else:
        print("FAIL: config.js not found")
        print(f"   Expected path: {config_path}")

    # Check login.html
    login_path = os.path.join(os.path.dirname(__file__), '..', 'login.html')
    if os.path.exists(login_path):
        with open(login_path, 'r') as f:
            content = f.read()

        checks = [
            ('Google script', 'accounts.google.com/gsi/client'),
            ('Config script', 'assets/js/config.js'),
            ('Google callback', 'handleGoogleSignIn'),
            ('Client ID initialization', 'data-client_id'),
        ]

        print("\nlogin.html checks:")
        for check_name, check_content in checks:
            if check_content in content:
                print(f"   PASS: {check_name}")
            else:
                print(f"   FAIL: {check_name} - MISSING")

    # Check register.html
    register_path = os.path.join(os.path.dirname(__file__), '..', 'register.html')
    if os.path.exists(register_path):
        with open(register_path, 'r') as f:
            content = f.read()

        checks = [
            ('Google script', 'accounts.google.com/gsi/client'),
            ('Config script', 'assets/js/config.js'),
            ('Google callback', 'handleGoogleSignUp'),
            ('Client ID initialization', 'data-client_id'),
        ]

        print("\nregister.html checks:")
        for check_name, check_content in checks:
            if check_content in content:
                print(f"   PASS: {check_name}")
            else:
                print(f"   FAIL: {check_name} - MISSING")

    print("\n" + "=" * 50)
    print("Quick Fix Commands:")
    print("1. Get your Google Client ID from Google Cloud Console")
    print("2. Edit assets/js/config.js")
    print("3. Replace GOOGLE_CLIENT_ID value with your real Client ID")
    print("4. Save and refresh your browser")
    print("\nTest:")
    print("1. Open http://127.0.0.1:8000/login.html")
    print("2. Click 'Continue with Google'")
    print("3. Should work without Error 400!")

if __name__ == '__main__':
    debug_google_oauth_config()
