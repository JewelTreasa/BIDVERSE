#!/usr/bin/env python
"""
Script to test registration functionality
"""
import os
import sys
import django

# Add the backend directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

# Configure Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from accounts.models import User

def test_registration():
    """Test the registration functionality"""
    print("=== Testing BidVerse Registration ===\n")

    # Test user data
    test_email = "newuser@example.com"
    test_password = "testpass123"

    # Check if user already exists
    if User.objects.filter(email=test_email).exists():
        print(f"User {test_email} already exists, deleting for clean test...")
        User.objects.filter(email=test_email).delete()

    # Test registration
    try:
        user = User(username=test_email, email=test_email)
        user.set_password(test_password)
        user.is_active = True
        user.save()

        print("SUCCESS: User created successfully!")
        print(f"Email: {user.email}")
        print(f"Username: {user.username}")
        print(f"Active: {user.is_active}")

        # Test authentication
        from django.contrib.auth import authenticate
        from django.test import RequestFactory

        rf = RequestFactory()
        request = rf.post('/login/')

        authenticated_user = authenticate(request, username=test_email, password=test_password)

        if authenticated_user:
            print("SUCCESS: User can authenticate!")
        else:
            print("ERROR: User authentication failed!")

    except Exception as e:
        print(f"ERROR: Registration failed: {e}")

    # Show total users
    print(f"\nTotal users after test: {User.objects.count()}")

if __name__ == '__main__':
    test_registration()
