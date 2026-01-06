#!/usr/bin/env python
"""
Script to test login functionality
"""
import requests
import sys
import os

# Add the backend directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

# Configure Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
import django
django.setup()

from accounts.models import User

def test_login():
    """Test the login functionality"""
    print("=== Testing BidVerse Login ===\n")

    # Check if test user exists
    try:
        user = User.objects.get(email='test@example.com')
        print(f"SUCCESS: Test user found: {user.email} (Active: {user.is_active})")
    except User.DoesNotExist:
        print("ERROR: Test user not found!")
        return

    # Test direct authentication
    from django.contrib.auth import authenticate
    from django.test import RequestFactory

    rf = RequestFactory()
    request = rf.post('/login/')

    authenticated_user = authenticate(request, username='test@example.com', password='password123')

    if authenticated_user:
        print("SUCCESS: Django authentication successful")
        print(f"  User: {authenticated_user.email}")
        print(f"  ID: {authenticated_user.id}")
    else:
        print("ERROR: Django authentication failed")

    # Test user lookup
    user_exists = User.objects.filter(email='test@example.com').exists()
    print(f"User exists in database: {user_exists}")

    # Show all users
    print(f"\nTotal users in database: {User.objects.count()}")
    for user in User.objects.all():
        print(f"  - {user.email} (Active: {user.is_active})")

if __name__ == '__main__':
    test_login()
