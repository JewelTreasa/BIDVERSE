#!/usr/bin/env python
import os
import django
import sys

# Setup Django
sys.path.append('.')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from accounts.models import User
from django.contrib.auth import authenticate

# Test login
def test_login():
    print("Testing login functionality...")

    # Get admin user
    admin_user = User.objects.filter(email='admin@example.com').first()
    if not admin_user:
        print("Admin user not found")
        return

    print(f"Admin user: {admin_user.email}")

    # Set password
    admin_user.set_password('admin123')
    admin_user.save()
    print("Password set to 'admin123'")

    # Test authentication
    user = authenticate(username='admin@example.com', password='admin123')
    if user:
        print("SUCCESS: Authentication successful")
        print(f"User type: {user.user_type}")
        print(f"Is active: {user.is_active}")
        print(f"Is verified: {user.is_verified}")
    else:
        print("FAILED: Authentication failed")

if __name__ == '__main__':
    test_login()
