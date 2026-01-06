#!/usr/bin/env python
"""
Script to create a test user for BidVerse login testing
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

def create_test_user():
    # Check if test user exists
    if User.objects.filter(email='test@example.com').exists():
        print('INFO: Test user already exists: test@example.com / password123')
        return

    # Create test user manually since USERNAME_FIELD = 'email'
    from django.contrib.auth.hashers import make_password

    user = User(
        email='test@example.com',
        password=make_password('password123'),
        is_active=True
    )
    user.save()
    user.is_active = True
    user.save()

    print('SUCCESS: Test user created!')
    print('Email: test@example.com')
    print('Password: password123')

def show_all_users():
    users = User.objects.all()
    print(f'\nTotal users in database: {users.count()}')
    for user in users:
        print(f'  - {user.email} (Active: {user.is_active})')

if __name__ == '__main__':
    create_test_user()
    show_all_users()
