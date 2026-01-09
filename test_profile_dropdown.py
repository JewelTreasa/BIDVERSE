#!/usr/bin/env python
"""
Test script to verify profile dropdown functionality
"""
import os
import sys
import django
from django.test import Client, TestCase
from django.contrib.auth import get_user_model

# Add the backend directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

# Configure Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

User = get_user_model()

def test_profile_dropdown():
    # Test 1: Check template rendering for anonymous user
    print("Test 1: Template rendering for anonymous user")
    from django.template import Context, Template
    from django.template.loader import get_template

    template = get_template('index.html')

    # Test anonymous user (user not authenticated)
    class MockUser:
        def __init__(self, is_authenticated=False):
            self.is_authenticated = is_authenticated
            self.email = ''
            self.first_name = ''
            self.last_name = ''

    anonymous_user = MockUser(is_authenticated=False)
    context = {'user': anonymous_user}
    rendered = template.render(context)

    if 'Log In' in rendered and 'Get Started' in rendered:
        print("PASS: Login/Register buttons found for anonymous user")
    else:
        print("FAIL: Login/Register buttons NOT found for anonymous user")

    # Test 2: Check template rendering for authenticated user
    print("\nTest 2: Template rendering for authenticated user")
    try:
        user = User.objects.get(email='test@example.com')
        auth_user = MockUser(is_authenticated=True)
        auth_user.email = user.email
        auth_user.first_name = user.first_name or ''
        auth_user.last_name = user.last_name or ''

        context = {'user': auth_user}
        rendered = template.render(context)

        if user.email in rendered:
            print("PASS: User email found in rendered template")
        else:
            print("FAIL: User email NOT found in rendered template")

        if 'Dashboard' in rendered:
            print("PASS: Dashboard link found in rendered template")
        else:
            print("FAIL: Dashboard link NOT found in rendered template")

        if 'fa-user-circle' in rendered:
            print("PASS: Profile icon found in rendered template")
        else:
            print("FAIL: Profile icon NOT found in rendered template")

        if 'profile-dropdown' in rendered:
            print("PASS: Profile dropdown HTML found in rendered template")
        else:
            print("FAIL: Profile dropdown HTML NOT found in rendered template")

        # Check that login buttons are NOT present for authenticated user
        if 'Log In' not in rendered and 'Get Started' not in rendered:
            print("PASS: Login/Register buttons correctly hidden for authenticated user")
        else:
            print("FAIL: Login/Register buttons incorrectly shown for authenticated user")

    except User.DoesNotExist:
        print("FAIL: Test user not found in database")
    except Exception as e:
        print(f"FAIL: Error testing authenticated template: {e}")

if __name__ == '__main__':
    test_profile_dropdown()
