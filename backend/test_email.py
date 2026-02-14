#!/usr/bin/env python
"""
Comprehensive test script for email configuration and password reset functionality.
"""
import os
import sys
import django

# Add the project directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Configure Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from django.core.mail import send_mail, get_connection
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from accounts.models import User

def test_email_configuration():
    """Test the email configuration"""
    print("=== Email Configuration Test ===\n")

    # Check email settings
    print("Email Backend:", settings.EMAIL_BACKEND)
    print("Email Host:", settings.EMAIL_HOST)
    print("Email Port:", settings.EMAIL_PORT)
    print("Use TLS:", settings.EMAIL_USE_TLS)
    print("Email User:", settings.EMAIL_HOST_USER)
    print("Email Password:", "***HIDDEN***" if settings.EMAIL_HOST_PASSWORD else "NOT SET")
    print("Default From Email:", settings.DEFAULT_FROM_EMAIL)
    print()

    # Check if .env file exists
    env_file = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(env_file):
        print("[SUCCESS] .env file found!")
    else:
        print("[WARNING] .env file not found. Using default values.")

    # Test email connection
    try:
        connection = get_connection()
        connection.open()
        print("[SUCCESS] Email connection successful!")
        connection.close()
    except Exception as e:
        print("[FAILED] Email connection failed:", str(e))
        print("Make sure EMAIL_HOST_USER and EMAIL_HOST_PASSWORD are set correctly in .env file.")
        print("For Gmail, use an App Password, not your regular password.")
        return False

    # Test sending email
    try:
        send_mail(
            subject='BidVerse Email Configuration Test',
            message='This is a test email from BidVerse. If you received this, email configuration is working correctly!',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[settings.EMAIL_HOST_USER],  # Send to yourself
            fail_silently=False,
        )
        print("[SUCCESS] Test email sent successfully!")
        print("Check your inbox for the test email.")
    except Exception as e:
        print("[FAILED] Test email failed:", str(e))
        return False

    return True

def test_password_reset_flow():
    """Test password reset token generation"""
    print("\n=== Password Reset Flow Test ===\n")

    try:
        # Get or create a test user
        user, created = User.objects.get_or_create(
            email='test@example.com',
            defaults={
                'username': 'testuser',
                'first_name': 'Test',
                'last_name': 'User',
                'user_type': 'BUYER'
            }
        )

        if created:
            user.set_password('testpass123')
            user.save()
            print("[SUCCESS] Created test user: test@example.com")
        else:
            print("[INFO] Using existing test user: test@example.com")

        # Generate password reset token
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        reset_url = f"http://localhost:8000/api/auth/reset/{uid}/{token}/"
        print(f"[SUCCESS] Generated reset URL: {reset_url}")

        # Test sending password reset email
        try:
            send_mail(
                subject='Password Reset Test - BidVerse',
                message=f'This is a test password reset email.\n\nReset link: {reset_url}\n\nThis link is for testing purposes only.',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
            print("[SUCCESS] Password reset test email sent!")
        except Exception as e:
            print("[FAILED] Password reset email failed:", str(e))
            return False

        return True

    except Exception as e:
        print("[FAILED] Password reset flow test failed:", str(e))
        return False

def main():
    """Run all tests"""
    print("BidVerse Email & Password Reset Configuration Test")
    print("=" * 50)

    try:
        email_success = test_email_configuration()
        reset_success = test_password_reset_flow()
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        email_success = False
        reset_success = False

    print("\n" + "=" * 50)
    print("SUMMARY:")
    print(f"Email Configuration: {'PASS' if email_success else 'FAIL'}")
    print(f"Password Reset Flow: {'PASS' if reset_success else 'FAIL'}")

    with open('email_test_results.txt', 'w') as f:
        f.write(f"Email Configuration: {'PASS' if email_success else 'FAIL'}\n")
        f.write(f"Password Reset Flow: {'PASS' if reset_success else 'FAIL'}\n")
        
    if email_success and reset_success:
        print("\n[SUCCESS] All tests passed! Password reset via email is ready to use.")
    else:
        print("\n[FAILED] Some tests failed. Please check the configuration above.")

if __name__ == '__main__':
    main()
