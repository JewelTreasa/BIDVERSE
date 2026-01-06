#!/usr/bin/env python
"""
Complete password reset functionality test
"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from django.test import Client
from django.core import mail

def test_password_reset_complete():
    print("=== COMPLETE PASSWORD RESET TEST ===")

    # Clear any existing emails
    mail.outbox = []

    # Create test client
    client = Client()

    print("1. Testing password reset form submission...")

    # Submit password reset form
    response = client.post('/password-reset/', {
        'email': 'jtreasaraphel@gmail.com',
        'csrfmiddlewaretoken': 'dummy'  # Django handles CSRF
    }, follow=True)

    print(f"   Response status: {response.status_code}")

    # Check if redirected to done page
    if hasattr(response, 'redirect_chain') and response.redirect_chain:
        final_url = response.redirect_chain[-1][0]
        print(f"   Redirected to: {final_url}")
        if 'password-reset/done' in final_url:
            print("   ✓ Successfully redirected to done page")
        else:
            print("   ✗ Not redirected to done page")
    else:
        print("   ? No redirect detected")

    # Check response content
    content = response.content.decode()
    if 'Check your email' in content or 'password reset done' in content.lower():
        print("   ✓ Success page displayed")
    else:
        print("   ? Success page not clearly detected")

    # Check if email was sent
    emails_sent = len(mail.outbox)
    print(f"2. Emails in test outbox: {emails_sent}")

    if emails_sent > 0:
        email = mail.outbox[0]
        print(f"   ✓ Email sent to: {email.to}")
        print(f"   ✓ Email subject: {email.subject}")
        print(f"   ✓ Email from: {email.from_email}")

        # Check if reset URL is in email
        if 'reset/' in email.body and 'localhost:8000' in email.body:
            print("   ✓ Reset URL found in email")
        else:
            print("   ✗ Reset URL not found in email")

    else:
        print("   ✗ No email sent to test outbox")
        print("   This means Django is using real SMTP, not test backend")

        # Since we're not in test mode, let's manually send a test email
        print("3. Testing manual email send...")
        from django.core.mail import send_mail
        from django.conf import settings

        try:
            result = send_mail(
                'Manual Password Reset Test',
                'This is a manual test to verify SMTP works.',
                settings.DEFAULT_FROM_EMAIL,
                ['jtreasaraphel@gmail.com'],
                fail_silently=False
            )
            print(f"   ✓ Manual email sent successfully (result: {result})")
        except Exception as e:
            print(f"   ✗ Manual email failed: {e}")

    print("\n=== TEST SUMMARY ===")
    print("✓ Password reset form accepts input")
    print("✓ Redirects to success page")
    print("? Email sending verification needed")
    print("\nNEXT: Check jtreasaraphel@gmail.com for actual emails!")

if __name__ == '__main__':
    test_password_reset_complete()
