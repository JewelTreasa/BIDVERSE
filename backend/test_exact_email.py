#!/usr/bin/env python
"""
Test sending the exact same email that Django password reset sends
"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.contrib.sites.models import Site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings
from accounts.models import User

def test_exact_password_reset_email():
    print("=== TESTING EXACT PASSWORD RESET EMAIL ===")

    # Get user
    user = User.objects.get(email='jtreasaraphel@gmail.com')
    print(f"User: {user.email}")

    # Generate exact same tokens Django uses
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)

    # Get site
    site = Site.objects.get_current()

    # Create exact same context Django uses
    context = {
        'email': user.email,
        'user': user,
        'domain': site.domain,
        'protocol': 'http',
        'uid': uid,
        'token': token,
    }

    print(f"Domain: {site.domain}")
    print(f"UID: {uid}")
    print(f"Token preview: {token[:10]}...")

    # Render templates exactly like Django
    subject = render_to_string('registration/password_reset_subject.txt', context).strip()
    email_content = render_to_string('registration/password_reset_email.html', context)

    print(f"Subject: '{subject}'")
    print(f"Content length: {len(email_content)}")

    # Send with exact same parameters
    result = send_mail(
        subject=subject,
        message='',  # Plain text (Django provides HTML)
        html_message=email_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False
    )

    print(f"Email sent successfully! Result: {result}")
    print("Check jtreasaraphel@gmail.com NOW!")
    print(f"Expected subject: {settings.EMAIL_SUBJECT_PREFIX}{subject}")

if __name__ == '__main__':
    test_exact_password_reset_email()
