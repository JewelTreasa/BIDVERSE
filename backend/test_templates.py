#!/usr/bin/env python
"""
Test email template rendering for password reset
"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from django.template.loader import render_to_string
from django.contrib.sites.models import Site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

def test_email_templates():
    print("=== EMAIL TEMPLATE RENDERING TEST ===")

    # Get site
    site = Site.objects.get_current()
    print(f"Site: {site.name} ({site.domain})")

    # Mock context (similar to what Django PasswordResetView provides)
    uid = urlsafe_base64_encode(force_bytes(6))  # Mock user ID
    token = "dummy-token-for-testing"

    context = {
        'email': 'jtreasaraphel@gmail.com',
        'user': type('MockUser', (), {'email': 'jtreasaraphel@gmail.com', 'get_username': lambda: 'jtreasaraphel'})(),
        'domain': site.domain,
        'protocol': 'http',
        'uid': uid,
        'token': token,
    }

    print(f"Context domain: {context['domain']}")
    print(f"Context protocol: {context['protocol']}")
    print(f"Generated UID: {uid}")
    print(f"Mock token: {token}")

    try:
        # Test subject template
        subject = render_to_string('registration/password_reset_subject.txt', context).strip()
        print(f"[SUCCESS] Subject template rendered: '{subject}'")

        # Test email template
        email_content = render_to_string('registration/password_reset_email.html', context)
        print(f"[SUCCESS] Email template rendered, length: {len(email_content)} characters")

        # Check for reset URL in email
        reset_url = f"{context['protocol']}://{context['domain']}/reset/{uid}/{token}/"
        print(f"Expected reset URL: {reset_url}")
        print(f"[SUCCESS] Reset URL found in email: {reset_url in email_content}")

        # Show a snippet of the email
        print("\nEmail content preview:")
        lines = email_content.split('\n')[:10]  # First 10 lines
        for line in lines:
            if line.strip():
                print(f"  {line.strip()}")

        return True

    except Exception as e:
        print(f"[FAILED] Template rendering failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    test_email_templates()
