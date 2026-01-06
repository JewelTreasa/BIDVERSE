#!/usr/bin/env python
"""
SendGrid Setup for BidVerse Email System
"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

# Install required packages:
# pip install sendgrid-django

# Update settings.py:
"""
# Replace Gmail settings with SendGrid
EMAIL_BACKEND = "sendgrid_backend.SendGridBackend"
SENDGRID_API_KEY = "your-sendgrid-api-key-here"
EMAIL_HOST_USER = "noreply@bidverse.com"  # Your verified SendGrid sender
DEFAULT_FROM_EMAIL = "noreply@bidverse.com"

# Remove Gmail settings:
# EMAIL_HOST, EMAIL_PORT, EMAIL_USE_TLS, EMAIL_HOST_PASSWORD
"""

# Get SendGrid API Key from: https://app.sendgrid.com/settings/api_keys
# Verify sender email in SendGrid dashboard
# Free tier: 100 emails/day

print("SendGrid Setup Instructions:")
print("1. Sign up at sendgrid.com")
print("2. Create API key")
print("3. Verify sender email")
print("4. Update settings.py as shown above")
print("5. Test with: python manage.py send_mail_test")
