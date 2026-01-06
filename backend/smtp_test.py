#!/usr/bin/env python
"""
Direct SMTP test to diagnose Gmail email issues
"""
import smtplib
import os
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from django.conf import settings
import datetime

def test_smtp():
    print("Testing Gmail SMTP Connection")
    print("=" * 40)

    print("From:", settings.EMAIL_HOST_USER)
    print("Password length:", len(settings.EMAIL_HOST_PASSWORD or ''))
    print("Host:", settings.EMAIL_HOST + ":" + str(settings.EMAIL_PORT))
    print("TLS:", settings.EMAIL_USE_TLS)
    print()

    try:
        # Create SMTP connection
        print("Connecting to Gmail SMTP...")
        server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
        server.starttls()

        # Try login
        print("Attempting login...")
        server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
        print("Login successful!")

        # Send test email
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print("Sending test email...")

        msg = f'''From: {settings.EMAIL_HOST_USER}
To: bidverse80@gmail.com
Subject: SMTP Direct Test - {timestamp}

SMTP Connection Test

Time: {timestamp}

SMTP login successful
Email sent successfully

If you receive this email, your Gmail app password is working correctly!

Check your Gmail:
- Inbox
- Spam/Junk folder
- Promotions tab
- All Mail

BidVerse SMTP Test
'''

        server.sendmail(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_USER, msg)
        server.quit()

        print(f"EMAIL SENT SUCCESSFULLY at {timestamp}")
        print("\nCHECK GMAIL NOW:")
        print("   - Primary Inbox")
        print("   - Spam/Junk Folder")
        print("   - Promotions Tab")
        print("   - Updates Tab")
        print("   - Search for 'SMTP' in All Mail")

        return True

    except smtplib.SMTPAuthenticationError as e:
        print(f"AUTHENTICATION FAILED: {e}")
        print("\nPOSSIBLE FIXES:")
        print("1. Check Gmail app password (generate new one)")
        print("2. Enable 2FA on Gmail account")
        print("3. Allow 'Less secure app access' in Gmail settings")
        print("4. Try a different email provider (SendGrid, Mailgun)")
        return False

    except Exception as e:
        print(f"SMTP ERROR: {e}")
        return False

if __name__ == '__main__':
    test_smtp()
