import os
import django
from django.conf import settings
from django.core.mail import send_mail

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

def test_subscription_email():
    print("Testing Subscription Confirmation Email...")
    
    # Mock Data
    recipient_email = settings.EMAIL_HOST_USER # Send to self for testing
    commodity = "TEST COMMODITY"
    
    subject = f"Notification Set: {commodity}"
    message = f"""
    Hi Test User,
    
    You have successfully subscribed to notifications for the auction: {commodity}.
    We will notify you via email when this auction starts!
    
    Auction Details:
    - Commodity: {commodity}
    - Base Price: ₹100
    - Quantity: 50 kg
    
    You can view the auction details here: http://localhost:8000/auction/1/
    
    Best regards,
    The BidVerse Team
    """
    
    try:
        print(f"Sending email to {recipient_email} from {settings.DEFAULT_FROM_EMAIL}...")
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [recipient_email],
            fail_silently=False
        )
        print("SUCCESS: Subscription confirmation email sent!")
        return True
    except Exception as e:
        print(f"FAILED: {e}")
        return False

if __name__ == '__main__':
    test_subscription_email()
