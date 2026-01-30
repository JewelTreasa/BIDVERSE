import os
import sys
import django
from django.test import Client
from django.utils import timezone
from datetime import timedelta

# Setup Django Path
# We are running from 'd:\BIDVERSE OUT', project root is 'd:\BIDVERSE OUT\backend'
sys.path.append(os.path.join(os.getcwd(), 'backend'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from accounts.models import User

def run_verification():
    print("Starting Verification...")
    
    # 1. Setup Data
    email = "test_buyer_verify@example.com"
    password = "password123"
    
    # Cleanup previous run
    User.objects.filter(email=email).delete()
    
    user = User.objects.create_user(username=email, email=email, password=password, user_type='BUYER')
    print(f"Created User: {user.email}")
    
    client = Client()
    
    # 2. Test Free Trial (First Login)
    print("\n[TEST 1] First Login (Free Trial)")
    response = client.post('/login/', {'email': email, 'password': password})
    
    user.refresh_from_db()
    if response.status_code == 302 and response.url == '/':
        print("PASS: Redirected to Home")
    else:
        print(f"FAIL: Status {response.status_code}, URL {response.url if hasattr(response, 'url') else 'None'}")
        
    if user.has_used_free_trial:
        print("PASS: has_used_free_trial set to True")
    else:
        print("FAIL: has_used_free_trial is False")
        
    # 3. Test Subsequent Login (Should Fail / Redirect)
    # Note: Client preserves session. We need to clear session or simulate "Next Time".
    # Since we implemented the check AT LOGIN, we need to log out and log in again.
    client.logout()
    
    print("\n[TEST 2] Second Login (Membership Required)")
    response = client.post('/login/', {'email': email, 'password': password})
    
    if response.status_code == 302 and '/membership/' in response.url:
        print("PASS: Redirected to Membership Plans")
    else:
        print(f"FAIL: Expected redirect to membership, got {response.status_code} {response.url if hasattr(response, 'url') else ''}")
        
    # 4. Test Purchase
    print("\n[TEST 3] Purchase Membership")
    # We need to be logged in to purchase. BUT the login failed (redirected).
    # In a real browser, the user is redirected but STILL LOGGED IN?
    # Let's check our view logic:
    # "if user is not None: login(request, user) ... if not trial_ok: redirect(membership)"
    # YES, they are logged in. The redirect happens AFTER login().
    # So `client` should still have the session unless `login()` failed.
    # `authenticate` succeeded. `login` called.
    
    # Verify we are logged in
    # (Client session cookie should be set)
    
    # Simulate clicking "Buy Monthly"
    response = client.get('/membership/purchase/monthly/')
    
    user.refresh_from_db()
    if user.membership_expiry and user.membership_expiry > timezone.now():
        print("PASS: Membership Expiry Updated")
    else:
        print("FAIL: Membership Expiry not set")
        
    if response.status_code == 302 and 'dashboard' in response.url:
        print("PASS: Redirected to Dashboard after purchase")
    else:
        print(f"FAIL: Expected redirect to dashboard, got {response.status_code} {response.url if hasattr(response, 'url') else ''}")
        
    # 5. Connect again
    print("\n[TEST 4] Access after Purchase")
    client.logout()
    response = client.post('/login/', {'email': email, 'password': password})
    
    if response.status_code == 302 and response.url == '/':
         print("PASS: Access Granted")
    else:
         print(f"FAIL: Access Denied {response.status_code} {response.url if hasattr(response, 'url') else ''}")

if __name__ == '__main__':
    run_verification()
