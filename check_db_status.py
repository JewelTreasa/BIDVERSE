
import os
import django
import sys

# Setup Django Path
sys.path.append(os.path.join(os.getcwd(), 'backend'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from accounts.models import User

def check_users():
    print(f"{'Email':<30} | {'Type':<10} | {'Used Trial?':<12} | {'Expiry':<20}")
    print("-" * 80)
    for u in User.objects.filter(user_type__in=['BUYER', 'FARMER']):
        expiry = u.membership_expiry.strftime('%Y-%m-%d') if u.membership_expiry else "None"
        print(f"{u.email:<30} | {u.user_type:<10} | {str(u.has_used_free_trial):<12} | {expiry:<20}")

if __name__ == '__main__':
    check_users()
