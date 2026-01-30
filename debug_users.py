import os
import django
import sys

sys.path.append(os.path.join(os.getcwd(), 'backend'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from accounts.models import User

def list_all_users():
    print(f"{'Email':<30} | {'Type':<10} | {'Used Trial':<10} | {'Expiry':<20}")
    print("-" * 80)
    for u in User.objects.all():
        print(f"{u.email:<30} | {u.user_type:<10} | {str(u.has_used_free_trial):<10} | {str(u.membership_expiry):<20}")

if __name__ == "__main__":
    list_all_users()
