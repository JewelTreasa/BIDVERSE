import os
import django
import sys
from django.utils import timezone

# Setup Django
sys.path.append(os.path.join(os.getcwd(), 'backend'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from accounts.models import User

def reset_users():
    print("Resetting users to 'Expired Trial' state (Case Insensitive)...")
    # Fetch all users and filter in python to be 100% sure about casing
    all_users = User.objects.all()
    
    count = 0
    for user in all_users:
        if not user.user_type:
            continue
            
        u_type = user.user_type.upper().strip()
        if u_type in ['BUYER', 'FARMER']:
            print(f"Processing: {user.email} [{user.user_type}]")
            # Force trial used
            user.has_used_free_trial = True
            # Remove membership
            user.membership_expiry = None
            user.save()
            count += 1
            
    print(f"Reset complete. Processed {count} users.")

if __name__ == "__main__":
    reset_users()
