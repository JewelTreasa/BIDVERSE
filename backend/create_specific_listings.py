import os
import django
from django.utils import timezone
from datetime import datetime, time, timedelta

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from accounts.models import User, Listing

def create_user_if_not_exists(email, first_name):
    user, created = User.objects.get_or_create(
        email=email,
        defaults={
            'username': email,
            'first_name': first_name,
            'user_type': 'FARMER',
            'is_verified': True,
            'is_active': True,
            'has_used_free_trial': True,
            'membership_type': 'YEARLY', # Make them premium so no limits
            'membership_expiry': timezone.now() + timedelta(days=365)
        }
    )
    if created:
        user.set_password('password123')
        user.save()
        print(f"Created user: {first_name} ({email})")
    else:
        print(f"Found user: {first_name} ({email})")
    return user

def create_listing(user, commodity, base_price, quantity, unit, date_obj, session_type):
    # Calculate end time based on session
    # Morning: Ends 1:30 PM (13:30)
    # Evening: Ends 6:15 PM (18:15)
    
    start_time = None
    end_time = None
    morning = False
    evening = False
    
    tz = timezone.get_current_timezone()
    
    if session_type == 'morning':
        morning = True
        # End time 1:30 PM
        et = datetime.combine(date_obj, time(13, 30))
        end_time = timezone.make_aware(et, tz)
        start_time_val = time(9, 30)
    else:
        evening = True
        # End time 6:15 PM
        et = datetime.combine(date_obj, time(18, 15))
        end_time = timezone.make_aware(et, tz)
        start_time_val = time(14, 15)
        
    # Check if we should actually create it (prevent duplicates roughly)
    # skipping strict dup check for speed, just create
    
    listing = Listing.objects.create(
        seller=user,
        commodity=commodity,
        base_price=base_price,
        quantity=quantity,
        unit=unit,
        end_time=end_time,
        morning_session=morning,
        evening_session=evening,
        is_active=True,
        description=f"Fresh {commodity} from {user.first_name}'s farm. High quality harvest."
    )
    print(f"Created Listing: {commodity} for {session_type.upper()} ({date_obj}) by {user.first_name}")

def main():
    # Users
    alan = create_user_if_not_exists('alan@example.com', 'Alan')
    anna = create_user_if_not_exists('anna.christina@example.com', 'Anna Christina')

    # Dates
    now = timezone.localtime(timezone.now())
    today = now.date()
    tomorrow = today + timedelta(days=1)
    
    print(f"\n--- Creating Listings for Today ({today}) Afternoon (Evening Session) ---")
    
    # Arecanut (Alan) - Today PM
    create_listing(alan, "Arecanut", 450.00, 100, "kg", today, "evening")
    
    # Rubber Sheet (Anna) - Today PM
    create_listing(anna, "Rubber Sheet", 180.00, 50, "sheets", today, "evening")

    print(f"\n--- Creating Listings for Tomorrow ({tomorrow}) Morning (Morning Session) ---")
    
    # Dried Grapes (Alan) - Tomorrow AM
    create_listing(alan, "Dried Grapes", 320.00, 200, "kg", tomorrow, "morning")
    
    # Pulses (Anna) - Tomorrow AM
    create_listing(anna, "Organic Pulses", 95.00, 5, "quintal", tomorrow, "morning")
    
    # Mix it up a bit - Add one more for tomorrow morning for Alan
    create_listing(alan, "Rubber Sheet", 175.00, 100, "sheets", tomorrow, "morning")

if __name__ == '__main__':
    main()
