
import os
import django
import random
from datetime import timedelta, time
from django.utils import timezone

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from accounts.models import User, Listing, Bid, NotificationSubscription

def create_dummy_data():
    print("Clearing existing data...")
    Listing.objects.all().delete()
    User.objects.filter(email__contains='example.com').delete()

    print("Creating dummy data...")

    # 1. Create Farmers
    farmers = []
    for i in range(1, 4):
        email = f"farmer{i}@example.com"
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'username': email,
                'first_name': f'Farmer {i}',
                'last_name': 'Doe',
                'user_type': 'FARMER',
                'is_verified': True,
                'phone': f'987654321{i}'
            }
        )
        if created:
            user.set_password('password123')
            user.save()
            print(f"Created farmer: {email}")
        farmers.append(user)

    # 2. Create Listings
    commodities = [
        ('RICE', 'Basmati Rice', 'kg'),
        ('WHEAT', 'Premium Wheat', 'quintal'),
        ('WHEAT', 'Organic Sharbati Wheat', 'quintal'),
        ('TOMATO', 'Fresh Tomatoes', 'kg'),
        ('POTATO', 'Organic Potatoes', 'kg'),
        ('ONION', 'Red Onions', 'kg'),
    ]

    now = timezone.now()
    today = now.date()
    tomorrow = today + timedelta(days=1)
    
    # Session End Times
    MORNING_END = time(13, 30)
    EVENING_END = time(18, 15)

    # Create listings for today and tomorrow
    dates = [today, tomorrow]
    
    for date in dates:
        # Create one of each commodity for each day to ensure variety and no duplicates
        # Shuffle to mix up the order
        day_commodities = list(commodities)
        random.shuffle(day_commodities)
        
        for code, name, unit in day_commodities:
            farmer = random.choice(farmers)
            
            # morning or evening or both
            if 'Premium' in name:
                choice = 'morning'
            elif 'Basmati' in name:
                choice = 'evening'
            elif 'Red Onion' in name:
                choice = 'both'
            elif 'Organic Potato' in name:
                choice = 'morning'
            elif 'Fresh Tomato' in name:
                choice = 'evening'
            else:
                choice = random.choice(['morning', 'evening', 'both'])

            morning = choice in ['morning', 'both']
            evening = choice in ['evening', 'both']
            
            if evening:
                end_time_val = EVENING_END
            else:
                end_time_val = MORNING_END
                
            end_time = timezone.make_aware(timezone.datetime.combine(date, end_time_val))

            listing = Listing.objects.create(
                seller=farmer,
                commodity=name,
                quantity=random.randint(50, 500),
                unit=unit,
                base_price=random.randint(2000, 5000) if unit == 'quintal' else random.randint(20, 100),
                end_time=end_time,
                description=f"High quality {name} from {farmer.first_name}.",
                morning_session=morning,
                evening_session=evening,
                is_active=True
            )
            print(f"Created listing: {listing.commodity} for {date} ({choice})")

    print("Dummy data creation complete! Total listings today:", Listing.objects.filter(end_time__date=today).count())

if __name__ == '__main__':
    create_dummy_data()
