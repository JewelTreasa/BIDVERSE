
import os
import django
import random
from datetime import timedelta, time
from django.utils import timezone

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from accounts.models import User, Listing

def add_more_data():
    print("Adding more auctions...")

    # 1. Ensure Farmers Exist
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
        else:
            print(f"Found existing farmer: {email}")
        farmers.append(user)

    # 2. Create Listings
    commodities = [
        ('RICE', 'Basmati Rice', 'kg'),
        ('WHEAT', 'Premium Wheat', 'quintal'),
        ('WHEAT', 'Organic Sharbati Wheat', 'quintal'),
        ('TOMATO', 'Fresh Tomatoes', 'kg'),
        ('POTATO', 'Organic Potatoes', 'kg'),
        ('ONION', 'Red Onions', 'kg'),
        ('APPLE', 'Shimla Apples', 'box'),
        ('GRAPES', 'Green Grapes', 'kg'),
        ('TEA', 'Darjeeling Tea', 'kg'),
        ('SPICE', 'Mixed Spices', 'kg'),
    ]

    now = timezone.now()
    today = now.date()
    # Add listings for next 3 days to have plenty of upcoming
    dates = [today, today + timedelta(days=1), today + timedelta(days=2)]
    
    # Session End Times
    MORNING_END = time(13, 30)
    EVENING_END = time(18, 15)

    created_count = 0

    for date in dates:
        # Create a random selection of commodities for each day
        day_commodities = random.sample(commodities, k=random.randint(4, 8))
        
        for code, name, unit in day_commodities:
            farmer = random.choice(farmers)
            
            # Determine session
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
                base_price=random.randint(2000, 5000) if unit == 'quintal' else random.randint(20, 200),
                end_time=end_time,
                description=f"Fresh {name} directly from the farm of {farmer.first_name}.",
                morning_session=morning,
                evening_session=evening,
                is_active=True
            )
            created_count += 1
            print(f"Created listing: {listing.commodity} for {date} ({choice})")

    print(f"Data addition complete! Added {created_count} new listings.")

if __name__ == '__main__':
    add_more_data()
