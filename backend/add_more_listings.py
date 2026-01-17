
import os
import django
import random
from datetime import timedelta, time
from django.utils import timezone

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from accounts.models import User, Listing

def add_more_listings():
    print("Finding farmers...")
    farmers = User.objects.filter(user_type='FARMER')
    if not farmers.exists():
        print("No farmers found. Please run create_dummy_data.py first.")
        return

    print(f"Found {farmers.count()} farmers.")

    commodities = [
        ('TOMATO', 'Organic Cherry Tomatoes', 'kg', 40, 80),
        ('POTATO', 'Russet Potatoes', 'kg', 25, 50),
        ('ONION', 'Sweet Yellow Onions', 'kg', 30, 60),
        ('WHEAT', 'Durum Wheat', 'quintal', 2200, 2800),
        ('RICE', 'Jasmine Rice', 'kg', 60, 100),
        ('PULSE', 'Green Moong Dal', 'kg', 90, 150),
        ('Saffron', 'Kashmiri Saffron', 'gram', 250, 400),
        ('Apple', 'Shimla Apples', 'kg', 120, 180),
        ('Grapes', 'Seedless Green Grapes', 'kg', 80, 140),
        ('Garlic', 'White Garlic', 'kg', 150, 250),
    ]

    now = timezone.now()
    today = now.date()
    # Create listings for today, tomorrow, and the day after
    dates = [today, today + timedelta(days=1), today + timedelta(days=2)]
    
    MORNING_END = time(13, 30)
    EVENING_END = time(18, 15)

    created_count = 0
    for date in dates:
        random.shuffle(commodities)
        # Add 3-5 items for each day
        items_to_add = random.randint(3, 5)
        for i in range(items_to_add):
            if i >= len(commodities): break
            
            code, name, unit, min_price, max_price = commodities[i]
            farmer = random.choice(farmers)
            
            choice = random.choice(['morning', 'evening', 'both'])
            morning = choice in ['morning', 'both']
            evening = choice in ['evening', 'both']
            
            if evening:
                end_time_val = EVENING_END
            else:
                end_time_val = MORNING_END
                
            end_time = timezone.make_aware(timezone.datetime.combine(date, end_time_val))
            
            # Skip if end_time is in the past
            if end_time < now:
                continue

            Listing.objects.create(
                seller=farmer,
                commodity=name,
                quantity=random.randint(20, 300),
                unit=unit,
                base_price=random.randint(min_price, max_price),
                end_time=end_time,
                description=f"Freshly harvested {name}. High quality and ready for delivery.",
                morning_session=morning,
                evening_session=evening,
                is_active=True
            )
            created_count += 1
            print(f"Created Listing: {name} for {date}")

    print(f"Successfully added {created_count} more listings!")

if __name__ == '__main__':
    add_more_listings()
