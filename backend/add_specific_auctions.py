
import os
import django
import shutil
from datetime import timedelta, time
from django.utils import timezone

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from accounts.models import User, Listing

def add_auctions():
    print("Moving images to assets...")
    # Paths to generated images (I'll need to use the actual filenames from earlier)
    # The filenames were:
    # arecanut_auction_image_1769680174361.png
    # cardamom_auction_image_1769680207327.png
    
    brain_dir = r'C:\Users\jtrea\.gemini\antigravity\brain\fac32b49-9dc4-4184-b3a8-3d26aaeea623'
    assets_dir = r'd:\BIDVERSE OUT\assets\images'
    
    arecanut_src = os.path.join(brain_dir, 'arecanut_auction_image_1769680174361.png')
    cardamom_src = os.path.join(brain_dir, 'cardamom_auction_image_1769680207327.png')
    
    arecanut_dst = os.path.join(assets_dir, 'arecanut.png')
    cardamom_dst = os.path.join(assets_dir, 'cardamom.png')
    
    try:
        shutil.copy(arecanut_src, arecanut_dst)
        shutil.copy(cardamom_src, cardamom_dst)
        print("Images moved successfully.")
    except Exception as e:
        print(f"Error moving images: {e}")

    # Get a farmer to be the seller
    farmer = User.objects.filter(user_type='FARMER').first()
    if not farmer:
        print("No farmer found. Creating one...")
        farmer = User.objects.create(
            email='farmer_auto@example.com',
            username='farmer_auto@example.com',
            first_name='Auto',
            last_name='Farmer',
            user_type='FARMER',
            is_verified=True
        )
        farmer.set_password('password123')
        farmer.save()

    now = timezone.now()
    today = now.date()
    
    # Session End Times
    # Morning: 9:30 - 13:30
    # Evening: 14:15 - 18:15
    MORNING_END = time(13, 30)
    EVENING_END = time(18, 15)

    listings_data = [
        {
            'name': 'Premium Arecanut',
            'quantity': 250,
            'unit': 'kg',
            'price': 450,
            'img': '/assets/images/arecanut.png',
            'session': 'both'
        },
        {
            'name': 'Green Cardamom (XL Pods)',
            'quantity': 50,
            'unit': 'kg',
            'price': 2200,
            'img': '/assets/images/cardamom.png',
            'session': 'morning'
        },
        {
            'name': 'Assorted Dry Fruits Platter',
            'quantity': 100,
            'unit': 'kg',
            'price': 1200,
            'img': '/assets/images/hero_dried_fruits.jpg',
            'session': 'evening'
        }
    ]

    for data in listings_data:
        morning = data['session'] in ['morning', 'both']
        evening = data['session'] in ['evening', 'both']
        
        end_time_val = EVENING_END if evening else MORNING_END
        end_time = timezone.make_aware(timezone.datetime.combine(today, end_time_val))
        
        # If it's already past the end time for today, set it for tomorrow
        if end_time < now:
            end_time += timedelta(days=1)

        Listing.objects.create(
            seller=farmer,
            commodity=data['name'],
            quantity=data['quantity'],
            unit=data['unit'],
            base_price=data['price'],
            image_url=data['img'],
            end_time=end_time,
            morning_session=morning,
            evening_session=evening,
            description=f"High quality {data['name']} fresh from the farm.",
            is_active=True
        )
        print(f"Created auction for {data['name']}")

if __name__ == '__main__':
    add_auctions()
