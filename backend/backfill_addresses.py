
import os
import django
import random

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from accounts.models import User

def backfill_addresses():
    farmers = User.objects.filter(user_type__iexact='FARMER')
    count = 0
    
    dummy_addresses = [
        "123 Green Valley Farm, Kerala, India - 686513",
        "456 Hilltop Agro, Idukki, Kerala - 685602",
        "789 River Side Fields, Kottayam, Kerala - 686001",
        "101 Spice Garden, Wayanad, Kerala - 673577",
        "202 Coconut Grove, Alappuzha, Kerala - 688001"
    ]

    print(f"Found {farmers.count()} farmers.")

    for farmer in farmers:
        if not farmer.address:
            # Assign a random address if empty
            addr = random.choice(dummy_addresses)
            farmer.address = addr
            farmer.save()
            print(f"Updated address for {farmer.email}: {addr}")
            count += 1
        else:
            print(f"Skipped {farmer.email} (Already has address)")

    print(f"Successfully backfilled {count} farmers.")

if __name__ == '__main__':
    backfill_addresses()
