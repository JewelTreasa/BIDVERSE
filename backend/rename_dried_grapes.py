import os
import django

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from accounts.models import Listing

def rename_commodity():
    # Case insensitive search for Dried Grapes
    listings = Listing.objects.filter(commodity__icontains="Dried Grapes")
    count = listings.count()
    
    if count > 0:
        print(f"Found {count} listings for 'Dried Grapes'. Updating to 'Black Raisins'...")
        for listing in listings:
            listing.commodity = "Black Raisins"
            listing.save()
        print("Update complete.")
    else:
        print("No listings found for 'Dried Grapes'. Checking for 'Black Raisins'...")
        existing = Listing.objects.filter(commodity__icontains="Black Raisins").count()
        print(f"Found {existing} listings already named 'Black Raisins'.")

if __name__ == '__main__':
    rename_commodity()
