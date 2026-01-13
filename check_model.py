import os
import django
import sys

# Add the project directory to sys.path
sys.path.append('d:\\BIDVERSE OUT\\backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from accounts.models import Listing
from django.utils import timezone

def check_properties():
    listing = Listing.objects.first()
    if not listing:
        print("No listings found")
        return
    
    print("-" * 50)
    print(f"VERIFICATION RESULTS FOR: {listing.commodity}")
    print("-" * 50)
    
    local_now = timezone.localtime(timezone.now())
    print(f"Current System Time (IST): {local_now.strftime('%Y-%m-%d %H:%M:%S')}")
    
    print(f"Display Price: {listing.display_price}")
    print(f"Display Label: {listing.display_label}")
    
    # Check start_time
    st = listing.start_time
    print(f"Start Time (Aware): {st}")
    
    # Check display_time
    dt = listing.display_time
    print(f"Display Time (Local Property): {dt}")
    
    # Raw value in DB
    print(f"Raw end_time from DB: {listing.end_time}")
    
    # Local conversion
    ist_end = timezone.localtime(listing.end_time)
    print(f"Converted end_time to IST: {ist_end.strftime('%H:%M')}")
    
    if dt == ist_end.strftime('%H:%M') or dt == st.strftime('%H:%M'):
        print("SUCCESS: Display time matches IST local time.")
    else:
        print("WARNING: Display time mismatch!")
    
    print("-" * 50)

if __name__ == "__main__":
    check_properties()
