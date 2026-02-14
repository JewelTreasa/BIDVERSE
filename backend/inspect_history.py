import os
import django
from django.utils import timezone

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from accounts.models import User, Listing, Bid

def inspect_bid_history(email):
    try:
        user = User.objects.get(email=email)
        print(f"--- History for {user.email} ---")
    except User.DoesNotExist:
        print(f"User {email} not found")
        return

    # All bids by this user
    bids = Bid.objects.filter(buyer=user).order_by('-timestamp')
    print(f"Total Bids Made: {bids.count()}")
    
    for bid in bids:
        l = bid.listing
        print(f"\n[Bid ID: {bid.id}] Amount: {bid.amount} on '{l.commodity}' (Listing {l.id})")
        print(f"  Listing Status: Active={l.is_active}, Ends={l.end_time}")
        
        # Who won?
        if not l.is_active:
            highest = l.bids.order_by('-amount', 'timestamp').first()
            if highest:
                winner = highest.buyer
                print(f"  Winner: {winner.email} with Bid {highest.amount}")
                if winner == user:
                     print("  ** THIS USER WON **")
                else:
                     print("  User LOST (outbid)")
            else:
                print("  No bids on closed listing? (Data inconsistency)")
        else:
            print("  Listing is still LIVE")

if __name__ == "__main__":
    inspect_bid_history("jeweltreasaraphel2028@mca.ajce.in")
