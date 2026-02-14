import os
import django
import re

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from accounts.models import User, Listing, Notification

def check_orphaned_notifications(email):
    with open("check_notifs_output.txt", "w") as f:
        try:
            user = User.objects.get(email=email)
            f.write(f"Checking for user: {user.email}\n")
        except User.DoesNotExist:
            f.write(f"User {email} not found.\n")
            return
        
        # Override print with f.write
        def print(msg):
            f.write(msg + "\n")

        # Get "WIN" notifications
        notifs = Notification.objects.filter(
            receiver=user, 
            message__icontains="won the auction"
        ).order_by('-created_at')
        
        print(f"Found {notifs.count()} 'Win' notifications.")
        
        for n in notifs:
            # Extract commodity name from message "You won the auction for X with a bid..."
            match = re.search(r"auction for (.*?) with a bid", n.message)
            if match:
                commodity_name = match.group(1)
                print(f"\n[Notification] '{commodity_name}' on {n.created_at.date()}")
                
                # Check if such a listing exists for this user (buyer won it)
                # Strategy: Find ANY inactive listing for this commodity where this user has a bid
                listings = Listing.objects.filter(
                    commodity__icontains=commodity_name,
                    is_active=False
                )
                
                if listings.exists():
                    print(f"  -> Found {listings.count()} inactive listing(s) matching '{commodity_name}'. Checking bids...")
                    found_match = False
                    for l in listings:
                        highest = l.bids.order_by('-amount').first()
                        if highest:
                             print(f"     List ID {l.id}: Highest Bid by {highest.buyer.email} (Amt: {highest.amount})")
                             if highest.buyer == user:
                                 print("     *** MATCH FOUND: User IS the winner ***")
                                 found_match = True
                        else:
                             print(f"     List ID {l.id}: No bids.")
                    
                    if not found_match:
                        print("  -> No matching listing found where user is the winner.")
                else:
                    print("  -> NO inactive listings found for this commodity. (Listing likely deleted)")
            else:
                print(f"Could not parse message: {n.message}")

if __name__ == "__main__":
    check_orphaned_notifications("jeweltreasaraphel2028@mca.ajce.in")
