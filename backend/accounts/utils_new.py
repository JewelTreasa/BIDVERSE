from django.utils import timezone
from datetime import datetime, time, timedelta
from django.conf import settings
from django.core.mail import send_mail
from .models import Listing, NotificationSubscription, Notification, Bid
import io
from django.http import HttpResponse
from django.template.loader import get_template
from xhtml2pdf import pisa

# Session timing constants
MORNING_START = time(9, 30)  # 9:30 AM
MORNING_END = time(13, 30)    # 1:30 PM
EVENING_START = time(14, 15) # 2:15 PM
EVENING_END = time(18, 15)   # 6:15 PM
BREAK_START = time(13, 30)  # 1:30 PM
BREAK_END = time(14, 15)     # 2:15 PM

def get_current_session_info():
    """Returns current session status: 'morning', 'evening', 'break', or 'closed'"""
    # Use local time for session logic (wall clock time)
    now = timezone.localtime(timezone.now())
    current_time = now.time()
    current_date = now.date()
    
    if MORNING_START <= current_time < MORNING_END:
        return {
            'session': 'morning',
            'is_active': True,
            'end_time': datetime.combine(current_date, MORNING_END),
            'is_break': False
        }
    elif BREAK_START <= current_time < BREAK_END:
        return {
            'session': 'break',
            'is_active': False,
            'next_session_start': datetime.combine(current_date, EVENING_START),
            'is_break': True
        }
    elif EVENING_START <= current_time < EVENING_END:
        return {
            'session': 'evening',
            'is_active': True,
            'end_time': datetime.combine(current_date, EVENING_END),
            'is_break': False
        }
    else:
        # Before morning or after evening
        if current_time < MORNING_START:
            return {
                'session': 'closed',
                'is_active': False,
                'next_session_start': datetime.combine(current_date, MORNING_START),
                'is_break': False
            }
        else:
            # After evening session, next morning
            next_date = current_date + timedelta(days=1)
            return {
                'session': 'closed',
                'is_active': False,
                'next_session_start': datetime.combine(next_date, MORNING_START),
                'is_break': False
            }

def calculate_listing_end_time(selected_date, morning_session, evening_session):
    """Calculate end_time based on selected sessions"""
    if morning_session and evening_session:
        # Both sessions selected - ends at evening end time
        return datetime.combine(selected_date, EVENING_END)
    elif morning_session:
        # Only morning - ends at morning end time
        return datetime.combine(selected_date, MORNING_END)
    elif evening_session:
        # Only evening - ends at evening end time
        return datetime.combine(selected_date, EVENING_END)
    else:
        # Default to evening if nothing selected (shouldn't happen with validation)
        return datetime.combine(selected_date, EVENING_END)

def send_auction_notifications():
    """Check for auctions starting now and send emails to subscribed users"""
    now = timezone.localtime(timezone.now())
    today = now.date()
    # Check for auctions that have started in the last few minutes but notification not sent
    # We'll consider 'started' as start_time <= now
    
    # Fetch active listings for today where notification_sent=False
    listings = Listing.objects.filter(
        is_active=True,
        end_time__date=today,
        notification_sent=False
    )
    
    # We need to send notifications if start_time <= now
    for listing in listings:
        if listing.start_time <= now:
            # Get subscribers
            subscriptions = NotificationSubscription.objects.filter(listing=listing)
            if subscriptions.exists():
                recipient_list = [sub.user.email for sub in subscriptions]
                
                subject = f"Auction Started: {listing.commodity}"
                message = f"""
                The auction for {listing.commodity} has started!
                
                Base Price: ₹{listing.base_price}
                Quantity: {listing.quantity} {listing.unit}
                
                Place your bid now: http://localhost:8000/auction/{listing.id}/
                """
                
                try:
                    send_mail(
                        subject,
                        message,
                        settings.EMAIL_HOST_USER,
                        recipient_list,
                        fail_silently=True
                    )
                    print(f"Sent notifications for listing {listing.id} to {len(recipient_list)} users.")
                except Exception as e:
                    print(f"Error sending notifications: {e}")
            
            # Mark as sent regardless to avoid loops
            listing.notification_sent = True
            listing.save()

def auto_end_expired_auctions():
    """Automatically deactivate auctions that have passed their end time and notify winners"""
    print("Checking for expired auctions...")
    # Also trigger start notifications
    send_auction_notifications()

    now = timezone.localtime(timezone.now())
    
    # Close any active auction where end_time covers the past
    Listing.objects.filter(is_active=True, end_time__lt=now).update(is_active=False)

    # Process ended auctions for winner notifications
    # We look for ended auctions (is_active=False) where winner_notified is False
    ended_auctions = Listing.objects.filter(is_active=False, winner_notified=False)

    for listing in ended_auctions:
        # Get the highest bid for this listing
        # If multiple bids have the same highest amount, the one placed first wins
        highest_bid = listing.bids.order_by('-amount', 'timestamp').first()
        
        if highest_bid:
            winner = highest_bid.buyer
            amount = highest_bid.amount
            
            # 1. Create a "WIN" notification for the pop-up
            Notification.objects.create(
                receiver=winner,
                message=f"Congratulations! You won the auction for {listing.commodity} with a bid of ₹{amount}!",
                notification_type='WIN'
            )
            
            # 2. Send appreciation mail
            subject = f"Congratulations! You won the auction: {listing.commodity}"
            message = f"""
            Hi {winner.first_name or winner.email},
            
            Congratulations! You have won the auction for {listing.commodity} on BidVerse.
            
            Winning Bid: ₹{amount}
            Quantity: {listing.quantity} {listing.unit}
            Seller: {listing.seller.get_full_name() or listing.seller.email}
            
            Please log in to your dashboard to view your won auctions and complete the next steps.
            
            Best regards,
            The BidVerse Team
            """
            
            try:
                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,
                    [winner.email],
                    fail_silently=True
                )
            except Exception as e:
                print(f"Error sending win email: {e}")

        # Mark as notified regardless of whether there was a bid (to avoid processing again)
        listing.winner_notified = True
        listing.save()

def render_to_pdf(template_src, context_dict={}):
    template = get_template(template_src)
    html  = template.render(context_dict)
    result = io.BytesIO()
    pdf = pisa.pisaDocument(io.BytesIO(html.encode("UTF-8")), result)
    if not pdf.err:
        return HttpResponse(result.getvalue(), content_type='application/pdf')
    return None
