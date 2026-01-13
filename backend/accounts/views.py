from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.urls import reverse
from .serializers import UserRegistrationSerializer, LoginSerializer, GoogleLoginSerializer
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.contrib import messages
from django.utils import timezone
from datetime import datetime, time, timedelta
from django.db.models import Q
from django.http import JsonResponse 
# Use our custom User model
from django.contrib.auth import get_user_model
from .models import Listing, Bid, NotificationSubscription
User = get_user_model()

# Session timing constants
MORNING_START = time(9, 30)  # 9:30 AM
MORNING_END = time(13, 30)    # 1:30 PM
EVENING_START = time(14, 15) # 2:15 PM
EVENING_END = time(18, 15)   # 6:15 PM
BREAK_START = time(13, 30)  # 1:30 PM
BREAK_END = time(14, 15)     # 2:15 PM

def get_current_session_info():
    """Returns current session status: 'morning', 'evening', 'break', or 'closed'"""
    now = timezone.now()
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
    now = timezone.now()
    # Check for auctions that have started in the last few minutes but notification not sent
    # We'll consider 'started' as start_time <= now
    
    # This is a bit complex because start_time is a property, not a field.
    # We can fetch active listings for today and filter in python, or optimize query.
    # For now, let's fetch active listings for today where notification_sent=False
    
    today = now.date()
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
    """Automatically deactivate auctions that have passed their end time"""
    # Also trigger notifications
    send_auction_notifications()

    now = timezone.now()
    today = now.date()
    current_time = now.time()
    
    # End morning-only auctions that have passed 1:30 PM
    if current_time >= MORNING_END:
        Listing.objects.filter(
            is_active=True,
            morning_session=True,
            evening_session=False,
            end_time__date=today
        ).update(is_active=False)
    
    # End evening-only auctions that have passed 6:15 PM
    if current_time >= EVENING_END:
        Listing.objects.filter(
            is_active=True,
            evening_session=True,
            end_time__date=today
        ).update(is_active=False)

def home(request):
    """Home page view showing latest auctions for current session"""
    # Auto-end expired auctions
    auto_end_expired_auctions()
    
    session_info = get_current_session_info()
    now = timezone.now()
    today = now.date()
    
    today = now.date()
    
    # Fetch all active listings for today (Live & Upcoming)
    # MODIFIED: Changed filter to show all future active auctions, not just 'today'
    latest_auctions = Listing.objects.filter(
        is_active=True,
        end_time__gt=now
    ).order_by('end_time')[:6]

    # Get user subscriptions if logged in
    subscribed_listing_ids = []
    if request.user.is_authenticated:
        subscribed_listing_ids = list(NotificationSubscription.objects.filter(
            user=request.user,
            listing__in=latest_auctions
        ).values_list('listing_id', flat=True))
    
    # Attach subscription status to auctions for template
    for auction in latest_auctions:
        auction.is_subscribed = auction.id in subscribed_listing_ids
    
    return render(request, 'index.html', {
        'latest_auctions': latest_auctions,
        'session_info': session_info,
        'now': now
    })

def contact(request):
    """Contact page view with form handling"""
    if request.method == 'POST':
        # In a real app, we'd save the message or send an email
        messages.success(request, "Thank you! Your message has been sent successfully.")
        return redirect('contact')
    return render(request, 'contact.html')

def marketplace(request):
    """View all active auctions with session-based filtering"""
    # Auto-end expired auctions
    auto_end_expired_auctions()
    
    session_info = get_current_session_info()
    now = timezone.now()
    today = now.date()
    
    # Live auctions for current session
    if session_info['is_active']:
        if session_info['session'] == 'morning':
            live_auctions = Listing.objects.filter(
                is_active=True,
                morning_session=True,
                end_time__date=today
            ).order_by('-created_at')
        else:  # evening
            live_auctions = Listing.objects.filter(
                is_active=True
            ).filter(
                Q(evening_session=True, end_time__date=today) |
                Q(morning_session=True, evening_session=True, end_time__date=today)
            ).order_by('-created_at')
    else:
        live_auctions = Listing.objects.none()
    
    # Upcoming evening auctions (shown during break time)
    upcoming_evening = Listing.objects.none()
    if session_info['is_break']:
        upcoming_evening = Listing.objects.filter(
            is_active=True,
            evening_session=True,
            end_time__date=today
        ).exclude(morning_session=True).order_by('-created_at')
    
    # Ended auctions today
    ended_today = Listing.objects.filter(
        is_active=False,
        end_time__date=today
    ).order_by('-end_time')
    
    return render(request, 'marketplace.html', {
        'live_auctions': live_auctions,
        'upcoming_evening': upcoming_evening,
        'ended_today': ended_today,
        'session_info': session_info
    })

def auction_detail(request, listing_id):
    """View details of a specific auction"""
    listing = get_object_or_404(Listing, id=listing_id)
    bid_history = listing.bids.all().order_by('-timestamp')[:5]
    return render(request, 'auction_detail.html', {'listing': listing, 'bid_history': bid_history})

@login_required
def toggle_notification(request, listing_id):
    """Toggle notification subscription for an auction"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid method'}, status=405)
        
    if request.user.user_type != 'BUYER':
        return JsonResponse({'error': 'Only buyers can subscribe'}, status=403)
        
    listing = get_object_or_404(Listing, id=listing_id)
    
    # Toggle subscription
    subscription, created = NotificationSubscription.objects.get_or_create(
        user=request.user,
        listing=listing
    )
    
    if not created:
        # If already exists, delete it (unsubscribe)
        subscription.delete()
        subscribed = False
    else:
        subscribed = True
        
    return JsonResponse({'subscribed': subscribed})

@login_required
def place_bid(request, listing_id):
    """Process a new bid"""
    if request.user.user_type != 'BUYER':
        messages.error(request, "Only buyers can place bids.")
        return redirect('auction_detail', listing_id=listing_id)
    
    listing = get_object_or_404(Listing, id=listing_id)
    if not listing.is_active or listing.end_time < timezone.now():
        messages.error(request, "This auction has ended.")
        return redirect('auction_detail', listing_id=listing_id)
        
    # Check if auction has started
    if listing.start_time > timezone.now():
        messages.error(request, f"This auction starts at {listing.start_time.strftime('%I:%M %p')}")
        return redirect('auction_detail', listing_id=listing_id)
        
    bid_amount = request.POST.get('amount')
    try:
        bid_amount = float(bid_amount)
    except (TypeError, ValueError):
        messages.error(request, "Invalid bid amount.")
        return redirect('auction_detail', listing_id=listing_id)
        
    current_highest = listing.current_highest_bid or listing.base_price
    if bid_amount <= float(current_highest):
        messages.error(request, f"Bid must be higher than ₹{current_highest}")
        return redirect('auction_detail', listing_id=listing_id)
        
    # Create Bid
    Bid.objects.create(listing=listing, buyer=request.user, amount=bid_amount)
    
    # Update Listing
    listing.current_highest_bid = bid_amount
    listing.save()
    
    messages.success(request, f"Successfully placed bid of ₹{bid_amount}!")
    return redirect('auction_detail', listing_id=listing_id)

class RegisterAPIView(generics.GenericAPIView):
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'user': serializer.data,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_201_CREATED)

class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'user_type': user.user_type,
            'email': user.email,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_200_OK)

class GoogleLoginAPIView(generics.GenericAPIView):
    serializer_class = GoogleLoginSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'user_type': user.user_type,
            'email': user.email,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_200_OK)

class PasswordResetRequestView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        email = request.data.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            
            # Construct reset URL (frontend route)
            # In a real app, this should link to your frontend: e.g., http://localhost:3000/reset-password/<uid>/<token>
            # For this backend demo, we'll just print it or send it.
            
            reset_link = f"http://localhost:8000/api/auth/password-reset-confirm/{uidb64}/{token}/"
            
            # Send Email
            try:
                send_mail(
                    subject="BidVerse Password Reset",
                    message=f"Click the link to reset your password: {reset_link}",
                    from_email=settings.EMAIL_HOST_USER if hasattr(settings, 'EMAIL_HOST_USER') else 'noreply@bidverse.com',
                    recipient_list=[email],
                    fail_silently=False,
                )
            except Exception as e:
                # In development with Console Backend, this won't fail usually.
                pass
                
            return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)
        
        return Response({'error': 'Email not found'}, status=status.HTTP_404_NOT_FOUND)

class PasswordResetConfirmView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is invalid or expired'}, status=status.HTTP_401_UNAUTHORIZED)
            
            password = request.data.get('password')
            user.set_password(password)
            user.save()
            
            return Response({'success': 'Password Reset Success'}, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError:
            return Response({'error': 'Token is invalid or expired'}, status=status.HTTP_401_UNAUTHORIZED)

# Custom Password Reset Views
from django.contrib.auth.views import (
    PasswordResetView,
    PasswordResetDoneView,
    PasswordResetConfirmView,
    PasswordResetCompleteView
)

class CustomPasswordResetView(PasswordResetView):
    # Basic template configuration
    template_name = 'registration/password_reset_form.html'
    email_template_name = 'registration/password_reset_email.html'
    subject_template_name = 'registration/password_reset_subject.txt'
    success_url = '/password-reset/done/'

    def form_valid(self, form):
        """Override to manually send password reset email"""
        email = form.cleaned_data['email']
        print(f"DEBUG: Processing password reset for: {email}")

        from django.contrib.auth import get_user_model
        from django.template.loader import render_to_string
        from django.contrib.sites.models import Site
        from django.utils.http import urlsafe_base64_encode
        from django.utils.encoding import force_bytes
        from django.contrib.auth.tokens import default_token_generator
        from django.core.mail import send_mail
        from django.conf import settings

        User = get_user_model()
        users = User.objects.filter(email=email)

        if users.exists():
            user = users.first()
            print(f"DEBUG: Found user {user.email}, sending manual password reset email")

            try:
                # Generate reset token
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)

                # Get site
                site = Site.objects.get_current()

                # Create context
                context = {
                    'email': user.email,
                    'user': user,
                    'domain': site.domain,
                    'protocol': 'http',
                    'uid': uid,
                    'token': token,
                }

                # Render templates
                subject = render_to_string(self.subject_template_name, context).strip()
                email_content = render_to_string(self.email_template_name, context)

                print(f"DEBUG: Subject: {subject}")
                print(f"DEBUG: Email length: {len(email_content)}")

                # Send email
                result = send_mail(
                    subject=subject,
                    message='',  # Plain text
                    html_message=email_content,  # HTML
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=False
                )

                print(f"DEBUG: Manual email sent successfully! Result: {result}")

            except Exception as e:
                print(f"DEBUG: Manual email sending failed: {e}")
                import traceback
                traceback.print_exc()

        # Call parent form_valid to maintain normal flow
        return super().form_valid(form)

class CustomPasswordResetDoneView(PasswordResetDoneView):
    template_name = 'registration/password_reset_done.html'

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'registration/password_reset_confirm.html'

class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = 'registration/password_reset_complete.html'

# Web Form Views
@csrf_protect
def login_user(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        csrf_token = request.POST.get("csrfmiddlewaretoken")

        # Debug logging
        print(f"Login attempt for email: {email}")
        print(f"CSRF token received: {csrf_token}")
        print(f"Session CSRF token: {request.session.get('_csrftoken', 'None')}")

        # Since USERNAME_FIELD = 'email', we authenticate with email as username
        user = authenticate(request, username=email, password=password)

        if user is not None:
            print(f"Authentication successful for user: {user.email}")
            login(request, user)
            print("Redirecting to home...")
            return redirect("home")
        else:
            # Check if user exists but password is wrong, or user doesn't exist
            user_exists = User.objects.filter(email=email).exists()
            print(f"Authentication failed. User exists: {user_exists}")
            if user_exists:
                error_msg = "Incorrect password. Please try again."
            else:
                error_msg = "No account found with this email address."
            return render(request, "login.html", {"error": error_msg})

    # Handle GET requests - display the login form
    return render(request, "login.html", {})

@login_required
def logout_user(request):
    """Log out the current user"""
    logout(request)
    return redirect("/")

def csrf_failure(request, reason=""):
    """Custom CSRF failure view with helpful debugging"""
    from django.http import HttpResponse
    from django.template import Template, Context

    template = Template("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CSRF Error - BidVerse</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #e74c3c; margin-bottom: 20px; }
            .solution { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 15px 0; }
            .code { background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 3px; font-family: monospace; }
            a { color: #3498db; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>CSRF Verification Failed</h1>
            <p>The CSRF token in your form submission didn't match the expected token. This is a security feature to prevent cross-site request forgery attacks.</p>

            <div class="solution">
                <h3>🔧 Quick Fix:</h3>
                <ol>
                    <li><strong>Hard refresh the page:</strong> Press <code>Ctrl+F5</code> (or <code>Cmd+Shift+R</code> on Mac)</li>
                    <li><strong>Try incognito mode:</strong> Open a new incognito/private window and try again</li>
                    <li><strong>Clear browser cache:</strong> Clear cached images and files for this site</li>
                </ol>
            </div>

            <div class="solution">
                <h3>🔍 Why This Happens:</h3>
                <ul>
                    <li>Page cached with old CSRF token</li>
                    <li>Browser session issues</li>
                    <li>Multiple tabs with different sessions</li>
                    <li>Cookies disabled or blocked</li>
                </ul>
            </div>

            <div class="solution">
                <h3>🚀 Try This Now:</h3>
                <p><a href="/login/" class="code">← Back to Login</a></p>
                <p>Or open this link in an incognito window: <code>http://127.0.0.1:8000/login/</code></p>
            </div>

            <p><small>Debug info: {{ reason }}</small></p>
        </div>
    </body>
    </html>
    """)

    context = Context({'reason': reason})
    return HttpResponse(template.render(context))

def check_auth_status(request):
    """Check authentication status for frontend"""
    from django.http import JsonResponse

    if request.user.is_authenticated:
        return JsonResponse({
            'authenticated': True,
            'user': {
                'email': request.user.email,
                'display_name': request.user.get_full_name() or request.user.email,
            }
        })
    else:
        return JsonResponse({
            'authenticated': False,
            'user': None
        })

def register_user(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")
        fullname = request.POST.get("fullname")
        phone = request.POST.get("phone")
        usertype = request.POST.get("usertype")

        # Basic validation
        if not email or not password:
            return render(request, "register.html", {"error": "Email and password are required"})

        if password != confirm_password:
            return render(request, "register.html", {"error": "Passwords do not match"})

        # Check if user already exists
        if User.objects.filter(email=email).exists():
            return render(request, "register.html", {"error": "Email already registered"})

        # Create user manually for custom User model
        user = User()
        user.email = email
        user.username = email  # Explicitly set username to email

        # Set optional fields
        if fullname:
            # Split fullname into first and last name
            name_parts = fullname.strip().split(' ', 1)
            user.first_name = name_parts[0]
            if len(name_parts) > 1:
                user.last_name = name_parts[1]

        if phone:
            user.phone = phone

        if usertype:
            user.user_type = usertype.upper()

        user.set_password(password)
        user.full_clean()  # Validate before saving
        user.save()
        return redirect("/login/")

    return render(request, "register.html")

def check_auth(request):
    """Check authentication status for frontend"""
    from django.http import JsonResponse

    if request.user.is_authenticated:
        return JsonResponse({
            'authenticated': True,
            'user': {
                'email': request.user.email,
                'display_name': request.user.get_full_name() or request.user.username,
            }
        })
    else:
        return JsonResponse({
            'authenticated': False,
            'user': None
        })

@login_required
def dashboard(request):
    """User dashboard view - routes to specialized templates based on user_type"""
    user_type = request.user.user_type
    section = request.GET.get('section', 'dashboard')
    context = {'user': request.user, 'section': section}
    
    if user_type == 'FARMER':
        if request.method == 'POST' and section == 'add_listing':
            # Get session selections
            morning_session = request.POST.get('morning_session') == 'on'
            evening_session = request.POST.get('evening_session') == 'on'
            
            # Validate at least one session is selected
            if not morning_session and not evening_session:
                messages.error(request, "Please select at least one session (Morning or Evening).")
                return redirect(reverse('dashboard') + '?section=add_listing')
            
            # Get selected date (default to today)
            selected_date_str = request.POST.get('listing_date')
            if selected_date_str:
                try:
                    selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
                except:
                    selected_date = timezone.now().date()
            else:
                selected_date = timezone.now().date()
            
            # Calculate end_time based on sessions
            end_time = calculate_listing_end_time(selected_date, morning_session, evening_session)
            
            Listing.objects.create(
                seller=request.user,
                commodity=request.POST.get('commodity'),
                quantity=request.POST.get('quantity'),
                unit=request.POST.get('unit'),
                base_price=request.POST.get('base_price'),
                end_time=end_time,
                description=request.POST.get('description'),
                image=request.FILES.get('image'),
                morning_session=morning_session,
                evening_session=evening_session
            )
            messages.success(request, "Listing created successfully!")
            return redirect(reverse('dashboard') + '?section=listings')
        
        if section == 'listings':
            context['listings'] = Listing.objects.filter(seller=request.user).order_by('-created_at')
        elif section == 'orders':
            # Sold items for farmer
            context['orders'] = Listing.objects.filter(seller=request.user, is_active=False).order_by('-end_time')
        elif section == 'dashboard':
            context['active_listings_count'] = Listing.objects.filter(seller=request.user, is_active=True).count()
            context['sold_count'] = Listing.objects.filter(seller=request.user, is_active=False).count()
            context['live_listings'] = Listing.objects.filter(seller=request.user, is_active=True).order_by('-created_at')[:5]
        
        return render(request, "dashboard/seller.html", context)
        
    elif user_type == 'BUYER':
        user_bids = Bid.objects.filter(buyer=request.user)
        
        if section == 'bids':
            context['bids'] = user_bids.order_by('-timestamp')
        elif section == 'won':
            # Simplified logic: listings where user has a bid and is_active=False
            # and their bid is >= current_highest_bid (which is usually their own)
            context['won_listings'] = Listing.objects.filter(
                is_active=False,
                bids__buyer=request.user
            ).distinct().order_by('-end_time')
        elif section == 'orders':
            context['orders'] = context.get('won_listings', Listing.objects.filter(is_active=False, bids__buyer=request.user).distinct())
        elif section == 'dashboard':
            context['active_bids_count'] = user_bids.filter(listing__is_active=True).values('listing').distinct().count()
            context['won_auctions_count'] = Listing.objects.filter(is_active=False, bids__buyer=request.user).distinct().count()
            context['recent_bids'] = user_bids.order_by('-timestamp')[:5]
        
        return render(request, "dashboard/buyer.html", context)
        
    elif user_type == 'ADMIN':
        if request.method == 'POST' and section == 'users':
            user_id = request.POST.get('user_id')
            action = request.POST.get('action')
            target_user = get_object_or_404(User, id=user_id)
            if action == 'verify':
                target_user.is_verified = True
                target_user.save()
                messages.success(request, f"User {target_user.email} verified successfully.")
            return redirect(reverse('dashboard') + '?section=users')

        if section == 'dashboard':
            context['total_users_count'] = User.objects.count()
            context['active_auctions_count'] = Listing.objects.filter(is_active=True).count()
            context['pending_verifications_count'] = User.objects.filter(is_verified=False).count()
            context['recent_users'] = User.objects.order_by('-date_joined')[:5]
        elif section == 'users':
            context['all_users'] = User.objects.all().order_by('-date_joined')
        elif section == 'auctions':
            context['all_listings'] = Listing.objects.all().order_by('-created_at')
            
        return render(request, "dashboard/admin.html", context)
    
    else:
        return render(request, "dashboard.html", {'user': request.user})

@login_required
def delete_listing(request, listing_id):
    """Delete a listing - seller can delete own, admin can delete any"""
    listing = get_object_or_404(Listing, id=listing_id)
    
    # Permission Check
    is_owner = listing.seller == request.user
    is_admin = request.user.user_type == 'ADMIN'
    
    if not (is_owner or is_admin):
        messages.error(request, "You don't have permission to delete this listing.")
        return redirect('dashboard')
    
    if request.method == 'POST':
        listing.delete()
        messages.success(request, "Listing deleted successfully.")
        
        # Redirect based on user type
        if is_admin:
            return redirect(reverse('dashboard') + '?section=auctions')
        else:
            return redirect(reverse('dashboard') + '?section=listings')
    
    # If GET request
    if is_admin:
         return redirect(reverse('dashboard') + '?section=auctions')
    return redirect(reverse('dashboard') + '?section=listings')