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
from django.db.models.functions import Coalesce
from django.http import JsonResponse 
import razorpay
from django.conf import settings 
# Use our custom User model
from django.contrib.auth import get_user_model
from .models import Listing, Bid, NotificationSubscription, Notification
User = get_user_model()

from .utils import (
    get_current_session_info, 
    auto_end_expired_auctions, 
    send_auction_notifications,
    calculate_listing_end_time,
    MORNING_START, MORNING_END, EVENING_START, EVENING_END, BREAK_START, BREAK_END
)

# Logic is now in utils.py to support background tasks

# Initialize Razorpay Client
razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

def membership_required(view_func):
    """
    Decorator to ensure User has active membership or valid free trial session.
    Applies only to BUYER and FARMER roles.
    """
    from functools import wraps
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_authenticated:
            user = request.user
            user_type_upper = user.user_type.upper() if user.user_type else ''
            
            if user_type_upper in ['BUYER', 'FARMER']:
                # 1. Check Active Membership
                has_active = user.membership_expiry and user.membership_expiry > timezone.now()
                
                # 2. Check Valid Free Trial Session
                is_trial_session = request.session.get('is_free_trial_session', False)
                
                if not has_active and not is_trial_session:
                    # BLOCK ACCESS
                    messages.warning(request, "Membership required to access this feature.")
                    return redirect('membership_plans')
                    
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def home(request):
    """Home page view showing latest auctions for current session"""
    # Auto-end expired auctions
    auto_end_expired_auctions()
    
    session_info = get_current_session_info()
    now = timezone.localtime(timezone.now())
    today = now.date()
    
    # Fetch all active listings for today (Live & Upcoming)
    # MODIFIED: Changed filter to show all future active auctions, not just 'today'
    latest_auctions = Listing.objects.filter(
        is_active=True,
        end_time__gt=now
    ).order_by('end_time')[:12]

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

def terms(request):
    return render(request, 'terms.html')

def privacy_policy(request):
    return render(request, 'privacy_policy.html')

def help_center(request):
    return render(request, 'help.html')

@membership_required
def marketplace(request):
    """View all active auctions with session-based filtering"""
    # Auto-end expired auctions
    auto_end_expired_auctions()
    
    session_info = get_current_session_info()
    now = timezone.localtime(timezone.now())
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
        # Include evening-only sessions AND whole-day sessions (which are on break)
        upcoming_evening = Listing.objects.filter(
            is_active=True,
            evening_session=True,
            end_time__date=today
        ).order_by('-created_at')
        # Note: We removed the .exclude(morning_session=True) so morning+evening are included here
    
    # Ended auctions today
    ended_today = Listing.objects.filter(
        is_active=False,
        end_time__date=today
    ).order_by('-end_time')
    
    # Get user subscriptions if logged in
    subscribed_listing_ids = []
    if request.user.is_authenticated:
        all_viewed_auctions = list(live_auctions) + list(upcoming_evening) + list(ended_today)
        subscribed_listing_ids = list(NotificationSubscription.objects.filter(
            user=request.user,
            listing__in=all_viewed_auctions
        ).values_list('listing_id', flat=True))
    
    # Attach subscription status
    for auction in live_auctions:
        auction.is_subscribed = auction.id in subscribed_listing_ids
    for auction in upcoming_evening:
        auction.is_subscribed = auction.id in subscribed_listing_ids
    for auction in ended_today:
        auction.is_subscribed = auction.id in subscribed_listing_ids
    
    return render(request, 'marketplace.html', {
        'live_auctions': live_auctions,
        'upcoming_evening': upcoming_evening,
        'ended_today': ended_today,
        'session_info': session_info
    })

@membership_required
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
        # Send confirmation email
        subject = f"Notification Set: {listing.commodity}"
        message = f"""
        Hi {request.user.first_name},
        
        You have successfully subscribed to notifications for the auction: {listing.commodity}.
        We will notify you via email when this auction starts!
        
        Auction Details:
        - Commodity: {listing.commodity}
        - Base Price: ₹{listing.base_price}
        - Quantity: {listing.quantity} {listing.unit}
        
        You can view the auction details here: http://localhost:8000/auction/{listing.id}/
        
        Best regards,
        The BidVerse Team
        """
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [request.user.email],
                fail_silently=True
            )
        except Exception as e:
            print(f"Error sending confirmation email: {e}")
        
    return JsonResponse({'subscribed': subscribed})

@login_required
@membership_required
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
        
    # Check if auction is on break
    if listing.is_break_time:
        messages.error(request, "Bidding is paused during the break (1:30 PM - 2:15 PM). Resumes at 2:15 PM.")
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
    template_name = 'forgot-password.html'
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
            
            # MEMBERSHIP & FREE TRIAL LOGIC
            user_type_upper = user.user_type.upper() if user.user_type else ''
            if user_type_upper in ['BUYER', 'FARMER']:
                # 1. Check if they have an active membership
                has_active_membership = False
                if user.membership_expiry and user.membership_expiry > timezone.now():
                    has_active_membership = True
                
                # 2. If no membership, check trial status
                if not has_active_membership:
                    if not user.has_used_free_trial:
                        # First time login!
                        # Mark trial as used (so next time they must pay)
                        user.has_used_free_trial = True
                        user.save()
                        
                        # Set session variable for immediate access
                        request.session['is_free_trial_session'] = True
                        
                        # messages.success(request, "Welcome! You are using your one-time Free Trial session.")
                    else:
                        # Trial used AND no membership -> Redirect to Plans
                        messages.warning(request, "Your free trial has ended. Please purchase a membership to continue.")
                        return redirect('membership_plans')

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

    return render(request, "login.html", {})

@csrf_exempt
def payment_success(request):
    """
    Handle Razorpay payment success callback.
    """
    if request.method == "POST":
        try:
            payment_id = request.POST.get('razorpay_payment_id', '')
            razorpay_order_id = request.POST.get('razorpay_order_id', '')
            signature = request.POST.get('razorpay_signature', '')
            
            # Verify Signature (In production, uncomment verification)
            # params_dict = {
            #     'razorpay_order_id': razorpay_order_id,
            #     'razorpay_payment_id': payment_id,
            #     'razorpay_signature': signature
            # }
            # razorpay_client.utility.verify_payment_signature(params_dict)
            
            # Find the pending order
            order = Order.objects.get(razorpay_order_id=razorpay_order_id)
            
            # Update Status
            order.status = 'CONFIRMED'
            order.save()
            
            # Redirect to the summary/checkout page (which will now show order summary)
            return redirect('checkout_auction', listing_id=order.listing.id)
            
        except Order.DoesNotExist:
            print("Order not found for razorpay_id:", razorpay_order_id)
            return redirect('dashboard')
        except Exception as e:
            print("Payment Error:", str(e))
            return redirect('dashboard')
            
    return redirect('dashboard')

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
        address = request.POST.get("address")
        
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
        
        if address:
            user.address = address

        if usertype:
            user_role = usertype.upper()
            user.user_type = user_role
            
            # Handle ID Proof for Farmers
            if user_role == 'FARMER':
                if 'id_proof' in request.FILES:
                    user.id_proof = request.FILES['id_proof']
                
                # Save Business & Bank Details
                user.business_name = request.POST.get('business_name', '')
                user.pan_number = request.POST.get('pan_number', '')
                user.gstin = request.POST.get('gstin', '')
                user.bank_name = request.POST.get('bank_name', '')
                user.bank_account_number = request.POST.get('bank_account_number', '')
                user.bank_ifsc_code = request.POST.get('bank_ifsc_code', '')
                
                # Farmers are unverified by default until ID check
                user.is_verified = False
            else:
                # Buyers are verified by default for now (or email verification logic separately)
                user.is_verified = True

        user.set_password(password)
        try:
            user.full_clean()  # Validate before saving
            user.save()
            return redirect("/login/")
        except Exception as e:
             return render(request, "register.html", {"error": str(e)})

    return render(request, "register.html")


from .models import Order
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required

@login_required
def checkout_auction(request, listing_id):
    listing = get_object_or_404(Listing, id=listing_id)
    
    # Ensure current user is the winner
    highest_bid = listing.bids.order_by('-amount').first()
    if not highest_bid or highest_bid.buyer != request.user:
        return redirect('dashboard')
        
    # Check if order already exists
    if hasattr(listing, 'order'):
         return render(request, 'order_summary.html', {'order': listing.order})
    
    # Calculate Base Amount (Bid x Quantity)
    base_amount = listing.quantity * highest_bid.amount
    
    if request.method == 'POST':
        delivery_method = request.POST.get('delivery_method')
        shipping_address = request.POST.get('shipping_address')
        payment_method = request.POST.get('payment_method')

        # Calculate Shipping Charge
        shipping_amount = 0
        if delivery_method == 'DELIVERY':
            # Shipping Charge: 2 per unit
            shipping_amount = listing.quantity * 2
            
        total_amount = base_amount + shipping_amount
        
        if payment_method == 'ONLINE':
            # Create Razorpay Order
            currency = 'INR'
            amount = int(total_amount * 100) # Amount in paise
            
            try:
                razorpay_order = razorpay_client.order.create(dict(
                    amount=amount,
                    currency=currency,
                    payment_capture='1'
                ))
                razorpay_order_id = razorpay_order['id']
                
                # Create Order (PENDING)
                order = Order.objects.create(
                    listing=listing,
                    buyer=request.user,
                    delivery_method=delivery_method,
                    shipping_address=shipping_address,
                    payment_method=payment_method,
                    shipping_amount=shipping_amount,
                    total_amount=total_amount,
                    status='PENDING', # Pending payment
                    razorpay_order_id=razorpay_order_id
                )
                
                # Render the template again with Razorpay details
                return render(request, 'checkout_auction.html', {
                    'listing': listing,
                    'bid_amount': highest_bid.amount,
                    'quantity': listing.quantity,
                    'unit': listing.unit,
                    'base_amount': base_amount,
                    'user_address': request.user.address,
                    
                    # Razorpay Data
                    'razorpay_order_id': razorpay_order_id,
                    'razorpay_merchant_key': settings.RAZORPAY_KEY_ID,
                    'razorpay_amount': amount,
                    'currency': currency,
                    'callback_url': request.build_absolute_uri(reverse('payment_success')),
                    
                    # Context for pre-filling form if they cancel payment
                    'selected_delivery_method': delivery_method,
                    'shipping_address': shipping_address
                })
            except Exception as e:
                return render(request, 'checkout_auction.html', {
                    'listing': listing,
                    'bid_amount': highest_bid.amount,
                    'quantity': listing.quantity,
                    'unit': listing.unit,
                    'base_amount': base_amount,
                    'user_address': request.user.address,
                    'error': f"Error creating payment order: {str(e)}"
                })

        # COD Flow
        if payment_method == 'COD':
            # Create Order
            order = Order.objects.create(
                listing=listing,
                buyer=request.user,
                delivery_method=delivery_method,
                shipping_address=shipping_address,
                payment_method=payment_method,
                shipping_amount=shipping_amount,
                total_amount=total_amount,
                status='CONFIRMED' # Auto-confirm for now
            )
            # Redirect to summary
            return redirect('checkout_auction', listing_id=listing.id)

    return render(request, 'checkout_auction.html', {
        'listing': listing,
        'bid_amount': highest_bid.amount,
        'quantity': listing.quantity,
        'unit': listing.unit,
        'base_amount': base_amount, # Pass base amount for JS calculation
        'user_address': request.user.address
    })

    return render(request, 'checkout_auction.html', {
        'listing': listing,
        'bid_amount': highest_bid.amount,
        'user_address': request.user.address
    })

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
    
    # Robust Membership Check
    user = request.user
    user_type_upper = user.user_type.upper() if user.user_type else ''
    if user_type_upper in ['BUYER', 'FARMER']:
        has_active = user.membership_expiry and user.membership_expiry > timezone.now()
        is_trial_session = request.session.get('is_free_trial_session', False)
        
        # Logic: 
        # 1. If active membership: OK
        # 2. If NO membership:
        #    - If in valid trial session (session var set): OK
        #    - Else: BLOCK (Redirect to Plans)
        
        if not has_active and not is_trial_session:
            # Check edge case: Maybe they JUST used the trial but session var lost? 
            # (Unlikely in same session used by login, but covers 'Next Time')
            
            # Message and Redirect
            messages.warning(request, "Membership required. Your free trial has ended.")
            return redirect('membership_plans')

    # Auto-end expired auctions
    auto_end_expired_auctions()

    user_type = request.user.user_type
    section = request.GET.get('section', 'dashboard')
    context = {'user': request.user, 'section': section, 'now': timezone.now()}
    
    if user_type == 'FARMER':
        if request.method == 'POST' and section == 'add_listing':
            # --- FREE TRIAL ENFORCEMENT ---
            if request.session.get('is_free_trial_session', False):
                active_count = Listing.objects.filter(seller=request.user, is_active=True).count()
                if active_count >= 1:
                    messages.error(request, "Free Trial Limit Reached: You can only have 1 active listing. Please upgrade to a membership plan.")
                    return redirect('membership_plans')
            # ------------------------------

            # Get session selections
            morning_session = request.POST.get('morning_session') == 'on'
            evening_session = request.POST.get('evening_session') == 'on'
            
            # Validate at least one session is selected
            if not morning_session and not evening_session:
                messages.error(request, "Please select at least one session (Morning or Evening).")
                return redirect(reverse('dashboard') + '?section=add_listing')
            
            # Get selected dates (comma separated from Flatpickr)
            selected_dates_str = request.POST.get('listing_date')
            dates_to_create = []
            
            if selected_dates_str:
                # Split by comma and strip whitespace
                date_strings = [d.strip() for d in selected_dates_str.split(',')]
                for ds in date_strings:
                    try:
                        date_obj = datetime.strptime(ds, '%Y-%m-%d').date()
                        dates_to_create.append(date_obj)
                    except ValueError:
                        continue
            
            # If no valid dates found (or empty), allow fallback to today (or handle error)
            if not dates_to_create:
                 dates_to_create.append(timezone.now().date())

            # Create a listing for EACH selected date
            created_count = 0
            now = timezone.localtime(timezone.now())
            today = now.date()
            current_time = now.time()

            for selected_date in dates_to_create:
                # Validation: Cannot select a session that has already passed for TODAY
                if selected_date == today:
                    if morning_session and current_time > MORNING_END:
                         messages.error(request, "Cannot schedule for Morning Session today as it has already ended.")
                         return redirect(reverse('dashboard') + '?section=add_listing')
                    
                    if evening_session and current_time > EVENING_END:
                         messages.error(request, "Cannot schedule for Evening Session today as it has already ended.")
                         return redirect(reverse('dashboard') + '?section=add_listing')

                    # Also strict check: Cannot schedule for morning if morning START has passed? 
                    # User requested: "time already past mrng session now" -> implies it is over.
                    # If user means "Started", we should use MORNING_START.
                    # But sticking to END is safer to avoid blocking "Live" listings if that's a feature.
                    # Given the user says "time already past mrng session", and it is 16:37, it is definitely ENDED.

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
                    image=request.FILES.get('image'), # Note: Same image instance used for all
                    morning_session=morning_session,
                    evening_session=evening_session
                )
                created_count += 1
                
            # Message removed as per user request
            return redirect(reverse('dashboard') + '?section=listings')
        
        if section == 'listings':
            listings = Listing.objects.filter(seller=request.user)
            
            # Search
            search_query = request.GET.get('search')
            if search_query:
                listings = listings.filter(commodity__icontains=search_query)
            
            # Sort
            sort_param = request.GET.get('sort')
            if sort_param == 'newest':
                listings = listings.order_by('-created_at')
            elif sort_param == 'oldest':
                listings = listings.order_by('created_at')
            elif sort_param == 'price_high':
                 listings = listings.annotate(
                     price=Coalesce('current_highest_bid', 'base_price')
                 ).order_by('-price')
            elif sort_param == 'price_low':
                 listings = listings.annotate(
                     price=Coalesce('current_highest_bid', 'base_price')
                 ).order_by('price')
            elif sort_param == 'date_asc':
                listings = listings.order_by('end_time')
            elif sort_param == 'date_desc':
                listings = listings.order_by('-end_time')
            else:
                 listings = listings.order_by('-created_at')

            # Status Filter
            status_filter = request.GET.get('status')
            now = timezone.now()
            
            if status_filter:
                if status_filter == 'closed':
                    listings = listings.filter(Q(is_active=False) | Q(end_time__lt=now))
                elif status_filter == 'live':
                    listings = listings.filter(is_active=True, end_time__gte=now)
                    listings = [l for l in listings if l.start_time <= now]
                elif status_filter == 'upcoming':
                    listings = listings.filter(is_active=True, end_time__gte=now)
                    listings = [l for l in listings if l.start_time > now]
            
            context['listings'] = listings
        elif section == 'orders' or section == 'sales':
            # Sold items for farmer
            # Filter Orders where the listing's seller is the specific user
            context['orders'] = Order.objects.filter(listing__seller=request.user).order_by('-created_at')
        elif section == 'unclaimed':
            # Sold but not claimed (no Order object)
            # Must be inactive, have a bid (winner), and no associated order
            context['unclaimed_listings'] = Listing.objects.filter(
                seller=request.user, 
                is_active=False, 
                order__isnull=True,
                current_highest_bid__isnull=False
            ).order_by('-end_time')
        elif section == 'dashboard':
            context['active_listings_count'] = Listing.objects.filter(seller=request.user, is_active=True).count()
            context['items_sold'] = Listing.objects.filter(seller=request.user, is_active=False).count()
            
            # Correct Revenue Calculation: Sum of CONFIRMED or COMPLETED orders
            confirmed_orders = Order.objects.filter(
                listing__seller=request.user,
                status__in=['CONFIRMED', 'COMPLETED']
            )
            context['total_revenue'] = sum(o.total_amount for o in confirmed_orders)
            
            context['live_listings'] = Listing.objects.filter(seller=request.user, is_active=True).order_by('-created_at')[:5]
            
            # Graph Data for Farmer: Last 7 days listings created
            days = []
            morning_counts = []
            evening_counts = []
            farmer_listings = Listing.objects.filter(seller=request.user)
            
            for i in range(6, -1, -1):
                date = (timezone.now() - timedelta(days=i)).date()
                days.append(date.strftime('%b %d'))
                
                # Filter listings created on this day
                day_listings = farmer_listings.filter(created_at__date=date)
                
                m_count = day_listings.filter(morning_session=True).count()
                e_count = day_listings.filter(evening_session=True).count()
                
                morning_counts.append(m_count)
                evening_counts.append(e_count)
            
            context['graph_labels'] = days
            context['graph_morning'] = morning_counts
            context['graph_evening'] = evening_counts
        
        return render(request, "dashboard/seller.html", context)
        
    elif user_type == 'BUYER':
        user_bids = Bid.objects.filter(buyer=request.user)
        
        if section == 'bids':
            context['bids'] = user_bids.order_by('-timestamp')
        elif section == 'won':
            # Correct logic: Valid winners only
            candidates = Listing.objects.filter(
                is_active=False,
                bids__buyer=request.user
            ).distinct().order_by('-end_time')
            
            won_items = []
            for l in candidates:
                # Check if highest bid belongs to current user
                highest = l.bids.order_by('-amount', 'timestamp').first()
                if highest and highest.buyer == request.user:
                    # Check if order exists (using OneToOne reverse relation check)
                    l.has_order = Order.objects.filter(listing=l).exists()
                    won_items.append(l)
            
            context['won_listings'] = won_items
        elif section == 'orders':
            context['orders'] = Order.objects.filter(buyer=request.user).order_by('-created_at')
        elif section == 'dashboard':
            context['active_bids_count'] = user_bids.filter(listing__is_active=True).values('listing').distinct().count()
            context['won_auctions_count'] = Listing.objects.filter(is_active=False, bids__buyer=request.user).distinct().count()
            context['recent_bids'] = user_bids.order_by('-timestamp')[:5]
            
            # Graph Data for Buyer: Last 7 days bids count
            days = []
            morning_counts = []
            evening_counts = []
            for i in range(6, -1, -1):
                date = (timezone.now() - timedelta(days=i)).date()
                days.append(date.strftime('%b %d'))
                
                # Filter bids for this user on this day
                day_bids = user_bids.filter(timestamp__date=date)
                
                # Count by session time
                m_count = 0
                e_count = 0
                for b in day_bids:
                    t = timezone.localtime(b.timestamp).time()
                    if MORNING_START <= t < MORNING_END:
                        m_count += 1
                    elif EVENING_START <= t <= EVENING_END:
                        e_count += 1
                    else:
                        # Fallback to listing session if outside strict times but on that day
                        if b.listing.morning_session: m_count += 1
                        elif b.listing.evening_session: e_count += 1
                
                morning_counts.append(m_count)
                evening_counts.append(e_count)
            
            context['graph_labels'] = days
            context['graph_morning'] = morning_counts
            context['graph_evening'] = evening_counts
        
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
            
            # Graph Data for Admin: Platform wide bids count
            days = []
            morning_counts = []
            evening_counts = []
            all_bids = Bid.objects.all()
            for i in range(6, -1, -1):
                date = (timezone.now() - timedelta(days=i)).date()
                days.append(date.strftime('%b %d'))
                
                day_bids = all_bids.filter(timestamp__date=date)
                m_count = 0
                e_count = 0
                for b in day_bids:
                    t = timezone.localtime(b.timestamp).time()
                    if MORNING_START <= t < MORNING_END:
                        m_count += 1
                    elif EVENING_START <= t <= EVENING_END:
                        e_count += 1
                    else:
                        if b.listing.morning_session: m_count += 1
                        elif b.listing.evening_session: e_count += 1

                morning_counts.append(m_count)
                evening_counts.append(e_count)
            
            context['graph_labels'] = days
            context['graph_morning'] = morning_counts
            context['graph_evening'] = evening_counts
        elif section == 'users':
            context['all_users'] = User.objects.all().order_by('-date_joined')
        elif section == 'auctions':
            listings = Listing.objects.all()
            
            # Search
            search_query = request.GET.get('search')
            if search_query:
                listings = listings.filter(
                    Q(commodity__icontains=search_query) | 
                    Q(seller__email__icontains=search_query)
                )
            
            # Sort
            sort_param = request.GET.get('sort')
            if sort_param == 'newest':
                listings = listings.order_by('-created_at')
            elif sort_param == 'oldest':
                listings = listings.order_by('created_at')
            elif sort_param == 'price_high':
                 listings = listings.annotate(
                     price=Coalesce('current_highest_bid', 'base_price')
                 ).order_by('-price')
            elif sort_param == 'price_low':
                 listings = listings.annotate(
                     price=Coalesce('current_highest_bid', 'base_price')
                 ).order_by('price')
            elif sort_param == 'date_asc':
                listings = listings.order_by('end_time')
            elif sort_param == 'date_desc':
                listings = listings.order_by('-end_time')
            else:
                 listings = listings.order_by('-created_at') # Default

            # Status Filter 
            status_filter = request.GET.get('status')
            now = timezone.now()
            
            if status_filter:
                if status_filter == 'closed':
                    listings = listings.filter(Q(is_active=False) | Q(end_time__lt=now))
                elif status_filter == 'live':
                    listings = listings.filter(is_active=True, end_time__gte=now)
                    # Filter start_time <= now in python
                    listings = [l for l in listings if l.start_time <= now]
                elif status_filter == 'upcoming':
                    listings = listings.filter(is_active=True, end_time__gte=now)
                    # Filter start_time > now in python
                    listings = [l for l in listings if l.start_time > now]
            
            context['all_listings'] = listings
        elif section == 'notifications':
             context['all_users'] = User.objects.all().order_by('email')
            
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

# New: Buyer notifications view (JSON)
@login_required
def notifications(request):
    notifs = request.user.notifications.order_by('-created_at').values('id', 'message', 'created_at', 'is_read')
    return JsonResponse(list(notifs), safe=False)

# Mark a notification as read
@login_required
def mark_notification_read(request, notif_id):
    # Use filter().update() for efficiency and to avoid 404 if already deleted/read issues happen
    updated = Notification.objects.filter(id=notif_id, receiver=request.user).update(is_read=True)
    
    if updated:
        return JsonResponse({'success': True})
    else:
        return JsonResponse({'error': 'Notification not found or access denied.'}, status=404)

# Admin: send notification form handling
@login_required
def send_notification(request):
    if request.user.user_type != 'ADMIN':
        messages.error(request, 'Only admins can send notifications.')
        return redirect('dashboard')
        
    if request.method == 'POST':
        message = request.POST.get('message')
        target = request.POST.get('target')  # 'all' or user id
        
        if not message:
            messages.error(request, 'Message cannot be empty.')
            return redirect(reverse('dashboard') + '?section=notifications')
            
        if target == 'all':
            buyers = User.objects.filter(user_type='BUYER')
            count = 0
            for buyer in buyers:
                Notification.objects.create(receiver=buyer, message=message)
                count += 1
            messages.success(request, f'Notification sent to {count} buyers.')
            
        else:
            try:
                buyer = User.objects.get(id=int(target), user_type='BUYER')
                Notification.objects.create(receiver=buyer, message=message)
                messages.success(request, f'Notification sent to {buyer.email}.')
            except (User.DoesNotExist, ValueError):
                messages.error(request, 'Selected buyer does not exist.')
        
        return redirect(reverse('dashboard') + '?section=notifications')
    
    return redirect('dashboard')

@login_required
def membership_plans(request):
    """View to show membership plans"""
    return render(request, 'membership_plans.html')

import razorpay
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt

@login_required
def purchase_membership(request, plan_type):
    """Create Razorpay Order and Render Checkout (Handles Mock Mode)"""
    user = request.user
    
    # Determine Amount (in Rupees)
    if plan_type == 'yearly':
        amount = 4999
    else:
        amount = 499
        
    amount_paise = amount * 100 # Razorpay takes amount in paise
    
    # Create Razorpay Client
    # NOTE: If keys are invalid/placeholder, this client creation works, but order.create will fail or client-side checkout will fail.
    # We allow this to proceed so the user sees the 'Real' integration attempt.
    
    if not settings.RAZORPAY_KEY_ID or not settings.RAZORPAY_KEY_SECRET:
         messages.error(request, "Razorpay Keys are missing in .env! Please add them.")
         return redirect('membership_plans')

    client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
    
    # Create Order
    try:
        data = {"amount": amount_paise, "currency": "INR", "payment_capture": "1"}
        payment = client.order.create(data=data)
        print(f"SUCCESS: Razorpay Order Created! ID: {payment['id']}")
    except Exception as e:
        print(f"Razorpay Error: {e}")
        # If order creation fails (e.g. invalid keys), we can't show checkout.
        messages.error(request, f"Payment Gateway Error: Invalid API Key or Network Issue. (Error: {str(e)})")
        return redirect('membership_plans')
    
    context = {
        'plan_type': plan_type,
        'amount': amount,
        'order_amount': amount_paise,
        'currency': 'INR',
        'order_id': payment['id'],
        'api_key': settings.RAZORPAY_KEY_ID,
        'mock_payment': False,
    }
    
    return render(request, 'payment_checkout.html', context)

@csrf_exempt
@login_required
def payment_success(request):
    """Verify Payment Signature and Activate Membership OR Confirm Auction Order"""
    
    # Check both POST (Razorpay) and GET (Mock/Manual)
    data = request.POST if request.method == 'POST' else request.GET
    
    # 1. Check if this is a Membership Payment
    plan_type = data.get('plan_type')
    is_mock = data.get('mock_payment') == 'true'
    
    razorpay_payment_id = data.get('razorpay_payment_id')
    razorpay_order_id = data.get('razorpay_order_id')
    razorpay_signature = data.get('razorpay_signature')

    if plan_type:
        if not is_mock:
            # REAL VERIFICATION
            client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
            
            params_dict = {
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': razorpay_payment_id,
                'razorpay_signature': razorpay_signature
            }
            
            try:
                client.utility.verify_payment_signature(params_dict)
            except razorpay.errors.SignatureVerificationError:
                messages.error(request, "Payment Verification Failed.")
                return redirect('membership_plans')
            except Exception:
                messages.error(request, "Payment Error.")
                return redirect('membership_plans')
                
        # --- SUCCESS LOGIC (Shared) ---
        user = request.user
        duration = 365 if plan_type == 'yearly' else 30
        
        # Update User
        user.membership_expiry = timezone.now() + timedelta(days=duration)
        user.has_used_free_trial = True
        user.membership_type = 'YEARLY' if plan_type == 'yearly' else 'MONTHLY'
        user.save()
        
        context = {
            'plan_type': plan_type,
            'expiry': user.membership_expiry
        }
        return render(request, 'payment_success.html', context)

    # 2. Check if this is an Auction Order Payment
    elif razorpay_order_id:
        try:
            # Find the order by Razorpay Order ID
            order = Order.objects.get(razorpay_order_id=razorpay_order_id)
        except Order.DoesNotExist:
            messages.error(request, "Order not found.")
            return redirect('dashboard')

        if not is_mock:
            client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
            params_dict = {
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': razorpay_payment_id,
                'razorpay_signature': razorpay_signature
            }
            try:
                client.utility.verify_payment_signature(params_dict)
            except Exception:
                messages.error(request, "Payment Verification Failed for Order.")
                return redirect('checkout_auction', listing_id=order.listing.id)
        
        # Success: Confirm the Order
        order.status = 'CONFIRMED'
        order.save()
        
        messages.success(request, f"Payment Successful! Order for {order.listing.commodity} confirmed.")
        # Redirect to Buyer Dashboard -> Orders section
        return redirect(reverse('dashboard') + '?section=orders')

    # Fallback
    return redirect('dashboard')
@csrf_exempt
def chatbot_response(request):
    if request.method == 'POST':
        try:
            import json
            data = json.loads(request.body)
            user_msg = data.get('message', '').lower()
            
            user = request.user
            role = "Support"
            if user.is_authenticated:
                if user.user_type == 'BUYER':
                    role = "Buyer"
                elif user.user_type == 'FARMER':
                    role = "Farmer"
                elif user.is_superuser or user.user_type == 'ADMIN':
                    role = "Admin"
            
            # Get Auction Session Info
            from .utils import get_current_session_info
            session_info = get_current_session_info()
            session_name = session_info['session'].capitalize()
            
            # Basic contextual logic
            response_text = ""
            if "hello" in user_msg or "hi" in user_msg:
                response_text = f"Hello! As your {role} assistant, I'm here to help. Currently, we are in the **{session_name}** auction session."
            
            elif "session" in user_msg or "time" in user_msg:
                if session_info['session'] == 'break':
                    response_text = f"We are currently on a **Break**. The next session (Evening) starts at {session_info['next_session_start'].strftime('%I:%M %p')}."
                elif session_info['is_active']:
                    response_text = f"The active session is **{session_name}**. It will end at {session_info['end_time'].strftime('%I:%M %p')}."
                else:
                    response_text = f"The sessions are currently **Closed**. The next session starts tomorrow at {session_info['next_session_start'].strftime('%I:%M %p')}."
            
            elif ("list" in user_msg or "who" in user_msg) and ("user" in user_msg or "member" in user_msg or "active" in user_msg):
                if role == "Admin":
                    from django.contrib.sessions.models import Session
                    # This is a naive way to find "logged in" users in local dev
                    # In production, you'd use a more robust way or check recently active
                    from django.utils import timezone
                    active_users = User.objects.filter(last_login__gte=timezone.now() - timezone.timedelta(hours=1))
                    if active_users.exists():
                        user_list = ", ".join([u.email for u in active_users])
                        response_text = f"There are {active_users.count()} users active in the last hour: {user_list}."
                    else:
                        response_text = "No users have logged in recently."
                else:
                    response_text = "Access Denied. Only administrators can list active users."

            elif "bid" in user_msg or "auction" in user_msg:
                if role == "Buyer":
                    response_text = "To place a bid, navigate to any live auction in the Marketplace and enter an amount higher than the current bid."
                elif role == "Farmer":
                    response_text = "Your active listings are shown on your Dashboard. You'll receive notifications when new bids are placed."
                else:
                    response_text = "Auctions are the heart of BidVerse. Buyers use them to purchase fresh commodities directly from farmers."
            
            elif "membership" in user_msg or "plan" in user_msg:
                response_text = "We offer various membership plans including Free Trial, Monthly, and Yearly. Check the Membership section for details."
            
            elif "contact" in user_msg or "support" in user_msg:
                response_text = "You can reach our support team via the Contact page or by emailing support@bidverse.com."
            
            else:
                response_text = f"I'm the {role} assistant. I can help you with auction sessions, bidding rules, or account management. Currently, the {session_name} session is underway."
                
            return JsonResponse({'response': response_text})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Invalid request'}, status=405)

@login_required
def send_reminder_email(request, listing_id):
    """
    Send a reminder email to the winner of a listing.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid method'}, status=405)
        
    listing = get_object_or_404(Listing, id=listing_id)
    
    # Ensure the requester is the seller
    if listing.seller != request.user:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
        
    # Get the winner
    highest_bid = listing.bids.order_by('-amount').first()
    if not highest_bid:
        return JsonResponse({'error': 'No winner found'}, status=404)
        
    winner = highest_bid.buyer
    
    # Send Email
    subject = f"Reminder: Claim your won auction - {listing.commodity}"
    message = f"""
    Hi {winner.first_name},
    
    This is a reminder from the seller regarding your won auction:
    
    Item: {listing.commodity}
    Winning Bid: ₹{highest_bid.amount}
    
    Please assume responsibility for the collection/delivery of your item as soon as possible.
    
    Regards,
    {listing.seller.get_full_name() or listing.seller.email}
    """
    
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [winner.email],
            fail_silently=False
        )
        return JsonResponse({'success': True, 'message': 'Reminder sent successfully'})
    except Exception as e:
        print(f"Error sending reminder: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def settings_view(request):
    """
    View to handle User Settings and Profile Update.
    """
    from .forms import UserProfileForm # Local import to avoid circular dependency if any

    if request.method == 'POST':
        form = UserProfileForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your profile has been updated successfully.')
            return redirect('settings')
        else:
            print("Settings Form Errors:", form.errors)
            messages.error(request, 'Please correct the errors below.')
    else:
        form = UserProfileForm(instance=request.user)
    
    return render(request, 'settings.html', {'form': form})

@csrf_exempt
def chatbot_message(request):
    """
    Handle Chatbot Messages.
    Returns a JSON response based on keywords and user role.
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_msg = data.get('message', '').lower()
            
            user = request.user
            role = "Guest"
            if user.is_authenticated:
                if user.user_type == 'BUYER':
                    role = "Buyer"
                elif user.user_type == 'FARMER':
                    role = "Farmer"
                elif user.is_superuser or user.user_type == 'ADMIN':
                    role = "Admin"
            
            # --- Logic ---
            response_text = ""

            # 1. Greetings
            if any(x in user_msg for x in ['hi', 'hello', 'hey']):
                response_text = f"Hello! I am your {role} Assistant. How can I help you today?"

            # 2. General Help
            elif any(x in user_msg for x in ['help', 'support', 'contact']):
                response_text = "You can contact support at **support@bidverse.com** or call us at **+91 98765 43210**. We are available 24/7."

            # 3. Auctions / Bidding (Buyer/Guest focus)
            elif any(x in user_msg for x in ['auction', 'bid', 'buy']):
                if role == "Farmer":
                    response_text = "As a **Farmer**, you can currently **list items** for auction. Switch to a Buyer account to place bids."
                else:
                    response_text = "To place a bid, go to the **Auctions** page, select an item, and enter your amount. Ensure you have a valid account."

            # 4. Selling / Listing (Farmer focus)
            elif any(x in user_msg for x in ['sell', 'list', 'farmer']):
                if role == "Buyer":
                    response_text = "As a **Buyer**, you can bid on items. To sell crops, please register as a **Farmer**."
                elif role == "Guest":
                    response_text = "To sell your produce, please **Register** as a Farmer first."
                else:
                    response_text = "To sell, go to your **Dashboard** and click **'Add Listing'**. You can set the quantity, unit, and base price."

            # 5. Pricing / Commission
            elif any(x in user_msg for x in ['price', 'cost', 'fee', 'commission']):
                response_text = "BidVerse charges a minimal platform fee on successful auctions. Registration is free for everyone!"

            # 6. Default Fallback
            else:
                response_text = "I'm sorry, I didn't quite catch that. Try asking about **auctions**, **selling**, or **support**."

            return JsonResponse({'response': response_text})

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=400)
