from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import datetime, time

class User(AbstractUser):
    USER_TYPE_CHOICES = (
        ('FARMER', 'Farmer (seller)'),
        ('BUYER', 'Buyer'),
        ('ADMIN', 'Admin'),
    )

    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15, unique=True, null=True, blank=True)
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES, default='BUYER')
    is_verified = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'phone']

    def __str__(self):
        return self.email

class Listing(models.Model):
    COMMODITY_CHOICES = (
        ('RICE', 'Basmati Rice'),
        ('WHEAT', 'Premium Wheat'),
        ('TOMATO', 'Fresh Tomatoes'),
        ('PULSE', 'Organic Pulses'),
    )
    
    seller = models.ForeignKey(User, on_delete=models.CASCADE, related_name='listings')
    commodity = models.CharField(max_length=100)
    quantity = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    unit = models.CharField(max_length=20, default='kg') # kg, quintal, ton, etc.
    base_price = models.DecimalField(max_digits=10, decimal_places=2)
    current_highest_bid = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    end_time = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    description = models.TextField(blank=True)
    image = models.FileField(upload_to='listings/', blank=True, null=True)
    image_url = models.URLField(blank=True, null=True)
    morning_session = models.BooleanField(default=False)
    evening_session = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    # New field to track if notification has been sent
    notification_sent = models.BooleanField(default=False)

    @property
    def start_time(self):
        # Session start times matching views.py
        MORNING_START = time(9, 30)
        EVENING_START = time(14, 15)
        
        start_t = MORNING_START # Default
        
        if self.morning_session and self.evening_session:
            start_t = MORNING_START
        elif self.morning_session:
            start_t = MORNING_START
        elif self.evening_session:
            start_t = EVENING_START
            
        # Combine with local end_time date
        listing_date = timezone.localtime(self.end_time).date()
        st = datetime.combine(listing_date, start_t)
        
        # Always use project timezone for start times
        tz = timezone.get_current_timezone()
        return timezone.make_aware(st, tz)

    @property
    def display_price(self):
        """Returns the current highest bid or base price as a whole number string."""
        price = self.current_highest_bid if self.current_highest_bid else self.base_price
        return f"{int(price)}"

    @property
    def display_label(self):
        """Returns 'Current Bid' if live, otherwise 'Base Price'."""
        return "Current Bid" if self.start_time <= timezone.now() else "Base Price"

    @property
    def time_label(self):
        """Returns 'Ends At' if live, otherwise 'Starts At'."""
        return "Ends At" if self.start_time <= timezone.now() else "Starts At"

    @property
    def display_time(self):
        """Returns formatted local end_time if live, otherwise start_time."""
        target_time = self.end_time if self.start_time <= timezone.now() else self.start_time
        return timezone.localtime(target_time).strftime("%I:%M %p")

    @property
    def display_image(self):
        """Returns the appropriate image path based on commodity name."""
        if self.image:
            return self.image.url
        if self.image_url:
            return self.image_url
            
        name = self.commodity.lower()
        if 'potato' in name:
            return '/assets/images/potato.png'
        elif 'onion' in name:
            return '/assets/images/onion.png'
        elif 'tomato' in name:
            return '/assets/images/tomato.png'
        elif 'rice' in name:
            return '/assets/images/rice.jpg'
        elif 'premium' in name and 'wheat' in name:
            return '/assets/images/premium_wheat.png'
        elif 'wheat' in name:
            return '/assets/images/wheat.jpg'
        return '/assets/images/placeholder-agri.jpg'

    @property
    def clean_description(self):
        """Returns a sanitized description or a default message."""
        if not self.description:
            return "No description provided for this agricultural commodity."
        return self.description.strip()

    def __str__(self):
        return f"{self.commodity} by {self.seller.email}"

class Bid(models.Model):
    listing = models.ForeignKey(Listing, on_delete=models.CASCADE, related_name='bids')
    buyer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='bids')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.amount} for {self.listing.commodity}"

class NotificationSubscription(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='subscriptions')
    listing = models.ForeignKey(Listing, on_delete=models.CASCADE, related_name='subscriptions')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'listing')

    def __str__(self):
        return f"{self.user.email} -> {self.listing.commodity}"
