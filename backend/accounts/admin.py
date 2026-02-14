from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Listing, Bid, NotificationSubscription, Notification, Order

class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'user_type', 'is_verified', 'phone', 'is_staff')
    list_filter = ('user_type', 'is_verified', 'is_staff', 'is_superuser', 'groups')
    search_fields = ('username', 'email', 'phone')
    ordering = ('email',)
    
    fieldsets = UserAdmin.fieldsets + (
        ('Custom Fields', {'fields': ('phone', 'user_type', 'is_verified', 'address', 'id_proof', 'membership_type', 'membership_expiry', 'has_used_free_trial')}),
    )

class ListingAdmin(admin.ModelAdmin):
    list_display = ('commodity', 'seller', 'base_price', 'current_highest_bid', 'end_time', 'is_active')
    list_filter = ('is_active', 'commodity', 'morning_session', 'evening_session')
    search_fields = ('commodity', 'seller__email', 'description')

class BidAdmin(admin.ModelAdmin):
    list_display = ('listing', 'buyer', 'amount', 'timestamp')
    list_filter = ('timestamp',)
    search_fields = ('listing__commodity', 'buyer__email')

class OrderAdmin(admin.ModelAdmin):
    list_display = ('id', 'listing', 'buyer', 'status', 'created_at')
    list_filter = ('status', 'delivery_method')
    search_fields = ('listing__commodity', 'buyer__email')

class NotificationAdmin(admin.ModelAdmin):
    list_display = ('receiver', 'message', 'notification_type', 'is_read', 'created_at')
    list_filter = ('is_read', 'notification_type')
    search_fields = ('receiver__email', 'message')

admin.site.register(User, CustomUserAdmin)
admin.site.register(Listing, ListingAdmin)
admin.site.register(Bid, BidAdmin)
admin.site.register(NotificationSubscription)
admin.site.register(Notification, NotificationAdmin)
admin.site.register(Order, OrderAdmin)
