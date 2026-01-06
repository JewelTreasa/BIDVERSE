from django.contrib import admin
from .models import User

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'first_name', 'last_name', 'user_type', 'phone', 'is_staff')
    list_filter = ('user_type', 'is_staff')
    search_fields = ('email', 'first_name', 'last_name')
