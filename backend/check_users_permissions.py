import os
import django
import sys

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from accounts.models import User

print("--- User Permissions Check ---")
users = User.objects.all()
for u in users:
    print(f"User: {u.email} | Staff: {u.is_staff} | Superuser: {u.is_superuser} | Active: {u.is_active}")

print(f"Total Users: {users.count()}")
