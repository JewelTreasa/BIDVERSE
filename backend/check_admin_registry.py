import os
import django
from django.conf import settings

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from django.contrib import admin
from accounts.models import User, Listing, Bid, Order, Notification

print("--- Checking Admin Registry ---")
registry = admin.site._registry

models_to_check = [User, Listing, Bid, Order, Notification]

all_registered = True
for model in models_to_check:
    if model in registry:
        print(f"[OK] {model.__name__} is registered.")
    else:
        print(f"[FAIL] {model.__name__} is NOT registered.")
        all_registered = False

if all_registered:
    print("\nSUCCESS: All models are registered.")
else:
    print("\nFAILURE: Some models are missing from admin.")

print(f"\nTotal registered models: {len(registry)}")
