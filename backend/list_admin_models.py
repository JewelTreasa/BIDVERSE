import os
import django
import sys

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from django.contrib import admin

with open('admin_models_list.txt', 'w') as f:
    f.write("--- Registered Models ---\n")
    registry = admin.site._registry
    for model, model_admin in registry.items():
        f.write(f"{model.__name__} (Admin: {model_admin.__class__.__name__})\n")
    f.write(f"Total: {len(registry)}\n")

print("Done writing to admin_models_list.txt")
