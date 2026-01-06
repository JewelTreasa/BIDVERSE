import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from django.contrib.auth import get_user_model
User = get_user_model()
u = User.objects.get(username='admin@example.com')
u.set_password('admin123')
u.save()
print('Password set successfully')
