import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bidverse.settings')
django.setup()

from django.contrib.auth import get_user_model
User = get_user_model()

email = 'admin@example.com'
password = 'admin123'

if not User.objects.filter(email=email).exists():
    User.objects.create_superuser(
        username=email,
        email=email,
        password=password,
        phone='0000000000',
        user_type='ADMIN'
    )
    print(f'Superuser {email} created successfully.')
else:
    print(f'Superuser {email} already exists.')
