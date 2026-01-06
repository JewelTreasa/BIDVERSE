import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'bidverse.settings'
import django
django.setup()

from django.contrib.auth.password_validation import validate_password
from accounts.models import User

print('=== PASSWORD VALIDATION TEST ===')

# Test passwords that would previously fail
test_passwords = [
    'jewel123',      # Similar to first name 'Jewel'
    'password123',   # Common password
    'testpass',      # Short password
    'MySecurePass123',  # Good password
    'bidverse2024',  # Contains username-like text
]

for password in test_passwords:
    try:
        # Get a test user with first name that might cause issues
        user = User(username='testuser', first_name='Jewel', email='test@example.com')
        validate_password(password, user)
        print(f'✓ Password "{password}" is VALID')
    except Exception as e:
        print(f'✗ Password "{password}" FAILED: {e}')

print('\n=== CURRENT VALIDATORS ===')
from django.conf import settings
for validator in settings.AUTH_PASSWORD_VALIDATORS:
    print(f'- {validator["NAME"]}')
