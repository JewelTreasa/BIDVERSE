#!/usr/bin/env python
import requests
import re

session = requests.Session()

# Get login page
login_page = session.get('http://127.0.0.1:8000/login/')
csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', login_page.text)
csrf_token = csrf_match.group(1) if csrf_match else ''

# Login
login_data = {
    'email': 'test@example.com',
    'password': 'password123',
    'csrfmiddlewaretoken': csrf_token
}
login_resp = session.post('http://127.0.0.1:8000/login/', data=login_data, allow_redirects=False)
print(f'Login status: {login_resp.status_code}')
print(f'Redirect location: {login_resp.headers.get("Location", "None")}')

# Get home page
home_resp = session.get('http://127.0.0.1:8000/')
content = home_resp.text

print(f'\nHome page check:')
print(f'Has profile-dropdown: {"profile-dropdown" in content}')
print(f'Has fa-user-circle: {"fa-user-circle" in content}')
print(f'Has Log In button: {"Log In" in content and "btn-outline" in content}')
print(f'Has user.is_authenticated check: {"user.is_authenticated" in content}')

# Check nav-buttons
nav_match = re.search(r'<div class="nav-buttons">(.*?)</div>', content, re.DOTALL)
if nav_match:
    nav_content = nav_match.group(1)
    print(f'\nNav-buttons contains:')
    if 'profile-dropdown' in nav_content:
        print('  - profile-dropdown')
    if 'Log In' in nav_content:
        print('  - Log In button')
