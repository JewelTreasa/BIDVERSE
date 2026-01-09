#!/usr/bin/env python
"""
Test if the profile dropdown appears when user is authenticated
"""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Create a session to maintain cookies
session = requests.Session()

# Configure retry strategy
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

print("Step 1: Getting login page to get CSRF token...")
login_page = session.get('http://127.0.0.1:8000/login/')
print(f"Login page status: {login_page.status_code}")

# Extract CSRF token from cookies or form
csrf_token = session.cookies.get('csrftoken')
if not csrf_token:
    # Try to get from form
    import re
    csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', login_page.text)
    if csrf_match:
        csrf_token = csrf_match.group(1)

print(f"CSRF token: {csrf_token[:20] if csrf_token else 'NOT FOUND'}...")

print("\nStep 2: Attempting login...")
login_data = {
    'email': 'test@example.com',
    'password': 'password123',
    'csrfmiddlewaretoken': csrf_token
}
login_response = session.post('http://127.0.0.1:8000/login/', data=login_data, allow_redirects=False)
print(f"Login response status: {login_response.status_code}")
print(f"Location header: {login_response.headers.get('Location', 'None')}")

print("\nStep 3: Getting home page after login...")
home_response = session.get('http://127.0.0.1:8000/')
content = home_response.text

print(f"Home page status: {home_response.status_code}")
print(f"Contains 'profile-dropdown': {'profile-dropdown' in content}")
print(f"Contains 'fa-user-circle': {'fa-user-circle' in content}")
print(f"Contains 'Log In': {'Log In' in content}")
print(f"Contains 'Dashboard': {'Dashboard' in content}")

# Check nav-buttons section
import re
nav_match = re.search(r'<div class="nav-buttons">(.*?)</div>', content, re.DOTALL)
if nav_match:
    nav_content = nav_match.group(1)
    print(f"\nNav-buttons content preview:")
    print(nav_content.strip()[:200])
