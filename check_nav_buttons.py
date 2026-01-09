#!/usr/bin/env python
"""
Check what's in the nav-buttons section
"""
import requests
import re

response = requests.get('http://127.0.0.1:8000/')
content = response.text

# Find the nav-buttons section
nav_buttons_match = re.search(r'<div class="nav-buttons">(.*?)</div>', content, re.DOTALL)
if nav_buttons_match:
    nav_content = nav_buttons_match.group(1)
    print('nav-buttons content:')
    print(nav_content.strip())
    print()

    # Check what buttons are present
    if 'Log In' in nav_content:
        print('Found: Log In button')
    if 'Get Started' in nav_content:
        print('Found: Get Started button')
    if 'profile-dropdown' in nav_content:
        print('Found: profile-dropdown')
    if 'fa-user-circle' in nav_content:
        print('Found: fa-user-circle icon')
else:
    print('nav-buttons section not found')
