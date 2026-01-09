#!/usr/bin/env python
"""
Test script to check what's being served on the home page
"""
import requests

try:
    response = requests.get('http://127.0.0.1:8000/')
    content = response.text
    print('Page loaded successfully')
    print('Status code:', response.status_code)
    print('Contains "Log In":', 'Log In' in content)
    print('Contains "profile-dropdown":', 'profile-dropdown' in content)
    print('Contains "fa-user-circle":', 'fa-user-circle' in content)
    print('Contains "user.is_authenticated":', 'user.is_authenticated' in content)

    # Check if the template is being processed (Django template tags should be gone)
    if '{%' in content or '{{' in content:
        print('WARNING: Django template tags found - template not processed!')
    else:
        print('Template appears to be processed correctly')

except Exception as e:
    print('Error:', e)
