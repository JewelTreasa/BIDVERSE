#!/usr/bin/env python
import os

def test_register_page_google_integration():
    """Test that register.html includes Google OAuth integration"""
    print("Testing Register Page Google OAuth Integration")
    print("=" * 50)

    # Check if register.html exists
    register_path = os.path.join(os.path.dirname(__file__), '..', 'register.html')
    if not os.path.exists(register_path):
        print("ERROR: register.html not found")
        return False

    with open(register_path, 'r', encoding='utf-8') as f:
        content = f.read()

    checks = [
        ('Google Identity Services script', 'accounts.google.com/gsi/client'),
        ('Google onload div', 'g_id_onload'),
        ('Google signin div', 'g_id_signin'),
        ('Google signup text', 'signup_with'),
        ('Config script', 'assets/js/config.js'),
        ('Google callback function', 'handleGoogleSignUp'),
        ('Client ID initialization', 'data-client_id'),
    ]

    all_passed = True
    for check_name, check_content in checks:
        if check_content in content:
            print(f"[PASS] {check_name}: FOUND")
        else:
            print(f"[FAIL] {check_name}: MISSING")
            all_passed = False

    print("\n" + "=" * 50)
    if all_passed:
        print("SUCCESS: Google OAuth integration is properly implemented in register.html")
        print("\nNext Steps:")
        print("1. Set your Google OAuth client ID in assets/js/config.js")
        print("2. Test with a real Google account")
        print("3. Verify user creation flow works correctly")
    else:
        print("ERROR: Some Google OAuth components are missing from register.html")

    return all_passed

if __name__ == '__main__':
    test_register_page_google_integration()
