#!/usr/bin/env python
import requests
import json

def test_login_api():
    url = 'http://127.0.0.1:8000/api/auth/login/'
    data = {
        'email': 'admin@example.com',
        'password': 'admin123'
    }

    try:
        response = requests.post(url, json=data)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")

        if response.status_code == 200:
            print("SUCCESS: Login API working")
            response_data = response.json()
            print(f"User: {response_data.get('email')}")
            print(f"User Type: {response_data.get('user_type')}")
            print(f"Access Token: {'Present' if response_data.get('access') else 'Missing'}")
        else:
            print("FAILED: Login API failed")

    except requests.exceptions.ConnectionError:
        print("FAILED: Cannot connect to server. Is Django running?")
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == '__main__':
    test_login_api()
