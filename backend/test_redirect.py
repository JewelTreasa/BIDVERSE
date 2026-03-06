import requests

def test_redirects():
    s = requests.Session()
    print("Testing /dashboard/ for unauthenticated user...")
    r = s.get('http://127.0.0.1:8000/dashboard/', allow_redirects=False)
    print(f"Status Code: {r.status_code}")
    print(f"Redirect Location: {r.headers.get('Location')}")
    
    if r.status_code == 302 and r.headers.get('Location') == '/login/?next=/dashboard/':
        print("Success! /dashboard/ redirects to /login/?next=/dashboard/")
    else:
        print("Failed! Redirect is incorrect.")

if __name__ == '__main__':
    test_redirects()
