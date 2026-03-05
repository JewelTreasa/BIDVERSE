import os
import requests
import json
from dotenv import load_dotenv

load_dotenv('.env')

def test_corporate_logic():
    api_key = os.getenv('GEMINI_API_KEY')
    query = "wheat"
    url = f'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}'
    headers = {'Content-Type': 'application/json'}
    
    prompt = f"""
    You are a business intelligence assistant for Indian farmers.
    The user wants to sell: "{query}".
    Find 3-5 REAL corporate buyers in India.
    Return ONLY a JSON array.
    """
    
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"response_mime_type": "application/json"}
    }
    
    print(f"Testing URL: {url}")
    response = requests.post(url, json=payload, headers=headers)
    print(f"STATUS: {response.status_code}")
    if response.status_code == 200:
        print("SUCCESS!")
        print(response.json())
    else:
        print(f"FAILED: {response.text}")

if __name__ == "__main__":
    test_corporate_logic()
