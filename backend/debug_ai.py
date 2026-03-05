import os
import requests
import json
from dotenv import load_dotenv

load_dotenv('.env')

def get_ai_response(prompt, system_instruction=None):
    api_key = os.getenv('GEMINI_API_KEY')
    url = f'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}'
    headers = {'Content-Type': 'application/json'}
    payload = {"contents": [{"parts": [{"text": f"{system_instruction}\n\n{prompt}"}]}]}
    
    response = requests.post(url, json=payload, headers=headers)
    print(f"STATUS: {response.status_code}")
    if response.status_code == 200:
        return response.json()['candidates'][0]['content']['parts'][0]['text']
    else:
        return f"ERROR: {response.text}"

if __name__ == "__main__":
    print(get_ai_response("Hello", "Test Bot"))
