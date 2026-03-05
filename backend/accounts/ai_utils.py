import os
import json
import requests
from django.conf import settings

def get_ai_response(prompt, system_instruction=None):
    """
    Interacts with Gemini API to get a response.
    Tries multiple model versions for resilience.
    """
    api_key = os.getenv('GEMINI_API_KEY')
    if not api_key:
        print("DEBUG: No GEMINI_API_KEY found in environment.")
        return None

    # Try these models in order
    models_to_try = [
        'gemini-2.0-flash',
        'gemini-1.5-flash',
        'gemini-pro',
    ]

    # Combine system instruction and prompt if provided
    full_prompt = f"{system_instruction}\n\nUser Question: {prompt}" if system_instruction else prompt
    payload = {
        "contents": [{"parts": [{"text": full_prompt}]}]
    }

    for model_name in models_to_try:
        url = f'https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}'
        headers = {'Content-Type': 'application/json'}

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            if response.status_code == 200:
                res_data = response.json()
                try:
                    ai_text = res_data['candidates'][0]['content']['parts'][0]['text']
                    return ai_text.strip()
                except (KeyError, IndexError):
                    continue # Try next model
            else:
                print(f"DEBUG: Model {model_name} failed with {response.status_code}")
                continue # Try next model
        except Exception as e:
            print(f"DEBUG: Connection error with {model_name}: {e}")
            continue

    return None
