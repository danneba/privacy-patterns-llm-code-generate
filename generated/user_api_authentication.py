"""
User API authentication helpers.

OWASP Top 10 (2021) compliance:
- A02 Cryptographic Failures: API key loaded from environment variables
- A03 Injection: parameterized requests to prevent injection attacks
- A05 Security Misconfiguration: no debug mode enabled in production

Privacy patterns:
- No sensitive data logged
- Data minimization: only required fields collected
"""

import os
import requests

def authenticate_user(api_url: str, username: str, password: str) -> bool:
    """Authenticate a user against the API using the provided credentials."""
    api_key = os.getenv('API_KEY')
    if not api_key:
        raise ValueError("API key not found in environment variables.")

    response = requests.post(api_url, json={'username': username, 'password': password}, headers={'Authorization': f'Bearer {api_key}'})
    
    if response.status_code == 200:
        return True
    elif response.status_code == 401:
        return False
    else:
        response.raise_for_status()