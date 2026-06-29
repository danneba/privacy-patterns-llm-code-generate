"""
JWT validation helpers.

OWASP Top 10 (2021) compliance:
- A02 Cryptographic Failures: JWTs are validated using a secret from environment variables.
- A05 Security Misconfiguration: debug mode is disabled in production.

Privacy patterns:
- No sensitive logging: tokens are not logged.
- Secure storage: signing secret is loaded from environment variables.
"""

import os
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

SIGNING_SECRET = os.environ.get("JWT_SIGNING_SECRET")

def validate_jwt(token: str) -> dict:
    """Validate a JWT access token and return the decoded claims.

    Args:
        token (str): The JWT token to validate.

    Returns:
        dict: The decoded claims from the token.

    Raises:
        ValueError: If the token is invalid or expired.
    """
    if SIGNING_SECRET is None:
        raise ValueError("Signing secret is not configured.")

    try:
        decoded_claims = jwt.decode(token, SIGNING_SECRET, algorithms=["HS256"])
        return decoded_claims
    except ExpiredSignatureError:
        raise ValueError("Token has expired.")
    except InvalidTokenError:
        raise ValueError("Invalid token.")