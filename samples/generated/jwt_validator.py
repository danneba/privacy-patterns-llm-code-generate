"""
JWT access token validation.

OWASP Top 10 (2021) compliance:
- A02 Cryptographic Failures: uses secrets from environment variables for signing
- A03 Injection: no user input is evaluated or executed
- A09 Logging & Monitoring Failures: does not log sensitive tokens or PII

Privacy patterns:
- No sensitive data logged
- Data minimization: only necessary claims are processed
"""

import os
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

def validate_jwt(token: str) -> dict:
    """Validate a JWT access token and return the decoded claims.

    Args:
        token (str): The JWT token to validate.

    Returns:
        dict: The decoded claims from the token.

    Raises:
        ValueError: If the token is invalid or expired.
    """
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        raise ValueError("Signing secret is not configured.")

    try:
        # Decode the token and verify its signature and expiry
        decoded_claims = jwt.decode(token, secret, algorithms=["HS256"])
        return decoded_claims
    except ExpiredSignatureError:
        raise ValueError("Token has expired.")
    except InvalidTokenError:
        raise ValueError("Invalid token.")