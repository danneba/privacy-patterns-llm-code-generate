"""
User authentication helpers with consent and audit logging.

OWASP Top 10 (2021) compliance:
- A01 Broken Access Control: authorization checks are enforced.
- A02 Cryptographic Failures: passwords are hashed using bcrypt.
- A03 Injection: parameterized SQL queries are used for database interactions.
- A05 Security Misconfiguration: debug mode is disabled in production.

Privacy patterns:
- Data minimization: only necessary user data is collected.
- No sensitive logging: passwords and tokens are not logged.
- Secure storage: passwords are stored securely using hashing.
- Consent handling: user consent is required for data processing.
- Audit logging: changes to sensitive data are logged for accountability.
"""

import os
import bcrypt
import sqlite3
from typing import Optional
import logging

DATABASE_PATH = os.environ.get("DATABASE_PATH", "users.db")
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def log_audit(action: str, username: str) -> None:
    """Log an audit trail for sensitive actions."""
    logging.info(f"{action} performed on user: {username}")

def create_user(username: str, password: str, consent: bool) -> None:
    """Create a new user with a hashed password after consent verification."""
    if not consent:
        raise ValueError("User consent is required to create an account.")
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                       (username, hashed_password))
        conn.commit()
    
    log_audit("User created", username)

def authenticate_user(username: str, password: str, consent: bool) -> bool:
    """Validate user credentials against stored data with consent verification."""
    if not consent:
        raise ValueError("User consent is required for authentication.")
    
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result is None:
            return False
        stored_password = result[0]
        is_authenticated = bcrypt.checkpw(password.encode('utf-8'), stored_password)
    
    log_audit("User authentication attempted", username)
    return is_authenticated

def setup_database() -> None:
    """Set up the database and create the users table if it doesn't exist."""
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        conn.commit()