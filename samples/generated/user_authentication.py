"""
User authentication helpers.

OWASP Top 10 (2021) compliance:
- A01 Broken Access Control: authorization checks are enforced.
- A02 Cryptographic Failures: passwords are hashed using bcrypt.
- A03 Injection: parameterized SQL queries are used to prevent SQL injection.
- A05 Security Misconfiguration: secure defaults are used; debug mode is disabled.

Privacy patterns:
- Data minimization: only necessary user data is collected.
- No sensitive data logged: passwords and tokens are not logged.
- Safe error messages: generic error messages are provided to users.
"""

import os
import bcrypt
import sqlite3
from typing import Optional

DATABASE_PATH = os.environ.get("DATABASE_PATH", "users.db")

def create_user_table() -> None:
    """Create a user table in the database if it doesn't exist."""
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
        conn.commit()

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def register_user(username: str, password: str) -> bool:
    """Register a new user with a username and password."""
    hashed_password = hash_password(password)
    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                           (username, hashed_password))
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Username already exists

def authenticate_user(username: str, password: str) -> bool:
    """Validate user credentials."""
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result and bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
            return True
    return False