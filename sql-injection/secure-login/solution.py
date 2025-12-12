"""
QuickCart User Authentication System - SECURED VERSION
========================================================
This module handles user authentication, registration, and management
for the QuickCart e-commerce platform.

All SQL injection vulnerabilities have been fixed using parameterized queries.
"""

import sqlite3
import hashlib
import os
from datetime import datetime
from typing import Optional, List, Dict, Tuple


# Database configuration
DATABASE_NAME = "quickcart_users.db"


def get_database_connection() -> sqlite3.Connection:
    """Create and return a database connection."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database() -> None:
    """Initialize the database with required tables."""
    conn = get_database_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT DEFAULT 'customer',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            success INTEGER NOT NULL,
            attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT
        )
    """)
    
    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()


def authenticate_user(username: str, password: str) -> Optional[Dict]:
    """
    Authenticate a user with username and password.
    
    Returns user data if successful, None otherwise.
    """
    conn = get_database_connection()
    cursor = conn.cursor()
    
    password_hash = hash_password(password)
    
    # FIXED: Using parameterized query
    query = "SELECT * FROM users WHERE username = ? AND password_hash = ?"
    cursor.execute(query, (username, password_hash))
    
    user = cursor.fetchone()
    
    if user:
        # Log successful login
        log_login_attempt(username, True)
        update_last_login(username)
        conn.close()
        return dict(user)
    else:
        # Log failed login
        log_login_attempt(username, False)
        conn.close()
        return None


def register_user(username: str, password: str, email: str, role: str = "customer") -> Tuple[bool, str]:
    """
    Register a new user.
    
    Returns (success, message) tuple.
    """
    conn = get_database_connection()
    cursor = conn.cursor()
    
    # Check if username already exists
    # FIXED: Using parameterized query
    check_query = "SELECT id FROM users WHERE username = ?"
    cursor.execute(check_query, (username,))
    
    if cursor.fetchone():
        conn.close()
        return False, "Username already exists"
    
    # Check if email already exists
    # FIXED: Using parameterized query
    email_query = "SELECT id FROM users WHERE email = ?"
    cursor.execute(email_query, (email,))
    
    if cursor.fetchone():
        conn.close()
        return False, "Email already registered"
    
    password_hash = hash_password(password)
    
    # Insert new user
    # FIXED: Using parameterized query
    insert_query = "INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)"
    
    try:
        cursor.execute(insert_query, (username, password_hash, email, role))
        conn.commit()
        conn.close()
        return True, "User registered successfully"
    except sqlite3.Error as e:
        conn.close()
        return False, f"Registration failed: {str(e)}"


def get_user_by_username(username: str) -> Optional[Dict]:
    """Retrieve user information by username."""
    conn = get_database_connection()
    cursor = conn.cursor()
    
    # FIXED: Using parameterized query
    query = "SELECT id, username, email, role, created_at, last_login, is_active FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return dict(user)
    return None


def get_user_by_email(email: str) -> Optional[Dict]:
    """Retrieve user information by email."""
    conn = get_database_connection()
    cursor = conn.cursor()
    
    # FIXED: Using parameterized query
    query = "SELECT id, username, email, role, created_at, last_login, is_active FROM users WHERE email = ?"
    cursor.execute(query, (email,))
    
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return dict(user)
    return None


def update_user_email(username: str, new_email: str) -> Tuple[bool, str]:
    """Update a user's email address."""
    conn = get_database_connection()
    cursor = conn.cursor()
    
    # Check if new email is already in use
    # FIXED: Using parameterized query
    check_query = "SELECT id FROM users WHERE email = ? AND username != ?"
    cursor.execute(check_query, (new_email, username))
    
    if cursor.fetchone():
        conn.close()
        return False, "Email already in use by another account"
    
    # Update email
    # FIXED: Using parameterized query
    update_query = "UPDATE users SET email = ? WHERE username = ?"
    
    try:
        cursor.execute(update_query, (new_email, username))
        conn.commit()
        conn.close()
        return True, "Email updated successfully"
    except sqlite3.Error as e:
        conn.close()
        return False, f"Update failed: {str(e)}"


def update_user_password(username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
    """Update a user's password after verifying old password."""
    conn = get_database_connection()
    cursor = conn.cursor()
    
    old_hash = hash_password(old_password)
    
    # Verify old password
    # FIXED: Using parameterized query
    verify_query = "SELECT id FROM users WHERE username = ? AND password_hash = ?"
    cursor.execute(verify_query, (username, old_hash))
    
    if not cursor.fetchone():
        conn.close()
        return False, "Current password is incorrect"
    
    new_hash = hash_password(new_password)
    
    # Update password
    # FIXED: Using parameterized query
    update_query = "UPDATE users SET password_hash = ? WHERE username = ?"
    
    try:
        cursor.execute(update_query, (new_hash, username))
        conn.commit()
        conn.close()
        return True, "Password updated successfully"
    except sqlite3.Error as e:
        conn.close()
        return False, f"Update failed: {str(e)}"


def deactivate_user(username: str) -> Tuple[bool, str]:
    """Deactivate a user account."""
    conn = get_database_connection()
    cursor = conn.cursor()
    
    # FIXED: Using parameterized query
    query = "UPDATE users SET is_active = 0 WHERE username = ?"
    
    try:
        cursor.execute(query, (username,))
        if cursor.rowcount == 0:
            conn.close()
            return False, "User not found"
        conn.commit()
        conn.close()
        return True, "User deactivated successfully"
    except sqlite3.Error as e:
        conn.close()
        return False, f"Deactivation failed: {str(e)}"


def get_users_by_role(role: str) -> List[Dict]:
    """Get all users with a specific role."""
    conn = get_database_connection()
    cursor = conn.cursor()
    
    # FIXED: Using parameterized query
    query = "SELECT id, username, email, role, created_at, last_login, is_active FROM users WHERE role = ?"
    cursor.execute(query, (role,))
    
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return users


def search_users(search_term: str) -> List[Dict]:
    """Search users by username or email."""
    conn = get_database_connection()
    cursor = conn.cursor()
    
    # FIXED: Using parameterized query with LIKE
    search_pattern = f"%{search_term}%"
    query = "SELECT id, username, email, role, created_at, is_active FROM users WHERE username LIKE ? OR email LIKE ?"
    cursor.execute(query, (search_pattern, search_pattern))
    
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return users


def log_login_attempt(username: str, success: bool, ip_address: str = "127.0.0.1") -> None:
    """Log a login attempt."""
    conn = get_database_connection()
    cursor = conn.cursor()
    
    success_int = 1 if success else 0
    
    # FIXED: Using parameterized query
    query = "INSERT INTO login_attempts (username, success, ip_address) VALUES (?, ?, ?)"
    
    try:
        cursor.execute(query, (username, success_int, ip_address))
        conn.commit()
    except sqlite3.Error:
        pass  # Silently fail for logging
    finally:
        conn.close()


def update_last_login(username: str) -> None:
    """Update the last login timestamp for a user."""
    conn = get_database_connection()
    cursor = conn.cursor()
    
    current_time = datetime.now().isoformat()
    
    # FIXED: Using parameterized query
    query = "UPDATE users SET last_login = ? WHERE username = ?"
    
    try:
        cursor.execute(query, (current_time, username))
        conn.commit()
    except sqlite3.Error:
        pass  # Silently fail for timestamp update
    finally:
        conn.close()


def get_login_history(username: str, limit: int = 10) -> List[Dict]:
    """Get login history for a user."""
    conn = get_database_connection()
    cursor = conn.cursor()
    
    # FIXED: Using parameterized query
    query = "SELECT * FROM login_attempts WHERE username = ? ORDER BY attempt_time DESC LIMIT ?"
    cursor.execute(query, (username, limit))
    
    history = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return history


def delete_user(username: str) -> Tuple[bool, str]:
    """Permanently delete a user account."""
    conn = get_database_connection()
    cursor = conn.cursor()
    
    # FIXED: Using parameterized query
    query = "DELETE FROM users WHERE username = ?"
    
    try:
        cursor.execute(query, (username,))
        if cursor.rowcount == 0:
            conn.close()
            return False, "User not found"
        conn.commit()
        conn.close()
        return True, "User deleted successfully"
    except sqlite3.Error as e:
        conn.close()
        return False, f"Deletion failed: {str(e)}"


def count_users_by_role(role: str) -> int:
    """Count the number of users with a specific role."""
    conn = get_database_connection()
    cursor = conn.cursor()
    
    # FIXED: Using parameterized query
    query = "SELECT COUNT(*) as count FROM users WHERE role = ?"
    cursor.execute(query, (role,))
    
    result = cursor.fetchone()
    conn.close()
    
    return result['count'] if result else 0


# Initialize database when module is imported
initialize_database()


if __name__ == "__main__":
    # Demo usage
    print("QuickCart Authentication System (Secured)")
    print("=" * 40)
    
    # Register a test user
    success, message = register_user("testuser", "password123", "test@quickcart.com")
    print(f"Registration: {message}")
    
    # Attempt login
    user = authenticate_user("testuser", "password123")
    if user:
        print(f"Login successful! Welcome, {user['username']}")
    else:
        print("Login failed!")
