"""
Test Suite for QuickCart Authentication System
===============================================
These tests verify both existing functionality and SQL injection protection.

Run with: python -m pytest tests.py -v
"""

import pytest
import os
import sqlite3
import sys

# Import the module to test (works with both starter.py and solution.py)
# Rename your file to 'auth.py' or modify this import
try:
    from solution import (
        initialize_database,
        authenticate_user,
        register_user,
        get_user_by_username,
        get_user_by_email,
        update_user_email,
        update_user_password,
        deactivate_user,
        get_users_by_role,
        search_users,
        delete_user,
        count_users_by_role,
        get_login_history,
        hash_password,
        DATABASE_NAME
    )
except ImportError:
    from solution import (
        initialize_database,
        authenticate_user,
        register_user,
        get_user_by_username,
        get_user_by_email,
        update_user_email,
        update_user_password,
        deactivate_user,
        get_users_by_role,
        search_users,
        delete_user,
        count_users_by_role,
        get_login_history,
        hash_password,
        DATABASE_NAME
    )


@pytest.fixture(autouse=True)
def setup_and_teardown():
    """Setup fresh database before each test, cleanup after."""
    # Remove existing database
    if os.path.exists(DATABASE_NAME):
        os.remove(DATABASE_NAME)
    
    # Initialize fresh database
    initialize_database()
    
    yield
    
    # Cleanup
    if os.path.exists(DATABASE_NAME):
        os.remove(DATABASE_NAME)


class TestBasicFunctionality:
    """Tests for basic functionality that must be preserved."""
    
    def test_register_new_user(self):
        """Test that new users can register successfully."""
        success, message = register_user("alice", "securepass123", "alice@example.com")
        assert success is True
        assert "successfully" in message.lower()
    
    def test_register_duplicate_username(self):
        """Test that duplicate usernames are rejected."""
        register_user("bob", "password1", "bob@example.com")
        success, message = register_user("bob", "password2", "bob2@example.com")
        assert success is False
        assert "username" in message.lower()
    
    def test_register_duplicate_email(self):
        """Test that duplicate emails are rejected."""
        register_user("user1", "password1", "same@example.com")
        success, message = register_user("user2", "password2", "same@example.com")
        assert success is False
        assert "email" in message.lower()
    
    def test_authenticate_valid_user(self):
        """Test that valid credentials authenticate successfully."""
        register_user("charlie", "mypassword", "charlie@example.com")
        user = authenticate_user("charlie", "mypassword")
        assert user is not None
        assert user['username'] == "charlie"
    
    def test_authenticate_invalid_password(self):
        """Test that wrong password fails authentication."""
        register_user("david", "correctpass", "david@example.com")
        user = authenticate_user("david", "wrongpass")
        assert user is None
    
    def test_authenticate_nonexistent_user(self):
        """Test that nonexistent users fail authentication."""
        user = authenticate_user("nonexistent", "anypassword")
        assert user is None
    
    def test_get_user_by_username(self):
        """Test retrieving user by username."""
        register_user("eve", "password", "eve@example.com")
        user = get_user_by_username("eve")
        assert user is not None
        assert user['email'] == "eve@example.com"
    
    def test_get_user_by_email(self):
        """Test retrieving user by email."""
        register_user("frank", "password", "frank@example.com")
        user = get_user_by_email("frank@example.com")
        assert user is not None
        assert user['username'] == "frank"
    
    def test_update_email(self):
        """Test updating user email."""
        register_user("grace", "password", "grace@old.com")
        success, _ = update_user_email("grace", "grace@new.com")
        assert success is True
        user = get_user_by_username("grace")
        assert user['email'] == "grace@new.com"
    
    def test_update_password(self):
        """Test updating user password."""
        register_user("henry", "oldpass", "henry@example.com")
        success, _ = update_user_password("henry", "oldpass", "newpass")
        assert success is True
        # Old password should no longer work
        assert authenticate_user("henry", "oldpass") is None
        # New password should work
        assert authenticate_user("henry", "newpass") is not None
    
    def test_deactivate_user(self):
        """Test user deactivation."""
        register_user("ivan", "password", "ivan@example.com")
        success, _ = deactivate_user("ivan")
        assert success is True
        user = get_user_by_username("ivan")
        assert user['is_active'] == 0
    
    def test_delete_user(self):
        """Test user deletion."""
        register_user("julia", "password", "julia@example.com")
        success, _ = delete_user("julia")
        assert success is True
        assert get_user_by_username("julia") is None
    
    def test_get_users_by_role(self):
        """Test filtering users by role."""
        register_user("admin1", "pass", "admin1@example.com", role="admin")
        register_user("admin2", "pass", "admin2@example.com", role="admin")
        register_user("customer1", "pass", "customer1@example.com", role="customer")
        
        admins = get_users_by_role("admin")
        assert len(admins) == 2
    
    def test_search_users(self):
        """Test user search functionality."""
        register_user("testuser1", "pass", "test1@search.com")
        register_user("testuser2", "pass", "test2@search.com")
        register_user("other", "pass", "other@example.com")
        
        results = search_users("test")
        assert len(results) == 2
    
    def test_count_users_by_role(self):
        """Test counting users by role."""
        register_user("c1", "pass", "c1@example.com", role="customer")
        register_user("c2", "pass", "c2@example.com", role="customer")
        register_user("a1", "pass", "a1@example.com", role="admin")
        
        assert count_users_by_role("customer") == 2
        assert count_users_by_role("admin") == 1


class TestSQLInjectionPrevention:
    """Tests to verify SQL injection vulnerabilities are fixed."""
    
    def test_sql_injection_login_bypass(self):
        """Test that SQL injection cannot bypass authentication."""
        register_user("victim", "secretpassword", "victim@example.com")
        
        # Classic SQL injection attempts
        injection_attempts = [
            ("victim' --", "anything"),
            ("victim'--", "anything"),
            ("' OR '1'='1", "' OR '1'='1"),
            ("' OR 1=1--", "anything"),
            ("admin'/*", "*/"),
            ("' UNION SELECT * FROM users--", "x"),
            ("victim'; DROP TABLE users;--", "x"),
        ]
        
        for username, password in injection_attempts:
            user = authenticate_user(username, password)
            assert user is None, f"SQL injection succeeded with username: {username}"
    
    def test_sql_injection_in_registration(self):
        """Test that SQL injection in registration is prevented."""
        # Try to inject via username
        malicious_username = "hacker'; DROP TABLE users;--"
        success, _ = register_user(malicious_username, "password", "hacker@example.com")
        
        # The registration might succeed (username is just a string), 
        # but it shouldn't execute the DROP TABLE
        # Verify users table still exists by trying another operation
        register_user("normaluser", "password", "normal@example.com")
        user = get_user_by_username("normaluser")
        assert user is not None, "Users table was dropped by SQL injection!"
    
    def test_sql_injection_in_email_lookup(self):
        """Test that SQL injection in email lookup is prevented."""
        register_user("target", "password", "target@example.com")
        
        # Try SQL injection in email lookup
        injection_email = "' OR '1'='1"
        user = get_user_by_email(injection_email)
        
        # Should not return any user
        assert user is None, "SQL injection in email lookup returned unauthorized data"
    
    def test_sql_injection_in_search(self):
        """Test that SQL injection in search is prevented."""
        register_user("admin", "adminpass", "admin@example.com", role="admin")
        register_user("user", "userpass", "user@example.com", role="customer")
        
        # Try to use UNION injection to get all users
        injection_search = "' UNION SELECT * FROM users WHERE role='admin"
        results = search_users(injection_search)
        
        # Should return empty results, not leak admin data
        # If injection worked, we'd get unexpected results
        for result in results:
            assert "admin" not in str(result.get('role', '')).lower() or \
                   injection_search in str(result.get('username', '')), \
                   "SQL injection in search leaked unauthorized data"
    
    def test_sql_injection_in_role_filter(self):
        """Test that SQL injection in role filter is prevented."""
        register_user("admin1", "pass", "admin1@example.com", role="admin")
        register_user("customer1", "pass", "customer1@example.com", role="customer")
        
        # Try to inject to get all users regardless of role
        injection_role = "admin' OR '1'='1"
        results = get_users_by_role(injection_role)
        
        # Should return 0 users (no role matches the injection string literally)
        # If injection worked, we'd get all users
        assert len(results) <= 1, "SQL injection in role filter returned too many results"
    
    def test_sql_injection_in_password_update(self):
        """Test that SQL injection in password update is prevented."""
        register_user("pwuser", "originalpass", "pwuser@example.com")
        
        # Try injection in old password field
        injection_old_pass = "' OR '1'='1"
        success, _ = update_user_password("pwuser", injection_old_pass, "newpass")
        
        # Should fail because injection shouldn't bypass password check
        assert success is False, "SQL injection bypassed password verification"
        
        # Original password should still work
        user = authenticate_user("pwuser", "originalpass")
        assert user is not None, "Original password no longer works after injection attempt"
    
    def test_sql_injection_in_email_update(self):
        """Test that SQL injection in email update is prevented."""
        register_user("emailuser", "pass", "original@example.com")
        register_user("other", "pass", "other@example.com")
        
        # Try to inject in the email update
        injection_email = "hacked@example.com' WHERE '1'='1"
        update_user_email("emailuser", injection_email)
        
        # Other user's email should not be changed
        other_user = get_user_by_username("other")
        assert other_user['email'] == "other@example.com", "SQL injection modified other user's email"
    
    def test_second_order_sql_injection(self):
        """Test prevention of second-order SQL injection."""
        # Register a user with a malicious username
        malicious_name = "admin'--"
        register_user(malicious_name, "password123", "malicious@example.com")
        
        # Try to authenticate - the stored malicious data shouldn't cause injection
        user = authenticate_user(malicious_name, "password123")
        
        # Should authenticate normally with the literal username
        assert user is not None, "Legitimate user with special chars couldn't login"
        assert user['username'] == malicious_name


class TestEdgeCases:
    """Tests for edge cases and special scenarios."""
    
    def test_special_characters_in_password(self):
        """Test that special characters in passwords work correctly."""
        special_pass = "p@$$w0rd'\"<>!@#$%^&*()"
        register_user("specialuser", special_pass, "special@example.com")
        
        user = authenticate_user("specialuser", special_pass)
        assert user is not None
    
    def test_unicode_in_username(self):
        """Test that unicode characters are handled properly."""
        unicode_name = "用户名"
        success, _ = register_user(unicode_name, "password", "unicode@example.com")
        
        if success:
            user = authenticate_user(unicode_name, "password")
            assert user is not None
    
    def test_empty_search_term(self):
        """Test search with empty string."""
        register_user("anyuser", "pass", "any@example.com")
        results = search_users("")
        # Should return all users or handle gracefully
        assert isinstance(results, list)
    
    def test_very_long_input(self):
        """Test handling of very long input strings."""
        long_string = "a" * 10000
        
        # Should handle gracefully without crashing
        try:
            authenticate_user(long_string, "password")
            get_user_by_username(long_string)
            search_users(long_string)
        except Exception as e:
            # Some graceful error handling is acceptable
            assert "sql" not in str(e).lower(), "SQL error exposed in exception"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
