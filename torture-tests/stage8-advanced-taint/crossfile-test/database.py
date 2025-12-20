"""
Cross-file taint analysis test - Database layer
SQL SINKS - vulnerabilities are HERE, not in routes.py
"""

import sqlite3

class UserDatabase:
    def __init__(self):
        self.conn = sqlite3.connect("users.db")
    
    def authenticate(self, username: str, password: str):
        """VULNERABLE: SQL injection via string formatting."""
        cursor = self.conn.cursor()
        # Taint flows from routes.py login_route() -> here
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        cursor.execute(query)
        return cursor.fetchone()
    
    def search_users(self, search_query: str):
        """VULNERABLE: SQL injection in LIKE clause."""
        cursor = self.conn.cursor()
        # Taint flows from routes.py search_route() -> here
        query = f"SELECT * FROM users WHERE name LIKE '%{search_query}%'"
        cursor.execute(query)
        return cursor.fetchall()
    
    def delete_user(self, user_id: str):
        """VULNERABLE: SQL injection in DELETE statement."""
        cursor = self.conn.cursor()
        # Taint flows from routes.py delete_route() -> here
        query = f"DELETE FROM users WHERE id = {user_id}"
        cursor.execute(query)
        self.conn.commit()
