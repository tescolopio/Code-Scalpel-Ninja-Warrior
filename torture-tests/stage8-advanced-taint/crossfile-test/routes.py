"""
Cross-file taint analysis test - Entry point
Routes receive user input and pass to database layer
"""

from database import UserDatabase

def login_route(username: str, password: str):
    """Flask/Django-style route handler - ENTRY POINT for taint."""
    db = UserDatabase()
    result = db.authenticate(username, password)
    return result

def search_route(query: str):
    """Search endpoint - ENTRY POINT for taint."""
    db = UserDatabase()
    users = db.search_users(query)
    return users

def delete_route(user_id: str):
    """Delete endpoint - ENTRY POINT for taint."""
    db = UserDatabase()
    db.delete_user(user_id)
    return {"status": "deleted"}
