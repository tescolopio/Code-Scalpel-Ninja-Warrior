"""
Backend API for the 'Full Stack Snap' Demo.
This file represents a standard FastAPI backend serving user data.
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Initialize FastAPI app
app = FastAPI(
    title="Legacy User API",
    description="Backend for the legacy integer-based user system."
)

# Enable CORS for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class User(BaseModel):
    """
    User model defining the structure of the API response.
    Current ID format: Integer (e.g., 1024)
    Target format for Demo: UUID String (e.g., "550e8400-e29b...")
    """
    user_id: int = Field(..., description="The unique identifier for the user")
    username: str = Field(..., description="The display name of the user")
    email: str = "user@example.com"
    is_active: bool = True

@app.get("/user/current", response_model=User)
async def get_current_user():
    """
    Returns the currently logged-in user.
    Simulates a database fetch returning an integer ID.
    """
    # In a real app, this would query a DB
    return User(
        user_id=1024,  # <--- CRITICAL: This integer is the contract anchor
        username="scalpel_fan",
        email="demo@codescalpel.com"
    )
