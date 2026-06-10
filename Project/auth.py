import bcrypt
from typing import Any, Dict, Optional, Tuple

from database import (
    create_user,
    get_user_by_email,
    get_user_by_id,
    update_user_password,
    update_user_profile,
)


def hash_password(password: str) -> str:
    """Hash a plain-text password with bcrypt."""
    password_bytes = password.encode("utf-8")
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plain-text password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def authenticate_user(db_path: str, email: str, password: str) -> Optional[Dict[str, Any]]:
    """Validate user credentials and return the user record if successful."""
    email = email.strip().lower()
    user = get_user_by_email(db_path, email)
    if user and verify_password(password, user["password_hash"]):
        return user
    return None


def get_user_profile(db_path: str, user_id: int) -> Optional[Dict[str, Any]]:
    """Returns the user profile record for the given user ID."""
    return get_user_by_id(db_path, user_id)


def save_user_profile(db_path: str, user_id: int, name: str, notify_enabled: bool) -> bool:
    """Update user profile fields in the database."""
    return update_user_profile(db_path, user_id, name, notify_enabled)


def change_user_password(db_path: str, user_id: int, password_hash: str) -> bool:
    """Persist a new hashed password for the user."""
    return update_user_password(db_path, user_id, password_hash)


def register_user(db_path: str, name: str, email: str, password: str) -> Tuple[bool, str]:
    """Register a new user if the email does not already exist."""
    email = email.strip().lower()
    if get_user_by_email(db_path, email):
        return False, "User already exists"
    password_hash = hash_password(password)
    create_user(
        db_path=db_path,
        name=name.strip(),
        email=email,
        password_hash=password_hash,
        notify_enabled=1
    )
    return True, "Account created successfully. Please login."


def create_default_admin_user(db_path: str) -> None:
    """Create a default admin user when the database has no users."""
    default_email = "admin@drift.local"
    default_name = "Administrator"
    existing = get_user_by_email(db_path, default_email)
    if existing:
        return

    password_hash = hash_password("Admin123!")
    create_user(
        db_path=db_path,
        name=default_name,
        email=default_email,
        password_hash=password_hash,
        notify_enabled=1
    )
