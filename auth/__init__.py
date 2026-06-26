"""
Authentication Package
======================

This package contains the core authentication modules for the secure login system.

Modules:
    - security: Cryptographic primitives (hashing, salting, constant-time comparison)
    - storage: JSON-based persistence layer
    - user_manager: User registration, profile management, and RBAC
    - session_manager: Secure session token lifecycle
    - auth_manager: High-level authentication orchestration (login, logout, lockout)
"""

from .security import SecurityUtils
from .storage import StorageManager
from .user_manager import UserManager
from .session_manager import SessionManager
from .auth_manager import AuthManager

__all__ = [
    "SecurityUtils",
    "StorageManager",
    "UserManager",
    "SessionManager",
    "AuthManager",
]
