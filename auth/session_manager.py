"""
session_manager.py — Secure Session Handling
==============================================

Manages the lifecycle of session tokens: creation, validation,
invalidation (logout), and optional expiration.

Security principles:
    - Tokens are generated with ``secrets.token_urlsafe`` (384 bits of
      entropy from the OS CSPRNG).  This makes brute-force guessing
      infeasible.
    - Tokens are bound to a specific user and stored alongside the user
      record.
    - Logout invalidates the token immediately; the old value can never
      be reused.
    - An optional expiration window automatically invalidates stale
      sessions.
"""

import time
from typing import Any, Dict, Optional, Tuple

from .security import SecurityUtils
from .storage import StorageManager


class SessionManager:
    """Creates, validates, and invalidates session tokens."""

    # Default session lifetime in seconds (1 hour).
    DEFAULT_SESSION_LIFETIME: int = 3600

    def __init__(self, storage: StorageManager) -> None:
        self.storage = storage

    # ------------------------------------------------------------------ #
    #  Session creation                                                   #
    # ------------------------------------------------------------------ #

    def create_session(
        self,
        username: str,
        lifetime: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """Create a new session for *username*.

        Any pre-existing session is replaced — only one active session
        per user is allowed (simple but effective against session
        fixation).

        Args:
            username: The authenticated user.
            lifetime: Session duration in seconds.  Defaults to
                      ``DEFAULT_SESSION_LIFETIME`` (3 600 s = 1 h).

        Returns:
            ``(success, token_or_error_message)``
        """
        user = self.storage.get_user(username)
        if user is None:
            return False, f"User '{username}' not found."

        if lifetime is None:
            lifetime = self.DEFAULT_SESSION_LIFETIME

        token = SecurityUtils.generate_session_token()
        now = time.time()

        user["session_token"] = token
        user["session_created_at"] = now
        user["session_expires_at"] = now + lifetime

        self.storage.save_user(username, user)
        return True, token

    # ------------------------------------------------------------------ #
    #  Session validation                                                 #
    # ------------------------------------------------------------------ #

    def validate_session(self, username: str, token: str) -> Tuple[bool, str]:
        """Check whether *token* is a valid, non-expired session for *username*.

        Args:
            username: The claimed user.
            token:    The session token presented by the client.

        Returns:
            ``(is_valid, message)``

        Security note:
            We compare tokens using ``hmac.compare_digest`` to prevent
            timing side-channels, even though session tokens are
            high-entropy and timing attacks are less practical here.
            Defence-in-depth.
        """
        user = self.storage.get_user(username)
        if user is None:
            return False, "User not found."

        stored_token = user.get("session_token")
        if stored_token is None:
            return False, "No active session."

        # Constant-time comparison
        import hmac as _hmac

        if not _hmac.compare_digest(stored_token, token):
            return False, "Invalid session token."

        # Expiration check
        expires_at = user.get("session_expires_at")
        if expires_at is not None and time.time() > expires_at:
            # Automatically invalidate expired session
            self.invalidate_session(username)
            return False, "Session has expired."

        return True, "Session is valid."

    # ------------------------------------------------------------------ #
    #  Session invalidation (logout)                                      #
    # ------------------------------------------------------------------ #

    def invalidate_session(self, username: str) -> Tuple[bool, str]:
        """Destroy the session for *username* (logout).

        The token is set to ``None``, so any subsequent validation
        attempt with the old token will fail.  The token cannot be
        replayed after logout.

        Returns:
            ``(success, message)``
        """
        user = self.storage.get_user(username)
        if user is None:
            return False, f"User '{username}' not found."

        if user.get("session_token") is None:
            return False, "No active session to invalidate."

        user["session_token"] = None
        user["session_created_at"] = None
        user["session_expires_at"] = None

        self.storage.save_user(username, user)
        return True, "Session invalidated successfully."

    # ------------------------------------------------------------------ #
    #  Helpers                                                            #
    # ------------------------------------------------------------------ #

    def get_session_info(self, username: str) -> Optional[Dict[str, Any]]:
        """Return session metadata for display purposes.

        Sensitive token values are truncated to the first 8 characters
        to avoid leaking them in UI output.
        """
        user = self.storage.get_user(username)
        if user is None:
            return None

        token = user.get("session_token")
        if token is None:
            return {"active": False}

        expires_at = user.get("session_expires_at")
        remaining = None
        if expires_at is not None:
            remaining = max(0, int(expires_at - time.time()))

        return {
            "active": True,
            # Show only a prefix — never log full tokens
            "token_prefix": token[:8] + "…",
            "created_at": user.get("session_created_at"),
            "expires_at": expires_at,
            "remaining_seconds": remaining,
        }
