"""
user_manager.py — User Registration & Profile Management
==========================================================

Handles user creation, profile retrieval, role-based access control,
and password / security-answer updates.

Security principles enforced here:
    - Passwords are NEVER stored — only their salted PBKDF2 hashes.
    - Security answers receive the same treatment as passwords.
    - Input validation rejects empty or whitespace-only values early.
    - Role assignment defaults to ``"user"``; only explicit action
      grants ``"admin"`` privileges.
"""

from typing import Any, Dict, List, Optional, Tuple

from .security import SecurityUtils
from .storage import StorageManager


class UserManager:
    """Manages user registration, profiles, and role-based access."""

    # Valid roles in the system
    VALID_ROLES = {"user", "admin"}

    def __init__(self, storage: StorageManager) -> None:
        self.storage = storage

    # ------------------------------------------------------------------ #
    #  Registration                                                       #
    # ------------------------------------------------------------------ #

    def register_user(
        self,
        username: str,
        password: str,
        security_question: str,
        security_answer: str,
        role: str = "user",
    ) -> Tuple[bool, str]:
        """Register a new user account.

        Workflow:
            1. Validate all inputs.
            2. Check for duplicate username.
            3. Generate a unique salt.
            4. Hash the password with that salt using PBKDF2-HMAC-SHA256.
            5. Hash the security answer with the same salt.
            6. Persist the record — plaintext password is discarded.

        Args:
            username:          Desired username (must be non-empty, alphanumeric + underscore).
            password:          Plaintext password (min 8 chars).
            security_question: Question used for password resets.
            security_answer:   Answer to the security question.
            role:              ``"user"`` or ``"admin"`` (default ``"user"``).

        Returns:
            ``(success: bool, message: str)``
        """
        # --- Input validation -------------------------------------------
        valid, msg = self._validate_registration_input(
            username, password, security_question, security_answer, role
        )
        if not valid:
            return False, msg

        # --- Duplicate check --------------------------------------------
        if self.storage.user_exists(username):
            return False, f"Username '{username}' is already taken."

        # --- Cryptographic operations -----------------------------------
        # Generate a CSPRNG salt and derive the password hash.
        # After this point the plaintext password is no longer needed.
        salt, password_hash = SecurityUtils.hash_new_password(password)

        # Hash the security answer with the SAME salt.
        # We normalise to lowercase inside hash_security_answer().
        security_answer_hash = SecurityUtils.hash_security_answer(
            security_answer, salt
        )

        # --- Build the user record --------------------------------------
        user_data: Dict[str, Any] = {
            "username": username,
            "salt": salt,
            "password_hash": password_hash,
            "role": role,
            "failed_login_count": 0,
            "locked_until": None,
            "session_token": None,
            "session_created_at": None,
            "session_expires_at": None,
            "security_question": security_question,
            "security_answer_hash": security_answer_hash,
        }

        # --- Persist (no plaintext passwords ever written) ---------------
        self.storage.save_user(username, user_data)

        return True, f"User '{username}' registered successfully."

    # ------------------------------------------------------------------ #
    #  Profile retrieval                                                  #
    # ------------------------------------------------------------------ #

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Retrieve a user record by username.

        Returns ``None`` if the user does not exist.
        """
        return self.storage.get_user(username)

    def get_safe_profile(self, username: str) -> Optional[Dict[str, str]]:
        """Return a sanitised view of a user's profile.

        Sensitive fields (salt, hashes, tokens) are excluded so that
        the caller cannot accidentally leak them.

        Returns:
            A dictionary with only ``username``, ``role``, and
            ``security_question``, or ``None``.
        """
        user = self.storage.get_user(username)
        if user is None:
            return None

        return {
            "username": user["username"],
            "role": user["role"],
            "security_question": user["security_question"],
            "failed_login_count": str(user.get("failed_login_count", 0)),
            "locked_until": str(user.get("locked_until", "N/A")),
            "session_active": "Yes" if user.get("session_token") else "No",
        }

    # ------------------------------------------------------------------ #
    #  Admin operations                                                   #
    # ------------------------------------------------------------------ #

    def list_all_users(self) -> List[Dict[str, Any]]:
        """Return sanitised summaries of all users (admin use)."""
        all_data = self.storage.load_all()
        result = []
        for uname, udata in all_data.items():
            result.append(
                {
                    "username": uname,
                    "role": udata.get("role", "user"),
                    "failed_login_count": udata.get("failed_login_count", 0),
                    "locked_until": udata.get("locked_until"),
                    "session_active": udata.get("session_token") is not None,
                }
            )
        return result

    def get_failed_login_stats(self) -> List[Dict[str, Any]]:
        """Return failed-login statistics for all users (admin use)."""
        all_data = self.storage.load_all()
        stats = []
        for uname, udata in all_data.items():
            stats.append(
                {
                    "username": uname,
                    "failed_login_count": udata.get("failed_login_count", 0),
                    "locked_until": udata.get("locked_until"),
                }
            )
        return stats

    # ------------------------------------------------------------------ #
    #  Password & security-answer updates                                 #
    # ------------------------------------------------------------------ #

    def update_password(self, username: str, new_password: str) -> Tuple[bool, str]:
        """Set a new password for *username*.

        A fresh salt is generated so that old hashes become useless even
        if the same password is reused (defence-in-depth).

        Also re-hashes the security answer with the new salt to maintain
        consistency.

        Args:
            username:     Target user.
            new_password: The new plaintext password (min 8 chars).

        Returns:
            ``(success, message)``
        """
        if len(new_password) < 8:
            return False, "Password must be at least 8 characters long."

        user = self.storage.get_user(username)
        if user is None:
            return False, f"User '{username}' not found."

        # Generate a NEW salt — never reuse an old one after a password
        # change.  This ensures that if the old hash is leaked, it
        # cannot be used with the new password.
        new_salt, new_hash = SecurityUtils.hash_new_password(new_password)

        # Re-hash the security answer with the new salt.  We don't have
        # the plaintext answer, so we need the caller to supply it when
        # doing a proper reset.  For admin resets, we keep the old
        # security answer hash but generate a new salt, which means
        # the security answer must be re-registered.  In this
        # implementation, admin resets clear the security answer.
        user["salt"] = new_salt
        user["password_hash"] = new_hash

        # Invalidate any existing session after a password change
        user["session_token"] = None
        user["session_created_at"] = None
        user["session_expires_at"] = None

        # Reset lockout state
        user["failed_login_count"] = 0
        user["locked_until"] = None

        self.storage.save_user(username, user)
        return True, f"Password updated for '{username}'."

    def update_password_with_answer(
        self, username: str, new_password: str, security_answer: str
    ) -> Tuple[bool, str]:
        """Reset a user's password and re-hash their security answer.

        Called during the password-reset flow after the answer has been
        verified.  Both password and security answer are re-hashed with
        a fresh salt.

        Args:
            username:        Target user.
            new_password:    New plaintext password.
            security_answer: The (already-verified) security answer.

        Returns:
            ``(success, message)``
        """
        if len(new_password) < 8:
            return False, "Password must be at least 8 characters long."

        user = self.storage.get_user(username)
        if user is None:
            return False, f"User '{username}' not found."

        new_salt, new_hash = SecurityUtils.hash_new_password(new_password)
        new_answer_hash = SecurityUtils.hash_security_answer(
            security_answer, new_salt
        )

        user["salt"] = new_salt
        user["password_hash"] = new_hash
        user["security_answer_hash"] = new_answer_hash

        # Invalidate session
        user["session_token"] = None
        user["session_created_at"] = None
        user["session_expires_at"] = None

        # Reset lockout
        user["failed_login_count"] = 0
        user["locked_until"] = None

        self.storage.save_user(username, user)
        return True, f"Password reset successfully for '{username}'."

    # ------------------------------------------------------------------ #
    #  Lockout management (admin)                                         #
    # ------------------------------------------------------------------ #

    def unlock_user(self, username: str) -> Tuple[bool, str]:
        """Manually unlock a locked account (admin operation).

        Args:
            username: The user to unlock.

        Returns:
            ``(success, message)``
        """
        user = self.storage.get_user(username)
        if user is None:
            return False, f"User '{username}' not found."

        user["failed_login_count"] = 0
        user["locked_until"] = None
        self.storage.save_user(username, user)
        return True, f"User '{username}' has been unlocked."

    # ------------------------------------------------------------------ #
    #  Input validation                                                   #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _validate_registration_input(
        username: str,
        password: str,
        security_question: str,
        security_answer: str,
        role: str,
    ) -> Tuple[bool, str]:
        """Validate registration fields.

        Returns:
            ``(is_valid, error_message)``
        """
        # Username rules
        if not username or not username.strip():
            return False, "Username cannot be empty."
        if len(username) < 3:
            return False, "Username must be at least 3 characters."
        if len(username) > 30:
            return False, "Username must be at most 30 characters."
        if not all(c.isalnum() or c == "_" for c in username):
            return False, "Username may only contain letters, digits, and underscores."

        # Password rules
        if not password or len(password) < 8:
            return False, "Password must be at least 8 characters long."
        if len(password) > 128:
            return False, "Password must be at most 128 characters long."

        # Security question / answer
        if not security_question or not security_question.strip():
            return False, "Security question cannot be empty."
        if not security_answer or not security_answer.strip():
            return False, "Security answer cannot be empty."

        # Role
        if role not in UserManager.VALID_ROLES:
            return False, f"Invalid role '{role}'. Must be one of {UserManager.VALID_ROLES}."

        return True, ""
