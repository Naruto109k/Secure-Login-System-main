"""
auth_manager.py — Authentication Orchestrator
===============================================

High-level façade that coordinates login, logout, lockout enforcement,
and password-reset flows by delegating to the specialised managers.

Security principles enforced here:
    - **Account lockout** after 3 consecutive failed attempts (brute-force
      mitigation).  The account is locked for 30 seconds and the lockout
      state is persisted in JSON.
    - **Automatic unlock** once the lockout window expires.
    - **Ambiguous error messages** for invalid credentials — we do NOT
      reveal whether the *username* or the *password* was wrong, because
      that would let an attacker enumerate valid usernames.
    - **Session creation** on successful login; session invalidation on
      logout.
    - **Counter reset** on successful login — consecutive failures are
      cleared.
"""

import time
from typing import Any, Dict, Optional, Tuple

from .security import SecurityUtils
from .session_manager import SessionManager
from .storage import StorageManager
from .user_manager import UserManager


class AuthManager:
    """Orchestrates authentication workflows."""

    # Lockout policy
    MAX_FAILED_ATTEMPTS: int = 3
    LOCKOUT_DURATION_SECONDS: int = 30

    def __init__(
        self,
        storage: Optional[StorageManager] = None,
    ) -> None:
        """Initialise with a shared ``StorageManager``.

        If none is provided a default one pointing at
        ``data/users.json`` is created automatically.
        """
        self.storage = storage or StorageManager()
        self.user_manager = UserManager(self.storage)
        self.session_manager = SessionManager(self.storage)

    # ================================================================== #
    #  Registration                                                       #
    # ================================================================== #

    def register(
        self,
        username: str,
        password: str,
        security_question: str,
        security_answer: str,
        role: str = "user",
    ) -> Tuple[bool, str]:
        """Register a new user.  Delegates to ``UserManager``."""
        return self.user_manager.register_user(
            username, password, security_question, security_answer, role
        )

    # ================================================================== #
    #  Login                                                              #
    # ================================================================== #

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """Authenticate a user and create a session on success.

        Workflow:
            1. Look up user → fail generically if not found.
            2. Check lockout → deny if locked.
            3. Verify password hash in constant time.
            4a. On failure: increment counter, potentially lock account.
            4b. On success: reset counter, create session, return token.

        Args:
            username: Claimed identity.
            password: Candidate password.

        Returns:
            ``(success, message_or_token)``
        """
        user = self.storage.get_user(username)

        # ── Step 1: user exists? ──────────────────────────────────────
        if user is None:
            # SECURITY: generic message — do NOT say "user not found"
            # because that lets an attacker enumerate valid usernames.
            return False, "Invalid username or password."

        # ── Step 2: lockout check ─────────────────────────────────────
        locked, lock_msg = self._check_lockout(user, username)
        if locked:
            return False, lock_msg

        # ── Step 3: verify password (constant-time) ───────────────────
        is_valid = SecurityUtils.verify_password(
            password, user["salt"], user["password_hash"]
        )

        if not is_valid:
            # ── Step 4a: failed attempt ───────────────────────────────
            return self._handle_failed_login(user, username)

        # ── Step 4b: successful login ─────────────────────────────────
        return self._handle_successful_login(user, username)

    # ================================================================== #
    #  Logout                                                             #
    # ================================================================== #

    def logout(self, username: str) -> Tuple[bool, str]:
        """End the user's session.

        The session token is set to ``None``; any future request
        presenting the old token will be rejected.
        """
        return self.session_manager.invalidate_session(username)

    # ================================================================== #
    #  Password reset                                                     #
    # ================================================================== #

    def initiate_password_reset(
        self, username: str
    ) -> Tuple[bool, str]:
        """Return the security question for *username*.

        If the user doesn't exist, return a generic failure.

        Returns:
            ``(success, security_question_or_error)``
        """
        user = self.storage.get_user(username)
        if user is None:
            return False, "User not found."
        return True, user["security_question"]

    def complete_password_reset(
        self,
        username: str,
        security_answer: str,
        new_password: str,
    ) -> Tuple[bool, str]:
        """Verify the security answer and set a new password.

        Args:
            username:        Target user.
            security_answer: Candidate answer.
            new_password:    The desired new password.

        Returns:
            ``(success, message)``
        """
        user = self.storage.get_user(username)
        if user is None:
            return False, "User not found."

        # Verify the security answer in constant time
        answer_ok = SecurityUtils.verify_security_answer(
            security_answer, user["salt"], user["security_answer_hash"]
        )
        if not answer_ok:
            return False, "Incorrect security answer."

        # Update password (and re-hash the answer with the new salt)
        return self.user_manager.update_password_with_answer(
            username, new_password, security_answer
        )

    # ================================================================== #
    #  Admin operations                                                   #
    # ================================================================== #

    def admin_list_users(self, requesting_user: str) -> Tuple[bool, Any]:
        """List all users.  Requires admin role.

        Args:
            requesting_user: The username of the person making the
                             request — used for authorisation.

        Returns:
            ``(authorised, user_list_or_error)``
        """
        ok, msg = self._require_admin(requesting_user)
        if not ok:
            return False, msg
        return True, self.user_manager.list_all_users()

    def admin_unlock_user(
        self, requesting_user: str, target_user: str
    ) -> Tuple[bool, str]:
        """Unlock a locked account.  Requires admin role."""
        ok, msg = self._require_admin(requesting_user)
        if not ok:
            return False, msg
        return self.user_manager.unlock_user(target_user)

    def admin_reset_password(
        self, requesting_user: str, target_user: str, new_password: str
    ) -> Tuple[bool, str]:
        """Reset another user's password.  Requires admin role."""
        ok, msg = self._require_admin(requesting_user)
        if not ok:
            return False, msg
        return self.user_manager.update_password(target_user, new_password)

    def admin_failed_login_stats(
        self, requesting_user: str
    ) -> Tuple[bool, Any]:
        """View failed-login statistics.  Requires admin role."""
        ok, msg = self._require_admin(requesting_user)
        if not ok:
            return False, msg
        return True, self.user_manager.get_failed_login_stats()

    # ================================================================== #
    #  Profile helpers                                                    #
    # ================================================================== #

    def get_profile(self, username: str) -> Optional[Dict[str, str]]:
        """Return a sanitised user profile (no secrets)."""
        return self.user_manager.get_safe_profile(username)

    def get_session_info(self, username: str) -> Optional[Dict[str, Any]]:
        """Return session metadata for the current user."""
        return self.session_manager.get_session_info(username)

    # ================================================================== #
    #  Internal helpers                                                   #
    # ================================================================== #

    def _check_lockout(
        self, user: Dict[str, Any], username: str
    ) -> Tuple[bool, str]:
        """Return ``(is_locked, message)`` for the given user.

        If the lockout window has expired, automatically unlock the
        account and persist the change.
        """
        locked_until = user.get("locked_until")
        if locked_until is None:
            return False, ""

        now = time.time()
        if now < locked_until:
            remaining = int(locked_until - now)
            return (
                True,
                f"Account is locked. Try again in {remaining} second(s).",
            )

        # Lockout expired — auto-unlock
        user["failed_login_count"] = 0
        user["locked_until"] = None
        self.storage.save_user(username, user)
        return False, ""

    def _handle_failed_login(
        self, user: Dict[str, Any], username: str
    ) -> Tuple[bool, str]:
        """Record a failed login and potentially lock the account.

        Returns:
            ``(False, message)`` always — login failed.
        """
        user["failed_login_count"] = user.get("failed_login_count", 0) + 1
        attempts = user["failed_login_count"]

        if attempts >= self.MAX_FAILED_ATTEMPTS:
            # Lock the account
            user["locked_until"] = time.time() + self.LOCKOUT_DURATION_SECONDS
            self.storage.save_user(username, user)
            return (
                False,
                f"Account locked after {attempts} failed attempts. "
                f"Try again in {self.LOCKOUT_DURATION_SECONDS} seconds.",
            )

        self.storage.save_user(username, user)
        remaining_attempts = self.MAX_FAILED_ATTEMPTS - attempts
        return (
            False,
            f"Invalid username or password. "
            f"{remaining_attempts} attempt(s) remaining before lockout.",
        )

    def _handle_successful_login(
        self, user: Dict[str, Any], username: str
    ) -> Tuple[bool, str]:
        """Reset the failure counter, create a session, return the token."""
        # Reset failed-attempt counter
        user["failed_login_count"] = 0
        user["locked_until"] = None
        self.storage.save_user(username, user)

        # Create a new session
        ok, token = self.session_manager.create_session(username)
        if not ok:
            return False, f"Login succeeded but session creation failed: {token}"

        return True, f"Login successful. Session token: {token[:16]}…"

    def _require_admin(self, username: str) -> Tuple[bool, str]:
        """Authorisation gate — checks that *username* has admin role.

        Returns:
            ``(is_admin, error_message)``
        """
        user = self.storage.get_user(username)
        if user is None:
            return False, "User not found."
        if user.get("role") != "admin":
            return False, "Access denied. Admin privileges required."
        return True, ""
