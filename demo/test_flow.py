"""
test_flow.py — Automated Demonstration & Test Suite
=====================================================

This module exercises every feature of the Secure Authentication System
without requiring manual interaction.  It uses a temporary JSON file so
the main user store is not affected.

Run directly::

    python -m secure_auth_system.demo.test_flow

Demonstrated scenarios:
    1.  Successful registration (user + admin)
    2.  Duplicate registration rejection
    3.  Input validation (short password, empty username)
    4.  Successful login → session token generation
    5.  Failed logins → incremental warnings
    6.  Account lockout after 3 failures
    7.  Lockout expiry (waits for timeout)
    8.  Login after lockout expires
    9.  Logout → session invalidation
   10.  Session reuse prevention after logout
   11.  Password reset via security question
   12.  Login with new password after reset
   13.  Admin: list users
   14.  Admin: view failed-login stats
   15.  Admin: unlock a locked user
   16.  Admin: reset another user's password
   17.  Non-admin denied access to admin panel
"""

import os
import sys
import time
import tempfile

# Ensure project root is on sys.path
_project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from secure_auth_system.auth.auth_manager import AuthManager
from secure_auth_system.auth.storage import StorageManager
from secure_auth_system.utils.helpers import (
    Colours,
    error,
    format_stats_table,
    format_user_table,
    header,
    info,
    section,
    success,
    warning,
)


# ────────────────────────────────────────────────────────────────────── #
#  Helpers                                                              #
# ────────────────────────────────────────────────────────────────────── #

_pass_count = 0
_fail_count = 0


def _assert(condition: bool, description: str) -> None:
    """Simple test assertion with coloured output."""
    global _pass_count, _fail_count
    if condition:
        _pass_count += 1
        print(f"  {Colours.GREEN}PASS{Colours.RESET}  {description}")
    else:
        _fail_count += 1
        print(f"  {Colours.RED}FAIL{Colours.RESET}  {description}")


def _step(title: str) -> None:
    """Print a step header."""
    print(section(title))


# ────────────────────────────────────────────────────────────────────── #
#  Main demo flow                                                       #
# ────────────────────────────────────────────────────────────────────── #

def run_demo() -> None:
    """Execute the full demonstration / test suite."""
    print(header("Secure Auth System — Demo / Test Flow"))

    # Use a temp file so we don't pollute the real data store
    temp_dir = tempfile.mkdtemp(prefix="secure_auth_demo_")
    temp_db = os.path.join(temp_dir, "test_users.db")
    print(info(f"Using temporary store: {temp_db}\n"))

    storage = StorageManager(filepath=temp_db)
    auth = AuthManager(storage=storage)

    # ────────────────────────────────────────────────────────────────── #
    #  1. Registration                                                   #
    # ────────────────────────────────────────────────────────────────── #

    _step("1. User Registration")

    ok, msg = auth.register(
        username="alice",
        password="SecurePass123!",
        security_question="What is your pet's name?",
        security_answer="Fluffy",
        role="user",
    )
    _assert(ok, f"Register 'alice' as user → {msg}")

    ok, msg = auth.register(
        username="bob_admin",
        password="AdminPass456!",
        security_question="What city were you born in?",
        security_answer="New York",
        role="admin",
    )
    _assert(ok, f"Register 'bob_admin' as admin → {msg}")

    # Duplicate registration
    ok, msg = auth.register(
        username="alice",
        password="AnotherPass789!",
        security_question="Fav colour?",
        security_answer="Blue",
    )
    _assert(not ok, f"Duplicate 'alice' rejected → {msg}")

    # Input validation
    ok, msg = auth.register("ab", "short", "q?", "a")
    _assert(not ok, f"Short username rejected → {msg}")

    ok, msg = auth.register("validuser", "short", "q?", "a")
    _assert(not ok, f"Short password rejected → {msg}")

    # Verify plaintext password is NOT stored
    user_data = storage.get_user("alice")
    _assert(
        "password" not in str(user_data).lower().replace("password_hash", "").replace("password_hash", ""),
        "Plaintext password NOT present in stored data"
    )
    _assert(user_data is not None and "salt" in user_data, "Salt is stored")
    _assert(user_data is not None and "password_hash" in user_data, "Password hash is stored")

    # ────────────────────────────────────────────────────────────────── #
    #  2. Successful Login                                               #
    # ────────────────────────────────────────────────────────────────── #

    _step("2. Successful Login")

    ok, msg = auth.login("alice", "SecurePass123!")
    _assert(ok, f"Alice login with correct password → {msg}")

    session = auth.get_session_info("alice")
    _assert(
        session is not None and session.get("active"),
        f"Session active, token prefix: {session.get('token_prefix', 'N/A') if session else 'N/A'}",
    )

    # Logout alice for subsequent tests
    auth.logout("alice")

    # ────────────────────────────────────────────────────────────────── #
    #  3. Failed Logins & Lockout                                        #
    # ────────────────────────────────────────────────────────────────── #

    _step("3. Failed Logins & Account Lockout")

    ok, msg = auth.login("alice", "WrongPassword1")
    _assert(not ok, f"Attempt 1 (wrong pass) → {msg}")

    ok, msg = auth.login("alice", "WrongPassword2")
    _assert(not ok, f"Attempt 2 (wrong pass) → {msg}")

    ok, msg = auth.login("alice", "WrongPassword3")
    _assert(not ok, f"Attempt 3 (wrong pass) → LOCKED: {msg}")

    # Verify locked
    ok, msg = auth.login("alice", "SecurePass123!")
    _assert(not ok, f"Correct password while locked → {msg}")

    # ────────────────────────────────────────────────────────────────── #
    #  4. Lockout Expiry                                                 #
    # ────────────────────────────────────────────────────────────────── #

    _step("4. Lockout Expiry")

    # Override lockout duration for testing (make it 3 seconds)
    original_lockout = auth.LOCKOUT_DURATION_SECONDS
    auth.LOCKOUT_DURATION_SECONDS = 3

    # Re-register a test user for lockout-expiry demo
    auth.register("charlie", "TestPass1234!", "Fav food?", "pizza")

    # Lock charlie
    auth.login("charlie", "wrong1")
    auth.login("charlie", "wrong2")
    ok, msg = auth.login("charlie", "wrong3")
    _assert(not ok, f"Charlie locked → {msg}")

    # Manually set a short lockout on charlie for quick test
    charlie = storage.get_user("charlie")
    if charlie:
        charlie["locked_until"] = time.time() + 3
        storage.save_user("charlie", charlie)

    print(info("Waiting 4 seconds for lockout to expire…"))
    time.sleep(4)

    ok, msg = auth.login("charlie", "TestPass1234!")
    _assert(ok, f"Charlie login after lockout expired → {msg}")

    auth.LOCKOUT_DURATION_SECONDS = original_lockout

    # ────────────────────────────────────────────────────────────────── #
    #  5. Session Management                                             #
    # ────────────────────────────────────────────────────────────────── #

    _step("5. Session Management")

    # Login alice again
    # First unlock alice (she was locked above)
    auth.user_manager.unlock_user("alice")
    ok, msg = auth.login("alice", "SecurePass123!")
    _assert(ok, f"Alice re-login → {msg}")

    session = auth.get_session_info("alice")
    _assert(
        session is not None and session.get("active"),
        "Session is active after login",
    )

    # Logout
    ok, msg = auth.logout("alice")
    _assert(ok, f"Alice logout → {msg}")

    session = auth.get_session_info("alice")
    _assert(
        session is not None and not session.get("active"),
        "Session inactive after logout",
    )

    # Double-logout
    ok, msg = auth.logout("alice")
    _assert(not ok, f"Double-logout rejected → {msg}")

    # ────────────────────────────────────────────────────────────────── #
    #  6. Password Reset Flow                                            #
    # ────────────────────────────────────────────────────────────────── #

    _step("6. Password Reset Flow")

    ok, question = auth.initiate_password_reset("alice")
    _assert(ok, f"Got security question → {question}")

    # Wrong answer
    ok, msg = auth.complete_password_reset("alice", "WrongAnswer", "NewPass1234!")
    _assert(not ok, f"Wrong security answer rejected → {msg}")

    # Correct answer
    ok, msg = auth.complete_password_reset("alice", "Fluffy", "NewPass1234!")
    _assert(ok, f"Correct answer → {msg}")

    # Login with new password
    ok, msg = auth.login("alice", "NewPass1234!")
    _assert(ok, f"Login with new password → {msg}")

    # Old password should fail
    auth.logout("alice")
    ok, msg = auth.login("alice", "SecurePass123!")
    _assert(not ok, f"Old password rejected → {msg}")

    # ────────────────────────────────────────────────────────────────── #
    #  7. Admin Operations                                               #
    # ────────────────────────────────────────────────────────────────── #

    _step("7. Admin Operations")

    # Login as admin
    ok, msg = auth.login("bob_admin", "AdminPass456!")
    _assert(ok, f"Admin login → {msg}")

    # List users
    ok, users = auth.admin_list_users("bob_admin")
    _assert(ok, "Admin can list users")
    if ok:
        print(format_user_table(users))

    # View stats
    ok, stats = auth.admin_failed_login_stats("bob_admin")
    _assert(ok, "Admin can view failed-login stats")
    if ok:
        print(format_stats_table(stats))

    # Unlock alice (she may have failed attempts from test 6)
    alice_data = storage.get_user("alice")
    if alice_data:
        alice_data["failed_login_count"] = 3
        alice_data["locked_until"] = time.time() + 999
        storage.save_user("alice", alice_data)

    ok, msg = auth.admin_unlock_user("bob_admin", "alice")
    _assert(ok, f"Admin unlocked alice → {msg}")

    alice_data = storage.get_user("alice")
    _assert(
        alice_data is not None and alice_data.get("failed_login_count") == 0,
        "Alice's failed count reset to 0 after admin unlock",
    )

    # Admin reset password
    ok, msg = auth.admin_reset_password("bob_admin", "alice", "AdminReset99!")
    _assert(ok, f"Admin reset alice's password → {msg}")

    auth.logout("bob_admin")

    # Verify alice can login with admin-set password
    ok, msg = auth.login("alice", "AdminReset99!")
    _assert(ok, f"Alice login with admin-reset password → {msg}")
    auth.logout("alice")

    # ────────────────────────────────────────────────────────────────── #
    #  8. Authorisation Check (non-admin)                                #
    # ────────────────────────────────────────────────────────────────── #

    _step("8. Non-Admin Denied Access")

    ok, msg = auth.login("alice", "AdminReset99!")
    _assert(ok, "Alice logged in")

    ok, result = auth.admin_list_users("alice")
    _assert(not ok, f"Non-admin 'alice' denied admin list → {result}")

    ok, msg = auth.admin_unlock_user("alice", "bob_admin")
    _assert(not ok, f"Non-admin 'alice' denied admin unlock → {msg}")

    auth.logout("alice")

    # ────────────────────────────────────────────────────────────────── #
    #  9. Non-existent User                                              #
    # ────────────────────────────────────────────────────────────────── #

    _step("9. Edge Cases")

    ok, msg = auth.login("nonexistent", "password123")
    _assert(not ok, f"Non-existent user login → {msg}")

    ok, msg = auth.initiate_password_reset("nonexistent")
    _assert(not ok, f"Reset for non-existent user → {msg}")

    # ────────────────────────────────────────────────────────────────── #
    #  Summary                                                           #
    # ────────────────────────────────────────────────────────────────── #

    print(header("Test Summary"))
    total = _pass_count + _fail_count
    print(f"\n  Total : {total}")
    print(f"  {Colours.GREEN}Passed: {_pass_count}{Colours.RESET}")
    print(f"  {Colours.RED}Failed: {_fail_count}{Colours.RESET}")

    if _fail_count == 0:
        print(f"\n  {success('All tests passed!')}")
    else:
        print(f"\n  {error(f'{_fail_count} test(s) failed.')}")

    # Clean up temp file
    try:
        os.remove(temp_db)
        os.rmdir(temp_dir)
    except OSError:
        pass

    print()


if __name__ == "__main__":
    run_demo()
