"""
helpers.py — Display and Formatting Utilities
===============================================

Pure helper functions for CLI output formatting.
No security-sensitive logic lives here.
"""

import datetime
import time
from typing import Any, Dict, List


# ────────────────────────────────────────────────────────────────────── #
#  ANSI colour helpers (works on Windows 10+ and most terminals)        #
# ────────────────────────────────────────────────────────────────────── #

class Colours:
    """ANSI escape codes for terminal colouring."""

    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"


def success(msg: str) -> str:
    """Wrap *msg* in green."""
    return f"{Colours.GREEN}{Colours.BOLD}✔ {msg}{Colours.RESET}"


def error(msg: str) -> str:
    """Wrap *msg* in red."""
    return f"{Colours.RED}{Colours.BOLD}✘ {msg}{Colours.RESET}"


def warning(msg: str) -> str:
    """Wrap *msg* in yellow."""
    return f"{Colours.YELLOW}{Colours.BOLD}⚠ {msg}{Colours.RESET}"


def info(msg: str) -> str:
    """Wrap *msg* in cyan."""
    return f"{Colours.CYAN}ℹ {msg}{Colours.RESET}"


def header(title: str, width: int = 56) -> str:
    """Return a centred header banner."""
    border = "═" * width
    padded = title.center(width)
    return (
        f"\n{Colours.BLUE}{Colours.BOLD}"
        f"╔{border}╗\n"
        f"║{padded}║\n"
        f"╚{border}╝"
        f"{Colours.RESET}"
    )


def section(title: str) -> str:
    """Return a section divider."""
    return f"\n{Colours.MAGENTA}{Colours.BOLD}── {title} ──{Colours.RESET}"


# ────────────────────────────────────────────────────────────────────── #
#  Data formatting                                                      #
# ────────────────────────────────────────────────────────────────────── #

def format_user_table(users: List[Dict[str, Any]]) -> str:
    """Format a list of user summaries as a simple text table."""
    if not users:
        return "  (no users registered)"

    lines = []
    lines.append(
        f"  {'Username':<18} {'Role':<8} {'Failed':<8} {'Locked':<16} {'Session'}"
    )
    lines.append("  " + "─" * 66)

    for u in users:
        locked_str = "No"
        locked_until = u.get("locked_until")
        if locked_until is not None:
            remaining = max(0, int(locked_until - time.time()))
            if remaining > 0:
                locked_str = f"Yes ({remaining}s)"
            else:
                locked_str = "Expired"

        session_str = "Active" if u.get("session_active") else "None"

        lines.append(
            f"  {u['username']:<18} "
            f"{u.get('role', 'user'):<8} "
            f"{u.get('failed_login_count', 0):<8} "
            f"{locked_str:<16} "
            f"{session_str}"
        )

    return "\n".join(lines)


def format_stats_table(stats: List[Dict[str, Any]]) -> str:
    """Format failed-login statistics as a text table."""
    if not stats:
        return "  (no users)"

    lines = []
    lines.append(f"  {'Username':<18} {'Failed Logins':<16} {'Locked Until'}")
    lines.append("  " + "─" * 54)

    for s in stats:
        locked = s.get("locked_until")
        if locked is not None:
            remaining = max(0, int(locked - time.time()))
            locked_str = f"{remaining}s remaining" if remaining > 0 else "Expired"
        else:
            locked_str = "—"

        lines.append(
            f"  {s['username']:<18} "
            f"{s.get('failed_login_count', 0):<16} "
            f"{locked_str}"
        )

    return "\n".join(lines)


def format_profile(profile: Dict[str, str]) -> str:
    """Format a user profile for display."""
    lines = []
    for key, value in profile.items():
        label = key.replace("_", " ").title()
        lines.append(f"  {label:<22} : {value}")
    return "\n".join(lines)


def format_session_info(session: Dict[str, Any]) -> str:
    """Format session metadata for display."""
    if not session.get("active"):
        return "  No active session."

    lines = []
    lines.append(f"  Token (prefix)     : {session.get('token_prefix', 'N/A')}")

    created = session.get("created_at")
    if created:
        dt = datetime.datetime.fromtimestamp(created)
        lines.append(f"  Created at         : {dt.strftime('%Y-%m-%d %H:%M:%S')}")

    remaining = session.get("remaining_seconds")
    if remaining is not None:
        lines.append(f"  Expires in         : {remaining} second(s)")

    return "\n".join(lines)


def timestamp_now() -> str:
    """Return the current local time as an ISO-format string."""
    return datetime.datetime.now().isoformat(timespec="seconds")
