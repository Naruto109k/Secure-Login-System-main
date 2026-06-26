"""
storage.py — SQLite Persistence Layer
=====================================

Handles reading and writing user data to ``data/users.db``.
"""

import sqlite3
import os
from pathlib import Path
from typing import Any, Dict, Optional


class StorageManager:
    """Manages SQLite-based user data persistence.

    Attributes:
        filepath: Absolute path to the SQLite data file.
    """

    def __init__(self, filepath: Optional[str] = None) -> None:
        """Initialise the storage manager.

        Args:
            filepath: Path to the SQLite DB file. Defaults to
                      ``<project_root>/data/users.db``.
        """
        if filepath is None:
            # Resolve relative to this file's parent → auth/ → project root
            project_root = Path(__file__).resolve().parent.parent
            filepath = str(project_root / "data" / "users.db")

        self.filepath: str = filepath
        self._ensure_file_exists()

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                   #
    # ------------------------------------------------------------------ #

    def _ensure_file_exists(self) -> None:
        """Create the data directory and initialize the database schema if missing."""
        directory = os.path.dirname(self.filepath)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)

        with sqlite3.connect(self.filepath) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    salt TEXT,
                    password_hash TEXT,
                    role TEXT,
                    failed_login_count INTEGER,
                    locked_until REAL,
                    session_token TEXT,
                    session_created_at REAL,
                    session_expires_at REAL,
                    security_question TEXT,
                    security_answer_hash TEXT
                )
            ''')
            conn.commit()

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert an sqlite3.Row to a standard dictionary."""
        return dict(row)

    # ------------------------------------------------------------------ #
    #  Public API                                                         #
    # ------------------------------------------------------------------ #

    def load_all(self) -> Dict[str, Any]:
        """Load and return the entire user store.

        Returns:
            A dictionary keyed by username.
        """
        result = {}
        with sqlite3.connect(self.filepath) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM users")
            for row in cursor:
                d = self._row_to_dict(row)
                result[d["username"]] = d
        return result

    def save_all(self, data: Dict[str, Any]) -> None:
        """Persist the entire user store to disk.
        
        This replaces the entire users table with the provided data.
        
        Args:
            data: Full user dictionary to write.
        """
        with sqlite3.connect(self.filepath) as conn:
            conn.execute("DELETE FROM users")
            for username, user_data in data.items():
                self._insert_user(conn, username, user_data)
            conn.commit()

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single user record.

        Args:
            username: The username to look up (case-sensitive).

        Returns:
            The user dictionary, or ``None`` if not found.
        """
        with sqlite3.connect(self.filepath) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row:
                return self._row_to_dict(row)
            return None

    def _insert_user(self, conn: sqlite3.Connection, username: str, user_data: Dict[str, Any]) -> None:
        """Helper to insert/replace a single user record within a connection."""
        conn.execute('''
            INSERT OR REPLACE INTO users (
                username, salt, password_hash, role, failed_login_count,
                locked_until, session_token, session_created_at,
                session_expires_at, security_question, security_answer_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            username,
            user_data.get('salt'),
            user_data.get('password_hash'),
            user_data.get('role'),
            user_data.get('failed_login_count'),
            user_data.get('locked_until'),
            user_data.get('session_token'),
            user_data.get('session_created_at'),
            user_data.get('session_expires_at'),
            user_data.get('security_question'),
            user_data.get('security_answer_hash')
        ))

    def save_user(self, username: str, user_data: Dict[str, Any]) -> None:
        """Create or update a single user record and persist immediately.

        Args:
            username:  The key under which to store the record.
            user_data: The user dictionary (must contain only serialisable
                       values — no plaintext passwords!).
        """
        user_data['username'] = username
        with sqlite3.connect(self.filepath) as conn:
            self._insert_user(conn, username, user_data)
            conn.commit()

    def delete_user(self, username: str) -> bool:
        """Delete a user record.

        Args:
            username: The user to remove.

        Returns:
            ``True`` if the user existed and was removed.
        """
        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()
            return cursor.rowcount > 0

    def user_exists(self, username: str) -> bool:
        """Check whether a username is already registered.

        Args:
            username: The username to check.

        Returns:
            ``True`` if a record exists for *username*.
        """
        with sqlite3.connect(self.filepath) as conn:
            cursor = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            return cursor.fetchone() is not None
