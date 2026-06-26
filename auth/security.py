"""
security.py — Cryptographic Utilities
======================================

This module provides all cryptographic primitives used throughout the
authentication system.  Every design choice is annotated with the threat
it mitigates.

Key security concepts implemented here:
    1. Password hashing with PBKDF2-HMAC-SHA256
    2. Cryptographically secure random salt generation
    3. Constant-time hash comparison to prevent timing attacks
    4. Secure random token generation for sessions

IMPORTANT — Why we NEVER store plaintext passwords:
    If an attacker gains read access to the database (users.json), they
    would immediately know every user's password.  With hashing, they get
    only irreversible digests that cannot be turned back into passwords.

IMPORTANT — Why we salt every password:
    Without a unique salt per user, identical passwords produce identical
    hashes.  An attacker with a pre-computed table of hash→password
    mappings (a "rainbow table") could reverse the hash instantly.
    A random salt makes every hash unique, even for the same password,
    rendering rainbow tables useless.

IMPORTANT — Why we use constant-time comparison:
    A naive byte-by-byte comparison (==) returns False as soon as the
    first mismatch is found.  An attacker can measure the response time
    to learn how many leading bytes matched, progressively recovering the
    hash.  `hmac.compare_digest` always compares the full length,
    eliminating this timing side-channel.
"""

import hashlib
import hmac
import secrets
from typing import Tuple


class SecurityUtils:
    """Low-level cryptographic helper methods.

    All methods are static so the class acts as a pure namespace — no
    instance state is needed.
    """

    # ------------------------------------------------------------------ #
    #  Configuration constants                                            #
    # ------------------------------------------------------------------ #

    # Number of PBKDF2 iterations.  OWASP recommends ≥600 000 for
    # PBKDF2-HMAC-SHA256 as of 2024.  We use 600 000 to balance security
    # and CLI responsiveness.
    PBKDF2_ITERATIONS: int = 600_000

    # Length (in bytes) of the derived key.  32 bytes = 256 bits —
    # matching the output length of SHA-256 for maximum entropy.
    HASH_LENGTH: int = 32

    # Length (in bytes) of the random salt.  32 bytes provides 256 bits
    # of entropy, far exceeding the birthday-attack threshold.
    SALT_LENGTH: int = 32

    # Length (in bytes) of session tokens.  48 bytes → 64 URL-safe
    # Base64 characters, yielding 384 bits of entropy.
    TOKEN_BYTE_LENGTH: int = 48

    # ------------------------------------------------------------------ #
    #  Salt generation                                                    #
    # ------------------------------------------------------------------ #

    @staticmethod
    def generate_salt() -> str:
        """Generate a cryptographically secure random salt.

        Uses ``secrets.token_hex`` which delegates to the OS CSPRNG
        (e.g. /dev/urandom on Linux, CryptGenRandom on Windows).

        Returns:
            A hex-encoded salt string of ``SALT_LENGTH * 2`` characters.

        Security note:
            ``secrets`` is specifically designed for security-sensitive
            randomness.  Never substitute ``random`` — it uses a
            deterministic PRNG seeded with predictable values.
        """
        return secrets.token_hex(SecurityUtils.SALT_LENGTH)

    # ------------------------------------------------------------------ #
    #  Password hashing                                                   #
    # ------------------------------------------------------------------ #

    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        """Derive a key from *password* using PBKDF2-HMAC-SHA256.

        Args:
            password: The user's plaintext password (never stored).
            salt:     A hex-encoded random salt unique to this user.

        Returns:
            A hex-encoded derived key.

        How PBKDF2 works:
            PBKDF2 applies a pseudorandom function (HMAC-SHA256 here)
            repeatedly for ``PBKDF2_ITERATIONS`` rounds.  Each round
            feeds the output of the previous round back as input,
            creating a computationally expensive derivation that slows
            brute-force attacks dramatically.

        Why HMAC-SHA256:
            HMAC provides resistance to length-extension attacks and
            is a well-analysed construction.  SHA-256 offers 128-bit
            collision resistance.
        """
        derived_key: bytes = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=password.encode("utf-8"),
            salt=bytes.fromhex(salt),
            iterations=SecurityUtils.PBKDF2_ITERATIONS,
            dklen=SecurityUtils.HASH_LENGTH,
        )
        return derived_key.hex()

    # ------------------------------------------------------------------ #
    #  Hash-and-salt convenience wrapper                                  #
    # ------------------------------------------------------------------ #

    @staticmethod
    def hash_new_password(password: str) -> Tuple[str, str]:
        """Generate a fresh salt and hash *password* with it.

        This is the primary entry point when creating a new credential
        (registration or password reset).

        Returns:
            A ``(salt, password_hash)`` tuple, both hex-encoded.
        """
        salt = SecurityUtils.generate_salt()
        password_hash = SecurityUtils.hash_password(password, salt)
        return salt, password_hash

    # ------------------------------------------------------------------ #
    #  Constant-time hash verification                                    #
    # ------------------------------------------------------------------ #

    @staticmethod
    def verify_password(password: str, salt: str, stored_hash: str) -> bool:
        """Verify a password against its stored hash.

        Args:
            password:    The plaintext candidate password.
            salt:        The user's unique hex-encoded salt.
            stored_hash: The hex-encoded hash stored at registration.

        Returns:
            ``True`` if the candidate matches; ``False`` otherwise.

        Security — Timing-attack mitigation:
            We use ``hmac.compare_digest`` instead of ``==``.

            With ``==``, Python short-circuits on the first mismatched
            byte.  An attacker submitting many requests and measuring
            response times can determine how many leading bytes of the
            hash are correct, effectively reducing a 256-bit search to a
            byte-by-byte one (256 × 32 = 8 192 attempts instead of 2²⁵⁶).

            ``hmac.compare_digest`` always compares every byte, making
            the execution time independent of how many bytes match.
        """
        computed_hash = SecurityUtils.hash_password(password, salt)

        # SECURITY: constant-time comparison — prevents timing attacks
        return hmac.compare_digest(computed_hash, stored_hash)

    # ------------------------------------------------------------------ #
    #  Secure session token generation                                    #
    # ------------------------------------------------------------------ #

    @staticmethod
    def generate_session_token() -> str:
        """Generate a cryptographically secure session token.

        Uses ``secrets.token_urlsafe`` which produces a URL-safe
        Base64-encoded string sourced from the OS CSPRNG.

        Returns:
            A URL-safe token string with 384 bits of entropy.

        Security note:
            Tokens must be unpredictable so that an attacker cannot
            forge a valid session.  ``secrets`` guarantees this;
            ``random`` or ``uuid4`` do NOT.
        """
        return secrets.token_urlsafe(SecurityUtils.TOKEN_BYTE_LENGTH)

    # ------------------------------------------------------------------ #
    #  Security answer hashing                                            #
    # ------------------------------------------------------------------ #

    @staticmethod
    def hash_security_answer(answer: str, salt: str) -> str:
        """Hash a security-question answer.

        The answer is normalised to lowercase and stripped of leading /
        trailing whitespace before hashing.  This makes verification
        resilient to trivial formatting differences while preserving
        the secrecy of the answer.

        Args:
            answer: The plaintext security answer.
            salt:   The user's unique hex-encoded salt.

        Returns:
            A hex-encoded derived key.

        Security note:
            Security answers are treated with the same care as passwords
            — they are salted, hashed with PBKDF2, and compared in
            constant time.  Storing them in plaintext would let an
            attacker who reads the JSON file reset any account.
        """
        normalised = answer.strip().lower()
        return SecurityUtils.hash_password(normalised, salt)

    @staticmethod
    def verify_security_answer(
        answer: str, salt: str, stored_hash: str
    ) -> bool:
        """Verify a security answer in constant time.

        Args:
            answer:      The candidate answer.
            salt:        The user's salt.
            stored_hash: The stored hash of the correct answer.

        Returns:
            ``True`` if the answer matches; ``False`` otherwise.
        """
        normalised = answer.strip().lower()
        return SecurityUtils.verify_password(normalised, salt, stored_hash)
