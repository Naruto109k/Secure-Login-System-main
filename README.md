# 🔐 Secure Authentication System

A production-style, modular, and educational secure authentication system built with **Python**, **Flask**, and **SQLite**.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Security Concepts](#security-concepts)
  - [Password Hashing (PBKDF2)](#password-hashing-pbkdf2)
  - [Salting](#salting)
  - [Timing-Safe Comparison](#timing-safe-comparison)
  - [Account Lockout (Brute-Force Protection)](#account-lockout-brute-force-protection)
  - [Secure Session Tokens](#secure-session-tokens)
- [How to Run](#how-to-run)
- [Database Schema](#database-schema)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)

---

## Overview

This project demonstrates how to build a **complete, secure authentication system**. It is designed to be both a working application and an educational resource for understanding authentication security.

Recently upgraded, the system now features a robust **SQLite backend** and a beautiful, modern **Flask-powered Web UI** using glassmorphism and vanilla HTML/CSS/JS.

Every security decision is documented in code comments explaining **what** it does and **why** it exists — which specific attack vector it defends against.

### What This Project Is

- ✅ A working Web-based authentication system
- ✅ An educational reference for secure auth design
- ✅ A demonstration of key cryptographic primitives
- ✅ A modular, clean-code example with full type hints

---

## Features

| Feature | Description |
|---|---|
| **User Registration** | Salted PBKDF2-HMAC-SHA256 password hashing |
| **Secure Login** | Constant-time hash comparison, generic error messages |
| **Account Lockout** | 3-strike brute-force protection with 30s auto-unlock |
| **Session Management** | CSPRNG tokens, expiration, secure invalidation |
| **Password Reset** | Security question + hashed answer verification |
| **Role-Based Access** | `admin` and `user` roles with API-level authorisation gates |
| **SQLite Persistence** | Fast, reliable data storage using native SQL queries |
| **Modern Web UI** | Dark mode, glassmorphism UI built without heavy frontend frameworks |
| **Admin Panel** | List users, unlock accounts, reset passwords, view stats |

---

## Architecture

```
secure_auth_system/
│
├── main.py                  # Entry point — launches the Flask Web Server
│
├── auth/
│   ├── __init__.py          # Package exports
│   ├── security.py          # Cryptographic primitives (hash, salt, compare)
│   ├── storage.py           # SQLite persistence layer
│   ├── user_manager.py      # Registration, profiles, RBAC, password updates
│   ├── session_manager.py   # Session token lifecycle
│   └── auth_manager.py      # High-level orchestrator (login, logout, lockout)
│
├── web/
│   ├── app.py               # Flask REST API and route handlers
│   ├── static/
│   │   ├── style.css        # Premium UI styles
│   │   └── script.js        # Vanilla JS logic bridging UI and APIs
│   └── templates/
│       └── index.html       # Single-Page Application (SPA) structure
│
├── data/
│   └── users.db             # Live SQLite user database (auto-created)
│
├── demo/
│   ├── __init__.py
│   └── test_flow.py         # Automated test/demo suite
│
├── utils/
│   ├── __init__.py
│   └── helpers.py           # Display formatting, ANSI colours
│
└── README.md                # This file
```

### Module Responsibilities

| Module | Responsibility |
|---|---|
| `security.py` | All cryptography: hashing, salting, token generation, constant-time comparison |
| `storage.py` | SQLite DB logic: load, save, create, delete user records using SQL queries |
| `user_manager.py` | Business logic: registration validation, profile views, RBAC, password updates |
| `session_manager.py` | Token lifecycle: create, validate, invalidate, expiry |
| `auth_manager.py` | Orchestration: combines all managers, enforces lockout policy |
| `web/app.py` | Exposes internal logic via RESTful API and serves the frontend |

---

## Security Concepts

### Password Hashing (PBKDF2)

**What:** PBKDF2 (Password-Based Key Derivation Function 2) transforms a password into a fixed-length hash through repeated application of HMAC-SHA256.

**How it works:**
```
password + salt → HMAC-SHA256 → (repeat 600,000 times) → hash
```

Each iteration feeds the previous output back as input, creating a computationally expensive chain. With 600,000 iterations, deriving a single hash takes approximately 0.3–1 second — negligible for a legitimate user, but devastating for an attacker trying billions of guesses.

**Why:** Passwords must never be stored in plaintext. If an attacker accesses the data store:
- **Plaintext:** They have every password immediately
- **Simple hash (MD5/SHA256):** They can use pre-computed tables to reverse most hashes in seconds
- **PBKDF2 with salt:** They must brute-force each password individually, taking thousands of years for strong passwords

**What it mitigates:** Direct password compromise, pre-computation attacks

### Salting

**What:** A salt is a cryptographically random value (32 bytes / 256 bits in this implementation) that is combined with the password before hashing. Each user gets a unique salt.

**Why it matters — without salting:**
```
hash("password123") = "ef92b778..."    ← Same for ALL users with this password
```
An attacker can build a "rainbow table" — a massive lookup table mapping common hashes to passwords — and reverse millions of hashes instantly.

**With salting:**
```
hash("password123" + salt_alice)  = "a1b2c3d4..."    ← Unique to Alice
hash("password123" + salt_bob)    = "e5f6g7h8..."    ← Unique to Bob
```
Even though Alice and Bob chose the same password, their hashes are completely different. The attacker must brute-force each user separately, and rainbow tables become useless because every salt produces a different table.

**What it mitigates:** Rainbow table attacks, hash deduplication attacks

### Timing-Safe Comparison

**What:** We use `hmac.compare_digest()` instead of `==` to compare hashes.

**The problem with `==`:**
```python
# Python's == operator short-circuits:
"abcdef" == "aXXXXX"  # Compares 'a'='a', then 'b'≠'X' → returns False (1 comparison)
"abcdef" == "abcXXX"  # Compares 'a','b','c', then 'd'≠'X' → returns False (3 comparisons)
```

An attacker can measure the response time and deduce how many leading bytes are correct:
- Fast response → first byte is wrong
- Slightly slower → first byte correct, second is wrong
- Even slower → first two bytes correct

This turns a 2²⁵⁶ brute-force problem into a ~256 × 32 = 8,192 attempt problem.

**The solution — `hmac.compare_digest()`:**
```python
hmac.compare_digest(a, b)  # Always compares ALL bytes, regardless of mismatches
```

Execution time is constant regardless of how many bytes match, eliminating the timing side-channel.

**What it mitigates:** Timing attacks / side-channel attacks

### Account Lockout (Brute-Force Protection)

**What:** After 3 consecutive failed login attempts, the account is locked for 30 seconds. During lockout, even the correct password is rejected.

**Why:**
- Without lockout, an attacker can try millions of passwords per second
- With lockout, they get 3 attempts per 30 seconds = 6 attempts/minute
- Brute-forcing a strong password at this rate would take thousands of years

**Implementation details:**
- The lockout timestamp is persisted in the database, surviving server restarts
- After the lockout period expires, the account automatically unlocks
- Successful login resets the failure counter to zero
- Admins can manually unlock accounts

**What it mitigates:** Online brute-force attacks, credential stuffing

### Secure Session Tokens

**What:** After successful authentication, a session token is generated using `secrets.token_urlsafe(48)`, producing a 384-bit random value from the OS CSPRNG.

**Why `secrets` and not `random` or `uuid4`:**
- `random` uses a Mersenne Twister PRNG — deterministic and predictable if the seed is known
- `uuid4` may use less entropy and is not guaranteed to be cryptographically secure on all platforms
- `secrets` is explicitly designed for security tokens and uses the OS's strongest available CSPRNG

**Token lifecycle:**
1. **Created** on successful login
2. **Validated** on each protected operation (constant-time comparison)
3. **Invalidated** on logout (set to `None` — old token can never be reused)
4. **Expires** after a configurable timeout (default: 1 hour)

**What it mitigates:** Session hijacking, token prediction, session replay after logout

---

## How to Run

### Prerequisites

- **Python 3.7+**
- **Flask** `pip install flask`

### Launch the Web App

```bash
# From the project root (Secure Login System/)
python secure_auth_system/main.py
```

Then, navigate to `http://localhost:5000` in your web browser.

### Automated Demo / Tests

```bash
# Runs all core logic test scenarios automatically
python -m secure_auth_system.demo.test_flow
```

---

## Database Schema

User records are stored in `data/users.db` via SQLite.

| Column | Type | Description |
|---|---|---|
| `username` | TEXT (PK) | Unique identifier |
| `salt` | TEXT | 256-bit random salt, unique per user |
| `password_hash` | TEXT | PBKDF2-HMAC-SHA256 derived key |
| `role` | TEXT | `"user"` or `"admin"` |
| `failed_login_count` | INTEGER | Consecutive failed login attempts |
| `locked_until` | REAL | Unix timestamp when lockout expires |
| `session_token` | TEXT | Active session token (CSPRNG) |
| `session_created_at` | REAL | Unix timestamp of session creation |
| `session_expires_at` | REAL | Unix timestamp of session expiry |
| `security_question` | TEXT | Password recovery question |
| `security_answer_hash` | TEXT | PBKDF2 hash of the answer |

> ⚠️ **Note:** `salt`, `password_hash`, and `security_answer_hash` are the only cryptographic fields. No plaintext passwords or answers are ever stored.

---

## Limitations

| Limitation | Explanation |
|---|---|
| **No TLS/HTTPS** | A production web deployment would require TLS to protect credentials in transit. |
| **PBKDF2 vs Argon2** | PBKDF2 is well-established but Argon2 (the Password Hashing Competition winner) provides better resistance to GPU/ASIC attacks via memory-hardness. |
| **No rate limiting at network level** | The lockout mechanism is application-level only. In production, use IP-based rate limiting (e.g., nginx, WAF). |
| **Security questions** | Generally considered weaker than TOTP/MFA. Used here for educational purposes. |
| **No password complexity rules** | Only minimum length is enforced. Production systems should check against breached-password databases. |

---

## Future Improvements

- 🔑 **Multi-Factor Authentication (MFA):** TOTP-based 2FA using `hmac` and `time`
- 🔒 **Argon2 hashing:** Memory-hard KDF for GPU-attack resistance (requires `argon2-cffi`)
- 📝 **Audit logging:** Record all login attempts, password changes, admin actions
- 🔄 **Password rotation policy:** Force periodic password changes
- 🛡️ **Breached-password check:** Verify passwords against Have I Been Pwned (k-anonymity API)
- ⏰ **Configurable lockout policy:** Admin-adjustable thresholds and durations
- 🧪 **Unit test suite:** `unittest` or `pytest` based comprehensive test coverage

---

## License

This project is provided for **educational purposes**. Use the security patterns demonstrated here as a foundation, but always rely on battle-tested libraries (Argon2, bcrypt) and frameworks for production deployments.

---

*Built with ❤️.*
