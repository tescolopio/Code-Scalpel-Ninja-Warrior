"""Obstacle 9.4: Negative Inference Validation

Tests that Code Scalpel correctly identifies SAFE code patterns and does NOT
hallucinate vulnerabilities where none exist.

An LLM without proper tooling might:
- Flag parameterized queries as SQL injection
- Report XSS where proper escaping is used
- Claim command injection in safe subprocess usage
- See vulnerabilities in properly validated input

PASS CRITERIA:
- Zero false positives on known-safe patterns
- High confidence "SAFE" verdicts (>85%)
- Correct identification of WHY code is safe

FAIL CRITERIA:
- Any false positive on these patterns
- Low confidence on clearly safe code
- Missing the protection mechanism in explanation
"""

import sqlite3
import subprocess
import html
import shlex
import os
from pathlib import Path
from typing import Optional
import secrets
import hmac
import hashlib


# =============================================================================
# SAFE SQL PATTERNS - Must NOT be flagged
# =============================================================================

def safe_sql_parameterized_tuple(conn, user_id: int):
    """SAFE: Parameterized query with tuple placeholder.

    This is the canonical safe pattern. The ? placeholder ensures
    user_id is never interpolated into the query string.
    """
    return conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()


def safe_sql_parameterized_named(conn, user_id: int, username: str):
    """SAFE: Named parameter binding.

    Using :name placeholders with dictionary binding is equally safe.
    """
    return conn.execute(
        "SELECT * FROM users WHERE id = :id AND name = :name",
        {"id": user_id, "name": username}
    ).fetchone()


def safe_sql_executemany(conn, users: list):
    """SAFE: Bulk insert with parameterized queries.

    executemany with placeholders is safe even for bulk operations.
    """
    conn.executemany(
        "INSERT INTO users (name, email) VALUES (?, ?)",
        [(u["name"], u["email"]) for u in users]
    )


def safe_sql_hardcoded_literal(conn):
    """SAFE: Hardcoded literal value, no user input.

    When values are hardcoded strings with no external input,
    there's no injection vector.
    """
    return conn.execute("SELECT * FROM users WHERE status = 'active'").fetchall()


def safe_sql_integer_cast(conn, user_id: str):
    """SAFE: Explicit integer cast before interpolation.

    Converting to int() before use guarantees only numeric values.
    """
    safe_id = int(user_id)  # Will raise ValueError on non-numeric
    return conn.execute(f"SELECT * FROM users WHERE id = {safe_id}").fetchone()


# =============================================================================
# SAFE COMMAND EXECUTION PATTERNS - Must NOT be flagged
# =============================================================================

def safe_subprocess_list_args(filename: str):
    """SAFE: Subprocess with list arguments, no shell.

    When shell=False (default) and args are a list, each argument
    is passed directly to the executable without shell interpretation.
    """
    return subprocess.run(
        ["ls", "-la", filename],
        capture_output=True,
        text=True,
        check=True
    )


def safe_subprocess_shlex_split(command: str):
    """SAFE: Using shlex to safely split command strings.

    shlex.split handles quoting correctly and prevents injection.
    Note: Still requires shell=False!
    """
    args = shlex.split(command)
    return subprocess.run(args, capture_output=True, text=True, shell=False)


def safe_os_execvp(args: list):
    """SAFE: Direct exec without shell.

    os.execvp bypasses shell entirely.
    """
    os.execvp(args[0], args)


def safe_hardcoded_command():
    """SAFE: Hardcoded command with no user input.

    Commands with no external input have no injection vector.
    """
    return subprocess.run(["date", "+%Y-%m-%d"], capture_output=True, text=True)


# =============================================================================
# SAFE XSS PATTERNS - Must NOT be flagged
# =============================================================================

def safe_xss_html_escape(user_input: str) -> str:
    """SAFE: Proper HTML escaping with html.escape().

    html.escape converts <, >, &, ', " to HTML entities.
    """
    escaped = html.escape(user_input)
    return f"<div>{escaped}</div>"


def safe_xss_html_escape_with_quote(user_input: str) -> str:
    """SAFE: HTML escaping with quote=True for attributes.

    quote=True ensures quotes are escaped for safe attribute use.
    """
    escaped = html.escape(user_input, quote=True)
    return f'<input value="{escaped}">'


def safe_xss_text_content_only():
    """SAFE: No dynamic content, hardcoded HTML.

    Static HTML with no user input is safe.
    """
    return "<div>Welcome to our site!</div>"


def safe_xss_integer_only(count: int) -> str:
    """SAFE: Only integers rendered, no string injection possible.

    Integers cannot contain HTML/JS payloads.
    """
    return f"<span>{int(count)}</span>"


# =============================================================================
# SAFE PATH TRAVERSAL PATTERNS - Must NOT be flagged
# =============================================================================

def safe_path_resolve_and_check(base_dir: str, user_filename: str) -> Optional[str]:
    """SAFE: Path resolution with containment check.

    Resolving to absolute path and checking it's within allowed directory.
    """
    base = Path(base_dir).resolve()
    requested = (base / user_filename).resolve()

    # Security check: ensure resolved path is within base
    if not str(requested).startswith(str(base)):
        raise ValueError("Path traversal attempt blocked")

    return requested.read_text()


def safe_path_basename_only(user_filename: str) -> str:
    """SAFE: Using only basename, discarding directory components.

    os.path.basename strips all directory traversal attempts.
    """
    safe_name = os.path.basename(user_filename)
    path = os.path.join("/safe/uploads/", safe_name)
    with open(path, "r") as f:
        return f.read()


def safe_path_whitelist(user_choice: str) -> str:
    """SAFE: Whitelist-based file access.

    Only pre-approved filenames can be accessed.
    """
    ALLOWED_FILES = {"readme.txt", "license.txt", "changelog.txt"}

    if user_choice not in ALLOWED_FILES:
        raise ValueError("File not in whitelist")

    with open(f"/docs/{user_choice}", "r") as f:
        return f.read()


# =============================================================================
# SAFE CRYPTOGRAPHIC PATTERNS - Must NOT be flagged
# =============================================================================

def safe_crypto_secrets_token():
    """SAFE: Using secrets module for token generation.

    secrets.token_hex uses cryptographically secure random.
    """
    return secrets.token_hex(32)


def safe_crypto_hmac_compare(provided: str, expected: str) -> bool:
    """SAFE: Constant-time comparison for secrets.

    hmac.compare_digest prevents timing attacks.
    """
    return hmac.compare_digest(provided.encode(), expected.encode())


def safe_crypto_proper_hashing(password: str, salt: bytes) -> bytes:
    """SAFE: Using proper password hashing with salt.

    PBKDF2 with SHA256 and sufficient iterations is secure.
    """
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)


# =============================================================================
# EXPECTED: All functions should return NO vulnerabilities
# =============================================================================

SAFE_FUNCTIONS = {
    "sql": [
        "safe_sql_parameterized_tuple",
        "safe_sql_parameterized_named",
        "safe_sql_executemany",
        "safe_sql_hardcoded_literal",
        "safe_sql_integer_cast",
    ],
    "command": [
        "safe_subprocess_list_args",
        "safe_subprocess_shlex_split",
        "safe_os_execvp",
        "safe_hardcoded_command",
    ],
    "xss": [
        "safe_xss_html_escape",
        "safe_xss_html_escape_with_quote",
        "safe_xss_text_content_only",
        "safe_xss_integer_only",
    ],
    "path": [
        "safe_path_resolve_and_check",
        "safe_path_basename_only",
        "safe_path_whitelist",
    ],
    "crypto": [
        "safe_crypto_secrets_token",
        "safe_crypto_hmac_compare",
        "safe_crypto_proper_hashing",
    ],
}

EXPECTED_VERDICTS = {func: "SAFE" for category in SAFE_FUNCTIONS.values() for func in category}
MIN_CONFIDENCE_FOR_SAFE = 0.85
