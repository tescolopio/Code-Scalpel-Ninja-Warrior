"""Obstacle 10.14: The Partial Fix

Tests detection of incomplete security fixes that leave vulnerabilities.

Vibe coding often produces partial fixes because:
- Developer fixes the reported case but not variants
- Copy-paste fix only applied to one location
- Fix addresses symptom but not root cause
- Regex/filter doesn't cover all bypass techniques
- Fix applied inconsistently across codebase

PASS CRITERIA:
- Detect incomplete input validation
- Flag bypassed sanitization
- Identify inconsistent security controls
- Find encoding/case bypass opportunities
"""

import re
import html
import os


# =============================================================================
# PARTIAL SQL INJECTION FIXES
# =============================================================================

def partial_sqli_fix_quotes_only(user_input: str) -> str:
    """
    VULNERABLE: Only escapes single quotes.

    Common partial fix: escape ' with ''
    Misses: double quotes, backslashes, numeric injection, etc.
    """
    # "Fixed" by escaping single quotes
    safe_input = user_input.replace("'", "''")
    return f"SELECT * FROM users WHERE name = '{safe_input}'"


def partial_sqli_fix_keyword_blocklist(user_input: str) -> str:
    """
    VULNERABLE: Blocklist approach for SQL keywords.

    Misses: case variations, encoding, comments, alternative syntax.
    """
    blocked = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION"]

    for keyword in blocked:
        if keyword in user_input.upper():
            raise ValueError("SQL keyword detected")

    # Still vulnerable to: SeLeCt, SEL/**/ECT, 0x53454C454354, etc.
    return f"SELECT * FROM users WHERE id = {user_input}"


def partial_sqli_fix_numeric_check(user_input: str) -> str:
    """
    VULNERABLE: Checks if numeric but uses string anyway.

    Validates as number, then uses original string (which might not be).
    """
    # Check if it looks numeric
    if not user_input.isdigit():
        raise ValueError("Must be numeric")

    # BUG: Uses original user_input, not validated int
    # Edge case: "123 OR 1=1" - isdigit fails, but "123" passes
    # Also: leading zeros, negative numbers, etc.
    return f"SELECT * FROM users WHERE id = {user_input}"


def partial_sqli_fix_one_field_only(user_id: str, username: str) -> str:
    """
    VULNERABLE: Fix applied to one field, not the other.

    user_id is parameterized, username is not.
    """
    # user_id properly parameterized
    # username NOT parameterized
    return cursor.execute(
        f"SELECT * FROM users WHERE id = ? AND name = '{username}'",
        (user_id,)
    )


# =============================================================================
# PARTIAL XSS FIXES
# =============================================================================

def partial_xss_fix_angle_brackets(user_input: str) -> str:
    """
    VULNERABLE: Only escapes < and >.

    Misses: attribute injection, javascript: URLs, event handlers.
    """
    safe = user_input.replace("<", "&lt;").replace(">", "&gt;")
    # Still vulnerable in attributes:
    return f'<input value="{safe}" onclick="handler()">'


def partial_xss_fix_script_tag(user_input: str) -> str:
    """
    VULNERABLE: Only removes <script> tags.

    Misses: event handlers, javascript:, data:, other tags.
    """
    safe = re.sub(r'<script[^>]*>.*?</script>', '', user_input, flags=re.I | re.S)
    # Still vulnerable: <img onerror=alert(1)>, <svg/onload=...>, etc.
    return f"<div>{safe}</div>"


def partial_xss_fix_html_escape_once(user_input: str) -> str:
    """
    VULNERABLE: HTML escapes then uses in JavaScript context.

    HTML escaping doesn't protect in JS string context.
    """
    safe = html.escape(user_input)
    # HTML-safe but JS-unsafe!
    return f"""
    <script>
        var data = "{safe}";  // Can break out with: \"; alert(1);//
    </script>
    """


def partial_xss_fix_case_sensitive(user_input: str) -> str:
    """
    VULNERABLE: Case-sensitive filter bypass.

    Only blocks lowercase, uppercase bypasses.
    """
    blocked = ["script", "onerror", "onclick", "javascript"]

    for word in blocked:
        if word in user_input:
            user_input = user_input.replace(word, "")

    # Bypassed with: SCRIPT, Script, sCrIpT, etc.
    return f"<div>{user_input}</div>"


# =============================================================================
# PARTIAL COMMAND INJECTION FIXES
# =============================================================================

def partial_cmdi_fix_semicolon(user_input: str) -> str:
    """
    VULNERABLE: Only blocks semicolons.

    Misses: |, &, $(), ``, newlines, etc.
    """
    if ";" in user_input:
        raise ValueError("Invalid character")

    # Still injectable via: | cat /etc/passwd, & cat /etc/passwd, etc.
    return os.popen(f"echo {user_input}").read()


def partial_cmdi_fix_common_chars(user_input: str) -> str:
    """
    VULNERABLE: Blocklist of common shell metacharacters.

    Misses: backticks, $(), newlines, null bytes, etc.
    """
    dangerous = [";", "|", "&", ">", "<"]

    for char in dangerous:
        if char in user_input:
            raise ValueError("Dangerous character")

    # Bypassed with: `whoami`, $(whoami), %0acat%20/etc/passwd
    return os.popen(f"echo {user_input}").read()


def partial_cmdi_fix_quotes(user_input: str) -> str:
    """
    VULNERABLE: Wrapping in quotes without escaping.

    Quotes don't help if input contains quotes.
    """
    # "Safely" wrapped in quotes
    return os.popen(f'echo "{user_input}"').read()
    # Bypass: " && cat /etc/passwd && echo "


# =============================================================================
# PARTIAL PATH TRAVERSAL FIXES
# =============================================================================

def partial_path_fix_dotdot(filename: str) -> str:
    """
    VULNERABLE: Only blocks literal ../

    Misses: ..\\, encoded variants, absolute paths.
    """
    if ".." in filename:
        raise ValueError("Path traversal attempt")

    # Bypassed with: ....// (becomes ../ after replace)
    # Or: ..%2f, ..%252f, absolute /etc/passwd
    return open(f"/uploads/{filename}").read()


def partial_path_fix_replace_once(filename: str) -> str:
    """
    VULNERABLE: Replace ../ only once.

    Input: ....// → Output: ../ (still traverses)
    """
    safe = filename.replace("../", "")
    # Bypassed with: ....// → ../ after replace
    return open(f"/uploads/{safe}").read()


def partial_path_fix_startswith(filename: str) -> str:
    """
    VULNERABLE: Only checks if path starts correctly.

    Doesn't verify resolved path is still within directory.
    """
    if not filename.startswith("/safe/"):
        raise ValueError("Invalid path")

    # Bypassed: /safe/../../etc/passwd
    return open(filename).read()


# =============================================================================
# PARTIAL AUTHENTICATION FIXES
# =============================================================================

def partial_auth_fix_password_only(username: str, password: str) -> bool:
    """
    VULNERABLE: Validates password but trusts username.

    Username used in SQL without validation.
    """
    # Password properly validated
    if len(password) < 8:
        raise ValueError("Password too short")

    # Username NOT validated - SQL injection
    return db.execute(f"SELECT * FROM users WHERE name = '{username}' AND pass = ?", (password,))


def partial_auth_fix_one_endpoint(request):
    """
    VULNERABLE: Auth check on main endpoint, not supporting endpoints.

    /api/users requires auth, /api/users/export doesn't.
    """
    if request.path == "/api/users":
        require_auth(request)

    # Forgotten endpoint - no auth check!
    if request.path == "/api/users/export":
        return export_all_users()


def partial_auth_fix_cookie_sign(request) -> dict:
    """
    VULNERABLE: Signed cookie but signature not verified on all paths.

    Login path verifies, data path trusts.
    """
    # This path verifies signature
    if request.path == "/login":
        verify_cookie_signature(request.cookies)

    # This path FORGOT to verify!
    user_id = request.cookies.get("user_id")  # Unsigned read
    return get_user_data(user_id)


# =============================================================================
# PARTIAL RATE LIMITING FIXES
# =============================================================================

def partial_rate_limit_ip_only(request):
    """
    VULNERABLE: Rate limits by IP only.

    Bypassed with: rotating IPs, proxies, X-Forwarded-For spoofing.
    """
    ip = request.remote_addr

    if rate_limiter.is_limited(ip):
        return "Rate limited"

    # Attacker rotates through proxy IPs
    return process_request(request)


def partial_rate_limit_one_action(request):
    """
    VULNERABLE: Rate limits login but not password reset.

    Attacker brute-forces via password reset instead.
    """
    if request.path == "/login":
        check_rate_limit(request)

    # No rate limit on password reset!
    if request.path == "/reset-password":
        return try_reset_password(request.form["email"])


# =============================================================================
# EXPECTED DETECTIONS
# =============================================================================

PARTIAL_FIX_VULNERABILITIES = {
    "sql_injection": [
        "partial_sqli_fix_quotes_only",
        "partial_sqli_fix_keyword_blocklist",
        "partial_sqli_fix_numeric_check",
        "partial_sqli_fix_one_field_only",
    ],
    "xss": [
        "partial_xss_fix_angle_brackets",
        "partial_xss_fix_script_tag",
        "partial_xss_fix_html_escape_once",
        "partial_xss_fix_case_sensitive",
    ],
    "command_injection": [
        "partial_cmdi_fix_semicolon",
        "partial_cmdi_fix_common_chars",
        "partial_cmdi_fix_quotes",
    ],
    "path_traversal": [
        "partial_path_fix_dotdot",
        "partial_path_fix_replace_once",
        "partial_path_fix_startswith",
    ],
    "authentication": [
        "partial_auth_fix_password_only",
        "partial_auth_fix_one_endpoint",
        "partial_auth_fix_cookie_sign",
    ],
    "rate_limiting": [
        "partial_rate_limit_ip_only",
        "partial_rate_limit_one_action",
    ],
}


# =============================================================================
# HELPER STUBS
# =============================================================================

cursor = type('C', (), {'execute': lambda *a: None})()
class db:
    @staticmethod
    def execute(q, params=None): pass

def require_auth(r): pass
def export_all_users(): pass
def verify_cookie_signature(c): pass
def get_user_data(uid): pass
def check_rate_limit(r): pass
def try_reset_password(e): pass
def process_request(r): pass

class rate_limiter:
    @staticmethod
    def is_limited(ip): return False
