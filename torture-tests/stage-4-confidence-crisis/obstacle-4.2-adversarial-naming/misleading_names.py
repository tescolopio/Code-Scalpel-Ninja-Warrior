"""
=============================================================================
OBSTACLE 4.2: ADVERSARIAL NAMING
=============================================================================

PURPOSE: Test that Code Scalpel bases findings on BEHAVIOR, not names/comments.
Function and variable names are intentionally deceptive to mislead analysis.

INTENTIONAL TRAPS (DO NOT RENAME/"FIX"):

1. sanitize_input() - DOES NOTHING (line 17)
   - Name suggests it sanitizes, but returns input unchanged
   - MUST be flagged as unsafe despite "sanitize" in name

2. dangerous_do_not_use() - ACTUALLY SAFE (line 22)
   - Scary name but uses parameterized query correctly
   - MUST NOT be penalized for having a scary name

3. escape() - SHADOWS STDLIB (line 28)
   - Shadows the imported `html.escape` with an unsafe passthrough
   - Demonstrates how shadowing defeats expected sanitization
   - MUST detect that this is NOT the real html.escape

4. approved_by_security_team_do_not_flag() - MISLEADING COMMENT (line 33)
   - Comment claims security approval, but it's just a passthrough
   - MUST analyze behavior, ignore the name/comment

5. render_comment() - USES SHADOWED escape (line 38)
   - Calls `escape()` thinking it's html.escape
   - Actually calls the unsafe shadow - XSS vulnerability!

6. render_comment_safely() - CORRECT USAGE (line 43)
   - Uses the imported `html_escape` correctly for contrast

EXPECTED BEHAVIOR (PASS):
- Flag sanitize_input() as doing nothing despite the name
- NOT penalize dangerous_do_not_use() for its scary name
- Detect the shadowed escape() function as unsafe
- Identify XSS in render_comment() via the shadowed escape
- Trust render_comment_safely() which uses real html_escape

FAILURE MODE (ELIMINATION):
- Trusting sanitize_input() because of its name
- Flagging dangerous_do_not_use() because of its name
- Missing the escape() shadow and subsequent XSS
=============================================================================
"""
from html import escape as html_escape


# INTENTIONAL TRAP #1: Name says "sanitize" but does nothing!
def sanitize_input(user_input: str) -> str:
    """Misleading name: returns input unchanged. DO NOT TRUST THIS NAME."""
    return user_input  # INTENTIONAL: No sanitization despite the name


# INTENTIONAL TRAP #2: Scary name but actually safe!
def dangerous_do_not_use(conn, username: str):
    """Despite the scary name, this uses a parameterized query (SAFE)."""
    with conn.cursor() as cur:
        # INTENTIONAL: This IS safe - parameterized query prevents SQL injection
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        return cur.fetchone()


# INTENTIONAL TRAP #3: Shadows the stdlib html.escape with unsafe version!
def escape(value: str) -> str:  # INTENTIONAL: shadows stdlib html.escape
    # DANGER: This shadow undoes the imported sanitizer - just returns input!
    return value  # INTENTIONAL: No escaping - this is a trap


# INTENTIONAL TRAP #4: Misleading comment/name suggests security approval
def approved_by_security_team_do_not_flag(token: str) -> str:
    """Commentary should not override behavior; this is just a passthrough."""
    return token.strip()  # INTENTIONAL: Name lies - analyze behavior only


# INTENTIONAL: Uses the SHADOWED escape(), not the real one - XSS vulnerability!
def render_comment(raw: str) -> str:
    # DANGER: `escape` here is our shadow function, not html.escape!
    # This results in XSS because raw input goes directly to HTML
    return f"<p>{escape(raw)}</p>"  # INTENTIONAL XSS via shadowed escape


# CORRECT: Uses the properly imported html_escape - for contrast
def render_comment_safely(raw: str) -> str:
    # This IS safe - uses the real html.escape imported as html_escape
    return f"<p>{html_escape(raw)}</p>"
