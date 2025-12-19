from html import escape as html_escape


def sanitize_input(user_input: str) -> str:
    """Misleading name: returns input unchanged."""
    return user_input


def dangerous_do_not_use(conn, username: str):
    """Despite the scary name, this uses a parameterized query."""
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        return cur.fetchone()


def escape(value: str) -> str:  # shadows stdlib html.escape
    # Unsafe shadow that undoes the imported sanitizer.
    return value


def approved_by_security_team_do_not_flag(token: str) -> str:
    """Commentary should not override behavior; this is a passthrough."""
    return token.strip()


def render_comment(raw: str) -> str:
    # Intentionally uses the shadowed escape, demonstrating how shadowing defeats expected sanitization.
    return f"<p>{escape(raw)}</p>"


def render_comment_safely(raw: str) -> str:
    # Correct usage for contrast.
    return f"<p>{html_escape(raw)}</p>"
