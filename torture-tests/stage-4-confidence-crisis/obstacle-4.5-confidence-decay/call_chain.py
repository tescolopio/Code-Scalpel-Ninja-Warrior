def delta(conn, user_input: str):
    # Direct vulnerability: unsafely interpolates user input.
    query = f"SELECT * FROM secrets WHERE owner = '{user_input}'"
    with conn.cursor() as cur:
        cur.execute(query)
        return cur.fetchall()


def charlie(conn, payload: dict):
    # Passes untrusted payload field directly into delta.
    return delta(conn, payload["actor"])


def bravo(conn, payload: dict):
    # Thin wrapper around charlie.
    return charlie(conn, payload)


def alpha(conn, payload: dict):
    # Entry point; should receive the lowest confidence about downstream issues.
    return bravo(conn, payload)
