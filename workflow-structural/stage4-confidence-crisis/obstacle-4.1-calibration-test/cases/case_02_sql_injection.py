def find_user(conn, username: str):
    # Vulnerable: direct string interpolation
    query = f"SELECT * FROM users WHERE username = '{username}'"
    with conn.cursor() as cur:
        cur.execute(query)
        return cur.fetchone()
