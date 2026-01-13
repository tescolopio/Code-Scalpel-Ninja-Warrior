def find_user(conn, username: str):
    # Safe: parameterized query
    query = "SELECT * FROM users WHERE username = %s"
    with conn.cursor() as cur:
        cur.execute(query, (username,))
        return cur.fetchone()
