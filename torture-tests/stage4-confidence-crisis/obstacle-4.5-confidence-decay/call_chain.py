"""
=============================================================================
OBSTACLE 4.5: CONFIDENCE DECAY TEST
=============================================================================

PURPOSE: Test that confidence decreases monotonically as inference chains
get longer. The further from the direct vulnerability, the lower confidence
should be.

INTENTIONAL VULNERABILITY CHAIN (DO NOT REFACTOR):

Call chain: alpha() -> bravo() -> charlie() -> delta()
                                                  ^
                                                  |
                                        SQL INJECTION HERE

CONFIDENCE EXPECTATIONS:
- delta():  HIGHEST confidence - direct SQL injection vulnerability
- charlie(): HIGH confidence - passes tainted input to delta()
- bravo():   MEDIUM confidence - one step removed
- alpha():   LOWEST confidence - entry point, furthest from vulnerability

The confidence should DECAY as we move up the call chain because:
1. More code could intervene between entry and sink
2. More assumptions about data flow are required
3. The connection becomes increasingly indirect

EXPECTED BEHAVIOR (PASS):
- Confidence(delta) > Confidence(charlie) > Confidence(bravo) > Confidence(alpha)
- Highest confidence only at the direct vulnerability (delta)
- Monotonic decrease along the inference chain
- All functions flagged, but with appropriately decreasing confidence

FAILURE MODE (ELIMINATION):
- Same confidence for all functions in the chain
- Higher confidence for distant callers than direct sink
- Missing any function in the chain
- Non-monotonic confidence (e.g., bravo > charlie)
=============================================================================
"""


# =============================================================================
# DELTA: The DIRECT vulnerability - SQL injection sink
# This should have the HIGHEST confidence in any analysis
# =============================================================================
def delta(conn, user_input: str):
    # INTENTIONAL VULNERABILITY: SQL injection - f-string interpolation
    # This is the DIRECT sink - highest confidence should be here
    query = f"SELECT * FROM secrets WHERE owner = '{user_input}'"  # VULNERABLE!
    with conn.cursor() as cur:
        cur.execute(query)  # Tainted user_input executed as SQL
        return cur.fetchall()


# =============================================================================
# CHARLIE: One step removed - passes tainted data to delta()
# Should have HIGH but LOWER confidence than delta()
# =============================================================================
def charlie(conn, payload: dict):
    # INTENTIONAL: Passes untrusted payload field directly into vulnerable delta()
    # Confidence should be high but less than delta() - indirect connection
    return delta(conn, payload.get("actor", ""))


# =============================================================================
# BRAVO: Two steps removed - thin wrapper around charlie()
# Should have MEDIUM confidence - further from the vulnerability
# =============================================================================
def bravo(conn, payload: dict):
    # INTENTIONAL: Thin wrapper - adds distance from the vulnerability
    # Confidence should be less than charlie() - even more indirect
    return charlie(conn, payload)


# =============================================================================
# ALPHA: Entry point - furthest from the vulnerability
# Should have the LOWEST confidence - most indirect connection
# =============================================================================
def alpha(conn, payload: dict):
    # INTENTIONAL: Entry point at the top of the call chain
    # Confidence should be LOWEST - furthest from delta() vulnerability
    return bravo(conn, payload)
