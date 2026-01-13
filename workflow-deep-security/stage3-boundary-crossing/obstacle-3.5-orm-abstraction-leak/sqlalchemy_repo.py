"""
=============================================================================
OBSTACLE 3.5: ORM ABSTRACTION LEAK (SQLAlchemy)
=============================================================================

PURPOSE: Demonstrate that ORM "escape hatches" like text() bypass ORM safety.
Developers often assume ORMs prevent SQL injection, but raw SQL constructs
within ORMs are just as dangerous as raw SQL outside of them.

INTENTIONAL SQL INJECTION (DO NOT ADD WHITELIST OR PARAMETERIZE):

1. text() Escape Hatch (line 27):
   - text() tells SQLAlchemy "this is raw SQL, don't touch it"
   - Bypasses ALL ORM safety features
   - Query is string-concatenated, not parameterized

2. Column Name Injection (line 28):
   - sort_column is user-controlled but NOT bound as parameter
   - ORDER BY {sort_column} is direct string interpolation
   - Attacker can inject: "id; DROP TABLE orders; --"

3. Partial Safety Illusion (line 31):
   - status IS properly bound via :status parameter
   - Creates FALSE sense of security
   - Developers may think "we're using parameters" but miss the column

EXPECTED BEHAVIOR (PASS):
- Detect text() as ORM escape hatch requiring scrutiny
- Flag sort_column as SQL injection vector
- Recognize column identifiers can't be parameterized safely
- NOT trust ORM usage implies safety

FAILURE MODE (ELIMINATION):
- Trusting ORM means SQL injection is impossible
- Missing the text() escape hatch
- Only checking value parameters, not identifiers
- Assuming SQLAlchemy prevents all injection
=============================================================================
"""
# INTENTIONAL: Injection surface via ORM escape hatch - do not add whitelisting!
from sqlalchemy import text


def list_orders(session, status: str, sort_column: str):
    """INTENTIONAL: SQL injection via column name in ORDER BY."""
    # DANGER: text() bypasses ORM safety - this is raw SQL!
    # sort_column is NOT a bound parameter - it's string interpolated!
    unsafe_query = text(
        f"SELECT id, status, total_cents FROM orders WHERE status = :status ORDER BY {sort_column}"
    )  # VULNERABILITY: Column identifier injection

    # NOTE: status IS properly bound, but sort_column is INJECTED!
    # This partial safety creates a false sense of security.
    return session.execute(unsafe_query, {"status": status}).fetchall()
