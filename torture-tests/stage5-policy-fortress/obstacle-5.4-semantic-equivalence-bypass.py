"""
=============================================================================
OBSTACLE 5.4: SEMANTIC EQUIVALENCE BYPASS
=============================================================================

PURPOSE: Test that policies apply at SEMANTIC level, not just literal strings.
Different syntax can have identical destructive effect. Policy engines must
understand INTENT, not just pattern-match specific keywords.

INTENTIONAL SEMANTIC EQUIVALENTS (ALL SHOULD BE FLAGGED):

1. TRUNCATE vs DELETE (line 42 vs 47):
   - TRUNCATE TABLE users: Removes all rows, resets identity
   - DELETE FROM users: Removes all rows, keeps identity
   - SEMANTIC EFFECT: Both destroy all user data!
   - Policy on "DELETE" must also catch "TRUNCATE"

2. Shell Command Equivalents (line 51):
   - find /data -delete: Deletes all files in /data
   - rm -rf /data: Also deletes all files in /data
   - SEMANTIC EFFECT: Both cause data destruction!
   - Different syntax, identical destruction

3. Policy Bypass Strategy:
   - If policy blocks "DELETE FROM users"
   - Attacker uses "TRUNCATE TABLE users" instead
   - If policy blocks "rm -rf"
   - Attacker uses "find -delete" instead

EXPECTED BEHAVIOR (PASS):
- Recognize TRUNCATE as semantically equivalent to DELETE-all
- Recognize find -delete as semantically equivalent to rm -rf
- Apply destructive-operation policies to ALL variants
- Understand intent, not just literal syntax

FAILURE MODE (ELIMINATION):
- Only pattern-matching "DELETE FROM"
- Missing TRUNCATE as destructive
- Only pattern-matching "rm -rf"
- Missing find -delete as destructive
- Literal string matching instead of semantic analysis
=============================================================================
"""

import subprocess


def truncate_users(conn) -> None:
    """DESTRUCTIVE: Equivalent to deleting all rows - bypasses DELETE policy!"""
    conn.execute("TRUNCATE TABLE users")  # DANGER: Destroys all user data!


def delete_users(conn) -> None:
    """DESTRUCTIVE: Classic pattern that policies often catch."""
    conn.execute("DELETE FROM users")  # DANGER: Destroys all user data!


def wipe_data_via_shell() -> None:
    """DESTRUCTIVE: Same effect as rm -rf /data - bypasses rm policy!"""
    subprocess.check_call(["find", "/data", "-delete"])  # DANGER: Destroys all data!
