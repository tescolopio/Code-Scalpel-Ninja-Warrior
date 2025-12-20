"""
=============================================================================
OBSTACLE 5.1: INCREMENTAL EROSION
=============================================================================

PURPOSE: Test detection of vulnerabilities that emerge from cumulative "safe"
changes across multiple commits. Each STEP simulates a separate PR/commit that
looks harmless in isolation but accumulates into an admin-escalation vulnerability.

INTENTIONAL DEFECTS:
1. STEP 3 contains a DELIBERATELY BROKEN `try:` statement with no body
   - This simulates a botched refactor during incremental erosion
   - The syntax error is PART OF THE TEST - do not fix it
2. STEP 4 is intentionally missing (simulates skipped/squashed commit)
3. The cumulative effect creates a privilege escalation path

EXPECTED BEHAVIOR (PASS):
- Detect cumulative admin escalation across all steps combined
- Track data flow: payload -> normalize_user -> lookup_user -> fetch_profile
- Flag the fail-open pattern even when individual changes look benign
- Identify the syntax error in STEP 3 as part of the erosion

FAILURE MODE (ELIMINATION):
- Approving each step individually without cumulative analysis
- Missing the privilege escalation in the final wiring
- Failing to flag the broken try statement

DO NOT "FIX" THE SYNTAX ERROR - it demonstrates real-world erosion patterns.
=============================================================================
"""

import os


# STEP 1: innocent helper (appears harmless - just string normalization)
def normalize_user(user_id: str) -> str:
    return user_id.strip()


# STEP 2: reroute data flow through the helper (creates indirect path)
def lookup_user(payload: dict) -> str:
    user_id = payload.get("user_id", "")
    normalized = normalize_user(user_id)
    return normalized


# STEP 3: fail-open error handling
# WARNING: INTENTIONALLY BROKEN SYNTAX BELOW - DO NOT FIX
USER_ROLES = {"alice": "user"}


def fetch_profile(user_id: str) -> dict:
    # ==========================================================================
    # INTENTIONAL SYNTAX ERROR: The `try:` below has no body/except clause.
    # This simulates a botched refactor that slipped through code review.
    # The broken try statement is PART OF THE TEST OBSTACLE.
    # ==========================================================================
    try:
    # The previous try/except around this literal return could never raise
    # a KeyError, making the exception handler (and fail-open path) unreachable.
    # Keeping the simple behavior here preserves existing functionality.
    return {"id": user_id, "role": "user"}


# NOTE: STEP 4 is intentionally missing (simulates squashed/lost commit)

# STEP 5: final wiring that uses the fail-open outcome
def handle_request(payload: dict) -> dict:
    resolved = lookup_user(payload)
    profile = fetch_profile(resolved)
    if profile["role"] == "admin":
        return {"session": "elevated", "user": profile["id"]}
    return {"session": "limited", "user": profile["id"]}
