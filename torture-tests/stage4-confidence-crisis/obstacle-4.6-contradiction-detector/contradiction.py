"""
=============================================================================
OBSTACLE 4.6: CONTRADICTION DETECTOR
=============================================================================

PURPOSE: Test detection of conflicting evidence where comments/docstrings
contradict actual code behavior. Code Scalpel must prefer code over comments.

INTENTIONAL CONTRADICTIONS (DO NOT "FIX"):

1. store_password() - DOCSTRING LIES (lines 26-28):
   - Docstring claims: "All passwords are hashed before storage"
   - Actual behavior: Stores password in PLAINTEXT
   - MUST detect this contradiction and flag plaintext storage

2. process_user() - COMMENT LIES (lines 31-36):
   - Parameter named `validated_user_id` implies validation
   - Comment claims validation already happened
   - Actual behavior: No validation whatsoever, trusts input blindly
   - MUST detect that the "validated" claim is false

EXPECTED BEHAVIOR (PASS):
- Detect that store_password() docstring contradicts behavior
- Flag plaintext password storage despite docstring claim
- Detect that process_user() trusts input without validation
- Prefer CODE BEHAVIOR over comments/docstrings/names
- Surface contradictions with appropriately reduced confidence

FAILURE MODE (ELIMINATION):
- Trusting the docstring that says passwords are hashed
- Missing the plaintext password storage vulnerability
- Trusting the "validated" parameter name without verification
- Giving high-confidence results without noting contradictions
=============================================================================
"""
# Storage for passwords - used to demonstrate plaintext storage issue
PASSWORD_STORE: list[str] = []


def store_password(password: str):
    # INTENTIONAL CONTRADICTION: Docstring claims hashing, code stores plaintext!
    """All passwords are hashed before storage."""
    # DANGER: Despite the docstring above, this stores in PLAINTEXT!
    PASSWORD_STORE.append(password)  # INTENTIONAL: No hashing - contradiction!


def process_user(validated_user_id: str, payload: dict):
    # INTENTIONAL CONTRADICTION: Comment claims validation, but none occurs!
    # Comment claims validation already happened, but no validation occurs here.
    user_id = validated_user_id  # INTENTIONAL: Trusts caller blindly - no validation!
    if payload.get("mode") == "secure":
        return f"secure-mode:{user_id}"
    return f"plaintext-mode:{user_id}"
