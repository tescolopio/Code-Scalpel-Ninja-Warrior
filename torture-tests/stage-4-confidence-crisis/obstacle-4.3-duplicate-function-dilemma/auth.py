"""
=============================================================================
OBSTACLE 4.3: DUPLICATE FUNCTION DILEMMA (auth.py)
=============================================================================

PURPOSE: Another `validate` function to create ambiguity.
See core.py for full obstacle documentation.

INTENTIONAL: This validate() checks JWT structure but NOT signature.
This is a DIFFERENT validate() from core.py and payments.py.
=============================================================================
"""


# INTENTIONAL: Yet another validate() - this one for JWT tokens
def validate(token: str) -> bool:
    # INTENTIONAL WEAKNESS: Minimal structural check only; does NOT verify signature!
    # This is a security issue, but a DIFFERENT one than other validate() functions
    return bool(token and token.count(".") == 2)
