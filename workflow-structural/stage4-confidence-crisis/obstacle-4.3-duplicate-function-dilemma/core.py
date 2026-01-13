"""
=============================================================================
OBSTACLE 4.3: DUPLICATE FUNCTION DILEMMA (core.py)
=============================================================================

PURPOSE: Test handling of multiple functions with the same name across modules.
This file is part of a set: core.py, auth.py, payments.py - all define validate().

INTENTIONAL AMBIGUITY (DO NOT RENAME):
Multiple `validate` functions exist in this test:
- core.py: BaseHandler.validate() and Handler.validate()
- auth.py: validate() for JWT tokens
- payments.py: validate() for payment data

When someone asks "is validate() secure?" - which one?

EXPECTED BEHAVIOR (PASS):
- Acknowledge multiple `validate` targets exist
- Request disambiguation before giving high-confidence answer
- Analyze each separately if asked to analyze all
- NOT give high-confidence answer about "validate" without context

FAILURE MODE (ELIMINATION):
- Picking one arbitrarily without noting others exist
- High-confidence answer about "validate" without disambiguation
- Missing any of the validate implementations
=============================================================================
"""


class BaseHandler:
    # INTENTIONAL: First validate() - basic type field check
    def validate(self, payload: dict) -> bool:
        # Base expectation: require a type field.
        return "type" in payload


class Handler(BaseHandler):
    # INTENTIONAL: Second validate() - overrides with stricter rules
    def validate(self, payload: dict) -> bool:  # overrides BaseHandler.validate
        # Overrides with stricter rules, but assumes payload is already sanitized.
        return super().validate(payload) and payload.get("type") in {"user", "admin"}
