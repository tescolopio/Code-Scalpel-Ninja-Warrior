"""Obstacle 9.6: Confidence Consistency

Tests that Code Scalpel produces CONSISTENT confidence scores across:
- Multiple runs on the same code
- Syntactically equivalent patterns
- Variable renaming
- Comment changes
- Whitespace variations

An LLM without proper tooling might:
- Give different confidence on each analysis
- Let variable names influence confidence
- Let comments affect security verdicts
- Have unstable results on whitespace changes

PASS CRITERIA:
- Same code must produce identical confidence (±0%)
- Equivalent patterns must produce same confidence (±5%)
- Variable renaming must NOT change confidence (±2%)
- Comments must NOT affect confidence (±0%)
- Whitespace must NOT affect confidence (±0%)
"""


# =============================================================================
# BASELINE PATTERNS - Reference confidence scores
# =============================================================================

def baseline_sqli_fstring(user_id):
    """BASELINE: SQL injection via f-string. Record confidence as reference."""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return cursor.execute(query)


def baseline_cmd_injection(cmd):
    """BASELINE: Command injection. Record confidence as reference."""
    import subprocess
    return subprocess.run(cmd, shell=True)


def baseline_xss(user_input):
    """BASELINE: XSS via f-string HTML. Record confidence as reference."""
    return f"<div>{user_input}</div>"


# =============================================================================
# SYNTACTIC EQUIVALENCE TESTS
# Must have SAME confidence as baseline (±5%)
# =============================================================================

def equivalent_sqli_format(user_id):
    """EQUIVALENT to baseline_sqli_fstring - using .format()."""
    query = "SELECT * FROM users WHERE id = {}".format(user_id)
    return cursor.execute(query)


def equivalent_sqli_percent(user_id):
    """EQUIVALENT to baseline_sqli_fstring - using % operator."""
    query = "SELECT * FROM users WHERE id = %s" % user_id
    return cursor.execute(query)


def equivalent_sqli_concat(user_id):
    """EQUIVALENT to baseline_sqli_fstring - using concatenation."""
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    return cursor.execute(query)


def equivalent_sqli_join(user_id):
    """EQUIVALENT to baseline_sqli_fstring - using join."""
    query = "".join(["SELECT * FROM users WHERE id = ", str(user_id)])
    return cursor.execute(query)


# =============================================================================
# VARIABLE RENAMING TESTS
# Must have SAME confidence as baseline (±2%)
# =============================================================================

def renamed_scary_sqli(DANGEROUS_USER_INPUT_DO_NOT_TRUST):
    """Same as baseline but with scary variable name."""
    query = f"SELECT * FROM users WHERE id = {DANGEROUS_USER_INPUT_DO_NOT_TRUST}"
    return cursor.execute(query)


def renamed_safe_sqli(validated_sanitized_safe_input):
    """Same as baseline but with reassuring variable name."""
    query = f"SELECT * FROM users WHERE id = {validated_sanitized_safe_input}"
    return cursor.execute(query)


def renamed_generic_sqli(x):
    """Same as baseline but with minimal variable name."""
    query = f"SELECT * FROM users WHERE id = {x}"
    return cursor.execute(query)


def renamed_verbose_sqli(the_user_identifier_from_request_parameter):
    """Same as baseline but with verbose variable name."""
    query = f"SELECT * FROM users WHERE id = {the_user_identifier_from_request_parameter}"
    return cursor.execute(query)


# =============================================================================
# COMMENT VARIATION TESTS
# Must have SAME confidence as baseline (±0%)
# =============================================================================

def commented_positive_sqli(user_id):
    """SQL injection with positive security comments (must NOT affect verdict)."""
    # This input has been validated by the security team
    # SQL injection is impossible here due to input sanitization
    # SAFE: Using parameterized queries
    query = f"SELECT * FROM users WHERE id = {user_id}"  # STILL VULNERABLE!
    return cursor.execute(query)


def commented_negative_sqli(user_id):
    """SQL injection with negative security comments (must NOT affect verdict)."""
    # WARNING: This code is vulnerable to SQL injection
    # TODO: Fix this security vulnerability immediately
    # DANGER: User input is not sanitized
    query = f"SELECT * FROM users WHERE id = {user_id}"  # VULNERABLE AS EXPECTED
    return cursor.execute(query)


def commented_misleading_sqli(user_id):
    """SQL injection with deliberately misleading comments."""
    # Using parameterized query with ? placeholder
    # Input is escaped using html.escape()
    # Validated against whitelist
    query = f"SELECT * FROM users WHERE id = {user_id}"  # Lie! Still vulnerable
    return cursor.execute(query)


# =============================================================================
# WHITESPACE VARIATION TESTS
# Must have SAME confidence as baseline (±0%)
# =============================================================================

def whitespace_compact_sqli(user_id):
    """Same vulnerability, minimal whitespace."""
    query=f"SELECT * FROM users WHERE id = {user_id}"
    return cursor.execute(query)


def whitespace_spread_sqli(user_id):
    """Same vulnerability, extra whitespace."""
    query    =    f"SELECT * FROM users WHERE id = {user_id}"
    return    cursor.execute(    query    )


def whitespace_multiline_sqli(
        user_id
):
    """Same vulnerability, multiline formatting."""
    query = (
        f"SELECT * FROM users WHERE id = {user_id}"
    )
    return cursor.execute(
        query
    )


def whitespace_extra_blank_lines_sqli(user_id):
    """Same vulnerability, extra blank lines."""


    query = f"SELECT * FROM users WHERE id = {user_id}"


    return cursor.execute(query)


# =============================================================================
# CONSISTENCY VERIFICATION MATRIX
# =============================================================================

CONSISTENCY_GROUPS = {
    "syntactic_equivalence": {
        "baseline": "baseline_sqli_fstring",
        "equivalents": [
            "equivalent_sqli_format",
            "equivalent_sqli_percent",
            "equivalent_sqli_concat",
            "equivalent_sqli_join",
        ],
        "max_confidence_delta": 0.05,  # ±5%
    },
    "variable_renaming": {
        "baseline": "baseline_sqli_fstring",
        "equivalents": [
            "renamed_scary_sqli",
            "renamed_safe_sqli",
            "renamed_generic_sqli",
            "renamed_verbose_sqli",
        ],
        "max_confidence_delta": 0.02,  # ±2%
    },
    "comment_variation": {
        "baseline": "baseline_sqli_fstring",
        "equivalents": [
            "commented_positive_sqli",
            "commented_negative_sqli",
            "commented_misleading_sqli",
        ],
        "max_confidence_delta": 0.00,  # ±0% - comments must have NO effect
    },
    "whitespace_variation": {
        "baseline": "baseline_sqli_fstring",
        "equivalents": [
            "whitespace_compact_sqli",
            "whitespace_spread_sqli",
            "whitespace_multiline_sqli",
            "whitespace_extra_blank_lines_sqli",
        ],
        "max_confidence_delta": 0.00,  # ±0% - whitespace must have NO effect
    },
}


# =============================================================================
# RUN-TO-RUN CONSISTENCY TEST
# Same code analyzed multiple times must produce identical results
# =============================================================================

IDEMPOTENCY_TEST_FUNCTIONS = [
    "baseline_sqli_fstring",
    "baseline_cmd_injection",
    "baseline_xss",
]

IDEMPOTENCY_REQUIRED_RUNS = 5
IDEMPOTENCY_MAX_VARIANCE = 0.00  # Must be IDENTICAL across runs
