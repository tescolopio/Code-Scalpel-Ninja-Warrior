"""
=============================================================================
OBSTACLE 5.3: TRANSITIVE DEPENDENCY ATTACK
=============================================================================

PURPOSE: Test that policy enforcement follows data through helper functions.
The forbidden path travels through several helpers before the write occurs.
Policies must apply at the FINAL SINK, not just where the value originates.

INTENTIONAL POLICY BYPASS PATTERN (DO NOT SHORTCUT):

1. FORBIDDEN Constant (line 37):
   - Defines "/etc/passwd" as the target
   - This is a CRITICAL security-sensitive path
   - Must be flagged regardless of how many hops it travels

2. sanitize_path() - Fake Sanitization (line 41-43):
   - LOOKS like it sanitizes the path
   - But is effectively a NO-OP (just returns input)
   - Should NOT cleanse the policy violation

3. render_payload() - Data Transformation (line 46-47):
   - Wraps the path in a dictionary
   - Path is now at payload["path"] - different location
   - Taint must follow through the transformation

4. file_writer() - Final Sink (line 50-52):
   - ACTUAL write to /etc/passwd happens here
   - Three function calls away from FORBIDDEN constant
   - Policy violation must be detected HERE

5. Call Chain (line 55-60):
   - FORBIDDEN -> sanitize_path -> write_config -> render_payload -> file_writer
   - Each hop must preserve the policy violation

EXPECTED BEHAVIOR (PASS):
- Track FORBIDDEN through all helper functions
- Detect policy violation at file_writer() sink
- NOT be fooled by sanitize_path() no-op
- Flag the /etc/passwd write attempt

FAILURE MODE (ELIMINATION):
- Only checking direct usage of FORBIDDEN
- Losing track at sanitize_path()
- Missing the final sink in file_writer()
- Trusting functions named "sanitize" without analysis
=============================================================================
"""

FORBIDDEN = "/etc/passwd"  # CRITICAL: Policy-forbidden path


def sanitize_path(path: str) -> str:
    """INTENTIONAL: Looks like sanitization but is effectively a no-op."""
    return path  # DOES NOTHING - path passes through unchanged!


def render_payload(path: str) -> dict:
    """INTENTIONAL: Data transformation - policy must follow through dict."""
    return {"path": path, "body": "append demo user"}


def file_writer(path: str, body: str) -> None:
    """FINAL SINK: This is where the actual /etc/passwd write happens!"""
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(body)  # DANGER: Writing to /etc/passwd!


def write_config(path: str) -> None:
    """INTENTIONAL: Intermediate hop in the call chain."""
    payload = render_payload(path)
    file_writer(payload["path"], payload["body"])


def configure_accounting() -> None:
    """INTENTIONAL: Entry point - policy violation starts here."""
    target = sanitize_path(FORBIDDEN)  # Fake sanitization
    write_config(target)  # Triggers the chain to /etc/passwd
