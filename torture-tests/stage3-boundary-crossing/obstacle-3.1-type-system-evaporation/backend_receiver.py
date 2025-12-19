"""
=============================================================================
OBSTACLE 3.1: TYPE SYSTEM EVAPORATION (Backend)
=============================================================================

PURPOSE: Demonstrate the backend blindly trusts the frontend's TypeScript types.
The frontend had a union type {'admin' | 'user'}, but that was erased at JSON
serialization. This Python service receives RAW, UNVALIDATED JSON strings.

INTENTIONAL VULNERABILITIES (DO NOT ADD VALIDATION):

1. No Server-Side Enum Validation (line 29):
   - body.get("role") returns whatever string was sent
   - Could be "admin", "user", "superadmin", "hacker", ANYTHING
   - TypeScript's Role type is MEANINGLESS here

2. Partial Superadmin Check (line 33):
   - Blocks "superadmin" but NOT other escalation attempts
   - What about "Administrator", "root", "ADMIN"?
   - Demonstrates incomplete validation

3. Trusting External JSON (line 37):
   - Backend assumes the union {'admin' | 'user'} is enforced elsewhere
   - This assumption is WRONG - frontend types don't enforce runtime
   - Stores unvalidated role directly

EXPECTED BEHAVIOR (PASS):
- Flag body.get("role") as TAINTED - it comes from external JSON
- Recognize lack of server-side enum validation
- NOT trust frontend type annotations
- Detect privilege escalation risk

FAILURE MODE (ELIMINATION):
- Trusting frontend-side TypeScript types
- Missing the unvalidated role assignment
- Not flagging the JSON parsing boundary
=============================================================================
"""
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.post("/api/boundary/role")
def update_role():
    """INTENTIONAL: No server-side enum validation - trusts TypeScript types."""
    body = request.get_json(force=True, silent=True) or {}
    # VULNERABILITY: No validation - trusts frontend TypeScript compile-time checks
    role = body.get("role")  # This could be ANYTHING!
    user_id = body.get("userId")

    # INTENTIONAL: Partial protection - blocks one value but not others
    if role == "superadmin":
        # Role that does not exist in the frontend type but is trivial to send over the wire.
        return jsonify({"error": "privilege escalation detected"}), 403

    # DANGER: Backend assumes the union {'admin' | 'user'} is enforced elsewhere.
    # Frontend TypeScript types do NOT enforce runtime values!
    return jsonify({"userId": user_id, "storedRole": role, "source": "unvalidated-json"})


if __name__ == "__main__":
    # Fixture server; keep debug disabled to avoid Werkzeug console exposure during analysis.
    app.run(port=8081)
