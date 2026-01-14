"""Obstacle 10.13: Implicit Trust Boundaries

Tests detection of implicit trust assumptions that create vulnerabilities.

Vibe coding often creates implicit trust because:
- "It's internal so it's safe"
- "The frontend already validated this"
- "Only admins can access this endpoint"
- "Our other service always sends valid data"
- "This came from the database so it's clean"

PASS CRITERIA:
- Detect missing server-side validation
- Flag trust of client-side checks
- Identify inter-service trust issues
- Find database data used without sanitization
"""

import json
from typing import Optional


# =============================================================================
# TRUSTING CLIENT-SIDE VALIDATION
# =============================================================================

def process_form_trust_frontend(request) -> dict:
    """
    VULNERABLE: Trusts that frontend validated the data.

    Frontend had validation, so backend skips it.
    Attacker bypasses frontend entirely.
    """
    # "Frontend validates this is a valid email"
    email = request.form.get("email")  # No validation!

    # "Frontend ensures this is between 1-100"
    quantity = request.form.get("quantity")  # No validation!

    # "Frontend only shows valid options"
    product_id = request.form.get("product_id")  # No validation!

    # All values used directly
    return process_order(email, int(quantity), product_id)


def trust_hidden_field(request) -> dict:
    """
    VULNERABLE: Trusts hidden form fields.

    Hidden fields are just as attacker-controlled as visible ones.
    """
    # "Hidden fields can't be modified by users"
    user_id = request.form.get("user_id")  # WRONG!
    is_admin = request.form.get("is_admin")  # WRONG!
    price = request.form.get("price")  # WRONG!

    return complete_purchase(user_id, is_admin == "true", float(price))


def trust_javascript_check(request) -> dict:
    """
    VULNERABLE: Trusts client-side JavaScript authorization.

    JavaScript can be disabled or bypassed.
    """
    # "JavaScript hides this button for non-admins"
    action = request.form.get("action")

    if action == "delete_all_users":
        # No server-side admin check!
        return delete_all_users()


# =============================================================================
# TRUSTING INTERNAL SERVICES
# =============================================================================

def process_internal_api_data(internal_data: dict) -> str:
    """
    VULNERABLE: Trusts data from internal API without validation.

    Internal services can have bugs, be compromised, or be spoofed.
    """
    # "This comes from our internal user service"
    username = internal_data["username"]  # No validation
    user_query = internal_data["search_query"]  # No validation

    # Used directly in SQL
    return f"SELECT * FROM logs WHERE user = '{username}' AND query LIKE '%{user_query}%'"


def trust_service_mesh(data: dict) -> dict:
    """
    VULNERABLE: Trusts service mesh authentication means data is safe.

    Service mesh authenticates the SERVICE, not the DATA.
    Compromised service sends malicious data through valid channel.
    """
    # "This is from an authenticated internal service via Istio"
    command = data["command"]  # No validation!
    target = data["target"]  # No validation!

    # Executes command from "trusted" service
    import subprocess
    result = subprocess.run([command, target], capture_output=True)
    return {"output": result.stdout.decode()}


def trust_message_queue(message: dict) -> None:
    """
    VULNERABLE: Trusts message queue data.

    Message queues can have poisoned messages or compromised producers.
    """
    # "Only our order service publishes to this queue"
    order_id = message["order_id"]
    sql = message["custom_query"]  # WHAT? Custom query in message?!

    # Executes arbitrary query from queue message
    db.execute(sql)


# =============================================================================
# TRUSTING DATABASE DATA
# =============================================================================

def render_user_profile_from_db(user_id: int) -> str:
    """
    VULNERABLE: Trusts database data is safe for output.

    Data in database might have been injected previously.
    Second-order XSS/injection.
    """
    user = db.query(f"SELECT * FROM users WHERE id = {user_id}").first()

    # "It's from our database, so it's safe"
    return f"""
    <h1>Profile: {user.display_name}</h1>
    <p>Bio: {user.bio}</p>
    <script>var userData = {user.preferences_json};</script>
    """


def use_db_value_in_query(record_id: int) -> list:
    """
    VULNERABLE: Second-order SQL injection.

    Value from database used in another query without sanitization.
    """
    # Get record from first table
    record = db.query(f"SELECT * FROM records WHERE id = {record_id}").first()

    # Use value from record in second query - SECOND ORDER INJECTION
    return db.query(f"SELECT * FROM data WHERE category = '{record.category}'").all()


def execute_stored_query(query_id: int) -> list:
    """
    VULNERABLE: Executing queries stored in database.

    If attacker can insert into the queries table, they control execution.
    """
    # "These are admin-approved queries"
    stored = db.query(f"SELECT sql FROM saved_queries WHERE id = {query_id}").first()

    # Executes whatever was stored
    return db.execute(stored.sql).fetchall()


# =============================================================================
# TRUSTING HEADERS / COOKIES
# =============================================================================

def trust_xff_header(request) -> str:
    """
    VULNERABLE: Trusts X-Forwarded-For header.

    This header is trivially spoofable by clients.
    """
    # "This is set by our load balancer"
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    # IP used in security decision
    if client_ip.startswith("10."):
        return admin_panel()  # Spoofed IP bypasses check!

    return "Access denied"


def trust_referer_header(request) -> str:
    """
    VULNERABLE: Trusts Referer header for authorization.

    Referer header is easily spoofed.
    """
    referer = request.headers.get("Referer", "")

    # "Only requests from our admin page can access this"
    if "/admin/" in referer:
        return delete_all_data()  # Spoofed referer!

    return "Forbidden"


def trust_custom_header(request) -> dict:
    """
    VULNERABLE: Trusts custom header for authentication.

    Custom headers can be set by anyone.
    """
    # "Our mobile app sets this header"
    api_key = request.headers.get("X-Mobile-API-Key")
    user_id = request.headers.get("X-User-ID")

    if api_key == "mobile-app-key-123":
        # Attacker sends same header, claims to be any user
        return get_user_data(user_id)


def trust_cookie_claims(request) -> dict:
    """
    VULNERABLE: Trusts unsigned cookie values.

    Cookies without signatures/encryption are attacker-controlled.
    """
    # "We set this cookie on login"
    user_role = request.cookies.get("user_role", "guest")
    user_id = request.cookies.get("user_id", "0")

    # Attacker modifies cookies
    if user_role == "admin":
        return admin_data()

    return user_data(user_id)


# =============================================================================
# TRUSTING FILE METADATA
# =============================================================================

def trust_content_type(request) -> str:
    """
    VULNERABLE: Trusts Content-Type header for file type.

    Client controls Content-Type - can upload malicious files.
    """
    content_type = request.headers.get("Content-Type")

    # "Only accept images"
    if content_type.startswith("image/"):
        # Attacker sends malware with image/png Content-Type
        save_file(request.data, content_type)
        return "Uploaded"

    return "Only images allowed"


def trust_filename_extension(filename: str, data: bytes) -> str:
    """
    VULNERABLE: Trusts filename extension from client.

    Filename is client-controlled, extension can lie.
    """
    if filename.endswith((".jpg", ".png", ".gif")):
        # Attacker: "malware.php.jpg" or "malware.jpg" (actually PHP)
        with open(f"/uploads/{filename}", "wb") as f:
            f.write(data)
        return "Uploaded"

    return "Invalid file type"


# =============================================================================
# EXPECTED DETECTIONS
# =============================================================================

IMPLICIT_TRUST_VULNERABILITIES = {
    "client_side_trust": [
        "process_form_trust_frontend",
        "trust_hidden_field",
        "trust_javascript_check",
    ],
    "internal_service_trust": [
        "process_internal_api_data",
        "trust_service_mesh",
        "trust_message_queue",
    ],
    "database_trust": [
        "render_user_profile_from_db",
        "use_db_value_in_query",
        "execute_stored_query",
    ],
    "header_cookie_trust": [
        "trust_xff_header",
        "trust_referer_header",
        "trust_custom_header",
        "trust_cookie_claims",
    ],
    "file_metadata_trust": [
        "trust_content_type",
        "trust_filename_extension",
    ],
}


# =============================================================================
# HELPER STUBS
# =============================================================================

def process_order(*args): pass
def complete_purchase(*args): pass
def delete_all_users(): pass
def admin_panel(): pass
def delete_all_data(): pass
def get_user_data(uid): pass
def admin_data(): pass
def user_data(uid): pass
def save_file(*args): pass

class db:
    @staticmethod
    def query(q): return type('Q', (), {'first': lambda: type('R', (), {'category': '', 'display_name': '', 'bio': '', 'preferences_json': '', 'sql': ''})(), 'all': lambda: []})()
    @staticmethod
    def execute(q): return type('R', (), {'fetchall': lambda: []})()
