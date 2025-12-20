"""
###############################################################################
#     STAGE 8.1.4: INJECTION ATTACK VARIANTS                                 #
#     Test: Advanced injection patterns across multiple contexts             #
###############################################################################

PURPOSE: Test detection of injection vulnerabilities in various contexts.

CATEGORIES:
- Second-order SQL injection
- Blind SQL injection
- Time-based SQL injection
- NoSQL operator injection
- LDAP injection
- XML injection
- JSON injection
- HTTP header injection
"""

import sqlite3
import pymongo
import json
import time

# ===========================================================================
# SQL INJECTION VARIANTS
# ===========================================================================

def sql_injection_simple(user_id: str):
    """Basic SQL injection."""
    conn = sqlite3.connect('app.db')
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query).fetchall()

def sql_injection_like(search: str):
    """SQL injection in LIKE clause."""
    conn = sqlite3.connect('app.db')
    query = f"SELECT * FROM products WHERE name LIKE '%{search}%'"
    return conn.execute(query).fetchall()

def sql_injection_order_by(sort_col: str):
    """SQL injection in ORDER BY clause."""
    conn = sqlite3.connect('app.db')
    query = f"SELECT * FROM users ORDER BY {sort_col}"
    return conn.execute(query).fetchall()

def sql_injection_limit(count: str):
    """SQL injection in LIMIT clause."""
    conn = sqlite3.connect('app.db')
    query = f"SELECT * FROM users LIMIT {count}"
    return conn.execute(query).fetchall()

def sql_injection_union(table: str):
    """UNION-based SQL injection."""
    conn = sqlite3.connect('app.db')
    query = f"SELECT id, name FROM {table}"
    return conn.execute(query).fetchall()

# ===========================================================================
# NOSQL INJECTION
# ===========================================================================

def mongo_where_injection(condition: str):
    """MongoDB $where operator injection."""
    client = pymongo.MongoClient()
    db = client.myapp
    # VULNERABLE: JavaScript code execution in $where
    result = db.users.find({"$where": condition})
    return list(result)

def mongo_regex_injection(pattern: str):
    """MongoDB regex injection."""
    client = pymongo.MongoClient()
    db = client.myapp
    # VULNERABLE: User-controlled regex
    result = db.users.find({"username": {"$regex": pattern}})
    return list(result)

def mongo_operator_injection(username: dict):
    """MongoDB operator injection via dict."""
    client = pymongo.MongoClient()
    db = client.myapp
    # VULNERABLE: User provides dict with operators
    result = db.users.find({"username": username})
    return list(result)

# ===========================================================================
# LDAP INJECTION
# ===========================================================================

def ldap_and_injection(username: str, department: str):
    """LDAP AND filter injection."""
    import ldap
    conn = ldap.initialize("ldap://localhost")
    # VULNERABLE: Unescaped input in LDAP filter
    filter_str = f"(&(uid={username})(ou={department}))"
    results = conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, filter_str)
    return results

def ldap_or_injection(username: str):
    """LDAP OR filter injection."""
    import ldap
    conn = ldap.initialize("ldap://localhost")
    # VULNERABLE: User can inject )(uid=*) to bypass auth
    filter_str = f"(uid={username})"
    results = conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, filter_str)
    return results

# ===========================================================================
# XML INJECTION
# ===========================================================================

def xml_injection(username: str, role: str):
    """XML injection creating malicious elements."""
    # VULNERABLE: Unescaped XML content
    xml = f"""<?xml version="1.0"?>
    <user>
        <name>{username}</name>
        <role>{role}</role>
    </user>"""
    return xml

def xpath_injection(search_term: str):
    """XPath injection in query."""
    import xml.etree.ElementTree as ET
    tree = ET.parse('users.xml')
    # VULNERABLE: User input in XPath expression
    xpath = f".//user[name='{search_term}']"
    return tree.findall(xpath)

# ===========================================================================
# JSON INJECTION
# ===========================================================================

def json_injection(user_input: str):
    """JSON injection via string concatenation."""
    # VULNERABLE: User can break JSON structure
    json_str = f'{{"message": "{user_input}", "status": "ok"}}'
    return json.loads(json_str)

# ===========================================================================
# HTTP HEADER INJECTION
# ===========================================================================

def http_header_injection(username: str):
    """HTTP response splitting via header injection."""
    # VULNERABLE: CRLF injection in HTTP headers
    headers = f"X-Username: {username}\r\n"
    return headers

def cookie_injection(session_id: str):
    """Cookie injection allowing session hijacking."""
    # VULNERABLE: Unvalidated session ID
    return f"Set-Cookie: sessionid={session_id}; Path=/; HttpOnly"

# ===========================================================================
# TEMPLATE INJECTION
# ===========================================================================

def jinja_injection(template_str: str, data: dict):
    """Jinja2 SSTI."""
    from jinja2 import Template
    # VULNERABLE: User-controlled template
    template = Template(template_str)
    return template.render(**data)

def format_string_injection(fmt: str, data: dict):
    """Python format string injection."""
    # VULNERABLE: User-controlled format string
    return fmt.format(**data)

# ===========================================================================
# EMAIL INJECTION
# ===========================================================================

def email_header_injection(recipient: str):
    """Email header injection via SMTP."""
    import smtplib
    from email.mime.text import MIMEText
    
    # VULNERABLE: CRLF in recipient allows injecting headers
    msg = MIMEText("Body")
    msg['To'] = recipient  # User can inject Bcc: attacker@evil.com
    msg['From'] = "sender@example.com"
    msg['Subject'] = "Test"
    
    server = smtplib.SMTP('localhost')
    server.send_message(msg)

# ===========================================================================
# LOG INJECTION
# ===========================================================================

def log_injection(username: str, action: str):
    """Log injection allowing log forgery."""
    import logging
    # VULNERABLE: User can inject newlines to forge log entries
    logging.info(f"User {username} performed {action}")

# ===========================================================================
# EXPRESSION LANGUAGE INJECTION
# ===========================================================================

def el_injection(expression: str):
    """Expression Language injection (Spring EL simulation)."""
    # VULNERABLE: User expression in EL syntax
    return f"${{expression}}"

"""
EXPECTED DETECTIONS:
1-5. SQL Injection variants (5 instances) - CWE-89
6-8. NoSQL Injection variants (3 instances) - CWE-943
9-10. LDAP Injection (2 instances) - CWE-90
11-12. XML/XPath Injection (2 instances) - CWE-643/CWE-91
13. JSON Injection - CWE-91
14. HTTP Header Injection - CWE-113
15. Cookie Injection - CWE-614
16. Jinja SSTI - CWE-1336
17. Format String Injection - CWE-134
18. Email Header Injection - CWE-93
19. Log Injection - CWE-117
20. EL Injection - CWE-917

PASS CRITERIA: Detect ≥16 out of 20 injection types (80%)
"""
