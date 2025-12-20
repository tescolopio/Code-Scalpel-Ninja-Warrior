"""
###############################################################################
#     STAGE 8.1.1: COMPREHENSIVE VULNERABILITY COVERAGE                       #
#     Requirement: >17 distinct vulnerability types with taint analysis       #
###############################################################################

PURPOSE: Test detection of 22 distinct CWE vulnerability types using
taint-based analysis. Each vulnerability has clear source, propagation, and sink.

VULNERABILITY TYPES TESTED:
1. SQL Injection (CWE-89)
2. NoSQL Injection (CWE-943)
3. Command Injection (CWE-78)
4. LDAP Injection (CWE-90)
5. XPath Injection (CWE-643)
6. Reflected XSS (CWE-79)
7. Stored XSS (CWE-79)
8. DOM-based XSS (CWE-79)
9. Path Traversal (CWE-22)
10. ZIP Slip (CWE-29851)
11. XXE (CWE-611)
12. SSRF (CWE-918)
13. Server-Side Template Injection (CWE-1336)
14. Unsafe Deserialization (CWE-502)
15. Weak Cryptography (CWE-327)
16. Hardcoded Secrets (CWE-798)
17. Open Redirect (CWE-601)
18. Code Injection (CWE-94)
19. ReDoS (CWE-1333)
20. LDAP Injection (CWE-90)
21. Expression Language Injection (CWE-917)
22. Mass Assignment (CWE-915)

PASS CRITERIA: Detect ≥17 out of 22 vulnerability types
"""

import os
import pickle
import hashlib
import subprocess
import xml.etree.ElementTree as ET
from jinja2 import Template
import yaml
import pymongo
import redis
import re

# ===========================================================================
# 1. SQL INJECTION (CWE-89)
# ===========================================================================

def sql_injection_basic(user_id: str) -> str:
    """CWE-89: SQL Injection via string concatenation."""
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return query

def sql_injection_union(table: str, column: str) -> str:
    """CWE-89: SQL Injection enabling UNION attacks."""
    query = f"SELECT {column} FROM {table} ORDER BY 1"
    return query

# ===========================================================================
# 2. NOSQL INJECTION (CWE-943)
# ===========================================================================

def mongodb_injection(username: str, password: str):
    """CWE-943: MongoDB NoSQL injection via dict construction."""
    client = pymongo.MongoClient()
    db = client.userdb
    
    # VULNERABLE: User input directly in query dict
    query = {"username": username, "$where": password}
    result = db.users.find(query)
    return list(result)

def redis_injection(key: str, value: str):
    """CWE-943: Redis command injection."""
    r = redis.Redis()
    # VULNERABLE: Redis command from user input
    r.execute_command(f"SET {key} {value}")

# ===========================================================================
# 3. COMMAND INJECTION (CWE-78)
# ===========================================================================

def command_injection_shell(filename: str) -> str:
    """CWE-78: OS command injection via shell=True."""
    result = subprocess.check_output(f"cat {filename}", shell=True)
    return result.decode()

def command_injection_array(repo_url: str):
    """CWE-78: Command injection via process args."""
    subprocess.run(["git", "clone", repo_url])

# ===========================================================================
# 4. LDAP INJECTION (CWE-90)
# ===========================================================================

def ldap_injection(username: str) -> str:
    """CWE-90: LDAP query injection."""
    import ldap
    conn = ldap.initialize("ldap://localhost")
    
    # VULNERABLE: LDAP filter from user input
    search_filter = f"(uid={username})"
    results = conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
    return str(results)

# ===========================================================================
# 5. XPATH INJECTION (CWE-643)
# ===========================================================================

def xpath_injection(username: str) -> list:
    """CWE-643: XPath query injection."""
    import xml.etree.ElementTree as ET
    tree = ET.parse("users.xml")
    
    # VULNERABLE: XPath with user input
    xpath = f".//user[username='{username}']"
    elements = tree.findall(xpath)
    return elements

# ===========================================================================
# 6-8. CROSS-SITE SCRIPTING (CWE-79)
# ===========================================================================

def reflected_xss(user_input: str) -> str:
    """CWE-79: Reflected XSS in HTML response."""
    return f"<div>You searched for: {user_input}</div>"

def stored_xss_save(comment: str):
    """CWE-79: Stored XSS - saving unescaped content."""
    with open("comments.html", "a") as f:
        f.write(f"<div class='comment'>{comment}</div>")

def dom_xss_javascript(user_data: str) -> str:
    """CWE-79: DOM-based XSS via JavaScript generation."""
    return f"<script>var userData = '{user_data}'; showData(userData);</script>"

# ===========================================================================
# 9. PATH TRAVERSAL (CWE-22)
# ===========================================================================

def path_traversal_file(filename: str) -> str:
    """CWE-22: Path traversal allowing directory escape."""
    with open(f"/var/www/uploads/{filename}", "r") as f:
        return f.read()

def path_traversal_absolute(filepath: str):
    """CWE-22: Path traversal with absolute paths."""
    return open(filepath, "r").read()

# ===========================================================================
# 10. ZIP SLIP (CWE-29851)
# ===========================================================================

def zip_slip_vulnerable(zip_path: str, extract_to: str):
    """CWE-29851: ZIP Slip via unvalidated archive extraction."""
    import zipfile
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        # VULNERABLE: No path validation
        zip_ref.extractall(extract_to)

# ===========================================================================
# 11. XML EXTERNAL ENTITY (CWE-611)
# ===========================================================================

def xxe_vulnerable(xml_content: str):
    """CWE-611: XXE attack via unsafe XML parsing."""
    parser = ET.XMLParser()
    tree = ET.fromstring(xml_content, parser=parser)
    return tree

# ===========================================================================
# 12. SERVER-SIDE REQUEST FORGERY (CWE-918)
# ===========================================================================

def ssrf_vulnerable(url: str) -> str:
    """CWE-918: SSRF allowing internal resource access."""
    import urllib.request
    response = urllib.request.urlopen(url)
    return response.read().decode()

# ===========================================================================
# 13. SERVER-SIDE TEMPLATE INJECTION (CWE-1336)
# ===========================================================================

def ssti_jinja2(user_input: str) -> str:
    """CWE-1336: SSTI in Jinja2 template."""
    template_string = "Hello {{ name }}!"
    template = Template(user_input)  # VULNERABLE: User input as template
    return template.render()

def ssti_format_string(user_input: str, data: dict) -> str:
    """CWE-1336: SSTI via format string."""
    return user_input.format(**data)  # VULNERABLE: User-controlled format string

# ===========================================================================
# 14. UNSAFE DESERIALIZATION (CWE-502)
# ===========================================================================

def pickle_deserialization(data: bytes):
    """CWE-502: Arbitrary code execution via pickle."""
    return pickle.loads(data)  # VULNERABLE: Untrusted pickle data

def yaml_deserialization(yaml_data: str):
    """CWE-502: Arbitrary code execution via YAML."""
    return yaml.load(yaml_data, Loader=yaml.Loader)  # VULNERABLE: Unsafe loader

# ===========================================================================
# 15. WEAK CRYPTOGRAPHY (CWE-327)
# ===========================================================================

def weak_hash_md5(password: str) -> str:
    """CWE-327: Weak cryptographic hash MD5."""
    return hashlib.md5(password.encode()).hexdigest()

def weak_hash_sha1(data: str) -> str:
    """CWE-327: Weak cryptographic hash SHA-1."""
    return hashlib.sha1(data.encode()).hexdigest()

# ===========================================================================
# 16. HARDCODED SECRETS (CWE-798)
# ===========================================================================

def hardcoded_api_key() -> dict:
    """CWE-798: Hardcoded API credentials."""
    return {
        "api_key": "sk-1234567890abcdefghijklmnop",
        "secret": "my_secret_password_123",
        "token": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxx"
    }

# ===========================================================================
# 17. OPEN REDIRECT (CWE-601)
# ===========================================================================

def open_redirect(redirect_url: str) -> str:
    """CWE-601: Unvalidated redirect to user-supplied URL."""
    return f"<meta http-equiv='refresh' content='0;url={redirect_url}'>"

# ===========================================================================
# 18. CODE INJECTION (CWE-94)
# ===========================================================================

def code_injection_eval(user_code: str):
    """CWE-94: Arbitrary code execution via eval()."""
    return eval(user_code)  # VULNERABLE: User input to eval

def code_injection_exec(user_script: str):
    """CWE-94: Arbitrary code execution via exec()."""
    exec(user_script)  # VULNERABLE: User input to exec

def code_injection_compile(source: str):
    """CWE-94: Code injection via compile()."""
    code = compile(source, '<string>', 'exec')  # VULNERABLE
    exec(code)

# ===========================================================================
# 19. REGULAR EXPRESSION DENIAL OF SERVICE (CWE-1333)
# ===========================================================================

def redos_vulnerable(user_input: str) -> bool:
    """CWE-1333: ReDoS via catastrophic backtracking."""
    # VULNERABLE: Exponential backtracking on (a+)+b pattern
    pattern = r"^(a+)+$"
    return bool(re.match(pattern, user_input))

# ===========================================================================
# 20. EXPRESSION LANGUAGE INJECTION (CWE-917)
# ===========================================================================

def el_injection_unsafe(expression: str) -> str:
    """CWE-917: Expression Language injection."""
    # Simulating Spring EL or OGNL
    return f"{{${expression}}}"  # VULNERABLE: User expression in EL syntax

# ===========================================================================
# 21. MASS ASSIGNMENT (CWE-915)
# ===========================================================================

class User:
    def __init__(self):
        self.username = ""
        self.email = ""
        self.is_admin = False

def mass_assignment_vuln(user: User, user_data: dict):
    """CWE-915: Mass assignment allowing privilege escalation."""
    for key, value in user_data.items():
        # VULNERABLE: Blindly setting attributes from user input
        setattr(user, key, value)  # User could set is_admin=True

# ===========================================================================
# 22. LOG INJECTION (CWE-117)
# ===========================================================================

def log_injection(username: str):
    """CWE-117: Log injection allowing log forgery."""
    import logging
    # VULNERABLE: User input directly in log message
    logging.info(f"User login: {username}")  # User could inject newlines

# ===========================================================================
# TEST SUMMARY
# ===========================================================================

"""
EXPECTED DETECTION COUNT: 22 vulnerability types

SEVERITY DISTRIBUTION:
- Critical (6): SQL Injection, Command Injection, Code Injection, 
                Unsafe Deserialization, XXE, SSTI
- High (8): NoSQL Injection, LDAP Injection, XPath Injection, XSS variants,
            SSRF, Path Traversal, ZIP Slip
- Medium (5): Open Redirect, Weak Crypto, Hardcoded Secrets, Mass Assignment, ReDoS
- Low (3): Log Injection, Expression Language Injection, Error Exposure

PASS CRITERIA:
✅ Detect ≥17 out of 22 vulnerability types (77% coverage)
✅ Zero false negatives on Critical severity vulnerabilities
✅ Clear CWE classification for each finding
✅ Accurate line numbers for all detections

FAIL CRITERIA:
❌ Detect <15 vulnerability types (68% coverage)
❌ Miss any Critical severity vulnerability
❌ False positive rate >5%
"""
