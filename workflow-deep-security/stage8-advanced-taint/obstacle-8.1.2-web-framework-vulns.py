"""
###############################################################################
#     STAGE 8.1.2: WEB FRAMEWORK VULNERABILITIES                             #
#     Test: Framework-specific security patterns (Flask/Django/FastAPI)      #
###############################################################################

PURPOSE: Detect vulnerabilities in common Python web framework patterns.

CATEGORIES:
- Route injection
- Template rendering vulnerabilities
- Session manipulation
- Cookie tampering
- Authentication bypass
- Authorization flaws
"""

from flask import Flask, request, render_template_string, session, redirect
from django.http import HttpResponse
from django.shortcuts import render

# ===========================================================================
# FLASK VULNERABILITIES
# ===========================================================================

app = Flask(__name__)

@app.route('/search')
def flask_xss_search():
    """Reflected XSS via Flask request parameter."""
    query = request.args.get('q', '')
    # VULNERABLE: Unescaped user input in HTML
    return f"<h1>Search results for: {query}</h1>"

@app.route('/template')
def flask_ssti():
    """Server-Side Template Injection in Flask."""
    template = request.args.get('template', 'default')
    # VULNERABLE: User input as template string
    return render_template_string(template)

@app.route('/redirect')
def flask_open_redirect():
    """Open redirect vulnerability."""
    next_url = request.args.get('next', '/')
    # VULNERABLE: Unvalidated redirect
    return redirect(next_url)

@app.route('/file')
def flask_path_traversal():
    """Path traversal in file serving."""
    filename = request.args.get('file')
    # VULNERABLE: No path validation
    with open(f'/var/www/files/{filename}', 'r') as f:
        return f.read()

@app.route('/sql')
def flask_sql_injection():
    """SQL injection in Flask route."""
    user_id = request.args.get('id')
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: String interpolation in SQL
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return str(cursor.fetchone())

# ===========================================================================
# DJANGO VULNERABILITIES
# ===========================================================================

def django_xss_view(request):
    """Django XSS via unescaped variable."""
    name = request.GET.get('name', '')
    # VULNERABLE: Unescaped HTML
    html = f"<div>Welcome, {name}!</div>"
    return HttpResponse(html)

def django_sql_raw(request):
    """Django raw SQL injection."""
    from django.db import connection
    user_input = request.GET.get('search', '')
    cursor = connection.cursor()
    # VULNERABLE: Raw SQL with string formatting
    cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{user_input}%'")
    return HttpResponse(str(cursor.fetchall()))

def django_command_injection(request):
    """Command injection in Django view."""
    import subprocess
    filename = request.POST.get('filename', '')
    # VULNERABLE: shell=True with user input
    result = subprocess.run(f"grep 'pattern' {filename}", shell=True, capture_output=True)
    return HttpResponse(result.stdout)

# ===========================================================================
# FASTAPI VULNERABILITIES
# ===========================================================================

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse

fastapi_app = FastAPI()

@fastapi_app.get("/search")
async def fastapi_xss(q: str = Query(None)):
    """FastAPI XSS vulnerability."""
    # VULNERABLE: Unescaped user input
    html = f"<html><body><h1>Results: {q}</h1></body></html>"
    return HTMLResponse(content=html)

@fastapi_app.get("/eval")
async def fastapi_code_injection(expr: str = Query(None)):
    """Code injection in FastAPI endpoint."""
    # VULNERABLE: eval() on user input
    result = eval(expr)
    return {"result": result}

@fastapi_app.get("/file/{filepath:path}")
async def fastapi_path_traversal(filepath: str):
    """Path traversal in FastAPI route."""
    # VULNERABLE: Arbitrary file read
    with open(filepath, 'r') as f:
        return {"content": f.read()}

# ===========================================================================
# SESSION & AUTHENTICATION VULNERABILITIES
# ===========================================================================

@app.route('/login', methods=['POST'])
def insecure_session():
    """Session fixation vulnerability."""
    username = request.form.get('username')
    password = request.form.get('password')
    
    # VULNERABLE: SQL injection in auth
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    user = cursor.execute(query).fetchone()
    
    if user:
        # VULNERABLE: Session fixation - not regenerating session ID
        session['user_id'] = user[0]
        session['is_admin'] = user[3]  # Direct trust of DB value
        return "Login successful"
    return "Login failed"

@app.route('/admin')
def insecure_authz():
    """Insecure authorization check."""
    # VULNERABLE: Client-controlled authorization
    is_admin = request.cookies.get('is_admin', 'false')
    if is_admin == 'true':
        return "Admin panel"
    return "Access denied"

# ===========================================================================
# DESERIALIZATION & PICKLE
# ===========================================================================

@app.route('/restore', methods=['POST'])
def pickle_deserialize():
    """Unsafe deserialization of session data."""
    import pickle
    import base64
    
    session_data = request.form.get('session')
    # VULNERABLE: Pickle deserialization of user input
    decoded = base64.b64decode(session_data)
    data = pickle.loads(decoded)
    return str(data)

# ===========================================================================
# MASS ASSIGNMENT
# ===========================================================================

class UserProfile:
    def __init__(self):
        self.username = ""
        self.email = ""
        self.is_admin = False
        self.credits = 0

@app.route('/update_profile', methods=['POST'])
def mass_assignment():
    """Mass assignment allowing privilege escalation."""
    profile = UserProfile()
    
    # VULNERABLE: Blindly updating all fields from user input
    for key, value in request.form.items():
        if hasattr(profile, key):
            setattr(profile, key, value)  # User can set is_admin=True
    
    return f"Profile updated: {profile.__dict__}"

# ===========================================================================
# XXE IN WEB CONTEXT
# ===========================================================================

@app.route('/parse_xml', methods=['POST'])
def xxe_upload():
    """XXE vulnerability in XML upload."""
    import xml.etree.ElementTree as ET
    
    xml_data = request.data.decode('utf-8')
    # VULNERABLE: No XXE protection
    tree = ET.fromstring(xml_data)
    return str(tree)

# ===========================================================================
# SSRF IN WEB CONTEXT
# ===========================================================================

@app.route('/fetch')
def ssrf_fetch():
    """SSRF allowing internal network access."""
    import urllib.request
    
    url = request.args.get('url')
    # VULNERABLE: No URL validation
    response = urllib.request.urlopen(url)
    return response.read()

"""
EXPECTED DETECTIONS:
1. flask_xss_search - XSS (CWE-79)
2. flask_ssti - SSTI (CWE-1336)
3. flask_open_redirect - Open Redirect (CWE-601)
4. flask_path_traversal - Path Traversal (CWE-22)
5. flask_sql_injection - SQL Injection (CWE-89)
6. django_xss_view - XSS (CWE-79)
7. django_sql_raw - SQL Injection (CWE-89)
8. django_command_injection - Command Injection (CWE-78)
9. fastapi_xss - XSS (CWE-79)
10. fastapi_code_injection - Code Injection (CWE-94)
11. fastapi_path_traversal - Path Traversal (CWE-22)
12. insecure_session - SQL Injection (CWE-89)
13. insecure_authz - Insecure Authorization (CWE-639)
14. pickle_deserialize - Unsafe Deserialization (CWE-502)
15. mass_assignment - Mass Assignment (CWE-915)
16. xxe_upload - XXE (CWE-611)
17. ssrf_fetch - SSRF (CWE-918)

PASS CRITERIA: Detect ≥14 out of 17 vulnerabilities (82%)
"""
