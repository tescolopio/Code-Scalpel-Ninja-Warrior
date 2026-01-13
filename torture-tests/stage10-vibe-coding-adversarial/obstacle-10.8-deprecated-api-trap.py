"""Obstacle 10.8: The Deprecated API Trap

Tests detection of deprecated APIs that have known security issues.

Vibe coding often produces code using deprecated APIs because:
- Old StackOverflow answers rank higher in search
- LLMs trained on older code suggest deprecated patterns
- Developers copy from legacy codebases
- Migration guides are ignored

PASS CRITERIA:
- Detect deprecated security-sensitive APIs
- Flag insecure defaults in old APIs
- Identify migration-required patterns
"""

import os
import pickle
import cgi
import md5  # Deprecated since Python 3.x
import sha  # Deprecated since Python 3.x
import commands  # Removed in Python 3
import urllib
import httplib  # Renamed in Python 3
import cStringIO  # Removed in Python 3
import __builtin__  # Renamed in Python 3


# =============================================================================
# DEPRECATED CRYPTO APIs
# =============================================================================

def hash_password_md5_deprecated(password: str) -> str:
    """
    VULNERABLE: Using deprecated md5 module for password hashing.

    md5 module was deprecated in favor of hashlib.
    More importantly, MD5 is cryptographically broken for passwords.
    """
    import md5  # Deprecated
    return md5.new(password).hexdigest()


def hash_data_sha_deprecated(data: str) -> str:
    """
    VULNERABLE: Using deprecated sha module.

    sha module was deprecated in favor of hashlib.
    SHA-1 is also now considered weak for many purposes.
    """
    import sha  # Deprecated
    return sha.new(data.encode()).hexdigest()


def weak_random_deprecated():
    """
    VULNERABLE: Using random module for security-sensitive operations.

    random.random() is not cryptographically secure.
    Should use secrets module instead.
    """
    import random
    # WRONG: Using random for tokens
    token = ''.join(random.choice('abcdef0123456789') for _ in range(32))
    return token


# =============================================================================
# DEPRECATED SHELL/OS APIs
# =============================================================================

def run_command_deprecated(cmd: str) -> str:
    """
    VULNERABLE: Using deprecated commands module.

    commands module was removed in Python 3.
    Also vulnerable to command injection.
    """
    import commands  # Deprecated/Removed
    return commands.getoutput(cmd)


def run_os_popen_deprecated(cmd: str) -> str:
    """
    VULNERABLE: Using deprecated os.popen.

    os.popen is deprecated in favor of subprocess.
    Also vulnerable to command injection.
    """
    return os.popen(cmd).read()


def run_os_system_deprecated(cmd: str) -> int:
    """
    VULNERABLE: os.system with user input.

    os.system is not deprecated but should be avoided.
    subprocess with shell=False is preferred.
    """
    return os.system(cmd)


# =============================================================================
# DEPRECATED URL/HTTP APIs
# =============================================================================

def fetch_url_deprecated(url: str) -> str:
    """
    VULNERABLE: Using deprecated urllib.urlopen.

    Python 2's urllib.urlopen is insecure:
    - No SSL verification by default
    - Follows redirects blindly
    - Can access file:// URLs (LFI)
    """
    import urllib  # Python 2 style
    return urllib.urlopen(url).read()


def make_http_request_deprecated(host: str, path: str) -> str:
    """
    VULNERABLE: Using deprecated httplib module.

    httplib is renamed to http.client in Python 3.
    This old pattern often lacks SSL verification.
    """
    import httplib  # Deprecated name
    conn = httplib.HTTPConnection(host)  # No HTTPS!
    conn.request("GET", path)
    return conn.getresponse().read()


def parse_query_deprecated(query_string: str) -> dict:
    """
    VULNERABLE: Using deprecated cgi.parse_qs.

    cgi.parse_qs is deprecated in favor of urllib.parse.parse_qs.
    The cgi module has various security issues.
    """
    import cgi
    return cgi.parse_qs(query_string)


# =============================================================================
# DEPRECATED SERIALIZATION APIs
# =============================================================================

def load_data_pickle_deprecated(data: bytes) -> object:
    """
    VULNERABLE: Unsafe pickle deserialization.

    pickle.loads on untrusted data is RCE.
    This pattern is extremely common in old code.
    """
    return pickle.loads(data)


def load_data_cpickle_deprecated(data: bytes) -> object:
    """
    VULNERABLE: Using cPickle (Python 2 module).

    cPickle is the C implementation of pickle - same RCE risk.
    Merged into pickle in Python 3.
    """
    import cPickle  # Deprecated/Removed
    return cPickle.loads(data)


def load_yaml_unsafe_deprecated(yaml_str: str) -> dict:
    """
    VULNERABLE: Using yaml.load without Loader.

    yaml.load() without Loader= is deprecated AND insecure.
    Can execute arbitrary Python code via !!python/object.
    """
    import yaml
    return yaml.load(yaml_str)  # Missing: Loader=yaml.SafeLoader


# =============================================================================
# DEPRECATED STRING/IO APIs
# =============================================================================

def format_string_deprecated(template: str, **kwargs) -> str:
    """
    VULNERABLE: Using % formatting with user template.

    Old-style % formatting can cause issues with untrusted templates.
    Format string vulnerabilities possible.
    """
    return template % kwargs


def use_cstringio_deprecated():
    """
    DEPRECATED: cStringIO module removed in Python 3.

    Should use io.StringIO or io.BytesIO.
    """
    import cStringIO
    return cStringIO.StringIO()


def use_stringio_deprecated():
    """
    DEPRECATED: StringIO.StringIO module changed in Python 3.

    Should use io.StringIO.
    """
    import StringIO
    return StringIO.StringIO()


# =============================================================================
# DEPRECATED WEB FRAMEWORK APIs
# =============================================================================

FLASK_DEPRECATED_CODE = '''
from flask import Flask
import flask

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload():
    """
    VULNERABLE: Using deprecated request.data without limits.

    Old Flask pattern - no file size limits, no validation.
    """
    # DEPRECATED: Direct access without validation
    data = flask.request.data  # No size limit!
    filename = flask.request.args.get('filename')  # Unsanitized

    # VULNERABLE: Path traversal
    with open(f'/uploads/{filename}', 'wb') as f:
        f.write(data)

    return 'OK'
'''


DJANGO_DEPRECATED_CODE = '''
from django.utils.html import strip_tags

def clean_html_deprecated(html_content):
    """
    VULNERABLE: Using strip_tags for security.

    strip_tags() is NOT a security function!
    It's for display purposes only.
    XSS is still possible.
    """
    # WRONG: strip_tags doesn't prevent XSS
    return strip_tags(html_content)
'''


# =============================================================================
# DEPRECATED AUTHENTICATION PATTERNS
# =============================================================================

def verify_password_direct_compare(provided: str, stored: str) -> bool:
    """
    VULNERABLE: Direct string comparison for passwords.

    Old pattern before constant-time comparison was standard.
    Vulnerable to timing attacks.
    """
    return provided == stored


def hash_password_md5_salt(password: str, salt: str) -> str:
    """
    VULNERABLE: Old salted MD5 pattern.

    Common in legacy systems, still vulnerable:
    - MD5 is broken
    - Salt concatenation can have issues
    - No key stretching
    """
    import hashlib
    return hashlib.md5((salt + password).encode()).hexdigest()


def generate_session_id_timestamp():
    """
    VULNERABLE: Predictable session ID from timestamp.

    Old pattern using time-based session IDs.
    Completely predictable and insecure.
    """
    import time
    import hashlib
    return hashlib.md5(str(time.time()).encode()).hexdigest()


# =============================================================================
# EXPECTED DETECTIONS
# =============================================================================

DEPRECATED_APIS = {
    "crypto": {
        "md5_module": "HIGH - Use hashlib with SHA-256+",
        "sha_module": "MEDIUM - Use hashlib with SHA-256+",
        "random_for_security": "HIGH - Use secrets module",
    },
    "shell": {
        "commands_module": "HIGH - Removed, use subprocess",
        "os_popen": "HIGH - Use subprocess",
        "os_system": "HIGH - Use subprocess with shell=False",
    },
    "network": {
        "urllib_urlopen": "HIGH - Use requests or urllib3",
        "httplib": "MEDIUM - Use http.client or requests",
        "cgi_parse": "MEDIUM - Use urllib.parse",
    },
    "serialization": {
        "pickle_loads": "CRITICAL - RCE risk",
        "cpickle": "CRITICAL - RCE risk",
        "yaml_load": "CRITICAL - RCE risk without SafeLoader",
    },
    "authentication": {
        "direct_string_compare": "HIGH - Use hmac.compare_digest",
        "md5_password": "CRITICAL - Use bcrypt/argon2",
        "timestamp_session": "CRITICAL - Use secrets.token_hex",
    },
}
