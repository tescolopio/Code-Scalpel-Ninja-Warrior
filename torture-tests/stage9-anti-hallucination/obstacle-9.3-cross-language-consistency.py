"""Obstacle 9.3: Cross-Language Consistency

Tests that Code Scalpel produces CONSISTENT verdicts for the same
vulnerability pattern implemented in different languages.

An LLM without proper tooling might:
- Miss vulnerabilities in less common languages
- Give different confidence scores for identical patterns
- Fail to recognize patterns in unfamiliar syntax

PASS CRITERIA:
- Same vulnerability pattern in Python, JavaScript, TypeScript, Java
  must all be detected
- Confidence scores should be within 10% of each other
- CWE/vulnerability type classification should be identical
"""

# =============================================================================
# PYTHON: SQL Injection via String Formatting
# =============================================================================

def python_sqli_fstring(user_id):
    """SQL injection via f-string in Python."""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return cursor.execute(query)


def python_sqli_format(user_id):
    """SQL injection via .format() in Python."""
    query = "SELECT * FROM users WHERE id = {}".format(user_id)
    return cursor.execute(query)


def python_sqli_percent(user_id):
    """SQL injection via % formatting in Python."""
    query = "SELECT * FROM users WHERE id = %s" % user_id
    return cursor.execute(query)


# =============================================================================
# PYTHON: Command Injection Patterns
# =============================================================================

import subprocess
import os


def python_cmd_injection_subprocess(cmd):
    """Command injection via subprocess with shell=True."""
    return subprocess.run(cmd, shell=True, capture_output=True)


def python_cmd_injection_os_system(cmd):
    """Command injection via os.system."""
    return os.system(cmd)


def python_cmd_injection_os_popen(cmd):
    """Command injection via os.popen."""
    return os.popen(cmd).read()


# =============================================================================
# PYTHON: XSS Patterns
# =============================================================================

def python_xss_fstring(user_input):
    """XSS via f-string HTML construction."""
    return f"<div>{user_input}</div>"


def python_xss_concatenation(user_input):
    """XSS via string concatenation."""
    return "<div>" + user_input + "</div>"


def python_xss_join(items):
    """XSS via join without escaping."""
    return "<ul>" + "".join(f"<li>{item}</li>" for item in items) + "</ul>"


# =============================================================================
# PYTHON: Path Traversal Patterns
# =============================================================================

def python_path_traversal_open(filename):
    """Path traversal via direct file open."""
    with open(f"/data/{filename}", "r") as f:
        return f.read()


def python_path_traversal_pathlib(filename):
    """Path traversal via pathlib (still vulnerable if not validated)."""
    from pathlib import Path
    return (Path("/data") / filename).read_text()


# =============================================================================
# EXPECTED: Cross-Language Equivalence Groups
# =============================================================================

CROSS_LANGUAGE_EQUIVALENCES = {
    "sql_injection": {
        "python": ["python_sqli_fstring", "python_sqli_format", "python_sqli_percent"],
        # JavaScript equivalents in companion .js file
        # TypeScript equivalents in companion .ts file
        # Java equivalents in companion .java file
        "expected_cwe": "CWE-89",
        "expected_severity": "CRITICAL",
        "max_confidence_delta": 0.10,
    },
    "command_injection": {
        "python": ["python_cmd_injection_subprocess", "python_cmd_injection_os_system",
                   "python_cmd_injection_os_popen"],
        "expected_cwe": "CWE-78",
        "expected_severity": "CRITICAL",
        "max_confidence_delta": 0.10,
    },
    "xss": {
        "python": ["python_xss_fstring", "python_xss_concatenation", "python_xss_join"],
        "expected_cwe": "CWE-79",
        "expected_severity": "HIGH",
        "max_confidence_delta": 0.10,
    },
    "path_traversal": {
        "python": ["python_path_traversal_open", "python_path_traversal_pathlib"],
        "expected_cwe": "CWE-22",
        "expected_severity": "HIGH",
        "max_confidence_delta": 0.10,
    },
}
