"""Obstacle 10.9: Environment Variable Trust

Tests detection of insecure environment variable handling.

Vibe coding often trusts environment variables because:
- "It's not in the code, so it's safe"
- Tutorials show env vars as the "secure" way to handle secrets
- Developers assume env vars are set by trusted sources
- Container environments create false sense of isolation

PASS CRITERIA:
- Detect env vars used in security-sensitive contexts
- Flag missing validation of env var contents
- Identify env var injection vectors
- Find secrets exposed via env vars in logs/errors
"""

import os
import subprocess
import logging


# =============================================================================
# ENVIRONMENT VARIABLE INJECTION
# =============================================================================

def execute_from_env_vulnerable():
    """
    VULNERABLE: Command execution using environment variable.

    If attacker can control environment (e.g., CGI, subprocess),
    they control what command runs.
    """
    cmd = os.environ.get("PROCESS_COMMAND", "echo hello")
    return subprocess.run(cmd, shell=True, capture_output=True)


def build_path_from_env_vulnerable():
    """
    VULNERABLE: Path construction from environment variable.

    Attacker-controlled env var leads to path traversal.
    """
    upload_dir = os.environ.get("UPLOAD_DIR", "/uploads")
    filename = "user_file.txt"
    # No validation that UPLOAD_DIR is actually safe
    full_path = os.path.join(upload_dir, filename)
    return open(full_path, "r").read()


def sql_from_env_vulnerable():
    """
    VULNERABLE: SQL table name from environment variable.

    Even "just a table name" can be injection if unvalidated.
    """
    table_name = os.environ.get("DATA_TABLE", "users")
    # Injection via table name!
    query = f"SELECT * FROM {table_name}"
    return db.execute(query)


def url_from_env_vulnerable():
    """
    VULNERABLE: URL/host from environment variable.

    SSRF via controlled environment variable.
    """
    import requests
    api_host = os.environ.get("API_HOST", "api.internal")
    # Attacker sets API_HOST=attacker.com or localhost:admin-port
    return requests.get(f"http://{api_host}/data")


# =============================================================================
# SECRET EXPOSURE VIA ENV VARS
# =============================================================================

def log_config_vulnerable():
    """
    VULNERABLE: Logging configuration exposes secrets.

    Common pattern: log all config at startup for debugging.
    This exposes secrets in logs.
    """
    config = {
        "database_host": os.environ.get("DB_HOST"),
        "database_password": os.environ.get("DB_PASSWORD"),  # SECRET!
        "api_key": os.environ.get("API_KEY"),  # SECRET!
        "debug_mode": os.environ.get("DEBUG"),
    }
    logging.info(f"Starting with config: {config}")  # Logs secrets!
    return config


def error_message_env_vulnerable(operation: str):
    """
    VULNERABLE: Error messages reveal env var values.

    On error, env var values leak in exception messages.
    """
    db_url = os.environ.get("DATABASE_URL")  # Contains password!
    try:
        connect(db_url)
    except Exception as e:
        # VULNERABLE: Exposes DATABASE_URL in error
        raise RuntimeError(f"Failed to connect to {db_url}: {e}")


def debug_dump_env_vulnerable():
    """
    VULNERABLE: Debug endpoint dumps all env vars.

    Common in development, sometimes left in production.
    """
    if os.environ.get("DEBUG") == "true":
        # Dumps ALL environment variables including secrets
        return dict(os.environ)


# =============================================================================
# MISSING VALIDATION OF ENV VARS
# =============================================================================

def crypto_key_from_env_vulnerable():
    """
    VULNERABLE: Using env var directly as crypto key.

    No validation of key length, format, or entropy.
    """
    from cryptography.fernet import Fernet
    key = os.environ.get("ENCRYPTION_KEY", "")
    # No validation - might be empty, wrong format, weak
    return Fernet(key)


def port_from_env_vulnerable():
    """
    VULNERABLE: Port number from env without validation.

    Could bind to privileged port, invalid port, or port 0.
    """
    port = os.environ.get("SERVER_PORT", "8080")
    # No validation of range, format
    return app.run(port=int(port))


def timeout_from_env_vulnerable():
    """
    VULNERABLE: Timeout from env without bounds checking.

    Attacker sets timeout to 0 or negative = DoS.
    Attacker sets timeout very high = resource exhaustion.
    """
    timeout = int(os.environ.get("REQUEST_TIMEOUT", "30"))
    # No bounds check!
    return requests.get(url, timeout=timeout)


def boolean_from_env_vulnerable():
    """
    VULNERABLE: Boolean from env with wrong parsing.

    Common mistake: any non-empty string is truthy.
    "false", "0", "no" are all truthy strings!
    """
    # WRONG: This checks if string exists, not if it's true
    if os.environ.get("SKIP_AUTH"):
        return True  # Auth skipped even if SKIP_AUTH="false"!

    # Also wrong:
    debug = os.environ.get("DEBUG")
    if debug:  # "false" is truthy!
        enable_debug_mode()


# =============================================================================
# SHELL INJECTION VIA ENV VARS
# =============================================================================

def subprocess_with_env_vulnerable(user_input: str):
    """
    VULNERABLE: Environment passed to subprocess enables injection.

    Even without shell=True, env vars can be exploited.
    """
    env = os.environ.copy()
    env["USER_INPUT"] = user_input  # Attacker controlled

    # Some programs use env vars unsafely
    return subprocess.run(
        ["some_program", "--config"],
        env=env,
        capture_output=True
    )


def ld_preload_vulnerable():
    """
    VULNERABLE: Not sanitizing dangerous env vars.

    LD_PRELOAD, PATH, etc. can be used to hijack execution.
    """
    # Running subprocess without clearing dangerous env vars
    return subprocess.run(
        ["/usr/bin/safe_binary"],
        capture_output=True
        # env=os.environ implicitly - includes LD_PRELOAD, LD_LIBRARY_PATH
    )


# =============================================================================
# DEFAULT VALUE ISSUES
# =============================================================================

def insecure_default_vulnerable():
    """
    VULNERABLE: Insecure default when env var not set.

    Production might not have env var set, falling back to insecure default.
    """
    secret_key = os.environ.get("SECRET_KEY", "development-key-123")
    # If SECRET_KEY not set in prod, uses predictable default!
    return secret_key


def empty_default_vulnerable():
    """
    VULNERABLE: Empty default causes errors or bypasses.

    Missing env var leads to empty password, empty key, etc.
    """
    password = os.environ.get("DB_PASSWORD", "")
    # Empty password might work on misconfigured DB!
    return connect(password=password)


def none_default_vulnerable():
    """
    VULNERABLE: None default used in string operations.

    Missing env var causes TypeError or string "None".
    """
    api_key = os.environ.get("API_KEY")  # Returns None if not set
    # This becomes string "None" in URL
    return f"https://api.example.com?key={api_key}"


# =============================================================================
# EXPECTED DETECTIONS
# =============================================================================

ENV_VAR_VULNERABILITIES = {
    "injection": [
        "execute_from_env_vulnerable",
        "build_path_from_env_vulnerable",
        "sql_from_env_vulnerable",
        "url_from_env_vulnerable",
    ],
    "secret_exposure": [
        "log_config_vulnerable",
        "error_message_env_vulnerable",
        "debug_dump_env_vulnerable",
    ],
    "missing_validation": [
        "crypto_key_from_env_vulnerable",
        "port_from_env_vulnerable",
        "timeout_from_env_vulnerable",
        "boolean_from_env_vulnerable",
    ],
    "shell_injection": [
        "subprocess_with_env_vulnerable",
        "ld_preload_vulnerable",
    ],
    "insecure_defaults": [
        "insecure_default_vulnerable",
        "empty_default_vulnerable",
        "none_default_vulnerable",
    ],
}


# =============================================================================
# HELPER STUBS
# =============================================================================

def connect(password=None, url=None):
    pass

def enable_debug_mode():
    pass

class db:
    @staticmethod
    def execute(query):
        pass

app = type("App", (), {"run": lambda self, port: None})()
