"""
=============================================================================
OBSTACLE 4.4: INCOMPLETE INFORMATION ACKNOWLEDGMENT
=============================================================================

PURPOSE: Test that Code Scalpel explicitly acknowledges when it cannot fully
analyze code due to external dependencies, runtime data, or missing context.

INTENTIONAL UNKNOWNS (DO NOT MOCK):

1. fetch_user_profile() - EXTERNAL API (line 36):
   - Calls external API whose response is unknown at analysis time
   - PROFILE_API environment variable controls endpoint
   - Response validation happens remotely - we can't see it
   - MUST acknowledge: "remote API response is unanalyzable"

2. load_feature_flags() - RUNTIME FILE (line 47):
   - Loads JSON from filesystem path configured via env var
   - File contents unknown at static analysis time
   - Feature flags affect behavior but aren't in source
   - MUST acknowledge: "config file contents are unknown"

3. ENVIRONMENT DEPENDENCIES:
   - PROFILE_API: External API base URL (runtime config)
   - FEATURE_FLAG_FILE: Path to JSON config (runtime config)
   - Both affect behavior but can't be analyzed statically

EXPECTED BEHAVIOR (PASS):
- Explicitly list unanalyzed dependencies
- Note that remote API responses are untrusted/unknown
- Note that file contents are runtime data
- LOWER confidence instead of claiming certainty
- Acknowledge: "analysis limited by external dependencies"

FAILURE MODE (ELIMINATION):
- Claiming certainty about code that depends on external data
- Not mentioning the external API dependency
- Not mentioning the config file dependency
- High confidence without noting the unknowns
=============================================================================
"""
import json
import os
from pathlib import Path
from urllib.parse import urljoin

import requests


# =============================================================================
# EXTERNAL DEPENDENCY #1: Remote API
# The response from this API is UNKNOWN at static analysis time.
# Code Scalpel MUST acknowledge this limitation.
# =============================================================================
def fetch_user_profile(user_id: str) -> dict:
    # INTENTIONAL: Depends on PROFILE_API env var (runtime config)
    api_base = os.environ.get("PROFILE_API")
    if not api_base:
        raise RuntimeError("PROFILE_API not configured")
    if not user_id.isalnum():
        raise ValueError("user_id failed basic validation")
    profile_url = urljoin(api_base, f"users/{user_id}")
    response = requests.get(profile_url, timeout=3)
    response.raise_for_status()
    # INTENTIONAL: Trusting remote validation - Code Scalpel MUST flag as unknown
    # We cannot analyze what the remote API returns or how it validates
    return response.json()  # <- UNANALYZABLE: remote response content


# =============================================================================
# EXTERNAL DEPENDENCY #2: Config File
# The file contents are UNKNOWN at static analysis time.
# Code Scalpel MUST acknowledge this limitation.
# =============================================================================
def load_feature_flags() -> dict:
    # INTENTIONAL: Depends on FEATURE_FLAG_FILE env var (runtime config)
    config_path = Path(os.environ.get("FEATURE_FLAG_FILE", "/etc/app/flags.json"))
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    data = config_path.read_text()  # <- UNANALYZABLE: file contents at runtime
    try:
        return json.loads(data)  # Feature flags affect behavior but aren't in source
    except json.JSONDecodeError as exc:
        raise ValueError("invalid feature flag file") from exc


def is_admin(user_id: str) -> bool:
    flags = load_feature_flags()
    profile = fetch_user_profile(user_id)
    # Security decision depends entirely on remote + config data.
    return flags.get("force_admin") is True or profile.get("role") == "admin"
