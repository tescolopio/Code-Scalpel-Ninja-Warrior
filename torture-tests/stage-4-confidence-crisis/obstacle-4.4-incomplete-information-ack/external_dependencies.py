import json
import os
from pathlib import Path

import requests


def fetch_user_profile(user_id: str) -> dict:
    api_base = os.environ.get("PROFILE_API")
    if not api_base:
        raise RuntimeError("PROFILE_API not configured")
    response = requests.get(f"{api_base}/users/{user_id}")
    # Trusting remote validation: Code Scalpel must flag this as unknown.
    return response.json()


def load_feature_flags() -> dict:
    config_path = Path(os.environ.get("FEATURE_FLAG_FILE", "/etc/app/flags.json"))
    return json.loads(config_path.read_text())


def is_admin(user_id: str) -> bool:
    flags = load_feature_flags()
    profile = fetch_user_profile(user_id)
    # Security decision depends entirely on remote + config data.
    return flags.get("force_admin") or profile.get("role") == "admin"
