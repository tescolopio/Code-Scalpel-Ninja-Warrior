"""
=============================================================================
OBSTACLE 5.5: CONFIGURATION OVERRIDE ATTACK
=============================================================================

PURPOSE: Test handling of configuration precedence that can disable security.
Environment variables can override file configs which override defaults.
Attacker who controls env vars can silently disable all policy enforcement.

INTENTIONAL CONFIG VULNERABILITIES (DO NOT FIX PRECEDENCE):

1. Config Precedence Chain (line 53):
   - DEFAULT_POLICY: Safe defaults (block_eval=True, enforce_admin_mfa=True)
   - file_policy: Loaded from policy.json (can override defaults)
   - env_overrides: From CODE_SCALPEL_POLICY env var (HIGHEST PRIORITY)
   - Attacker controls env -> attacker controls policy!

2. Environment Variable Override (line 50-52):
   - CODE_SCALPEL_POLICY env var can set ANY policy values
   - Setting '{"block_eval": false}' disables eval protection
   - No validation that overrides are safe

3. Silent Policy Disable (line 57-59):
   - dangerous_eval() checks policy before executing
   - If policy.get("block_eval") is False, executes arbitrary code!
   - Env override silently bypasses the safety check

4. The Dangerous Sink (line 62-63):
   - execute_untrusted() runs exec(payload)
   - Only protected by the policy check
   - Policy disabled = arbitrary code execution

EXPECTED BEHAVIOR (PASS):
- Detect that env vars can override security policies
- Flag config merge patterns as potential bypass vectors
- Recognize exec() is only conditionally protected
- Understand config precedence enables policy bypass

FAILURE MODE (ELIMINATION):
- Trusting DEFAULT_POLICY without checking overrides
- Missing the env var -> policy -> exec() chain
- Assuming config files are trusted
- Not detecting configuration-based policy bypass
=============================================================================
"""

import json
import os
from pathlib import Path

# Safe defaults - but these can be OVERRIDDEN!
DEFAULT_POLICY = {"block_eval": True, "enforce_admin_mfa": True}


def load_policy_from_file(path: Path) -> dict:
    """Load policy from file - can override defaults."""
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def effective_policy(config_path: str = "policy.json") -> dict:
    """DANGER: Merge order allows env vars to disable security!"""
    file_policy = load_policy_from_file(Path(config_path))
    raw_env_policy = os.getenv("CODE_SCALPEL_POLICY")  # ATTACKER-CONTROLLED!
    env_policy = raw_env_policy if raw_env_policy else "{}"
    try:
        env_overrides = json.loads(env_policy)
    except json.JSONDecodeError:
        env_overrides = {}
    # VULNERABILITY: env_overrides has HIGHEST PRIORITY - can disable anything!
    merged = {**DEFAULT_POLICY, **file_policy, **env_overrides}
    return merged


def dangerous_eval() -> None:
    """CONDITIONALLY DANGEROUS: Protected only by policy check."""
    policy = effective_policy()
    # VULNERABILITY: If env var sets block_eval=false, this executes!
    if not policy.get("block_eval", True):
        execute_untrusted("print('policy is disabled; executing arbitrary code')")


def execute_untrusted(payload: str) -> None:
    """CRITICAL: Arbitrary code execution - protected only by config!"""
    exec(payload, {})  # DANGER: Runs if policy is overridden!


if __name__ == "__main__":
    # Try: CODE_SCALPEL_POLICY='{"block_eval": false}' python obstacle-5.5-configuration-override.py
    dangerous_eval()
