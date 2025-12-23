#!/usr/bin/env python3
"""Apply a stage-appropriate Code Scalpel policy/config profile.

This repo keeps multiple profiles under `.code-scalpel/profiles/`.
The active config is the trio of files in `.code-scalpel/`:
- config.json
- policy.yaml
- budget.yaml

Usage:
  python torture-tests/tools/apply_code_scalpel_profile.py --profile relaxed
  python torture-tests/tools/apply_code_scalpel_profile.py --profile strict
  python torture-tests/tools/apply_code_scalpel_profile.py --stage 3

Notes:
- This script only copies files; it does not restart the MCP server.
  If your MCP server caches config at startup, restart it after switching.
"""

from __future__ import annotations

import argparse
import shutil
from datetime import datetime, timezone
from pathlib import Path


def _repo_root() -> Path:
    # torture-tests/tools/apply_code_scalpel_profile.py -> repo root
    return Path(__file__).resolve().parents[2]


def _profile_for_stage(stage: int) -> str:
    if stage <= 4:
        return "relaxed"
    return "strict"


def apply_profile(profile: str) -> None:
    root = _repo_root()
    policy_dir = root / ".code-scalpel"
    src_dir = policy_dir / "profiles" / profile

    if not src_dir.is_dir():
        raise SystemExit(f"Unknown profile '{profile}'. Expected directory: {src_dir}")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = policy_dir / "backups" / f"{timestamp}-{profile}"
    backup_dir.mkdir(parents=True, exist_ok=True)

    for filename in ("config.json", "policy.yaml", "budget.yaml"):
        dst = policy_dir / filename
        if dst.exists():
            shutil.copy2(dst, backup_dir / filename)

        src = src_dir / filename
        if not src.exists():
            raise SystemExit(f"Profile '{profile}' missing required file: {src}")

        shutil.copy2(src, dst)

    (policy_dir / ".active_profile").write_text(profile + "\n", encoding="utf-8")
    print(f"Applied profile: {profile}")
    print(f"Backup saved: {backup_dir}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply Code Scalpel policy/config profile")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--profile", choices=["relaxed", "strict"], help="Profile name")
    group.add_argument("--stage", type=int, choices=range(1, 9), help="Stage number (1-8)")

    args = parser.parse_args()

    profile = args.profile if args.profile else _profile_for_stage(args.stage)
    apply_profile(profile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
