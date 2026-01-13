from pathlib import Path


BASE = Path("/var/app/uploads")


def read_file(filename: str) -> str:
    # Vulnerable: uses user-supplied filename without validation, allowing path traversal
    target = BASE / filename
    return target.read_text()
