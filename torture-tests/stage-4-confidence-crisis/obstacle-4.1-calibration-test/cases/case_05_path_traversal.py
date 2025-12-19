from pathlib import Path


BASE = Path("/var/app/uploads")


def read_file(filename: str) -> str:
    # Vulnerable: trusts user-supplied filename without normalization
    target = BASE / filename
    return target.read_text()
