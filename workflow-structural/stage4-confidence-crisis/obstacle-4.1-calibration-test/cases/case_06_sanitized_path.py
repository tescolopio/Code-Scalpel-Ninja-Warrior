from pathlib import Path

BASE = Path("/var/app/uploads")
ALLOWLIST = {"report.txt", "summary.md"}


def read_file(filename: str) -> str:
    normalized = Path(filename).name
    if normalized not in ALLOWLIST:
        raise ValueError("file not allowed")
    return (BASE / normalized).read_text()
