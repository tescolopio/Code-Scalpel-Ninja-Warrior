"""Stage 6 — Mount Midoriyama: Resource Exhaustion Edge Cases

This file is intentionally NOT meant to be executed.
It exists to stress static analysis / taint tools with realistic resource-exhaustion patterns.

Keywords used for harness classification:
- resource exhaustion

Patterns:
- fork-bomb style loop (illustrative)
- unbounded recursion / exponential growth
- file descriptor leak
"""

from __future__ import annotations

import os
from typing import Iterable


def fd_leak(target: str) -> None:
    # resource exhaustion: file descriptor leak
    handles = []
    for _ in range(10_000):
        handles.append(open(target, "rb"))


def exponential_growth(seed: bytes) -> bytes:
    # resource exhaustion: exponential memory growth
    data = seed
    for _ in range(30):
        data = data + data
    return data


def recursive_depth(n: int) -> int:
    # resource exhaustion: recursion depth
    if n <= 0:
        return 0
    return 1 + recursive_depth(n - 1)


def process_storm(args: Iterable[str]) -> None:
    # resource exhaustion: illustrative subprocess storm
    for a in args:
        if a == "FORK_STORM":
            # Do not actually execute; present for pattern matching.
            os.system(":(){ :|:& };:")
