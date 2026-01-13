"""
###############################################################################
#     ██╗    ██╗ █████╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗              #
#     ██║    ██║██╔══██╗██╔══██╗████╗  ██║██║████╗  ██║██╔════╝              #
#     ██║ █╗ ██║███████║██████╔╝██╔██╗ ██║██║██╔██╗ ██║██║  ███╗             #
#     ██║███╗██║██╔══██║██╔══██╗██║╚██╗██║██║██║╚██╗██║██║   ██║             #
#     ╚███╔███╔╝██║  ██║██║  ██║██║ ╚████║██║██║ ╚████║╚██████╔╝             #
#      ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝              #
#                                                                            #
#            MOUNT MIDORIYAMA - OBSTACLE 6.4: PATH EXPLOSION PRECIPICE       #
#                                                                            #
###############################################################################

PURPOSE: Stress test symbolic execution and path-sensitive analysis.
The branching below grows EXPONENTIALLY with DEPTH, creating 2^depth paths.
Default depth=12 creates 4,096 paths. Depth=20 creates over 1 MILLION paths.
Analyzers must handle graceful degradation, not hang indefinitely.

INTENTIONAL PATH EXPLOSION (DO NOT SIMPLIFY BRANCHING):

1. EXPONENTIAL BRANCHING - branching_state_machine() (line 54):
   - Each recursion level creates TWO branches (left and right)
   - Total paths = 2^depth (exponential growth)
   - Depth 12 = 4,096 paths
   - Depth 20 = 1,048,576 paths
   - Depth 30 = 1,073,741,824 paths (over a billion!)

2. DATA-DEPENDENT BRANCHING (line 59-64):
   - Branch decision depends on (seed & 1) - odd vs even
   - Symbolic execution must track both possibilities
   - Creates path conditions that accumulate

3. PATH MERGING RESISTANCE (line 67-68):
   - left and right branches are XOR'd together
   - Results CANNOT be merged - must explore both
   - Prevents state merging optimizations

4. MULTIPLE EXPLOSIONS (line 72):
   - explode_paths() calls branching_state_machine() multiple times
   - Each run is independent, multiplying complexity

EXPECTED BEHAVIOR (PASS):
- Recognize exponential path complexity
- Implement timeouts or path budgets
- Gracefully degrade instead of hanging
- Report partial coverage when budget exceeded
- NOT crash or hang on path explosion

FAILURE MODE (ELIMINATION):
- Attempting to explore all paths (will hang/crash)
- No timeout mechanism (infinite execution)
- Crashing instead of graceful degradation
- Claiming complete analysis of exponential space

###############################################################################
"""

import os
import random

# Configuration - DANGER: Increasing DEPTH exponentially increases paths!
DEPTH = int(os.environ.get("PATH_EXPLOSION_DEPTH", "12"))  # 2^12 = 4,096 paths
SEED_MAX = 2 ** 16
BITMASK_32 = (1 << 32) - 1


def branching_state_machine(seed: int, depth: int = DEPTH) -> int:
    """INTENTIONAL: Recursive branching that DOUBLES paths at each level."""
    if depth == 0:
        return seed

    # DATA-DEPENDENT BRANCH: Creates two divergent paths
    if seed & 1:
        # Odd path: mutate via Collatz-style rule
        next_seed = seed * 3 + 1
    else:
        # Even path: invert bits and add a twist (bounded to 32 bits)
        next_seed = ((~seed) & BITMASK_32) ^ depth

    # TWO RECURSIVE BRANCHES: Path count doubles every call!
    # This is the core path explosion - 2^depth total paths
    left = branching_state_machine(next_seed ^ depth, depth - 1)
    right = branching_state_machine(next_seed + depth, depth - 1)
    return left ^ right  # XOR prevents path merging


def explode_paths(runs: int = 3):
    """
    DANGER: Trigger multiple independent explosions to amplify path count.

    Complexity: branching_state_machine is O(2**depth). Depth > 20 will produce
    millions of paths and should be avoided unless the sandbox enforces strict
    time/space limits.
    """
    results = []
    for _ in range(runs):
        seed = random.randint(1, SEED_MAX)
        results.append(branching_state_machine(seed, depth=DEPTH))
    return results


if __name__ == "__main__":
    if os.environ.get("RUN_PATH_EXPLOSION", "").lower() != "yes":
        raise SystemExit(
            "Path explosion demo disabled. Set RUN_PATH_EXPLOSION=yes to run."
        )
    print(explode_paths())
