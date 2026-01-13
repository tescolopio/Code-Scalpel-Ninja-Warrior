"""
=============================================================================
OBSTACLE 6.2: RESOURCE EXHAUSTION ASSAULT
=============================================================================

██╗    ██╗ █████╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗ 
██║    ██║██╔══██╗██╔══██╗████╗  ██║██║████╗  ██║██╔════╝ 
██║ █╗ ██║███████║██████╔╝██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
██║███╗██║██╔══██║██╔══██╗██║╚██╗██║██║██║╚██╗██║██║   ██║
╚███╔███╔╝██║  ██║██║  ██║██║ ╚████║██║██║ ╚████║╚██████╔╝
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 

DO NOT SET RESOURCE_ASSAULT_MODE=detonate OUTSIDE A HARDENED SANDBOX!
These attacks WILL exhaust system resources and may crash your machine.

PURPOSE: Test resource limiting and graceful degradation under DoS conditions.
Code Scalpel must detect resource exhaustion patterns and enforce limits.

SAFETY MODES:
- dry-run (default): Bounded iterations, safe for testing
- detonate: INFINITE loops - ONLY use in sandbox with strict cgroups/ulimits!

INTENTIONAL RESOURCE ATTACKS:

1. cpu_spin() - CPU EXHAUSTION (line 60):
   - Infinite tight loop consuming 100% CPU
   - Tests CPU time limits (cgroups cpu.max)
   - MUST be terminated by sandbox CPU quota

2. memory_bomb() - MEMORY EXHAUSTION (line 70):
   - Allocates 1MB chunks until OOM
   - Tests memory limits (cgroups memory.max)
   - MUST be terminated by sandbox memory quota

3. descriptor_storm() - FILE DESCRIPTOR EXHAUSTION (line 85):
   - Opens file descriptors until limit hit
   - Tests ulimit -n / RLIMIT_NOFILE
   - MUST fail gracefully at descriptor limit

4. disk_fill() - DISK QUOTA EXHAUSTION (line 105):
   - Writes continuously to fill disk
   - Tests disk quota limits
   - MUST be stopped by sandbox disk quota

5. thread_bomb() - THREAD EXHAUSTION (line 125):
   - Spawns threads without bound
   - Tests process/thread limits (ulimit -u)
   - MUST fail gracefully at thread limit

EXPECTED BEHAVIOR (PASS):
- ALL attacks contained by resource limits
- Graceful termination, not system crash
- Sandbox limits enforced before system damage
- Code Scalpel flags all patterns as DoS risks

FAILURE MODE (ELIMINATION):
- Any attack exhausting host resources
- System crash or unresponsiveness
- Sandbox failing to enforce limits
=============================================================================
"""

import os
import tempfile
import threading
import time

# Safety mode configuration
MODE = os.environ.get("RESOURCE_ASSAULT_MODE", "dry-run").lower()
BOUNDED_ITERATIONS = int(os.environ.get("RESOURCE_ASSAULT_BUDGET", "10000"))


def _bounded(loop_body):
    """Execute loop body with bounded iterations for dry-run safety."""
    for _ in range(BOUNDED_ITERATIONS):
        loop_body()


# =============================================================================
# ATTACK #1: CPU EXHAUSTION
# Infinite tight loop consuming 100% CPU on one core.
# Sandbox MUST enforce CPU time limits via cgroups.
# =============================================================================
def cpu_spin():
    """INTENTIONAL: Tight loop to consume CPU - DoS attack pattern."""
    if MODE == "detonate":
        while True:  # INTENTIONAL: Infinite loop - CPU exhaustion
            pass
    else:
        _bounded(lambda: None)  # Safe bounded version


# =============================================================================
# ATTACK #2: MEMORY EXHAUSTION (MEMORY BOMB)
# Repeatedly allocates 1MB chunks until out of memory.
# Sandbox MUST enforce memory limits via cgroups.
# =============================================================================
def memory_bomb():
    """INTENTIONAL: Repeatedly allocate memory chunks - OOM attack."""
    blobs = []
    def _alloc():
        blobs.append(b"x" * 1024 * 1024)  # INTENTIONAL: 1MB allocation

    try:
        if MODE == "detonate":
            while True:  # INTENTIONAL: Infinite allocation - memory bomb
                _alloc()
        else:
            _bounded(_alloc)  # Safe bounded version
    finally:
        blobs.clear()  # Cleanup
    return len(blobs)


# =============================================================================
# ATTACK #3: FILE DESCRIPTOR EXHAUSTION
# Opens file descriptors until system limit is hit.
# Sandbox MUST enforce descriptor limits via ulimit.
# =============================================================================
def descriptor_storm():
    """INTENTIONAL: Open file descriptors until limit - FD exhaustion."""
    handles = []
    paths = []
    def _open():
        fd, path = tempfile.mkstemp(prefix="midoriyama-")
        handles.append(fd)
        paths.append(path)

    try:
        if MODE == "detonate":
            while True:  # INTENTIONAL: Infinite FD opening
                _open()
        else:
            _bounded(_open)  # Safe bounded version
    finally:
        for fd in handles:
            os.close(fd)
        for path in paths:
            try:
                os.remove(path)
            except OSError:
                pass
    return len(handles)


# =============================================================================
# ATTACK #4: DISK QUOTA EXHAUSTION
# Writes continuously to fill disk quota.
# Sandbox MUST enforce disk limits via quota or cgroups.
# =============================================================================
def disk_fill():
    """INTENTIONAL: Write repeatedly to fill disk quota - disk DoS."""
    def _cleanup(target: str) -> bool:
        try:
            os.remove(target)
            return True
        except OSError:
            return False

    cleaned = False
    temp_path = tempfile.mkstemp(prefix="midoriyama-disk-")[1]
    chunk = b"flood" * 1024  # INTENTIONAL: 5KB per write
    try:
        with open(temp_path, "wb") as handle:
            if MODE == "detonate":
                while True:  # INTENTIONAL: Infinite disk writes
                    handle.write(chunk)
                    handle.flush()
            else:
                for _ in range(BOUNDED_ITERATIONS):  # Safe bounded version
                    handle.write(chunk)
    finally:
        cleaned = _cleanup(temp_path)
    return {"path": temp_path, "cleaned": cleaned}


# =============================================================================
# ATTACK #5: THREAD BOMB
# Spawns threads without bound until system limit.
# Sandbox MUST enforce process/thread limits via ulimit.
# =============================================================================
def thread_bomb():
    """INTENTIONAL: Spawn threads without bound - thread exhaustion."""
    spawned = []
    def _spawn():
        t = threading.Thread(target=time.sleep, args=(60,), daemon=True)
        t.start()
        spawned.append(t)

    if MODE == "detonate":
        while True:  # INTENTIONAL: Infinite thread spawning
            _spawn()
    else:
        _bounded(_spawn)  # Safe bounded version
    return len(spawned)


# Registry of all attacks for batch execution
ATTACKS = (cpu_spin, memory_bomb, descriptor_storm, disk_fill, thread_bomb)


def run_all():
    """Execute all resource attacks and collect results."""
    results = {}
    for attack in ATTACKS:
        name = attack.__name__
        try:
            results[name] = attack()
        except (OSError, RuntimeError, MemoryError) as exc:
            results[name] = f"FAILED: {exc}"
    return results


if __name__ == "__main__":
    if MODE not in {"dry-run", "detonate"}:
        raise SystemExit(f"Unknown RESOURCE_ASSAULT_MODE '{MODE}'")
    if MODE != "detonate":
        print("Dry-run mode; set RESOURCE_ASSAULT_MODE=detonate for full attack.")
    print(run_all())
