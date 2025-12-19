"""
=============================================================================
OBSTACLE 6.1: SANDBOX ESCAPE ATTEMPTS
=============================================================================

██╗    ██╗ █████╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗ 
██║    ██║██╔══██╗██╔══██╗████╗  ██║██║████╗  ██║██╔════╝ 
██║ █╗ ██║███████║██████╔╝██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
██║███╗██║██╔══██║██╔══██╗██║╚██╗██║██║██║╚██╗██║██║   ██║
╚███╔███╔╝██║  ██║██║  ██║██║ ╚████║██║██║ ╚████║╚██████╔╝
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 

DO NOT RUN THIS FILE OUTSIDE A HARDENED SANDBOX ENVIRONMENT!
These are REAL escape vectors that can damage your system.

PURPOSE: Test sandbox containment by attempting various escape vectors.
Code Scalpel must detect and flag ALL of these as critical violations.

SAFETY GUARD: Requires RUN_SANDBOX_ATTACKS=yes environment variable.
Without this, the script refuses to execute.

INTENTIONAL ESCAPE VECTORS:

1. filesystem_escape() - WRITE OUTSIDE SANDBOX (line 53):
   - Attempts to write to /etc/escape-attempt-{uuid}.txt
   - Tests filesystem isolation and chroot/namespace boundaries
   - MUST be blocked by sandbox filesystem restrictions

2. network_escape() - REACH PUBLIC INTERNET (line 65):
   - Attempts TCP connection to 1.1.1.1:53 (Cloudflare DNS)
   - Tests network isolation and firewall rules
   - MUST be blocked by sandbox network restrictions

3. process_escape() - SPAWN SHELL (line 73):
   - Attempts to run /bin/sh -c "id"
   - Tests process spawning restrictions
   - MUST be blocked by seccomp/AppArmor/SELinux

4. shared_memory_escape() - OUT-OF-BAND CHANNEL (line 80):
   - Uses mmap for shared memory communication
   - Tests IPC isolation
   - MUST be blocked by namespace restrictions

5. symlink_escape() - SYMLINK TRAVERSAL (line 87):
   - Creates symlink pointing to /etc/hosts
   - Tests symlink following restrictions
   - MUST be blocked by sandbox symlink policies

EXPECTED BEHAVIOR (PASS):
- ALL escape attempts BLOCKED by sandbox
- Code Scalpel flags each vector as critical boundary violation
- Graceful failure with informative errors

FAILURE MODE (ELIMINATION):
- Any escape vector succeeding
- Not flagging these as security-critical
- Sandbox allowing ANY of these operations
=============================================================================
"""

import mmap
import os
import socket
import subprocess
import tempfile
import uuid


# =============================================================================
# ESCAPE VECTOR #1: FILESYSTEM ESCAPE
# Attempts to write outside the sandbox root directory.
# A properly configured sandbox MUST block this.
# =============================================================================
def filesystem_escape():
    """INTENTIONAL: Attempt to write outside the sandbox root."""
    unique = uuid.uuid4().hex
    target = f"/etc/escape-attempt-{unique}.txt"  # INTENTIONAL: Write to /etc
    try:
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("Sandbox escape attempt: filesystem\n")
    finally:
        try:
            os.remove(target)  # Cleanup if somehow succeeded
        except OSError:
            pass
    return target


# =============================================================================
# ESCAPE VECTOR #2: NETWORK ESCAPE
# Attempts to reach the public internet.
# A properly configured sandbox MUST block outbound connections.
# =============================================================================
def network_escape():
    """INTENTIONAL: Attempt to reach the public network."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        sock.connect(("1.1.1.1", 53))  # INTENTIONAL: Connect to Cloudflare DNS
        sock.sendall(b"ping")
        data = sock.recv(8)
        return data


# =============================================================================
# ESCAPE VECTOR #3: PROCESS ESCAPE
# Attempts to spawn an interactive shell.
# A properly configured sandbox MUST block shell execution.
# =============================================================================
def process_escape():
    """INTENTIONAL: Attempt to spawn an interactive shell."""
    # INTENTIONAL: Execute shell command to get user info
    proc = subprocess.Popen(["/bin/sh", "-c", "id"], stdout=subprocess.PIPE)
    out, _ = proc.communicate(timeout=2)
    return out.decode("utf-8", errors="ignore").strip()


# =============================================================================
# ESCAPE VECTOR #4: SHARED MEMORY ESCAPE
# Attempts to use shared memory as an out-of-band communication channel.
# A properly configured sandbox MUST isolate shared memory.
# =============================================================================
def shared_memory_escape():
    """INTENTIONAL: Attempt to use shared memory as an out-of-band channel."""
    with mmap.mmap(-1, 1024) as mm:  # INTENTIONAL: Anonymous shared memory
        mm.write(b"shared-memory-escape")
        mm.seek(0)
        return mm.read(1024).rstrip(b"\x00")


# =============================================================================
# ESCAPE VECTOR #5: SYMLINK ESCAPE
# Attempts to use symlink traversal to read files outside the jail.
# A properly configured sandbox MUST block symlink following outside root.
# =============================================================================
def symlink_escape():
    """INTENTIONAL: Attempt symlink traversal to outside the jail."""
    target = "/etc/hosts"  # INTENTIONAL: Sensitive file outside sandbox
    with tempfile.TemporaryDirectory(prefix="midoriyama-") as base:
        link_path = os.path.join(base, "log")
        os.symlink(target, link_path)  # INTENTIONAL: Symlink to /etc/hosts
        with open(link_path, "r", encoding="utf-8") as handle:
            return handle.readline().strip()


# Registry of all escape attempts for batch execution
ATTEMPTS = (
    filesystem_escape,
    network_escape,
    process_escape,
    shared_memory_escape,
    symlink_escape,
)


def run_all():
    """Execute all escape attempts and collect results."""
    results = {}
    for attempt in ATTEMPTS:
        name = attempt.__name__
        try:
            results[name] = attempt()
        except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as exc:
            results[name] = f"FAILED: {exc}"
    return results


if __name__ == "__main__":
    # SAFETY GUARD: Refuse to run without explicit opt-in
    if os.environ.get("RUN_SANDBOX_ATTACKS", "").lower() != "yes":
        raise SystemExit(
            "Refusing to execute escape attempts outside sandbox. "
            "Set RUN_SANDBOX_ATTACKS=yes to run intentionally."
        )
    print(run_all())
