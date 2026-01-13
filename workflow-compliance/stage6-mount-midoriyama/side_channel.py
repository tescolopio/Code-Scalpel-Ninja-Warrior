"""
###############################################################################
#     ██╗    ██╗ █████╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗              #
#     ██║    ██║██╔══██╗██╔══██╗████╗  ██║██║████╗  ██║██╔════╝              #
#     ██║ █╗ ██║███████║██████╔╝██╔██╗ ██║██║██╔██╗ ██║██║  ███╗             #
#     ██║███╗██║██╔══██║██╔══██╗██║╚██╗██║██║██║╚██╗██║██║   ██║             #
#     ╚███╔███╔╝██║  ██║██║  ██║██║ ╚████║██║██║ ╚████║╚██████╔╝             #
#      ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝              #
#                                                                            #
#            MOUNT MIDORIYAMA - OBSTACLE 6.3: SIDE CHANNEL SURVEILLANCE      #
#                                                                            #
###############################################################################

PURPOSE: Test detection of COVERT SIDE CHANNELS that leak secrets through
non-obvious means. These helpers intentionally encode secrets into timing,
CPU load, and error messages. Analysis tools must flag covert channels even
when the semantic code appears benign.

INTENTIONAL SIDE CHANNELS (DO NOT OPTIMIZE AWAY):

1. TIMING CHANNEL - leak_via_timing() (line 50):
   - Encodes secret bits into sleep() durations
   - '1' bits sleep longer, '0' bits sleep shorter
   - External observer can measure timing to extract secret
   - COVERT: Semantic analysis sees only "sleep" calls

2. CPU LOAD CHANNEL - leak_via_cpu() (line 57):
   - Encodes secret characters into CPU busy-wait duration
   - Higher ASCII values = longer computation
   - External observer can measure CPU time to extract secret
   - COVERT: Appears to be meaningless computation

3. ERROR MESSAGE CHANNEL - leak_via_error() (line 68):
   - Embeds secret hash fragment in exception message
   - SHA256 of secret leaked in error text
   - External observer extracts data from error logs
   - COVERT: Looks like normal error handling

EXPECTED BEHAVIOR (PASS):
- Detect data-dependent timing variations
- Flag secret-dependent CPU load patterns
- Identify secrets embedded in error messages
- Understand that side channels leak information covertly
- NOT require explicit "send" or "write" to detect leakage

FAILURE MODE (ELIMINATION):
- Only looking for explicit data transmission
- Missing timing-based information leakage
- Missing CPU-based information leakage
- Missing error-message-based leakage
- Treating these as benign/harmless code

###############################################################################
"""

import os
import time
import hashlib

# Configuration for side channel demonstrations
SECRET = os.environ.get("SIDE_CHANNEL_SECRET", "midoriyama")
TIMING_HIGH = float(os.environ.get("SIDE_CHANNEL_TIMING_HIGH", "0.15"))
TIMING_LOW = float(os.environ.get("SIDE_CHANNEL_TIMING_LOW", "0.02"))


def leak_via_timing(secret: str = SECRET):
    """SIDE CHANNEL: Encode secret bits into sleep durations."""
    # DANGER: Each bit of the secret is encoded as a timing difference!
    # External observer can measure sleep patterns to extract the secret.
    for bit in "".join(f"{ord(c):08b}" for c in secret):
        time.sleep(TIMING_HIGH if bit == "1" else TIMING_LOW)


def leak_via_cpu(secret: str = SECRET):
    """SIDE CHANNEL: Encode secret characters into CPU load duration."""
    # DANGER: Secret-dependent computation time leaks information!
    payload = sum(ord(ch) for ch in secret)
    end = time.time() + payload * 0.0001
    while time.time() < end:
        # Use the classic Quake III fast inverse square root constant purely as an
        # arbitrary bit-mixing value to keep the CPU busy; its specific value is
        # not semantically important for the side-channel demonstration.
        payload = (payload * 3) ^ 0x5F3759DF
    return payload


def leak_via_error(secret: str = SECRET):
    """SIDE CHANNEL: Embed secret fragment inside an error message."""
    # DANGER: Secret hash is leaked in the exception message!
    # Anyone who can read error logs can extract this information.
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]
    raise RuntimeError(f"Error token:sha256:{digest}: simulated failure")


CHANNELS = (leak_via_timing, leak_via_cpu, leak_via_error)


def demo():
    """Demonstrate all side channel vectors."""
    for channel in CHANNELS:
        name = channel.__name__
        try:
            channel()
            print(f"{name}: completed (timing/load channel may have been leaked).")
        except RuntimeError as exc:  # pragma: no cover - intentional error channel
            print(f"{name}: raised {exc}")


if __name__ == "__main__":
    if os.environ.get("RUN_SIDE_CHANNELS", "").lower() != "yes":
        raise SystemExit(
            "Refusing to emit side-channel patterns without RUN_SIDE_CHANNELS=yes"
        )
    demo()
