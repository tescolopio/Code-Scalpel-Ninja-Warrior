"""
=============================================================================
OBSTACLE 1.8: THE VERSION VARIANCE
=============================================================================

PURPOSE: Test handling of language version differences that change semantics.
This code behaves DIFFERENTLY in Python 2 vs Python 3.

INTENTIONAL VERSION AMBIGUITIES (DO NOT "FIX"):

1. DIVISION SEMANTICS (line 28):
   - Python 2: 3/2 = 1 (integer division, truncates)
   - Python 3: 3/2 = 1.5 (true division, float result)
   - Same syntax, completely different behavior!

2. BYTES VS STRING TYPE (lines 35-39):
   - Python 2: bytes is an alias for str, b'\xff' is str
   - Python 3: bytes is distinct from str, b'\xff' is bytes
   - isinstance(b'\xff', str) returns True in Py2, False in Py3

3. PRINT FUNCTION (line 22):
   - Uses `from __future__ import print_function` for Py2 compatibility
   - Without this, `print(...)` is a syntax error in Python 2

EXPECTED BEHAVIOR (PASS):
- Detect or know target Python version
- Apply version-appropriate semantics
- Flag version ambiguity where behavior differs
- NOT silently apply wrong-version rules

FAILURE MODE (ELIMINATION):
- Applying Python 3 semantics to Python 2 code (or vice versa)
- Missing that `result` has different values per version
- Incorrect type analysis for bytes literal
- Treating this as unambiguous code

This file is INTENTIONALLY valid in both Python 2 and 3 with different behavior.
=============================================================================
"""
# Mixed Python 2/3 features to force version-aware parsing and semantics
from __future__ import print_function  # INTENTIONAL: Required for Py2 print()

def divide(a, b):
    # INTENTIONAL: Division behavior differs by Python version
    # Python 2: 3/2 = 1 (integer division)
    # Python 3: 3/2 = 1.5 (true division)
    return a / b  # <- AMBIGUOUS: result depends on interpreter version!

result = divide(3, 2)  # INTENTIONAL: result is 1 in Py2, 1.5 in Py3

print('py3-style print keeps working, but beware of version semantics')
if result == 1:
    print("Python 2 integer division branch (3/2 == 1)")
else:
    print("Python 3 true division branch (3/2 == 1.5)")

# INTENTIONAL: bytes type differs between Python versions
encoded = b'\xff'  # In Py2: this is str; In Py3: this is bytes
if isinstance(encoded, str):
    print("Python 2: bytes are str")  # This branch runs in Python 2
else:
    print("Python 3: bytes are distinct from str")  # This branch runs in Python 3
