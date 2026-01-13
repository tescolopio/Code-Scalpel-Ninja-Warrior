"""Obstacle 9.5: Quantitative Precision Matrix

Tests that Code Scalpel provides PRECISE quantitative assessments:
- Exact line numbers for vulnerabilities
- Accurate character positions
- Correct call depth counts
- Precise taint path lengths
- Accurate complexity metrics

An LLM without proper tooling might:
- Give approximate line numbers ("around line 50")
- Miss exact positions in complex expressions
- Incorrectly count call chain depth
- Estimate rather than calculate metrics

PASS CRITERIA:
- Line numbers must be EXACT (no off-by-one errors)
- Character positions must be precise to the character
- Call depths must be calculated, not estimated
- Taint paths must trace every hop accurately
"""

import os
import subprocess


# =============================================================================
# LINE NUMBER PRECISION TEST
# =============================================================================

# Lines 1-25 are docstrings and imports

def safe_function_one():  # Line 26
    """This function is safe."""
    return "safe"  # Line 28

def safe_function_two():  # Line 30
    """This function is also safe."""
    x = 1  # Line 32
    y = 2  # Line 33
    return x + y  # Line 34

def vulnerable_at_exact_line(user_input):  # Line 36
    """VULNERABLE: SQL injection at EXACTLY line 40."""
    # Comment line 38
    # Comment line 39
    query = f"SELECT * FROM users WHERE id = {user_input}"  # Line 40 - VULNERABILITY HERE
    return query  # Line 41

def another_safe_function():  # Line 43
    """Safe function after the vulnerable one."""
    return [1, 2, 3]  # Line 45

def multi_vuln_function(a, b, c):  # Line 47
    """Multiple vulnerabilities at specific lines."""
    # Line 49
    sql1 = f"SELECT * FROM t1 WHERE x = {a}"  # Line 50 - VULN #1
    # Line 51
    sql2 = f"SELECT * FROM t2 WHERE y = {b}"  # Line 52 - VULN #2
    # Line 53
    sql3 = f"SELECT * FROM t3 WHERE z = {c}"  # Line 54 - VULN #3
    return [sql1, sql2, sql3]  # Line 55


# =============================================================================
# COLUMN/CHARACTER POSITION PRECISION TEST
# =============================================================================

def column_precision_test(user):  # Line 61
    """Vulnerability at specific column in line."""
    # The f-string starts at different columns
    a = 1; b = 2; query = f"SELECT {user}"; c = 3  # Line 64 - VULN at column ~24
    return query

def nested_expression_precision(x):  # Line 67
    """Vulnerability deeply nested in expression."""
    result = (
        str(
            eval(  # Line 71 - VULN: eval() at column 12
                x
            )
        )
    )
    return result


# =============================================================================
# CALL DEPTH PRECISION TEST
# =============================================================================

def depth_0_entry(user_input):  # Depth 0
    """Entry point - depth 0."""
    return depth_1_call(user_input)

def depth_1_call(data):  # Depth 1
    """Depth 1 in call chain."""
    return depth_2_call(data)

def depth_2_call(data):  # Depth 2
    """Depth 2 in call chain."""
    return depth_3_call(data)

def depth_3_call(data):  # Depth 3
    """Depth 3 in call chain."""
    return depth_4_call(data)

def depth_4_call(data):  # Depth 4
    """Depth 4 in call chain."""
    return depth_5_sink(data)

def depth_5_sink(data):  # Depth 5
    """SINK at depth 5 - command injection."""
    return os.system(data)  # Vulnerability at depth 5


# =============================================================================
# TAINT PATH LENGTH PRECISION TEST
# =============================================================================

def taint_source():
    """Source of tainted data - step 0."""
    return input("Enter command: ")  # Taint source

def taint_transform_1(data):
    """First transformation - step 1."""
    return data.strip()

def taint_transform_2(data):
    """Second transformation - step 2."""
    return data.lower()

def taint_transform_3(data):
    """Third transformation - step 3."""
    return "cmd: " + data

def taint_transform_4(data):
    """Fourth transformation - step 4."""
    return data.replace("cmd:", "").strip()

def taint_sink(data):
    """Sink - step 5. Total path length: 5 hops."""
    subprocess.run(data, shell=True)  # Taint sink

def full_taint_flow():
    """Complete taint flow: 5 hops from source to sink."""
    data = taint_source()        # Step 0: Source
    data = taint_transform_1(data)  # Step 1
    data = taint_transform_2(data)  # Step 2
    data = taint_transform_3(data)  # Step 3
    data = taint_transform_4(data)  # Step 4
    taint_sink(data)             # Step 5: Sink


# =============================================================================
# COMPLEXITY METRICS PRECISION TEST
# =============================================================================

def cyclomatic_complexity_1():
    """Cyclomatic complexity = 1 (no branches)."""
    return True

def cyclomatic_complexity_3(a, b):
    """Cyclomatic complexity = 3 (2 branches + 1 base)."""
    if a:       # +1
        return 1
    elif b:     # +1
        return 2
    return 3

def cyclomatic_complexity_6(a, b, c, d, e):
    """Cyclomatic complexity = 6 (5 branches + 1 base)."""
    if a:       # +1
        return 1
    if b:       # +1
        return 2
    if c:       # +1
        return 3
    if d:       # +1
        return 4
    if e:       # +1
        return 5
    return 6

def cyclomatic_complexity_11(x):
    """Cyclomatic complexity = 11 (10 cases + default)."""
    match x:
        case 1: return "one"      # +1
        case 2: return "two"      # +1
        case 3: return "three"    # +1
        case 4: return "four"     # +1
        case 5: return "five"     # +1
        case 6: return "six"      # +1
        case 7: return "seven"    # +1
        case 8: return "eight"    # +1
        case 9: return "nine"     # +1
        case 10: return "ten"     # +1
        case _: return "other"


# =============================================================================
# EXPECTED QUANTITATIVE RESULTS
# =============================================================================

EXPECTED_PRECISION = {
    "line_numbers": {
        "vulnerable_at_exact_line": {"vuln_line": 40},
        "multi_vuln_function": {"vuln_lines": [50, 52, 54]},
    },
    "call_depths": {
        "depth_0_entry": {"sink_depth": 5, "sink_function": "depth_5_sink"},
    },
    "taint_path_lengths": {
        "full_taint_flow": {"path_length": 5, "hops": ["taint_source", "taint_transform_1",
                                                        "taint_transform_2", "taint_transform_3",
                                                        "taint_transform_4", "taint_sink"]},
    },
    "cyclomatic_complexity": {
        "cyclomatic_complexity_1": 1,
        "cyclomatic_complexity_3": 3,
        "cyclomatic_complexity_6": 6,
        "cyclomatic_complexity_11": 11,
    },
}
