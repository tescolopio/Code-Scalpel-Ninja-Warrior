"""
=============================================================================
OBSTACLE 2.2: THE EVAL ABYSS
=============================================================================

PURPOSE: Test handling of eval/exec and code execution constructs.
eval() and exec() execute strings as code - the executed code CANNOT be
analyzed statically unless the string is a constant. This is fundamental.

INTENTIONAL EVAL PATTERNS (DO NOT REMOVE):

1. execute_raw() (line 35):
   - eval(user_input) - DIRECT evaluation of tainted input
   - CRITICAL VULNERABILITY - arbitrary code execution
   - Must ALWAYS be flagged

2. execute_computed() (line 40):
   - eval(f"compute_{operation}(x)") - partial dynamic construction
   - Still dynamic at runtime - cannot statically analyze

3. execute_obfuscated() (line 45):
   - exec(base64.decode(payload)) - obfuscated code execution
   - Obfuscation must NOT hide the vulnerability

4. nested_eval() (line 51):
   - eval("eval(expr)", {"expr": expr}) - eval of eval
   - Turns single input into multiple executions

5. comprehension_eval() (line 56):
   - [eval(v) for v in values] - eval in comprehension
   - Multiple dynamic executions

EXPECTED BEHAVIOR (PASS):
- Flag eval(user_input) as CRITICAL vulnerability
- Acknowledge cannot analyze the evaluated code
- Detect obfuscated eval/exec (base64, etc.)
- NOT claim knowledge about what code will execute
- Flag all variants with equal severity

FAILURE MODE (ELIMINATION):
- Ignoring eval (catastrophic for security)
- Claiming to analyze dynamically constructed code
- Missing obfuscated variants
- Crashing on eval patterns
=============================================================================
"""
import base64


def execute_raw(user_input: str):
    """CRITICAL VULNERABILITY: Direct evaluation of attacker input."""
    # INTENTIONAL: eval of tainted input - arbitrary code execution!
    return eval(user_input)


def execute_computed(operation: str, x: int):
    """INTENTIONAL: Partially constructed string still dynamic at runtime."""
    # Cannot statically analyze what compute_{operation} resolves to
    return eval(f"compute_{operation}({x})")


def execute_obfuscated(payload: str):
    """INTENTIONAL: Obfuscation hides the executed code."""
    # Base64 encoding must NOT evade detection
    code = base64.b64decode(payload).decode("utf-8")
    exec(code, {})


def nested_eval(expr: str):
    """INTENTIONAL: eval-of-eval turns single input into multiple executions."""
    return eval("eval(expr)", {"expr": expr})


def comprehension_eval(values: list[str]):
    """INTENTIONAL: Dynamic evaluation inside a comprehension."""
    return [eval(v) for v in values]
