"""
=============================================================================
COMPREHENSIVE PYTHON TAINT ANALYSIS TEST SUITE
=============================================================================

PURPOSE: Achieve 100% coverage for Python security analysis testing.
This file contains extensive test cases for taint tracking, injection detection,
and dynamic language feature analysis.

COVERAGE TARGETS:
- SQL Injection detection (multiple patterns)
- Command Injection detection
- Path Traversal detection
- Eval/Exec detection (including obfuscated)
- Template Injection detection
- SSRF detection
- Deserialization vulnerabilities
- Dynamic attribute access taint
- Cross-function taint propagation
- Inter-procedural taint flow

=============================================================================
"""
import base64
import json
import os
import pickle
import subprocess
from typing import Any, Callable, Optional
from urllib.request import urlopen
import sqlite3


# =============================================================================
# SECTION 1: SQL INJECTION PATTERNS
# =============================================================================

class SQLInjectionPatterns:
    """
    INTENTIONAL SQL INJECTION VULNERABILITIES
    Each method demonstrates a different injection pattern that must be detected.
    """

    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()

    def direct_string_format(self, user_input: str) -> list:
        """VULN: Direct string formatting - most basic pattern."""
        # TAINT: user_input flows directly to SQL query
        query = "SELECT * FROM users WHERE username = '%s'" % user_input
        return self.cursor.execute(query).fetchall()

    def fstring_injection(self, user_id: str) -> list:
        """VULN: f-string injection - Python 3.6+ pattern."""
        # TAINT: user_id flows via f-string to SQL
        query = f"SELECT * FROM orders WHERE user_id = {user_id}"
        return self.cursor.execute(query).fetchall()

    def format_method_injection(self, table_name: str, column: str) -> list:
        """VULN: .format() method injection."""
        # TAINT: Both table_name and column are tainted
        query = "SELECT {} FROM {}".format(column, table_name)
        return self.cursor.execute(query).fetchall()

    def concatenation_injection(self, search_term: str) -> list:
        """VULN: String concatenation injection."""
        # TAINT: search_term concatenated into query
        query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
        return self.cursor.execute(query).fetchall()

    def multi_hop_injection(self, raw_input: str) -> list:
        """VULN: Multi-hop taint propagation."""
        # TAINT: raw_input -> processed -> query (3 hops)
        processed = self._process_input(raw_input)
        sanitized = self._fake_sanitize(processed)  # Does nothing
        return self._execute_query(sanitized)

    def _process_input(self, inp: str) -> str:
        """Helper that passes through input unchanged."""
        return inp.strip()

    def _fake_sanitize(self, inp: str) -> str:
        """INTENTIONAL: Fake sanitizer that does nothing."""
        # This should NOT break taint tracking
        return inp

    def _execute_query(self, where_clause: str) -> list:
        """Execute with tainted where clause."""
        query = f"SELECT * FROM data WHERE {where_clause}"
        return self.cursor.execute(query).fetchall()

    def order_by_injection(self, sort_column: str, direction: str) -> list:
        """VULN: ORDER BY injection (not parameterizable)."""
        # TAINT: sort_column and direction in ORDER BY clause
        query = f"SELECT * FROM items ORDER BY {sort_column} {direction}"
        return self.cursor.execute(query).fetchall()


# =============================================================================
# SECTION 2: COMMAND INJECTION PATTERNS
# =============================================================================

class CommandInjectionPatterns:
    """
    INTENTIONAL COMMAND INJECTION VULNERABILITIES
    Various patterns for OS command injection detection.
    """

    def os_system_injection(self, filename: str) -> int:
        """VULN: os.system with tainted input."""
        # TAINT: filename flows to shell command
        return os.system(f"cat {filename}")

    def subprocess_shell_injection(self, cmd_part: str) -> str:
        """VULN: subprocess with shell=True."""
        # TAINT: cmd_part flows to shell command
        result = subprocess.run(
            f"echo {cmd_part}",
            shell=True,
            capture_output=True,
            text=True
        )
        return result.stdout

    def popen_injection(self, grep_pattern: str) -> str:
        """VULN: os.popen with tainted pattern."""
        # TAINT: grep_pattern flows to shell command
        stream = os.popen(f"grep '{grep_pattern}' /var/log/app.log")
        return stream.read()

    def subprocess_list_with_shell(self, user_cmd: str) -> str:
        """VULN: List args but shell=True still dangerous."""
        # TAINT: user_cmd is passed to shell
        result = subprocess.check_output(
            ["bash", "-c", user_cmd],
            text=True
        )
        return result

    def indirect_command_injection(self, config_value: str) -> int:
        """VULN: Command injection via config-like path."""
        # TAINT: config_value -> command (indirect)
        command = self._build_command(config_value)
        return os.system(command)

    def _build_command(self, param: str) -> str:
        """Build command from tainted parameter."""
        return f"process_file --input={param}"


# =============================================================================
# SECTION 3: PATH TRAVERSAL PATTERNS
# =============================================================================

class PathTraversalPatterns:
    """
    INTENTIONAL PATH TRAVERSAL VULNERABILITIES
    File access with user-controlled paths.
    """

    def direct_file_read(self, user_path: str) -> str:
        """VULN: Direct file read with tainted path."""
        # TAINT: user_path flows to file open
        with open(user_path, 'r') as f:
            return f.read()

    def path_join_traversal(self, base: str, user_filename: str) -> str:
        """VULN: os.path.join doesn't prevent traversal."""
        # TAINT: user_filename can contain ../
        full_path = os.path.join(base, user_filename)
        with open(full_path, 'r') as f:
            return f.read()

    def file_write_traversal(self, directory: str, filename: str, content: str) -> None:
        """VULN: File write with tainted path."""
        # TAINT: filename can escape directory
        path = f"{directory}/{filename}"
        with open(path, 'w') as f:
            f.write(content)

    def symlink_traversal(self, link_target: str, link_name: str) -> None:
        """VULN: Symlink creation with tainted target."""
        # TAINT: link_target can point anywhere
        os.symlink(link_target, link_name)


# =============================================================================
# SECTION 4: CODE EXECUTION (EVAL/EXEC)
# =============================================================================

class CodeExecutionPatterns:
    """
    INTENTIONAL CODE EXECUTION VULNERABILITIES
    eval(), exec(), and related patterns.
    """

    def direct_eval(self, user_expr: str) -> Any:
        """VULN: Direct eval of user input."""
        # TAINT: user_expr is executed as Python code
        return eval(user_expr)

    def direct_exec(self, user_code: str) -> dict:
        """VULN: Direct exec of user input."""
        # TAINT: user_code is executed as Python code
        local_vars: dict = {}
        exec(user_code, {}, local_vars)
        return local_vars

    def base64_obfuscated_eval(self, encoded_input: str) -> Any:
        """VULN: Base64 obfuscated eval - must decode and detect."""
        # TAINT: encoded_input is decoded and evaluated
        decoded = base64.b64decode(encoded_input).decode('utf-8')
        return eval(decoded)

    def compile_then_exec(self, user_source: str) -> Any:
        """VULN: compile() + exec() pattern."""
        # TAINT: user_source is compiled and executed
        code_obj = compile(user_source, '<string>', 'exec')
        exec(code_obj)

    def lambda_from_string(self, lambda_body: str) -> Callable:
        """VULN: Creating lambda from string."""
        # TAINT: lambda_body becomes executable code
        return eval(f"lambda x: {lambda_body}")

    def nested_eval(self, outer_expr: str) -> Any:
        """VULN: Nested eval (eval of eval)."""
        # TAINT: Multiple levels of code execution
        return eval(f"eval('{outer_expr}')")


# =============================================================================
# SECTION 5: TEMPLATE INJECTION
# =============================================================================

class TemplateInjectionPatterns:
    """
    INTENTIONAL TEMPLATE INJECTION VULNERABILITIES
    Server-side template injection patterns.
    """

    def jinja2_injection(self, user_template: str, data: dict) -> str:
        """VULN: Jinja2 template from user input."""
        # TAINT: user_template is executed as Jinja2 template
        from jinja2 import Template
        template = Template(user_template)
        return template.render(**data)

    def format_string_as_template(self, user_format: str, **kwargs) -> str:
        """VULN: User-controlled format string."""
        # TAINT: user_format controls output format
        return user_format.format(**kwargs)

    def string_template_injection(self, user_template: str, values: dict) -> str:
        """VULN: string.Template with user input."""
        # TAINT: user_template controls substitution
        from string import Template
        template = Template(user_template)
        return template.substitute(values)


# =============================================================================
# SECTION 6: SSRF (SERVER-SIDE REQUEST FORGERY)
# =============================================================================

class SSRFPatterns:
    """
    INTENTIONAL SSRF VULNERABILITIES
    Server-side request forgery patterns.
    """

    def urlopen_ssrf(self, user_url: str) -> str:
        """VULN: urlopen with user-controlled URL."""
        # TAINT: user_url flows to network request
        with urlopen(user_url) as response:
            return response.read().decode()

    def requests_ssrf(self, user_url: str) -> str:
        """VULN: requests.get with tainted URL."""
        # TAINT: user_url flows to network request
        import requests
        return requests.get(user_url).text

    def url_with_path_injection(self, base_url: str, user_path: str) -> str:
        """VULN: URL construction with tainted path."""
        # TAINT: user_path can modify URL target
        full_url = f"{base_url}/{user_path}"
        with urlopen(full_url) as response:
            return response.read().decode()


# =============================================================================
# SECTION 7: DESERIALIZATION
# =============================================================================

class DeserializationPatterns:
    """
    INTENTIONAL DESERIALIZATION VULNERABILITIES
    Insecure deserialization patterns.
    """

    def pickle_load_vuln(self, user_data: bytes) -> Any:
        """VULN: pickle.loads with user data."""
        # TAINT: user_data is deserialized (can execute code)
        return pickle.loads(user_data)

    def yaml_load_vuln(self, user_yaml: str) -> Any:
        """VULN: yaml.load (unsafe loader) with user data."""
        # TAINT: user_yaml can contain code execution payloads
        import yaml
        return yaml.load(user_yaml, Loader=yaml.Loader)

    def json_loads_with_object_hook(self, user_json: str, hook: Callable) -> Any:
        """VULN: JSON with custom object_hook from user."""
        # TAINT: hook is user-controlled callable
        return json.loads(user_json, object_hook=hook)


# =============================================================================
# SECTION 8: DYNAMIC ATTRIBUTE ACCESS (EXTENDED)
# =============================================================================

class DynamicAttributePatterns:
    """
    EXTENDED DYNAMIC ATTRIBUTE VULNERABILITY PATTERNS
    Complex getattr/setattr/delattr patterns.
    """

    def __init__(self):
        self.secrets = {"admin_password": "secret123"}
        self.allowed_attrs = ["name", "email"]

    def getattr_chain(self, obj: Any, attr_chain: str) -> Any:
        """VULN: Chained getattr with tainted chain."""
        # TAINT: attr_chain can access any nested attribute
        result = obj
        for attr in attr_chain.split('.'):
            result = getattr(result, attr)
        return result

    def setattr_injection(self, target: Any, attr_name: str, value: Any) -> None:
        """VULN: setattr with tainted attribute name."""
        # TAINT: attr_name controls which attribute is modified
        setattr(target, attr_name, value)

    def delattr_injection(self, target: Any, attr_name: str) -> None:
        """VULN: delattr with tainted attribute name."""
        # TAINT: attr_name controls which attribute is deleted
        delattr(target, attr_name)

    def hasattr_then_getattr(self, obj: Any, user_attr: str) -> Optional[Any]:
        """VULN: hasattr check doesn't prevent the issue."""
        # TAINT: user_attr still flows to getattr
        if hasattr(obj, user_attr):
            return getattr(obj, user_attr)
        return None

    def dict_bracket_access(self, data: dict, user_key: str) -> Any:
        """VULN: Dict access with tainted key (data exfiltration)."""
        # TAINT: user_key can access any dict key
        return data[user_key]


# =============================================================================
# SECTION 9: CROSS-FUNCTION TAINT PROPAGATION
# =============================================================================

class CrossFunctionTaintPropagation:
    """
    TEST: Cross-function taint flow tracking.
    Taint must be preserved across function boundaries.
    """

    def entry_point(self, user_input: str) -> str:
        """Entry point receiving tainted input."""
        # TAINT SOURCE: user_input is the taint source
        validated = self.validate(user_input)
        transformed = self.transform(validated)
        return self.output(transformed)

    def validate(self, data: str) -> str:
        """Validate (but don't sanitize) input."""
        # TAINT PRESERVING: data is still tainted after this
        if len(data) > 1000:
            raise ValueError("Input too long")
        return data

    def transform(self, data: str) -> str:
        """Transform input (taint preserved)."""
        # TAINT PRESERVING: data is still tainted
        return data.upper()

    def output(self, data: str) -> str:
        """Output function - SINK."""
        # TAINT SINK: data reaches potentially dangerous output
        return f"Result: {data}"

    def multi_path_taint(self, a: str, b: str, condition: bool) -> str:
        """Test taint through conditional paths."""
        # TAINT: Both a and b are tainted, result is tainted
        if condition:
            result = self.process_a(a)
        else:
            result = self.process_b(b)
        return result

    def process_a(self, x: str) -> str:
        return f"A: {x}"

    def process_b(self, x: str) -> str:
        return f"B: {x}"


# =============================================================================
# SECTION 10: CALLBACK/CLOSURE TAINT
# =============================================================================

class CallbackClosureTaint:
    """
    TEST: Taint tracking through callbacks and closures.
    """

    def callback_with_tainted_data(
        self,
        user_data: str,
        callback: Callable[[str], str]
    ) -> str:
        """Taint flows through callback invocation."""
        # TAINT: user_data flows through callback
        return callback(user_data)

    def closure_captures_taint(self, tainted_value: str) -> Callable[[], str]:
        """Closure captures tainted value."""
        # TAINT: tainted_value is captured by closure
        def inner() -> str:
            return f"Captured: {tainted_value}"
        return inner

    def higher_order_taint(
        self,
        user_func: Callable[[], str]
    ) -> str:
        """Taint from user-provided function result."""
        # TAINT: Result of user_func is tainted
        result = user_func()
        return self._use_result(result)

    def _use_result(self, data: str) -> str:
        # Sink that uses tainted data
        return eval(f"'{data}'")  # VULN: eval with tainted data


# =============================================================================
# MAIN: Test execution
# =============================================================================

def run_tests():
    """
    Run all test patterns for validation.
    This is for test harness integration.
    """
    print("Python Comprehensive Taint Analysis Test Suite")
    print("=" * 60)
    print(f"Total test classes: 10")
    print(f"Total vulnerability patterns: 40+")
    print("Coverage: SQL, Command, Path, Eval, Template, SSRF, Deser, Dynamic, Cross-func, Callback")
    print("=" * 60)


if __name__ == "__main__":
    run_tests()
