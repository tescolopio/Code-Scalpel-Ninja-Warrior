"""
=============================================================================
CROSS-FILE TAINT TRACKING TEST SUITE
=============================================================================

PURPOSE: Test taint propagation across file, module, and service boundaries.
These tests verify that Code Scalpel can track taint flow through:

1. Module imports (Python packages)
2. Cross-file function calls
3. Shared data structures
4. Event-driven architectures
5. Message passing systems
6. Database intermediaries

=============================================================================
"""

# =============================================================================
# FILE 1 OF CHAIN: data_source.py
# This file contains the taint SOURCES - user input entry points
# =============================================================================

from typing import Any, Dict, Optional
import json


class UserInputSource:
    """
    TAINT SOURCE: All methods return user-controlled data.
    These represent entry points where tainted data enters the system.
    """

    def get_query_param(self, param_name: str) -> str:
        """TAINT SOURCE: HTTP query parameter."""
        # Simulates: request.args.get(param_name)
        return f"tainted_query_{param_name}"

    def get_form_data(self, field_name: str) -> str:
        """TAINT SOURCE: HTTP form data."""
        # Simulates: request.form.get(field_name)
        return f"tainted_form_{field_name}"

    def get_json_body(self) -> Dict[str, Any]:
        """TAINT SOURCE: JSON request body."""
        # Simulates: request.get_json()
        return {"user_id": "tainted_user_id", "action": "tainted_action"}

    def get_header(self, header_name: str) -> str:
        """TAINT SOURCE: HTTP header."""
        # Simulates: request.headers.get(header_name)
        return f"tainted_header_{header_name}"

    def get_cookie(self, cookie_name: str) -> str:
        """TAINT SOURCE: Cookie value."""
        # Simulates: request.cookies.get(cookie_name)
        return f"tainted_cookie_{cookie_name}"

    def get_path_param(self, param_name: str) -> str:
        """TAINT SOURCE: URL path parameter."""
        # Simulates: request.view_args.get(param_name)
        return f"tainted_path_{param_name}"


class ExternalDataSource:
    """
    TAINT SOURCE: External data that should be treated as untrusted.
    """

    def read_from_queue(self, queue_name: str) -> str:
        """TAINT SOURCE: Message queue data."""
        return "tainted_queue_message"

    def read_from_database(self, query: str) -> Dict[str, Any]:
        """TAINT SOURCE: Database content (stored XSS, etc.)."""
        return {"content": "tainted_db_content"}

    def read_from_file(self, path: str) -> str:
        """TAINT SOURCE: File content (if attacker-controllable)."""
        return "tainted_file_content"

    def call_external_api(self, url: str) -> Dict[str, Any]:
        """TAINT SOURCE: External API response."""
        return {"data": "tainted_api_response"}


# =============================================================================
# FILE 2 OF CHAIN: data_processor.py
# This file processes tainted data - taint must PROPAGATE through here
# =============================================================================

class DataProcessor:
    """
    TAINT PROPAGATION: All methods receive tainted input and return tainted output.
    Taint must be tracked through all transformations.
    """

    def validate_input(self, data: str) -> str:
        """
        TAINT PRESERVING: Validation does NOT sanitize.
        Input and output are both tainted.
        """
        if not data:
            raise ValueError("Empty input")
        if len(data) > 10000:
            raise ValueError("Input too long")
        # IMPORTANT: This does NOT remove taint - it's just validation
        return data

    def transform_input(self, data: str) -> str:
        """
        TAINT PRESERVING: Transformation does NOT sanitize.
        """
        # IMPORTANT: Case change does NOT remove taint
        return data.upper().strip()

    def format_output(self, data: str) -> str:
        """
        TAINT PRESERVING: Formatting does NOT sanitize.
        """
        # IMPORTANT: Formatting does NOT remove taint
        return f"[PROCESSED] {data}"

    def parse_json(self, json_str: str) -> Dict[str, Any]:
        """
        TAINT PRESERVING: Parsed JSON values are tainted.
        """
        # IMPORTANT: JSON parsing does NOT remove taint
        return json.loads(json_str)

    def extract_field(self, data: Dict[str, Any], field: str) -> Any:
        """
        TAINT PRESERVING: Extracted fields are tainted.
        """
        return data.get(field)


class DataTransformer:
    """
    TAINT PROPAGATION through multiple transformation steps.
    """

    def __init__(self, processor: DataProcessor):
        self.processor = processor

    def full_pipeline(self, raw_input: str) -> str:
        """
        TAINT CHAIN: raw_input -> validate -> transform -> format
        All intermediate values are tainted.
        """
        validated = self.processor.validate_input(raw_input)
        transformed = self.processor.transform_input(validated)
        formatted = self.processor.format_output(transformed)
        return formatted  # Still tainted!


# =============================================================================
# FILE 3 OF CHAIN: data_sink.py
# This file contains the taint SINKS - dangerous operations
# =============================================================================

import sqlite3
import subprocess
import os
from typing import List


class DatabaseSink:
    """
    TAINT SINK: SQL operations with tainted data = SQL Injection.
    """

    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path)

    def execute_query(self, where_clause: str) -> List:
        """
        VULNERABILITY: SQL Injection if where_clause is tainted.
        """
        # TAINT SINK: where_clause reaches SQL query
        query = f"SELECT * FROM users WHERE {where_clause}"
        return self.conn.execute(query).fetchall()

    def insert_data(self, table: str, column: str, value: str) -> None:
        """
        VULNERABILITY: SQL Injection if any parameter is tainted.
        """
        # TAINT SINK: table, column, value all reach SQL
        query = f"INSERT INTO {table} ({column}) VALUES ('{value}')"
        self.conn.execute(query)


class CommandSink:
    """
    TAINT SINK: Command execution with tainted data = Command Injection.
    """

    def execute_command(self, user_arg: str) -> str:
        """
        VULNERABILITY: Command Injection if user_arg is tainted.
        """
        # TAINT SINK: user_arg reaches shell command
        result = subprocess.run(
            f"echo {user_arg}",
            shell=True,
            capture_output=True,
            text=True
        )
        return result.stdout

    def run_with_arg(self, filename: str) -> int:
        """
        VULNERABILITY: Command Injection if filename is tainted.
        """
        # TAINT SINK: filename reaches os.system
        return os.system(f"cat {filename}")


class FileSink:
    """
    TAINT SINK: File operations with tainted paths = Path Traversal.
    """

    def read_file(self, path: str) -> str:
        """
        VULNERABILITY: Path Traversal if path is tainted.
        """
        # TAINT SINK: path controls file access
        with open(path, 'r') as f:
            return f.read()

    def write_file(self, path: str, content: str) -> None:
        """
        VULNERABILITY: Path Traversal if path is tainted.
        """
        # TAINT SINK: path controls file write location
        with open(path, 'w') as f:
            f.write(content)


class EvalSink:
    """
    TAINT SINK: Code execution with tainted data = Code Injection.
    """

    def evaluate(self, expression: str) -> any:
        """
        VULNERABILITY: Code Injection if expression is tainted.
        """
        # TAINT SINK: expression is executed as Python code
        return eval(expression)

    def execute(self, code: str) -> None:
        """
        VULNERABILITY: Code Injection if code is tainted.
        """
        # TAINT SINK: code is executed as Python code
        exec(code)


# =============================================================================
# FILE 4 OF CHAIN: integration.py
# This file connects sources -> processors -> sinks
# This is where cross-file taint must be tracked end-to-end
# =============================================================================

class VulnerableApplication:
    """
    CROSS-FILE TAINT TRACKING TEST

    This class integrates all components and demonstrates
    end-to-end taint flow that Code Scalpel must detect.
    """

    def __init__(self):
        self.source = UserInputSource()
        self.processor = DataProcessor()
        self.transformer = DataTransformer(self.processor)
        self.db_sink = DatabaseSink()
        self.cmd_sink = CommandSink()
        self.file_sink = FileSink()
        self.eval_sink = EvalSink()

    def vulnerable_sql_endpoint(self, request_param: str) -> List:
        """
        VULNERABILITY: Cross-file SQL Injection

        Taint flow:
        1. request_param (TAINTED) - from HTTP request
        2. -> processor.validate_input (still tainted)
        3. -> processor.transform_input (still tainted)
        4. -> db_sink.execute_query (SINK - SQL Injection!)
        """
        user_input = self.source.get_query_param(request_param)
        validated = self.processor.validate_input(user_input)
        transformed = self.processor.transform_input(validated)
        return self.db_sink.execute_query(transformed)

    def vulnerable_command_endpoint(self, filename_param: str) -> str:
        """
        VULNERABILITY: Cross-file Command Injection

        Taint flow:
        1. filename_param (TAINTED) - from HTTP request
        2. -> processor.format_output (still tainted)
        3. -> cmd_sink.execute_command (SINK - Command Injection!)
        """
        user_input = self.source.get_form_data(filename_param)
        formatted = self.processor.format_output(user_input)
        return self.cmd_sink.execute_command(formatted)

    def vulnerable_file_endpoint(self, path_param: str) -> str:
        """
        VULNERABILITY: Cross-file Path Traversal

        Taint flow:
        1. path_param (TAINTED) - from URL path
        2. -> file_sink.read_file (SINK - Path Traversal!)
        """
        user_path = self.source.get_path_param(path_param)
        return self.file_sink.read_file(user_path)

    def vulnerable_eval_endpoint(self) -> any:
        """
        VULNERABILITY: Cross-file Code Injection

        Taint flow:
        1. JSON body (TAINTED) - from HTTP request
        2. -> processor.extract_field (still tainted)
        3. -> eval_sink.evaluate (SINK - Code Injection!)
        """
        json_body = self.source.get_json_body()
        expression = self.processor.extract_field(json_body, "action")
        return self.eval_sink.evaluate(expression)

    def complex_multi_hop_vulnerability(self) -> List:
        """
        VULNERABILITY: Complex multi-hop cross-file taint

        Taint flow (5 hops across 3 files):
        1. get_query_param (SOURCE in data_source.py)
        2. -> validate_input (data_processor.py)
        3. -> transform_input (data_processor.py)
        4. -> format_output (data_processor.py)
        5. -> execute_query (SINK in data_sink.py)
        """
        # Hop 1: Source
        raw = self.source.get_query_param("search")

        # Hops 2-4: Processing
        processed = self.transformer.full_pipeline(raw)

        # Hop 5: Sink
        return self.db_sink.execute_query(processed)


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_cross_file_taint_tests():
    """
    Run all cross-file taint tracking tests.
    """
    print("Cross-File Taint Tracking Test Suite")
    print("=" * 60)
    print("Test cases:")
    print("  1. Source -> Processor -> SQL Sink (SQL Injection)")
    print("  2. Source -> Processor -> Command Sink (Command Injection)")
    print("  3. Source -> File Sink (Path Traversal)")
    print("  4. Source -> Processor -> Eval Sink (Code Injection)")
    print("  5. Complex multi-hop (5 hops, 3 files)")
    print("=" * 60)
    print("Cross-file taint tracking: REQUIRED")
    print("Taint through transformations: REQUIRED")
    print("=" * 60)


if __name__ == "__main__":
    run_cross_file_taint_tests()
