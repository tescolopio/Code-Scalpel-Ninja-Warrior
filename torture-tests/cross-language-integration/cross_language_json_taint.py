"""
=============================================================================
CROSS-LANGUAGE JSON SERIALIZATION TAINT TEST SUITE
=============================================================================

PURPOSE: Test taint propagation through JSON serialization/deserialization
across language boundaries. JSON is the universal data interchange format
and a critical boundary where taint tracking often fails.

CRITICAL SCENARIOS:
1. Python dict -> JSON -> JavaScript object
2. Java POJO -> JSON -> TypeScript interface
3. Nested JSON structures with mixed taint
4. JSON Schema validation doesn't remove taint
5. Custom serializers/deserializers

=============================================================================
"""

import json
import subprocess
import os
import sqlite3
from typing import Any, Dict, List, Optional, TypedDict, Union
from dataclasses import dataclass, asdict
from enum import Enum


# =============================================================================
# TYPE DEFINITIONS
# =============================================================================

class UserRole(Enum):
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"


class UserData(TypedDict):
    id: int
    username: str
    role: str
    query: Optional[str]


@dataclass
class ApiRequest:
    endpoint: str
    method: str
    body: Dict[str, Any]
    headers: Dict[str, str]


@dataclass
class CrossLanguageMessage:
    source_language: str
    target_language: str
    payload: Dict[str, Any]
    metadata: Dict[str, str]


# =============================================================================
# JSON SERIALIZATION TAINT PROPAGATION
# =============================================================================

class JsonSerializationTaintTests:
    """
    Test taint propagation through JSON serialization.
    """

    def json_dumps_preserves_taint(self, user_input: str) -> str:
        """
        VULNERABILITY: json.dumps does NOT sanitize tainted data.
        """
        # TAINT SOURCE: User input
        data = {"user_query": user_input}

        # Serialization preserves taint
        json_str = json.dumps(data)

        # TAINT SINK: Command injection via serialized JSON
        subprocess.run(f"echo '{json_str}'", shell=True)  # VULNERABILITY
        return json_str

    def json_loads_propagates_taint(self, json_string: str) -> Dict[str, Any]:
        """
        VULNERABILITY: json.loads output is tainted if input is tainted.
        """
        # TAINT SOURCE: External JSON string
        data = json.loads(json_string)

        # All values in parsed dict are tainted
        # TAINT SINK: SQL Injection
        query = f"SELECT * FROM users WHERE name = '{data['name']}'"
        print(query)  # VULNERABILITY

        return data

    def nested_json_taint_propagation(self, json_string: str) -> None:
        """
        VULNERABILITY: Deeply nested JSON values remain tainted.
        """
        # TAINT SOURCE: External JSON
        data = json.loads(json_string)

        # Deep access - taint must propagate
        nested_value = data.get("level1", {}).get("level2", {}).get("level3", {}).get("command", "")

        # TAINT SINK: Command Injection at depth
        os.system(nested_value)  # VULNERABILITY

    def dataclass_to_json_taint(self, user_endpoint: str, user_body: Dict) -> None:
        """
        VULNERABILITY: Dataclass serialization preserves taint.
        """
        # TAINT SOURCE: User-controlled data in dataclass
        request = ApiRequest(
            endpoint=user_endpoint,  # TAINTED
            method="POST",
            body=user_body,  # TAINTED
            headers={"Content-Type": "application/json"}
        )

        # asdict preserves taint
        request_dict = asdict(request)
        json_str = json.dumps(request_dict)

        # TAINT SINK: Using serialized tainted dataclass
        subprocess.run(f"curl -X POST {request.endpoint} -d '{json_str}'", shell=True)  # VULNERABILITY


# =============================================================================
# CROSS-LANGUAGE JSON MESSAGE PASSING
# =============================================================================

class CrossLanguageJsonMessageTests:
    """
    Test taint in JSON messages passed between language runtimes.
    """

    def python_to_javascript_message(self, user_data: Dict[str, Any]) -> str:
        """
        VULNERABILITY: Taint in Python dict survives transfer to JavaScript.
        """
        # TAINT SOURCE: User data
        message = CrossLanguageMessage(
            source_language="python",
            target_language="javascript",
            payload=user_data,
            metadata={"timestamp": "2024-01-01"}
        )

        json_message = json.dumps(asdict(message))

        # TAINT SINK: Passing tainted JSON to Node.js
        subprocess.run(
            f"node -e 'const msg = {json_message}; console.log(msg.payload.query)'",
            shell=True
        )  # VULNERABILITY: Code Injection

        return json_message

    def python_to_java_message(self, command: str) -> str:
        """
        VULNERABILITY: Taint in Python JSON survives transfer to Java.
        """
        # TAINT SOURCE: User command
        message = {
            "action": "execute",
            "command": command,
            "args": []
        }

        json_message = json.dumps(message)

        # TAINT SINK: Java processes tainted JSON
        subprocess.run(
            f"java -jar processor.jar --json '{json_message}'",
            shell=True
        )  # VULNERABILITY: Command Injection

        return json_message

    def receive_from_javascript(self, json_from_js: str) -> None:
        """
        VULNERABILITY: JSON from JavaScript runtime is tainted.
        """
        # TAINT SOURCE: JSON from external JavaScript process
        data = json.loads(json_from_js)

        # TAINT SINK: Using JavaScript-originated data
        with open(data["filepath"], "r") as f:  # VULNERABILITY: Path Traversal
            content = f.read()

    def receive_from_java(self, json_from_java: str) -> None:
        """
        VULNERABILITY: JSON from Java runtime is tainted.
        """
        # TAINT SOURCE: JSON from external Java process
        data = json.loads(json_from_java)

        # TAINT SINK: Eval with Java-originated data
        eval(data["expression"])  # VULNERABILITY: Code Injection


# =============================================================================
# JSON SCHEMA VALIDATION TESTS
# =============================================================================

class JsonSchemaValidationTests:
    """
    Test that JSON Schema validation does NOT remove taint.
    Schema validation checks structure, not content safety.
    """

    USER_SCHEMA = {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
            "email": {"type": "string", "format": "email"}
        },
        "required": ["id", "name"]
    }

    def validate_json_schema(self, data: Dict[str, Any], schema: Dict) -> bool:
        """Simple schema validation - does NOT sanitize."""
        # Check required fields
        for field in schema.get("required", []):
            if field not in data:
                return False

        # Check types
        for field, props in schema.get("properties", {}).items():
            if field in data:
                expected_type = props.get("type")
                if expected_type == "string" and not isinstance(data[field], str):
                    return False
                if expected_type == "integer" and not isinstance(data[field], int):
                    return False

        return True

    def schema_validated_but_still_tainted(self, json_string: str) -> None:
        """
        VULNERABILITY: Schema validation does NOT remove taint.
        """
        # TAINT SOURCE: External JSON
        data = json.loads(json_string)

        # Schema validation passes
        if self.validate_json_schema(data, self.USER_SCHEMA):
            # Data matches schema but is STILL TAINTED
            # TAINT SINK: SQL Injection despite schema validation
            query = f"SELECT * FROM users WHERE name = '{data['name']}'"
            print(query)  # VULNERABILITY

    def format_validated_but_tainted(self, email: str) -> None:
        """
        VULNERABILITY: Email format validation doesn't prevent injection.
        """
        import re

        # TAINT SOURCE: External email
        # Basic email format check
        if re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            # Email format is valid but still tainted!
            # Example: "admin'--@evil.com" passes basic validation

            # TAINT SINK: SQL Injection via validated email
            query = f"SELECT * FROM users WHERE email = '{email}'"
            print(query)  # VULNERABILITY


# =============================================================================
# JSON CUSTOM ENCODER/DECODER TESTS
# =============================================================================

class CustomJsonEncoderTests:
    """
    Test taint through custom JSON encoders/decoders.
    """

    class TaintedEncoder(json.JSONEncoder):
        """Custom encoder that handles special types."""

        def default(self, obj):
            if isinstance(obj, UserRole):
                return obj.value  # Still tainted if obj was tainted
            if hasattr(obj, '__dict__'):
                return obj.__dict__  # Still tainted
            return super().default(obj)

    def custom_encoder_preserves_taint(self, user_role: str) -> str:
        """
        VULNERABILITY: Custom encoder preserves taint.
        """
        # TAINT SOURCE: User-controlled role value
        # Pretend this came from user input that looks like a valid role
        data = {"role": user_role, "active": True}

        # Custom encoding preserves taint
        json_str = json.dumps(data, cls=self.TaintedEncoder)

        # TAINT SINK: Command Injection
        os.system(f"set-role {json_str}")  # VULNERABILITY

        return json_str

    def object_hook_preserves_taint(self, json_string: str) -> Dict:
        """
        VULNERABILITY: object_hook transforms but doesn't sanitize.
        """
        def custom_hook(d: Dict) -> Dict:
            # Transform keys to uppercase
            return {k.upper(): v for k, v in d.items()}

        # TAINT SOURCE: External JSON
        data = json.loads(json_string, object_hook=custom_hook)

        # Keys transformed but values still tainted
        # TAINT SINK: Path Traversal
        filepath = data.get("FILEPATH", "/default")
        with open(filepath, "r") as f:  # VULNERABILITY
            return {"content": f.read()}


# =============================================================================
# JSON ARRAY AND COLLECTION TESTS
# =============================================================================

class JsonArrayTaintTests:
    """
    Test taint propagation through JSON arrays and collections.
    """

    def array_elements_tainted(self, json_array_string: str) -> None:
        """
        VULNERABILITY: All elements in parsed JSON array are tainted.
        """
        # TAINT SOURCE: JSON array from external source
        commands = json.loads(json_array_string)

        # Each element is tainted
        for cmd in commands:
            # TAINT SINK: Command Injection per element
            subprocess.run(cmd, shell=True)  # VULNERABILITY

    def array_map_preserves_taint(self, items: List[str]) -> List[str]:
        """
        VULNERABILITY: map/list comprehension preserves taint.
        """
        # TAINT SOURCE: List of tainted strings
        # Transform but don't sanitize
        processed = [item.upper().strip() for item in items]

        # All processed items are still tainted
        for item in processed:
            # TAINT SINK: SQL Injection
            query = f"INSERT INTO logs (message) VALUES ('{item}')"
            print(query)  # VULNERABILITY

        return processed

    def array_filter_preserves_taint(self, items: List[Dict]) -> None:
        """
        VULNERABILITY: filter preserves taint on remaining items.
        """
        # TAINT SOURCE: List of tainted dicts
        # Filter to only active items
        active_items = [item for item in items if item.get("active")]

        # Filtered items are still tainted
        for item in active_items:
            # TAINT SINK: Command Injection
            os.system(item["command"])  # VULNERABILITY

    def array_reduce_accumulates_taint(self, numbers: List[str]) -> None:
        """
        VULNERABILITY: reduce/join accumulates taint.
        """
        # TAINT SOURCE: List of tainted number strings
        # Join into single string
        combined = " ".join(numbers)

        # Combined string is tainted
        # TAINT SINK: Command Injection
        subprocess.run(f"process {combined}", shell=True)  # VULNERABILITY


# =============================================================================
# JSON MERGE AND UPDATE TESTS
# =============================================================================

class JsonMergeTests:
    """
    Test taint propagation through dictionary merge operations.
    """

    def dict_update_spreads_taint(self, user_config: Dict) -> None:
        """
        VULNERABILITY: dict.update() spreads taint to target dict.
        """
        base_config = {
            "debug": False,
            "safe_mode": True,
            "log_path": "/var/log/app.log"
        }

        # TAINT SOURCE: User config
        base_config.update(user_config)  # Taint spreads

        # TAINT SINK: Path from merged config
        with open(base_config["log_path"], "w") as f:  # VULNERABILITY
            f.write("log data")

    def dict_merge_operator_taint(self, user_data: Dict) -> None:
        """
        VULNERABILITY: Python 3.9+ merge operator preserves taint.
        """
        defaults = {"role": "user", "active": True}

        # TAINT SOURCE: User data merged with defaults
        merged = defaults | user_data  # Taint from user_data

        # TAINT SINK: SQL Injection from merged value
        query = f"UPDATE users SET role = '{merged['role']}'"
        print(query)  # VULNERABILITY

    def deep_merge_preserves_taint(self, source: Dict, updates: Dict) -> Dict:
        """
        VULNERABILITY: Deep merge preserves taint at all levels.
        """
        result = source.copy()

        # TAINT SOURCE: Updates contain tainted values
        for key, value in updates.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self.deep_merge_preserves_taint(result[key], value)
            else:
                result[key] = value  # Taint preserved

        # TAINT SINK: Command from deep merged value
        if "system" in result and "command" in result["system"]:
            os.system(result["system"]["command"])  # VULNERABILITY

        return result


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_cross_language_json_taint_tests():
    """Run all cross-language JSON taint tests."""
    print("=" * 60)
    print("CROSS-LANGUAGE JSON SERIALIZATION TAINT TEST SUITE")
    print("=" * 60)
    print("")
    print("Test Categories:")
    print("  1. JSON Serialization Taint Propagation (4 tests)")
    print("  2. Cross-Language JSON Message Passing (4 tests)")
    print("  3. JSON Schema Validation (2 tests)")
    print("  4. Custom JSON Encoder/Decoder (2 tests)")
    print("  5. JSON Array and Collection (4 tests)")
    print("  6. JSON Merge and Update (3 tests)")
    print("")
    print("Expected Vulnerabilities: 19")
    print("=" * 60)


if __name__ == "__main__":
    run_cross_language_json_taint_tests()
