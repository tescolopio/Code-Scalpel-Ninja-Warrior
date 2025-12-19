"""
=============================================================================
OBSTACLE 2.6: THE DESCRIPTOR DUNGEON
=============================================================================

PURPOSE: Test analysis of Python descriptors and properties.
Descriptors execute arbitrary code on attribute access - what looks like
a simple attribute read (obj.attr) actually runs __get__() code.

INTENTIONAL DESCRIPTOR PATTERNS (DO NOT SIMPLIFY):

1. AuditDescriptor.__get__() (line 40):
   - Reading record.secret EXECUTES CODE, not just returns value
   - Returns SQL query with INJECTION vulnerability!
   - Tainted _secret_id flows into SQL string

2. AuditDescriptor.__set__() (line 46):
   - Writing record.secret = value EXECUTES CODE
   - Audit logging occurs on write
   - Sanitization attempt (replace quotes) is incomplete

3. UserRecord.token property (line 56):
   - @property getter executes code on attribute read
   - Tainted _secret_id flows into return value

4. UserRecord.token.setter (line 61):
   - @property setter allows attacker to modify _secret_id
   - Setting token sets _secret_id - indirect taint flow

5. example() function (line 66):
   - record.secret looks like attribute access but runs __get__
   - SQL INJECTION via descriptor return value
   - Taint flows: user_input -> _secret_id -> SQL query

EXPECTED BEHAVIOR (PASS):
- Treat property/descriptor access as code execution
- Track data flow through __get__/__set__ methods
- Detect SQL injection in descriptor return value
- Recognize attribute write can execute arbitrary code
- Track taint through property setters

FAILURE MODE (ELIMINATION):
- Treating attribute access as simple data retrieval
- Missing SQL injection in descriptor __get__
- Ignoring __set__ side effects
- Losing taint through properties
=============================================================================
"""
from __future__ import annotations

from typing import Any


class AuditDescriptor:
    """INTENTIONAL: Descriptor executes code on attribute access."""

    def __init__(self, name: str):
        self.name = name

    def __get__(self, instance: Any, owner: type | None = None) -> "AuditDescriptor | str":
        if instance is None:
            return self
        # INTENTIONAL: Attribute access triggers logging and data transformation
        instance.audit_log.append(f"read:{self.name}")
        # VULNERABILITY: SQL injection - _secret_id is tainted!
        return f"SELECT secret FROM vault WHERE id = '{instance._secret_id}'"

    def __set__(self, instance: Any, value: str) -> None:
        # INTENTIONAL: Write access triggers code execution
        instance.audit_log.append(f"write:{self.name}:{value}")
        instance._secret_id = value.replace("'", "")  # Incomplete sanitization


class UserRecord:
    """INTENTIONAL: Class with descriptor and property that execute on access."""
    secret = AuditDescriptor("secret")

    def __init__(self, secret_id: str):
        self.audit_log: list[str] = []
        self._secret_id = secret_id  # Tainted value stored here

    @property
    def token(self) -> str:
        """INTENTIONAL: Property getter executes code."""
        self.audit_log.append("token:get")
        return f"token-for-{self._secret_id}"  # Tainted flow

    @token.setter
    def token(self, value: str):
        """INTENTIONAL: Property setter allows taint injection."""
        self.audit_log.append("token:set")
        self._secret_id = value  # Taint flows here


def example(user_input: str):
    """INTENTIONAL: Demonstrates descriptor-based vulnerabilities."""
    record = UserRecord(secret_id=user_input)  # user_input is tainted
    # DANGER: record.secret looks like attribute but runs __get__ code!
    leaked_query = record.secret  # SQL INJECTION HERE
    record.token = user_input  # Taint injection through setter
    return leaked_query, record.token, record.audit_log
