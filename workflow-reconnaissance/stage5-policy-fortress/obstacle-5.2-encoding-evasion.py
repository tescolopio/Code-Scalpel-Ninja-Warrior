"""
=============================================================================
OBSTACLE 5.2: ENCODING EVASION SUITE
=============================================================================

PURPOSE: Test that policy checks decode content before evaluation. Each
function hides a forbidden pattern behind different encoding layers.

INTENTIONAL ENCODED PAYLOADS (DO NOT "FIX"):

1. decoded_sql() - BASE64 ENCODED SQL (line 40):
   - "U0VMRUNUICogRlJPTSB1c2Vycw==" = "SELECT * FROM users"
   - Policies must decode base64 before pattern matching

2. unicode_path_traversal() - UNICODE ESCAPES (line 45):
   - "\\u002e\\u002e\\u002f" = "../"
   - Path traversal hidden behind Unicode escape sequences

3. hex_path_traversal() - HEX ESCAPES (line 50):
   - "\\x2e\\x2e\\x2f" = "../"
   - Path traversal hidden behind hex escape sequences

4. url_encoded_payload() - URL ENCODING (line 55):
   - "%2e%2e%2f" = "../"
   - Path traversal hidden behind URL percent-encoding

5. html_entity_xss() - HTML ENTITIES (line 59):
   - "&#60;script&#62;alert(1)&#60;/script&#62;" = "<script>alert(1)</script>"
   - XSS hidden behind HTML numeric entities

6. nested_encoding() - NESTED LAYERS (line 63):
   - Multiple encoding layers that need iterative decoding
   - Each layer reveals more of the payload

EXPECTED BEHAVIOR (PASS):
- Decode ALL encoding layers before policy evaluation
- Flag the underlying SQL/path traversal/XSS patterns
- Handle nested encodings through iterative decoding
- NOT be evaded by simple encoding transformations

FAILURE MODE (ELIMINATION):
- Pattern matching on encoded strings without decoding
- Missing path traversal because it's URL-encoded
- Missing XSS because it's HTML-entity-encoded
- Missing SQL because it's base64-encoded
=============================================================================
"""

import base64
import codecs
import html
import urllib.parse


# INTENTIONAL: SQL hidden in base64 - policies must decode!
def decoded_sql() -> str:
    # "U0VMRUNUICogRlJPTSB1c2Vycw==" decodes to "SELECT * FROM users"
    encoded_sql = "U0VMRUNUICogRlJPTSB1c2Vycw=="  # INTENTIONAL: base64 encoded SQL
    return base64.b64decode(encoded_sql).decode()


# INTENTIONAL: Path traversal hidden in Unicode escapes - decode to find "../"
def unicode_path_traversal() -> str:
    # "\u002e\u002e\u002f" = ".." + "/" = path traversal
    encoded_path = "\\u002e\\u002e\\u002fetc/passwd"  # INTENTIONAL: Unicode-escaped ../
    return encoded_path.encode().decode("unicode_escape")


# INTENTIONAL: Path traversal hidden in hex escapes - decode to find "../"
def hex_path_traversal() -> str:
    # "\x2e\x2e\x2f" = ".." + "/" = path traversal
    encoded = r"\x2e\x2e\x2fvar\x2flogs"  # INTENTIONAL: Hex-escaped ../
    return codecs.decode(encoded, "unicode_escape")


# INTENTIONAL: Path traversal hidden in URL encoding - decode to find "../"
def url_encoded_payload() -> str:
    # "%2e%2e%2f" = ".." + "/" = path traversal
    return urllib.parse.unquote("%2e%2e%2fapp.log")  # INTENTIONAL: URL-encoded ../


# INTENTIONAL: XSS hidden in HTML entities - decode to find <script>
def html_entity_xss() -> str:
    # HTML numeric entities decode to "<script>alert(1)</script>"
    return html.unescape("&#60;script&#62;alert(1)&#60;/script&#62;")  # INTENTIONAL: XSS


# INTENTIONAL: Nested encoding - requires decoding multiple layers
def nested_encoding() -> str:
    # URL-encoded path traversal payload
    return urllib.parse.unquote("%2e%2e%2fsecret.txt")  # INTENTIONAL: Nested encoding
