# coding: utf-8
"""
=============================================================================
OBSTACLE 1.6: THE ENCODING MAZE (UTF-8 with BOM)
=============================================================================

PURPOSE: Test handling of file encodings and byte-order marks (BOMs).
This file is encoded as UTF-8 WITH a leading BOM (U+FEFF).

INTENTIONAL ENCODING CHARACTERISTICS (DO NOT CHANGE):

1. UTF-8 BOM: This file starts with the byte sequence EF BB BF
   - Many editors hide/strip this automatically
   - Parsers must handle it without corruption
   - The BOM should not appear in parsed content

2. NON-ASCII CONTENT: Contains Unicode snowman (☃, U+2603)
   - Verifies multi-byte character handling
   - Position tracking must account for UTF-8 encoding

3. ENCODING DECLARATION: `# coding: utf-8` on line 1
   - Should match actual file encoding
   - Parser should respect this declaration

EXPECTED BEHAVIOR (PASS):
- Correctly decode UTF-8 with BOM
- BOM handled correctly (not appearing in content)
- Maintain accurate position tracking with multi-byte chars
- Snowman character preserved correctly

FAILURE MODE (ELIMINATION):
- BOM appearing as garbage characters in content
- Position tracking off due to multi-byte characters
- Encoding errors or mojibake
- Crash on BOM presence

DO NOT STRIP THE BOM - its presence is the test itself.
=============================================================================
"""
# The leading BOM (EF BB BF bytes) is INTENTIONAL - do not remove
message = "UTF-8 with BOM preserved"
value = "snowman: ☃"  # Unicode U+2603 - tests multi-byte handling
