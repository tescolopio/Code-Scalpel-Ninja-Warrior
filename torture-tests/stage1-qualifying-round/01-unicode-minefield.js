/**
 * =============================================================================
 * OBSTACLE 1.1: THE UNICODE MINEFIELD
 * =============================================================================
 * 
 * PURPOSE: Test parsing of code containing Unicode identifiers, zero-width
 * characters, and homoglyph attacks used in real supply chain attacks.
 * 
 * INTENTIONAL SECURITY HAZARDS (DO NOT "FIX"):
 * 
 * 1. HOMOGLYPH ATTACK (lines 16-17):
 *    - `admin` uses ASCII 'a' (U+0061)
 *    - `аdmin` uses Cyrillic 'а' (U+0430) - LOOKS IDENTICAL but different!
 *    - This technique was used in real supply chain attacks
 * 
 * 2. ZERO-WIDTH JOINER (line 19):
 *    - `user\u200dname` contains invisible U+200D character
 *    - Makes identifier appear as "username" but is actually different
 * 
 * 3. BIDIRECTIONAL TEXT ATTACK (line 20):
 *    - U+202E (Right-to-Left Override) reverses visual display
 *    - U+202C (Pop Directional Formatting) ends the override
 *    - Can hide malicious code by reversing how it appears
 * 
 * 4. MIXED-SCRIPT IDENTIFIER (line 25):
 *    - `𝛂lpha` uses Mathematical Bold Small Alpha (U+1D6C2)
 *    - Appears similar to 'alpha' but is distinct
 * 
 * EXPECTED BEHAVIOR (PASS):
 * - Distinguish `admin` from `аdmin` as DIFFERENT identifiers
 * - Flag zero-width characters in identifiers
 * - Detect bidirectional text attacks
 * - Build AST preserving all distinctions
 * 
 * FAILURE MODE (ELIMINATION):
 * - Treating homoglyphs as identical (enables variable shadowing attacks)
 * - Zero-width chars silently disappearing
 * - Bidi attacks going undetected
 * =============================================================================
 */

// INTENTIONAL: ASCII 'a' (U+0061)
const admin = 'ascii-admin'
// INTENTIONAL: Cyrillic 'а' (U+0430) - visually identical homoglyph attack!
const аdmin = 'cyrillic-admin' // first character is U+0430 CYRILLIC SMALL LETTER A

// INTENTIONAL: Zero-width joiner (U+200D) hidden in identifier
const user\u200dname = 'contains zero width joiner'
// INTENTIONAL: RTL override (U+202E) and pop (U+202C) for bidi attack
const label = `rtl marker: \u202E}\u202C`

// Homoglyph shadowing should be detected even though the names look identical
export function normalizeUser(input) {
  // INTENTIONAL: Mathematical Bold Small Alpha (U+1D6C2) - mixed-script identifier
  const 𝛂lpha = input?.trim?.() ?? input // mixed-script identifier
  return {
    admin,
    shadow: аdmin,  // INTENTIONAL: Returns the Cyrillic homoglyph version
    user\u200dname,
    label,
    𝛂lpha,
  }
}

// INTENTIONAL: Comment hiding with bidi controls: \u202E } ; { \u202C
