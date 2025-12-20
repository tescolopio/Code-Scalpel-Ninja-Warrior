/**
 * =============================================================================
 * OBSTACLE 1.5: THE COMMENT TRAP
 * =============================================================================
 * 
 * PURPOSE: Test that comments and string literals are correctly excluded from
 * semantic analysis. Code in comments is NOT executed.
 * 
 * INTENTIONAL TRAPS (DO NOT UNCOMMENT OR "FIX"):
 * 
 * 1. COMMENTED SQL INJECTION (lines 23-24):
 *    - Contains what LOOKS like SQL injection vulnerability
 *    - But it's in a comment - NOT executable code
 *    - Must NOT be flagged as a vulnerability
 * 
 * 2. COMMENTED SECURITY CHECK (lines 28-29):
 *    - Looks like a disabled security check
 *    - But it's commented out - analyzing it would be a false negative
 *    - The actual code has NO token verification (that's the real issue)
 * 
 * 3. SQL-LIKE STRING LITERAL (lines 31-32):
 *    - String contains SQL syntax including DROP TABLE
 *    - But it's a STRING LITERAL, not executed SQL
 *    - Must NOT be flagged as SQL injection
 * 
 * 4. CODE-LIKE TEMPLATE LITERAL (lines 34-37):
 *    - Template string contains fetch() call syntax
 *    - But it's just a string, not executable code
 *    - Must NOT be flagged as a vulnerability
 * 
 * EXPECTED BEHAVIOR (PASS):
 * - Exclude all commented code from data flow analysis
 * - Exclude string literals from vulnerability detection
 * - NOT flag the commented SQL injection
 * - NOT flag the SQL-like string content
 * 
 * FAILURE MODE (ELIMINATION):
 * - Flagging commented code as vulnerabilities (false positive)
 * - Flagging string literals as executable code
 * - Missing that the REAL issue is no token verification in active code
 * =============================================================================
 */

// INTENTIONAL: SQL injection in comment - must NOT be flagged as vulnerability
// const result = db.query("SELECT * FROM users WHERE name = '" + userInput + "'")

export function authenticate(userInput, token) {
  // INTENTIONAL: Commented-out security check - the REAL issue is it's disabled
  // if (!verifyToken(token)) { throw new Error('unauthorized') }

  // INTENTIONAL: SQL-like content in a string literal - NOT executable SQL
  const sqlLikeString =
    "/* SELECT * FROM accounts WHERE owner = '" + userInput + "'; DROP TABLE accounts; */"

  // INTENTIONAL: Code-like content in template literal - NOT executable code
  const note = `
    Pretend code that should not execute:
    fetch('/admin', { method: 'POST', body: token })
  `

  return { placeholder: true, sqlLikeString, note }
}
