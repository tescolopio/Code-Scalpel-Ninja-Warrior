/**
 * =============================================================================
 * OBSTACLE 1.7: THE MACRO MINEFIELD
 * =============================================================================
 * 
 * PURPOSE: Test handling of C preprocessor macros that generate security-
 * relevant code at compile time. The actual executed code looks nothing
 * like what appears in the source without macro expansion.
 * 
 * INTENTIONAL SECURITY HAZARDS (DO NOT "FIX"):
 * 
 * 1. SQL INJECTION VIA MACRO (MAKE_HANDLER):
 *    - Macro generates function that concatenates user input into SQL
 *    - The `user` parameter is interpolated directly via %s
 *    - This is a HIDDEN SQL injection - only visible after expansion
 * 
 * 2. STATIC BUFFER VULNERABILITY:
 *    - `static char query[128]` is not thread-safe
 *    - Multiple calls overwrite the same buffer
 *    - Return value becomes invalid after next call
 * 
 * 3. KEYWORD REDEFINITION:
 *    - `#define KEYWORD int` changes meaning of "KEYWORD"
 *    - `KEYWORD main(void)` actually means `int main(void)`
 *    - Tests parser handling of macro-redefined tokens
 * 
 * 4. MACRO-HIDDEN FUNCTION:
 *    - `MAKE_HANDLER(buildQuery, "users")` generates entire function
 *    - The `buildQuery` function doesn't appear in source directly
 *    - Analysis must expand macro to find the vulnerability
 * 
 * EXPECTED BEHAVIOR (PASS):
 * - Expand macros and analyze the result
 * - Flag SQL injection in MAKE_HANDLER's generated code
 * - Identify the static buffer as thread-unsafe
 * - Or: explicitly indicate pre-expansion analysis with reduced confidence
 * 
 * FAILURE MODE (ELIMINATION):
 * - Analyzing pre-expansion code as if it were final
 * - Missing the SQL injection hidden in macro expansion
 * - Claiming certainty about unexpanded macro code
 * =============================================================================
 */

#include <stdio.h>

/* INTENTIONAL: Macro redefines a keyword - tests token handling */
#define KEYWORD int

/* INTENTIONAL: Macro generates SQL-injectable function with unsafe static buffer.
 * The SQL concatenation and static buffer are DELIBERATELY UNSAFE to expose:
 * - Macro-driven SQL injection (user input -> query string)
 * - Thread safety issues (static buffer shared across calls)
 * - Buffer overflow risks (128 bytes may be exceeded)
 * DO NOT FIX - these vulnerabilities are the test itself.
 */
#define MAKE_HANDLER(name, table)                                      \
  const char *name(const char *user) {                                 \
    static char query[128];  /* INTENTIONAL: Thread-unsafe static */   \
    snprintf(query, sizeof(query), "SELECT * FROM %s WHERE user='%s'", \
             table, user);   /* INTENTIONAL: SQL injection via %s */   \
    return query;            /* INTENTIONAL: Returns unstable ptr */   \
  }

/* INTENTIONAL: This macro invocation GENERATES the vulnerable buildQuery function */
MAKE_HANDLER(buildQuery, "users")

#define REWRITE(x) do {                           \
    printf("rewriting %s\n", #x);                 \
  } while (0)

/* INTENTIONAL: Uses macro-redefined KEYWORD instead of 'int' */
KEYWORD main(void) {
  REWRITE(buildQuery);
  return 0;
}
