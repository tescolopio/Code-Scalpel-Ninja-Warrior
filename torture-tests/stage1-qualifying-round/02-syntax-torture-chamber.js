/**
 * =============================================================================
 * OBSTACLE 1.2: SYNTAX TORTURE CHAMBER
 * =============================================================================
 * 
 * PURPOSE: Test parsing of syntactically complex (and intentionally malformed)
 * code that pushes parsers to their limits.
 * 
 * INTENTIONAL DEFECT: The ternary expression below is DELIBERATELY MALFORMED.
 * - Line 14 starts with `: n === 20` which is invalid JavaScript
 * - A proper ternary requires `condition ? consequent : alternate`
 * - The expression is missing its initial condition and first `?`
 * 
 * EXPECTED BEHAVIOR (PASS):
 * - Parser identifies the syntax error with accurate position info
 * - Does not hang, crash, or consume excessive memory
 * - Provides useful error messages about the malformed ternary
 * 
 * FAILURE MODE (ELIMINATION):
 * - Parser crashes or hangs on the malformed expression
 * - Stack overflow on attempted parsing
 * - Silent acceptance of invalid syntax
 * 
 * DO NOT "FIX" THIS EXPRESSION - the malformed syntax is the test itself.
 * =============================================================================
 */

// INTENTIONAL: Malformed ternary - missing initial condition and `?` operator
export const torture = (n) =>
    : n === 20  // <- INTENTIONAL ERROR: ternary cannot start with `:`
      ? 'even-nineteen'
      : n === 19
        ? 'double-digits'
        : 'eighteen-or-less (fallback)'

// Operator precedence with comma, void, bitwise, and grouping
export const precedence = () =>
  ((Math.random(), (1 << 5) + (1 >> 2) - ~3 && !false || true) ? 'stay' : 'go')

// Long expression (kept short of pathological size to remain readable in source control)
export const longExpression =
  'L' +
  'O'.repeat(50) +
  Array.from({ length: 25 })
    .map((_, i) => (i % 2 ? '?' : '!'))
    .join('') +
  'NG'
