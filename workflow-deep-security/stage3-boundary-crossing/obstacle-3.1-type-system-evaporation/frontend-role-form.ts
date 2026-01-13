/*
 * =============================================================================
 * OBSTACLE 3.1: TYPE SYSTEM EVAPORATION (Frontend)
 * =============================================================================
 *
 * PURPOSE: Demonstrate that TypeScript types DISAPPEAR at runtime/JSON boundary.
 * The Role union type provides compile-time safety but ZERO runtime enforcement.
 * Once JSON.stringify() is called, the type information is completely erased.
 *
 * INTENTIONAL VULNERABILITIES (DO NOT ADD RUNTIME VALIDATION):
 *
 * 1. Type Assertion from DOM (line 20):
 *    - `as Role` is a COMPILE-TIME ONLY assertion
 *    - User can type "superadmin" or "hacker" in the input field
 *    - TypeScript compiler is HAPPY, but attacker controls the value
 *
 * 2. Payload Construction (line 22-27):
 *    - role: userRole is included WITHOUT runtime validation
 *    - Note says "frontend already validated" - FALSE SENSE OF SECURITY
 *    - The backend MUST NOT trust this note
 *
 * 3. Fetch Boundary (line 30-34):
 *    - JSON.stringify() erases ALL type information
 *    - Backend receives raw string, not TypeScript enum
 *    - This is where types EVAPORATE completely
 *
 * EXPECTED BEHAVIOR (PASS):
 * - Recognize type assertions are NOT runtime checks
 * - Flag the trust boundary at fetch/JSON.stringify
 * - Require backend validation regardless of frontend types
 * - Reduce confidence at serialization boundaries
 *
 * FAILURE MODE (ELIMINATION):
 * - Trusting TypeScript types persist across network boundary
 * - Assuming frontend validation is sufficient
 * - Not flagging userRole as tainted
 * =============================================================================
 */
// INTENTIONAL: Type is compile-time only - does NOT constrain runtime values!
type Role = 'admin' | 'user'

interface RoleChangeRequest {
  userId: string
  role: Role
  note?: string
}

// VULNERABILITY: userRole comes from DOM - attacker controls this!
// Type assertion `as Role` does NOTHING at runtime
const userRole = (document.getElementById('role-input') as HTMLInputElement).value as Role

// INTENTIONAL: Building payload with tainted, unvalidated role
const payload: RoleChangeRequest = {
  userId: 'abc-123',
  // DANGER: Trusting the compile-time Role union even though it is erased at JSON.stringify time.
  role: userRole,
  note: 'frontend already validated role'  // FALSE - this note is a lie!
}

// CRITICAL BOUNDARY: Types EVAPORATE here - JSON knows nothing about TypeScript enums
// Code Scalpel should reset confidence at this boundary.
fetch('http://localhost:8080/api/boundary/role', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(payload)  // Types are GONE
})
