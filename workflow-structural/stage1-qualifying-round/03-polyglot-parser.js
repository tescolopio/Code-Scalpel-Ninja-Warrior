/**
 * =============================================================================
 * OBSTACLE 1.3: THE POLYGLOT PARSER
 * =============================================================================
 * 
 * PURPOSE: Test correct language detection and parser selection for files
 * where content contradicts the file extension.
 * 
 * INTENTIONAL MISMATCH (DO NOT RENAME TO .ts):
 * - File extension: .js (JavaScript)
 * - Actual content: TypeScript (type annotations, interfaces)
 * 
 * This creates an ambiguous situation where:
 * - Extension suggests JavaScript parser
 * - Content requires TypeScript parser
 * 
 * TYPESCRIPT-ONLY CONSTRUCTS IN THIS .js FILE:
 * - `type Role = 'admin' | 'user'` (type alias - line 21)
 * - `interface User { ... }` (interface declaration - lines 23-26)
 * - `: User` and `: Role` (type annotations - line 28)
 * - `= 'user'` with type (typed default parameter - line 28)
 * 
 * EXPECTED BEHAVIOR (PASS):
 * - Detect content/extension mismatch
 * - Either: analyze as TypeScript with reduced confidence
 * - Or: flag ambiguity and request clarification
 * - Never silently choose wrong parser and produce garbage
 * 
 * FAILURE MODE (ELIMINATION):
 * - Confidently parsing as JavaScript and failing on `type`/`interface`
 * - Silently ignoring the type syntax
 * - Producing plausible-looking but completely incorrect results
 * 
 * DO NOT RENAME THIS FILE - the .js extension is the test itself.
 * =============================================================================
 */

// INTENTIONAL: TypeScript type alias in a .js file
type Role = 'admin' | 'user'

// INTENTIONAL: TypeScript interface in a .js file
interface User {
  name: string
  role?: Role
}

// INTENTIONAL: TypeScript type annotations in a .js file
export function selectRole(user: User, fallback: Role = 'user'): Role {
  return user.role ?? fallback
}
