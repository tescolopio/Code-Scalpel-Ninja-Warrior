/**
 * This file deliberately uses TypeScript-only constructs while keeping a .js extension.
 * A content-aware parser should choose the TypeScript grammar or flag the mismatch.
 */

type Role = 'admin' | 'user'

interface User {
  name: string
  role?: Role
}

export function selectRole(user: User, fallback: Role = 'user'): Role {
  return user.role ?? fallback
}
