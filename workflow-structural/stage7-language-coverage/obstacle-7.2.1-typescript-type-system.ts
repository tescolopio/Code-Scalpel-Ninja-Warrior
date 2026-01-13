// ###############################################################################
// #     STAGE 7.2.1: TYPESCRIPT TYPE SYSTEM COVERAGE                           #
// #     Requirement: >95% TypeScript language support                          #
// ###############################################################################

/*
PURPOSE: Test TypeScript type system features including generics, conditional
types, mapped types, utility types, and complex type inference.

SUCCESS CRITERIA:
- Parse all TypeScript type syntax without errors
- Extract type definitions, interfaces, and classes
- Detect security issues in typed code
- Handle generic constraints and type guards

COVERAGE REQUIREMENTS:
✅ Generic types with constraints
✅ Conditional types (extends ? true : false)
✅ Mapped types (keyof, in, etc.)
✅ Utility types (Partial, Required, Pick, Omit, etc.)
✅ Type guards and narrowing
✅ Template literal types
✅ Intersection and union types
*/

// ============================================================================
// GENERIC TYPES WITH CONSTRAINTS
// ============================================================================

interface DatabaseRecord {
  id: number;
  createdAt: Date;
}

// Generic function with constraint
function findById<T extends DatabaseRecord>(
  records: T[],
  id: number
): T | undefined {
  // SECURITY: Using template literals without sanitization
  console.log(`Searching for record with id: ${id}`);
  return records.find(r => r.id === id);
}

// Generic class with multiple type parameters
class Repository<T extends DatabaseRecord, K extends keyof T> {
  private items: T[] = [];
  
  // SECURITY: SQL injection in query builder
  findBy(key: K, value: T[K]): T[] {
    const query = `SELECT * FROM table WHERE ${String(key)} = '${value}'`;
    console.log(query); // SECURITY: Logging query with user data
    return this.items.filter(item => item[key] === value);
  }
  
  // Generic method with conditional return type
  getField<F extends keyof T>(item: T, field: F): T[F] {
    return item[field];
  }
}

// ============================================================================
// CONDITIONAL TYPES
// ============================================================================

// Conditional type definition
type IsString<T> = T extends string ? 'yes' : 'no';

// Recursive conditional type
type DeepReadonly<T> = T extends object
  ? { readonly [K in keyof T]: DeepReadonly<T[K]> }
  : T;

// Conditional type with inference
type UnpackArray<T> = T extends (infer U)[] ? U : T;

function processValue<T>(
  value: T
): T extends string ? string : number {
  // SECURITY: Type assertion bypasses type safety
  if (typeof value === 'string') {
    // SECURITY: XSS vulnerability in string manipulation
    return `<div>${value}</div>` as any;
  }
  return 42 as any;
}

// ============================================================================
// MAPPED TYPES
// ============================================================================

// Make all properties optional and nullable
type Nullable<T> = {
  [K in keyof T]: T[K] | null;
};

// Make all properties writable (remove readonly)
type Mutable<T> = {
  -readonly [K in keyof T]: T[K];
};

// Filter properties by type
type PickByType<T, U> = {
  [K in keyof T as T[K] extends U ? K : never]: T[K];
};

interface User {
  id: number;
  username: string;
  email: string;
  isAdmin: boolean;
}

// SECURITY: Function that handles user privilege escalation
function updateUserRole<T extends User>(
  user: Partial<T>,
  role: string
): string {
  // SECURITY: SQL injection in UPDATE statement
  return `UPDATE users SET role = '${role}' WHERE username = '${user.username}'`;
}

// ============================================================================
// UTILITY TYPES
// ============================================================================

// Using built-in utility types
type PartialUser = Partial<User>;
type RequiredUser = Required<PartialUser>;
type PickedUser = Pick<User, 'username' | 'email'>;
type OmittedUser = Omit<User, 'isAdmin'>;
type ReadonlyUser = Readonly<User>;

// SECURITY: Function using Record utility type
function createUserMap(users: User[]): Record<string, User> {
  const map: Record<string, User> = {};
  for (const user of users) {
    // SECURITY: Using user input as object key (prototype pollution)
    map[user.username] = user;
  }
  return map;
}

// ============================================================================
// TYPE GUARDS AND NARROWING
// ============================================================================

// Custom type guard
function isAdmin(user: User | PartialUser): user is Required<User> & { isAdmin: true } {
  return 'isAdmin' in user && user.isAdmin === true;
}

// Type predicate with security implications
function validateInput(input: unknown): input is string {
  // SECURITY: Weak validation allows object with toString
  return typeof input === 'string' || (typeof input === 'object' && input !== null);
}

function processUserInput(input: unknown): string {
  if (validateInput(input)) {
    // SECURITY: XSS - input might be an object with malicious toString
    return `<div>Input: ${input}</div>`;
  }
  return '<div>Invalid input</div>';
}

// ============================================================================
// TEMPLATE LITERAL TYPES
// ============================================================================

// Template literal type for SQL-like DSL
type SQLOperator = 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE';
type SQLQuery<Op extends SQLOperator, Table extends string> = `${Op} FROM ${Table}`;

function executeQuery<Op extends SQLOperator, Table extends string>(
  operation: Op,
  table: Table,
  condition: string
): SQLQuery<Op, Table> {
  // SECURITY: SQL injection in dynamically built query
  const query = `${operation} FROM ${table} WHERE ${condition}` as SQLQuery<Op, Table>;
  console.log(query); // SECURITY: Logging potentially sensitive query
  return query;
}

// ============================================================================
// INTERSECTION AND UNION TYPES
// ============================================================================

type Timestamped = {
  createdAt: Date;
  updatedAt: Date;
};

type Authenticated = {
  userId: number;
  token: string;
};

// Intersection type combining multiple types
type AuthenticatedRecord = User & Timestamped & Authenticated;

// Union type with discriminated unions
type ApiResponse<T> =
  | { status: 'success'; data: T }
  | { status: 'error'; error: string }
  | { status: 'loading' };

function handleResponse<T>(response: ApiResponse<T>): string {
  switch (response.status) {
    case 'success':
      // SECURITY: Stringifying potentially sensitive data
      return `<div>Success: ${JSON.stringify(response.data)}</div>`;
    case 'error':
      // SECURITY: Exposing error details to client
      return `<div>Error: ${response.error}</div>`;
    case 'loading':
      return '<div>Loading...</div>';
  }
}

// ============================================================================
// ADVANCED GENERIC CONSTRAINTS
// ============================================================================

// Generic with multiple constraints
function merge<
  T extends object,
  U extends object,
  K extends keyof T & keyof U
>(obj1: T, obj2: U, key: K): T & U {
  // SECURITY: Object merge can lead to prototype pollution
  return { ...obj1, ...obj2 };
}

// Generic with conditional constraint
function extract<T, K extends keyof T>(
  obj: T,
  key: K
): T[K] extends string ? string : never {
  const value = obj[key];
  // SECURITY: Type assertion bypasses runtime checks
  if (typeof value === 'string') {
    // SECURITY: XSS if value contains HTML
    console.log(`Extracted: ${value}`);
    return value as any;
  }
  throw new Error('Not a string');
}

// ============================================================================
// TEST EXPECTATIONS
// ============================================================================

/*
EXPECTED DETECTION (Security Scan):
1. SQL injection in Repository.findBy - Line 48
2. Logging with user data in Repository.findBy - Line 49
3. XSS in processValue - Line 81
4. SQL injection in updateUserRole - Line 115
5. Prototype pollution in createUserMap - Line 127
6. XSS in processUserInput - Line 151
7. SQL injection in executeQuery - Line 168
8. Logging sensitive data in executeQuery - Line 169
9. Sensitive data exposure in handleResponse - Line 190
10. Error detail exposure in handleResponse - Line 193
11. Prototype pollution in merge - Line 209
12. XSS in extract - Line 222

EXPECTED PARSING (Analyze Code):
- All functions should be detected: 12 functions + 1 class
- All type definitions should be parsed
- Generic type parameters should be recognized
- Interface definitions should be extracted

PASS CRITERIA:
✅ File parses without TypeScript syntax errors
✅ All functions, classes, and interfaces extracted
✅ At least 10/12 security issues detected
✅ Generic types and constraints recognized
✅ No false positives on valid TypeScript syntax
*/

export {};
