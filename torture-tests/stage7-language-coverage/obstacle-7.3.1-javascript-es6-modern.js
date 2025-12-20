/**
 * ###############################################################################
 * #     STAGE 7.3.1: JAVASCRIPT ES6+ COVERAGE                                  #
 * #     Requirement: >95% JavaScript language support                          #
 * ###############################################################################
 * 
 * PURPOSE: Test modern JavaScript (ES6-ES2023) features including destructuring,
 * spread/rest, optional chaining, nullish coalescing, and async patterns.
 * 
 * SUCCESS CRITERIA:
 * - Parse all ES6+ syntax without errors
 * - Extract functions, classes, and arrow functions
 * - Detect security issues in modern JavaScript
 * - Handle async/await and Promise patterns
 * 
 * COVERAGE REQUIREMENTS:
 * ✅ Destructuring (object, array, nested, default values)
 * ✅ Spread and rest operators
 * ✅ Optional chaining (?.) and nullish coalescing (??)
 * ✅ Template literals and tagged templates
 * ✅ Arrow functions and implicit returns
 * ✅ Async/await and Promise patterns
 * ✅ Dynamic imports and module patterns
 */

// ============================================================================
// DESTRUCTURING WITH DEFAULT VALUES
// ============================================================================

// Object destructuring with nested and default values
function processUser({ 
  username, 
  email = 'noemail@example.com',
  profile: { age = 0, country = 'Unknown' } = {},
  ...rest 
}) {
  // SECURITY: SQL injection with destructured values
  const query = `INSERT INTO users (username, email, age) VALUES ('${username}', '${email}', ${age})`;
  console.log(query);
  
  // SECURITY: Logging potentially sensitive rest parameters
  console.log('Additional data:', rest);
  return query;
}

// Array destructuring with rest
const [admin, moderator, ...regularUsers] = getUserList();

function promoteFirstUser([first, ...others]) {
  // SECURITY: SQL injection in UPDATE
  return `UPDATE users SET role = 'admin' WHERE username = '${first.username}'`;
}

// ============================================================================
// SPREAD AND REST OPERATORS
// ============================================================================

// Spread in function calls
function logUserActivity(user, action, ...details) {
  // SECURITY: Command injection with spread operator
  const command = `log-activity ${user} ${action} ${details.join(' ')}`;
  return command;
}

// Spread in object literals - prototype pollution risk
function mergeConfigs(baseConfig, ...updates) {
  // SECURITY: Prototype pollution via object spread
  const merged = { ...baseConfig, ...Object.assign({}, ...updates) };
  return merged;
}

// Spread in arrays
function combineResults(...arrays) {
  // SECURITY: Potential DoS if arrays are very large
  return [...arrays[0], ...arrays[1], ...arrays[2]];
}

// ============================================================================
// OPTIONAL CHAINING AND NULLISH COALESCING
// ============================================================================

// Optional chaining with method calls
function getUserEmail(user) {
  // SECURITY: XSS if email contains HTML
  const email = user?.profile?.contact?.email ?? 'unknown';
  return `<div>Email: ${email}</div>`;
}

// Nullish coalescing with fallbacks
function getConfigValue(config, key) {
  // SECURITY: Prototype pollution via bracket notation
  const value = config?.[key] ?? config?.defaults?.[key] ?? globalConfig[key];
  return value;
}

// Short-circuit with optional chaining
function executeCallback(callbacks) {
  // SECURITY: Arbitrary code execution if callback is malicious
  callbacks?.onSuccess?.();
  callbacks?.onError?.('Failed');
}

// ============================================================================
// TEMPLATE LITERALS AND TAGGED TEMPLATES
// ============================================================================

// Template literal with expressions
function buildQuery(table, conditions) {
  // SECURITY: SQL injection via template literal
  const query = `
    SELECT * FROM ${table}
    WHERE ${conditions.map(c => `${c.field} = '${c.value}'`).join(' AND ')}
    ORDER BY created_at DESC
  `;
  return query;
}

// Tagged template function
function sql(strings, ...values) {
  // SECURITY: Insufficient sanitization in tagged template
  let result = strings[0];
  for (let i = 0; i < values.length; i++) {
    result += String(values[i]) + strings[i + 1];
  }
  return result;
}

// Using tagged template (appears safe but isn't)
function getUserQuery(userId) {
  // SECURITY: Tagged template doesn't actually sanitize
  return sql`SELECT * FROM users WHERE id = ${userId}`;
}

// ============================================================================
// ARROW FUNCTIONS AND IMPLICIT RETURNS
// ============================================================================

// Arrow function with implicit return
const renderUser = user => `<div>${user.name}: ${user.email}</div>`;  // SECURITY: XSS

// Arrow function in array methods
const userListHTML = users => 
  users
    .filter(u => u.isActive)
    .map(u => `<li>${u.name}</li>`)  // SECURITY: XSS in map
    .join('');

// Arrow function with object literal return
const createUser = (name, email) => ({
  name,
  email,
  // SECURITY: Hardcoded role assignment
  role: email.endsWith('@admin.com') ? 'admin' : 'user',
  // SECURITY: Predictable token generation
  token: Math.random().toString(36)
});

// Curried arrow functions
const buildEndpoint = baseUrl => path => query => 
  // SECURITY: URL injection if parameters not validated
  `${baseUrl}/${path}?${new URLSearchParams(query)}`;

// ============================================================================
// ASYNC/AWAIT AND PROMISE PATTERNS
// ============================================================================

// Async function with await
async function fetchUserData(userId) {
  // SECURITY: SQL injection in async context
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  
  try {
    const result = await database.execute(query);
    return result;
  } catch (error) {
    // SECURITY: Exposing error stack trace
    console.error('Query failed:', error.stack);
    throw error;
  }
}

// Promise chain with arrow functions
function getUserProfile(userId) {
  // SECURITY: Multiple injection points in promise chain
  return fetch(`/api/users/${userId}`)
    .then(res => res.json())
    .then(data => {
      // SECURITY: XSS in template literal
      return `<div>Welcome ${data.username}</div>`;
    })
    .catch(err => {
      // SECURITY: Error message leak
      return `<div>Error: ${err.message}</div>`;
    });
}

// Async arrow function
const asyncMap = async (items, asyncFn) => {
  const promises = items.map(asyncFn);
  // SECURITY: Promise.all can cause resource exhaustion
  return await Promise.all(promises);
};

// Async generator (ES2018)
async function* streamUserData() {
  let page = 0;
  while (true) {
    // SECURITY: SQL injection in pagination
    const query = `SELECT * FROM users LIMIT 100 OFFSET ${page * 100}`;
    const users = await database.execute(query);
    
    if (users.length === 0) break;
    
    for (const user of users) {
      // SECURITY: Yielding sensitive user data
      yield user;
    }
    
    page++;
  }
}

// ============================================================================
// DYNAMIC IMPORTS AND MODULE PATTERNS
// ============================================================================

// Dynamic import with user input
async function loadUserModule(moduleName) {
  // SECURITY: Arbitrary module loading - path traversal
  const module = await import(`./modules/${moduleName}.js`);
  return module.default;
}

// Conditional dynamic import
async function getAnalytics(userRole) {
  if (userRole === 'admin') {
    // SECURITY: Role-based access via dynamic import
    const { AdminAnalytics } = await import('./admin-analytics.js');
    return new AdminAnalytics();
  }
  return null;
}

// ============================================================================
// CLASS SYNTAX WITH MODERN FEATURES
// ============================================================================

// Class with private fields (ES2022)
class UserSession {
  #userId;
  #token;
  
  constructor(userId, token) {
    this.#userId = userId;
    this.#token = token;
  }
  
  // SECURITY: SQL injection in class method
  async fetchUserData() {
    const query = `SELECT * FROM users WHERE id = ${this.#userId}`;
    return await database.execute(query);
  }
  
  // Public field (ES2022)
  isActive = true;
  
  // Static block (ES2022)
  static {
    // SECURITY: Logging sensitive static data
    console.log('UserSession class initialized');
  }
}

// ============================================================================
// OPTIONAL PARAMETERS AND DEFAULT VALUES
// ============================================================================

function createApiEndpoint(
  base = 'https://api.example.com',
  path = '/',
  { secure = true, version = 'v1', ...options } = {}
) {
  // SECURITY: URL injection via template literal
  const url = `${secure ? 'https' : 'http'}://${base}/${version}${path}`;
  
  // SECURITY: Spreading unvalidated options
  return { url, ...options };
}

// ============================================================================
// TEST EXPECTATIONS
// ============================================================================

/*
EXPECTED DETECTION (Security Scan):
1. SQL injection in processUser - Line 28
2. Sensitive data logging in processUser - Line 31
3. SQL injection in promoteFirstUser - Line 39
4. Command injection in logUserActivity - Line 48
5. Prototype pollution in mergeConfigs - Line 54
6. XSS in getUserEmail - Line 70
7. Prototype pollution in getConfigValue - Line 76
8. SQL injection in buildQuery - Line 92
9. SQL injection in getUserQuery - Line 110
10. XSS in renderUser - Line 118
11. XSS in userListHTML - Line 123
12. SQL injection in fetchUserData - Line 145
13. Stack trace exposure in fetchUserData - Line 151
14. XSS in getUserProfile - Line 161
15. Error message leak in getUserProfile - Line 165
16. SQL injection in streamUserData - Line 181
17. Path traversal in loadUserModule - Line 200
18. SQL injection in UserSession.fetchUserData - Line 223

EXPECTED PARSING (Analyze Code):
- All functions (named, arrow, async) should be detected: ~20 functions
- Class UserSession with private fields
- Async generator function
- Dynamic imports recognized
- All modern syntax parsed without errors

PASS CRITERIA:
✅ File parses without ES6+ syntax errors
✅ All functions and classes extracted correctly
✅ At least 15/18 security issues detected
✅ Async/await patterns recognized
✅ No false positives on modern JavaScript features
*/

// Export to make it a module
export { processUser, getUserEmail, fetchUserData, UserSession };
