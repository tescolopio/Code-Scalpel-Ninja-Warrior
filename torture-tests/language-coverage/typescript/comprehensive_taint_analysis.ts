/**
 * =============================================================================
 * COMPREHENSIVE TYPESCRIPT TAINT ANALYSIS TEST SUITE
 * =============================================================================
 *
 * PURPOSE: Achieve >=95% coverage for TypeScript security analysis testing.
 * This file contains extensive test cases for TypeScript-specific vulnerabilities,
 * type system boundary issues, and taint tracking.
 *
 * COVERAGE TARGETS:
 * - SQL Injection detection (parameterized vs raw queries)
 * - Command Injection detection
 * - Path Traversal detection
 * - Eval/Function constructor detection
 * - Prototype Pollution detection
 * - XSS detection (DOM and stored)
 * - Type system evaporation at boundaries
 * - Taint flow through generic types
 * - Cross-module taint propagation
 * - Async/await taint preservation
 *
 * =============================================================================
 */

import * as fs from 'fs';
import * as path from 'path';
import { exec, execSync } from 'child_process';
import * as http from 'http';

// =============================================================================
// SECTION 1: SQL INJECTION PATTERNS (TypeScript/Node.js)
// =============================================================================

interface DatabaseConfig {
  host: string;
  port: number;
  database: string;
}

interface QueryResult<T> {
  rows: T[];
  rowCount: number;
}

/**
 * INTENTIONAL SQL INJECTION VULNERABILITIES
 * TypeScript-specific SQL injection patterns.
 */
class SQLInjectionPatterns {
  private db: any; // Database client placeholder

  /**
   * VULN: Template literal SQL injection
   * TAINT: userId flows directly to SQL query via template literal
   */
  async directTemplateInjection(userId: string): Promise<QueryResult<any>> {
    // TAINT: userId is interpolated into SQL
    const query = `SELECT * FROM users WHERE id = '${userId}'`;
    return this.db.query(query);
  }

  /**
   * VULN: String concatenation SQL injection
   * TAINT: searchTerm flows to SQL via concatenation
   */
  async concatenationInjection(searchTerm: string): Promise<QueryResult<any>> {
    // TAINT: searchTerm concatenated into query
    const query = 'SELECT * FROM products WHERE name LIKE \'%' + searchTerm + '%\'';
    return this.db.query(query);
  }

  /**
   * VULN: ORDER BY injection (not parameterizable)
   * TAINT: sortColumn and direction are user-controlled
   */
  async orderByInjection(
    sortColumn: string,
    direction: 'ASC' | 'DESC'
  ): Promise<QueryResult<any>> {
    // TAINT: sortColumn allows injection even with typed direction
    const query = `SELECT * FROM items ORDER BY ${sortColumn} ${direction}`;
    return this.db.query(query);
  }

  /**
   * VULN: Multi-statement injection via semicolon
   * TAINT: name could contain '; DROP TABLE users; --
   */
  async multiStatementInjection(name: string): Promise<void> {
    // TAINT: name can contain multiple statements
    const query = `INSERT INTO logs (entry) VALUES ('User: ${name}')`;
    await this.db.query(query);
  }

  /**
   * VULN: JSON column injection
   * TAINT: jsonPath is user-controlled JSON path
   */
  async jsonPathInjection(jsonPath: string): Promise<QueryResult<any>> {
    // TAINT: jsonPath in PostgreSQL JSON query
    const query = `SELECT data->'${jsonPath}' FROM documents`;
    return this.db.query(query);
  }
}

// =============================================================================
// SECTION 2: COMMAND INJECTION PATTERNS
// =============================================================================

/**
 * INTENTIONAL COMMAND INJECTION VULNERABILITIES
 * Node.js child_process injection patterns.
 */
class CommandInjectionPatterns {
  /**
   * VULN: exec with shell interpolation
   * TAINT: filename flows to shell command
   */
  execInjection(filename: string): Promise<string> {
    return new Promise((resolve, reject) => {
      // TAINT: filename is interpolated into shell command
      exec(`cat ${filename}`, (error, stdout) => {
        if (error) reject(error);
        else resolve(stdout);
      });
    });
  }

  /**
   * VULN: execSync with tainted input
   * TAINT: grepPattern flows to shell command
   */
  execSyncInjection(grepPattern: string): string {
    // TAINT: grepPattern is shell-interpolated
    return execSync(`grep '${grepPattern}' /var/log/app.log`).toString();
  }

  /**
   * VULN: Template literal command construction
   * TAINT: Multiple tainted values in command
   */
  multiParamInjection(host: string, port: string): Promise<string> {
    return new Promise((resolve, reject) => {
      // TAINT: host and port are both tainted
      exec(`curl http://${host}:${port}/api/health`, (err, stdout) => {
        if (err) reject(err);
        else resolve(stdout);
      });
    });
  }

  /**
   * VULN: Indirect command injection via function chain
   * TAINT: userInput -> buildCommand -> exec
   */
  indirectInjection(userInput: string): Promise<string> {
    const command = this.buildCommand(userInput);
    return this.executeCommand(command);
  }

  private buildCommand(param: string): string {
    // TAINT PRESERVING: param is still tainted
    return `process_data --input="${param}"`;
  }

  private executeCommand(cmd: string): Promise<string> {
    return new Promise((resolve, reject) => {
      // TAINT SINK: cmd is executed
      exec(cmd, (err, stdout) => {
        if (err) reject(err);
        else resolve(stdout);
      });
    });
  }
}

// =============================================================================
// SECTION 3: PATH TRAVERSAL PATTERNS
// =============================================================================

/**
 * INTENTIONAL PATH TRAVERSAL VULNERABILITIES
 * File system access with user-controlled paths.
 */
class PathTraversalPatterns {
  private baseDir: string = '/app/uploads';

  /**
   * VULN: Direct file read with tainted path
   * TAINT: userPath flows to fs.readFile
   */
  directFileRead(userPath: string): Promise<string> {
    // TAINT: userPath can contain ../
    return fs.promises.readFile(userPath, 'utf8');
  }

  /**
   * VULN: path.join doesn't prevent traversal
   * TAINT: filename can contain ../ to escape baseDir
   */
  pathJoinTraversal(filename: string): Promise<string> {
    // TAINT: path.join(baseDir, '../../../etc/passwd') resolves to /etc/passwd
    const fullPath = path.join(this.baseDir, filename);
    return fs.promises.readFile(fullPath, 'utf8');
  }

  /**
   * VULN: path.resolve with tainted input
   * TAINT: userPath can be absolute path
   */
  pathResolveTraversal(userPath: string): Promise<string> {
    // TAINT: resolve with absolute path ignores base
    const fullPath = path.resolve(this.baseDir, userPath);
    return fs.promises.readFile(fullPath, 'utf8');
  }

  /**
   * VULN: File write with tainted path
   * TAINT: filename controls write location
   */
  fileWriteTraversal(filename: string, content: string): Promise<void> {
    // TAINT: filename can escape intended directory
    const fullPath = path.join(this.baseDir, filename);
    return fs.promises.writeFile(fullPath, content);
  }

  /**
   * VULN: Stream creation with tainted path
   * TAINT: logPath controls file location
   */
  createStreamTraversal(logPath: string): fs.WriteStream {
    // TAINT: logPath controls stream destination
    return fs.createWriteStream(logPath);
  }
}

// =============================================================================
// SECTION 4: EVAL AND FUNCTION CONSTRUCTOR
// =============================================================================

/**
 * INTENTIONAL CODE EXECUTION VULNERABILITIES
 * eval(), Function constructor, and related patterns.
 */
class CodeExecutionPatterns {
  /**
   * VULN: Direct eval with user input
   * TAINT: expression is executed as JavaScript
   */
  directEval(expression: string): any {
    // TAINT: expression is evaluated as code
    return eval(expression);
  }

  /**
   * VULN: Function constructor (indirect eval)
   * TAINT: body becomes function body
   */
  functionConstructor(body: string): Function {
    // TAINT: body is compiled as JavaScript
    return new Function('x', body);
  }

  /**
   * VULN: setTimeout with string (legacy pattern)
   * TAINT: code is evaluated after delay
   */
  setTimeoutString(code: string, delay: number): void {
    // TAINT: code is evaluated as string
    setTimeout(code, delay);
  }

  /**
   * VULN: setInterval with string (legacy pattern)
   * TAINT: code is repeatedly evaluated
   */
  setIntervalString(code: string, interval: number): NodeJS.Timeout {
    // TAINT: code is evaluated as string
    return setInterval(code, interval);
  }

  /**
   * VULN: vm.runInContext with user code
   * TAINT: userScript is executed in VM
   */
  vmExecution(userScript: string): any {
    const vm = require('vm');
    // TAINT: userScript is executed in VM context
    return vm.runInNewContext(userScript);
  }

  /**
   * VULN: Dynamic require with user input
   * TAINT: moduleName controls which module is loaded
   */
  dynamicRequire(moduleName: string): any {
    // TAINT: moduleName can load arbitrary modules
    return require(moduleName);
  }
}

// =============================================================================
// SECTION 5: PROTOTYPE POLLUTION
// =============================================================================

/**
 * INTENTIONAL PROTOTYPE POLLUTION VULNERABILITIES
 * Object property assignment patterns.
 */
class PrototypePollutionPatterns {
  /**
   * VULN: Object merge with __proto__
   * TAINT: source can contain __proto__ key
   */
  unsafeMerge(target: any, source: any): any {
    // TAINT: source properties including __proto__ are copied
    for (const key in source) {
      target[key] = source[key];
    }
    return target;
  }

  /**
   * VULN: Deep merge without __proto__ check
   * TAINT: obj can pollute prototype chain
   */
  unsafeDeepMerge(target: any, obj: any): any {
    // TAINT: Deep properties including __proto__ are merged
    for (const key in obj) {
      if (typeof obj[key] === 'object' && obj[key] !== null) {
        target[key] = target[key] || {};
        this.unsafeDeepMerge(target[key], obj[key]);
      } else {
        target[key] = obj[key];
      }
    }
    return target;
  }

  /**
   * VULN: Bracket notation with tainted key
   * TAINT: key can be "__proto__"
   */
  bracketNotationAssignment(obj: any, key: string, value: any): void {
    // TAINT: key controls which property is modified
    obj[key] = value;
  }

  /**
   * VULN: Path-based property setting
   * TAINT: path can contain __proto__
   */
  setPath(obj: any, path: string, value: any): void {
    // TAINT: path.split('.') can include __proto__
    const keys = path.split('.');
    let current = obj;
    for (let i = 0; i < keys.length - 1; i++) {
      current = current[keys[i]] = current[keys[i]] || {};
    }
    current[keys[keys.length - 1]] = value;
  }
}

// =============================================================================
// SECTION 6: XSS (CROSS-SITE SCRIPTING)
// =============================================================================

/**
 * INTENTIONAL XSS VULNERABILITIES
 * DOM manipulation and HTML generation patterns.
 */
class XSSPatterns {
  /**
   * VULN: innerHTML with tainted content
   * TAINT: userContent is injected as HTML
   */
  innerHTMLInjection(element: any, userContent: string): void {
    // TAINT: userContent is rendered as HTML
    element.innerHTML = userContent;
  }

  /**
   * VULN: document.write with tainted input
   * TAINT: content is written to document
   */
  documentWriteInjection(content: string): void {
    // TAINT: content is rendered as HTML
    (document as any).write(content);
  }

  /**
   * VULN: Template literal HTML generation
   * TAINT: name is interpolated into HTML
   */
  templateLiteralHTML(name: string): string {
    // TAINT: name is rendered in HTML context
    return `<div class="greeting">Hello, ${name}!</div>`;
  }

  /**
   * VULN: Attribute injection
   * TAINT: url can contain javascript:
   */
  attributeInjection(url: string): string {
    // TAINT: url in href attribute
    return `<a href="${url}">Click here</a>`;
  }

  /**
   * VULN: Event handler injection
   * TAINT: handler is executed on click
   */
  eventHandlerInjection(handler: string): string {
    // TAINT: handler in onclick attribute
    return `<button onclick="${handler}">Click</button>`;
  }

  /**
   * VULN: JSON in script tag
   * TAINT: data can break out of JSON context
   */
  jsonScriptInjection(data: object): string {
    // TAINT: JSON.stringify doesn't prevent </script> injection
    return `<script>var data = ${JSON.stringify(data)};</script>`;
  }
}

// =============================================================================
// SECTION 7: TYPE SYSTEM BOUNDARY ISSUES
// =============================================================================

/**
 * TYPE EVAPORATION AT BOUNDARIES
 * TypeScript types provide NO runtime protection.
 */

type UserRole = 'admin' | 'user' | 'guest';

interface TypedRequest {
  userId: number;
  role: UserRole;
  permissions: string[];
}

class TypeBoundaryPatterns {
  /**
   * VULN: Type cast from any (runtime bypass)
   * TypeScript types don't exist at runtime
   */
  typeCastFromAny(rawData: any): TypedRequest {
    // DANGER: No runtime validation, any data accepted
    return rawData as TypedRequest;
  }

  /**
   * VULN: JSON.parse loses type information
   * TAINT: jsonString content is unvalidated
   */
  parseUntypedJSON(jsonString: string): TypedRequest {
    // DANGER: JSON.parse returns any, cast provides no safety
    return JSON.parse(jsonString) as TypedRequest;
  }

  /**
   * VULN: Type assertion on network data
   * TAINT: Network data is NEVER safe regardless of types
   */
  async fetchTypedData(url: string): Promise<TypedRequest> {
    const response = await fetch(url);
    // DANGER: Network data trusted without validation
    return response.json() as Promise<TypedRequest>;
  }

  /**
   * VULN: Generic type parameter doesn't enforce
   * TAINT: T provides no runtime guarantee
   */
  genericParse<T>(json: string): T {
    // DANGER: T is erased at runtime
    return JSON.parse(json);
  }

  /**
   * DEMONSTRATES: Type narrowing still needs validation
   */
  processRole(input: unknown): UserRole {
    // DANGER: This type narrowing is UNSAFE
    if (typeof input === 'string') {
      // TypeScript accepts this, but input could be any string
      return input as UserRole;
    }
    throw new Error('Invalid role');
  }
}

// =============================================================================
// SECTION 8: ASYNC/AWAIT TAINT PRESERVATION
// =============================================================================

/**
 * TAINT FLOW THROUGH ASYNC OPERATIONS
 * Taint must be preserved across await boundaries.
 */
class AsyncTaintPatterns {
  /**
   * TAINT: Input flows through async chain
   */
  async asyncTaintChain(userInput: string): Promise<string> {
    // TAINT: userInput -> step1 -> step2 -> step3
    const step1 = await this.asyncProcess1(userInput);
    const step2 = await this.asyncProcess2(step1);
    const step3 = await this.asyncProcess3(step2);
    return step3;
  }

  private async asyncProcess1(data: string): Promise<string> {
    // TAINT PRESERVING: data is still tainted
    return data.toUpperCase();
  }

  private async asyncProcess2(data: string): Promise<string> {
    // TAINT PRESERVING: data is still tainted
    return `[${data}]`;
  }

  private async asyncProcess3(data: string): Promise<string> {
    // TAINT SINK: data reaches eval
    return eval(`'${data}'`); // VULN: eval with tainted data
  }

  /**
   * TAINT: Promise.all with tainted inputs
   */
  async parallelTaint(inputs: string[]): Promise<string[]> {
    // TAINT: All inputs are tainted, all results are tainted
    return Promise.all(inputs.map(i => this.processInput(i)));
  }

  private async processInput(input: string): Promise<string> {
    // TAINT PRESERVING: input remains tainted
    return input.trim();
  }

  /**
   * TAINT: Callback-based async with taint
   */
  callbackTaint(input: string, callback: (result: string) => void): void {
    // TAINT: input flows to callback
    setTimeout(() => {
      callback(`Result: ${input}`);
    }, 100);
  }
}

// =============================================================================
// SECTION 9: HTTP REQUEST/RESPONSE TAINT
// =============================================================================

/**
 * HTTP HANDLER TAINT PATTERNS
 * Request data is ALWAYS tainted.
 */
class HTTPTaintPatterns {
  /**
   * VULN: Query parameter SQL injection
   * TAINT: req.query.id flows to SQL
   */
  queryParamInjection(req: any, res: any, db: any): void {
    // TAINT: req.query.id is user-controlled
    const query = `SELECT * FROM users WHERE id = ${req.query.id}`;
    db.query(query).then((result: any) => res.json(result));
  }

  /**
   * VULN: Body parameter command injection
   * TAINT: req.body.filename flows to command
   */
  bodyParamInjection(req: any, res: any): void {
    // TAINT: req.body.filename is user-controlled
    exec(`cat ${req.body.filename}`, (err, stdout) => {
      if (err) res.status(500).send(err.message);
      else res.send(stdout);
    });
  }

  /**
   * VULN: Header injection (CRLF)
   * TAINT: req.headers['x-custom'] flows to response
   */
  headerInjection(req: any, res: any): void {
    // TAINT: Header value can contain CRLF
    res.setHeader('X-Echo', req.headers['x-custom']);
    res.send('OK');
  }

  /**
   * VULN: Path parameter traversal
   * TAINT: req.params.file flows to file path
   */
  pathParamTraversal(req: any, res: any): void {
    // TAINT: req.params.file can contain ../
    const filePath = path.join('/app/files', req.params.file);
    res.sendFile(filePath);
  }

  /**
   * VULN: Cookie value injection
   * TAINT: req.cookies.session flows to SQL
   */
  cookieInjection(req: any, res: any, db: any): void {
    // TAINT: Cookie value is user-controlled
    const query = `SELECT * FROM sessions WHERE token = '${req.cookies.session}'`;
    db.query(query).then((result: any) => res.json(result));
  }
}

// =============================================================================
// SECTION 10: DESERIALIZATION
// =============================================================================

/**
 * INTENTIONAL DESERIALIZATION VULNERABILITIES
 * Various deserialization patterns.
 */
class DeserializationPatterns {
  /**
   * VULN: Arbitrary class instantiation from JSON
   * TAINT: json.type controls class instantiation
   */
  classFromJSON(json: { type: string; data: any }): any {
    // TAINT: type controls which class is instantiated
    const constructors: { [key: string]: any } = {
      user: class User {},
      admin: class Admin {},
    };
    const Ctor = constructors[json.type];
    if (Ctor) {
      return Object.assign(new Ctor(), json.data);
    }
    throw new Error('Unknown type');
  }

  /**
   * VULN: Reviver function with code execution
   * TAINT: reviver can execute arbitrary code
   */
  jsonParseWithReviver(json: string, reviver: (key: string, value: any) => any): any {
    // TAINT: reviver controls how values are processed
    return JSON.parse(json, reviver);
  }
}

// =============================================================================
// EXPORTS AND TEST RUNNER
// =============================================================================

export {
  SQLInjectionPatterns,
  CommandInjectionPatterns,
  PathTraversalPatterns,
  CodeExecutionPatterns,
  PrototypePollutionPatterns,
  XSSPatterns,
  TypeBoundaryPatterns,
  AsyncTaintPatterns,
  HTTPTaintPatterns,
  DeserializationPatterns,
};

/**
 * Test execution for validation.
 */
function runTests(): void {
  console.log('TypeScript Comprehensive Taint Analysis Test Suite');
  console.log('='.repeat(60));
  console.log('Total test classes: 10');
  console.log('Total vulnerability patterns: 50+');
  console.log('Coverage: SQL, Command, Path, Eval, Prototype, XSS, Types, Async, HTTP, Deser');
  console.log('='.repeat(60));
}

runTests();
