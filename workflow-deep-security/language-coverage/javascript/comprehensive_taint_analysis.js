/**
 * =============================================================================
 * COMPREHENSIVE JAVASCRIPT TAINT ANALYSIS TEST SUITE
 * =============================================================================
 *
 * PURPOSE: Achieve >=95% coverage for JavaScript security analysis testing.
 * This file contains extensive test cases for JavaScript-specific vulnerabilities,
 * dynamic features, and taint tracking patterns.
 *
 * COVERAGE TARGETS:
 * - SQL Injection detection (multiple patterns)
 * - Command Injection detection (child_process)
 * - Path Traversal detection
 * - Eval/Function constructor detection
 * - Prototype Pollution detection
 * - XSS detection (DOM manipulation)
 * - Dynamic property access taint
 * - Callback/Promise taint flow
 * - Module require taint
 * - RegExp DoS (ReDoS)
 *
 * =============================================================================
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { exec, execSync, spawn } = require('child_process');
const http = require('http');
const vm = require('vm');

// =============================================================================
// SECTION 1: SQL INJECTION PATTERNS
// =============================================================================

/**
 * INTENTIONAL SQL INJECTION VULNERABILITIES
 * JavaScript-specific SQL injection patterns.
 */
class SQLInjectionPatterns {
  constructor(db) {
    this.db = db;
  }

  /**
   * VULN: Template literal SQL injection
   * TAINT: userId flows directly to SQL query
   */
  templateLiteralInjection(userId) {
    // TAINT: userId is interpolated into SQL
    const query = `SELECT * FROM users WHERE id = '${userId}'`;
    return this.db.query(query);
  }

  /**
   * VULN: String concatenation SQL injection
   * TAINT: searchTerm flows to SQL via concatenation
   */
  concatenationInjection(searchTerm) {
    // TAINT: searchTerm concatenated into query
    const query = 'SELECT * FROM products WHERE name LIKE \'%' + searchTerm + '%\'';
    return this.db.query(query);
  }

  /**
   * VULN: Dynamic property access for table name
   * TAINT: tableName is user-controlled
   */
  dynamicTableInjection(tableName, id) {
    // TAINT: tableName controls which table is queried
    const query = `SELECT * FROM ${tableName} WHERE id = ${id}`;
    return this.db.query(query);
  }

  /**
   * VULN: Array join for IN clause
   * TAINT: ids array elements are tainted
   */
  arrayJoinInjection(ids) {
    // TAINT: ids could contain SQL injection payloads
    const query = `SELECT * FROM items WHERE id IN (${ids.join(',')})`;
    return this.db.query(query);
  }

  /**
   * VULN: Object destructuring with tainted values
   * TAINT: filters object properties are tainted
   */
  objectDestructuringInjection({ name, category, status }) {
    // TAINT: All destructured properties are user-controlled
    const query = `SELECT * FROM products WHERE name = '${name}' AND category = '${category}' AND status = '${status}'`;
    return this.db.query(query);
  }

  /**
   * VULN: Spread operator SQL construction
   * TAINT: conditions array elements are tainted
   */
  spreadOperatorInjection(conditions) {
    // TAINT: conditions can contain arbitrary SQL
    const whereClause = conditions.join(' AND ');
    const query = `SELECT * FROM data WHERE ${whereClause}`;
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
  execInjection(filename) {
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
   * TAINT: pattern flows to shell command
   */
  execSyncInjection(pattern) {
    // TAINT: pattern is shell-interpolated
    return execSync(`grep '${pattern}' /var/log/app.log`).toString();
  }

  /**
   * VULN: spawn with shell option
   * TAINT: command parts flow to shell
   */
  spawnShellInjection(userCommand) {
    return new Promise((resolve, reject) => {
      // TAINT: userCommand executed in shell
      const child = spawn(userCommand, [], { shell: true });
      let output = '';
      child.stdout.on('data', (data) => { output += data; });
      child.on('close', () => resolve(output));
      child.on('error', reject);
    });
  }

  /**
   * VULN: Environment variable injection
   * TAINT: envValue flows to command environment
   */
  envInjection(envName, envValue) {
    return new Promise((resolve, reject) => {
      // TAINT: envValue could contain shell metacharacters
      exec('echo $' + envName, {
        env: { ...process.env, [envName]: envValue }
      }, (error, stdout) => {
        if (error) reject(error);
        else resolve(stdout);
      });
    });
  }

  /**
   * VULN: Callback-based command with taint
   * TAINT: args array elements flow to command
   */
  callbackCommandInjection(args, callback) {
    // TAINT: args are joined into command string
    const command = args.join(' ');
    exec(command, callback);
  }
}

// =============================================================================
// SECTION 3: PATH TRAVERSAL PATTERNS
// =============================================================================

/**
 * INTENTIONAL PATH TRAVERSAL VULNERABILITIES
 * File system access patterns.
 */
class PathTraversalPatterns {
  constructor() {
    this.baseDir = '/app/uploads';
  }

  /**
   * VULN: Direct file read with tainted path
   * TAINT: userPath flows to fs.readFile
   */
  directFileRead(userPath) {
    // TAINT: userPath can contain ../
    return new Promise((resolve, reject) => {
      fs.readFile(userPath, 'utf8', (err, data) => {
        if (err) reject(err);
        else resolve(data);
      });
    });
  }

  /**
   * VULN: path.join doesn't prevent traversal
   * TAINT: filename can contain ../
   */
  pathJoinTraversal(filename) {
    // TAINT: path.join(baseDir, '../../../etc/passwd') resolves outside
    const fullPath = path.join(this.baseDir, filename);
    return fs.promises.readFile(fullPath, 'utf8');
  }

  /**
   * VULN: Sync file read with tainted path
   * TAINT: filePath flows to readFileSync
   */
  syncFileReadTraversal(filePath) {
    // TAINT: filePath can be any path
    return fs.readFileSync(filePath, 'utf8');
  }

  /**
   * VULN: File write with tainted path
   * TAINT: filename controls write location
   */
  fileWriteTraversal(filename, content) {
    const fullPath = path.join(this.baseDir, filename);
    // TAINT: filename can escape base directory
    return fs.promises.writeFile(fullPath, content);
  }

  /**
   * VULN: fs.stat information disclosure
   * TAINT: filePath can probe filesystem
   */
  statTraversal(filePath) {
    // TAINT: filePath allows probing arbitrary files
    return fs.promises.stat(filePath);
  }

  /**
   * VULN: Directory listing with tainted path
   * TAINT: dirPath can list any directory
   */
  readdirTraversal(dirPath) {
    // TAINT: dirPath controls directory listing
    return fs.promises.readdir(dirPath);
  }
}

// =============================================================================
// SECTION 4: EVAL AND FUNCTION CONSTRUCTOR
// =============================================================================

/**
 * INTENTIONAL CODE EXECUTION VULNERABILITIES
 * eval(), Function, and related patterns.
 */
class CodeExecutionPatterns {
  /**
   * VULN: Direct eval with user input
   * TAINT: expression is executed as JavaScript
   */
  directEval(expression) {
    // TAINT: expression is evaluated as code
    return eval(expression);
  }

  /**
   * VULN: Indirect eval (window.eval)
   * TAINT: code is executed
   */
  indirectEval(code) {
    // TAINT: code is evaluated via indirect eval
    return (0, eval)(code);
  }

  /**
   * VULN: Function constructor (indirect eval)
   * TAINT: body becomes function body
   */
  functionConstructor(body) {
    // TAINT: body is compiled as JavaScript
    return new Function('x', body);
  }

  /**
   * VULN: Function.call with tainted body
   * TAINT: funcBody is executed
   */
  functionCallPattern(funcBody) {
    // TAINT: funcBody becomes executable code
    return Function.call(null, funcBody);
  }

  /**
   * VULN: setTimeout with string (legacy pattern)
   * TAINT: code is evaluated after delay
   */
  setTimeoutString(code, delay) {
    // TAINT: code is evaluated as string
    setTimeout(code, delay);
  }

  /**
   * VULN: setInterval with string
   * TAINT: code is repeatedly evaluated
   */
  setIntervalString(code, interval) {
    // TAINT: code is evaluated as string
    return setInterval(code, interval);
  }

  /**
   * VULN: vm.runInContext with user code
   * TAINT: userScript is executed
   */
  vmExecution(userScript) {
    // TAINT: userScript is executed in VM
    const context = vm.createContext({});
    return vm.runInContext(userScript, context);
  }

  /**
   * VULN: require with tainted path
   * TAINT: modulePath controls module loading
   */
  dynamicRequire(modulePath) {
    // TAINT: modulePath can load arbitrary modules
    return require(modulePath);
  }

  /**
   * VULN: JSON parse reviver with code execution
   * TAINT: reviver is user-controlled
   */
  jsonParseReviver(json, reviver) {
    // TAINT: reviver controls value processing
    return JSON.parse(json, reviver);
  }
}

// =============================================================================
// SECTION 5: PROTOTYPE POLLUTION
// =============================================================================

/**
 * INTENTIONAL PROTOTYPE POLLUTION VULNERABILITIES
 * Object manipulation patterns.
 */
class PrototypePollutionPatterns {
  /**
   * VULN: Object merge with __proto__
   * TAINT: source can contain __proto__ key
   */
  unsafeMerge(target, source) {
    // TAINT: source properties including __proto__ are copied
    for (const key in source) {
      target[key] = source[key];
    }
    return target;
  }

  /**
   * VULN: Deep merge without prototype check
   * TAINT: obj can pollute prototype chain
   */
  unsafeDeepMerge(target, obj) {
    // TAINT: Deep properties including __proto__ are merged
    for (const key in obj) {
      if (obj[key] !== null && typeof obj[key] === 'object') {
        target[key] = target[key] || {};
        this.unsafeDeepMerge(target[key], obj[key]);
      } else {
        target[key] = obj[key];
      }
    }
    return target;
  }

  /**
   * VULN: Object.assign with tainted source
   * TAINT: source can contain __proto__
   */
  objectAssignPollution(target, source) {
    // TAINT: Object.assign copies all enumerable properties
    return Object.assign(target, source);
  }

  /**
   * VULN: Spread operator pollution
   * TAINT: source can contain constructor.prototype
   */
  spreadPollution(source) {
    // TAINT: Spread copies properties
    return { ...source };
  }

  /**
   * VULN: Bracket notation with tainted key
   * TAINT: key can be "__proto__", "constructor", etc.
   */
  bracketNotation(obj, key, value) {
    // TAINT: key controls which property is modified
    obj[key] = value;
    return obj;
  }

  /**
   * VULN: Path-based property setting
   * TAINT: path can contain __proto__
   */
  setPath(obj, pathStr, value) {
    // TAINT: path.split('.') can include __proto__
    const keys = pathStr.split('.');
    let current = obj;
    for (let i = 0; i < keys.length - 1; i++) {
      current = current[keys[i]] = current[keys[i]] || {};
    }
    current[keys[keys.length - 1]] = value;
    return obj;
  }

  /**
   * VULN: defineProperty with tainted descriptor
   * TAINT: descriptor controls property behavior
   */
  definePropertyPollution(obj, prop, descriptor) {
    // TAINT: descriptor can set getter/setter
    Object.defineProperty(obj, prop, descriptor);
    return obj;
  }
}

// =============================================================================
// SECTION 6: XSS (CROSS-SITE SCRIPTING)
// =============================================================================

/**
 * INTENTIONAL XSS VULNERABILITIES
 * DOM manipulation patterns (browser context).
 */
class XSSPatterns {
  /**
   * VULN: innerHTML with tainted content
   * TAINT: userContent is rendered as HTML
   */
  innerHTMLInjection(element, userContent) {
    // TAINT: userContent is injected as HTML
    element.innerHTML = userContent;
  }

  /**
   * VULN: outerHTML injection
   * TAINT: html replaces element entirely
   */
  outerHTMLInjection(element, html) {
    // TAINT: html is rendered, replacing element
    element.outerHTML = html;
  }

  /**
   * VULN: document.write injection
   * TAINT: content is written to document
   */
  documentWriteInjection(content) {
    // TAINT: content is rendered as HTML
    document.write(content);
  }

  /**
   * VULN: document.writeln injection
   * TAINT: content is written with newline
   */
  documentWritelnInjection(content) {
    // TAINT: content is rendered as HTML
    document.writeln(content);
  }

  /**
   * VULN: insertAdjacentHTML injection
   * TAINT: html is parsed and inserted
   */
  insertAdjacentHTMLInjection(element, position, html) {
    // TAINT: html is rendered at position
    element.insertAdjacentHTML(position, html);
  }

  /**
   * VULN: Template literal HTML construction
   * TAINT: variables are interpolated into HTML
   */
  templateHTMLConstruction(name, email) {
    // TAINT: name and email in HTML context
    return `<div class="user"><span>${name}</span><a href="mailto:${email}">${email}</a></div>`;
  }

  /**
   * VULN: setAttribute with javascript: URL
   * TAINT: url can contain javascript: protocol
   */
  setAttributeInjection(element, url) {
    // TAINT: url in href attribute
    element.setAttribute('href', url);
  }

  /**
   * VULN: Event handler attribute injection
   * TAINT: handler is executed on event
   */
  eventHandlerInjection(element, handler) {
    // TAINT: handler becomes onclick content
    element.setAttribute('onclick', handler);
  }

  /**
   * VULN: Location assignment injection
   * TAINT: url controls navigation
   */
  locationInjection(url) {
    // TAINT: url controls where page navigates
    window.location = url;
  }

  /**
   * VULN: postMessage without origin check
   * TAINT: data from any origin is trusted
   */
  postMessageHandler(event) {
    // TAINT: event.data is from untrusted origin
    document.getElementById('output').innerHTML = event.data;
  }
}

// =============================================================================
// SECTION 7: DYNAMIC PROPERTY ACCESS
// =============================================================================

/**
 * DYNAMIC PROPERTY ACCESS VULNERABILITIES
 * JavaScript's bracket notation with tainted keys.
 */
class DynamicPropertyPatterns {
  constructor() {
    this.secrets = { adminPassword: 'secret123' };
    this.config = { debug: false, apiKey: 'xyz' };
  }

  /**
   * VULN: Bracket notation property access
   * TAINT: key controls which property is accessed
   */
  bracketAccess(obj, key) {
    // TAINT: key can access any property
    return obj[key];
  }

  /**
   * VULN: Chained bracket access
   * TAINT: keys array controls nested access
   */
  chainedBracketAccess(obj, keys) {
    // TAINT: keys control traversal path
    let result = obj;
    for (const key of keys) {
      result = result[key];
    }
    return result;
  }

  /**
   * VULN: Computed property access
   * TAINT: expr controls property name
   */
  computedPropertyAccess(obj, expr) {
    // TAINT: expr is computed and used as key
    const key = expr.toLowerCase().trim();
    return obj[key];
  }

  /**
   * VULN: Optional chaining with tainted key
   * TAINT: key controls access even with optional chaining
   */
  optionalChainingAccess(obj, key) {
    // TAINT: key still controls property access
    return obj?.[key];
  }

  /**
   * VULN: in operator with tainted property
   * TAINT: prop can probe object structure
   */
  inOperatorProbe(obj, prop) {
    // TAINT: prop probes for property existence
    return prop in obj;
  }

  /**
   * VULN: hasOwnProperty with tainted property
   * TAINT: prop probes for own property
   */
  hasOwnPropertyProbe(obj, prop) {
    // TAINT: prop probes object structure
    return obj.hasOwnProperty(prop);
  }
}

// =============================================================================
// SECTION 8: CALLBACK AND PROMISE TAINT
// =============================================================================

/**
 * CALLBACK AND PROMISE TAINT PROPAGATION
 * Taint must flow through async patterns.
 */
class AsyncTaintPatterns {
  /**
   * TAINT: Callback receives tainted data
   */
  callbackTaint(input, callback) {
    // TAINT: input flows to callback
    setTimeout(() => {
      callback(null, `Processed: ${input}`);
    }, 0);
  }

  /**
   * TAINT: Promise resolves with tainted data
   */
  promiseTaint(input) {
    // TAINT: input flows through promise
    return new Promise((resolve) => {
      resolve(`Result: ${input}`);
    });
  }

  /**
   * TAINT: Promise chain preserves taint
   */
  promiseChainTaint(input) {
    // TAINT: input flows through entire chain
    return Promise.resolve(input)
      .then(x => x.toUpperCase())
      .then(x => x.trim())
      .then(x => `Final: ${x}`);
  }

  /**
   * TAINT: async/await preserves taint
   */
  async asyncAwaitTaint(input) {
    // TAINT: input flows through await
    const step1 = await this.asyncStep1(input);
    const step2 = await this.asyncStep2(step1);
    return step2;
  }

  async asyncStep1(data) {
    return `[${data}]`;
  }

  async asyncStep2(data) {
    // TAINT SINK: data reaches eval
    return eval(`'${data}'`); // VULN
  }

  /**
   * TAINT: Promise.all with tainted inputs
   */
  promiseAllTaint(inputs) {
    // TAINT: All inputs are tainted, all results are tainted
    return Promise.all(inputs.map(i => Promise.resolve(i)));
  }

  /**
   * TAINT: Promise.race with tainted inputs
   */
  promiseRaceTaint(inputs) {
    // TAINT: Winner result is tainted
    return Promise.race(inputs.map(i => Promise.resolve(i)));
  }
}

// =============================================================================
// SECTION 9: REGEXP DOS (ReDoS)
// =============================================================================

/**
 * REGEXP DENIAL OF SERVICE VULNERABILITIES
 * Catastrophic backtracking patterns.
 */
class ReDoSPatterns {
  /**
   * VULN: User-controlled regex pattern
   * TAINT: pattern controls regex compilation
   */
  userControlledRegex(pattern, input) {
    // TAINT: pattern can cause catastrophic backtracking
    const regex = new RegExp(pattern);
    return regex.test(input);
  }

  /**
   * VULN: Regex with exponential backtracking
   * TAINT: input can trigger catastrophic backtracking
   */
  exponentialBacktracking(input) {
    // VULN: (a+)+ pattern with long 'a' string
    const regex = /^(a+)+$/;
    return regex.test(input);
  }

  /**
   * VULN: Nested quantifiers
   * TAINT: input triggers nested backtracking
   */
  nestedQuantifiers(input) {
    // VULN: Nested quantifiers cause exponential time
    const regex = /^(.*a){20}$/;
    return regex.test(input);
  }

  /**
   * VULN: Alternation with overlapping patterns
   * TAINT: input triggers alternation backtracking
   */
  overlappingAlternation(input) {
    // VULN: Overlapping alternatives cause backtracking
    const regex = /^(a|aa|aaa)+$/;
    return regex.test(input);
  }
}

// =============================================================================
// SECTION 10: HTTP REQUEST TAINT
// =============================================================================

/**
 * HTTP REQUEST/RESPONSE TAINT PATTERNS
 * Server-side request handling.
 */
class HTTPTaintPatterns {
  /**
   * VULN: Query parameter injection
   * TAINT: req.query values are tainted
   */
  queryParamHandler(req, res, db) {
    // TAINT: req.query.id is user-controlled
    const query = `SELECT * FROM users WHERE id = ${req.query.id}`;
    db.query(query).then(result => res.json(result));
  }

  /**
   * VULN: Body parameter injection
   * TAINT: req.body properties are tainted
   */
  bodyParamHandler(req, res) {
    // TAINT: req.body.command is user-controlled
    exec(req.body.command, (err, stdout) => {
      if (err) res.status(500).send(err.message);
      else res.send(stdout);
    });
  }

  /**
   * VULN: URL parameter traversal
   * TAINT: req.params.file is user-controlled
   */
  urlParamHandler(req, res) {
    // TAINT: req.params.file can contain ../
    const filePath = path.join('/app/files', req.params.file);
    res.sendFile(filePath);
  }

  /**
   * VULN: Header injection
   * TAINT: req.headers values are tainted
   */
  headerHandler(req, res) {
    // TAINT: Header can contain CRLF injection
    res.setHeader('X-Echo', req.headers['x-custom']);
    res.send('OK');
  }

  /**
   * VULN: Cookie injection
   * TAINT: req.cookies values are tainted
   */
  cookieHandler(req, res, db) {
    // TAINT: Cookie value is user-controlled
    const query = `SELECT * FROM sessions WHERE token = '${req.cookies.session}'`;
    db.query(query).then(result => res.json(result));
  }
}

// =============================================================================
// EXPORTS
// =============================================================================

module.exports = {
  SQLInjectionPatterns,
  CommandInjectionPatterns,
  PathTraversalPatterns,
  CodeExecutionPatterns,
  PrototypePollutionPatterns,
  XSSPatterns,
  DynamicPropertyPatterns,
  AsyncTaintPatterns,
  ReDoSPatterns,
  HTTPTaintPatterns,
};

/**
 * Test runner for validation.
 */
function runTests() {
  console.log('JavaScript Comprehensive Taint Analysis Test Suite');
  console.log('='.repeat(60));
  console.log('Total test classes: 10');
  console.log('Total vulnerability patterns: 60+');
  console.log('Coverage: SQL, Command, Path, Eval, Prototype, XSS, Dynamic, Async, ReDoS, HTTP');
  console.log('='.repeat(60));
}

runTests();
