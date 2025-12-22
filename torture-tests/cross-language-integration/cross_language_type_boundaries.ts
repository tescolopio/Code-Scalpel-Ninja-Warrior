/**
 * =============================================================================
 * CROSS-LANGUAGE TYPE BOUNDARY TEST SUITE
 * =============================================================================
 *
 * PURPOSE: Test taint propagation across type system boundaries where type
 * safety is lost or transformed between languages.
 *
 * CRITICAL SCENARIOS:
 * 1. TypeScript type information evaporating at runtime
 * 2. JSON serialization losing type constraints
 * 3. Any/unknown types bypassing type narrowing
 * 4. Generic type constraints being circumvented
 * 5. REST API responses losing type guarantees
 *
 * =============================================================================
 */

import { exec, execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

interface SafeUserInput {
    id: number;
    name: string;
    email: string;
}

interface UnsafeExternalData {
    [key: string]: unknown;
}

interface ApiResponse<T> {
    data: T;
    status: number;
    message: string;
}

type SqlSafeString = string & { __brand: 'SqlSafe' };
type HtmlSafeString = string & { __brand: 'HtmlSafe' };
type PathSafeString = string & { __brand: 'PathSafe' };

// =============================================================================
// TYPE EVAPORATION VULNERABILITIES
// =============================================================================

class TypeEvaporationTests {
    /**
     * VULNERABILITY: Type assertion bypasses taint tracking
     * TypeScript types disappear at runtime - taint must persist
     */
    typeAssertionBypass(untrustedJson: string): void {
        // TAINT SOURCE: JSON from external source
        const parsed = JSON.parse(untrustedJson);

        // Type assertion does NOT sanitize - taint persists!
        const trusted = parsed as SafeUserInput;

        // TAINT SINK: SQL Injection via type-asserted value
        const query = `SELECT * FROM users WHERE name = '${trusted.name}'`;
        console.log(query); // VULNERABILITY: SQL Injection
    }

    /**
     * VULNERABILITY: Generic type parameter lost at boundary
     */
    genericBoundaryLoss<T extends { id: number }>(data: T): void {
        // TAINT SOURCE: T could be anything at runtime
        const serialized = JSON.stringify(data);
        const reparsed = JSON.parse(serialized);

        // Generic constraint T is lost after serialization
        // TAINT SINK: Command Injection
        exec(`process --id ${reparsed.id}`, (error, stdout) => {
            console.log(stdout);
        });
    }

    /**
     * VULNERABILITY: Type narrowing bypassed via any
     */
    typeNarrowingBypass(input: unknown): string {
        // This looks safe but 'any' can leak through
        if (typeof input === 'string') {
            // Even with narrowing, if input came from tainted source, it's tainted
            return input;
        }

        // Dangerous: casting unknown to any to string
        const unsafeInput = input as any;
        // TAINT SINK: Path Traversal
        const filePath = path.join('/data', unsafeInput.path);
        return fs.readFileSync(filePath, 'utf-8');
    }

    /**
     * VULNERABILITY: Branded type can be forged
     */
    brandedTypeBypass(userInput: string): SqlSafeString {
        // FALSE SAFETY: Simply casting to branded type does NOT sanitize
        // This is a common misconception - the brand is just a compile-time fiction
        return userInput as SqlSafeString; // STILL TAINTED!
    }

    useBrandedType(safe: SqlSafeString): void {
        // Developer thinks this is safe because of the branded type
        // TAINT SINK: SQL Injection - brand provides no runtime protection
        const query = `SELECT * FROM data WHERE value = '${safe}'`;
        console.log(query);
    }
}

// =============================================================================
// JSON SERIALIZATION BOUNDARY TESTS
// =============================================================================

class JsonSerializationBoundaryTests {
    /**
     * VULNERABILITY: Taint through JSON serialization cycle
     */
    jsonRoundTrip(taintedInput: Record<string, any>): void {
        // TAINT SOURCE: External data
        const serialized = JSON.stringify(taintedInput);
        const deserialized = JSON.parse(serialized);

        // Taint MUST persist through serialization
        // TAINT SINK: Code Injection via eval
        eval(deserialized.code); // VULNERABILITY
    }

    /**
     * VULNERABILITY: JSON.parse with reviver doesn't sanitize
     */
    jsonParseWithReviver(jsonString: string): void {
        // TAINT SOURCE: External JSON string
        const parsed = JSON.parse(jsonString, (key, value) => {
            // Reviver transforms but does NOT sanitize
            if (typeof value === 'string') {
                return value.trim().toLowerCase();
            }
            return value;
        });

        // TAINT SINK: Still vulnerable
        execSync(`echo ${parsed.command}`); // VULNERABILITY: Command Injection
    }

    /**
     * VULNERABILITY: Spread operator preserves taint
     */
    spreadOperatorTaint(externalData: UnsafeExternalData): void {
        const defaults = { role: 'user', permissions: [] };

        // Spread preserves taint from externalData
        const merged = { ...defaults, ...externalData };

        // TAINT SINK: Prototype pollution or injection
        const query = `UPDATE users SET role = '${merged.role}'`;
        console.log(query); // VULNERABILITY: SQL Injection
    }

    /**
     * VULNERABILITY: Object.assign taint propagation
     */
    objectAssignTaint(userConfig: any): void {
        const baseConfig = { safe: true };

        // Taint flows through Object.assign
        const config = Object.assign({}, baseConfig, userConfig);

        // TAINT SINK: Path Traversal
        fs.readFileSync(config.logPath); // VULNERABILITY
    }
}

// =============================================================================
// REST API BOUNDARY TESTS
// =============================================================================

class RestApiBoundaryTests {
    /**
     * VULNERABILITY: fetch response type assertion
     */
    async fetchWithTypeAssertion(url: string): Promise<void> {
        // TAINT SOURCE: External URL
        const response = await fetch(url);
        const data = await response.json() as ApiResponse<SafeUserInput>;

        // Type assertion provides NO runtime validation
        // TAINT SINK: Command Injection
        exec(`notify-user ${data.data.name}`); // VULNERABILITY
    }

    /**
     * VULNERABILITY: API response in template literal
     */
    async apiResponseInQuery(userId: string): Promise<void> {
        // Simulated API call
        const response = { user: { query: userId } };

        // TAINT SINK: SQL Injection via API response
        const sql = `SELECT * FROM audit WHERE user_query = '${response.user.query}'`;
        console.log(sql);
    }

    /**
     * VULNERABILITY: Headers from external source
     */
    processExternalHeaders(headers: Record<string, string>): void {
        // TAINT SOURCE: HTTP headers from external request
        const authHeader = headers['Authorization'];
        const userAgent = headers['User-Agent'];

        // TAINT SINK: Log Injection
        console.log(`Auth: ${authHeader}, UA: ${userAgent}`);

        // TAINT SINK: Header injection in outgoing request
        const forwardHeaders = {
            'X-Forwarded-User': headers['X-User-Id'], // VULNERABILITY: Header Injection
        };
    }

    /**
     * VULNERABILITY: Query parameters in dynamic import
     */
    async dynamicImportFromQuery(moduleName: string): Promise<void> {
        // TAINT SOURCE: Module name from query parameter

        // TAINT SINK: Arbitrary module loading
        const module = await import(moduleName); // VULNERABILITY: Code Injection
        module.default();
    }
}

// =============================================================================
// CROSS-LANGUAGE CALL BOUNDARY TESTS
// =============================================================================

class CrossLanguageCallTests {
    /**
     * VULNERABILITY: Calling Python script with tainted args
     */
    callPythonWithTaintedArgs(userInput: string): void {
        // TAINT SOURCE: User input

        // TAINT SINK: Command Injection via Python call
        execSync(`python3 process.py --input "${userInput}"`); // VULNERABILITY
    }

    /**
     * VULNERABILITY: Calling Java with tainted system properties
     */
    callJavaWithTaintedProps(configValue: string): void {
        // TAINT SOURCE: External config

        // TAINT SINK: Command Injection via Java call
        execSync(`java -Dconfig.value=${configValue} -jar app.jar`); // VULNERABILITY
    }

    /**
     * VULNERABILITY: Node child process with tainted env
     */
    spawnWithTaintedEnv(envValue: string): void {
        // TAINT SOURCE: External value
        const env = {
            ...process.env,
            USER_CONFIG: envValue, // Tainted environment variable
        };

        // TAINT SINK: Environment variable injection
        exec('node worker.js', { env }); // VULNERABILITY
    }

    /**
     * VULNERABILITY: FFI/native call with tainted buffer
     */
    nativeCallWithTaintedData(userData: string): void {
        // TAINT SOURCE: User data

        // Simulated native call via command
        // TAINT SINK: Buffer overflow / injection via native call
        const buffer = Buffer.from(userData);
        execSync(`native-processor "${buffer.toString('base64')}"`); // VULNERABILITY
    }
}

// =============================================================================
// ASYNC BOUNDARY CROSSING TESTS
// =============================================================================

class AsyncBoundaryCrossingTests {
    private taintedData: string = '';

    /**
     * VULNERABILITY: Taint across promise boundaries
     */
    async promiseBoundaryTaint(input: string): Promise<void> {
        // TAINT SOURCE
        const tainted = await Promise.resolve(input);

        // Taint persists across await
        await new Promise((resolve) => setTimeout(resolve, 100));

        // TAINT SINK: Still tainted after async boundary
        eval(tainted); // VULNERABILITY: Code Injection
    }

    /**
     * VULNERABILITY: Taint through callback chains
     */
    callbackChainTaint(input: string, callback: (result: string) => void): void {
        // TAINT SOURCE
        this.taintedData = input;

        setTimeout(() => {
            // Taint captured in closure
            const processed = this.taintedData.toUpperCase();

            process.nextTick(() => {
                // TAINT SINK: Command Injection through callbacks
                exec(processed); // VULNERABILITY
                callback(processed);
            });
        }, 100);
    }

    /**
     * VULNERABILITY: Event emitter taint propagation
     */
    eventEmitterTaint(input: string): void {
        const EventEmitter = require('events');
        const emitter = new EventEmitter();

        // TAINT SOURCE: Input captured in event data
        emitter.on('process', (data: string) => {
            // TAINT SINK: Data from event is still tainted
            fs.writeFileSync(data, 'content'); // VULNERABILITY: Path Traversal
        });

        emitter.emit('process', input);
    }

    /**
     * VULNERABILITY: Promise.all preserves taint in array
     */
    async promiseAllTaint(inputs: string[]): Promise<void> {
        // TAINT SOURCE: Array of tainted inputs
        const results = await Promise.all(
            inputs.map((input) => Promise.resolve(input))
        );

        // All results are still tainted
        for (const result of results) {
            // TAINT SINK: SQL Injection
            const query = `INSERT INTO logs VALUES ('${result}')`;
            console.log(query); // VULNERABILITY
        }
    }
}

// =============================================================================
// RUNTIME TYPE CHECK BYPASS TESTS
// =============================================================================

class RuntimeTypeCheckBypassTests {
    /**
     * VULNERABILITY: instanceof check doesn't verify string safety
     */
    instanceofBypass(input: unknown): void {
        if (input instanceof String || typeof input === 'string') {
            // String type doesn't mean safe!
            // TAINT SINK: SQL Injection
            const query = `SELECT * FROM t WHERE x = '${input}'`;
            console.log(query); // VULNERABILITY
        }
    }

    /**
     * VULNERABILITY: Array.isArray doesn't verify element safety
     */
    arrayCheckBypass(input: unknown): void {
        if (Array.isArray(input)) {
            // Array check doesn't sanitize contents
            // TAINT SINK: Command Injection via array join
            exec(`process ${input.join(' ')}`); // VULNERABILITY
        }
    }

    /**
     * VULNERABILITY: typeof guard is insufficient
     */
    typeofGuardBypass(input: unknown): string {
        if (typeof input === 'string') {
            // typeof === 'string' does NOT mean safe
            // TAINT SINK: Path Traversal
            return fs.readFileSync(input, 'utf-8'); // VULNERABILITY
        }
        return '';
    }

    /**
     * VULNERABILITY: Custom type guard can be wrong
     */
    isSafeInput(input: unknown): input is SafeUserInput {
        // This type guard is WRONG - it doesn't actually validate
        return typeof input === 'object' && input !== null;
    }

    useCustomTypeGuard(input: unknown): void {
        if (this.isSafeInput(input)) {
            // Type guard passed but data is still tainted
            // TAINT SINK: SQL Injection
            const query = `SELECT * FROM users WHERE id = ${input.id}`;
            console.log(query); // VULNERABILITY
        }
    }
}

// =============================================================================
// TEST RUNNER
// =============================================================================

function runCrossLanguageTypeBoundaryTests(): void {
    console.log('='.repeat(60));
    console.log('CROSS-LANGUAGE TYPE BOUNDARY TEST SUITE');
    console.log('='.repeat(60));
    console.log('');
    console.log('Test Categories:');
    console.log('  1. Type Evaporation (5 tests)');
    console.log('  2. JSON Serialization Boundaries (4 tests)');
    console.log('  3. REST API Boundaries (4 tests)');
    console.log('  4. Cross-Language Calls (4 tests)');
    console.log('  5. Async Boundary Crossing (4 tests)');
    console.log('  6. Runtime Type Check Bypass (5 tests)');
    console.log('');
    console.log('Expected Vulnerabilities: 26');
    console.log('='.repeat(60));
}

export {
    TypeEvaporationTests,
    JsonSerializationBoundaryTests,
    RestApiBoundaryTests,
    CrossLanguageCallTests,
    AsyncBoundaryCrossingTests,
    RuntimeTypeCheckBypassTests,
    runCrossLanguageTypeBoundaryTests,
};
