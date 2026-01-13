/**
 * =============================================================================
 * TYPESCRIPT ADVANCED TYPE SYSTEM TAINT TEST SUITE
 * =============================================================================
 *
 * PURPOSE: Test taint tracking through TypeScript's advanced type system
 * features where type safety provides a false sense of security.
 *
 * CRITICAL SCENARIOS:
 * 1. Generic type constraints bypassed at runtime
 * 2. Conditional types losing taint information
 * 3. Mapped types and utility types with tainted data
 * 4. Template literal types with injection
 * 5. Discriminated unions with tainted discriminants
 * 6. Type guards that don't validate content
 *
 * =============================================================================
 */

import { exec, execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

// =============================================================================
// GENERIC TYPE CONSTRAINT BYPASS TESTS
// =============================================================================

interface SafeInput {
    readonly validated: true;
    value: string;
}

interface UnsafeInput {
    validated?: false;
    value: string;
}

type StrictlyTyped<T extends SafeInput> = {
    data: T;
    timestamp: number;
};

class GenericConstraintBypassTests {
    /**
     * VULNERABILITY: Generic constraint doesn't ensure safety at runtime
     */
    processWithConstraint<T extends SafeInput>(input: T): void {
        // TypeScript thinks input.value is safe because T extends SafeInput
        // But at runtime, anything can be passed via type assertion

        // TAINT SINK: SQL Injection - constraint provides no runtime protection
        const query = `SELECT * FROM data WHERE value = '${input.value}'`;
        console.log(query); // VULNERABILITY
    }

    /**
     * VULNERABILITY: Generic constraint with conditional bypass
     */
    conditionalGeneric<T extends { safe: boolean; value: string }>(
        input: T
    ): string {
        // Conditional based on type property doesn't sanitize
        if (input.safe) {
            // Developer thinks this path is safe
            // TAINT SINK: Still vulnerable
            return execSync(`echo ${input.value}`).toString(); // VULNERABILITY
        }
        return 'rejected';
    }

    /**
     * VULNERABILITY: Generic array element access
     */
    processGenericArray<T extends string[]>(items: T): void {
        // Each element in T is still tainted
        for (const item of items) {
            // TAINT SINK: Command Injection per element
            exec(`process ${item}`); // VULNERABILITY
        }
    }

    /**
     * VULNERABILITY: Generic function return type
     */
    genericTransform<T, R>(input: T, transform: (t: T) => R): R {
        // Transform function preserves taint
        const result = transform(input);
        return result; // TAINTED if input was tainted
    }

    useGenericTransform(userInput: string): void {
        const result = this.genericTransform(userInput, (s) => s.toUpperCase());
        // TAINT SINK: Result is still tainted
        fs.writeFileSync(result, 'data'); // VULNERABILITY: Path Traversal
    }
}

// =============================================================================
// CONDITIONAL TYPE TAINT TESTS
// =============================================================================

type ExtractString<T> = T extends string ? T : never;
type UnwrapPromise<T> = T extends Promise<infer U> ? U : T;
type FlattenArray<T> = T extends Array<infer U> ? U : T;

type IsString<T> = T extends string ? 'string' : 'other';
type SafeOrUnsafe<T> = T extends { validated: true } ? 'safe' : 'unsafe';

class ConditionalTypeTaintTests {
    /**
     * VULNERABILITY: Conditional type extraction preserves taint
     */
    extractString<T>(input: T): ExtractString<T> {
        if (typeof input === 'string') {
            // Conditional type narrows but doesn't sanitize
            return input as ExtractString<T>; // STILL TAINTED
        }
        throw new Error('Not a string');
    }

    useExtractedString(userInput: unknown): void {
        const extracted = this.extractString(userInput);
        // TAINT SINK: SQL Injection with extracted value
        const query = `SELECT * FROM t WHERE x = '${extracted}'`;
        console.log(query); // VULNERABILITY
    }

    /**
     * VULNERABILITY: Promise unwrapping preserves taint
     */
    async unwrapPromise<T>(input: Promise<T>): Promise<UnwrapPromise<Promise<T>>> {
        const result = await input;
        return result as UnwrapPromise<Promise<T>>; // TAINTED if promise resolved tainted value
    }

    async useUnwrappedPromise(taintedPromise: Promise<string>): Promise<void> {
        const value = await this.unwrapPromise(taintedPromise);
        // TAINT SINK: Command Injection
        exec(value); // VULNERABILITY
    }

    /**
     * VULNERABILITY: Array flattening preserves element taint
     */
    flattenArray<T>(input: T[]): FlattenArray<T[]>[] {
        return input as FlattenArray<T[]>[]; // Each element still tainted
    }

    useFlattenedArray(taintedArray: string[][]): void {
        const flattened = this.flattenArray(taintedArray.flat());
        for (const item of flattened) {
            // TAINT SINK: Path Traversal per element
            fs.readFileSync(`/data/${item}`); // VULNERABILITY
        }
    }

    /**
     * VULNERABILITY: Type narrowing via conditional doesn't sanitize
     */
    checkType<T>(input: T): IsString<T> {
        if (typeof input === 'string') {
            return 'string' as IsString<T>;
        }
        return 'other' as IsString<T>;
    }

    processBasedOnType(input: unknown): void {
        const typeCheck = this.checkType(input);
        if (typeCheck === 'string') {
            // Input is string but still tainted!
            // TAINT SINK: Eval
            eval(input as string); // VULNERABILITY
        }
    }
}

// =============================================================================
// MAPPED TYPE TAINT TESTS
// =============================================================================

type Readonly<T> = { readonly [P in keyof T]: T[P] };
type Partial<T> = { [P in keyof T]?: T[P] };
type Required<T> = { [P in keyof T]-?: T[P] };
type Nullable<T> = { [P in keyof T]: T[P] | null };

type MakeUnsafe<T> = { [P in keyof T]: any };
type Stringify<T> = { [P in keyof T]: string };

class MappedTypeTaintTests {
    /**
     * VULNERABILITY: Readonly doesn't prevent tainted usage
     */
    processReadonly(input: Readonly<{ command: string; path: string }>): void {
        // Readonly prevents mutation, not tainted execution
        // TAINT SINK: Command Injection
        exec(input.command); // VULNERABILITY

        // TAINT SINK: Path Traversal
        fs.readFileSync(input.path); // VULNERABILITY
    }

    /**
     * VULNERABILITY: Partial type still holds tainted values
     */
    processPartial(input: Partial<{ query: string; table: string }>): void {
        if (input.query && input.table) {
            // Optional fields are still tainted when present
            // TAINT SINK: SQL Injection
            const sql = `SELECT ${input.query} FROM ${input.table}`;
            console.log(sql); // VULNERABILITY
        }
    }

    /**
     * VULNERABILITY: Required doesn't validate content
     */
    processRequired(
        input: Required<{ filename?: string; content?: string }>
    ): void {
        // Required ensures presence, not safety
        // TAINT SINK: Path Traversal
        fs.writeFileSync(input.filename, input.content); // VULNERABILITY
    }

    /**
     * VULNERABILITY: Custom mapped type with taint
     */
    processStringified(input: Stringify<{ id: number; name: string }>): void {
        // All values are strings but still tainted
        // TAINT SINK: SQL Injection
        const query = `SELECT * FROM t WHERE id = '${input.id}' AND name = '${input.name}'`;
        console.log(query); // VULNERABILITY
    }

    /**
     * VULNERABILITY: Pick and Omit preserve taint
     */
    processPickedFields(input: Pick<{ a: string; b: string; c: string }, 'a' | 'b'>): void {
        // Picked fields are still tainted
        // TAINT SINK: Command Injection
        execSync(`${input.a} ${input.b}`); // VULNERABILITY
    }

    processOmittedFields(input: Omit<{ safe: boolean; unsafe: string }, 'safe'>): void {
        // Omitting a field doesn't make others safe
        // TAINT SINK: Eval
        eval(input.unsafe); // VULNERABILITY
    }
}

// =============================================================================
// TEMPLATE LITERAL TYPE TAINT TESTS
// =============================================================================

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE';
type ApiPath = `/api/${string}`;
type FullUrl = `https://${string}`;

type SqlColumn = `col_${string}`;
type TableName = `tbl_${string}`;

class TemplateLiteralTypeTaintTests {
    /**
     * VULNERABILITY: Template literal type at runtime is just a string
     */
    makeApiCall(method: HttpMethod, apiPath: ApiPath): void {
        // apiPath matches template but content is tainted
        const url = `https://api.example.com${apiPath}`;

        // TAINT SINK: SSRF via template literal typed path
        fetch(url); // VULNERABILITY
    }

    /**
     * VULNERABILITY: SQL column template doesn't prevent injection
     */
    queryWithColumn(column: SqlColumn, table: TableName): void {
        // Template types provide pattern matching, not sanitization
        // TAINT SINK: SQL Injection
        const query = `SELECT ${column} FROM ${table}`;
        console.log(query); // VULNERABILITY
    }

    /**
     * VULNERABILITY: URL template type doesn't validate
     */
    fetchFromUrl(url: FullUrl): void {
        // Type ensures https:// prefix but content after is tainted
        // TAINT SINK: SSRF
        fetch(url); // VULNERABILITY
    }

    /**
     * VULNERABILITY: Dynamic template literal construction
     */
    buildPath(base: string, segment: string): ApiPath {
        // TAINT SOURCE flows into template literal
        const path = `/api/${segment}` as ApiPath; // TAINTED

        // Using the tainted path
        return path;
    }

    useBuildPath(userSegment: string): void {
        const apiPath = this.buildPath('/api', userSegment);
        // TAINT SINK: Path used in file operation
        fs.readFileSync(apiPath); // VULNERABILITY: Path Traversal
    }
}

// =============================================================================
// DISCRIMINATED UNION TAINT TESTS
// =============================================================================

type SafeAction = { type: 'safe'; value: string };
type UnsafeAction = { type: 'unsafe'; value: string };
type Action = SafeAction | UnsafeAction;

type SuccessResult = { success: true; data: string };
type ErrorResult = { success: false; error: string };
type Result = SuccessResult | ErrorResult;

class DiscriminatedUnionTaintTests {
    /**
     * VULNERABILITY: Discriminant can be tainted
     */
    processAction(action: Action): void {
        // Discriminant itself could be tainted/spoofed at runtime
        if (action.type === 'safe') {
            // Developer trusts this path
            // TAINT SINK: But action.value is still tainted
            exec(action.value); // VULNERABILITY
        }
    }

    /**
     * VULNERABILITY: Union narrowing doesn't sanitize
     */
    handleResult(result: Result): void {
        if (result.success) {
            // Narrowed to SuccessResult, but data is tainted
            // TAINT SINK: SQL Injection
            const query = `INSERT INTO results VALUES ('${result.data}')`;
            console.log(query); // VULNERABILITY
        } else {
            // error field is also tainted
            // TAINT SINK: XSS via error message
            console.log(`<div class="error">${result.error}</div>`); // VULNERABILITY
        }
    }

    /**
     * VULNERABILITY: Exhaustive switch doesn't protect values
     */
    exhaustiveSwitch(action: Action): string {
        switch (action.type) {
            case 'safe':
                // TAINT SINK: Command Injection in 'safe' case
                return execSync(action.value).toString(); // VULNERABILITY
            case 'unsafe':
                // Obviously unsafe
                return execSync(action.value).toString(); // VULNERABILITY
            default:
                const _exhaustive: never = action;
                return _exhaustive;
        }
    }

    /**
     * VULNERABILITY: Type guards with discriminated unions
     */
    isSafeAction(action: Action): action is SafeAction {
        return action.type === 'safe';
    }

    useTypeGuard(action: Action): void {
        if (this.isSafeAction(action)) {
            // Type guard narrows but doesn't sanitize value
            // TAINT SINK: Path Traversal
            fs.readFileSync(action.value); // VULNERABILITY
        }
    }
}

// =============================================================================
// TYPE ASSERTION AND CASTING TAINT TESTS
// =============================================================================

interface TrustedData {
    source: 'internal';
    payload: string;
}

interface UntrustedData {
    source: 'external';
    payload: string;
}

class TypeAssertionTaintTests {
    /**
     * VULNERABILITY: as assertion bypasses type safety
     */
    assertAsTrusted(data: unknown): TrustedData {
        // Type assertion provides NO runtime validation
        return data as TrustedData; // STILL UNTRUSTED/TAINTED
    }

    useAssertedData(externalData: unknown): void {
        const trusted = this.assertAsTrusted(externalData);
        // Developer thinks data is trusted because of the type
        // TAINT SINK: Command Injection
        exec(trusted.payload); // VULNERABILITY
    }

    /**
     * VULNERABILITY: Double assertion via unknown
     */
    doubleAssertion(data: UntrustedData): TrustedData {
        // Type system allows this but it's dangerous
        return (data as unknown) as TrustedData; // TAINTED
    }

    /**
     * VULNERABILITY: Non-null assertion preserves taint
     */
    nonNullAssertion(maybeValue: string | null | undefined): void {
        // Non-null assertion says "trust me, it exists"
        const value = maybeValue!; // Still tainted if original was tainted

        // TAINT SINK: SQL Injection
        const query = `SELECT * FROM t WHERE x = '${value}'`;
        console.log(query); // VULNERABILITY
    }

    /**
     * VULNERABILITY: const assertion doesn't sanitize
     */
    constAssertion(input: string): void {
        const config = {
            command: input, // TAINTED
            options: ['--flag'] as const,
        } as const;

        // const doesn't make the tainted value safe
        // TAINT SINK: Command Injection
        exec(config.command); // VULNERABILITY
    }

    /**
     * VULNERABILITY: satisfies operator preserves taint
     */
    satisfiesOperator(input: unknown): void {
        const validated = input satisfies { path: string } as { path: string };

        // satisfies checks type compatibility, not content safety
        // TAINT SINK: Path Traversal
        fs.readFileSync(validated.path); // VULNERABILITY
    }
}

// =============================================================================
// INFER AND COMPLEX TYPE TAINT TESTS
// =============================================================================

type InferReturn<T> = T extends (...args: any[]) => infer R ? R : never;
type InferArrayElement<T> = T extends (infer E)[] ? E : never;
type InferPromiseValue<T> = T extends Promise<infer V> ? V : never;

class InferTypeTaintTests {
    /**
     * VULNERABILITY: Inferred return type preserves taint
     */
    processInferredReturn<T extends (...args: any[]) => any>(
        fn: T,
        ...args: Parameters<T>
    ): InferReturn<T> {
        return fn(...args); // Return value tainted if fn processes tainted args
    }

    useTaintedFunction(userInput: string): void {
        const transform = (s: string) => s.toUpperCase();
        const result = this.processInferredReturn(transform, userInput);

        // TAINT SINK: Inferred return is tainted
        exec(result); // VULNERABILITY
    }

    /**
     * VULNERABILITY: Inferred array element taint
     */
    getFirstElement<T extends any[]>(arr: T): InferArrayElement<T> {
        return arr[0]; // Element is tainted if array contains tainted data
    }

    useArrayElement(taintedArray: string[]): void {
        const first = this.getFirstElement(taintedArray);
        // TAINT SINK: SQL Injection
        const query = `SELECT * FROM t WHERE x = '${first}'`;
        console.log(query); // VULNERABILITY
    }

    /**
     * VULNERABILITY: Deeply nested type inference
     */
    deepInfer<T extends Promise<{ data: { value: string }[] }>>(
        promise: T
    ): void {
        promise.then((result) => {
            for (const item of result.data) {
                // Deeply nested value is still tainted
                // TAINT SINK: Command Injection
                exec(item.value); // VULNERABILITY
            }
        });
    }
}

// =============================================================================
// TEST RUNNER
// =============================================================================

function runAdvancedTypeSystemTaintTests(): void {
    console.log('='.repeat(60));
    console.log('TYPESCRIPT ADVANCED TYPE SYSTEM TAINT TEST SUITE');
    console.log('='.repeat(60));
    console.log('');
    console.log('Test Categories:');
    console.log('  1. Generic Constraint Bypass (5 tests)');
    console.log('  2. Conditional Type Taint (5 tests)');
    console.log('  3. Mapped Type Taint (6 tests)');
    console.log('  4. Template Literal Type Taint (5 tests)');
    console.log('  5. Discriminated Union Taint (4 tests)');
    console.log('  6. Type Assertion Taint (5 tests)');
    console.log('  7. Infer Type Taint (3 tests)');
    console.log('');
    console.log('Expected Vulnerabilities: 38');
    console.log('='.repeat(60));
}

export {
    GenericConstraintBypassTests,
    ConditionalTypeTaintTests,
    MappedTypeTaintTests,
    TemplateLiteralTypeTaintTests,
    DiscriminatedUnionTaintTests,
    TypeAssertionTaintTests,
    InferTypeTaintTests,
    runAdvancedTypeSystemTaintTests,
};
