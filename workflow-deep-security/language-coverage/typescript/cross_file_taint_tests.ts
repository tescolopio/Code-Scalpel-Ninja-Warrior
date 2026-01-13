/**
 * =============================================================================
 * TYPESCRIPT CROSS-FILE TAINT TRACKING TEST SUITE
 * =============================================================================
 *
 * PURPOSE: Test taint propagation across TypeScript files/modules with
 * specific focus on type system boundaries where taint tracking can fail.
 *
 * STRUCTURE: Simulates multiple modules with typed interfaces.
 * Type annotations do NOT affect runtime taint - must be tracked regardless.
 *
 * =============================================================================
 */

import { exec, execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

interface TaintedInput {
    value: string;
    source: 'query' | 'body' | 'header' | 'cookie' | 'path';
}

interface SafeInput {
    value: string;
    validated: true;
    sanitized: true;
}

interface UserData {
    id: string;
    name: string;
    email: string;
    role: string;
}

interface ApiResponse<T> {
    data: T;
    status: number;
    message: string;
}

type ProcessorFn<T, R> = (input: T) => R;
type AsyncProcessorFn<T, R> = (input: T) => Promise<R>;

// =============================================================================
// MODULE 1: TYPED DATA SOURCES
// =============================================================================

class TypedUserInputSource {
    /**
     * TAINT SOURCE: Returns typed but tainted data
     */
    getQueryParam(paramName: string): TaintedInput {
        return {
            value: `tainted_query_${paramName}`,
            source: 'query'
        };
    }

    /**
     * TAINT SOURCE: Request body with interface
     */
    getRequestBody<T extends object>(): T {
        // Type parameter doesn't affect taint
        return {
            userId: 'tainted_user_id',
            action: 'tainted_action'
        } as T; // TAINTED despite type assertion
    }

    /**
     * TAINT SOURCE: Typed header value
     */
    getHeader(headerName: string): string {
        return `tainted_header_${headerName}`;
    }

    /**
     * TAINT SOURCE: User data object
     */
    getUserData(): UserData {
        return {
            id: 'tainted_id',
            name: 'tainted_name',
            email: 'tainted_email',
            role: 'tainted_role'
        }; // All fields TAINTED
    }
}

class TypedExternalSource {
    /**
     * TAINT SOURCE: Generic API response
     */
    async fetchApi<T>(url: string): Promise<ApiResponse<T>> {
        return {
            data: { value: 'tainted_api_data' } as T,
            status: 200,
            message: 'ok'
        }; // data is TAINTED
    }

    /**
     * TAINT SOURCE: Database query result
     */
    async queryDatabase<T>(query: string): Promise<T[]> {
        return [{ content: 'tainted_db_content' }] as T[];
    }
}

// =============================================================================
// MODULE 2: TYPED DATA PROCESSORS
// =============================================================================

class TypedDataProcessor {
    /**
     * TAINT PRESERVING: Type conversion doesn't sanitize
     */
    convertToSafe(input: TaintedInput): SafeInput {
        // Type assertion does NOT sanitize!
        return {
            value: input.value, // STILL TAINTED
            validated: true,
            sanitized: true
        };
    }

    /**
     * TAINT PRESERVING: Generic processor
     */
    process<T, R>(input: T, transformer: ProcessorFn<T, R>): R {
        return transformer(input); // Taint flows through generic
    }

    /**
     * TAINT PRESERVING: Async generic processor
     */
    async processAsync<T, R>(
        input: T,
        transformer: AsyncProcessorFn<T, R>
    ): Promise<R> {
        return transformer(input); // Taint preserved through async
    }

    /**
     * TAINT PRESERVING: Partial type transformation
     */
    transformPartial<T extends object>(
        input: T,
        updates: Partial<T>
    ): T {
        return { ...input, ...updates }; // Taint from both sources
    }

    /**
     * TAINT PRESERVING: Pick specific fields
     */
    pickFields<T, K extends keyof T>(input: T, keys: K[]): Pick<T, K> {
        const result = {} as Pick<T, K>;
        for (const key of keys) {
            result[key] = input[key]; // Each field still tainted
        }
        return result;
    }
}

class TypedDataTransformer {
    private processor: TypedDataProcessor;

    constructor(processor: TypedDataProcessor) {
        this.processor = processor;
    }

    /**
     * TAINT CHAIN: Pipeline with types
     */
    fullPipeline(raw: TaintedInput): SafeInput {
        // This looks like it creates SafeInput but it's still tainted
        const safe = this.processor.convertToSafe(raw);
        return safe; // TAINTED despite SafeInput type
    }

    /**
     * TAINT CHAIN: Generic pipeline
     */
    genericPipeline<T, R>(input: T, ...transformers: ProcessorFn<any, any>[]): R {
        let current: any = input;
        for (const transformer of transformers) {
            current = transformer(current);
        }
        return current as R; // TAINTED through entire chain
    }
}

// =============================================================================
// MODULE 3: TYPED DATA SINKS
// =============================================================================

class TypedDatabaseSink {
    /**
     * TAINT SINK: SQL Injection with typed input
     */
    executeQuery(input: SafeInput): void {
        // Type says SafeInput but value is still tainted!
        const query = `SELECT * FROM users WHERE data = '${input.value}'`;
        console.log(query); // VULNERABILITY
    }

    /**
     * TAINT SINK: SQL with UserData fields
     */
    insertUser(user: UserData): void {
        const query = `INSERT INTO users (id, name, email, role) VALUES
            ('${user.id}', '${user.name}', '${user.email}', '${user.role}')`;
        console.log(query); // VULNERABILITY (4 injection points)
    }

    /**
     * TAINT SINK: Generic query execution
     */
    queryWithParams<T extends Record<string, string>>(
        table: string,
        params: T
    ): void {
        const conditions = Object.entries(params)
            .map(([k, v]) => `${k} = '${v}'`)
            .join(' AND ');
        const query = `SELECT * FROM ${table} WHERE ${conditions}`;
        console.log(query); // VULNERABILITY
    }
}

class TypedCommandSink {
    /**
     * TAINT SINK: Command Injection despite types
     */
    executeCommand(input: SafeInput): void {
        exec(input.value); // VULNERABILITY
    }

    /**
     * TAINT SINK: Typed array of commands
     */
    executeMultiple(inputs: SafeInput[]): void {
        for (const input of inputs) {
            execSync(input.value); // VULNERABILITY per element
        }
    }
}

class TypedFileSink {
    /**
     * TAINT SINK: Path Traversal with typed path
     */
    readFile(filepath: SafeInput): string {
        return fs.readFileSync(filepath.value, 'utf-8'); // VULNERABILITY
    }

    /**
     * TAINT SINK: Generic file operation
     */
    processFile<T extends { path: string }>(input: T): void {
        fs.readFileSync(input.path); // VULNERABILITY
    }
}

class TypedEvalSink {
    /**
     * TAINT SINK: Code Injection with type assertion
     */
    evaluate(input: SafeInput): unknown {
        return eval(input.value); // VULNERABILITY
    }

    /**
     * TAINT SINK: Function from typed string
     */
    createFunction(body: SafeInput): Function {
        return new Function(body.value); // VULNERABILITY
    }
}

// =============================================================================
// MODULE 4: TYPED INTEGRATION
// =============================================================================

class TypedVulnerableApplication {
    private source: TypedUserInputSource;
    private externalSource: TypedExternalSource;
    private processor: TypedDataProcessor;
    private transformer: TypedDataTransformer;
    private dbSink: TypedDatabaseSink;
    private cmdSink: TypedCommandSink;
    private fileSink: TypedFileSink;
    private evalSink: TypedEvalSink;

    constructor() {
        this.source = new TypedUserInputSource();
        this.externalSource = new TypedExternalSource();
        this.processor = new TypedDataProcessor();
        this.transformer = new TypedDataTransformer(this.processor);
        this.dbSink = new TypedDatabaseSink();
        this.cmdSink = new TypedCommandSink();
        this.fileSink = new TypedFileSink();
        this.evalSink = new TypedEvalSink();
    }

    /**
     * CROSS-FILE VULNERABILITY: Types don't prevent SQL Injection
     */
    vulnerableSqlWithTypes(param: string): void {
        const input: TaintedInput = this.source.getQueryParam(param);
        const safe: SafeInput = this.transformer.fullPipeline(input);
        this.dbSink.executeQuery(safe); // VULNERABILITY despite SafeInput type
    }

    /**
     * CROSS-FILE VULNERABILITY: UserData fields are tainted
     */
    vulnerableUserInsert(): void {
        const user: UserData = this.source.getUserData();
        this.dbSink.insertUser(user); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: Generic taint propagation
     */
    vulnerableGenericProcessing(): void {
        const input = this.source.getQueryParam('data');
        const processed = this.processor.process(
            input,
            (i: TaintedInput) => ({ value: i.value.toUpperCase() } as SafeInput)
        );
        this.cmdSink.executeCommand(processed); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: Async generic taint
     */
    async vulnerableAsyncGeneric(): Promise<void> {
        const input = this.source.getQueryParam('cmd');
        const result = await this.processor.processAsync(
            input,
            async (i: TaintedInput) => {
                await new Promise(r => setTimeout(r, 10));
                return { value: i.value, validated: true, sanitized: true } as SafeInput;
            }
        );
        this.evalSink.evaluate(result); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: API response to SQL
     */
    async vulnerableApiToSql(): Promise<void> {
        const response = await this.externalSource.fetchApi<{ query: string }>(
            'https://api.example.com'
        );
        const query = `SELECT * FROM t WHERE x = '${response.data}'`;
        console.log(query); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: Partial type doesn't sanitize
     */
    vulnerablePartialUpdate(): void {
        const user = this.source.getUserData();
        const updated = this.processor.transformPartial(user, { role: 'admin' });
        this.dbSink.insertUser(updated); // VULNERABILITY (id, name, email still tainted)
    }

    /**
     * CROSS-FILE VULNERABILITY: Pick preserves taint
     */
    vulnerablePickFields(): void {
        const user = this.source.getUserData();
        const picked = this.processor.pickFields(user, ['id', 'name']);
        const query = `SELECT * FROM t WHERE id = '${picked.id}' AND name = '${picked.name}'`;
        console.log(query); // VULNERABILITY
    }
}

// =============================================================================
// MODULE 5: TYPED EVENT-DRIVEN TAINT
// =============================================================================

interface TypedEvent<T> {
    type: string;
    payload: T;
    timestamp: number;
}

class TypedEventBus extends EventEmitter {
    /**
     * TAINT PRESERVING: Typed event emission
     */
    emitTyped<T>(event: TypedEvent<T>): void {
        this.emit(event.type, event.payload);
    }

    /**
     * TAINT SINK: Handler receives tainted payload
     */
    setupHandlers(): void {
        this.on('userInput', (payload: SafeInput) => {
            // Type says SafeInput but it's still tainted
            const query = `SELECT * FROM t WHERE x = '${payload.value}'`;
            console.log(query); // VULNERABILITY
        });

        this.on('command', (payload: { cmd: string }) => {
            exec(payload.cmd); // VULNERABILITY
        });
    }
}

class TypedEventApp {
    private source: TypedUserInputSource;
    private bus: TypedEventBus;

    constructor() {
        this.source = new TypedUserInputSource();
        this.bus = new TypedEventBus();
        this.bus.setupHandlers();
    }

    /**
     * CROSS-FILE VULNERABILITY: Typed event with tainted data
     */
    emitTaintedEvent(): void {
        const input = this.source.getQueryParam('data');
        const event: TypedEvent<SafeInput> = {
            type: 'userInput',
            payload: { value: input.value, validated: true, sanitized: true },
            timestamp: Date.now()
        };
        this.bus.emitTyped(event); // Taint flows to handler
    }
}

// =============================================================================
// MODULE 6: GENERIC CROSS-FILE TAINT
// =============================================================================

class GenericService<T, R> {
    private transformer: ProcessorFn<T, R>;

    constructor(transformer: ProcessorFn<T, R>) {
        this.transformer = transformer;
    }

    /**
     * TAINT PRESERVING: Generic processing
     */
    process(input: T): R {
        return this.transformer(input);
    }
}

class GenericRepository<T extends { id: string }> {
    /**
     * TAINT SINK: Generic query
     */
    findById(id: string): void {
        const query = `SELECT * FROM entities WHERE id = '${id}'`;
        console.log(query); // VULNERABILITY if id is tainted
    }

    /**
     * TAINT SINK: Generic insert
     */
    save(entity: T): void {
        const query = `INSERT INTO entities (id) VALUES ('${entity.id}')`;
        console.log(query); // VULNERABILITY if entity.id is tainted
    }
}

class GenericTaintApp {
    private source: TypedUserInputSource;

    constructor() {
        this.source = new TypedUserInputSource();
    }

    /**
     * CROSS-FILE VULNERABILITY: Generic service chain
     */
    processWithGenericService(): void {
        const input = this.source.getQueryParam('data');

        const service = new GenericService<TaintedInput, SafeInput>(
            (i) => ({ value: i.value, validated: true, sanitized: true })
        );

        const result = service.process(input);
        exec(result.value); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: Generic repository
     */
    useGenericRepository(): void {
        const user = this.source.getUserData();
        const repo = new GenericRepository<UserData>();
        repo.findById(user.id); // VULNERABILITY
        repo.save(user); // VULNERABILITY
    }
}

// =============================================================================
// TEST RUNNER
// =============================================================================

function runTypescriptCrossFileTaintTests(): void {
    console.log('='.repeat(60));
    console.log('TYPESCRIPT CROSS-FILE TAINT TRACKING TEST SUITE');
    console.log('='.repeat(60));
    console.log('');
    console.log('Module Structure:');
    console.log('  1. Typed Sources (TypedUserInputSource, TypedExternalSource)');
    console.log('  2. Typed Processors (TypedDataProcessor, TypedDataTransformer)');
    console.log('  3. Typed Sinks (TypedDatabaseSink, TypedCommandSink, etc.)');
    console.log('  4. Typed Integration (TypedVulnerableApplication)');
    console.log('  5. Typed Events (TypedEventBus, TypedEventApp)');
    console.log('  6. Generic Classes (GenericService, GenericRepository)');
    console.log('');
    console.log('Key Insight: TypeScript types provide NO runtime protection');
    console.log('Cross-File Taint Paths: 20+');
    console.log('Expected Vulnerabilities: 30');
    console.log('='.repeat(60));
}

export {
    // Types
    TaintedInput,
    SafeInput,
    UserData,
    // Sources
    TypedUserInputSource,
    TypedExternalSource,
    // Processors
    TypedDataProcessor,
    TypedDataTransformer,
    // Sinks
    TypedDatabaseSink,
    TypedCommandSink,
    TypedFileSink,
    TypedEvalSink,
    // Integration
    TypedVulnerableApplication,
    // Events
    TypedEventBus,
    TypedEventApp,
    // Generics
    GenericService,
    GenericRepository,
    GenericTaintApp,
    // Runner
    runTypescriptCrossFileTaintTests,
};
