/**
 * =============================================================================
 * JAVASCRIPT CROSS-FILE TAINT TRACKING TEST SUITE
 * =============================================================================
 *
 * PURPOSE: Test taint propagation across JavaScript files, modules, and
 * service boundaries. JavaScript's dynamic nature and module system create
 * unique challenges for cross-file taint tracking.
 *
 * STRUCTURE: This file simulates multiple modules that would typically be
 * in separate files. Code Scalpel must track taint across these boundaries.
 *
 * =============================================================================
 */

const { exec, execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');

// =============================================================================
// MODULE 1: DATA SOURCES (Simulates data_source.js)
// =============================================================================

/**
 * UserInputSource - All methods return TAINTED data
 */
class UserInputSource {
    /**
     * TAINT SOURCE: HTTP query parameter
     */
    getQueryParam(paramName) {
        return `tainted_query_${paramName}`;
    }

    /**
     * TAINT SOURCE: HTTP form data
     */
    getFormData(fieldName) {
        return `tainted_form_${fieldName}`;
    }

    /**
     * TAINT SOURCE: JSON request body
     */
    getJsonBody() {
        return {
            userId: 'tainted_user_id',
            action: 'tainted_action',
            query: 'tainted_query'
        };
    }

    /**
     * TAINT SOURCE: HTTP header
     */
    getHeader(headerName) {
        return `tainted_header_${headerName}`;
    }

    /**
     * TAINT SOURCE: Cookie value
     */
    getCookie(cookieName) {
        return `tainted_cookie_${cookieName}`;
    }

    /**
     * TAINT SOURCE: URL path parameter
     */
    getPathParam(paramName) {
        return `tainted_path_${paramName}`;
    }

    /**
     * TAINT SOURCE: WebSocket message
     */
    getWebSocketMessage() {
        return { type: 'message', data: 'tainted_ws_data' };
    }
}

/**
 * ExternalDataSource - External data that should be treated as untrusted
 */
class ExternalDataSource {
    /**
     * TAINT SOURCE: Message queue data
     */
    readFromQueue(queueName) {
        return 'tainted_queue_message';
    }

    /**
     * TAINT SOURCE: Database content (stored XSS potential)
     */
    readFromDatabase(query) {
        return { content: 'tainted_db_content' };
    }

    /**
     * TAINT SOURCE: External API response
     */
    async callExternalApi(url) {
        return { data: 'tainted_api_response' };
    }

    /**
     * TAINT SOURCE: File content (if attacker-controllable path)
     */
    readFromFile(filepath) {
        return 'tainted_file_content';
    }
}

// =============================================================================
// MODULE 2: DATA PROCESSORS (Simulates data_processor.js)
// =============================================================================

/**
 * DataProcessor - Transforms data but does NOT sanitize
 */
class DataProcessor {
    /**
     * TAINT PRESERVING: Validation does NOT remove taint
     */
    validateInput(data) {
        if (!data) {
            throw new Error('Empty input');
        }
        if (data.length > 10000) {
            throw new Error('Input too long');
        }
        return data; // STILL TAINTED
    }

    /**
     * TAINT PRESERVING: Transformation does NOT sanitize
     */
    transformInput(data) {
        return data.toUpperCase().trim(); // STILL TAINTED
    }

    /**
     * TAINT PRESERVING: Formatting does NOT sanitize
     */
    formatOutput(data) {
        return `[PROCESSED] ${data}`; // STILL TAINTED
    }

    /**
     * TAINT PRESERVING: JSON parsing preserves taint
     */
    parseJson(jsonStr) {
        return JSON.parse(jsonStr); // All values TAINTED
    }

    /**
     * TAINT PRESERVING: Object spread preserves taint
     */
    mergeWithDefaults(data) {
        const defaults = { safe: true, role: 'user' };
        return { ...defaults, ...data }; // Taint from data spreads
    }

    /**
     * TAINT PRESERVING: Array operations preserve taint
     */
    processArray(items) {
        return items
            .filter(item => item.length > 0)
            .map(item => item.toLowerCase());
        // All items STILL TAINTED
    }
}

/**
 * DataTransformer - Multi-step pipeline that preserves taint
 */
class DataTransformer {
    constructor(processor) {
        this.processor = processor;
    }

    /**
     * TAINT CHAIN: Full pipeline preserves taint through all steps
     */
    fullPipeline(rawInput) {
        const validated = this.processor.validateInput(rawInput);
        const transformed = this.processor.transformInput(validated);
        const formatted = this.processor.formatOutput(transformed);
        return formatted; // STILL TAINTED after 3 transformations
    }

    /**
     * TAINT CHAIN: Async pipeline
     */
    async asyncPipeline(rawInput) {
        const validated = await Promise.resolve(
            this.processor.validateInput(rawInput)
        );
        const transformed = await new Promise((resolve) =>
            setTimeout(() => resolve(this.processor.transformInput(validated)), 10)
        );
        return transformed; // STILL TAINTED after async transformations
    }
}

// =============================================================================
// MODULE 3: DATA SINKS (Simulates data_sink.js)
// =============================================================================

/**
 * DatabaseSink - SQL operations with tainted data = SQL Injection
 */
class DatabaseSink {
    constructor() {
        this.queries = [];
    }

    /**
     * TAINT SINK: SQL Injection if whereClause is tainted
     */
    executeQuery(whereClause) {
        const query = `SELECT * FROM users WHERE ${whereClause}`;
        this.queries.push(query);
        console.log(query); // VULNERABILITY: SQL Injection
        return [];
    }

    /**
     * TAINT SINK: SQL Injection via INSERT
     */
    insertData(table, column, value) {
        const query = `INSERT INTO ${table} (${column}) VALUES ('${value}')`;
        console.log(query); // VULNERABILITY: SQL Injection
    }

    /**
     * TAINT SINK: SQL Injection via dynamic table name
     */
    queryTable(tableName, conditions) {
        const query = `SELECT * FROM ${tableName} WHERE ${conditions}`;
        console.log(query); // VULNERABILITY: SQL Injection
    }
}

/**
 * CommandSink - Command execution with tainted data = Command Injection
 */
class CommandSink {
    /**
     * TAINT SINK: Command Injection via exec
     */
    executeCommand(userArg) {
        exec(`echo ${userArg}`, (error, stdout) => {
            console.log(stdout);
        }); // VULNERABILITY: Command Injection
    }

    /**
     * TAINT SINK: Command Injection via execSync
     */
    executeCommandSync(userArg) {
        return execSync(`cat ${userArg}`).toString(); // VULNERABILITY
    }

    /**
     * TAINT SINK: Command Injection via spawn with shell
     */
    spawnWithShell(command) {
        spawn(command, { shell: true }); // VULNERABILITY
    }
}

/**
 * FileSink - File operations with tainted paths = Path Traversal
 */
class FileSink {
    /**
     * TAINT SINK: Path Traversal via readFile
     */
    readFile(filepath) {
        return fs.readFileSync(filepath, 'utf-8'); // VULNERABILITY
    }

    /**
     * TAINT SINK: Path Traversal via writeFile
     */
    writeFile(filepath, content) {
        fs.writeFileSync(filepath, content); // VULNERABILITY
    }

    /**
     * TAINT SINK: Path Traversal via path.join
     */
    readWithJoin(basePath, userPath) {
        const fullPath = path.join(basePath, userPath);
        return fs.readFileSync(fullPath, 'utf-8'); // VULNERABILITY
    }
}

/**
 * EvalSink - Code execution with tainted data = Code Injection
 */
class EvalSink {
    /**
     * TAINT SINK: Code Injection via eval
     */
    evaluate(expression) {
        return eval(expression); // VULNERABILITY
    }

    /**
     * TAINT SINK: Code Injection via Function constructor
     */
    createFunction(body) {
        return new Function(body)(); // VULNERABILITY
    }

    /**
     * TAINT SINK: Code Injection via setTimeout with string
     */
    delayedEval(code) {
        setTimeout(code, 100); // VULNERABILITY
    }
}

// =============================================================================
// MODULE 4: INTEGRATION (Simulates integration.js)
// =============================================================================

/**
 * VulnerableApplication - Integrates sources, processors, and sinks
 * This demonstrates end-to-end taint flow across module boundaries
 */
class VulnerableApplication {
    constructor() {
        this.source = new UserInputSource();
        this.externalSource = new ExternalDataSource();
        this.processor = new DataProcessor();
        this.transformer = new DataTransformer(this.processor);
        this.dbSink = new DatabaseSink();
        this.cmdSink = new CommandSink();
        this.fileSink = new FileSink();
        this.evalSink = new EvalSink();
    }

    /**
     * CROSS-FILE VULNERABILITY: SQL Injection through processing chain
     */
    vulnerableSqlEndpoint(requestParam) {
        // Source (data_source.js)
        const userInput = this.source.getQueryParam(requestParam);

        // Processing (data_processor.js)
        const validated = this.processor.validateInput(userInput);
        const transformed = this.processor.transformInput(validated);

        // Sink (data_sink.js)
        return this.dbSink.executeQuery(transformed); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: Command Injection through formatting
     */
    vulnerableCommandEndpoint(filenameParam) {
        const userInput = this.source.getFormData(filenameParam);
        const formatted = this.processor.formatOutput(userInput);
        return this.cmdSink.executeCommand(formatted); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: Path Traversal via path parameter
     */
    vulnerableFileEndpoint(pathParam) {
        const userPath = this.source.getPathParam(pathParam);
        return this.fileSink.readFile(userPath); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: Code Injection via JSON body
     */
    vulnerableEvalEndpoint() {
        const jsonBody = this.source.getJsonBody();
        const expression = jsonBody.action;
        return this.evalSink.evaluate(expression); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: Multi-hop with async pipeline
     */
    async complexAsyncVulnerability() {
        // Hop 1: Source
        const raw = this.source.getQueryParam('search');

        // Hops 2-4: Async processing
        const processed = await this.transformer.asyncPipeline(raw);

        // Hop 5: Sink
        return this.dbSink.executeQuery(processed); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: External API -> SQL
     */
    async externalApiToSql(apiUrl) {
        const response = await this.externalSource.callExternalApi(apiUrl);
        const data = response.data;
        return this.dbSink.insertData('logs', 'message', data); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: Queue message -> Command
     */
    queueToCommand(queueName) {
        const message = this.externalSource.readFromQueue(queueName);
        return this.cmdSink.executeCommand(message); // VULNERABILITY
    }
}

// =============================================================================
// MODULE 5: EVENT-DRIVEN CROSS-FILE TAINT
// =============================================================================

/**
 * EventBus - Demonstrates taint through event-driven architecture
 */
class EventBus extends EventEmitter {
    constructor() {
        super();
        this.setupHandlers();
    }

    setupHandlers() {
        // Handler that receives tainted data
        this.on('userInput', (data) => {
            // TAINT SINK: SQL Injection via event
            const query = `SELECT * FROM events WHERE data = '${data}'`;
            console.log(query); // VULNERABILITY
        });

        // Handler with command execution
        this.on('processCommand', (cmd) => {
            // TAINT SINK: Command Injection via event
            exec(cmd); // VULNERABILITY
        });

        // Handler with file operation
        this.on('readFile', (filepath) => {
            // TAINT SINK: Path Traversal via event
            fs.readFileSync(filepath); // VULNERABILITY
        });
    }
}

/**
 * EventDrivenApp - Cross-file taint through events
 */
class EventDrivenApp {
    constructor() {
        this.source = new UserInputSource();
        this.bus = new EventBus();
    }

    /**
     * CROSS-FILE VULNERABILITY: Taint through event emission
     */
    processUserInput(paramName) {
        const input = this.source.getQueryParam(paramName);
        this.bus.emit('userInput', input); // Taint flows to handler
    }

    /**
     * CROSS-FILE VULNERABILITY: Multiple events with tainted data
     */
    processMultipleInputs() {
        const cmd = this.source.getFormData('command');
        const file = this.source.getPathParam('file');

        this.bus.emit('processCommand', cmd); // VULNERABILITY
        this.bus.emit('readFile', file); // VULNERABILITY
    }
}

// =============================================================================
// MODULE 6: CALLBACK AND CLOSURE CROSS-FILE TAINT
// =============================================================================

/**
 * CallbackProcessor - Taint through callbacks
 */
class CallbackProcessor {
    /**
     * TAINT PRESERVING: Callback receives tainted data
     */
    processWithCallback(data, callback) {
        const processed = data.toUpperCase();
        callback(processed); // Tainted data passed to callback
    }

    /**
     * TAINT PRESERVING: Higher-order function with taint
     */
    createProcessor(transformer) {
        return (data) => {
            const transformed = transformer(data);
            return transformed; // Still tainted
        };
    }
}

/**
 * ClosureApp - Cross-file taint through closures
 */
class ClosureApp {
    constructor() {
        this.source = new UserInputSource();
        this.callbackProcessor = new CallbackProcessor();
    }

    /**
     * CROSS-FILE VULNERABILITY: Taint in callback
     */
    processWithTaintedCallback(paramName) {
        const input = this.source.getQueryParam(paramName);

        this.callbackProcessor.processWithCallback(input, (result) => {
            // TAINT SINK: SQL Injection in callback
            const query = `SELECT * FROM data WHERE x = '${result}'`;
            console.log(query); // VULNERABILITY
        });
    }

    /**
     * CROSS-FILE VULNERABILITY: Taint captured in closure
     */
    createTaintedHandler(paramName) {
        const input = this.source.getQueryParam(paramName);

        // Closure captures tainted input
        return () => {
            // TAINT SINK: Command Injection via closure
            exec(input); // VULNERABILITY
        };
    }

    /**
     * CROSS-FILE VULNERABILITY: Higher-order function with taint
     */
    useHigherOrderProcessor() {
        const input = this.source.getFormData('data');
        const processor = this.callbackProcessor.createProcessor(
            (x) => x.toLowerCase()
        );
        const result = processor(input);

        // TAINT SINK: Path Traversal
        fs.readFileSync(result); // VULNERABILITY
    }
}

// =============================================================================
// MODULE 7: PROMISE CHAIN CROSS-FILE TAINT
// =============================================================================

/**
 * AsyncService - Async operations that preserve taint
 */
class AsyncService {
    async fetchData(query) {
        return { data: `result_for_${query}` }; // Tainted if query is tainted
    }

    async processData(data) {
        return data.toUpperCase(); // Still tainted
    }

    async saveData(data) {
        // TAINT SINK: SQL Injection in async method
        const query = `INSERT INTO results VALUES ('${data}')`;
        console.log(query); // VULNERABILITY
    }
}

/**
 * PromiseChainApp - Cross-file taint through promise chains
 */
class PromiseChainApp {
    constructor() {
        this.source = new UserInputSource();
        this.asyncService = new AsyncService();
    }

    /**
     * CROSS-FILE VULNERABILITY: Promise chain maintains taint
     */
    async promiseChainVulnerability(paramName) {
        const input = this.source.getQueryParam(paramName);

        const result = await this.asyncService.fetchData(input)
            .then(res => this.asyncService.processData(res.data));

        // TAINT SINK: Command Injection after promise chain
        exec(result); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: Promise.all with tainted data
     */
    async promiseAllVulnerability() {
        const inputs = [
            this.source.getQueryParam('a'),
            this.source.getQueryParam('b'),
            this.source.getQueryParam('c')
        ];

        const results = await Promise.all(
            inputs.map(input => this.asyncService.processData(input))
        );

        // TAINT SINK: SQL Injection with all results
        results.forEach(result => {
            const query = `INSERT INTO log VALUES ('${result}')`;
            console.log(query); // VULNERABILITY (3x)
        });
    }
}

// =============================================================================
// TEST RUNNER
// =============================================================================

function runCrossFileTaintTests() {
    console.log('='.repeat(60));
    console.log('JAVASCRIPT CROSS-FILE TAINT TRACKING TEST SUITE');
    console.log('='.repeat(60));
    console.log('');
    console.log('Module Structure:');
    console.log('  1. Data Sources (UserInputSource, ExternalDataSource)');
    console.log('  2. Data Processors (DataProcessor, DataTransformer)');
    console.log('  3. Data Sinks (DatabaseSink, CommandSink, FileSink, EvalSink)');
    console.log('  4. Integration (VulnerableApplication)');
    console.log('  5. Event-Driven (EventBus, EventDrivenApp)');
    console.log('  6. Callbacks/Closures (CallbackProcessor, ClosureApp)');
    console.log('  7. Promise Chains (AsyncService, PromiseChainApp)');
    console.log('');
    console.log('Cross-File Taint Paths: 20+');
    console.log('Expected Vulnerabilities: 35');
    console.log('='.repeat(60));
}

module.exports = {
    // Sources
    UserInputSource,
    ExternalDataSource,
    // Processors
    DataProcessor,
    DataTransformer,
    // Sinks
    DatabaseSink,
    CommandSink,
    FileSink,
    EvalSink,
    // Integration
    VulnerableApplication,
    // Event-driven
    EventBus,
    EventDrivenApp,
    // Callbacks/Closures
    CallbackProcessor,
    ClosureApp,
    // Async
    AsyncService,
    PromiseChainApp,
    // Runner
    runCrossFileTaintTests
};
