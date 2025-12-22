/**
 * =============================================================================
 * JAVA CROSS-FILE TAINT TRACKING TEST SUITE
 * =============================================================================
 *
 * PURPOSE: Test taint propagation across Java classes, packages, and layers.
 * Java's strong typing and OOP patterns create specific taint tracking
 * challenges across inheritance, interfaces, and dependency injection.
 *
 * STRUCTURE: Simulates a layered architecture with Controller -> Service ->
 * Repository pattern common in enterprise Java applications.
 *
 * =============================================================================
 */

package com.codescalpel.tests.crossfile;

import java.io.*;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;
import java.util.stream.*;

// =============================================================================
// LAYER 1: DATA SOURCES (Simulates controller/input layer)
// =============================================================================

/**
 * UserInputSource - All methods return TAINTED data
 */
class UserInputSource {
    /**
     * TAINT SOURCE: HTTP query parameter
     */
    public String getQueryParam(String paramName) {
        return "tainted_query_" + paramName;
    }

    /**
     * TAINT SOURCE: Form data
     */
    public String getFormData(String fieldName) {
        return "tainted_form_" + fieldName;
    }

    /**
     * TAINT SOURCE: JSON body as Map
     */
    public Map<String, String> getJsonBody() {
        Map<String, String> body = new HashMap<>();
        body.put("userId", "tainted_user_id");
        body.put("action", "tainted_action");
        body.put("query", "tainted_query");
        return body; // All values TAINTED
    }

    /**
     * TAINT SOURCE: HTTP header
     */
    public String getHeader(String headerName) {
        return "tainted_header_" + headerName;
    }

    /**
     * TAINT SOURCE: Path variable
     */
    public String getPathVariable(String varName) {
        return "tainted_path_" + varName;
    }

    /**
     * TAINT SOURCE: User DTO from request
     */
    public UserDTO getUserDTO() {
        UserDTO dto = new UserDTO();
        dto.setId("tainted_id");
        dto.setName("tainted_name");
        dto.setEmail("tainted_email");
        dto.setRole("tainted_role");
        return dto; // All fields TAINTED
    }
}

/**
 * DTO class - fields can be tainted
 */
class UserDTO {
    private String id;
    private String name;
    private String email;
    private String role;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
}

/**
 * ExternalDataSource - External data that should be untrusted
 */
class ExternalDataSource {
    /**
     * TAINT SOURCE: Message queue data
     */
    public String readFromQueue(String queueName) {
        return "tainted_queue_message";
    }

    /**
     * TAINT SOURCE: External API response
     */
    public Map<String, Object> callExternalApi(String url) {
        Map<String, Object> response = new HashMap<>();
        response.put("data", "tainted_api_data");
        return response;
    }

    /**
     * TAINT SOURCE: Database content (could contain stored XSS)
     */
    public String readFromDatabase(String query) {
        return "tainted_db_content";
    }
}

// =============================================================================
// LAYER 2: SERVICE LAYER (Business logic that preserves taint)
// =============================================================================

/**
 * DataProcessor - Transforms data but does NOT sanitize
 */
class DataProcessor {
    /**
     * TAINT PRESERVING: Validation does NOT remove taint
     */
    public String validateInput(String data) throws IllegalArgumentException {
        if (data == null || data.isEmpty()) {
            throw new IllegalArgumentException("Empty input");
        }
        if (data.length() > 10000) {
            throw new IllegalArgumentException("Input too long");
        }
        return data; // STILL TAINTED
    }

    /**
     * TAINT PRESERVING: Transformation does NOT sanitize
     */
    public String transformInput(String data) {
        return data.toUpperCase().trim(); // STILL TAINTED
    }

    /**
     * TAINT PRESERVING: Formatting does NOT sanitize
     */
    public String formatOutput(String data) {
        return String.format("[PROCESSED] %s", data); // STILL TAINTED
    }

    /**
     * TAINT PRESERVING: DTO field extraction
     */
    public String extractField(UserDTO dto, String fieldName) {
        switch (fieldName) {
            case "id": return dto.getId();
            case "name": return dto.getName();
            case "email": return dto.getEmail();
            case "role": return dto.getRole();
            default: return null;
        } // Returned value is TAINTED
    }

    /**
     * TAINT PRESERVING: Stream processing
     */
    public List<String> processStream(List<String> items) {
        return items.stream()
            .filter(s -> s != null && !s.isEmpty())
            .map(String::toLowerCase)
            .collect(Collectors.toList());
        // All items STILL TAINTED
    }
}

/**
 * DataTransformer - Multi-step pipeline
 */
class DataTransformer {
    private final DataProcessor processor;

    public DataTransformer(DataProcessor processor) {
        this.processor = processor;
    }

    /**
     * TAINT CHAIN: Full pipeline preserves taint
     */
    public String fullPipeline(String rawInput) {
        String validated = processor.validateInput(rawInput);
        String transformed = processor.transformInput(validated);
        String formatted = processor.formatOutput(transformed);
        return formatted; // STILL TAINTED after 3 transformations
    }

    /**
     * TAINT CHAIN: Async pipeline (simulated)
     */
    public CompletableFuture<String> asyncPipeline(String rawInput) {
        return CompletableFuture.supplyAsync(() -> processor.validateInput(rawInput))
            .thenApply(processor::transformInput)
            .thenApply(processor::formatOutput);
        // Result is STILL TAINTED
    }
}

/**
 * Generic service that preserves taint
 */
class GenericService<T, R> {
    private final Function<T, R> transformer;

    public GenericService(Function<T, R> transformer) {
        this.transformer = transformer;
    }

    /**
     * TAINT PRESERVING: Generic processing
     */
    public R process(T input) {
        return transformer.apply(input); // Taint flows through generic
    }
}

// =============================================================================
// LAYER 3: REPOSITORY/SINK LAYER
// =============================================================================

/**
 * DatabaseSink - SQL operations
 */
class DatabaseSink {
    /**
     * TAINT SINK: SQL Injection via WHERE clause
     */
    public void executeQuery(String whereClause) throws SQLException {
        String query = "SELECT * FROM users WHERE " + whereClause;
        System.out.println(query); // VULNERABILITY
    }

    /**
     * TAINT SINK: SQL Injection via INSERT
     */
    public void insertData(String table, String column, String value) throws SQLException {
        String query = String.format("INSERT INTO %s (%s) VALUES ('%s')", table, column, value);
        System.out.println(query); // VULNERABILITY
    }

    /**
     * TAINT SINK: SQL Injection via DTO fields
     */
    public void insertUser(UserDTO user) throws SQLException {
        String query = String.format(
            "INSERT INTO users (id, name, email, role) VALUES ('%s', '%s', '%s', '%s')",
            user.getId(), user.getName(), user.getEmail(), user.getRole()
        );
        System.out.println(query); // VULNERABILITY (4 injection points)
    }

    /**
     * TAINT SINK: SQL Injection via ORDER BY
     */
    public void queryWithSort(String sortColumn, String sortDirection) throws SQLException {
        String query = "SELECT * FROM users ORDER BY " + sortColumn + " " + sortDirection;
        System.out.println(query); // VULNERABILITY
    }
}

/**
 * CommandSink - Command execution
 */
class CommandSink {
    /**
     * TAINT SINK: Command Injection via Runtime.exec
     */
    public void executeCommand(String userArg) throws IOException {
        Runtime.getRuntime().exec("echo " + userArg); // VULNERABILITY
    }

    /**
     * TAINT SINK: Command Injection via ProcessBuilder
     */
    public void executeWithBuilder(String command) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
        pb.start(); // VULNERABILITY
    }

    /**
     * TAINT SINK: Command Injection via array
     */
    public void executeWithArgs(String... args) throws IOException {
        Runtime.getRuntime().exec(args); // VULNERABILITY if args contains tainted data
    }
}

/**
 * FileSink - File operations
 */
class FileSink {
    /**
     * TAINT SINK: Path Traversal via File
     */
    public String readFile(String path) throws IOException {
        return new String(java.nio.file.Files.readAllBytes(
            java.nio.file.Paths.get(path)
        )); // VULNERABILITY
    }

    /**
     * TAINT SINK: Path Traversal via FileInputStream
     */
    public byte[] readWithStream(String path) throws IOException {
        try (FileInputStream fis = new FileInputStream(path)) { // VULNERABILITY
            return fis.readAllBytes();
        }
    }

    /**
     * TAINT SINK: Path Traversal via write
     */
    public void writeFile(String path, String content) throws IOException {
        java.nio.file.Files.writeString(
            java.nio.file.Paths.get(path), // VULNERABILITY
            content
        );
    }
}

/**
 * EvalSink - Code/expression evaluation
 */
class EvalSink {
    /**
     * TAINT SINK: Script Injection via ScriptEngine
     */
    public Object evaluateScript(String script) throws Exception {
        javax.script.ScriptEngine engine =
            new javax.script.ScriptEngineManager().getEngineByName("javascript");
        return engine.eval(script); // VULNERABILITY
    }

    /**
     * TAINT SINK: Expression Language Injection (simulated)
     */
    public void evaluateExpression(String expression) {
        // Simulates SpEL or OGNL evaluation
        System.out.println("Evaluating: " + expression); // VULNERABILITY
    }
}

// =============================================================================
// LAYER 4: INTEGRATION (Cross-layer taint flow)
// =============================================================================

/**
 * VulnerableApplication - Integrates all layers
 */
class VulnerableApplication {
    private final UserInputSource source;
    private final ExternalDataSource externalSource;
    private final DataProcessor processor;
    private final DataTransformer transformer;
    private final DatabaseSink dbSink;
    private final CommandSink cmdSink;
    private final FileSink fileSink;
    private final EvalSink evalSink;

    public VulnerableApplication() {
        this.source = new UserInputSource();
        this.externalSource = new ExternalDataSource();
        this.processor = new DataProcessor();
        this.transformer = new DataTransformer(processor);
        this.dbSink = new DatabaseSink();
        this.cmdSink = new CommandSink();
        this.fileSink = new FileSink();
        this.evalSink = new EvalSink();
    }

    /**
     * CROSS-FILE VULNERABILITY: Query param -> Service -> SQL
     */
    public void vulnerableSqlEndpoint(String paramName) throws SQLException {
        String userInput = source.getQueryParam(paramName);
        String validated = processor.validateInput(userInput);
        String transformed = processor.transformInput(validated);
        dbSink.executeQuery(transformed); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: Form data -> Format -> Command
     */
    public void vulnerableCommandEndpoint(String fieldName) throws IOException {
        String userInput = source.getFormData(fieldName);
        String formatted = processor.formatOutput(userInput);
        cmdSink.executeCommand(formatted); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: Path variable -> File read
     */
    public String vulnerableFileEndpoint(String varName) throws IOException {
        String userPath = source.getPathVariable(varName);
        return fileSink.readFile(userPath); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: JSON body -> Eval
     */
    public Object vulnerableEvalEndpoint() throws Exception {
        Map<String, String> body = source.getJsonBody();
        String expression = body.get("action");
        return evalSink.evaluateScript(expression); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: DTO through pipeline -> SQL
     */
    public void vulnerableDtoEndpoint() throws SQLException {
        UserDTO dto = source.getUserDTO();
        dbSink.insertUser(dto); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: Multi-hop pipeline
     */
    public void complexMultiHopVulnerability() throws SQLException {
        String raw = source.getQueryParam("search");
        String processed = transformer.fullPipeline(raw);
        dbSink.executeQuery(processed); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: Async pipeline -> SQL
     */
    public void asyncPipelineVulnerability() throws Exception {
        String raw = source.getQueryParam("async");
        String result = transformer.asyncPipeline(raw).get();
        dbSink.executeQuery(result); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: External API -> SQL
     */
    public void externalApiVulnerability() throws SQLException {
        Map<String, Object> response = externalSource.callExternalApi("http://api.example.com");
        String data = (String) response.get("data");
        dbSink.insertData("logs", "message", data); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: Queue message -> Command
     */
    public void queueToCommandVulnerability() throws IOException {
        String message = externalSource.readFromQueue("commands");
        cmdSink.executeCommand(message); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: Generic service chain
     */
    public void genericServiceVulnerability() throws IOException {
        String input = source.getQueryParam("generic");
        GenericService<String, String> service = new GenericService<>(String::toUpperCase);
        String result = service.process(input);
        cmdSink.executeCommand(result); // VULNERABILITY
    }

    /**
     * CROSS-FILE VULNERABILITY: Stream processing -> SQL
     */
    public void streamProcessingVulnerability() throws SQLException {
        List<String> inputs = Arrays.asList(
            source.getQueryParam("a"),
            source.getQueryParam("b"),
            source.getQueryParam("c")
        );
        List<String> processed = processor.processStream(inputs);
        for (String item : processed) {
            dbSink.insertData("logs", "value", item); // VULNERABILITY (3x)
        }
    }
}

// =============================================================================
// LAYER 5: INTERFACE-BASED TAINT PROPAGATION
// =============================================================================

/**
 * Interface for data sources
 */
interface DataSource {
    String getData(String key);
}

/**
 * Interface for data sinks
 */
interface DataSink {
    void consumeData(String data) throws Exception;
}

/**
 * Implementation with taint source
 */
class TaintedDataSource implements DataSource {
    @Override
    public String getData(String key) {
        return "tainted_" + key; // TAINT SOURCE
    }
}

/**
 * Implementation with taint sink
 */
class SqlDataSink implements DataSink {
    @Override
    public void consumeData(String data) {
        String query = "SELECT * FROM t WHERE x = '" + data + "'";
        System.out.println(query); // VULNERABILITY
    }
}

/**
 * Wiring through interfaces
 */
class InterfaceBasedApp {
    private final DataSource source;
    private final DataSink sink;

    public InterfaceBasedApp(DataSource source, DataSink sink) {
        this.source = source;
        this.sink = sink;
    }

    /**
     * CROSS-FILE VULNERABILITY: Interface-based taint flow
     */
    public void process(String key) throws Exception {
        String data = source.getData(key);
        sink.consumeData(data); // VULNERABILITY
    }
}

// =============================================================================
// LAYER 6: INHERITANCE-BASED TAINT PROPAGATION
// =============================================================================

/**
 * Abstract processor
 */
abstract class AbstractProcessor {
    /**
     * TAINT PRESERVING: Template method
     */
    public String process(String input) {
        String validated = validate(input);
        String transformed = transform(validated);
        return transformed; // TAINTED if input was tainted
    }

    protected abstract String validate(String input);
    protected abstract String transform(String input);
}

/**
 * Concrete processor that preserves taint
 */
class ConcreteProcessor extends AbstractProcessor {
    @Override
    protected String validate(String input) {
        return input.trim(); // STILL TAINTED
    }

    @Override
    protected String transform(String input) {
        return input.toUpperCase(); // STILL TAINTED
    }
}

/**
 * Inheritance-based app
 */
class InheritanceBasedApp {
    private final UserInputSource source;
    private final AbstractProcessor processor;
    private final DatabaseSink sink;

    public InheritanceBasedApp() {
        this.source = new UserInputSource();
        this.processor = new ConcreteProcessor();
        this.sink = new DatabaseSink();
    }

    /**
     * CROSS-FILE VULNERABILITY: Inheritance-based taint flow
     */
    public void process(String param) throws SQLException {
        String input = source.getQueryParam(param);
        String processed = processor.process(input);
        sink.executeQuery(processed); // VULNERABILITY
    }
}

// =============================================================================
// TEST RUNNER
// =============================================================================

public class CrossFileTaintTests {
    public static void main(String[] args) {
        System.out.println("=".repeat(60));
        System.out.println("JAVA CROSS-FILE TAINT TRACKING TEST SUITE");
        System.out.println("=".repeat(60));
        System.out.println("");
        System.out.println("Layer Structure:");
        System.out.println("  1. Data Sources (UserInputSource, ExternalDataSource)");
        System.out.println("  2. Service Layer (DataProcessor, DataTransformer)");
        System.out.println("  3. Sink Layer (DatabaseSink, CommandSink, FileSink)");
        System.out.println("  4. Integration (VulnerableApplication)");
        System.out.println("  5. Interface-Based (DataSource, DataSink)");
        System.out.println("  6. Inheritance-Based (AbstractProcessor)");
        System.out.println("");
        System.out.println("Cross-File Taint Paths: 20+");
        System.out.println("Expected Vulnerabilities: 35");
        System.out.println("=".repeat(60));
    }
}
