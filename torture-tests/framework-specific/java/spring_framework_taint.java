/**
 * =============================================================================
 * JAVA SPRING FRAMEWORK TAINT TEST SUITE
 * =============================================================================
 *
 * PURPOSE: Test taint propagation through Spring Framework patterns including
 * Spring MVC, Spring Data JPA, Spring Security, and common enterprise patterns.
 *
 * CRITICAL SCENARIOS:
 * 1. @RequestParam, @PathVariable, @RequestBody taint
 * 2. Spring Data JPA query methods vs @Query annotations
 * 3. Spring Security authentication context
 * 4. SpEL expression injection
 * 5. Bean validation bypass
 * 6. RestTemplate/WebClient taint propagation
 *
 * =============================================================================
 */

package com.codescalpel.tests.spring;

import java.io.*;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;

// Simulated Spring annotations (would be real imports in actual Spring app)
@interface RestController {}
@interface RequestMapping { String value() default ""; }
@interface GetMapping { String value() default ""; }
@interface PostMapping { String value() default ""; }
@interface RequestParam { String value() default ""; boolean required() default true; }
@interface PathVariable { String value() default ""; }
@interface RequestBody {}
@interface RequestHeader { String value() default ""; }
@interface CookieValue { String value() default ""; }
@interface Valid {}
@interface Validated {}
@interface Query { String value() default ""; }
@interface Param { String value() default ""; }
@interface Transactional {}
@interface PreAuthorize { String value() default ""; }
@interface Value { String value() default ""; }
@interface Autowired {}

/**
 * Spring MVC Controller taint tests.
 */
@RestController
@RequestMapping("/api")
public class SpringFrameworkTaint {

    // =============================================================================
    // SPRING MVC REQUEST PARAMETER TAINT TESTS
    // =============================================================================

    /**
     * VULNERABILITY: @RequestParam values are tainted.
     */
    @GetMapping("/search")
    public String searchWithRequestParam(
            @RequestParam("q") String query,
            @RequestParam("sort") String sortBy,
            @RequestParam(value = "limit", required = false) String limit
    ) throws SQLException {
        // TAINT SOURCE: All @RequestParam values

        // TAINT SINK: SQL Injection via request params
        String sql = "SELECT * FROM products WHERE name LIKE '%" + query + "%' " +
                     "ORDER BY " + sortBy + " LIMIT " + limit;
        executeQuery(sql);  // VULNERABILITY (3 injection points)

        return "results";
    }

    /**
     * VULNERABILITY: @PathVariable values are tainted.
     */
    @GetMapping("/users/{userId}/documents/{docId}")
    public String getDocument(
            @PathVariable("userId") String userId,
            @PathVariable("docId") String docId
    ) throws Exception {
        // TAINT SOURCE: Path variables

        // TAINT SINK: SQL Injection
        String sql = "SELECT * FROM documents WHERE user_id = '" + userId +
                     "' AND doc_id = '" + docId + "'";
        executeQuery(sql);  // VULNERABILITY

        // TAINT SINK: Path Traversal
        String filePath = "/data/users/" + userId + "/docs/" + docId + ".pdf";
        return new String(java.nio.file.Files.readAllBytes(
            java.nio.file.Paths.get(filePath)));  // VULNERABILITY
    }

    /**
     * VULNERABILITY: @RequestBody is tainted.
     */
    @PostMapping("/users")
    public String createUser(@RequestBody UserDTO userDto) throws SQLException {
        // TAINT SOURCE: Entire request body

        // TAINT SINK: SQL Injection via DTO fields
        String sql = "INSERT INTO users (name, email, role) VALUES ('" +
                     userDto.getName() + "', '" + userDto.getEmail() + "', '" +
                     userDto.getRole() + "')";
        executeQuery(sql);  // VULNERABILITY

        return "created";
    }

    /**
     * VULNERABILITY: @RequestHeader values are tainted.
     */
    @GetMapping("/process")
    public String processWithHeaders(
            @RequestHeader("X-Custom-Data") String customData,
            @RequestHeader("User-Agent") String userAgent
    ) throws Exception {
        // TAINT SOURCE: HTTP headers

        // TAINT SINK: Command Injection
        Runtime.getRuntime().exec("log-request --data \"" + customData + "\"");  // VULNERABILITY

        // TAINT SINK: Log Injection
        System.out.println("User-Agent: " + userAgent);  // VULNERABILITY

        return "processed";
    }

    /**
     * VULNERABILITY: @CookieValue values are tainted.
     */
    @GetMapping("/session")
    public String getSession(@CookieValue("sessionId") String sessionId) throws SQLException {
        // TAINT SOURCE: Cookie value

        // TAINT SINK: SQL Injection via cookie
        String sql = "SELECT * FROM sessions WHERE id = '" + sessionId + "'";
        executeQuery(sql);  // VULNERABILITY

        return "session";
    }

    // =============================================================================
    // SPRING DATA JPA TAINT TESTS
    // =============================================================================

    /**
     * VULNERABILITY: @Query with string concatenation.
     */
    // In a real repository interface:
    // @Query("SELECT u FROM User u WHERE u.name LIKE %" + name + "%")
    // List<User> findByNameContaining(@Param("name") String name);

    public List<Object> unsafeJpaQuery(String userInput) throws SQLException {
        // Simulating unsafe @Query with concatenation
        // TAINT SOURCE: User input in JPA query

        // TAINT SINK: JPQL/SQL Injection
        String jpql = "SELECT u FROM User u WHERE u.name = '" + userInput + "'";
        System.out.println("JPQL: " + jpql);  // VULNERABILITY

        return new ArrayList<>();
    }

    /**
     * VULNERABILITY: Native query with @Query and tainted input.
     */
    // @Query(value = "SELECT * FROM users WHERE role = :role", nativeQuery = true)
    public List<Object> unsafeNativeQuery(String role) throws SQLException {
        // TAINT SOURCE: User-controlled role

        // TAINT SINK: SQL Injection in native query
        String sql = "SELECT * FROM users WHERE role = '" + role + "'";
        executeQuery(sql);  // VULNERABILITY

        return new ArrayList<>();
    }

    /**
     * VULNERABILITY: Dynamic ORDER BY in JPA.
     */
    public List<Object> dynamicSorting(String sortColumn, String sortDirection) throws SQLException {
        // TAINT SOURCE: User-controlled sort parameters

        // TAINT SINK: SQL Injection via ORDER BY
        // Common pattern that bypasses parameterized queries
        String sql = "SELECT * FROM users ORDER BY " + sortColumn + " " + sortDirection;
        executeQuery(sql);  // VULNERABILITY

        return new ArrayList<>();
    }

    /**
     * VULNERABILITY: Specification/Criteria API with tainted input.
     */
    public List<Object> criteriaWithTaintedField(String fieldName, String value) throws SQLException {
        // TAINT SOURCE: Field name from user

        // TAINT SINK: Dynamic field access (if not validated)
        String jpql = "SELECT e FROM Entity e WHERE e." + fieldName + " = '" + value + "'";
        System.out.println("JPQL: " + jpql);  // VULNERABILITY

        return new ArrayList<>();
    }

    // =============================================================================
    // SPRING EXPRESSION LANGUAGE (SpEL) TAINT TESTS
    // =============================================================================

    /**
     * VULNERABILITY: SpEL injection via @Value.
     */
    // @Value("#{systemProperties['user.input']}")
    // private String spelValue;

    public Object unsafeSpelEvaluation(String expression) {
        // TAINT SOURCE: User-controlled SpEL expression

        // TAINT SINK: SpEL Injection (simulated)
        // In real Spring: new SpelExpressionParser().parseExpression(expression).getValue()
        System.out.println("Evaluating SpEL: " + expression);  // VULNERABILITY

        return null;
    }

    /**
     * VULNERABILITY: SpEL in @PreAuthorize with tainted value.
     */
    // @PreAuthorize("hasRole('" + userRole + "')")
    public void unsafePreAuthorize(String userRole) {
        // TAINT SOURCE: User-controlled role in security expression

        // TAINT SINK: SpEL Injection in security context
        String spelExpr = "hasRole('" + userRole + "')";
        System.out.println("Security SpEL: " + spelExpr);  // VULNERABILITY
    }

    /**
     * VULNERABILITY: SpEL in @Cacheable key.
     */
    // @Cacheable(key = "#userInput")
    public Object unsafeCacheKey(String userInput) {
        // TAINT SOURCE: User input as cache key (could be SpEL)

        // TAINT SINK: SpEL Injection via cache key
        System.out.println("Cache key SpEL: " + userInput);  // VULNERABILITY

        return null;
    }

    // =============================================================================
    // SPRING SECURITY TAINT TESTS
    // =============================================================================

    /**
     * VULNERABILITY: Authentication principal properties could be tainted.
     * (If username comes from external IdP or is user-modifiable)
     */
    public void unsafeAuthenticationUsage(Object authentication) throws SQLException {
        // Simulating: SecurityContextHolder.getContext().getAuthentication()
        // TAINT SOURCE: Authentication properties (especially from OAuth/SAML)

        String username = "user_from_auth"; // Would be authentication.getName()

        // TAINT SINK: SQL Injection if username is attacker-controlled
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        executeQuery(sql);  // POTENTIAL VULNERABILITY (depends on auth source)
    }

    /**
     * VULNERABILITY: JWT claims are tainted.
     */
    public void unsafeJwtClaims(Map<String, Object> claims) throws Exception {
        // TAINT SOURCE: JWT claims (especially custom claims)
        String userId = (String) claims.get("sub");
        String customClaim = (String) claims.get("customData");

        // TAINT SINK: Command Injection
        Runtime.getRuntime().exec("process-user " + userId);  // VULNERABILITY

        // TAINT SINK: SQL Injection
        String sql = "UPDATE users SET data = '" + customClaim + "'";
        executeQuery(sql);  // VULNERABILITY
    }

    // =============================================================================
    // RESTTEMPLATE/WEBCLIENT TAINT TESTS
    // =============================================================================

    /**
     * VULNERABILITY: RestTemplate with tainted URL.
     */
    public String unsafeRestTemplateCall(String endpoint) throws Exception {
        // TAINT SOURCE: User-controlled endpoint

        // TAINT SINK: SSRF via RestTemplate
        // In real code: restTemplate.getForObject(endpoint, String.class)
        java.net.URL url = new java.net.URL(endpoint);
        return url.openStream().toString();  // VULNERABILITY: SSRF
    }

    /**
     * VULNERABILITY: RestTemplate with tainted path parameter.
     */
    public String unsafePathParameter(String resourceId) throws Exception {
        // TAINT SOURCE: User-controlled resource ID
        String url = "https://api.example.com/resources/" + resourceId;

        // TAINT SINK: SSRF/Path manipulation
        return new java.net.URL(url).openStream().toString();  // VULNERABILITY
    }

    /**
     * VULNERABILITY: WebClient with tainted headers.
     */
    public void unsafeWebClientHeaders(String headerValue) {
        // TAINT SOURCE: User-controlled header value

        // TAINT SINK: Header Injection
        // In real code: webClient.get().header("X-Custom", headerValue)
        System.out.println("Setting header: X-Custom: " + headerValue);  // VULNERABILITY
    }

    // =============================================================================
    // BEAN VALIDATION BYPASS TESTS
    // =============================================================================

    /**
     * VULNERABILITY: @Valid annotation doesn't prevent injection.
     */
    @PostMapping("/validated")
    public String validatedInput(@Valid @RequestBody ValidatedDTO dto) throws SQLException {
        // @Valid checks constraints but doesn't sanitize!
        // TAINT SOURCE: Validated but still tainted DTO

        // TAINT SINK: SQL Injection despite validation
        String sql = "INSERT INTO data (value) VALUES ('" + dto.getValue() + "')";
        executeQuery(sql);  // VULNERABILITY

        return "ok";
    }

    /**
     * VULNERABILITY: Custom validator doesn't sanitize.
     */
    public void customValidation(String input) throws SQLException {
        // Custom validation only checks format
        if (input.matches("^[a-zA-Z0-9_]+$")) {
            // Looks alphanumeric but still tainted!
            // Also, regex could be bypassed with Unicode

            // TAINT SINK: SQL Injection
            String sql = "SELECT * FROM t WHERE x = '" + input + "'";
            executeQuery(sql);  // VULNERABILITY (regex bypass possible)
        }
    }

    // =============================================================================
    // SPRING TRANSACTION TAINT TESTS
    // =============================================================================

    /**
     * VULNERABILITY: Taint persists across transaction boundaries.
     */
    @Transactional
    public void transactionalMethod(String userInput) throws SQLException {
        // TAINT SOURCE: User input in transactional method

        // First database operation
        String sql1 = "INSERT INTO log (message) VALUES ('" + userInput + "')";
        executeQuery(sql1);  // VULNERABILITY

        // Second database operation in same transaction
        String sql2 = "UPDATE stats SET last_query = '" + userInput + "'";
        executeQuery(sql2);  // VULNERABILITY
    }

    /**
     * VULNERABILITY: Taint through service layer.
     */
    public void serviceLayerTaint(String input) throws Exception {
        // Taint flows through service layer
        String processed = processInService(input);  // Still tainted

        // TAINT SINK: Command Injection via service-processed data
        Runtime.getRuntime().exec(processed);  // VULNERABILITY
    }

    private String processInService(String input) {
        // Transformation doesn't sanitize
        return input.toUpperCase().trim();  // STILL TAINTED
    }

    // =============================================================================
    // SPRING MESSAGING TAINT TESTS
    // =============================================================================

    /**
     * VULNERABILITY: @MessageMapping payload is tainted.
     */
    // @MessageMapping("/chat")
    public void handleWebSocketMessage(String message) throws Exception {
        // TAINT SOURCE: WebSocket message payload

        // TAINT SINK: Command Injection
        Runtime.getRuntime().exec("log-message " + message);  // VULNERABILITY
    }

    /**
     * VULNERABILITY: @KafkaListener message is tainted.
     */
    // @KafkaListener(topics = "user-events")
    public void handleKafkaMessage(String message) throws SQLException {
        // TAINT SOURCE: Kafka message payload

        // TAINT SINK: SQL Injection
        String sql = "INSERT INTO events (data) VALUES ('" + message + "')";
        executeQuery(sql);  // VULNERABILITY
    }

    /**
     * VULNERABILITY: @RabbitListener message is tainted.
     */
    // @RabbitListener(queues = "commands")
    public void handleRabbitMessage(Map<String, Object> message) throws Exception {
        // TAINT SOURCE: RabbitMQ message
        String command = (String) message.get("cmd");

        // TAINT SINK: Command Injection
        Runtime.getRuntime().exec(command);  // VULNERABILITY
    }

    // =============================================================================
    // HELPER CLASSES AND METHODS
    // =============================================================================

    static class UserDTO {
        private String name;
        private String email;
        private String role;

        public String getName() { return name; }
        public String getEmail() { return email; }
        public String getRole() { return role; }
    }

    static class ValidatedDTO {
        // @NotBlank @Size(max = 100)
        private String value;

        public String getValue() { return value; }
    }

    private void executeQuery(String sql) throws SQLException {
        System.out.println("Executing: " + sql);
    }

    // =============================================================================
    // TEST RUNNER
    // =============================================================================

    public static void main(String[] args) {
        System.out.println("=".repeat(60));
        System.out.println("JAVA SPRING FRAMEWORK TAINT TEST SUITE");
        System.out.println("=".repeat(60));
        System.out.println("");
        System.out.println("Test Categories:");
        System.out.println("  1. Spring MVC Request Taint (5 tests)");
        System.out.println("  2. Spring Data JPA Taint (4 tests)");
        System.out.println("  3. SpEL Injection (3 tests)");
        System.out.println("  4. Spring Security Taint (2 tests)");
        System.out.println("  5. RestTemplate/WebClient Taint (3 tests)");
        System.out.println("  6. Bean Validation Bypass (2 tests)");
        System.out.println("  7. Spring Transaction Taint (2 tests)");
        System.out.println("  8. Spring Messaging Taint (3 tests)");
        System.out.println("");
        System.out.println("Expected Vulnerabilities: 35");
        System.out.println("=".repeat(60));
    }
}
