/**
 * =============================================================================
 * CROSS-LANGUAGE REST API TAINT TEST SUITE
 * =============================================================================
 *
 * PURPOSE: Test taint propagation through REST API boundaries between
 * different language runtimes (Java backend, JavaScript/TypeScript frontend,
 * Python microservices).
 *
 * CRITICAL SCENARIOS:
 * 1. Request body taint from frontend to backend
 * 2. Query parameter taint across services
 * 3. Header injection across API boundaries
 * 4. Response data taint from backend to frontend
 * 5. Microservice-to-microservice taint propagation
 *
 * =============================================================================
 */

package com.codescalpel.tests.crosslanguage;

import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * REST API boundary taint tests for cross-language scenarios.
 */
public class CrossLanguageRestApiTaint {

    // =============================================================================
    // REQUEST BODY TAINT TESTS
    // =============================================================================

    /**
     * VULNERABILITY: Request body from JavaScript frontend is tainted.
     * Simulates receiving JSON body from a React/Vue/Angular frontend.
     */
    public void handleFrontendRequestBody(String jsonBody) throws Exception {
        // TAINT SOURCE: JSON body from JavaScript frontend
        // Frontend code: fetch('/api/users', { method: 'POST', body: JSON.stringify(userData) })

        // Parse JSON (simplified - in reality would use Jackson/Gson)
        String username = extractJsonField(jsonBody, "username");
        String query = extractJsonField(jsonBody, "query");

        // TAINT SINK: SQL Injection from frontend data
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        executeQuery(sql);  // VULNERABILITY

        // TAINT SINK: Command Injection from frontend data
        Runtime.getRuntime().exec("grep " + query + " /var/log/app.log");  // VULNERABILITY
    }

    /**
     * VULNERABILITY: Multipart form data from frontend is tainted.
     */
    public void handleMultipartUpload(String filename, byte[] fileContent) throws Exception {
        // TAINT SOURCE: Filename from frontend form submission

        // TAINT SINK: Path Traversal via filename
        File uploadDir = new File("/uploads");
        File targetFile = new File(uploadDir, filename);  // VULNERABILITY
        try (FileOutputStream fos = new FileOutputStream(targetFile)) {
            fos.write(fileContent);
        }
    }

    /**
     * VULNERABILITY: Form-urlencoded data from frontend is tainted.
     */
    public void handleFormSubmission(Map<String, String> formData) throws Exception {
        // TAINT SOURCE: Form data from HTML form submission
        String email = formData.get("email");
        String message = formData.get("message");

        // TAINT SINK: SQL Injection
        String sql = "INSERT INTO contact_form (email, message) VALUES ('" +
                     email + "', '" + message + "')";
        executeQuery(sql);  // VULNERABILITY

        // TAINT SINK: Log Injection
        System.out.println("Contact from: " + email + " - " + message);  // VULNERABILITY
    }

    // =============================================================================
    // QUERY PARAMETER TAINT TESTS
    // =============================================================================

    /**
     * VULNERABILITY: Query parameters from any client are tainted.
     */
    public void handleQueryParameters(String searchTerm, String sortBy, String limit)
            throws Exception {
        // TAINT SOURCE: Query parameters (?search=xxx&sort=yyy&limit=zzz)

        // TAINT SINK: SQL Injection via search term
        String sql = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%' " +
                     "ORDER BY " + sortBy + " LIMIT " + limit;
        executeQuery(sql);  // VULNERABILITY (3 injection points)
    }

    /**
     * VULNERABILITY: Path parameters are tainted.
     */
    public void handlePathParameters(String userId, String resourceId) throws Exception {
        // TAINT SOURCE: Path parameters (/api/users/{userId}/resources/{resourceId})

        // TAINT SINK: SQL Injection via path parameter
        String sql = "SELECT * FROM resources WHERE user_id = '" + userId +
                     "' AND id = '" + resourceId + "'";
        executeQuery(sql);  // VULNERABILITY
    }

    /**
     * VULNERABILITY: Matrix parameters are tainted.
     */
    public void handleMatrixParameters(String filter, String page) throws Exception {
        // TAINT SOURCE: Matrix parameters (/api/items;filter=xxx;page=yyy)

        // TAINT SINK: Command Injection
        Runtime.getRuntime().exec(new String[]{"filter-tool", "--filter", filter});  // VULNERABILITY
    }

    // =============================================================================
    // HEADER TAINT TESTS
    // =============================================================================

    /**
     * VULNERABILITY: Request headers are tainted.
     */
    public void handleRequestHeaders(Map<String, String> headers) throws Exception {
        // TAINT SOURCE: HTTP headers from client
        String authHeader = headers.get("Authorization");
        String userAgent = headers.get("User-Agent");
        String customHeader = headers.get("X-Custom-Data");

        // TAINT SINK: Log Injection via headers
        System.out.println("Auth: " + authHeader);  // VULNERABILITY
        System.out.println("UA: " + userAgent);     // VULNERABILITY

        // TAINT SINK: SQL Injection via custom header
        String sql = "INSERT INTO audit_log (data) VALUES ('" + customHeader + "')";
        executeQuery(sql);  // VULNERABILITY
    }

    /**
     * VULNERABILITY: Forwarded headers are tainted.
     */
    public void handleForwardedHeaders(String xForwardedFor, String xRealIp) throws Exception {
        // TAINT SOURCE: Forwarded headers (can be spoofed by client)

        // TAINT SINK: Log Injection
        System.out.println("Request from IP: " + xForwardedFor);  // VULNERABILITY

        // TAINT SINK: SQL Injection (storing IP)
        String sql = "INSERT INTO access_log (ip) VALUES ('" + xRealIp + "')";
        executeQuery(sql);  // VULNERABILITY
    }

    /**
     * VULNERABILITY: Cookie values are tainted.
     */
    public void handleCookies(String sessionCookie, String preferencesCookie) throws Exception {
        // TAINT SOURCE: Cookie values from client

        // TAINT SINK: SQL Injection via cookie
        String sql = "SELECT * FROM sessions WHERE id = '" + sessionCookie + "'";
        executeQuery(sql);  // VULNERABILITY

        // TAINT SINK: Deserialization (if cookie contains serialized data)
        // This would be even more dangerous with actual deserialization
    }

    // =============================================================================
    // RESPONSE TAINT TESTS (Backend to Frontend)
    // =============================================================================

    /**
     * VULNERABILITY: Database content sent to frontend for rendering.
     * If frontend doesn't sanitize, this enables Stored XSS.
     */
    public String getStoredContent(String contentId) throws Exception {
        // TAINT SOURCE: Database content (could contain stored XSS)
        String sql = "SELECT content FROM user_content WHERE id = '" + contentId + "'";
        String content = executeQueryAndGetResult(sql);  // VULNERABILITY: SQL Injection

        // Response sent to frontend - if rendered unsafely, XSS occurs
        // The taint should propagate to frontend and be tracked there
        return content;  // TAINT: Stored XSS potential
    }

    /**
     * VULNERABILITY: User-generated content in API response.
     */
    public Map<String, String> getUserProfile(String userId) throws Exception {
        // Simulated database query result with user-controlled content
        Map<String, String> profile = new HashMap<>();
        profile.put("username", "user_supplied_name");    // TAINT: Could contain XSS
        profile.put("bio", "user_supplied_bio");          // TAINT: Could contain XSS
        profile.put("website", "user_supplied_url");      // TAINT: Could contain malicious URL

        return profile;  // All values potentially tainted for frontend
    }

    // =============================================================================
    // MICROSERVICE COMMUNICATION TAINT TESTS
    // =============================================================================

    /**
     * VULNERABILITY: Data from Python microservice is tainted.
     */
    public void receivePythonServiceData(String jsonFromPython) throws Exception {
        // TAINT SOURCE: JSON response from Python microservice
        String command = extractJsonField(jsonFromPython, "command");
        String filepath = extractJsonField(jsonFromPython, "filepath");

        // TAINT SINK: Command Injection
        Runtime.getRuntime().exec(command);  // VULNERABILITY

        // TAINT SINK: Path Traversal
        new File(filepath).delete();  // VULNERABILITY
    }

    /**
     * VULNERABILITY: Data to/from Node.js service maintains taint.
     */
    public void callNodeService(String userInput) throws Exception {
        // TAINT SOURCE: User input passed to Node.js service
        String nodeServiceUrl = "http://node-service:3000/process";

        // Sending tainted data to Node.js
        URL url = new URL(nodeServiceUrl + "?input=" + URLEncoder.encode(userInput, "UTF-8"));
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");

        // TAINT SOURCE: Response from Node.js (which processed tainted input)
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String response = reader.readLine();
        reader.close();

        // TAINT SINK: Using response from Node.js
        Runtime.getRuntime().exec("notify " + response);  // VULNERABILITY
    }

    /**
     * VULNERABILITY: gRPC-style message taint (simulated as REST).
     */
    public void handleGrpcStyleMessage(String protoJsonMessage) throws Exception {
        // TAINT SOURCE: Protocol buffer message (as JSON for simulation)
        String action = extractJsonField(protoJsonMessage, "action");
        String payload = extractJsonField(protoJsonMessage, "payload");

        // TAINT SINK: Eval-like behavior
        if ("execute".equals(action)) {
            Runtime.getRuntime().exec(payload);  // VULNERABILITY
        }

        // TAINT SINK: SQL from proto message
        if ("query".equals(action)) {
            executeQuery(payload);  // VULNERABILITY
        }
    }

    /**
     * VULNERABILITY: Event-driven message from message queue.
     */
    public void handleQueueMessage(String queueMessage) throws Exception {
        // TAINT SOURCE: Message from RabbitMQ/Kafka/SQS
        String eventType = extractJsonField(queueMessage, "event_type");
        String eventData = extractJsonField(queueMessage, "data");

        // TAINT SINK: Command Injection from queue message
        if ("process_file".equals(eventType)) {
            Runtime.getRuntime().exec("process " + eventData);  // VULNERABILITY
        }

        // TAINT SINK: SQL Injection from queue message
        if ("update_record".equals(eventType)) {
            String sql = "UPDATE records SET data = '" + eventData + "'";
            executeQuery(sql);  // VULNERABILITY
        }
    }

    // =============================================================================
    // WEBHOOK AND CALLBACK TAINT TESTS
    // =============================================================================

    /**
     * VULNERABILITY: Webhook payload from external service is tainted.
     */
    public void handleWebhook(String webhookPayload, Map<String, String> headers)
            throws Exception {
        // TAINT SOURCE: Webhook from external service (GitHub, Stripe, etc.)
        String eventType = extractJsonField(webhookPayload, "type");
        String eventData = extractJsonField(webhookPayload, "data");

        // Even with signature verification, the DATA is still tainted
        // (signature just proves it came from the service, not that it's safe)

        // TAINT SINK: SQL Injection from webhook data
        String sql = "INSERT INTO webhook_events (type, data) VALUES ('" +
                     eventType + "', '" + eventData + "')";
        executeQuery(sql);  // VULNERABILITY
    }

    /**
     * VULNERABILITY: OAuth callback parameters are tainted.
     */
    public void handleOAuthCallback(String code, String state, String redirectUri)
            throws Exception {
        // TAINT SOURCE: OAuth callback parameters
        // Even 'state' parameter can be tainted if attacker-controlled

        // TAINT SINK: Open Redirect
        if (redirectUri != null) {
            // Redirecting to user-supplied URL
            System.out.println("Redirect to: " + redirectUri);  // VULNERABILITY
        }

        // TAINT SINK: Log Injection
        System.out.println("OAuth code: " + code + ", state: " + state);  // VULNERABILITY
    }

    // =============================================================================
    // GRAPHQL TAINT TESTS
    // =============================================================================

    /**
     * VULNERABILITY: GraphQL query from client is tainted.
     */
    public void handleGraphQLQuery(String graphqlQuery, String variables) throws Exception {
        // TAINT SOURCE: GraphQL query and variables from client

        // TAINT SINK: Query Injection if passed to backend unsafely
        // (In real GraphQL, this would be the resolver that's vulnerable)
        String extractedValue = extractJsonField(variables, "userId");

        String sql = "SELECT * FROM users WHERE id = '" + extractedValue + "'";
        executeQuery(sql);  // VULNERABILITY
    }

    /**
     * VULNERABILITY: GraphQL mutation with file upload.
     */
    public void handleGraphQLMutation(String mutationName, String filename, byte[] content)
            throws Exception {
        // TAINT SOURCE: GraphQL mutation with file upload

        if ("uploadFile".equals(mutationName)) {
            // TAINT SINK: Path Traversal
            File target = new File("/uploads/" + filename);  // VULNERABILITY
            try (FileOutputStream fos = new FileOutputStream(target)) {
                fos.write(content);
            }
        }
    }

    // =============================================================================
    // HELPER METHODS
    // =============================================================================

    private String extractJsonField(String json, String field) {
        // Simplified JSON field extraction (would use Jackson/Gson in reality)
        int start = json.indexOf("\"" + field + "\":\"");
        if (start == -1) return "";
        start += field.length() + 4;
        int end = json.indexOf("\"", start);
        if (end == -1) return "";
        return json.substring(start, end);
    }

    private void executeQuery(String sql) throws SQLException {
        // Simulated query execution
        System.out.println("Executing: " + sql);
    }

    private String executeQueryAndGetResult(String sql) throws SQLException {
        // Simulated query execution with result
        System.out.println("Executing: " + sql);
        return "result_from_database";
    }

    // =============================================================================
    // TEST RUNNER
    // =============================================================================

    public static void main(String[] args) {
        System.out.println("=".repeat(60));
        System.out.println("CROSS-LANGUAGE REST API TAINT TEST SUITE");
        System.out.println("=".repeat(60));
        System.out.println("");
        System.out.println("Test Categories:");
        System.out.println("  1. Request Body Taint (3 tests)");
        System.out.println("  2. Query Parameter Taint (3 tests)");
        System.out.println("  3. Header Taint (3 tests)");
        System.out.println("  4. Response Taint (2 tests)");
        System.out.println("  5. Microservice Communication (4 tests)");
        System.out.println("  6. Webhook and Callback (2 tests)");
        System.out.println("  7. GraphQL (2 tests)");
        System.out.println("");
        System.out.println("Expected Vulnerabilities: 32");
        System.out.println("=".repeat(60));
    }
}
