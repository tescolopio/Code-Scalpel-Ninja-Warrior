/**
 * ###############################################################################
 * #     STAGE 7.4.1: JAVA MODERN FEATURES COVERAGE                             #
 * #     Requirement: >95% Java language support                                #
 * ###############################################################################
 * 
 * PURPOSE: Test modern Java (8-21) features including lambdas, streams, var,
 * records, sealed classes, and pattern matching.
 * 
 * SUCCESS CRITERIA:
 * - Parse all Java 8-21 syntax without errors
 * - Extract classes, methods, interfaces, records
 * - Detect security issues in modern Java code
 * - Handle lambda expressions and method references
 * 
 * COVERAGE REQUIREMENTS:
 * ✅ Lambda expressions and method references
 * ✅ Stream API and collectors
 * ✅ var keyword (local variable type inference)
 * ✅ Records (Java 16+)
 * ✅ Sealed classes and interfaces (Java 17+)
 * ✅ Pattern matching for instanceof (Java 16+)
 * ✅ Text blocks (Java 15+)
 * ✅ Switch expressions (Java 14+)
 */

package com.scalpel.torture.stage7;

import java.sql.*;
import java.util.*;
import java.util.stream.*;
import java.util.function.*;

// ============================================================================
// LAMBDA EXPRESSIONS AND FUNCTIONAL INTERFACES
// ============================================================================

public class ModernJavaFeatures {
    
    // Lambda with security implications
    public List<String> filterUsers(List<String> users, String role) {
        // SECURITY: SQL injection in lambda predicate
        return users.stream()
            .filter(user -> {
                String query = "SELECT * FROM users WHERE username = '" + user + "' AND role = '" + role + "'";
                System.out.println(query); // SECURITY: Logging sensitive query
                return user.startsWith("admin");
            })
            .collect(Collectors.toList());
    }
    
    // Method reference with security issue
    public void processUsernames(List<String> usernames) {
        // SECURITY: forEach with potentially dangerous operation
        usernames.forEach(this::executeCommand); // Method reference
    }
    
    private void executeCommand(String command) {
        // SECURITY: Command injection
        try {
            Runtime.getRuntime().exec("process-user " + command);
        } catch (Exception e) {
            e.printStackTrace(); // SECURITY: Stack trace exposure
        }
    }
    
    // ============================================================================
    // STREAM API WITH SECURITY VULNERABILITIES
    // ============================================================================
    
    public String buildUserQuery(List<Integer> userIds) {
        // SECURITY: SQL injection via stream and string concatenation
        String idList = userIds.stream()
            .map(String::valueOf)
            .collect(Collectors.joining(","));
        
        return "SELECT * FROM users WHERE id IN (" + idList + ")";
    }
    
    public Map<String, String> createUserMap(List<User> users) {
        // SECURITY: Potential injection if username contains malicious content
        return users.stream()
            .collect(Collectors.toMap(
                User::getUsername, // Key can be user-controlled
                user -> "<div>" + user.getEmail() + "</div>" // SECURITY: XSS
            ));
    }
    
    // Parallel stream with security implications
    public List<String> processUserDataParallel(List<String> data) {
        return data.parallelStream()
            .map(item -> {
                // SECURITY: SQL injection in parallel processing
                String sql = "UPDATE users SET status = 'processed' WHERE data = '" + item + "'";
                return sql;
            })
            .collect(Collectors.toList());
    }
    
    // ============================================================================
    // VAR KEYWORD (Local Variable Type Inference)
    // ============================================================================
    
    public void useVarKeyword(String userId) {
        // Using var for local variables
        var connection = getConnection();
        var statement = connection.createStatement();
        
        // SECURITY: SQL injection with var
        var query = "SELECT * FROM users WHERE id = '" + userId + "'";
        
        try {
            var resultSet = statement.executeQuery(query);
            
            var userData = new ArrayList<String>();
            while (resultSet.next()) {
                var username = resultSet.getString("username");
                // SECURITY: XSS in HTML generation
                var html = "<div>User: " + username + "</div>";
                userData.add(html);
            }
        } catch (SQLException e) {
            // SECURITY: Exception details exposed
            System.err.println("SQL Error: " + e.getMessage());
        }
    }
    
    // ============================================================================
    // RECORDS (Java 16+)
    // ============================================================================
    
    // Record with validation
    public record UserCredentials(String username, String password) {
        // Compact constructor with validation
        public UserCredentials {
            // SECURITY: Weak password validation
            if (password.length() < 6) {
                throw new IllegalArgumentException("Password too short");
            }
            // SECURITY: Logging sensitive password
            System.out.println("Creating credentials for: " + username);
        }
        
        // SECURITY: Record method with SQL injection
        public String buildAuthQuery() {
            return "SELECT * FROM users WHERE username = '" + username + 
                   "' AND password = '" + password + "'";
        }
    }
    
    // Record for data transfer
    public record UserDTO(int id, String name, String email, String role) {}
    
    // Using records in stream operations
    public List<String> processUserDTOs(List<UserDTO> users) {
        return users.stream()
            .map(user -> {
                // SECURITY: XSS in HTML generation from record
                return "<div>%s (%s) - %s</div>".formatted(
                    user.name(), user.email(), user.role()
                );
            })
            .toList(); // Java 16+ convenience method
    }
    
    // ============================================================================
    // SEALED CLASSES (Java 17+)
    // ============================================================================
    
    // Sealed interface with permitted subtypes
    public sealed interface DatabaseOperation 
        permits SelectOperation, InsertOperation, UpdateOperation {
        String toSQL();
    }
    
    // Final implementation of sealed interface
    public final class SelectOperation implements DatabaseOperation {
        private final String table;
        private final String condition;
        
        public SelectOperation(String table, String condition) {
            this.table = table;
            this.condition = condition;
        }
        
        @Override
        public String toSQL() {
            // SECURITY: SQL injection in sealed class
            return "SELECT * FROM " + table + " WHERE " + condition;
        }
    }
    
    // Non-sealed implementation allows further extension
    public non-sealed class InsertOperation implements DatabaseOperation {
        private String table;
        private Map<String, String> values;
        
        @Override
        public String toSQL() {
            // SECURITY: SQL injection in map values
            String columns = String.join(",", values.keySet());
            String vals = values.values().stream()
                .map(v -> "'" + v + "'")
                .collect(Collectors.joining(","));
            return "INSERT INTO " + table + " (" + columns + ") VALUES (" + vals + ")";
        }
    }
    
    public final class UpdateOperation implements DatabaseOperation {
        private String table;
        private String updates;
        private String condition;
        
        @Override
        public String toSQL() {
            // SECURITY: Multiple SQL injection points
            return "UPDATE " + table + " SET " + updates + " WHERE " + condition;
        }
    }
    
    // ============================================================================
    // PATTERN MATCHING FOR INSTANCEOF (Java 16+)
    // ============================================================================
    
    public String processOperation(DatabaseOperation op) {
        // Pattern matching with instanceof
        if (op instanceof SelectOperation select) {
            // SECURITY: Executing potentially malicious query
            return executeQuery(select.toSQL());
        } else if (op instanceof InsertOperation insert) {
            return executeQuery(insert.toSQL());
        } else if (op instanceof UpdateOperation update) {
            // SECURITY: Update without authorization check
            return executeQuery(update.toSQL());
        }
        return "Unknown operation";
    }
    
    private String executeQuery(String sql) {
        // SECURITY: Logging sensitive SQL
        System.out.println("Executing: " + sql);
        return "Query executed";
    }
    
    // ============================================================================
    // TEXT BLOCKS (Java 15+)
    // ============================================================================
    
    public String buildComplexQuery(String username, String email, String role) {
        // SECURITY: SQL injection in text block
        var query = """
            SELECT 
                u.id,
                u.username,
                u.email,
                r.role_name
            FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE u.username = '%s'
              AND u.email = '%s'
              AND r.role_name = '%s'
            ORDER BY u.created_at DESC
            """.formatted(username, email, role);
        
        return query;
    }
    
    public String buildHTMLResponse(String username, String message) {
        // SECURITY: XSS in text block
        return """
            <html>
            <body>
                <h1>Welcome, %s</h1>
                <div class="message">%s</div>
            </body>
            </html>
            """.formatted(username, message);
    }
    
    // ============================================================================
    // SWITCH EXPRESSIONS (Java 14+)
    // ============================================================================
    
    public String getUserRole(String userType) {
        // Switch expression with yield
        return switch (userType) {
            case "ADMIN" -> "administrator";
            case "MOD" -> "moderator";
            case "USER" -> "regular_user";
            default -> {
                // SECURITY: Logging user input
                System.out.println("Unknown user type: " + userType);
                yield "guest";
            }
        };
    }
    
    public String buildQueryByRole(String role, String condition) {
        // SECURITY: SQL injection in switch expression
        String table = switch (role) {
            case "admin" -> "admin_users";
            case "moderator" -> "mod_users";
            default -> "users";
        };
        
        // SECURITY: SQL injection via condition parameter
        return "SELECT * FROM " + table + " WHERE " + condition;
    }
    
    // ============================================================================
    // HELPER CLASSES AND METHODS
    // ============================================================================
    
    private Connection getConnection() {
        try {
            // SECURITY: Hardcoded database credentials
            return DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/testdb",
                "admin",
                "password123"
            );
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }
    
    // Simple User class for examples
    static class User {
        private String username;
        private String email;
        
        public String getUsername() { return username; }
        public String getEmail() { return email; }
    }
}

// ============================================================================
// TEST EXPECTATIONS
// ============================================================================

/*
EXPECTED DETECTION (Security Scan):
1. SQL injection in filterUsers - Line 35
2. Logging sensitive query in filterUsers - Line 36
3. Stack trace exposure in executeCommand - Line 53
4. Command injection in executeCommand - Line 51
5. SQL injection in buildUserQuery - Line 67
6. XSS in createUserMap - Line 74
7. SQL injection in processUserDataParallel - Line 83
8. SQL injection in useVarKeyword - Line 97
9. XSS in useVarKeyword - Line 104
10. Sensitive logging in UserCredentials - Line 124
11. SQL injection in UserCredentials.buildAuthQuery - Line 129
12. XSS in processUserDTOs - Line 141
13. SQL injection in SelectOperation.toSQL - Line 162
14. SQL injection in InsertOperation.toSQL - Line 180
15. SQL injection in UpdateOperation.toSQL - Line 194
16. Logging sensitive SQL in executeQuery - Line 210
17. SQL injection in buildComplexQuery - Line 221
18. XSS in buildHTMLResponse - Line 234
19. SQL injection in buildQueryByRole - Line 260
20. Hardcoded credentials in getConnection - Line 273

EXPECTED PARSING (Analyze Code):
- Main class ModernJavaFeatures with ~20 methods
- 3 inner classes (SelectOperation, InsertOperation, UpdateOperation)
- 2 records (UserCredentials, UserDTO)
- 1 sealed interface (DatabaseOperation)
- 1 static nested class (User)
- Lambda expressions and stream operations recognized

PASS CRITERIA:
✅ File parses without Java syntax errors
✅ All classes, records, and methods extracted
✅ At least 17/20 security issues detected
✅ Lambda and stream operations recognized
✅ Sealed classes and records parsed correctly
✅ No false positives on modern Java syntax
*/
