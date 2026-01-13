/*
 * =============================================================================
 * OBSTACLE 3.5: ORM ABSTRACTION LEAK (Spring Data JPA)
 * =============================================================================
 *
 * PURPOSE: Demonstrate that Spring Data JPA @Query with SpEL is an injection vector.
 * The ?#{#param} syntax allows runtime expression evaluation - when used with
 * user-controlled column names, it enables SQL/JPQL injection.
 *
 * INTENTIONAL SQL INJECTION (DO NOT ADD WHITELIST):
 *
 * 1. SpEL Expression Injection (line 38):
 *    - ?#{#sortColumn} evaluates SpEL expression at runtime
 *    - sortColumn is user-controlled parameter
 *    - Attacker can inject: "id; DROP TABLE orders; --"
 *
 * 2. ORDER BY Injection (line 38):
 *    - Column identifiers CANNOT be safely parameterized in JPQL
 *    - Standard practice is whitelist validation - intentionally omitted
 *    - Spring Data does NOT sanitize SpEL results
 *
 * 3. Repository Interface Trust (entire file):
 *    - Repository pattern creates illusion of safety
 *    - Developers assume Spring handles security
 *    - @Query annotation with SpEL is dangerous escape hatch
 *
 * EXPECTED BEHAVIOR (PASS):
 * - Detect SpEL ?#{} as potential injection vector
 * - Flag user-controlled sortColumn in ORDER BY
 * - Recognize @Query doesn't automatically prevent injection
 * - NOT trust Spring Data JPA abstractions blindly
 *
 * FAILURE MODE (ELIMINATION):
 * - Trusting Spring Data prevents SQL injection
 * - Missing SpEL expression evaluation risks
 * - Only checking for raw string concatenation
 * - Assuming JPA repositories are safe by default
 * =============================================================================
 */
// INTENTIONAL: Insecure construct to validate that Code Scalpel flags ORM escape hatches.
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface OrderRepository extends JpaRepository<OrderEntity, Long> {

    // VULNERABILITY: User-controlled sortColumn is spliced directly into JPQL ORDER BY via SpEL!
    // SpEL ?#{#sortColumn} evaluates the parameter as an expression, enabling injection.
    // No whitelist validation - attacker can inject arbitrary JPQL/SQL.
    @Query("SELECT o FROM OrderEntity o WHERE o.status = :status ORDER BY ?#{#sortColumn}")
    java.util.List<OrderEntity> findUnsafe(@Param("status") String status, @Param("sortColumn") String sortColumn);
}
