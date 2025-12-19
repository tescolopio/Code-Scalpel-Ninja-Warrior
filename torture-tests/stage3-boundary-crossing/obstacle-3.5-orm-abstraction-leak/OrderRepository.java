// Obstacle 3.5: ORM escape hatch that leaks raw SQL injection through a dynamic ORDER BY.
// Intentional insecure construct to validate that Code Scalpel flags ORM escape hatches.
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface OrderRepository extends JpaRepository<OrderEntity, Long> {

    // User-controlled sortColumn is spliced directly into the ORDER BY via SpEL (no whitelist).
    @Query(value = "SELECT * FROM orders WHERE status = :status ORDER BY ?#{#sortColumn}", nativeQuery = true)
    java.util.List<OrderEntity> findUnsafe(@Param("status") String status, @Param("sortColumn") String sortColumn);
}
