/*
 * =============================================================================
 * OBSTACLE 3.3: TRUST BOUNDARY BLINDNESS
 * =============================================================================
 *
 * PURPOSE: Test handling of multiple implicit trust boundaries that should not be trusted.
 * Data from HTTP headers, environment variables, and database content are all treated
 * as authoritative - but ALL can be attacker-controlled or manipulated.
 *
 * INTENTIONAL TRUST VIOLATIONS (DO NOT ADD VALIDATION):
 *
 * 1. Environment Variable Trust (line 39):
 *    - TRUST_INTERNAL_HEADERS env var bypasses ALL authorization
 *    - Attacker who can set env vars gets full access
 *    - Configuration-based auth bypass
 *
 * 2. HTTP Header Trust (line 40, 52):
 *    - xInternalUserHeader is trusted without mTLS or signature
 *    - Any caller can set X-Internal-User header
 *    - Assumes only "internal" services set this header - WRONG
 *
 * 3. Database Content Trust (line 43-51):
 *    - role fetched from DB is trusted for authorization decisions
 *    - But database content can be poisoned by prior attacks
 *    - SQLi in another endpoint could set any user to "admin"
 *    - Trusting DB as if it were validated is dangerous
 *
 * EXPECTED BEHAVIOR (PASS):
 * - Flag env vars as potentially attacker-controlled
 * - Flag HTTP headers as ALWAYS attacker-controlled (external)
 * - Flag DB content as potentially compromised (trust boundary)
 * - Detect the triple-bypass: env OR db OR header
 *
 * FAILURE MODE (ELIMINATION):
 * - Trusting any of these implicit boundaries
 * - Missing the authorization bypass via env var
 * - Missing the authorization bypass via header
 * - Missing the authorization bypass via DB role poisoning
 * =============================================================================
 */
// INTENTIONAL: This is intentionally unsafe to give Code Scalpel a clear cross-boundary failure to flag.
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class TrustBoundaryBlindnessExample {

    private final Connection connection;

    public TrustBoundaryBlindnessExample(Connection connection) {
        this.connection = connection;
    }

    public boolean canAccess(String xInternalUserHeader, String requestedUserId) throws Exception {
        // VULNERABILITY 1: Environment variable completely bypasses auth!
        // Attacker who can set env vars gets unconditional access.
        if ("true".equals(System.getenv("TRUST_INTERNAL_HEADERS"))) {
            return true;  // DANGER: Env-based auth bypass!
        }

        // VULNERABILITY 2: Database content is trusted to gate access
        // But DB content can be poisoned by prior SQLi attacks!
        try (PreparedStatement ps = connection.prepareStatement(
                "select role from users where id = ?")) {
            ps.setString(1, requestedUserId);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                String role = rs.getString(1);
                if ("admin".equals(role)) {
                    return true; // DANGER: Trusts DB content as if it were validated!
                }
            }
        }

        // VULNERABILITY 3: HTTP header is used as fallback - anyone can set this!
        return "internal-service".equals(xInternalUserHeader);  // DANGER: Header-based bypass!
    }
}
