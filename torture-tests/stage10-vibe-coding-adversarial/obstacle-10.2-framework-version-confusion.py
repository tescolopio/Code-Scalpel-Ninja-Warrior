"""Obstacle 10.2: Framework Version Confusion

Tests detection of code patterns that were safe in old framework versions
but are VULNERABLE in newer versions (or vice versa).

Vibe coding often produces code that:
- Uses outdated security patterns from old tutorials
- Mixes patterns from different framework versions
- Assumes deprecated security defaults still apply
- Ignores breaking security changes between versions

PASS CRITERIA:
- Detect version-specific vulnerabilities
- Flag deprecated security patterns
- Identify unsafe default changes
- Note framework version assumptions
"""

# =============================================================================
# DJANGO VERSION CONFUSION
# =============================================================================

# Django < 1.8: CSRF was opt-in via @csrf_protect
# Django >= 1.8: CSRF is on by default, opt-out via @csrf_exempt
# Vibe-coded pattern often disables CSRF "because old tutorial said so"

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse


@csrf_exempt  # DANGEROUS: Disables CSRF protection
def update_profile(request):
    """
    VULNERABLE: CSRF disabled on state-changing endpoint.

    Old tutorials (Django 1.5 era) often showed @csrf_exempt on API views.
    Modern Django has CSRF enabled by default - disabling it is dangerous.
    """
    if request.method == "POST":
        user = request.user
        user.email = request.POST.get("email")
        user.save()
        return JsonResponse({"status": "updated"})


# Django < 3.0: XSS protection via manual escaping or |safe filter understanding
# Django >= 3.0: Autoescape is default, but mark_safe bypasses it
# Vibe-coded pattern trusts mark_safe without understanding implications

from django.utils.safestring import mark_safe


def render_user_content(user_input):
    """
    VULNERABLE: mark_safe on user input.

    Copy-pasted from tutorials showing how to render HTML.
    Developer didn't understand mark_safe trusts the content completely.
    """
    # Developer thought mark_safe is for "making content safe"
    # Actually it means "I'm marking this AS safe (trust me)"
    return mark_safe(f"<div class='content'>{user_input}</div>")


# =============================================================================
# FLASK VERSION CONFUSION
# =============================================================================

# Flask < 1.0: JSON responses needed manual Content-Type
# Flask >= 1.0: jsonify sets correct headers
# Old patterns might set headers manually AND use jsonify (redundant/confusing)

from flask import Flask, request, jsonify
import json

app = Flask(__name__)


@app.route("/api/data", methods=["POST"])
def get_data():
    """
    VULNERABLE: Mixing old and new Flask patterns + no CSRF.

    Old Flask didn't have built-in CSRF. Modern Flask-WTF does.
    This API endpoint has no CSRF protection at all.
    """
    data = request.get_json()
    user_query = data.get("query")
    # Old pattern: manual SQL (before Flask-SQLAlchemy was standard)
    result = db.execute(f"SELECT * FROM items WHERE name LIKE '%{user_query}%'")
    return jsonify(results=list(result))


# Flask-Login < 0.5.0: remember_me duration was configurable differently
# Vibe-coded pattern might use old config that doesn't work

@app.route("/login", methods=["POST"])
def login():
    """
    POTENTIALLY VULNERABLE: Old remember_me pattern.

    Flask-Login changed how remember duration works.
    Old tutorials show patterns that may not work as expected.
    """
    from flask_login import login_user
    user = User.query.filter_by(email=request.form["email"]).first()
    if user and user.check_password(request.form["password"]):
        # Old pattern - might not work as expected in newer versions
        login_user(user, remember=True, duration=timedelta(days=365))
        return jsonify({"status": "ok"})


# =============================================================================
# EXPRESS.JS VERSION CONFUSION
# =============================================================================

EXPRESS_VULNERABLE_CODE = '''
// Express < 4.0: bodyParser was built-in
// Express >= 4.0: bodyParser is separate, with different defaults
// Vibe-coded pattern might have security misconfigurations

const express = require('express');
const bodyParser = require('body-parser');

const app = express();

// DANGEROUS: Old pattern - extended: true can lead to prototype pollution
// In newer versions, this creates objects that can be exploited
app.use(bodyParser.urlencoded({ extended: true }));

// DANGEROUS: No limit on body size (DoS vulnerability)
// Old Express didn't enforce limits by default
app.use(bodyParser.json());

// VULNERABLE: No helmet, no rate limiting
// Old tutorials didn't emphasize these
app.post('/api/user', (req, res) => {
    const userData = req.body;
    // Direct use of req.body without validation
    db.query(`INSERT INTO users SET ?`, userData);
    res.json({ success: true });
});
'''


# =============================================================================
# REACT VERSION CONFUSION
# =============================================================================

REACT_VULNERABLE_CODE = '''
// React < 16.3: componentWillReceiveProps was standard
// React >= 16.3: Deprecated, but vibe-coded components still use it
// Can cause security issues with improper state updates

class UserProfile extends React.Component {
    // DEPRECATED: This lifecycle method is unsafe
    componentWillReceiveProps(nextProps) {
        // VULNERABLE: Directly setting state from props without validation
        if (nextProps.userInput !== this.props.userInput) {
            this.setState({ content: nextProps.userInput });
        }
    }

    render() {
        // VULNERABLE: dangerouslySetInnerHTML from state
        // Combined with componentWillReceiveProps, this is XSS
        return (
            <div dangerouslySetInnerHTML={{ __html: this.state.content }} />
        );
    }
}

// React < 17: Event pooling was enabled (confusing async behavior)
// Vibe-coded handlers might have race conditions

function SearchBox() {
    const [query, setQuery] = useState('');

    const handleChange = (e) => {
        // Old React: e.persist() was needed for async
        // New React: Not needed, but old patterns might cause issues
        setTimeout(() => {
            // VULNERABLE: Using event after async delay
            // In old React this would fail or have stale value
            setQuery(e.target.value);  // Fixed in React 17+, but confusing
        }, 100);
    };

    // VULNERABLE: Query used in SQL without escaping
    useEffect(() => {
        fetch(`/api/search?q=${query}`);  // No URL encoding!
    }, [query]);

    return <input onChange={handleChange} />;
}
'''


# =============================================================================
# SPRING BOOT VERSION CONFUSION
# =============================================================================

SPRING_VULNERABLE_CODE = '''
// Spring Boot 1.x vs 2.x security defaults changed dramatically
// Vibe-coded patterns often mix both

@RestController
public class UserController {

    // Spring Boot 1.x: @RequestMapping allowed GET by default
    // Spring Boot 2.x: More explicit mapping required
    // VULNERABLE: State-changing operation on GET
    @RequestMapping("/user/delete/{id}")  // Allows GET!
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        userRepository.deleteById(id);
        return ResponseEntity.ok().build();
    }

    // VULNERABLE: No CSRF, uses old Spring Security patterns
    // Spring Boot 2.x has CSRF enabled by default
    // But this is often disabled in REST APIs without proper alternative
    @PostMapping("/user/update")
    public User updateUser(@RequestBody User user) {
        // Direct binding without validation
        return userRepository.save(user);
    }
}

// Spring Security configuration - mixing old and new patterns
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // DEPRECATED: WebSecurityConfigurerAdapter is deprecated in Spring 5.7+
    // Old pattern that may have security gaps

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()  // DANGEROUS: Blanket CSRF disable
            .authorizeRequests()
            .antMatchers("/api/**").permitAll()  // DANGEROUS: Too permissive
            .anyRequest().authenticated();
    }

    // VULNERABLE: Old password encoder pattern
    @Bean
    public PasswordEncoder passwordEncoder() {
        // Spring 5+: This is now insecure, should use BCrypt
        return NoOpPasswordEncoder.getInstance();
    }
}
'''


# =============================================================================
# EXPECTED DETECTIONS
# =============================================================================

FRAMEWORK_VERSION_ISSUES = {
    "django": {
        "csrf_exempt_abuse": {
            "pattern": "@csrf_exempt on state-changing endpoint",
            "versions_affected": "All (but especially post-1.8 where CSRF is default)",
            "severity": "HIGH",
        },
        "mark_safe_misuse": {
            "pattern": "mark_safe() on user input",
            "versions_affected": "All",
            "severity": "CRITICAL",
        },
    },
    "flask": {
        "no_csrf_protection": {
            "pattern": "POST endpoint without Flask-WTF CSRF",
            "versions_affected": "All",
            "severity": "HIGH",
        },
    },
    "express": {
        "extended_urlencoded": {
            "pattern": "bodyParser.urlencoded({ extended: true })",
            "versions_affected": "4.x+",
            "severity": "MEDIUM",
        },
        "no_body_limit": {
            "pattern": "bodyParser.json() without limit",
            "versions_affected": "All",
            "severity": "MEDIUM",
        },
    },
    "react": {
        "dangerous_innerhtml": {
            "pattern": "dangerouslySetInnerHTML with user input",
            "versions_affected": "All",
            "severity": "CRITICAL",
        },
        "deprecated_lifecycle": {
            "pattern": "componentWillReceiveProps usage",
            "versions_affected": "16.3+",
            "severity": "LOW",
        },
    },
    "spring": {
        "request_mapping_get": {
            "pattern": "@RequestMapping without method on state change",
            "versions_affected": "All",
            "severity": "HIGH",
        },
        "noop_password_encoder": {
            "pattern": "NoOpPasswordEncoder usage",
            "versions_affected": "5.x+",
            "severity": "CRITICAL",
        },
    },
}
