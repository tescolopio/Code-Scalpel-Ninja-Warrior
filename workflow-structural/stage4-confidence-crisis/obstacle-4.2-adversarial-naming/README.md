# Obstacle 4.2: Adversarial Naming

These snippets pair misleading names with opposing behaviors. Code Scalpel should ignore names and comments and rely solely on semantics.

## Expectations
- `sanitize_input` is a no-op and must be flagged.
- `dangerous_do_not_use` is parameterized and should **not** be penalized just because of its name.
- `escape` shadows the stdlib import and is unsafe; this shadowing must be detected.
- Confidence should derive from behavior, not how “safe” or “scary” identifiers sound.
