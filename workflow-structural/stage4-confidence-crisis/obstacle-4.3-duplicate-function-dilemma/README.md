# Obstacle 4.3: Duplicate Function Dilemma

Several functions share the same name but live in different modules and have different security properties. A query like “review the `validate` function” is intentionally ambiguous.

## Layout
- `auth.py` – `validate` performs minimal JWT shape checks.
- `payments.py` – `validate` builds SQL unsafely.
- `core.py` – `Handler.validate` overrides a parent implementation.

## Expectations
- Code Scalpel must enumerate all matching `validate` candidates instead of silently picking one.
- Confidence must be reduced in ambiguous contexts and clearly explain which function each finding refers to.
