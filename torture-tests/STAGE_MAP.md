# Ninja Warrior Stage Map (Wrangled)

This repo’s `torture-tests/` suite started as a **Ninja Warrior**-style gauntlet (Stages 1–6), then grew additional suites (audit trail, policy engine, language coverage, etc.).

Rather than moving files around (which is noisy and breaks links), the harness maps the existing folder layout back into a consistent stage model.

## Stages

### Stage 1 — Qualifying Round
- Folder(s): `stage1-qualifying-round/`
- Goal: parser/encoding/syntax torture, basic robustness.

### Stage 2 — Dynamic Labyrinth
- Folder(s): `stage2-dynamic-labyrinth/`
- Goal: dynamic Python patterns (metaclasses, monkey patching, descriptor tricks, dynamic imports).

### Stage 3 — Boundary Crossing
- Folder(s):
  - `stage3-boundary-crossing/`
  - `cross-language-integration/` (mapped into Stage 3)
- Goal: cross-boundary data flows (ORM escape hatches, message queues, schema drift, type evaporation).

### Stage 4 — Confidence Crisis
- Folder(s): `stage4-confidence-crisis/`
- Goal: ambiguity, adversarial naming, duplicates, contradictions, incomplete context.

### Stage 5 — Policy Fortress
- Folder(s):
  - `stage5-policy-fortress/`
  - `policy-engine/` (mapped into Stage 5)
  - `crypto-verify/` (mapped into Stage 5)
  - `audit-trail/` (mapped into Stage 5)
  - `change-budget/` (mapped into Stage 5)
- Goal: governance hardening (fail-closed behavior, policy integrity, audit integrity, change budgets).

### Stage 6 — Mount Midoriyama
- Folder(s): `stage6-mount-midoriyama/`
- Goal: sandbox escape attempts, resource exhaustion, path explosion.

### Stage 7 — Language Coverage
- Folder(s):
  - `stage7-language-coverage/`
  - `language-coverage/` (mapped into Stage 7)
  - `framework-specific/` (mapped into Stage 7)
  - `advanced-async/` (mapped into Stage 7)
- Goal: breadth across languages/frameworks and modern language features.

### Stage 8 — Advanced Taint
- Folder(s): `stage8-advanced-taint/`
- Goal: comprehensive vulnerability surface + cross-file taint.

## Adding new tests

When adding new tests:
- Prefer placing them under the corresponding `stageN-.../` folder.
- If a test is a “suite” (many files + its own runner), you can keep it as a top-level folder, but update the harness stage mapping to include it.

## Harness behavior

The harness (`test_harness.py`) deduplicates files so a test only counts once even if a directory is mapped into multiple stages.
