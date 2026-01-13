# Obstacle 4.5: Confidence Decay Test

Inference chain: `alpha` → `bravo` → `charlie` → `delta`. The direct vulnerability lives in `delta`. Confidence should be highest when reporting on `delta`, then decay monotonically as conclusions are propagated up the call chain.

## Expectations
- `delta` (direct SQL injection) => highest certainty.
- `charlie` (passes tainted data) => lower confidence than `delta`.
- `bravo` and `alpha` => progressively lower confidence.
- Reports must explicitly call out inference depth when describing findings in upstream functions.
