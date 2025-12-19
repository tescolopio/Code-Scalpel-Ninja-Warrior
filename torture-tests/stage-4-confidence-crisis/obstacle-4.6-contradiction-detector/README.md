# Obstacle 4.6: Contradiction Detector

This snippet mixes conflicting signals: comments and docstrings promise safety while the code does the opposite. Code Scalpel must favor runtime behavior, call out contradictions, and lower confidence.

## Expectations
- Flag mismatch between “hashed”/“encrypted” claims and plaintext storage.
- Note that `validated_user_id` is not actually validated.
- Do **not** let reassuring comments raise confidence.
