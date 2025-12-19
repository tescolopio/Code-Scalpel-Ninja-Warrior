# Obstacle 4.1: The Calibration Test

Goal: verify Code Scalpel's reported confidence matches accuracy on known outcomes. Six tiny cases with labeled ground truth live in `cases/`. Run Code Scalpel on each file, capture predicted verdict (safe/vulnerable) and confidence, then bucket results:

- 0–50%, 50–70%, 70–90%, 90–100%
- Compute accuracy per bucket and Expected Calibration Error (ECE)

Passing thresholds (from spec):
- 90%+ bucket accuracy ≥ 85%
- 70–90% bucket accuracy ≥ 65%
- 50–70% bucket accuracy ≥ 45%
- No bucket accuracy < (midpoint – 15%)
- Overall ECE < 10%

## Evidence to collect
- Raw Code Scalpel output for each case (verdict + confidence)
- Bucketed accuracy table and ECE calculation
- Notes for any “unknown” or “unanalyzable” outputs (counted as incorrect)
- Hash of collected evidence

## How to run
1. Analyze each file in `cases/` independently.
2. Fill results into a spreadsheet or notebook using `ground_truth.csv`.
3. Compute bucket accuracy and ECE; attach the table to the test record.
