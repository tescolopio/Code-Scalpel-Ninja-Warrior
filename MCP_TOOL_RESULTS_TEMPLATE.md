# MCP Tool Results (Template)

This file is a *template* for recording MCP tool-by-tool results.

Write your filled-in run output to `results/MCP_TOOL_RESULTS.md` (ignored by git) or a versioned file like `results/MCP_TOOL_RESULTS_v3.2.4.md`.

## Run Metadata

- Date:
- Code Scalpel version:
- Transport: streamable HTTP (SSE)
- Notes:

## Scorecard

| Tool | Normal | Edge | Negative | Perf | Status | Evidence |
|---|---:|---:|---:|---:|---|---|
| analyze_code |  |  |  |  |  |  |
| crawl_project |  |  |  |  |  |  |
| cross_file_security_scan |  |  |  |  |  |  |
| extract_code |  |  |  |  |  |  |
| generate_unit_tests |  |  |  |  |  |  |
| get_call_graph |  |  |  |  |  |  |
| get_cross_file_dependencies |  |  |  |  |  |  |
| get_file_context |  |  |  |  |  |  |
| get_graph_neighborhood |  |  |  |  |  |  |
| get_project_map |  |  |  |  |  |  |
| get_symbol_references |  |  |  |  |  |  |
| scan_dependencies |  |  |  |  |  |  |
| security_scan |  |  |  |  |  |  |
| simulate_refactor |  |  |  |  |  |  |
| symbolic_execute |  |  |  |  |  |  |
| type_evaporation_scan |  |  |  |  |  |  |
| unified_sink_detect |  |  |  |  |  |  |
| update_symbol |  |  |  |  |  |  |
| validate_paths |  |  |  |  |  |  |
| verify_policy_integrity |  |  |  |  |  |  |

## Failures / Findings

List any mismatches (expected vs actual), perf overruns, false negatives/positives, and attach pointers to logs/evidence files under `results/`.
