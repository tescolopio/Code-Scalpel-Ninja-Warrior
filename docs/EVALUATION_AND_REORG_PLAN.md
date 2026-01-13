# Code Scalpel Ninja Warrior: Torture Test Evaluation & Reorganization Plan

## 1. Executive Summary
The current "Ninja Warrior" torture suite is organized by **Conceptual Stage** (e.g., "Confidence Crisis", "Mount Midoriyama"). While thematic, this structure obscures coverage gaps for specific Code Scalpel tools. 

To ensure **Robustness**, **Difficulty**, and **Total Coverage** of all 22 tools, we will transition to a **Workflow-Centric Model**. This aligns tests with how agents actually use the tools in sequence (e.g., *Scan -> Extract -> Refactor*).

## 2. Tool Inventory & Coverage Goals (The "Scalpel 22")
We must verify at least one "Torture" class test for every tool.

| ID | Tool Name | Current Status | Proposed Workflow |
|----|-----------|----------------|-------------------|
| 1 | `analyze_code` | Covered (Stage 1) | **Core Analysis** |
| 2 | `extract_code` | Covered (Stage 7) - **Fail** | **Surgical Ops** |
| 3 | `crawl_project` | Covered (Massive Repo) | **Reconnaissance** |
| 4 | `cross_file_security_scan` | Covered (Stage 8) - **Pass** | **Deep Security** |
| 5 | `get_call_graph` | Partial (Stage 4) | **Structural** |
| 6 | `get_cross_file_dependencies`| Covered (Stage 8) | **Structural** |
| 7 | `get_project_map` | Partial | **Reconnaissance** |
| 8 | `scan_dependencies` | Covered (Stage 3/7) | **Compliance** |
| 9 | `security_scan` | Covered (Stage 2/6) | **Deep Security** |
| 10 | `validate_paths` | Covered (Stage 7) | **Reconnaissance** |
| 11 | `generate_unit_tests` | **GAP** | **Validation** |
| 12 | `symbolic_execute` | Covered (Stage 2/4) | **Validation** |
| 13 | `rename_symbol` | **GAP** | **Surgical Ops** |
| 14 | `update_symbol` | **GAP** | **Surgical Ops** |
| 15 | `get_file_context` | **GAP** | **Reconnaissance** |
| 16 | `get_graph_neighborhood` | **GAP** | **Structural** |
| 17 | `get_symbol_references` | Partial (Stage 4) | **Structural** |
| 18 | `simulate_refactor` | Partial (Stage 5) | **Surgical Ops** |
| 19 | `type_evaporation_scan` | Covered (Stage 3) | **Deep Security** |
| 20 | `unified_sink_detect` | Covered (Stage 1) | **Deep Security** |
| 21 | `verify_policy_integrity` | Covered (Stage 5/6) | **Compliance** |
| 22 | `code_policy_check` | Covered (Stage 6) | **Compliance** |

## 3. Reorganization Strategy: Multi-Tool Workflows
We will reorganize `torture-tests/` into 5 high-level Workflow Directories.

### A. `workflow-reconnaissance/` (Map & Territory)
*Tools: `crawl_project`, `get_project_map`, `validate_paths`, `get_file_context`*
* **Tests:**
    * **Massive Scale:** 10k+ file repo navigation (Mocked).
    * **Broken Paths:** Symlinks, missing mounts, permission denied inputs.
    * **Context Trap:** Files with 10k lines of comments vs code.

### B. `workflow-structural/` (Graph & Flow)
*Tools: `get_call_graph`, `get_graph_neighborhood`, `get_cross_file_dependencies`, `get_symbol_references`*
* **Tests:**
    * **The Spaghetti Monster:** Circular imports with depth > 50.
    * **Shadow Realm:** Classes with same name in different modules.
    * **Graph Explosion:** A function called by 5,000 other functions.

### C. `workflow-surgical-ops/` (Incision & Modification)
*Tools: `extract_code`, `update_symbol`, `rename_symbol`, `simulate_refactor`*
* **Tests:**
    * **Precision Strike:** Extract 1 method from a file with specific indentation/encoding.
    * **Atomic Fail:** `update_symbol` where disk write fails halfway (Simulated).
    * **Refactor Hazard:** Rename a symbol that is dynamically constructed (`getattr(obj, "method")`).

### D. `workflow-deep-security/` (Taint & Poison)
*Tools: `security_scan`, `cross_file_security_scan`, `unified_sink_detect`, `type_evaporation_scan`*
* **Tests:**
    * **Polyglot Payload:** Taint passing from Python -> JSON -> TypeScript.
    * **Sink Camouflage:** Sinks hidden in decorators, metaclasses, or comments.
    * **Type Illusion:** TypeScript interfaces that don't match runtime data.

### E. `workflow-compliance/` (Law & Order)
*Tools: `verify_policy_integrity`, `code_policy_check`, `scan_dependencies`, `generate_unit_tests`, `symbolic_execute`*
* **Tests:**
    * **Tampered Seal:** Policy files with valid hash but invalid signature.
    * **Dependency Hell:** Circular dependencies with vulnerabilities.
    * **Symbolic Maze:** Functions solvable only by symbolic execution constraints.

## 4. Robustness & Difficulty Audit Plan
For each test file, we will run the `Evaluation Protocol`:

1.  **The Flake Check:** Run test 5 times. Must pass 5/5.
2.  **The False Positive Check:** Run against "Known Safe" code (Golden Master). Must return 0 issues.
3.  **The Complexity Check:**
    *   **Level 1 (Basic):** Direct call (e.g., `eval(x)`).
    *   **Level 2 (Obfuscated):** Indirection (e.g., `func = eval; func(x)`).
    *   **Level 3 (Polyglot):** Across language/file boundaries.
    *   **Level 4 (Adversarial):** Code specifically written to trick regex/AST parsers.

## 5. Execution Steps
1.  **Inventory:** Run `ls -R` and map existing files to new folders.
2.  **Migrate:** Move files to `torture-tests/workflow-*/`.
3.  **Fill Gaps:** Create placeholders for missing tools (e.g., `rename_symbol`).
4.  **Verify:** Run the `test_harness.py` adapted to the new structure.
