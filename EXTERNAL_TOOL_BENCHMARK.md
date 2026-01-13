# External Static Analysis Benchmark

## Overview
This document compares the findings of **Code Scalpel v3.3.0** against industry-standard static analysis tools (**Bandit**, **Ruff**, **Semgrep**) on the `Code-Scalpel-Ninja-Warrior` test suite.

## 1. Security Analysis (Bandit vs. Code Scalpel)
**Target:** `workflow-compliance` (28 files) and `workflow-deep-security` (Deep Taint).

| Feature | Bandit (v1.7.x) | Code Scalpel (Enterprise) | Difference |
| :--- | :--- | :--- | :--- |
| **Total Issues Found** | 639 (mostly `assert`) | **1,237** | Code Scalpel found ~2x more distinct issues. |
| **Hardcoded Secrets** | Detected as **Low Severity** (B105) | Detected as **Critical** (SEC001) | Code Scalpel correctly prioritizes secrets in a compliance context. |
| **Taint Analysis** | **Missed Cross-File Flows** | **Detected** (`security_scan`) | Bandit is file-local AST only. Code Scalpel traces data flow across modules. |
| **Noise Ratio** | High (582 `assert` warnings mixed in) | Low (Categorized) | Code Scalpel separates `PY005` (Info) from `SEC` (Critical). |
| **Compliance Mapping** | None | **HIPAA, SOC2, PCI-DSS** | Code Scalpel maps findings directly to regulatory controls. |

### Detailed Findings
*   **Bandit:** Flooded the report with `B101: assert_used` (582 occurrences). Identified potential passwords like `DEFAULT_SECRET` but flagged them as **Low Severity**, which could be filtered out by default CI pipelines.
*   **Code Scalpel:** Identified the same `assert` usage as **Info** (PY005) but escalated `HARDCODED_SECRET` to **Critical**, ensuring they block deployment in a compliance workflow.

## 2. Quality & Linting (Ruff vs. Code Scalpel)
**Target:** `workflow-compliance`

| Feature | Ruff (v0.3.x) | Code Scalpel (Enterprise) | Difference |
| :--- | :--- | :--- | :--- |
| **Focus** | Speed, Syntax, Imports | Policy, Logic, Complexity | Ruff wins on speed; Code Scalpel wins on depth. |
| **Findings** | **252** (Unused imports, specific style) | **1,237** (Complexity, Magic Numbers, Length) | Code Scalpel enforces "Business Health" metrics Ruff ignores. |
| **Magic Numbers** | Ignored | **Detected/Flagged** (BP007) | Code Scalpel identified "Magic Constants" (e.g., `8601`) breaking maintainability. |
| **Function Length** | Ignored (default) | **Enforced** (BP004) | Code Scalpel flagged Functions > 50 lines. |
| **Async Safety** | Basic | **Advanced** (`ASYNC002`) | Code Scalpel flagged blocking calls inside async functions. |

## 3. Advanced SAST (Semgrep OSS vs. Code Scalpel)
**Target:** `workflow-deep-security` and `workflow-compliance`.

| Feature | Semgrep OSS (v1.147.0) | Code Scalpel (Enterprise) | Difference |
| :--- | :--- | :--- | :--- |
| **Deep Taint (Cross-File)** | **Detected (2 findings)** | **Detected (3 flows)** | Semgrep caught standard SQLi but missed complex dynamic flows. |
| **Compliance/Policy** | **0 findings** (Default config) | **1,237 findings** | Semgrep requires custom rule writing for policy; Code Scalpel has it built-in. |
| **Legacy Code** | **0 findings** | **Detected** (`eval` usage) | Semgrep standard rules missed the legacy nightmare context. |
| **Setup Complexity** | High (Managed Environment issues) | Zero (Agent-native) | Required conda/pip workarounds; Code Scalpel is tool-native. |

### Detailed Findings
*   **Semgrep:** Excellent specific finding for the SQL Injection in `db.py` (Rule: `python.lang.security.audit.formatted-sql-query`). However, running with `--config=auto` yielded **zero** results for the entire compliance suite, missing magic numbers, complexity issues, and maintainability blockers.
*   **Code Scalpel:** Correctly identified the same SQL injection but also flagged the "Legacy Nightmare" code and thousands of policy violations needed for the audit.

## 4. Tool Capabilities Summary

| Capability | Bandit | Ruff | Semgrep | Code Scalpel |
| :--- | :---: | :---: | :---: | :---: |
| **Polyglot** | ❌ (Python) | ❌ (Python) | ✅ (Many) | ✅ (Py, JS, TS, Java) |
| **Deep Taint Analysis** | ❌ | ❌ | ✅ (Pro/Ci only?) | ✅ (Native) |
| **Surgical Refactoring** | ❌ | ✅ (Fix only) | ❌ (No fix) | ✅ (Update Symbol) |
| **Configuration** | File-based | File-based | Rules (YAML) | Tier-based + Config |
| **Zero-Config Run** | ✅ | ✅ | ✅ | ✅ (`extract_code`) |

## Conclusion
While **Ruff** remains the champion for raw speed and **Semgrep** is a powerful engine for custom security rules, **Code Scalpel** operates at a higher semantic level for **Autonomous Agents**.

*   **Context Awareness:** Semgrep treats files as text/AST. Code Scalpel treats them as *components* (extracting structure, calculating complexity).
*   **Agent Utility:** Semgrep output is for humans (lines of code). Code Scalpel output is for Agents (JSON structure, complexity scores, functions).
*   **Cross-File Dependencies:** Code Scalpel's `get_cross_file_dependencies` is designed for **Context Window Management** (sending just the right code to the LLM), whereas Semgrep is designed for **Reporting**.
