# Code Scalpel Ninja Warrior 🥷

**The Ultimate "Torture Test" Suite for Code Scalpel**

This repository contains rigorous test cases designed to push the [Code Scalpel](https://github.com/code-scalpel) MCP server to its limits. Unlike standard unit tests, these "Ninja Warrior" stages test resilience against complex, adversarial, and deeply nested code patterns.

## 🏗️ Architecture: The Workflow Bio-Dome

The tests are organized into 5 primary workflows, mirroring how AI agents use Code Scalpel in the wild. Each workflow unifies classic "Challenges", "Torture Tests", and Industry "Benchmarks".

### 1. 🕵️ Workflow: Reconnaissance
**Goal:** Map the territory without crashing.
- **Tools:** `crawl_project`, `get_project_map`, `validate_paths`, `get_file_context`
- **Key Tests:**
    - `stage5-policy-fortress` (Access controls)
    - `challenge-05-blindfold-maze` (Massive repo checks)
    - `challenge-07-broken-build` (Path validation)

### 2. 🏛️ Workflow: Structural
**Goal:** Understand relationships and contracts.
- **Tools:** `get_call_graph`, `scan_dependencies`, `verify_policy`, `mcp_contract`
- **Key Tests:**
    - `stage4-confidence-crisis` (Deep dependencies)
    - `benchmark-droidbench` (Complex call graphs)
    - `challenge-01-full-stack-snap` (API Contracts)

### 3. 🔪 Workflow: Surgical Ops
**Goal:** Precise extraction and modification.
- **Tools:** `extract_code`, `update_symbol`, `rename_symbol`
- **Key Tests:**
    - `challenge-02-legacy-nightmare` (Extracting legacy spaghetti)
    - *(New surgical torture tests coming soon)*

### 4. 🛡️ Workflow: Deep Security
**Goal:** Find the needle in the haystack.
- **Tools:** `security_scan`, `cross_file_security_scan`, `unified_sink_detect`, `simulate_refactor`
- **Key Tests:**
    - `stage8-advanced-taint` (Cross-file data flow)
    - `stage2-dynamic-labyrinth` (Dynamic Python tricks)
    - `benchmark-owasp` & `benchmark-juliet` (False positive checks)

### 5. ⚖️ Workflow: Compliance
**Goal:** Ensure governance and resource limits.
- **Tools:** `verify_policy_integrity`, `type_evaporation_scan`
- **Key Tests:**
    - `stage6-mount-midoriyama` (Resource exhaustion)
    - `audit-trail` & `policy-engine`
    - `benchmark-cvefixes`

---

## 🚀 Running the Gauntlet

The test harness has been updated to support this new structure.

```bash
# Run the harness from the root
python3 harness/test_harness.py --all
```

## 📁 Directory Structure

```
Code-Scalpel-Ninja-Warrior/
├── workflow-reconnaissance/  # Mapping & Access
├── workflow-structural/      # Graph & Deps
├── workflow-surgical-ops/    # Extract & Edit
├── workflow-deep-security/   # Taint & Vulns
├── workflow-compliance/      # Governance & Limits
├── harness/                  # Test Runner & Tools
└── challenges/               # (Legacy Demo Source)
```
