# Code Scalpel Ninja Warrior: Comprehensive Repository Inventory & Reorganization

## 1. Executive Summary
The `Code-Scalpel-Ninja-Warrior` repository is a massive, multi-faceted test suite capable of validating every aspect of the Code Scalpel MCP server. However, it is currently fragmented into three distinct "continents" of tests:
1.  **The Challenges** (`challenges/`): 7 discrete, gamified scenarios used for demos and quick reliability checks.
2.  **The Torture Tests** (`torture-tests/`): A rigorous, "from every angle" verification suite for specific tool capabilities.
3.  **The Benchmarks** (`benchmarks/`): Industry-standard datasets (OWASP, Juliet, DroidBench) for performance and accuracy baselining.

To "verify Code Scalpel from every angle," we must treat this **entire repository** as the validation surface, not just `torture-tests/`.

## 2. The Hidden Gems (Why we need the whole repo)
Analysis reveals critical test workflows hiding outside `torture-tests/`:

*   **`challenges/07_broken_build/`**: The perfect test for `validate_paths` and `scan_dependencies`. Currently, no equivalent exists in `torture-tests/`.
*   **`benchmarks/juliet-java/`**: A goldmine for `security_scan` accuracy testing (False Positive/Negative rates), which `torture-tests/` lacks volume for.
*   **`results/exhaustive_v3.2.7/`**: Evidence of a "prior art" exhaustive testing script that we should revive.

## 3. The Unified "Bio-Dome" Architecture (Proposed)
We will unify these "continents" under a single **Workflow-Centric** taxonomy without destroying the historical `challenges/` (which are useful for demos). We will create **Symlinks** or **Wrapper Scripts** that map these resources into the 5 Workflows defined in the previous plan.

### Workflow Mapping (The "Grand Unification")

| Workflow | Primary Source (`torture-tests/`) | Reinforcements from `challenges/` | Reinforcements from `benchmarks/` |
| :--- | :--- | :--- | :--- |
| **Reconnaissance** | `stage5-policy-fortress` | **05_blindfold_maze** (Massive Repo)<br>**07_broken_build** (Path Validation) | N/A |
| **Structural** | `stage4-confidence-crisis` | **01_the_full_stack_snap** (API Contracts) | `droidbench` (Call Graph complexity) |
| **Surgical Ops** | **GAP** (Needs creation) | **02_legacy_nightmare** (Extract Legacy Code) | N/A |
| **Deep Security** | `stage8-advanced-taint`<br>`stage2-dynamic-labyrinth` | **03_supply_chain_trap** (Hidden Deps)<br>**04_hidden_bug** (Conditionals) | `owasp-benchmark`<br>`juliet-java` |
| **Compliance** | `stage6-mount-midoriyama` | **06_policy_prison** (Policy Checks) | `cvefixes` (Vulnerability counting) |

## 4. Enhanced Reorganization Plan
Instead of just moving files in `torture-tests/`, we will:

1.  **Create the 5 Workflow Directories** (`workflow-*`) at the repository root.
2.  **Migrate `torture-tests/`** into these directories (as they are "owned" by this effort).
3.  **Symlink `challenges/`** into relevant workflows (preserving their demo utility).
4.  **Symlink `benchmarks/`** as "Load Tests" within relevant workflows.

## 5. Tool Coverage Matrix (Repository Wide)
By combining all three sources, we achieve **100% Tool Coverage**:

*   `extract_code`: **Covered** by `challenges/02_legacy_nightmare` (Legacy function extraction).
*   `scan_dependencies`: **Covered** by `challenges/03_supply_chain_trap` (Obfuscated requirements).
*   `symbolic_execute`: **Covered** by `challenges/04_hidden_bug` (Unreachable code detection).

## 6. Action Items
1.  **Execute Phase 1:** Create `workflow-*` folders.
2.  **Execute Phase 2:** Move `torture-tests` content.
3.  **Execute Phase 3:** Symlink `challenges` content.
4.  **Execute Phase 4:** Create a Master Test Harness that runs distinct workflows across *all* sources.
