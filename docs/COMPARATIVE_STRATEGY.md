# Strategy for Comparative Analysis: Code Scalpel

## The Core Distinction
To provide a "true comparison," we must distinguish between tools we compete **AGAINST** (Static Analysis/SAST) and tools we work **WITH** (AI Assistants).

---

## 1. Comparing AGAINST: Static Analysis (SAST)
**Tools:** SonarQube, Semgrep, Checkmarx, CodeQL, Bandit.
**The Metric:** *Contextual Relevance & Actionability*

Most SAST tools are "Find & Report." Code Scalpel is "Locate & Verify."

### Test Strategy: The "False Positive" & "Context" Challenge
Run a benchmark focusing on complex, cross-file logic that trips up regex-based or file-local tools.

| Dimension | Standard SAST (The "Other Guys") | Code Scalpel | Why We Win |
| :--- | :--- | :--- | :--- |
| **Cross-File Data Flow** | Often limited or requires full build artifact | **Native & On-Demand** | We trace import chains dynamically without needing a compiled build. |
| **Logic vs. Pattern** | Flags `eval()` everywhere (High False Positive) | Flags `eval(user_input)` (High Precision) | `unified_sink_detect` uses confidence scoring based on variable origin. |
| **Broken Code** | Falls over on syntax errors | **Partial Parsing** | We parse function-by-function, allowing analysis of "work in progress" code. |
| **The "Fix"** | Generic suggestion text | **Surgical `update_symbol`** | We provide the *mechanism* to apply the fix safely, not just the advice. |

**Concrete Demo Plan:**
1.  **Type Evaporation:** Create a test where types look safe in TypeScript but evaporate in Python. (Semgrep misses this; Code Scalpel catches it).
2.  **Dead Code:** Identify functions that *look* used (same name) but aren't imported. (Text search fails; Graph analysis succeeds).

---

## 2. Comparing WITH: AI Assistants
**Tools:** GitHub Copilot, Cursor, Cody.
**The Metric:** *Hallucination Rate & Safe Execution*

Code Scalpel is the **Toolbelt** for these Agents. We don't replace the Brain (LLM); we provide the Hands (Tools).

### Test Strategy: The "Augmentation" Study
Compare an AI attempting a task *Raw* (Text Generation) vs. *Instrumented* (Tool Use).

| Task | AI Alone (Raw Generation) | AI + Code Scalpel | The "Scalpel Effect" |
| :--- | :--- | :--- | :--- |
| **Refactoring** | Rewrites full file. Often drops comments, messes up indentation or imports. | `extract_code` -> `update_symbol` | **Preservation.** Only the target function changes. Surrounding code (and hidden hacks) remains untouched. |
| **Safety** | Suggests `os.system(cmd)` because it's easy. | `simulate_refactor` -> **BLOCKED** | **Guardrails.** The tool catches the CVE *before* the code is written to disk. |
| **Context** | "I can't see that file." / Guessing APIs. | `get_file_context` / `get_symbol_references` | **Grounding.** The AI queries the repo map to find the *actual* definition file. |
| **Verification** | "I hope this works." | `generate_unit_tests` -> `run_test` | **certainty.** The AI generates a test to prove the fix works. |

### The "Win" Message
> "Copilot is a brilliant architect. Code Scalpel is the master builder ensuring the walls don't fall down."

**Concrete Demo Plan:**
1.  **The "Blind" Agent:** Ask an AI to refactor a function without extracting it first. (It will hallucinate arguments).
2.  **The "Scalpel" Agent:** Use `extract_code` to get the signature, then `update_symbol`. (Perfect accuracy).

---

## 3. The "Hybrid" Advantage: Agentic Workflow
The ultimate comparison isn't A vs B, but the **Workflow**.

*   **Old Way:** Developer writes code -> Pushes to CI -> SonarQube fails build (30 mins later) -> Developer context switches -> Fixes bug.
*   **Scalpel Way:** Agent proposes code -> `simulate_refactor` checks it (3 seconds) -> `update_symbol` applies it -> Done.

**Metric:** *Time to Validated Fix.*
Code Scalpel reduces the loop from "Commit-CI-Reject" to "Generate-Validate-Apply" inside the IDE.
