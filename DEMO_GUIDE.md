# Code Scalpel Ninja Warrior - Demo Scenarios

> **Focus:** Proving the "Code Scalpel Moment" through live demonstration.
>
> **Philosophy:** "If a demo needs explanation, it’s not ready."

This document outlines the key demonstration scenarios ("Demos") tailored for showcasing Code Scalpel's unique capabilities to Engineering, Security, and Marketing audiences.

---

## Demo 1: "The Full-Stack Snap" (Type Evaporation)

**The Hook:** Most AI agents break full-stack apps because they treat files in isolation. This demo proves Code Scalpel "sees" the invisible connection between a Python backend and a TypeScript frontend.

### The Setup
A simple app (provided in this repo) with:
*   **Backend:** FastAPI (Python) API endpoint.
*   **Frontend:** React/TypeScript interface consuming that endpoint.

### The Scenario
You ask the agent to:
> "Change the user ID from an integer to a UUID string in the backend API."

### The "Standard Agent" Failure
*   It updates the Python Pydantic model.
*   It leaves the TypeScript interface defined as `number`.
*   The app compiles (types check locally per file), but crashes at runtime or displays `NaN` when loading data.

### The Code Scalpel Moment
1.  The agent changes the Python backend.
2.  It runs **`type_evaporation_scan`**.
3.  The tool returns a **Critical Risk** alert:
    > "Type Evaporation detected at fetch('/api/user'). Backend sends string, Frontend expects number".
4.  The agent automatically fixes the TypeScript interface (e.g., `interface User { id: string }`) to match.

### Why it wins
It demonstrates the **"Pro Tier" cross-file correlation capability** that no standard MCP tool offers. It validates that Code Scalpel doesn't just read code—it understands the *contract* between systems.

---

## Demo 2: "The Surgeon vs. The Butcher" (Surgical Editing)

**The Hook:** LLMs are notorious for "lazy coding"—deleting comments, ruining formatting, or hallucinating code when editing large files. This demo visualizes the "Scalpel" branding.

### The Setup
A massive, legacy Python file (2,000+ lines) full of crucial inline comments, weird indentation, and complex logic.

### The Scenario
You ask the agent to:
> "Update the calculate_tax function to handle a new region."

### The "Standard Agent" Failure
*   **The Butcher Approach:** The LLM rewrites the whole file.
*   It strips comments, truncates the end of the file due to token limits, or subtly breaks indentation elsewhere.
*   The diff is 2,000 lines ("Red Sea"), making code review impossible.

### The Code Scalpel Moment
1.  The agent uses **`extract_code`** to read *only* the `calculate_tax` function.
2.  It performs the logic update locally on those few lines.
3.  It calls **`update_symbol`** to replace *only* that function body.
4.  **The Climax:** Show the git diff. It is clean, precise, and touches exactly 12 lines. The rest of the file is bit-perfect.

### Why it wins
It proves **safety and respect for legacy code**. It highlights the syntax validation and backup creation features of `update_symbol`, contrasting the "Surgical" precision against the brute-force rewriting of standard tools.

---

## Demo 3: "The Typosquat Trap" (Supply Chain Defense)

**The Hook:** Security is usually boring. Make it exciting by simulating an active attack.

### The Setup
A clean Python project.

### The Scenario
You prompt the agent:
> "I need to parse some YAML files. Please install a library for that."

### The "Standard Agent" Failure
*   The agent (simulated or real) tries to install `PyYAML` but makes a typo or picks a malicious look-alike package (e.g., `pyaml` vs `PyYAML` confusion).
*   It executes `pip install pyaml` without verification.

### The Code Scalpel Moment
1.  Before installation, the agent calls **`scan_dependencies`**.
2.  The tool triggers the **typosquatting_detection** (Pro Tier feature).
3.  **The Alert:**
    > "STOP. pyaml is a potential typosquat of PyYAML. Supply Chain Risk Score: 85/100".
4.  The agent corrects itself and installs the safe version (`PyYAML`).

### Why it wins
It shows the **"World Class" security mindset**. It moves beyond simple CVE scanning to proactive threat detection, catching attacks before they happen.

---

## Demo 4: "The Bug That Doesn't Exist Yet" (Symbolic Execution)

**The Hook:** Unit tests only find bugs you expect. Symbolic execution finds bugs you didn't imagine.

### The Setup
A Python function that looks fine but has a mathematical edge case (e.g., a "division by zero" or "integer overflow" that only happens if input `x == 9421`).

### The Scenario
You prompt the agent:
> "Write tests for this function."

### The "Standard Agent" Failure
*   Writes 3 basic tests (positive, negative, zero logic).
*   All tests pass.
*   The bug remains hidden in production.

### The Code Scalpel Moment
1.  The agent runs **`symbolic_execute`**.
2.  The tool explores the Z3 constraint paths and reports:
    > "Unreachable Code / Crash detected when x = 9421".
3.  The agent generates a specific test case for `input=9421` that fails, **proving the bug exists**.

### Why it wins
It showcases **"Deep Tech."** It proves Code Scalpel isn't just a wrapper for other APIs; it has an internal reasoning engine using Z3 constraint solving to find deep logical flaws.

---

## Demo 5: "The Blindfold Maze" (Context & Navigation Squad)

**The Hook:** "Standard agents are lost in large repos. Code Scalpel creates a mental map instantly."

### The Setup
A complex "spaghetti repo" with dispersed logic (`auth`, `database`, `utils`) mimicking enterprise legacy code.

### The Scenario
You prompt the agent:
> "Explain how the authentication flow connects to the database, then find the specific file where the login retry logic lives."

### The "Standard Agent" Failure
*   It asks: "Please provide the relevant files." (It can't see the whole repo).
*   It hallucinates file paths (`src/login.py` instead of `src/auth/login.py`).

### The Code Scalpel Moment
1.  Agent calls **`get_project_map`** to see the topography.
2.  Agent calls **`get_call_graph`** on `src/auth/login.py` to trace the data flow.
3.  Agent calls **`get_graph_neighborhood`** to see strictly related modules (`connector`, `logger`).
4.  It produces a perfect architecture summary and points to the exact file.

---

## Demo 6: "The Perfect Guard" (Compliance & Policy Squad)

**The Hook:** "Security isn't just about bugs; it's about rules. Watch Code Scalpel enforce corporate law."

### The Setup
A developer tries to commit `risky_commit.py` which uses `md5` (banned) and `os.system` (dangerous), bypassing the `policy.yaml`.

### The Scenario
You prompt the agent:
> "Review this PR for the Enterprise release."

### The Code Scalpel Moment
1.  **`verify_policy_integrity`** checks the digital signature of the company policy file (finds it valid).
2.  **`code_policy_check`** flags the missing docstrings and banned `hashlib.md5` import.
3.  **`cross_file_security_scan`** traces the taint from `data` input to `os.system`.
4.  **The Bombshell:** The agent executes a **Hard Block**: "Blocked: 4 Violations. Signature Verified. Security Risk Critical."

---

## Demo 7: "The Self-Healing Challenge" (Maintenance & Test Squad)

**The Hook:** "Writing code is easy. Fixing broken tests and dependencies is hard. Code Scalpel does the dirty work."

### The Setup
A broken project: `main.py` depends on a `docker-compose.yml` volume that points to a non-existent file (`config/setup.json`). Tests are missing.

### The Scenario
You prompt the agent:
> "Fix the build."

### The Code Scalpel Moment
1.  **`validate_paths`** scans the `docker-compose.yml` and realizes `./config/setup.json` does not exist on disk. It flags the environment error.
2.  **`generate_unit_tests`** writes missing tests for `main.py`, mocking the `utils` dependency.
3.  **The Bombshell:** The agent fixes the *environment* (creates the directory/file) and the *code* (adds tests) in one autonomous loop.

