# Competitive Landscape Analysis

## Overview
Code Scalpel operates in a crowded market of Static Application Security Testing (SAST) and Code Quality tools. However, its "Surgical Agent" architecture differentiates it from traditional scanners.

## 1. Traditional Enterprise SAST (The "Heavyweights")
**Competitors:** [SonarQube](https://www.sonarsource.com/products/sonarqube/), [Checkmarx](https://checkmarx.com/), [Veracode](https://www.veracode.com/), [Fortify](https://www.microfocus.com/en-us/cyberres/application-security/fortify)

| Feature | Enterprise SAST | Code Scalpel |
| :--- | :--- | :--- |
| **Primary Goal** | Reporting & Dashboards | **Fixing & Modification** |
| **Analysis Depth** | Deep Data Flow (Slow) | **Deep Taint (On-Demand)** |
| **Workflow** | CI/CD Gate -> Jira Ticket | **Agent Tool -> Direct Fix** |
| **Setup** | Complex Server Infrastructure | **Lightweight Agent/MCP** |

**Verdict:** Code Scalpel is faster for *intercative development*. You don't wait for a report; you ask the agent to "fix the SQL injection in auth.py".

## 2. Modern Developer-First Tools
**Competitors:** [Snyk](https://snyk.io/), [Semgrep](https://semgrep.dev/), [CodeQL](https://codeql.github.com/)

| Feature | Snyk / Semgrep | Code Scalpel |
| :--- | :--- | :--- |
| **Speed** | Blazing Fast (AST-based) | Fast (Surgical) |
| **Customization** | YAML Rules / Queries | **Python-based Logic** |
| **Fixing** | Auto-PRs (Generic) | **Context-Aware Refactoring** |
| **Scope** | SCA (Dependencies) + Code | **Code Structure + Taint + Logic** |

**Verdict:** Semgrep is unbeatable for speed and custom rules. Code Scalpel shines when the fix requires understanding *dependencies across files* (e.g., changing a function signature requires updating all callers).

## 3. AI Coding Assistants
**Competitors:** [GitHub Copilot](https://github.com/features/copilot), [Cursor](https://cursor.sh/), [Sourcegraph Cody](https://sourcegraph.com/cody)

| Feature | AI Assistants | Code Scalpel |
| :--- | :--- | :--- |
| **Mechanism** | LLM Prediction (Probabilistic) | **Symbolic Analysis (Deterministic)** |
| **Context** | Window-limited (RAG) | **Full Graph Awareness** |
| **Reliability** | Can Hallucinate APIs | **Verifies Existence First** |
| **Safety** | User Must Review | **Simulates Refactor Safety** |

**Verdict:** Code Scalpel is the "Left Brain" (Logic/Validation) to the AI's "Right Brain" (Creativity). It prevents the AI from Hallucinating libraries or breaking builds by validating changes before they happen.

## 4. Language-Specific Linters
**Competitors:** [Pylint](https://pypi.org/project/pylint/), [Bandit](https://github.com/PyCQA/bandit), [ESLint](https://eslint.org/)

| Feature | Linters | Code Scalpel |
| :--- | :--- | :--- |
| **Scope** | Single File | **Project-Wide** |
| **Type Checking** | Limited (unless MyPy) | **Type Evaporation Detection** |
| **Secrets** | Regex-based | **Context-Aware** |

**Verdict:** Linters are essential for basic hygiene. Code Scalpel handles the "grey area" vulnerabilities that span the frontend-backend divide (Type Evaporation) which linters miss.

## Summary: The "Surgical" Niche
Code Scalpel is not trying to replace SonarQube's dashboards or Copilot's chat. It fills the specific niche of **"Safe, Verified Code Modification by Agents."**
*   **Don't just find the bug** (SonarQube).
*   **Don't just guess the fix** (Copilot).
*   **Locate, Verify, Simulate, and Apply.**
