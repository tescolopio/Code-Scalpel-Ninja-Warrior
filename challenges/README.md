# ⚔️ Code Scalpel Ninja Warrior

**Can your AI agent survive this gauntlet?**

Most AI coding agents are blunt instruments. They hallucinate paths, break legacy formatting, and introduce security vulnerabilities.

This repository contains **4 Challenges** designed to break standard LLM coding agents. They demonstrate why **Code Scalpel**—the surgical toolset for AI—is required for production-grade autonomous coding.

## The Challenges

| Level | Challenge Name | The Trap | The Code Scalpel Solution |
| :--- | :--- | :--- | :--- |
| 01 | **The Full-Stack Snap** | Changing a Python API silently breaks the TypeScript frontend. | `type_evaporation_scan` detects the mismatch across languages. |
| 02 | **The Legacy Nightmare** | A massive file with fragile formatting. Standard AIs rewrite (and ruin) it. | `extract_code` + `update_symbol` performs surgical, atomic edits. |
| 03 | **The Supply Chain Trap** | A requested library sounds safe but is a known typosquat. | `scan_dependencies` flags the supply chain risk before install. |
| 04 | **The Hidden Bug** | A mathematical edge case that standard tests miss. | `symbolic_execute` uses Z3 constraint solving to find the crash. |
| 05 | **The Blindfold Maze** | A massive repo where "standard" agents get lost. | `get_project_map` + `get_call_graph` visualize architecture instantly. |
| 06 | **The Policy Prison** | A risky commit with banned libraries and bad code quality. | `code_policy_check` + `verify_policy_integrity` block the PR. |
| 07 | **The Broken Build** | Missing tests and broken file paths in Docker config. | `validate_paths` fixes the environment; `generate_unit_tests` fixes the code. |

## How to Run
1. Clone this repo.
2. Point your standard AI (Cursor, Copilot, or vanilla Claude/GPT) at a folder and give it the prompt. **Watch it fail.**
3. Equip your agent with **Code Scalpel** tools. **Watch it succeed.**
