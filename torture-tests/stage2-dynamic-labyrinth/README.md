# Stage 2 – The Dynamic Labyrinth

These assets implement the **Dynamic Language Pathology** level from the *Code Scalpel Ninja Warrior* specification (see `Code_Scalpel_Ninja_Warrior_Torture_Tests.md`, Stage 2). Each file is a minimal Python snippet that exercises a specific obstacle. Analyze each snippet independently and record:

- Code Scalpel findings and confidence scores
- Any explicit uncertainty acknowledgments
- Time/memory metrics
- Hash of the analyzed file (per Evidence Requirements)

## Obstacle Map

| Obstacle | File | Scenario focus | Expected Code Scalpel behavior |
| --- | --- | --- | --- |
| 2.1 Getattr Gauntlet | `obstacle-2.1-getattr-gauntlet.py` | Dynamic attribute resolution driven by tainted input and proxying via `__getattr__` | Treat results as tainted; avoid claiming specific attribute targets |
| 2.2 Eval Abyss | `obstacle-2.2-eval-abyss.py` | Direct and obfuscated `eval`/`exec` of tainted strings | Flag as critical, acknowledge unanalyzable executed code |
| 2.3 Metaclass Maze | `obstacle-2.3-metaclass-maze.py` | Metaclasses inject security-relevant methods at runtime | Reduce confidence; flag dynamic class construction |
| 2.4 Factory Function Fog | `obstacle-2.4-factory-function-fog.py` | Factories/closures generate handlers that capture tainted values | Track taint through closures and decorator transforms |
| 2.5 Monkey Patch Mayhem | `obstacle-2.5-monkey-patch-mayhem.py` | Runtime patching disables security checks and alters built-ins | Detect patches and treat downstream analysis with reduced confidence |
| 2.6 Descriptor Dungeon | `obstacle-2.6-descriptor-dungeon.py` | Descriptors/properties that execute logic on access | Treat property access as code execution; track data flow through descriptors |
| 2.7 Import Illusion | `obstacle-2.7-import-illusion.py` | Dynamic imports, custom import hooks, and tainted module names | Flag tainted import targets as critical and acknowledge unknown modules |

### Usage notes

- These snippets require **Python 3.10 or later** (they use features such as `type | None` and built-in generics like `list[str]`).
- These snippets require **Python 3.10 or later** (use of `type | None` and built-in generics like `list[str]`).
- Inputs labeled `user_input`, `action`, or `payload` should be treated as attacker-controlled.
- None of the snippets attempt to catch exceptions; analysis should surface the security implications of the dynamic behavior rather than runtime success.
- These files are intentionally standalone to avoid cross-contamination of results between obstacles.
