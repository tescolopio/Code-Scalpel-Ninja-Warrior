# Stage 1 – The Qualifying Round (Parser & AST Fundamentals)

This directory contains self-contained torture tests for the first stage of the **Code Scalpel Ninja Warrior** suite. Each file exercises one of the eight Qualifying Round obstacles so parsers and AST builders can be validated without needing the rest of the monorepo.

| Obstacle | File | Focus |
| --- | --- | --- |
| 1.1 Unicode Minefield | `01-unicode-minefield.js` | Homoglyph identifiers, zero-width characters, bidi text |
| 1.2 Syntax Torture Chamber | `02-syntax-torture-chamber.js` | Deep nesting, long lines, ternary/precedence stress |
| 1.3 Polyglot Parser | `03-polyglot-parser.js` | Extension/content mismatch (TypeScript in .js) |
| 1.4 Incomplete Code Challenge | `04-incomplete-code-challenge.js` | Missing delimiters and mid-edit fragments |
| 1.5 Comment Trap | `05-comment-trap.js` | Commented-out logic, code-like strings, nested comments |
| 1.6 Encoding Maze | `06-encoding-maze-utf8-bom.py` | UTF-8 BOM handling and hidden whitespace |
| 1.7 Macro Minefield | `07-macro-minefield.c` | Preprocessor-generated functions and keyword tricks |
| 1.8 Version Variance | `08-version-variance.py` | Python 2 vs 3 semantics and syntax differences |

**How to use**

1. Point your parser/analysis step at this directory.
2. Verify that each file produces a valid AST or explicit, location-aware errors.
3. Record confidence/uncertainty as called out in the torture test specification.
