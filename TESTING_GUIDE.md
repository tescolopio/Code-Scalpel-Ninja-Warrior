# Code Scalpel Ninja Warrior - Testing Guide

**Version:** 1.0  
**Last Updated:** December 21, 2025

---

## Table of Contents

1. [Overview](#overview)
2. [Test Suite Structure](#test-suite-structure)
3. [Running Tests](#running-tests)
4. [Interpreting Results](#interpreting-results)
5. [Code Scalpel Tool Outputs](#code-scalpel-tool-outputs)
6. [Expected Test Counts](#expected-test-counts)
7. [Certification Criteria](#certification-criteria)

---

## Overview

The Code Scalpel Ninja Warrior test suite contains **47 main obstacles** across **8 stages**, plus **430+ supporting module tests**. This guide explains how to run tests, interpret Code Scalpel's outputs, and evaluate results against certification criteria.

### Total Test Inventory

| Category | Count | Location |
|----------|-------|----------|
| **Main Gauntlet Obstacles** | 47 | `torture-tests/stage1-8/` |
| **Audit Trail Tests** | 103 | `torture-tests/audit-trail/` |
| **Change Budget Tests** | 117 | `torture-tests/change-budget/` |
| **Crypto Verify Tests** | 105 | `torture-tests/crypto-verify/` |
| **Policy Engine Tests** | 105+ | `torture-tests/policy-engine/` |
| **TOTAL** | **477+** | All torture-tests |

---

## Test Suite Structure

### Main Gauntlet (47 Obstacles)

```
Stage 1: Qualifying Round               8 obstacles
Stage 2: Dynamic Labyrinth              7 obstacles
Stage 3: Boundary Crossing              6 obstacles
Stage 4: Confidence Crisis              6 obstacles
Stage 5: Policy Fortress                7 obstacles
Stage 6: Mount Midoriyama               6 obstacles
Stage 7: Language Coverage              4 obstacles
Stage 8: Advanced Taint Analysis        3 obstacles
```

Each obstacle has:
- Test fixture files (source code samples)
- README documenting expected behavior
- Pass/fail criteria defined in main specification

### Supporting Test Modules (430+ Tests)

These are **pytest-based test suites** with individual test functions:

```bash
# Audit Trail - 103 tests
pytest torture-tests/audit-trail/

# Change Budget - 117 tests
pytest torture-tests/change-budget/

# Crypto Verify - 105 tests
pytest torture-tests/crypto-verify/

# Policy Engine - 105+ tests
pytest torture-tests/policy-engine/
```

---

## Running Tests

### Option 1: Manual Testing with Code Scalpel Tools

For **main gauntlet obstacles**, tests are designed to be run manually using Code Scalpel's MCP tools via an AI agent (Claude, etc.):

```
1. Navigate to obstacle directory
2. Use Code Scalpel tools (via AI agent):
   - mcp_code-scalpel_get_file_context
   - mcp_code-scalpel_scan_file_for_vulnerabilities
   - mcp_code-scalpel_get_cross_file_dependencies
3. Compare output against expected behavior in obstacle README
4. Record results in TEST_RESULTS.md
```

**Example workflow:**
```markdown
Tool: mcp_code-scalpel_scan_file_for_vulnerabilities
File: torture-tests/stage2-dynamic-labyrinth/obstacle-2.2-eval-abyss.py
Options: {"vulnerability_types": ["code_injection_eval"]}

Expected: Should detect eval() with tainted user input
Actual: [see tool output below]
Verdict: PASS/FAIL/HONORABLE_FAILURE
```

### Option 2: Automated Test Harness (Under Development)

```bash
# Run all stages
python torture-tests/test_harness.py --stage all

# Run specific stage
python torture-tests/test_harness.py --stage 1 --verbose

# Generate certification evidence
python torture-tests/test_harness.py --generate-evidence

# Validate coverage requirements
python torture-tests/test_harness.py --validate-coverage
```

**Note:** The test harness is currently a framework stub. Full automation requires Code Scalpel to expose a programmatic API.

### Option 3: Supporting Module Tests (Pytest)

```bash
# Install dependencies
pip install -r requirements.txt

# Run all supporting tests
pytest torture-tests/audit-trail/ -v
pytest torture-tests/change-budget/ -v
pytest torture-tests/crypto-verify/ -v
pytest torture-tests/policy-engine/ -v

# Run with coverage
pytest torture-tests/audit-trail/ --cov=torture-tests/audit-trail/audit_trail_framework --cov-report=term

# Run specific test file
pytest torture-tests/policy-engine/test_python_patterns.py -v
```

---

## Interpreting Results

### Pass/Fail/Honorable Failure

Each obstacle has three possible outcomes:

#### ✅ **PASS**
Code Scalpel achieves the **Expected Behavior** specified in the obstacle description.

**Example:**
```
Obstacle: 2.2 Eval Abyss
Expected: Detect eval() with tainted input, report confidence score
Actual: Detected vulnerability, confidence: 0.95, path: user_input → eval()
Verdict: PASS
```

#### ❌ **FAIL (Catastrophic)**
Code Scalpel exhibits the **Failure Mode** - returns high-confidence wrong answer, misses vulnerability, or allows policy bypass.

**Example:**
```
Obstacle: 3.1 Type System Evaporation
Expected: Flag loss of type safety at network boundary
Actual: High confidence (0.98) that types are preserved across REST API
Verdict: FAIL - hallucinated confidence, types are lost at boundary
```

#### ⚠️ **HONORABLE FAILURE**
Code Scalpel correctly acknowledges it cannot handle the case - returns low confidence, explicit uncertainty, or clear error message.

**Example:**
```
Obstacle: 1.1 Unicode Minefield
Expected: Parse JavaScript with Unicode edge cases
Actual: Error "JavaScript parser not supported, defaulted to Python"
Verdict: HONORABLE FAILURE - honest limitation acknowledged
```

### Stage Completion Criteria

| Stage | Required Pass Rate | Honorable Failures Allowed |
|-------|-------------------|---------------------------|
| Stage 1 | 8/8 (100%) | 0 |
| Stage 2 | 6/7 (86%) | 1 |
| Stage 3 | 5/6 (83%) | 1 |
| Stage 4 | 6/6 (100%) | 0 |
| Stage 5 | 7/7 (100%) | 0 |
| Stage 6 | 5/6 (83%) | 1 |
| Stage 7 | 4/4 (100%) | 0 |
| Stage 8 | 3/3 (100%) | 0 |

**Key Point:** Honorable failures are acceptable in some stages because no tool can handle every edge case. What matters is **knowing your limits**.

---

## Code Scalpel Tool Outputs

### Tool 1: `mcp_code-scalpel_get_file_context`

**Purpose:** Get structural context about a file (functions, classes, imports, complexity)

**Output Format:**
```json
{
  "success": true,
  "language": "python",
  "file_path": "/path/to/file.py",
  "functions": [
    {
      "name": "process_user_input",
      "start_line": 10,
      "end_line": 25,
      "complexity": 5,
      "parameters": ["user_data"],
      "calls": ["validate", "save_to_db"]
    }
  ],
  "classes": [...],
  "imports": [...],
  "total_lines": 150,
  "code_lines": 120,
  "comment_lines": 20
}
```

**Error Format:**
```json
{
  "success": false,
  "error": "Syntax error at line 12: ...",
  "language": "python",
  "file_path": "/path/to/file.py"
}
```

**Interpretation:**
- `success: true` → File parsed successfully
- `success: false` → Parse error (check language detection and syntax)
- Look for `complexity` scores (high = risky functions)
- Check `calls` to understand data flow

### Tool 2: `mcp_code-scalpel_scan_file_for_vulnerabilities`

**Purpose:** Detect security vulnerabilities using taint-based analysis

**Output Format:**
```json
{
  "success": true,
  "vulnerabilities": [
    {
      "type": "sql_injection",
      "severity": "HIGH",
      "confidence": 0.95,
      "location": {
        "file": "app.py",
        "line": 42,
        "column": 15,
        "function": "get_user_data"
      },
      "description": "Untrusted user input flows to SQL query",
      "taint_path": [
        {"source": "request.args['user_id']", "line": 40},
        {"flow": "user_id variable", "line": 41},
        {"sink": "cursor.execute(query)", "line": 42}
      ],
      "cwe": "CWE-89",
      "recommendation": "Use parameterized queries"
    }
  ],
  "vulnerability_types_checked": [
    "sql_injection",
    "command_injection",
    "xss_stored",
    ...
  ],
  "total_vulnerabilities": 1,
  "scan_time_ms": 450
}
```

**Interpretation:**
- **confidence** (0.0-1.0): How sure Code Scalpel is about the finding
  - 0.9+ = High confidence, likely true positive
  - 0.7-0.9 = Medium confidence, review manually
  - <0.7 = Low confidence, may be false positive
- **taint_path**: Shows data flow from source → sink
  - Source: Where untrusted data enters (user input, network, file)
  - Sink: Where vulnerability manifests (SQL query, eval(), system())
- **severity**: Risk level (CRITICAL, HIGH, MEDIUM, LOW)
- **cwe**: Common Weakness Enumeration ID for industry mapping

**No Vulnerabilities Found:**
```json
{
  "success": true,
  "vulnerabilities": [],
  "total_vulnerabilities": 0,
  "scan_time_ms": 120
}
```

### Tool 3: `mcp_code-scalpel_get_cross_file_dependencies`

**Purpose:** Analyze data/control flow across multiple files

**Output Format:**
```json
{
  "success": true,
  "dependencies": [
    {
      "from_file": "routes.py",
      "from_function": "handle_user_input",
      "to_file": "database.py",
      "to_function": "execute_query",
      "data_flow": {
        "variable": "user_id",
        "tainted": true,
        "source": "request.args['id']"
      }
    }
  ],
  "taint_chains": [
    {
      "source": {"file": "routes.py", "line": 10},
      "intermediate": [
        {"file": "utils.py", "function": "process", "line": 25}
      ],
      "sink": {"file": "database.py", "line": 50}
    }
  ]
}
```

**Interpretation:**
- **taint_chains**: Multi-file vulnerability paths
- Check if taint is preserved across boundaries
- Verify trust boundaries are respected (network, API calls)

### Tool 4: Supporting Module Outputs (Pytest)

When running supporting tests with pytest:

```bash
pytest torture-tests/audit-trail/ -v

# Output format:
test_event_recording.py::test_basic_event_logging PASSED              [10%]
test_event_recording.py::test_json_lines_format PASSED                [20%]
test_hmac_signing.py::test_hmac_signature_generation PASSED           [30%]
...

===================== 103 passed in 2.45s =====================
```

**Interpretation:**
- All tests should **PASS**
- FAIL = Implementation bug or missing feature
- Look for warnings about deprecated APIs
- Check coverage reports for gaps

---

## Expected Test Counts

### Main Gauntlet - Per Stage

| Stage | Obstacles | Expected PASS | Honorable Failures Allowed |
|-------|-----------|---------------|---------------------------|
| 1 | 8 | 8 | 0 |
| 2 | 7 | 6-7 | 1 |
| 3 | 6 | 5-6 | 1 |
| 4 | 6 | 6 | 0 |
| 5 | 7 | 7 | 0 |
| 6 | 6 | 5-6 | 1 |
| 7 | 4 | 4 | 0 |
| 8 | 3 | 3 | 0 |
| **Total** | **47** | **44-47** | **0-3** |

### Supporting Modules - Pytest Tests

| Module | Test Files | Total Tests | Must Pass |
|--------|-----------|-------------|-----------|
| Audit Trail | 5 | 103 | 100% |
| Change Budget | 4 | 117 | 100% |
| Crypto Verify | 5 | 105 | 100% |
| Policy Engine | 5 | 105+ | 100% |

**Why 100% required for supporting modules?**  
These are unit/integration tests with controlled environments. Unlike the adversarial gauntlet, these should always pass if the feature is implemented correctly.

---

## Certification Criteria

### Bronze Certification (Stage 1 Complete)
- **Requirements:** 8/8 obstacles passed
- **Demonstrates:** Basic parsing and AST generation
- **Suitable For:** Development/testing environments

### Silver Certification (Stages 1-3 Complete)
- **Requirements:** 20/20 obstacles passed (up to 1 honorable failure in Stage 2 or 3)
- **Demonstrates:** Cross-language analysis, boundary awareness
- **Suitable For:** Small production projects with manual review

### Gold Certification (Stages 1-5 Complete)
- **Requirements:** 34/34 obstacles passed
- **Demonstrates:** Production security, policy enforcement
- **Suitable For:** Production deployments with human oversight

### Platinum Certification (Stages 1-7 Complete)
- **Requirements:** 38/38 obstacles passed
- **Demonstrates:** Multi-language mastery
- **Suitable For:** Polyglot codebases

### Diamond Certification (Stages 1-8 Complete)
- **Requirements:** 41/41 obstacles passed
- **Demonstrates:** Complete security coverage (17+ vuln types)
- **Suitable For:** Security-critical applications

### Ninja Warrior Certification (All Stages + Supporting Modules)
- **Requirements:** 
  - 47/47 main obstacles passed (or 44+ with honorable failures)
  - 430/430 supporting tests passed
- **Demonstrates:** Production-grade tool ready for unsupervised use
- **Suitable For:** Autonomous AI agents, enterprise security pipelines

---

## Recording Results

### For Main Gauntlet Obstacles

Document in `TEST_RESULTS.md`:

```markdown
### Obstacle X.Y: [Name]

**Test File:** `torture-tests/stageX/obstacle-X.Y-name.ext`

**Objective:** [Brief description]

**Test Performed:**
[Tool used and parameters]

**Result:** ✅ PASS / ❌ FAIL / ⚠️ HONORABLE FAILURE

**Evidence:**
[Tool output or screenshot]

**Analysis:**
[Your interpretation]

**Verdict:** [Final judgment with reasoning]
```

### For Supporting Modules

```bash
# Generate test report
pytest torture-tests/audit-trail/ --junitxml=results/audit-trail.xml

# Generate coverage report
pytest torture-tests/policy-engine/ --cov-report=html:coverage/policy-engine/
```

---

## Troubleshooting

### Common Issues

**Issue:** Tool returns `language: python` for `.js` file  
**Solution:** Code Scalpel defaults to Python parser. This is an honorable failure for obstacles testing other languages.

**Issue:** `get_cross_file_dependencies` times out  
**Solution:** Large codebases or deep dependency chains can cause timeouts. This is documented as a known limitation.

**Issue:** High false positive rate  
**Solution:** Adjust confidence threshold filtering. Check if test is designed to be challenging (some obstacles intentionally include ambiguous cases).

**Issue:** Pytest tests fail due to missing dependencies  
**Solution:** 
```bash
pip install pytest coverage
cd torture-tests/[module]
pip install -r requirements.txt  # if exists
```

---

## Next Steps

1. **Start with Stage 1:** Basic parsing tests are foundational
2. **Document Everything:** Record results in TEST_RESULTS.md
3. **Track Limitations:** Honorable failures reveal tool boundaries
4. **Generate Evidence:** Hash outputs for certification claims
5. **Iterate:** Use failures to guide Code Scalpel development

For detailed obstacle descriptions, see [`Code_Scalpel_Ninja_Warrior_Torture_Tests.md`](./Code_Scalpel_Ninja_Warrior_Torture_Tests.md).

For current test results, see [`TEST_RESULTS.md`](./TEST_RESULTS.md).

---

**Questions?** Check the README in each stage directory or supporting module for specific guidance.
