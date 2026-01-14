"""External Security Tools Integration.

This package provides integration with external security analysis tools
for comparison testing against Code Scalpel MCP tools.

Supported Tools:
- Semgrep: Semantic code analysis
- Bandit: Python security linter
- Ruff: Fast Python linter with security rules
- Safety: Dependency vulnerability scanner
- pip-audit: Python package auditor

Usage:
    from external_tools.test_external_security_tools import (
        ToolComparisonFramework,
        SemgrepTool,
        BanditTool,
        RuffTool,
    )

    framework = ToolComparisonFramework()
    results = framework.run_all(project_path)
    comparison = framework.compare_findings(results)
"""

from pathlib import Path

EXTERNAL_TOOLS_DIR = Path(__file__).parent
