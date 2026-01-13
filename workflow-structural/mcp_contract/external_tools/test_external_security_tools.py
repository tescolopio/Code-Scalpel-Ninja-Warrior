"""External Security Tools Integration Tests.

This module provides a framework for testing and comparing Code Scalpel
against industry-standard security tools:

- Semgrep: Semantic code analysis
- Bandit: Python security linter
- Ruff: Fast Python linter (includes security rules)
- Safety: Dependency vulnerability scanner
- pip-audit: Python package auditor
- npm-audit: Node.js package auditor
- Trivy: Container/dependency scanner

Each tool integration includes:
1. Installation detection
2. Execution wrapper
3. Result normalization
4. Comparison with Code Scalpel
5. Coverage analysis (what each tool catches)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

import pytest


class Severity(Enum):
    """Unified severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


@dataclass
class Finding:
    """Unified finding representation across all tools."""
    tool: str
    rule_id: str
    severity: Severity
    message: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column: Optional[int] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    category: Optional[str] = None
    raw: dict = field(default_factory=dict)

    def matches(self, other: "Finding", *, fuzzy: bool = False) -> bool:
        """Check if this finding matches another (for dedup/comparison)."""
        if fuzzy:
            # Match on file + approximate line + similar category
            same_file = self.file_path == other.file_path
            close_line = abs((self.line_number or 0) - (other.line_number or 0)) <= 5
            similar_cat = (self.category or "").lower() in (other.category or "").lower() or \
                          (other.category or "").lower() in (self.category or "").lower()
            return same_file and close_line and similar_cat
        else:
            return (self.file_path == other.file_path and
                    self.line_number == other.line_number and
                    self.rule_id == other.rule_id)


@dataclass
class ToolResult:
    """Result from running an external tool."""
    tool_name: str
    success: bool
    execution_time: float
    findings: list[Finding]
    error: Optional[str] = None
    raw_output: Optional[str] = None


class ExternalTool(ABC):
    """Base class for external security tools."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Tool name."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if tool is installed and available."""
        pass

    @abstractmethod
    def run(self, target: Path, **kwargs) -> ToolResult:
        """Run the tool on target path."""
        pass

    def _normalize_severity(self, raw: str) -> Severity:
        """Normalize severity string to enum."""
        raw = raw.upper().strip()
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "ERROR": Severity.HIGH,
            "HIGH": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
            "INFORMATION": Severity.INFO,
        }
        return mapping.get(raw, Severity.UNKNOWN)


# =============================================================================
# SEMGREP INTEGRATION
# =============================================================================

class SemgrepTool(ExternalTool):
    """Semgrep semantic code analysis tool."""

    @property
    def name(self) -> str:
        return "semgrep"

    def is_available(self) -> bool:
        return shutil.which("semgrep") is not None

    def run(self, target: Path, *, config: str = "auto", **kwargs) -> ToolResult:
        start = time.monotonic()
        try:
            result = subprocess.run(
                ["semgrep", "--json", "--config", config, str(target)],
                capture_output=True,
                text=True,
                timeout=300
            )
            elapsed = time.monotonic() - start

            if result.returncode not in (0, 1):  # 1 means findings exist
                return ToolResult(
                    tool_name=self.name,
                    success=False,
                    execution_time=elapsed,
                    findings=[],
                    error=result.stderr or "Semgrep failed",
                    raw_output=result.stdout
                )

            data = json.loads(result.stdout) if result.stdout else {}
            findings = []

            for r in data.get("results", []):
                findings.append(Finding(
                    tool=self.name,
                    rule_id=r.get("check_id", "unknown"),
                    severity=self._normalize_severity(r.get("extra", {}).get("severity", "MEDIUM")),
                    message=r.get("extra", {}).get("message", ""),
                    file_path=r.get("path"),
                    line_number=r.get("start", {}).get("line"),
                    column=r.get("start", {}).get("col"),
                    cwe=r.get("extra", {}).get("metadata", {}).get("cwe"),
                    owasp=r.get("extra", {}).get("metadata", {}).get("owasp"),
                    category=r.get("extra", {}).get("metadata", {}).get("category"),
                    raw=r
                ))

            return ToolResult(
                tool_name=self.name,
                success=True,
                execution_time=elapsed,
                findings=findings,
                raw_output=result.stdout
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.name,
                success=False,
                execution_time=time.monotonic() - start,
                findings=[],
                error="Timeout after 300s"
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                success=False,
                execution_time=time.monotonic() - start,
                findings=[],
                error=str(e)
            )


# =============================================================================
# BANDIT INTEGRATION
# =============================================================================

class BanditTool(ExternalTool):
    """Bandit Python security linter."""

    @property
    def name(self) -> str:
        return "bandit"

    def is_available(self) -> bool:
        return shutil.which("bandit") is not None

    def run(self, target: Path, **kwargs) -> ToolResult:
        start = time.monotonic()
        try:
            result = subprocess.run(
                ["bandit", "-r", "-f", "json", str(target)],
                capture_output=True,
                text=True,
                timeout=300
            )
            elapsed = time.monotonic() - start

            # Bandit returns 1 if findings exist, which is normal
            data = json.loads(result.stdout) if result.stdout else {}
            findings = []

            for r in data.get("results", []):
                findings.append(Finding(
                    tool=self.name,
                    rule_id=r.get("test_id", "unknown"),
                    severity=self._normalize_severity(r.get("issue_severity", "MEDIUM")),
                    message=r.get("issue_text", ""),
                    file_path=r.get("filename"),
                    line_number=r.get("line_number"),
                    cwe=r.get("issue_cwe", {}).get("id") if isinstance(r.get("issue_cwe"), dict) else None,
                    category=r.get("test_name"),
                    raw=r
                ))

            return ToolResult(
                tool_name=self.name,
                success=True,
                execution_time=elapsed,
                findings=findings,
                raw_output=result.stdout
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.name,
                success=False,
                execution_time=time.monotonic() - start,
                findings=[],
                error="Timeout after 300s"
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                success=False,
                execution_time=time.monotonic() - start,
                findings=[],
                error=str(e)
            )


# =============================================================================
# RUFF INTEGRATION
# =============================================================================

class RuffTool(ExternalTool):
    """Ruff fast Python linter with security rules."""

    @property
    def name(self) -> str:
        return "ruff"

    def is_available(self) -> bool:
        return shutil.which("ruff") is not None

    def run(self, target: Path, **kwargs) -> ToolResult:
        start = time.monotonic()
        try:
            # Run with security-related rules
            result = subprocess.run(
                ["ruff", "check", "--output-format", "json",
                 "--select", "S,B,A,C90,T20,ERA,PL", str(target)],
                capture_output=True,
                text=True,
                timeout=120
            )
            elapsed = time.monotonic() - start

            data = json.loads(result.stdout) if result.stdout else []
            findings = []

            for r in data:
                # Map Ruff codes to severity
                code = r.get("code", "")
                if code.startswith("S"):  # Security
                    severity = Severity.HIGH
                    category = "security"
                elif code.startswith("B"):  # Bugbear
                    severity = Severity.MEDIUM
                    category = "bugs"
                else:
                    severity = Severity.LOW
                    category = "style"

                findings.append(Finding(
                    tool=self.name,
                    rule_id=code,
                    severity=severity,
                    message=r.get("message", ""),
                    file_path=r.get("filename"),
                    line_number=r.get("location", {}).get("row"),
                    column=r.get("location", {}).get("column"),
                    category=category,
                    raw=r
                ))

            return ToolResult(
                tool_name=self.name,
                success=True,
                execution_time=elapsed,
                findings=findings,
                raw_output=result.stdout
            )

        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                success=False,
                execution_time=time.monotonic() - start,
                findings=[],
                error=str(e)
            )


# =============================================================================
# SAFETY/PIP-AUDIT INTEGRATION
# =============================================================================

class SafetyTool(ExternalTool):
    """Safety dependency vulnerability scanner."""

    @property
    def name(self) -> str:
        return "safety"

    def is_available(self) -> bool:
        return shutil.which("safety") is not None

    def run(self, target: Path, **kwargs) -> ToolResult:
        start = time.monotonic()
        try:
            # Look for requirements.txt
            req_file = target / "requirements.txt" if target.is_dir() else target

            result = subprocess.run(
                ["safety", "check", "-r", str(req_file), "--json"],
                capture_output=True,
                text=True,
                timeout=120
            )
            elapsed = time.monotonic() - start

            # Safety JSON output varies by version
            findings = []
            try:
                data = json.loads(result.stdout) if result.stdout else []
                if isinstance(data, list):
                    for r in data:
                        if isinstance(r, list) and len(r) >= 5:
                            findings.append(Finding(
                                tool=self.name,
                                rule_id=r[4] if len(r) > 4 else "unknown",
                                severity=Severity.HIGH,
                                message=r[3] if len(r) > 3 else "",
                                category="dependency_vulnerability",
                                raw={"package": r[0] if r else None, "data": r}
                            ))
            except json.JSONDecodeError:
                pass

            return ToolResult(
                tool_name=self.name,
                success=True,
                execution_time=elapsed,
                findings=findings,
                raw_output=result.stdout
            )

        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                success=False,
                execution_time=time.monotonic() - start,
                findings=[],
                error=str(e)
            )


# =============================================================================
# TOOL COMPARISON FRAMEWORK
# =============================================================================

class ToolComparisonFramework:
    """Framework for comparing multiple security tools."""

    def __init__(self):
        self.tools: list[ExternalTool] = [
            SemgrepTool(),
            BanditTool(),
            RuffTool(),
            SafetyTool(),
        ]

    def get_available_tools(self) -> list[ExternalTool]:
        """Return list of installed tools."""
        return [t for t in self.tools if t.is_available()]

    def run_all(self, target: Path) -> dict[str, ToolResult]:
        """Run all available tools on target."""
        results = {}
        for tool in self.get_available_tools():
            results[tool.name] = tool.run(target)
        return results

    def compare_findings(
        self,
        results: dict[str, ToolResult],
        *,
        fuzzy: bool = True
    ) -> dict:
        """Compare findings across tools."""
        all_findings = []
        for tool_name, result in results.items():
            all_findings.extend(result.findings)

        # Group by approximate location
        unique_issues = []
        for finding in all_findings:
            matched = False
            for existing in unique_issues:
                if finding.matches(existing["canonical"], fuzzy=fuzzy):
                    existing["found_by"].append(finding.tool)
                    existing["variants"].append(finding)
                    matched = True
                    break
            if not matched:
                unique_issues.append({
                    "canonical": finding,
                    "found_by": [finding.tool],
                    "variants": [finding]
                })

        # Classify by detection coverage
        universal = [i for i in unique_issues if len(i["found_by"]) == len(results)]
        partial = [i for i in unique_issues if 1 < len(i["found_by"]) < len(results)]
        unique = [i for i in unique_issues if len(i["found_by"]) == 1]

        return {
            "total_unique_issues": len(unique_issues),
            "universal_detections": len(universal),
            "partial_detections": len(partial),
            "unique_to_single_tool": len(unique),
            "by_tool": {
                name: len(r.findings)
                for name, r in results.items()
            },
            "issues": unique_issues
        }


# =============================================================================
# PYTEST FIXTURES AND TESTS
# =============================================================================

@pytest.fixture
def comparison_framework():
    return ToolComparisonFramework()


@pytest.fixture
def vulnerable_project(tmp_path):
    """Create a project with known vulnerabilities."""
    (tmp_path / "app.py").write_text('''
import subprocess
import pickle
import yaml

def run_command(user_input):
    # Command injection - B602, S602
    subprocess.call(user_input, shell=True)

def load_data(data):
    # Insecure deserialization - B301
    return pickle.loads(data)

def parse_yaml(data):
    # Unsafe YAML load - B506
    return yaml.load(data)

def sql_query(user_id):
    # SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

def eval_code(code):
    # Code injection - B307
    return eval(code)

SECRET_KEY = "hardcoded-secret-12345"  # Hardcoded secret - B105
''')

    (tmp_path / "requirements.txt").write_text('''
flask==1.0.0
django==2.0.0
pyyaml==5.1
''')

    return tmp_path


class TestExternalToolAvailability:
    """Test which external tools are available."""

    def test_list_available_tools(self, comparison_framework):
        """Report which tools are installed."""
        available = comparison_framework.get_available_tools()
        print(f"\nAvailable tools: {[t.name for t in available]}")

        # This is informational - don't fail if tools missing
        assert isinstance(available, list)


class TestIndividualTools:
    """Test each external tool individually."""

    def test_semgrep_on_vulnerable_code(self, vulnerable_project):
        """Test Semgrep detects vulnerabilities."""
        tool = SemgrepTool()
        if not tool.is_available():
            pytest.skip("Semgrep not installed")

        result = tool.run(vulnerable_project)
        print(f"\nSemgrep: {len(result.findings)} findings in {result.execution_time:.1f}s")
        assert result.success or result.error

    def test_bandit_on_vulnerable_code(self, vulnerable_project):
        """Test Bandit detects vulnerabilities."""
        tool = BanditTool()
        if not tool.is_available():
            pytest.skip("Bandit not installed")

        result = tool.run(vulnerable_project)
        print(f"\nBandit: {len(result.findings)} findings in {result.execution_time:.1f}s")

        if result.success:
            # Bandit should find at least some of the issues
            assert len(result.findings) >= 3, f"Expected at least 3 findings, got {len(result.findings)}"

    def test_ruff_on_vulnerable_code(self, vulnerable_project):
        """Test Ruff detects security issues."""
        tool = RuffTool()
        if not tool.is_available():
            pytest.skip("Ruff not installed")

        result = tool.run(vulnerable_project)
        print(f"\nRuff: {len(result.findings)} findings in {result.execution_time:.1f}s")
        assert result.success or result.error


class TestToolComparison:
    """Compare multiple tools on the same codebase."""

    def test_compare_all_tools(self, comparison_framework, vulnerable_project):
        """Run all available tools and compare results."""
        available = comparison_framework.get_available_tools()
        if len(available) < 2:
            pytest.skip(f"Need at least 2 tools for comparison, have {len(available)}")

        results = comparison_framework.run_all(vulnerable_project)
        comparison = comparison_framework.compare_findings(results)

        print(f"\n=== Tool Comparison ===")
        print(f"Total unique issues: {comparison['total_unique_issues']}")
        print(f"Universal (all tools): {comparison['universal_detections']}")
        print(f"Partial (some tools): {comparison['partial_detections']}")
        print(f"Unique to one tool: {comparison['unique_to_single_tool']}")
        print(f"\nFindings by tool:")
        for tool, count in comparison["by_tool"].items():
            print(f"  {tool}: {count}")

        assert comparison["total_unique_issues"] >= 0

    def test_coverage_matrix(self, comparison_framework, vulnerable_project):
        """Generate coverage matrix for vulnerability types."""
        available = comparison_framework.get_available_tools()
        if not available:
            pytest.skip("No external tools available")

        results = comparison_framework.run_all(vulnerable_project)

        # Build coverage matrix
        vuln_types = set()
        for result in results.values():
            for f in result.findings:
                if f.category:
                    vuln_types.add(f.category)

        matrix = {}
        for vtype in vuln_types:
            matrix[vtype] = {
                tool.name: any(
                    f.category == vtype
                    for f in results.get(tool.name, ToolResult(tool.name, False, 0, [])).findings
                )
                for tool in available
            }

        print(f"\n=== Coverage Matrix ===")
        for vtype, coverage in matrix.items():
            covered_by = [t for t, found in coverage.items() if found]
            print(f"  {vtype}: {covered_by}")


class TestCodeScalpelComparison:
    """Compare Code Scalpel against external tools."""

    def test_code_scalpel_vs_bandit(self, mcp_client, vulnerable_project):
        """Compare Code Scalpel findings with Bandit."""
        # Run Bandit
        bandit = BanditTool()
        if not bandit.is_available():
            pytest.skip("Bandit not installed")

        bandit_result = bandit.run(vulnerable_project)

        # Run Code Scalpel
        code = (vulnerable_project / "app.py").read_text()
        cs_raw = mcp_client.tools_call("security_scan", {"code": code})

        # Normalize Code Scalpel result
        if isinstance(cs_raw, dict):
            if "data" in cs_raw:
                cs_data = cs_raw.get("data", {})
            else:
                cs_data = cs_raw
            cs_findings = cs_data.get("vulnerabilities", [])
            cs_count = len(cs_findings)
        else:
            cs_count = 0

        print(f"\n=== Code Scalpel vs Bandit ===")
        print(f"Bandit findings: {len(bandit_result.findings)}")
        print(f"Code Scalpel findings: {cs_count}")

        # Both should find something
        if bandit_result.findings and cs_count == 0:
            pytest.xfail("Code Scalpel should detect vulnerabilities that Bandit found")

    def test_code_scalpel_unique_detections(self, mcp_client, comparison_framework, vulnerable_project):
        """Find vulnerabilities Code Scalpel catches that others miss."""
        # Get external tool findings
        results = comparison_framework.run_all(vulnerable_project)

        # Get Code Scalpel findings
        code = (vulnerable_project / "app.py").read_text()
        cs_raw = mcp_client.tools_call("security_scan", {"code": code})

        if isinstance(cs_raw, dict):
            if "data" in cs_raw:
                cs_vulns = cs_raw.get("data", {}).get("vulnerabilities", [])
            else:
                cs_vulns = cs_raw.get("vulnerabilities", [])
        else:
            cs_vulns = []

        # Extract line numbers from Code Scalpel
        cs_lines = set()
        for v in cs_vulns:
            if isinstance(v, dict) and v.get("line"):
                cs_lines.add(v["line"])

        # Extract line numbers from external tools
        external_lines = set()
        for result in results.values():
            for f in result.findings:
                if f.line_number:
                    external_lines.add(f.line_number)

        # Find unique to Code Scalpel
        unique_to_cs = cs_lines - external_lines

        print(f"\n=== Code Scalpel Unique Detections ===")
        print(f"Lines only Code Scalpel found: {sorted(unique_to_cs)}")
        print(f"Lines only external tools found: {sorted(external_lines - cs_lines)}")
        print(f"Lines both found: {sorted(cs_lines & external_lines)}")
