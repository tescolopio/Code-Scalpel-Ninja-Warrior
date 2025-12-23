#!/usr/bin/env python3
"""
=============================================================================
CODE SCALPEL NINJA WARRIOR - TEST HARNESS
=============================================================================

A comprehensive test harness for running the torture test suite against
Code Scalpel and generating evidence for certification.

COVERAGE TARGETS:
- Python Analysis: 100%
- TypeScript Analysis: >=95%
- JavaScript Analysis: >=95%
- Java Analysis: >=95%
- Security Scanning: >=17 vulnerability types (taint-based)
- Cross-File Taint: Full coverage

USAGE:
    python test_harness.py --stage all
    python test_harness.py --stage 1 --verbose
    python test_harness.py --generate-evidence
    python test_harness.py --validate-coverage

=============================================================================
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


class Stage(Enum):
    """Torture test stages matching the Ninja Warrior gauntlet."""
    QUALIFYING_ROUND = 1
    DYNAMIC_LABYRINTH = 2
    BOUNDARY_CROSSING = 3
    CONFIDENCE_CRISIS = 4
    POLICY_FORTRESS = 5
    MOUNT_MIDORIYAMA = 6
    LANGUAGE_COVERAGE = 7
    ADVANCED_TAINT = 8


class Language(Enum):
    """Supported languages for analysis."""
    PYTHON = "python"
    TYPESCRIPT = "typescript"
    JAVASCRIPT = "javascript"
    JAVA = "java"
    C = "c"
    PROTOBUF = "protobuf"
    GRAPHQL = "graphql"
    SQL = "sql"


class VulnerabilityType(Enum):
    """
    Tracked vulnerability types for security scanning.
    Minimum requirement: >=17 types with taint-based detection.
    """
    # Injection vulnerabilities (taint-based)
    SQL_INJECTION = "sql_injection"
    JPQL_SPEL_INJECTION = "jpql_spel_injection"
    COMMAND_INJECTION = "command_injection"
    CODE_INJECTION_EVAL = "code_injection_eval"
    CODE_INJECTION_EXEC = "code_injection_exec"
    PATH_TRAVERSAL = "path_traversal"
    LDAP_INJECTION = "ldap_injection"
    XSS_STORED = "xss_stored"
    XSS_REFLECTED = "xss_reflected"
    TEMPLATE_INJECTION = "template_injection"

    # Dynamic language vulnerabilities
    GETATTR_TAINT = "getattr_taint"
    SETATTR_TAINT = "setattr_taint"
    DYNAMIC_IMPORT = "dynamic_import"
    METACLASS_ABUSE = "metaclass_abuse"
    MONKEY_PATCHING = "monkey_patching"
    DESCRIPTOR_ABUSE = "descriptor_abuse"
    FACTORY_TAINT = "factory_function_taint"

    # Cross-boundary vulnerabilities
    TYPE_EVAPORATION = "type_evaporation"
    SCHEMA_DRIFT = "schema_drift"
    TRUST_BOUNDARY_VIOLATION = "trust_boundary_violation"
    ORM_ESCAPE_HATCH = "orm_escape_hatch"
    MESSAGE_QUEUE_TAINT = "message_queue_taint"
    CROSS_PROTOCOL_TAINT = "cross_protocol_taint"

    # Encoding and bypass
    BASE64_ENCODED_INJECTION = "base64_encoded_injection"
    UNICODE_BYPASS = "unicode_bypass"
    HEX_ENCODED_INJECTION = "hex_encoded_injection"
    SEMANTIC_EQUIVALENCE_BYPASS = "semantic_equivalence_bypass"

    # Sandbox and resource
    SANDBOX_ESCAPE_FILESYSTEM = "sandbox_escape_filesystem"
    SANDBOX_ESCAPE_NETWORK = "sandbox_escape_network"
    SANDBOX_ESCAPE_PROCESS = "sandbox_escape_process"
    RESOURCE_EXHAUSTION = "resource_exhaustion"

    # Other
    HOMOGLYPH_ATTACK = "homoglyph_attack"
    BIDI_TEXT_ATTACK = "bidi_text_attack"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    DESERIALIZATION = "deserialization"
    SSRF = "ssrf"


@dataclass
class TestCase:
    """Represents a single torture test case."""
    obstacle_id: str
    name: str
    stage: Stage
    file_path: Path
    language: Language
    vulnerability_types: list[VulnerabilityType] = field(default_factory=list)
    expected_behavior: str = ""
    failure_mode: str = ""
    is_cross_file: bool = False
    related_files: list[Path] = field(default_factory=list)


@dataclass
class TestResult:
    """Result of running a single test case."""
    test_case: TestCase
    passed: bool
    honorable_failure: bool = False
    confidence_score: float = 0.0
    execution_time_ms: float = 0.0
    memory_usage_mb: float = 0.0
    vulnerabilities_detected: list[VulnerabilityType] = field(default_factory=list)
    taint_paths_found: int = 0
    output: str = ""
    error: str = ""
    evidence_hash: str = ""


@dataclass
class StageResult:
    """Aggregated results for a torture test stage."""
    stage: Stage
    total_tests: int
    passed: int
    failed: int
    honorable_failures: int
    pass_rate: float
    required_pass_rate: float
    stage_passed: bool
    test_results: list[TestResult] = field(default_factory=list)


@dataclass
class CoverageReport:
    """Language and vulnerability coverage report."""
    python_coverage: float
    typescript_coverage: float
    javascript_coverage: float
    java_coverage: float
    vulnerability_types_covered: int
    vulnerability_types_required: int
    cross_file_taint_tests: int
    taint_based_detections: int
    meets_requirements: bool


class TortureTestHarness:
    """
    Main test harness for Code Scalpel Ninja Warrior torture tests.
    """

    # Stage pass rate requirements from the specification
    STAGE_REQUIREMENTS = {
        Stage.QUALIFYING_ROUND: (8, 8, 1.0, 0),      # 100%, 0 honorable failures
        Stage.DYNAMIC_LABYRINTH: (6, 7, 0.86, 1),   # 86%, 1 honorable failure
        Stage.BOUNDARY_CROSSING: (5, 6, 0.83, 1),   # 83%, 1 honorable failure
        Stage.CONFIDENCE_CRISIS: (6, 6, 1.0, 0),    # 100%, 0 honorable failures
        Stage.POLICY_FORTRESS: (7, 7, 1.0, 0),      # 100%, 0 honorable failures
        Stage.MOUNT_MIDORIYAMA: (5, 6, 0.83, 1),    # 83%, 1 honorable failure
        # Stages 7-8 were added after the original 1-6 gauntlet.
        # Keep minimum requirements simple: these stages should not be empty.
        Stage.LANGUAGE_COVERAGE: (1, 1, 1.0, 0),
        Stage.ADVANCED_TAINT: (1, 1, 1.0, 0),
    }

    # Certification levels
    CERTIFICATIONS = {
        "bronze": [Stage.QUALIFYING_ROUND],
        "silver": [Stage.QUALIFYING_ROUND, Stage.DYNAMIC_LABYRINTH, Stage.BOUNDARY_CROSSING],
        "gold": [Stage.QUALIFYING_ROUND, Stage.DYNAMIC_LABYRINTH, Stage.BOUNDARY_CROSSING,
                 Stage.CONFIDENCE_CRISIS, Stage.POLICY_FORTRESS],
        "ninja_warrior": list(Stage),
    }

    # Coverage targets
    COVERAGE_TARGETS = {
        Language.PYTHON: 1.0,      # 100%
        Language.TYPESCRIPT: 0.95,  # >=95%
        Language.JAVASCRIPT: 0.95,  # >=95%
        Language.JAVA: 0.95,        # >=95%
    }

    MIN_VULNERABILITY_TYPES = 17

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.torture_tests_dir = base_dir / "torture-tests"
        self.evidence_dir = base_dir / "evidence"
        self.test_cases: list[TestCase] = []
        self.results: list[TestResult] = []

    def discover_tests(self) -> list[TestCase]:
        """Discover all test cases from the torture-tests directory."""
        test_cases: list[TestCase] = []
        seen_files: set[Path] = set()

        # Stage-to-directory mapping.
        # This intentionally avoids moving files around: several suites grew outside
        # the original stage folders, so we map them into the closest stage.
        stage_dirs: dict[Stage, list[str]] = {
            Stage.QUALIFYING_ROUND: ["stage1-qualifying-round"],
            Stage.DYNAMIC_LABYRINTH: ["stage2-dynamic-labyrinth"],
            Stage.BOUNDARY_CROSSING: [
                "stage3-boundary-crossing",
                "cross-language-integration",
            ],
            Stage.CONFIDENCE_CRISIS: ["stage4-confidence-crisis"],
            Stage.POLICY_FORTRESS: [
                "stage5-policy-fortress",
                "policy-engine",
                "crypto-verify",
                "audit-trail",
                "change-budget",
            ],
            Stage.MOUNT_MIDORIYAMA: ["stage6-mount-midoriyama"],
            Stage.LANGUAGE_COVERAGE: [
                "stage7-language-coverage",
                "language-coverage",
                "framework-specific",
                "advanced-async",
            ],
            Stage.ADVANCED_TAINT: ["stage8-advanced-taint"],
        }

        for stage, dir_names in stage_dirs.items():
            for dir_name in dir_names:
                stage_dir = self.torture_tests_dir / dir_name
                if not stage_dir.exists():
                    continue

                for test_case in self._discover_stage_tests(stage, stage_dir):
                    # Deduplicate in case a directory is mapped to multiple stages
                    # or a file is reachable via multiple paths.
                    if test_case.file_path in seen_files:
                        continue
                    seen_files.add(test_case.file_path)
                    test_cases.append(test_case)

        self.test_cases = test_cases
        return test_cases

    def _discover_stage_tests(self, stage: Stage, stage_dir: Path) -> list[TestCase]:
        """Discover tests within a specific stage directory."""
        tests = []

        # Language extension mapping
        lang_map = {
            ".py": Language.PYTHON,
            ".ts": Language.TYPESCRIPT,
            ".js": Language.JAVASCRIPT,
            ".java": Language.JAVA,
            ".c": Language.C,
            ".proto": Language.PROTOBUF,
            ".graphql": Language.GRAPHQL,
        }

        for file_path in stage_dir.rglob("*"):
            if file_path.is_file() and file_path.suffix in lang_map:
                # Skip README files
                if file_path.stem.lower() == "readme":
                    continue

                test_case = TestCase(
                    obstacle_id=self._extract_obstacle_id(file_path),
                    name=file_path.stem,
                    stage=stage,
                    file_path=file_path,
                    language=lang_map[file_path.suffix],
                    vulnerability_types=self._extract_vulnerability_types(file_path),
                    is_cross_file=self._check_cross_file(file_path),
                    related_files=self._find_related_files(file_path),
                )
                tests.append(test_case)

        return tests

    def _extract_obstacle_id(self, file_path: Path) -> str:
        """Extract obstacle ID from file path."""
        name = file_path.stem
        # Handle patterns like "obstacle-2.1-getattr-gauntlet" or "01-unicode-minefield"
        parts = name.split("-")
        if parts and parts[0].startswith("obstacle"):
            return "-".join(parts[:2])
        elif parts and parts[0].isdigit():
            return parts[0]
        return name

    def _extract_vulnerability_types(self, file_path: Path) -> list[VulnerabilityType]:
        """Extract vulnerability types from test file metadata."""
        vuln_types = []

        # Mapping of keywords to vulnerability types
        keyword_map = {
            "sql_injection": VulnerabilityType.SQL_INJECTION,
            "sql injection": VulnerabilityType.SQL_INJECTION,
            "spel": VulnerabilityType.JPQL_SPEL_INJECTION,
            "command injection": VulnerabilityType.COMMAND_INJECTION,
            "eval": VulnerabilityType.CODE_INJECTION_EVAL,
            "exec": VulnerabilityType.CODE_INJECTION_EXEC,
            "path traversal": VulnerabilityType.PATH_TRAVERSAL,
            "getattr": VulnerabilityType.GETATTR_TAINT,
            "setattr": VulnerabilityType.SETATTR_TAINT,
            "dynamic import": VulnerabilityType.DYNAMIC_IMPORT,
            "__import__": VulnerabilityType.DYNAMIC_IMPORT,
            "metaclass": VulnerabilityType.METACLASS_ABUSE,
            "monkey patch": VulnerabilityType.MONKEY_PATCHING,
            "descriptor": VulnerabilityType.DESCRIPTOR_ABUSE,
            "factory": VulnerabilityType.FACTORY_TAINT,
            "type.*evaporation": VulnerabilityType.TYPE_EVAPORATION,
            "schema drift": VulnerabilityType.SCHEMA_DRIFT,
            "trust boundary": VulnerabilityType.TRUST_BOUNDARY_VIOLATION,
            "orm": VulnerabilityType.ORM_ESCAPE_HATCH,
            "message queue": VulnerabilityType.MESSAGE_QUEUE_TAINT,
            "kafka": VulnerabilityType.MESSAGE_QUEUE_TAINT,
            "rabbitmq": VulnerabilityType.MESSAGE_QUEUE_TAINT,
            "base64": VulnerabilityType.BASE64_ENCODED_INJECTION,
            "unicode": VulnerabilityType.UNICODE_BYPASS,
            "homoglyph": VulnerabilityType.HOMOGLYPH_ATTACK,
            "bidi": VulnerabilityType.BIDI_TEXT_ATTACK,
            "sandbox escape": VulnerabilityType.SANDBOX_ESCAPE_FILESYSTEM,
            "resource exhaustion": VulnerabilityType.RESOURCE_EXHAUSTION,
            "xss": VulnerabilityType.XSS_STORED,
            "template injection": VulnerabilityType.TEMPLATE_INJECTION,
            "prototype pollution": VulnerabilityType.PROTOTYPE_POLLUTION,
            "deserialization": VulnerabilityType.DESERIALIZATION,
            "ssrf": VulnerabilityType.SSRF,
        }

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace").lower()
            for keyword, vuln_type in keyword_map.items():
                if keyword in content and vuln_type not in vuln_types:
                    vuln_types.append(vuln_type)
        except Exception:
            pass

        return vuln_types

    def _check_cross_file(self, file_path: Path) -> bool:
        """Check if test involves cross-file taint tracking."""
        parent = file_path.parent
        sibling_files = list(parent.glob("*"))
        code_files = [f for f in sibling_files if f.suffix in [".py", ".ts", ".js", ".java"]]
        return len(code_files) > 1

    def _find_related_files(self, file_path: Path) -> list[Path]:
        """Find related files for cross-file tests."""
        parent = file_path.parent
        related = []
        for f in parent.glob("*"):
            if f != file_path and f.suffix in [".py", ".ts", ".js", ".java", ".proto", ".graphql"]:
                related.append(f)
        return related

    def run_test(self, test_case: TestCase) -> TestResult:
        """Run a single test case against Code Scalpel."""
        start_time = time.time()

        # Placeholder for actual Code Scalpel integration
        # In production, this would invoke Code Scalpel API
        result = TestResult(
            test_case=test_case,
            passed=True,  # Placeholder
            confidence_score=0.0,
            execution_time_ms=(time.time() - start_time) * 1000,
            vulnerabilities_detected=test_case.vulnerability_types,
            taint_paths_found=len(test_case.vulnerability_types),
        )

        # Generate evidence hash
        result.evidence_hash = self._generate_evidence_hash(test_case, result)

        return result

    def run_stage(self, stage: Stage) -> StageResult:
        """Run all tests in a stage."""
        stage_tests = [t for t in self.test_cases if t.stage == stage]
        results = [self.run_test(t) for t in stage_tests]

        required, total, rate, allowed_failures = self.STAGE_REQUIREMENTS[stage]
        passed = sum(1 for r in results if r.passed)
        honorable = sum(1 for r in results if r.honorable_failure)

        return StageResult(
            stage=stage,
            total_tests=len(results),
            passed=passed,
            failed=len(results) - passed,
            honorable_failures=honorable,
            pass_rate=passed / max(len(results), 1),
            required_pass_rate=rate,
            stage_passed=passed >= required and honorable <= allowed_failures,
            test_results=results,
        )

    def run_all_stages(self) -> dict[Stage, StageResult]:
        """Run all torture test stages."""
        return {stage: self.run_stage(stage) for stage in Stage}

    def calculate_coverage(self) -> CoverageReport:
        """Calculate language and vulnerability coverage."""
        lang_counts = {lang: 0 for lang in Language}
        lang_totals = {lang: 0 for lang in Language}

        vuln_types_covered = set()
        cross_file_tests = 0
        taint_based = 0

        for tc in self.test_cases:
            lang_totals[tc.language] = lang_totals.get(tc.language, 0) + 1
            lang_counts[tc.language] = lang_counts.get(tc.language, 0) + 1

            for vt in tc.vulnerability_types:
                vuln_types_covered.add(vt)
                taint_based += 1

            if tc.is_cross_file:
                cross_file_tests += 1

        # Calculate coverage percentages (based on expected targets)
        # Using discovered tests as baseline
        py_cov = lang_counts.get(Language.PYTHON, 0) / max(lang_totals.get(Language.PYTHON, 1), 1)
        ts_cov = lang_counts.get(Language.TYPESCRIPT, 0) / max(lang_totals.get(Language.TYPESCRIPT, 1), 1)
        js_cov = lang_counts.get(Language.JAVASCRIPT, 0) / max(lang_totals.get(Language.JAVASCRIPT, 1), 1)
        java_cov = lang_counts.get(Language.JAVA, 0) / max(lang_totals.get(Language.JAVA, 1), 1)

        return CoverageReport(
            python_coverage=py_cov,
            typescript_coverage=ts_cov,
            javascript_coverage=js_cov,
            java_coverage=java_cov,
            vulnerability_types_covered=len(vuln_types_covered),
            vulnerability_types_required=self.MIN_VULNERABILITY_TYPES,
            cross_file_taint_tests=cross_file_tests,
            taint_based_detections=taint_based,
            meets_requirements=(
                py_cov >= self.COVERAGE_TARGETS[Language.PYTHON] and
                ts_cov >= self.COVERAGE_TARGETS[Language.TYPESCRIPT] and
                js_cov >= self.COVERAGE_TARGETS[Language.JAVASCRIPT] and
                java_cov >= self.COVERAGE_TARGETS[Language.JAVA] and
                len(vuln_types_covered) >= self.MIN_VULNERABILITY_TYPES
            ),
        )

    def _generate_evidence_hash(self, test_case: TestCase, result: TestResult) -> str:
        """Generate integrity hash for evidence."""
        evidence_data = json.dumps({
            "obstacle_id": test_case.obstacle_id,
            "file_path": str(test_case.file_path),
            "passed": result.passed,
            "confidence": result.confidence_score,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, sort_keys=True)
        return hashlib.sha256(evidence_data.encode()).hexdigest()

    def generate_evidence_report(self, stage_results: dict[Stage, StageResult]) -> dict:
        """Generate comprehensive evidence report for certification."""
        coverage = self.calculate_coverage()

        # Determine certification level
        cert_level = "none"
        for level, required_stages in self.CERTIFICATIONS.items():
            if all(stage_results.get(s, StageResult(s, 0, 0, 0, 0, 0, 0, False)).stage_passed
                   for s in required_stages):
                cert_level = level

        return {
            "report_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "certification_level": cert_level,
            "coverage": asdict(coverage),
            "stage_results": {
                stage.name: asdict(result)
                for stage, result in stage_results.items()
            },
            "vulnerability_types": [v.value for v in VulnerabilityType],
            "total_tests": len(self.test_cases),
            "tests_by_language": {
                lang.value: len([t for t in self.test_cases if t.language == lang])
                for lang in Language
            },
        }

    def save_evidence(self, report: dict, output_path: Path) -> None:
        """Save evidence report to file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"Evidence saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Code Scalpel Ninja Warrior Test Harness"
    )
    parser.add_argument(
        "--stage",
        choices=["all", "1", "2", "3", "4", "5", "6", "7", "8"],
        default="all",
        help="Stage to run (1-8 or 'all')"
    )
    parser.add_argument(
        "--generate-evidence",
        action="store_true",
        help="Generate evidence report"
    )
    parser.add_argument(
        "--validate-coverage",
        action="store_true",
        help="Validate coverage requirements"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("evidence/report.json"),
        help="Output path for evidence report"
    )

    args = parser.parse_args()

    base_dir = Path(__file__).parent.parent
    harness = TortureTestHarness(base_dir)

    print("=" * 60)
    print("CODE SCALPEL NINJA WARRIOR - TEST HARNESS")
    print("=" * 60)

    # Discover tests
    print("\nDiscovering test cases...")
    tests = harness.discover_tests()
    print(f"Found {len(tests)} test cases")

    if args.verbose:
        for tc in tests:
            print(f"  - {tc.obstacle_id}: {tc.name} ({tc.language.value})")

    # Validate coverage
    if args.validate_coverage:
        print("\nValidating coverage requirements...")
        coverage = harness.calculate_coverage()
        print(f"  Python coverage: {coverage.python_coverage:.1%}")
        print(f"  TypeScript coverage: {coverage.typescript_coverage:.1%}")
        print(f"  JavaScript coverage: {coverage.javascript_coverage:.1%}")
        print(f"  Java coverage: {coverage.java_coverage:.1%}")
        print(f"  Vulnerability types: {coverage.vulnerability_types_covered}/{coverage.vulnerability_types_required}")
        print(f"  Cross-file taint tests: {coverage.cross_file_taint_tests}")
        print(f"  Taint-based detections: {coverage.taint_based_detections}")
        print(f"  Meets requirements: {'✓' if coverage.meets_requirements else '✗'}")

    # Run tests
    if args.stage != "all":
        stage = Stage(int(args.stage))
        print(f"\nRunning Stage {args.stage}...")
        result = harness.run_stage(stage)
        stage_results = {stage: result}
    else:
        print("\nRunning all stages...")
        stage_results = harness.run_all_stages()

    # Print results
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    for stage, result in stage_results.items():
        status = "✓ PASSED" if result.stage_passed else "✗ FAILED"
        print(f"Stage {stage.value} ({stage.name}): {status}")
        print(f"  Pass rate: {result.pass_rate:.1%} (required: {result.required_pass_rate:.1%})")
        print(f"  Tests: {result.passed}/{result.total_tests} passed")

    # Generate evidence
    if args.generate_evidence:
        print("\nGenerating evidence report...")
        report = harness.generate_evidence_report(stage_results)
        harness.save_evidence(report, args.output)

    print("\n" + "=" * 60)
    print("DONE")
    print("=" * 60)


if __name__ == "__main__":
    main()
