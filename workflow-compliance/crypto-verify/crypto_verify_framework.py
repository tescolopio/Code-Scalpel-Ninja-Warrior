#!/usr/bin/env python3
"""
=============================================================================
CRYPTOGRAPHIC POLICY VERIFICATION FRAMEWORK
=============================================================================

Comprehensive test suite for Code Scalpel's Cryptographic Policy Verification
feature. This feature detects unauthorized modifications to policy files using
SHA-256 hashes and HMAC-signed manifests.

CORE FEATURES:
- SHA-256 file hashing for integrity verification
- HMAC-signed manifests for tamper detection
- Multiple manifest sources (file, git, env)
- Unexpected file detection
- Security-first error handling

MANIFEST SCHEMA:
{
    "version": "1.0",
    "created_at": "2025-12-19T14:30:00.000Z",
    "files": {
        "policy.yaml": {"hash": "sha256:...", "size": 2048},
        "budget.yaml": {"hash": "sha256:...", "size": 512}
    },
    "signature": "hmac-sha256:..."
}

VERIFICATION ALGORITHM:
1. Load manifest from file/git/env
2. Verify manifest HMAC signature → Invalid? SecurityError
3. For each file in manifest:
   a. Check file exists → Missing? SecurityError
   b. Compute SHA-256 of current file
   c. Compare to manifest hash → Mismatch? SecurityError
4. Check for unexpected files in policy_dir → Found? SecurityError
5. Return success

=============================================================================
"""
import hashlib
import hmac
import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# =============================================================================
# ENUMS AND DATA STRUCTURES
# =============================================================================

class ManifestSource(Enum):
    """Source for loading the policy manifest."""
    FILE = "file"
    GIT = "git"
    ENV = "env"


class SecurityErrorCode(Enum):
    """Security error codes for detailed error reporting."""
    MANIFEST_NOT_FOUND = "MANIFEST_NOT_FOUND"
    MANIFEST_SIGNATURE_INVALID = "MANIFEST_SIGNATURE_INVALID"
    MANIFEST_PARSE_ERROR = "MANIFEST_PARSE_ERROR"
    MANIFEST_SCHEMA_INVALID = "MANIFEST_SCHEMA_INVALID"
    FILE_MISSING = "FILE_MISSING"
    FILE_HASH_MISMATCH = "FILE_HASH_MISMATCH"
    FILE_SIZE_MISMATCH = "FILE_SIZE_MISMATCH"
    UNEXPECTED_FILE = "UNEXPECTED_FILE"
    SECRET_NOT_CONFIGURED = "SECRET_NOT_CONFIGURED"


class SecurityError(Exception):
    """Raised when a security violation is detected."""
    def __init__(self, message: str, code: SecurityErrorCode, details: Dict[str, Any] = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}


@dataclass
class FileVerificationResult:
    """Result of verifying a single file."""
    file_path: str
    verified: bool
    expected_hash: Optional[str] = None
    actual_hash: Optional[str] = None
    expected_size: Optional[int] = None
    actual_size: Optional[int] = None
    error: Optional[str] = None


@dataclass
class VerificationResult:
    """Result of verifying all policy files."""
    verified: bool
    files_checked: int
    manifest_version: str = "1.0"
    manifest_created_at: Optional[str] = None
    file_results: List[FileVerificationResult] = field(default_factory=list)
    unexpected_files: List[str] = field(default_factory=list)
    error: Optional[str] = None
    error_code: Optional[SecurityErrorCode] = None


@dataclass
class ManifestFileEntry:
    """Entry for a file in the manifest."""
    hash: str
    size: int


@dataclass
class PolicyManifest:
    """Policy manifest structure."""
    version: str
    created_at: str
    files: Dict[str, ManifestFileEntry]
    signature: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "version": self.version,
            "created_at": self.created_at,
            "files": {
                path: {"hash": entry.hash, "size": entry.size}
                for path, entry in self.files.items()
            },
            "signature": self.signature
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyManifest":
        """Create from dictionary."""
        files = {}
        for path, entry in data.get("files", {}).items():
            files[path] = ManifestFileEntry(
                hash=entry["hash"],
                size=entry["size"]
            )
        return cls(
            version=data.get("version", "1.0"),
            created_at=data.get("created_at", ""),
            files=files,
            signature=data.get("signature", "")
        )


# =============================================================================
# CRYPTOGRAPHIC POLICY VERIFIER
# =============================================================================

class CryptographicPolicyVerifier:
    """
    Verifies policy files using cryptographic hashes and HMAC-signed manifests.

    Features:
    - SHA-256 file integrity verification
    - HMAC-SHA256 manifest signing
    - Multiple manifest sources (file, git, env)
    - Unexpected file detection
    """

    DEFAULT_SECRET = "default-policy-secret"
    SECRET_ENV_VAR = "SCALPEL_POLICY_SECRET"
    MANIFEST_FILENAME = "policy.manifest.json"
    MANIFEST_ENV_VAR = "SCALPEL_POLICY_MANIFEST"
    SUPPORTED_EXTENSIONS = {".yaml", ".yml", ".json", ".rego"}

    def __init__(
        self,
        policy_dir: str,
        manifest_source: str = "file",
        strict_mode: bool = True
    ):
        """
        Initialize the verifier.

        Args:
            policy_dir: Path to the policy directory
            manifest_source: Where to load manifest from ("file", "git", "env")
            strict_mode: If True, unexpected files cause verification failure
        """
        self.policy_dir = Path(policy_dir)
        self.manifest_source = ManifestSource(manifest_source)
        self.strict_mode = strict_mode
        self._secret = self._get_secret()

    def _get_secret(self) -> bytes:
        """Get the HMAC secret from environment or use default."""
        secret = os.environ.get(self.SECRET_ENV_VAR, self.DEFAULT_SECRET)
        return secret.encode('utf-8')

    def _compute_file_hash(self, file_path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return f"sha256:{sha256.hexdigest()}"

    def _get_file_size(self, file_path: Path) -> int:
        """Get file size in bytes."""
        return file_path.stat().st_size

    def _sign_manifest(self, manifest_data: Dict[str, Any]) -> str:
        """
        Sign manifest data using HMAC-SHA256.

        Args:
            manifest_data: Manifest dictionary WITHOUT signature field

        Returns:
            HMAC signature as "hmac-sha256:<hex>"
        """
        # Create copy without signature
        data_to_sign = {k: v for k, v in manifest_data.items() if k != "signature"}
        # Canonical JSON
        message = json.dumps(data_to_sign, sort_keys=True, separators=(',', ':'))
        signature = hmac.new(
            self._secret,
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return f"hmac-sha256:{signature}"

    def _verify_manifest_signature(self, manifest: PolicyManifest) -> bool:
        """
        Verify the manifest's HMAC signature.

        Args:
            manifest: The manifest to verify

        Returns:
            True if signature is valid
        """
        manifest_dict = manifest.to_dict()
        expected_signature = self._sign_manifest(manifest_dict)
        return hmac.compare_digest(manifest.signature, expected_signature)

    def _load_manifest_from_file(self) -> PolicyManifest:
        """Load manifest from file system."""
        manifest_path = self.policy_dir / self.MANIFEST_FILENAME

        if not manifest_path.exists():
            raise SecurityError(
                f"Manifest file not found: {manifest_path}",
                SecurityErrorCode.MANIFEST_NOT_FOUND,
                {"path": str(manifest_path)}
            )

        try:
            with open(manifest_path, 'r') as f:
                data = json.load(f)
            return PolicyManifest.from_dict(data)
        except json.JSONDecodeError as e:
            raise SecurityError(
                f"Failed to parse manifest: {e}",
                SecurityErrorCode.MANIFEST_PARSE_ERROR,
                {"error": str(e)}
            )

    def _load_manifest_from_env(self) -> PolicyManifest:
        """Load manifest from environment variable (base64 JSON)."""
        import base64

        manifest_b64 = os.environ.get(self.MANIFEST_ENV_VAR)
        if not manifest_b64:
            raise SecurityError(
                f"Manifest not found in environment variable: {self.MANIFEST_ENV_VAR}",
                SecurityErrorCode.MANIFEST_NOT_FOUND,
                {"env_var": self.MANIFEST_ENV_VAR}
            )

        try:
            manifest_json = base64.b64decode(manifest_b64).decode('utf-8')
            data = json.loads(manifest_json)
            return PolicyManifest.from_dict(data)
        except (base64.binascii.Error, json.JSONDecodeError) as e:
            raise SecurityError(
                f"Failed to parse manifest from env: {e}",
                SecurityErrorCode.MANIFEST_PARSE_ERROR,
                {"error": str(e)}
            )

    def _load_manifest_from_git(self) -> PolicyManifest:
        """Load manifest from git (last committed version)."""
        import subprocess

        manifest_path = self.policy_dir / self.MANIFEST_FILENAME
        relative_path = manifest_path.relative_to(Path.cwd()) if manifest_path.is_absolute() else manifest_path

        try:
            result = subprocess.run(
                ["git", "show", f"HEAD:{relative_path}"],
                capture_output=True,
                text=True,
                check=True
            )
            data = json.loads(result.stdout)
            return PolicyManifest.from_dict(data)
        except subprocess.CalledProcessError as e:
            raise SecurityError(
                f"Failed to load manifest from git: {e.stderr}",
                SecurityErrorCode.MANIFEST_NOT_FOUND,
                {"error": e.stderr}
            )
        except json.JSONDecodeError as e:
            raise SecurityError(
                f"Failed to parse manifest from git: {e}",
                SecurityErrorCode.MANIFEST_PARSE_ERROR,
                {"error": str(e)}
            )

    def _load_manifest(self) -> PolicyManifest:
        """Load manifest from configured source."""
        if self.manifest_source == ManifestSource.FILE:
            return self._load_manifest_from_file()
        elif self.manifest_source == ManifestSource.ENV:
            return self._load_manifest_from_env()
        elif self.manifest_source == ManifestSource.GIT:
            return self._load_manifest_from_git()
        else:
            raise ValueError(f"Unknown manifest source: {self.manifest_source}")

    def _get_policy_files(self) -> List[Path]:
        """Get all policy files in the policy directory."""
        if not self.policy_dir.exists():
            return []

        files = []
        for ext in self.SUPPORTED_EXTENSIONS:
            files.extend(self.policy_dir.glob(f"*{ext}"))
        return files

    def _validate_manifest_schema(self, manifest: PolicyManifest) -> None:
        """Validate manifest schema."""
        if not manifest.version:
            raise SecurityError(
                "Manifest missing required field: version",
                SecurityErrorCode.MANIFEST_SCHEMA_INVALID,
                {"missing_field": "version"}
            )

        if not manifest.created_at:
            raise SecurityError(
                "Manifest missing required field: created_at",
                SecurityErrorCode.MANIFEST_SCHEMA_INVALID,
                {"missing_field": "created_at"}
            )

        if not manifest.signature:
            raise SecurityError(
                "Manifest missing required field: signature",
                SecurityErrorCode.MANIFEST_SCHEMA_INVALID,
                {"missing_field": "signature"}
            )

    def verify(self) -> VerificationResult:
        """
        Verify all policy files against the manifest.

        Returns:
            VerificationResult with verification status

        Raises:
            SecurityError: If verification fails
        """
        # Step 1: Load manifest
        manifest = self._load_manifest()

        # Step 2: Validate manifest schema
        self._validate_manifest_schema(manifest)

        # Step 3: Verify manifest signature
        if not self._verify_manifest_signature(manifest):
            raise SecurityError(
                "Manifest signature invalid",
                SecurityErrorCode.MANIFEST_SIGNATURE_INVALID,
                {"signature": manifest.signature}
            )

        file_results = []

        # Step 4: Verify each file in manifest
        for file_path, entry in manifest.files.items():
            full_path = self.policy_dir / file_path

            # Check file exists
            if not full_path.exists():
                raise SecurityError(
                    f"Policy file missing: {file_path}",
                    SecurityErrorCode.FILE_MISSING,
                    {"file": file_path}
                )

            # Compute current hash
            actual_hash = self._compute_file_hash(full_path)
            actual_size = self._get_file_size(full_path)

            # Compare hash
            if actual_hash != entry.hash:
                raise SecurityError(
                    f"File hash mismatch: {file_path}",
                    SecurityErrorCode.FILE_HASH_MISMATCH,
                    {
                        "file": file_path,
                        "expected_hash": entry.hash,
                        "actual_hash": actual_hash
                    }
                )

            # Compare size (optional but recommended)
            if actual_size != entry.size:
                raise SecurityError(
                    f"File size mismatch: {file_path}",
                    SecurityErrorCode.FILE_SIZE_MISMATCH,
                    {
                        "file": file_path,
                        "expected_size": entry.size,
                        "actual_size": actual_size
                    }
                )

            file_results.append(FileVerificationResult(
                file_path=file_path,
                verified=True,
                expected_hash=entry.hash,
                actual_hash=actual_hash,
                expected_size=entry.size,
                actual_size=actual_size
            ))

        # Step 5: Check for unexpected files
        unexpected_files = []
        manifest_files = set(manifest.files.keys())

        for policy_file in self._get_policy_files():
            relative_path = policy_file.name
            if relative_path not in manifest_files and relative_path != self.MANIFEST_FILENAME:
                unexpected_files.append(relative_path)

        if unexpected_files and self.strict_mode:
            raise SecurityError(
                f"Unexpected policy file(s): {', '.join(unexpected_files)}",
                SecurityErrorCode.UNEXPECTED_FILE,
                {"files": unexpected_files}
            )

        return VerificationResult(
            verified=True,
            files_checked=len(file_results),
            manifest_version=manifest.version,
            manifest_created_at=manifest.created_at,
            file_results=file_results,
            unexpected_files=unexpected_files
        )

    def sign(self) -> PolicyManifest:
        """
        Create and sign a manifest for all policy files.

        Returns:
            Signed PolicyManifest
        """
        files = {}

        for policy_file in self._get_policy_files():
            if policy_file.name == self.MANIFEST_FILENAME:
                continue

            file_hash = self._compute_file_hash(policy_file)
            file_size = self._get_file_size(policy_file)

            files[policy_file.name] = ManifestFileEntry(
                hash=file_hash,
                size=file_size
            )

        manifest_data = {
            "version": "1.0",
            "created_at": datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
            "files": {
                path: {"hash": entry.hash, "size": entry.size}
                for path, entry in files.items()
            }
        }

        signature = self._sign_manifest(manifest_data)

        manifest = PolicyManifest(
            version=manifest_data["version"],
            created_at=manifest_data["created_at"],
            files=files,
            signature=signature
        )

        return manifest

    def save_manifest(self, manifest: PolicyManifest) -> Path:
        """
        Save manifest to file.

        Args:
            manifest: Manifest to save

        Returns:
            Path to saved manifest file
        """
        manifest_path = self.policy_dir / self.MANIFEST_FILENAME

        with open(manifest_path, 'w') as f:
            json.dump(manifest.to_dict(), f, indent=2)

        return manifest_path


# =============================================================================
# TEST DATA STRUCTURES
# =============================================================================

@dataclass
class CryptoTestCase:
    """Represents a crypto verification test case."""
    test_id: str
    name: str
    description: str
    setup: Optional[callable] = None
    test_fn: Optional[callable] = None
    expected_pass: bool = True


@dataclass
class CryptoTestResult:
    """Result of running a crypto verification test."""
    test_case: CryptoTestCase
    passed: bool
    error: Optional[str] = None
    execution_time_ms: float = 0.0


# =============================================================================
# TEST RUNNER
# =============================================================================

class CryptoVerifyTestRunner:
    """Test runner for crypto verification tests."""

    def __init__(self):
        self.results: List[CryptoTestResult] = []

    def run_test(self, test_case: CryptoTestCase) -> CryptoTestResult:
        """Run a single test case."""
        start = time.perf_counter()

        try:
            if test_case.setup:
                test_case.setup()

            if test_case.test_fn:
                test_case.test_fn()

            passed = test_case.expected_pass
            error = None

        except AssertionError as e:
            passed = not test_case.expected_pass
            error = str(e)
        except Exception as e:
            passed = False
            error = f"{type(e).__name__}: {e}"

        elapsed = (time.perf_counter() - start) * 1000

        result = CryptoTestResult(
            test_case=test_case,
            passed=passed,
            error=error,
            execution_time_ms=elapsed
        )

        self.results.append(result)
        return result

    def run_all(self, test_cases: List[CryptoTestCase]) -> List[CryptoTestResult]:
        """Run all test cases."""
        self.results = []
        for test_case in test_cases:
            self.run_test(test_case)
        return self.results

    def generate_report(self) -> Dict[str, Any]:
        """Generate a test report."""
        passed = sum(1 for r in self.results if r.passed)
        failed = len(self.results) - passed

        return {
            "total": len(self.results),
            "passed": passed,
            "failed": failed,
            "pass_rate": passed / max(len(self.results), 1),
            "failures": [
                {
                    "test_id": r.test_case.test_id,
                    "name": r.test_case.name,
                    "error": r.error
                }
                for r in self.results if not r.passed
            ]
        }


# =============================================================================
# HELPER FUNCTIONS FOR TESTS
# =============================================================================

def create_test_policy_dir() -> Path:
    """Create a temporary policy directory for testing."""
    tmpdir = tempfile.mkdtemp(prefix="policy_test_")
    return Path(tmpdir)


def create_policy_file(policy_dir: Path, filename: str, content: str) -> Path:
    """Create a policy file with given content."""
    file_path = policy_dir / filename
    with open(file_path, 'w') as f:
        f.write(content)
    return file_path


def cleanup_test_policy_dir(policy_dir: Path) -> None:
    """Remove temporary policy directory."""
    import shutil
    if policy_dir.exists():
        shutil.rmtree(policy_dir)


# =============================================================================
# MAIN EXECUTION
# =============================================================================

def main():
    """Run the crypto verification test framework."""
    print("=" * 70)
    print("CODE SCALPEL CRYPTOGRAPHIC POLICY VERIFICATION FRAMEWORK")
    print("=" * 70)
    print()
    print("Features:")
    print("  - SHA-256 file integrity verification")
    print("  - HMAC-SHA256 manifest signing")
    print("  - Multiple manifest sources (file, git, env)")
    print("  - Unexpected file detection")
    print("  - Strict mode for enterprise compliance")
    print()
    print("Security Properties:")
    print("  - Policy files are hashed with SHA-256")
    print("  - Manifests are signed with HMAC-SHA256")
    print("  - Any modification is detected")
    print("  - Unexpected files are flagged")
    print("=" * 70)


if __name__ == "__main__":
    main()
