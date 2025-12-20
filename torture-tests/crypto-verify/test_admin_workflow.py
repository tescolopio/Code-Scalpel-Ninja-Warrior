#!/usr/bin/env python3
"""
=============================================================================
ADMINISTRATOR WORKFLOW TESTS
=============================================================================

PURPOSE: Test the administrator workflow for signing and updating policies.
These tests verify the complete workflow that administrators follow:

1. Initial manifest creation and signing
2. Updating policies and re-signing
3. Adding new policy files
4. Removing policy files
5. Secret key rotation
6. Multi-environment workflows

ADMINISTRATOR WORKFLOW:
```bash
# After modifying policies
export SCALPEL_POLICY_SECRET="your-secret-key"
python -m code_scalpel.policy_engine.crypto_verify sign --policy-dir .code-scalpel
git add .code-scalpel/policy.manifest.json && git commit -m "Update manifest"
```

=============================================================================
"""
import base64
import json
import os
import tempfile
from pathlib import Path

from crypto_verify_framework import (
    CryptographicPolicyVerifier, PolicyManifest, ManifestFileEntry,
    SecurityError, SecurityErrorCode,
    create_test_policy_dir, create_policy_file, cleanup_test_policy_dir
)


# =============================================================================
# INITIAL SETUP WORKFLOW TESTS
# =============================================================================

def test_initial_manifest_creation():
    """
    TEST: Administrator creates initial manifest for new project.

    Workflow:
    1. Create policy files
    2. Set secret key
    3. Sign policies
    4. Save manifest
    """
    policy_dir = create_test_policy_dir()
    old_secret = os.environ.get("SCALPEL_POLICY_SECRET")
    os.environ["SCALPEL_POLICY_SECRET"] = "admin-secret-key"

    try:
        # Step 1: Create policy files
        create_policy_file(policy_dir, "policy.yaml", "rules:\n  - name: no-sql-injection\n")
        create_policy_file(policy_dir, "budget.yaml", "limits:\n  tokens: 10000\n")

        # Step 2-3: Create verifier and sign
        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()

        # Step 4: Save manifest
        manifest_path = verifier.save_manifest(manifest)

        # Verify manifest was created
        assert manifest_path.exists()
        assert manifest.version == "1.0"
        assert len(manifest.files) == 2

        # Verify it can be verified
        result = verifier.verify()
        assert result.verified == True

    finally:
        if old_secret:
            os.environ["SCALPEL_POLICY_SECRET"] = old_secret
        else:
            os.environ.pop("SCALPEL_POLICY_SECRET", None)
        cleanup_test_policy_dir(policy_dir)


def test_empty_project_initial_setup():
    """
    TEST: Administrator sets up empty project (no policies yet).
    """
    policy_dir = create_test_policy_dir()

    try:
        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        assert len(manifest.files) == 0
        assert manifest.signature is not None

        # Can still verify (empty is valid)
        result = verifier.verify()
        assert result.verified == True

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# UPDATE WORKFLOW TESTS
# =============================================================================

def test_update_existing_policy():
    """
    TEST: Administrator updates existing policy and re-signs.

    Workflow:
    1. Modify policy file
    2. Re-run sign command
    3. Commit new manifest
    """
    policy_dir = create_test_policy_dir()

    try:
        # Initial setup
        create_policy_file(policy_dir, "policy.yaml", "rules: [v1]")
        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest1 = verifier.sign()
        verifier.save_manifest(manifest1)

        # Verification passes
        assert verifier.verify().verified == True

        # Administrator modifies policy
        create_policy_file(policy_dir, "policy.yaml", "rules: [v2, new-rule]")

        # Old manifest now fails
        try:
            verifier.verify()
            raise AssertionError("Modified file should fail old manifest")
        except SecurityError:
            pass

        # Administrator re-signs
        manifest2 = verifier.sign()
        verifier.save_manifest(manifest2)

        # New manifest succeeds
        result = verifier.verify()
        assert result.verified == True

        # Signatures should be different
        assert manifest1.signature != manifest2.signature

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_add_new_policy_file():
    """
    TEST: Administrator adds new policy file and re-signs.
    """
    policy_dir = create_test_policy_dir()

    try:
        # Initial setup with one file
        create_policy_file(policy_dir, "policy.yaml", "rules: []")
        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest1 = verifier.sign()
        verifier.save_manifest(manifest1)

        assert len(manifest1.files) == 1

        # Add new policy file
        create_policy_file(policy_dir, "security.yaml", "security:\n  enabled: true")

        # Without re-signing, new file is unexpected
        try:
            verifier.verify()
            raise AssertionError("New file should be unexpected")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.UNEXPECTED_FILE

        # Re-sign
        manifest2 = verifier.sign()
        verifier.save_manifest(manifest2)

        # Now includes both files
        assert len(manifest2.files) == 2
        assert "security.yaml" in manifest2.files

        # Verification passes
        assert verifier.verify().verified == True

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_remove_policy_file():
    """
    TEST: Administrator removes policy file and re-signs.
    """
    policy_dir = create_test_policy_dir()

    try:
        # Initial setup with two files
        create_policy_file(policy_dir, "policy.yaml", "rules: []")
        create_policy_file(policy_dir, "deprecated.yaml", "old: config")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest1 = verifier.sign()
        verifier.save_manifest(manifest1)

        assert len(manifest1.files) == 2

        # Remove deprecated file
        (policy_dir / "deprecated.yaml").unlink()

        # Old manifest fails (missing file)
        try:
            verifier.verify()
            raise AssertionError("Missing file should fail")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.FILE_MISSING

        # Re-sign
        manifest2 = verifier.sign()
        verifier.save_manifest(manifest2)

        # Now only has one file
        assert len(manifest2.files) == 1
        assert "deprecated.yaml" not in manifest2.files

        # Verification passes
        assert verifier.verify().verified == True

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_rename_policy_file():
    """
    TEST: Administrator renames policy file and re-signs.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "old_name.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest1 = verifier.sign()
        verifier.save_manifest(manifest1)

        # Rename file
        (policy_dir / "old_name.yaml").rename(policy_dir / "new_name.yaml")

        # Old manifest fails
        try:
            verifier.verify()
            raise AssertionError("Rename should fail old manifest")
        except SecurityError:
            pass

        # Re-sign
        manifest2 = verifier.sign()
        verifier.save_manifest(manifest2)

        assert "old_name.yaml" not in manifest2.files
        assert "new_name.yaml" in manifest2.files

        assert verifier.verify().verified == True

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# SECRET KEY MANAGEMENT TESTS
# =============================================================================

def test_initial_secret_key_setup():
    """
    TEST: Administrator sets up initial secret key.
    """
    policy_dir = create_test_policy_dir()
    os.environ.pop("SCALPEL_POLICY_SECRET", None)

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        # Without custom secret, uses default
        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest1 = verifier.sign()

        # With custom secret
        os.environ["SCALPEL_POLICY_SECRET"] = "production-secret"
        verifier2 = CryptographicPolicyVerifier(str(policy_dir))
        manifest2 = verifier2.sign()

        # Signatures should be different
        assert manifest1.signature != manifest2.signature

    finally:
        os.environ.pop("SCALPEL_POLICY_SECRET", None)
        cleanup_test_policy_dir(policy_dir)


def test_secret_key_rotation():
    """
    TEST: Administrator rotates secret key.

    Workflow:
    1. Sign with old key
    2. Switch to new key
    3. Re-sign all policies
    4. Verify with new key
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        # Sign with old key
        os.environ["SCALPEL_POLICY_SECRET"] = "old-key"
        verifier1 = CryptographicPolicyVerifier(str(policy_dir))
        manifest1 = verifier1.sign()
        verifier1.save_manifest(manifest1)

        assert verifier1.verify().verified == True

        # Rotate to new key
        os.environ["SCALPEL_POLICY_SECRET"] = "new-key"
        verifier2 = CryptographicPolicyVerifier(str(policy_dir))

        # Old manifest fails with new key
        try:
            verifier2.verify()
            raise AssertionError("Old manifest should fail with new key")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.MANIFEST_SIGNATURE_INVALID

        # Re-sign with new key
        manifest2 = verifier2.sign()
        verifier2.save_manifest(manifest2)

        # Now verification passes
        assert verifier2.verify().verified == True

    finally:
        os.environ.pop("SCALPEL_POLICY_SECRET", None)
        cleanup_test_policy_dir(policy_dir)


def test_secret_key_per_environment():
    """
    TEST: Different environments use different secrets.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        # Development environment
        os.environ["SCALPEL_POLICY_SECRET"] = "dev-secret"
        dev_verifier = CryptographicPolicyVerifier(str(policy_dir))
        dev_manifest = dev_verifier.sign()

        # Production environment
        os.environ["SCALPEL_POLICY_SECRET"] = "prod-secret"
        prod_verifier = CryptographicPolicyVerifier(str(policy_dir))
        prod_manifest = prod_verifier.sign()

        # Different signatures
        assert dev_manifest.signature != prod_manifest.signature

    finally:
        os.environ.pop("SCALPEL_POLICY_SECRET", None)
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# MULTI-ENVIRONMENT WORKFLOW TESTS
# =============================================================================

def test_manifest_from_env_variable():
    """
    TEST: CI/CD environment uses manifest from environment variable.
    """
    policy_dir = create_test_policy_dir()
    old_manifest_env = os.environ.get("SCALPEL_POLICY_MANIFEST")
    old_secret_env = os.environ.get("SCALPEL_POLICY_SECRET")

    try:
        os.environ["SCALPEL_POLICY_SECRET"] = "ci-secret"

        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        # Build environment creates manifest
        build_verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = build_verifier.sign()

        # Encode manifest for CI environment
        manifest_json = json.dumps(manifest.to_dict())
        manifest_b64 = base64.b64encode(manifest_json.encode()).decode()
        os.environ["SCALPEL_POLICY_MANIFEST"] = manifest_b64

        # CI environment uses env source
        ci_verifier = CryptographicPolicyVerifier(str(policy_dir), manifest_source="env")
        result = ci_verifier.verify()

        assert result.verified == True

    finally:
        if old_manifest_env:
            os.environ["SCALPEL_POLICY_MANIFEST"] = old_manifest_env
        else:
            os.environ.pop("SCALPEL_POLICY_MANIFEST", None)
        if old_secret_env:
            os.environ["SCALPEL_POLICY_SECRET"] = old_secret_env
        else:
            os.environ.pop("SCALPEL_POLICY_SECRET", None)
        cleanup_test_policy_dir(policy_dir)


def test_cross_team_collaboration():
    """
    TEST: Multiple team members can verify with shared secret.
    """
    policy_dir = create_test_policy_dir()
    shared_secret = "team-shared-secret"

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        # Team member 1 signs
        os.environ["SCALPEL_POLICY_SECRET"] = shared_secret
        member1_verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = member1_verifier.sign()
        member1_verifier.save_manifest(manifest)

        # Team member 2 verifies (new instance, same secret)
        member2_verifier = CryptographicPolicyVerifier(str(policy_dir))
        result = member2_verifier.verify()

        assert result.verified == True

    finally:
        os.environ.pop("SCALPEL_POLICY_SECRET", None)
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# MANIFEST INSPECTION TESTS
# =============================================================================

def test_inspect_manifest_contents():
    """
    TEST: Administrator can inspect manifest contents.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: [a, b, c]")
        create_policy_file(policy_dir, "budget.yaml", "limits: {}")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Read and inspect manifest
        manifest_path = policy_dir / "policy.manifest.json"
        with open(manifest_path) as f:
            data = json.load(f)

        # Can see all file info
        assert "files" in data
        assert "policy.yaml" in data["files"]
        assert "hash" in data["files"]["policy.yaml"]
        assert "size" in data["files"]["policy.yaml"]

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_verification_result_details():
    """
    TEST: Administrator can inspect verification results.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")
        create_policy_file(policy_dir, "budget.yaml", "limits: {}")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        result = verifier.verify()

        # Can inspect results
        assert result.verified == True
        assert result.files_checked == 2
        assert result.manifest_version == "1.0"
        assert len(result.file_results) == 2

        for file_result in result.file_results:
            assert file_result.verified == True
            assert file_result.expected_hash is not None
            assert file_result.actual_hash == file_result.expected_hash

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# ERROR RECOVERY TESTS
# =============================================================================

def test_recovery_from_corrupted_manifest():
    """
    TEST: Administrator recovers from corrupted manifest.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Corrupt the manifest
        manifest_path = policy_dir / "policy.manifest.json"
        with open(manifest_path, 'w') as f:
            f.write("{ corrupted json")

        # Verification fails
        try:
            verifier.verify()
            raise AssertionError("Corrupted manifest should fail")
        except SecurityError:
            pass

        # Recovery: re-sign
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Now verification passes
        assert verifier.verify().verified == True

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_recovery_from_deleted_manifest():
    """
    TEST: Administrator recovers from deleted manifest.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Delete manifest
        (policy_dir / "policy.manifest.json").unlink()

        # Verification fails
        try:
            verifier.verify()
            raise AssertionError("Missing manifest should fail")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.MANIFEST_NOT_FOUND

        # Recovery: re-sign
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Now verification passes
        assert verifier.verify().verified == True

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_recovery_from_unauthorized_changes():
    """
    TEST: Administrator recovers from unauthorized policy changes.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: [safe]")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Unauthorized modification
        create_policy_file(policy_dir, "policy.yaml", "rules: [malicious]")

        # Detected
        try:
            verifier.verify()
            raise AssertionError("Unauthorized change should be detected")
        except SecurityError:
            pass

        # Recovery option 1: Restore original file
        create_policy_file(policy_dir, "policy.yaml", "rules: [safe]")
        assert verifier.verify().verified == True

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# STRICT MODE MANAGEMENT TESTS
# =============================================================================

def test_toggle_strict_mode():
    """
    TEST: Administrator toggles strict mode for different environments.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Add unexpected file
        create_policy_file(policy_dir, "extra.yaml", "development: true")

        # Strict mode fails
        strict_verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=True)
        try:
            strict_verifier.verify()
            raise AssertionError("Strict mode should fail")
        except SecurityError:
            pass

        # Non-strict mode passes with warning
        lenient_verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=False)
        result = lenient_verifier.verify()

        assert result.verified == True
        assert len(result.unexpected_files) > 0

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_admin_workflow_tests():
    """Run all administrator workflow tests."""
    tests = [
        ("INIT-001", "Initial manifest creation", test_initial_manifest_creation),
        ("INIT-002", "Empty project setup", test_empty_project_initial_setup),
        ("UPDATE-001", "Update existing policy", test_update_existing_policy),
        ("UPDATE-002", "Add new policy file", test_add_new_policy_file),
        ("UPDATE-003", "Remove policy file", test_remove_policy_file),
        ("UPDATE-004", "Rename policy file", test_rename_policy_file),
        ("SECRET-001", "Initial secret key setup", test_initial_secret_key_setup),
        ("SECRET-002", "Secret key rotation", test_secret_key_rotation),
        ("SECRET-003", "Secret key per environment", test_secret_key_per_environment),
        ("MULTIENV-001", "Manifest from env variable", test_manifest_from_env_variable),
        ("MULTIENV-002", "Cross-team collaboration", test_cross_team_collaboration),
        ("INSPECT-001", "Inspect manifest contents", test_inspect_manifest_contents),
        ("INSPECT-002", "Verification result details", test_verification_result_details),
        ("RECOVERY-001", "Recovery from corrupted manifest", test_recovery_from_corrupted_manifest),
        ("RECOVERY-002", "Recovery from deleted manifest", test_recovery_from_deleted_manifest),
        ("RECOVERY-003", "Recovery from unauthorized changes", test_recovery_from_unauthorized_changes),
        ("MODE-001", "Toggle strict mode", test_toggle_strict_mode),
    ]

    print("=" * 70)
    print("ADMINISTRATOR WORKFLOW TESTS")
    print("=" * 70)
    print()

    passed = 0
    failed = 0

    for test_id, name, test_fn in tests:
        try:
            test_fn()
            print(f"✓ PASS: [{test_id}] {name}")
            passed += 1
        except AssertionError as e:
            print(f"✗ FAIL: [{test_id}] {name}")
            print(f"  Reason: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ ERROR: [{test_id}] {name}")
            print(f"  Exception: {type(e).__name__}: {e}")
            failed += 1

    print()
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 70)

    return passed, failed


if __name__ == "__main__":
    run_admin_workflow_tests()
