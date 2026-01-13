#!/usr/bin/env python3
"""
=============================================================================
MANIFEST VERIFICATION TESTS
=============================================================================

PURPOSE: Test manifest loading and HMAC signature verification.
These tests verify that:

1. Manifests are loaded correctly from various sources
2. HMAC signatures are verified correctly
3. Invalid signatures are rejected
4. Missing manifests are detected
5. Corrupted manifests are handled
6. Schema validation works

=============================================================================
"""
import base64
import json
import os
import tempfile
from pathlib import Path

from crypto_verify_framework import (
    CryptographicPolicyVerifier, PolicyManifest, ManifestFileEntry,
    SecurityError, SecurityErrorCode, ManifestSource,
    create_test_policy_dir, create_policy_file, cleanup_test_policy_dir
)


# =============================================================================
# SIGNATURE VERIFICATION TESTS
# =============================================================================

def test_valid_signature_passes():
    """
    TEST: Valid HMAC signature passes verification.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))

        # Sign and save
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Verify
        result = verifier.verify()

        assert result.verified == True
        assert result.files_checked == 1

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_invalid_signature_fails():
    """
    TEST: Invalid HMAC signature raises SecurityError.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()

        # Tamper with signature
        manifest_dict = manifest.to_dict()
        manifest_dict["signature"] = "hmac-sha256:0000000000000000000000000000000000000000000000000000000000000000"

        manifest_path = policy_dir / "policy.manifest.json"
        with open(manifest_path, 'w') as f:
            json.dump(manifest_dict, f)

        try:
            verifier.verify()
            raise AssertionError("Invalid signature should raise SecurityError")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.MANIFEST_SIGNATURE_INVALID

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_tampered_manifest_content_fails():
    """
    TEST: Tampering with manifest content invalidates signature.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Read and tamper with manifest
        manifest_path = policy_dir / "policy.manifest.json"
        with open(manifest_path) as f:
            data = json.load(f)

        # Change version (signature should now be invalid)
        data["version"] = "2.0"

        with open(manifest_path, 'w') as f:
            json.dump(data, f)

        try:
            verifier.verify()
            raise AssertionError("Tampered manifest should fail")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.MANIFEST_SIGNATURE_INVALID

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_tampered_file_hash_in_manifest_fails():
    """
    TEST: Tampering with file hash in manifest invalidates signature.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Tamper with file hash
        manifest_path = policy_dir / "policy.manifest.json"
        with open(manifest_path) as f:
            data = json.load(f)

        data["files"]["policy.yaml"]["hash"] = "sha256:tampered"

        with open(manifest_path, 'w') as f:
            json.dump(data, f)

        try:
            verifier.verify()
            raise AssertionError("Tampered file hash should fail")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.MANIFEST_SIGNATURE_INVALID

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_removed_signature_fails():
    """
    TEST: Missing signature field raises SecurityError.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Remove signature
        manifest_path = policy_dir / "policy.manifest.json"
        with open(manifest_path) as f:
            data = json.load(f)

        del data["signature"]

        with open(manifest_path, 'w') as f:
            json.dump(data, f)

        try:
            verifier.verify()
            raise AssertionError("Missing signature should fail")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.MANIFEST_SCHEMA_INVALID

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_truncated_signature_fails():
    """
    TEST: Truncated signature fails verification.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Truncate signature
        manifest_path = policy_dir / "policy.manifest.json"
        with open(manifest_path) as f:
            data = json.load(f)

        data["signature"] = "hmac-sha256:abc123"  # Truncated

        with open(manifest_path, 'w') as f:
            json.dump(data, f)

        try:
            verifier.verify()
            raise AssertionError("Truncated signature should fail")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.MANIFEST_SIGNATURE_INVALID

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# MANIFEST LOADING TESTS (FILE SOURCE)
# =============================================================================

def test_load_manifest_from_file():
    """
    TEST: Manifest is loaded correctly from file.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir), manifest_source="file")
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        result = verifier.verify()
        assert result.verified == True

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_missing_manifest_file_fails():
    """
    TEST: Missing manifest file raises SecurityError.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))

        # Don't create manifest
        try:
            verifier.verify()
            raise AssertionError("Missing manifest should fail")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.MANIFEST_NOT_FOUND

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_corrupted_manifest_json_fails():
    """
    TEST: Corrupted JSON in manifest raises SecurityError.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        # Create corrupted manifest
        manifest_path = policy_dir / "policy.manifest.json"
        with open(manifest_path, 'w') as f:
            f.write("{ this is not valid json }")

        verifier = CryptographicPolicyVerifier(str(policy_dir))

        try:
            verifier.verify()
            raise AssertionError("Corrupted JSON should fail")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.MANIFEST_PARSE_ERROR

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_empty_manifest_file_fails():
    """
    TEST: Empty manifest file raises SecurityError.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        # Create empty manifest
        manifest_path = policy_dir / "policy.manifest.json"
        manifest_path.touch()

        verifier = CryptographicPolicyVerifier(str(policy_dir))

        try:
            verifier.verify()
            raise AssertionError("Empty manifest should fail")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.MANIFEST_PARSE_ERROR

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# MANIFEST LOADING TESTS (ENV SOURCE)
# =============================================================================

def test_load_manifest_from_env():
    """
    TEST: Manifest is loaded correctly from environment variable.
    """
    policy_dir = create_test_policy_dir()
    old_env = os.environ.get("SCALPEL_POLICY_MANIFEST")

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        # Create and sign manifest
        file_verifier = CryptographicPolicyVerifier(str(policy_dir), manifest_source="file")
        manifest = file_verifier.sign()

        # Encode manifest as base64
        manifest_json = json.dumps(manifest.to_dict())
        manifest_b64 = base64.b64encode(manifest_json.encode()).decode()
        os.environ["SCALPEL_POLICY_MANIFEST"] = manifest_b64

        # Verify using env source
        env_verifier = CryptographicPolicyVerifier(str(policy_dir), manifest_source="env")
        result = env_verifier.verify()

        assert result.verified == True

    finally:
        if old_env:
            os.environ["SCALPEL_POLICY_MANIFEST"] = old_env
        else:
            os.environ.pop("SCALPEL_POLICY_MANIFEST", None)
        cleanup_test_policy_dir(policy_dir)


def test_missing_manifest_env_fails():
    """
    TEST: Missing manifest env var raises SecurityError.
    """
    old_env = os.environ.pop("SCALPEL_POLICY_MANIFEST", None)

    try:
        policy_dir = create_test_policy_dir()
        try:
            verifier = CryptographicPolicyVerifier(str(policy_dir), manifest_source="env")
            verifier.verify()
            raise AssertionError("Missing env var should fail")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.MANIFEST_NOT_FOUND
        finally:
            cleanup_test_policy_dir(policy_dir)

    finally:
        if old_env:
            os.environ["SCALPEL_POLICY_MANIFEST"] = old_env


def test_invalid_base64_env_fails():
    """
    TEST: Invalid base64 in env var raises SecurityError.
    """
    old_env = os.environ.get("SCALPEL_POLICY_MANIFEST")
    os.environ["SCALPEL_POLICY_MANIFEST"] = "not-valid-base64!!!"

    try:
        policy_dir = create_test_policy_dir()
        try:
            verifier = CryptographicPolicyVerifier(str(policy_dir), manifest_source="env")
            verifier.verify()
            raise AssertionError("Invalid base64 should fail")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.MANIFEST_PARSE_ERROR
        finally:
            cleanup_test_policy_dir(policy_dir)

    finally:
        if old_env:
            os.environ["SCALPEL_POLICY_MANIFEST"] = old_env
        else:
            os.environ.pop("SCALPEL_POLICY_MANIFEST", None)


# =============================================================================
# SCHEMA VALIDATION TESTS
# =============================================================================

def test_missing_version_fails():
    """
    TEST: Missing version field raises SecurityError.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        # Create manifest without version
        manifest_data = {
            "created_at": "2025-01-01T00:00:00.000+00:00",
            "files": {},
            "signature": "hmac-sha256:abc"
        }

        manifest_path = policy_dir / "policy.manifest.json"
        with open(manifest_path, 'w') as f:
            json.dump(manifest_data, f)

        verifier = CryptographicPolicyVerifier(str(policy_dir))

        try:
            verifier.verify()
            raise AssertionError("Missing version should fail")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.MANIFEST_SCHEMA_INVALID
            assert "version" in str(e)

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_missing_created_at_fails():
    """
    TEST: Missing created_at field raises SecurityError.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        # Create manifest without created_at
        manifest_data = {
            "version": "1.0",
            "files": {},
            "signature": "hmac-sha256:abc"
        }

        manifest_path = policy_dir / "policy.manifest.json"
        with open(manifest_path, 'w') as f:
            json.dump(manifest_data, f)

        verifier = CryptographicPolicyVerifier(str(policy_dir))

        try:
            verifier.verify()
            raise AssertionError("Missing created_at should fail")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.MANIFEST_SCHEMA_INVALID
            assert "created_at" in str(e)

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_empty_version_fails():
    """
    TEST: Empty version field raises SecurityError.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        manifest_data = {
            "version": "",
            "created_at": "2025-01-01T00:00:00.000+00:00",
            "files": {},
            "signature": "hmac-sha256:abc"
        }

        manifest_path = policy_dir / "policy.manifest.json"
        with open(manifest_path, 'w') as f:
            json.dump(manifest_data, f)

        verifier = CryptographicPolicyVerifier(str(policy_dir))

        try:
            verifier.verify()
            raise AssertionError("Empty version should fail")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.MANIFEST_SCHEMA_INVALID

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# CROSS-INSTANCE VERIFICATION TESTS
# =============================================================================

def test_cross_instance_verification():
    """
    TEST: Manifest signed by one instance verifies with another (same secret).
    """
    old_secret = os.environ.get("SCALPEL_POLICY_SECRET")
    os.environ["SCALPEL_POLICY_SECRET"] = "shared-secret"

    try:
        policy_dir = create_test_policy_dir()
        try:
            create_policy_file(policy_dir, "policy.yaml", "rules: []")

            # First instance signs
            verifier1 = CryptographicPolicyVerifier(str(policy_dir))
            manifest = verifier1.sign()
            verifier1.save_manifest(manifest)

            # Second instance verifies
            verifier2 = CryptographicPolicyVerifier(str(policy_dir))
            result = verifier2.verify()

            assert result.verified == True

        finally:
            cleanup_test_policy_dir(policy_dir)

    finally:
        if old_secret:
            os.environ["SCALPEL_POLICY_SECRET"] = old_secret
        else:
            os.environ.pop("SCALPEL_POLICY_SECRET", None)


def test_different_secret_fails_verification():
    """
    TEST: Manifest signed with different secret fails verification.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        # Sign with secret1
        os.environ["SCALPEL_POLICY_SECRET"] = "secret-one"
        verifier1 = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier1.sign()
        verifier1.save_manifest(manifest)

        # Verify with secret2
        os.environ["SCALPEL_POLICY_SECRET"] = "secret-two"
        verifier2 = CryptographicPolicyVerifier(str(policy_dir))

        try:
            verifier2.verify()
            raise AssertionError("Different secret should fail")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.MANIFEST_SIGNATURE_INVALID

    finally:
        os.environ.pop("SCALPEL_POLICY_SECRET", None)
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# VERIFICATION RESULT TESTS
# =============================================================================

def test_verification_result_fields():
    """
    TEST: VerificationResult has all expected fields.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")
        create_policy_file(policy_dir, "budget.yaml", "limits: {}")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        result = verifier.verify()

        assert result.verified == True
        assert result.files_checked == 2
        assert result.manifest_version == "1.0"
        assert result.manifest_created_at is not None
        assert len(result.file_results) == 2

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_file_result_details():
    """
    TEST: FileVerificationResult contains expected details.
    """
    policy_dir = create_test_policy_dir()

    try:
        content = "rules: []\n"
        create_policy_file(policy_dir, "policy.yaml", content)

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        result = verifier.verify()

        file_result = result.file_results[0]
        assert file_result.file_path == "policy.yaml"
        assert file_result.verified == True
        assert file_result.expected_hash.startswith("sha256:")
        assert file_result.actual_hash == file_result.expected_hash
        assert file_result.expected_size == len(content.encode())

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_manifest_verification_tests():
    """Run all manifest verification tests."""
    tests = [
        ("VERIFY-001", "Valid signature passes", test_valid_signature_passes),
        ("VERIFY-002", "Invalid signature fails", test_invalid_signature_fails),
        ("VERIFY-003", "Tampered content fails", test_tampered_manifest_content_fails),
        ("VERIFY-004", "Tampered file hash fails", test_tampered_file_hash_in_manifest_fails),
        ("VERIFY-005", "Removed signature fails", test_removed_signature_fails),
        ("VERIFY-006", "Truncated signature fails", test_truncated_signature_fails),
        ("LOAD-FILE-001", "Load from file", test_load_manifest_from_file),
        ("LOAD-FILE-002", "Missing manifest file fails", test_missing_manifest_file_fails),
        ("LOAD-FILE-003", "Corrupted JSON fails", test_corrupted_manifest_json_fails),
        ("LOAD-FILE-004", "Empty manifest file fails", test_empty_manifest_file_fails),
        ("LOAD-ENV-001", "Load from env", test_load_manifest_from_env),
        ("LOAD-ENV-002", "Missing env var fails", test_missing_manifest_env_fails),
        ("LOAD-ENV-003", "Invalid base64 fails", test_invalid_base64_env_fails),
        ("SCHEMA-001", "Missing version fails", test_missing_version_fails),
        ("SCHEMA-002", "Missing created_at fails", test_missing_created_at_fails),
        ("SCHEMA-003", "Empty version fails", test_empty_version_fails),
        ("CROSS-001", "Cross-instance verification", test_cross_instance_verification),
        ("CROSS-002", "Different secret fails", test_different_secret_fails_verification),
        ("RESULT-001", "Verification result fields", test_verification_result_fields),
        ("RESULT-002", "File result details", test_file_result_details),
    ]

    print("=" * 70)
    print("MANIFEST VERIFICATION TESTS")
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
    run_manifest_verification_tests()
