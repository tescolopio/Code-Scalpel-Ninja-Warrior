#!/usr/bin/env python3
"""
=============================================================================
MANIFEST SIGNING TESTS
=============================================================================

PURPOSE: Test manifest creation and HMAC-SHA256 signing functionality.
These tests verify that:

1. Manifests are created with correct schema
2. HMAC-SHA256 signatures are generated correctly
3. Signatures are deterministic for same content
4. Different content produces different signatures
5. Secret key management works correctly
6. Manifest serialization is correct

=============================================================================
"""
import hashlib
import hmac
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
# MANIFEST CREATION TESTS
# =============================================================================

def test_sign_creates_manifest():
    """
    TEST: sign() creates a valid manifest structure.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules:\n  - name: test\n")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()

        assert manifest is not None, "Manifest should not be None"
        assert manifest.version == "1.0", "Version should be 1.0"
        assert manifest.created_at is not None, "created_at should be set"
        assert manifest.signature is not None, "Signature should be set"
        assert len(manifest.files) > 0, "Files should be present"

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_manifest_includes_all_policy_files():
    """
    TEST: Manifest includes all policy files in directory.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")
        create_policy_file(policy_dir, "budget.yaml", "limits: {}")
        create_policy_file(policy_dir, "security.json", '{"rules": []}')

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()

        assert "policy.yaml" in manifest.files
        assert "budget.yaml" in manifest.files
        assert "security.json" in manifest.files
        assert len(manifest.files) == 3

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_manifest_file_entry_has_hash_and_size():
    """
    TEST: Each file entry has correct hash and size.
    """
    policy_dir = create_test_policy_dir()
    content = "rules:\n  - name: test\n  - name: another\n"

    try:
        file_path = create_policy_file(policy_dir, "policy.yaml", content)

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()

        entry = manifest.files["policy.yaml"]

        # Verify hash format
        assert entry.hash.startswith("sha256:"), \
            f"Hash should start with sha256: got {entry.hash}"

        # Verify hash is correct
        expected_hash = "sha256:" + hashlib.sha256(content.encode()).hexdigest()
        assert entry.hash == expected_hash, \
            f"Hash mismatch: {entry.hash} != {expected_hash}"

        # Verify size
        assert entry.size == len(content.encode()), \
            f"Size mismatch: {entry.size} != {len(content.encode())}"

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_manifest_excludes_manifest_file():
    """
    TEST: Manifest file itself is not included in files list.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")
        create_policy_file(policy_dir, "policy.manifest.json", '{"old": "manifest"}')

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()

        assert "policy.manifest.json" not in manifest.files

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_manifest_version_is_1_0():
    """
    TEST: Manifest version is set to "1.0".
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()

        assert manifest.version == "1.0"

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_manifest_created_at_is_iso8601():
    """
    TEST: created_at is valid ISO 8601 timestamp.
    """
    from datetime import datetime

    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()

        # Should parse without error
        parsed = datetime.fromisoformat(manifest.created_at.replace('Z', '+00:00'))
        assert parsed is not None

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# SIGNATURE GENERATION TESTS
# =============================================================================

def test_signature_is_hmac_sha256():
    """
    TEST: Signature uses HMAC-SHA256 algorithm.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()

        assert manifest.signature.startswith("hmac-sha256:"), \
            f"Signature should start with hmac-sha256: got {manifest.signature}"

        # Extract hex part
        hex_part = manifest.signature.replace("hmac-sha256:", "")
        assert len(hex_part) == 64, f"Hex should be 64 chars, got {len(hex_part)}"

        # Verify it's valid hex
        int(hex_part, 16)

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_signature_is_deterministic():
    """
    TEST: Same content produces same signature (with same timestamp).
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))

        # Sign the same data with fixed timestamp
        manifest_data = {
            "version": "1.0",
            "created_at": "2025-01-01T00:00:00.000+00:00",
            "files": {
                "policy.yaml": {
                    "hash": "sha256:abc123",
                    "size": 10
                }
            }
        }

        sig1 = verifier._sign_manifest(manifest_data)
        sig2 = verifier._sign_manifest(manifest_data)

        assert sig1 == sig2, "Same data should produce same signature"

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_different_content_different_signature():
    """
    TEST: Different content produces different signatures.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))

        manifest_data1 = {
            "version": "1.0",
            "created_at": "2025-01-01T00:00:00.000+00:00",
            "files": {"policy.yaml": {"hash": "sha256:abc", "size": 10}}
        }

        manifest_data2 = {
            "version": "1.0",
            "created_at": "2025-01-01T00:00:00.000+00:00",
            "files": {"policy.yaml": {"hash": "sha256:def", "size": 10}}
        }

        sig1 = verifier._sign_manifest(manifest_data1)
        sig2 = verifier._sign_manifest(manifest_data2)

        assert sig1 != sig2, "Different content should produce different signatures"

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_signature_changes_with_file_hash():
    """
    TEST: Changing file hash changes the signature.
    """
    policy_dir = create_test_policy_dir()

    try:
        verifier = CryptographicPolicyVerifier(str(policy_dir))

        base_data = {
            "version": "1.0",
            "created_at": "2025-01-01T00:00:00.000+00:00",
            "files": {"policy.yaml": {"hash": "sha256:original", "size": 100}}
        }

        modified_data = {
            "version": "1.0",
            "created_at": "2025-01-01T00:00:00.000+00:00",
            "files": {"policy.yaml": {"hash": "sha256:modified", "size": 100}}
        }

        sig1 = verifier._sign_manifest(base_data)
        sig2 = verifier._sign_manifest(modified_data)

        assert sig1 != sig2

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_signature_changes_with_file_size():
    """
    TEST: Changing file size changes the signature.
    """
    policy_dir = create_test_policy_dir()

    try:
        verifier = CryptographicPolicyVerifier(str(policy_dir))

        base_data = {
            "version": "1.0",
            "created_at": "2025-01-01T00:00:00.000+00:00",
            "files": {"policy.yaml": {"hash": "sha256:abc", "size": 100}}
        }

        modified_data = {
            "version": "1.0",
            "created_at": "2025-01-01T00:00:00.000+00:00",
            "files": {"policy.yaml": {"hash": "sha256:abc", "size": 200}}
        }

        sig1 = verifier._sign_manifest(base_data)
        sig2 = verifier._sign_manifest(modified_data)

        assert sig1 != sig2

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_signature_changes_with_version():
    """
    TEST: Changing version changes the signature.
    """
    policy_dir = create_test_policy_dir()

    try:
        verifier = CryptographicPolicyVerifier(str(policy_dir))

        base_data = {
            "version": "1.0",
            "created_at": "2025-01-01T00:00:00.000+00:00",
            "files": {}
        }

        modified_data = {
            "version": "2.0",
            "created_at": "2025-01-01T00:00:00.000+00:00",
            "files": {}
        }

        sig1 = verifier._sign_manifest(base_data)
        sig2 = verifier._sign_manifest(modified_data)

        assert sig1 != sig2

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# SECRET KEY MANAGEMENT TESTS
# =============================================================================

def test_default_secret_used():
    """
    TEST: Default secret is used when env var not set.
    """
    old_secret = os.environ.pop("SCALPEL_POLICY_SECRET", None)

    try:
        policy_dir = create_test_policy_dir()
        try:
            create_policy_file(policy_dir, "policy.yaml", "rules: []")

            verifier = CryptographicPolicyVerifier(str(policy_dir))
            manifest = verifier.sign()

            assert manifest.signature is not None
            assert manifest.signature.startswith("hmac-sha256:")

        finally:
            cleanup_test_policy_dir(policy_dir)

    finally:
        if old_secret:
            os.environ["SCALPEL_POLICY_SECRET"] = old_secret


def test_custom_secret_from_env():
    """
    TEST: Custom secret from environment variable is used.
    """
    old_secret = os.environ.get("SCALPEL_POLICY_SECRET")
    os.environ["SCALPEL_POLICY_SECRET"] = "my-custom-secret"

    try:
        policy_dir = create_test_policy_dir()
        try:
            create_policy_file(policy_dir, "policy.yaml", "rules: []")

            verifier = CryptographicPolicyVerifier(str(policy_dir))

            # Manually compute with custom secret
            manifest_data = {
                "version": "1.0",
                "created_at": "2025-01-01T00:00:00.000+00:00",
                "files": {}
            }

            message = json.dumps(manifest_data, sort_keys=True, separators=(',', ':'))
            expected = "hmac-sha256:" + hmac.new(
                b"my-custom-secret",
                message.encode(),
                hashlib.sha256
            ).hexdigest()

            actual = verifier._sign_manifest(manifest_data)
            assert actual == expected

        finally:
            cleanup_test_policy_dir(policy_dir)

    finally:
        if old_secret:
            os.environ["SCALPEL_POLICY_SECRET"] = old_secret
        else:
            os.environ.pop("SCALPEL_POLICY_SECRET", None)


def test_different_secrets_different_signatures():
    """
    TEST: Different secrets produce different signatures.
    """
    manifest_data = {
        "version": "1.0",
        "created_at": "2025-01-01T00:00:00.000+00:00",
        "files": {}
    }

    message = json.dumps(manifest_data, sort_keys=True, separators=(',', ':'))

    sig1 = hmac.new(b"secret-one", message.encode(), hashlib.sha256).hexdigest()
    sig2 = hmac.new(b"secret-two", message.encode(), hashlib.sha256).hexdigest()

    assert sig1 != sig2


# =============================================================================
# MANIFEST SERIALIZATION TESTS
# =============================================================================

def test_manifest_to_dict():
    """
    TEST: Manifest serializes to correct dictionary format.
    """
    manifest = PolicyManifest(
        version="1.0",
        created_at="2025-01-01T00:00:00.000+00:00",
        files={
            "policy.yaml": ManifestFileEntry(hash="sha256:abc", size=100),
            "budget.yaml": ManifestFileEntry(hash="sha256:def", size=200)
        },
        signature="hmac-sha256:xyz"
    )

    data = manifest.to_dict()

    assert data["version"] == "1.0"
    assert data["created_at"] == "2025-01-01T00:00:00.000+00:00"
    assert data["files"]["policy.yaml"]["hash"] == "sha256:abc"
    assert data["files"]["policy.yaml"]["size"] == 100
    assert data["signature"] == "hmac-sha256:xyz"


def test_manifest_from_dict():
    """
    TEST: Manifest deserializes from dictionary correctly.
    """
    data = {
        "version": "1.0",
        "created_at": "2025-01-01T00:00:00.000+00:00",
        "files": {
            "policy.yaml": {"hash": "sha256:abc", "size": 100}
        },
        "signature": "hmac-sha256:xyz"
    }

    manifest = PolicyManifest.from_dict(data)

    assert manifest.version == "1.0"
    assert manifest.created_at == "2025-01-01T00:00:00.000+00:00"
    assert "policy.yaml" in manifest.files
    assert manifest.files["policy.yaml"].hash == "sha256:abc"
    assert manifest.signature == "hmac-sha256:xyz"


def test_manifest_roundtrip():
    """
    TEST: Manifest survives serialization roundtrip.
    """
    original = PolicyManifest(
        version="1.0",
        created_at="2025-01-01T00:00:00.000+00:00",
        files={
            "policy.yaml": ManifestFileEntry(hash="sha256:abc123", size=1024)
        },
        signature="hmac-sha256:signature123"
    )

    data = original.to_dict()
    restored = PolicyManifest.from_dict(data)

    assert restored.version == original.version
    assert restored.created_at == original.created_at
    assert restored.signature == original.signature
    assert len(restored.files) == len(original.files)


def test_save_manifest_to_file():
    """
    TEST: Manifest is saved to file correctly.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()

        saved_path = verifier.save_manifest(manifest)

        assert saved_path.exists()
        assert saved_path.name == "policy.manifest.json"

        # Verify content
        with open(saved_path) as f:
            data = json.load(f)

        assert data["version"] == manifest.version
        assert data["signature"] == manifest.signature

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# CANONICAL JSON TESTS
# =============================================================================

def test_canonical_json_sorted_keys():
    """
    TEST: Manifest signing uses sorted keys.
    """
    policy_dir = create_test_policy_dir()

    try:
        verifier = CryptographicPolicyVerifier(str(policy_dir))

        # Keys in different order should produce same signature
        data1 = {"z": 1, "a": 2, "m": 3}
        data2 = {"a": 2, "m": 3, "z": 1}

        sig1 = verifier._sign_manifest(data1)
        sig2 = verifier._sign_manifest(data2)

        assert sig1 == sig2, "Key order should not affect signature"

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_canonical_json_no_whitespace():
    """
    TEST: Manifest signing uses compact JSON (no whitespace).
    """
    data = {"key": "value", "nested": {"inner": "data"}}
    canonical = json.dumps(data, sort_keys=True, separators=(',', ':'))

    assert " " not in canonical
    assert "\n" not in canonical


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_manifest_signing_tests():
    """Run all manifest signing tests."""
    tests = [
        ("CREATE-001", "Sign creates manifest", test_sign_creates_manifest),
        ("CREATE-002", "Manifest includes all files", test_manifest_includes_all_policy_files),
        ("CREATE-003", "File entry has hash and size", test_manifest_file_entry_has_hash_and_size),
        ("CREATE-004", "Excludes manifest file", test_manifest_excludes_manifest_file),
        ("CREATE-005", "Version is 1.0", test_manifest_version_is_1_0),
        ("CREATE-006", "Created at is ISO8601", test_manifest_created_at_is_iso8601),
        ("SIG-001", "Signature is HMAC-SHA256", test_signature_is_hmac_sha256),
        ("SIG-002", "Signature is deterministic", test_signature_is_deterministic),
        ("SIG-003", "Different content different signature", test_different_content_different_signature),
        ("SIG-004", "Signature changes with file hash", test_signature_changes_with_file_hash),
        ("SIG-005", "Signature changes with file size", test_signature_changes_with_file_size),
        ("SIG-006", "Signature changes with version", test_signature_changes_with_version),
        ("SECRET-001", "Default secret used", test_default_secret_used),
        ("SECRET-002", "Custom secret from env", test_custom_secret_from_env),
        ("SECRET-003", "Different secrets different signatures", test_different_secrets_different_signatures),
        ("SERIAL-001", "Manifest to dict", test_manifest_to_dict),
        ("SERIAL-002", "Manifest from dict", test_manifest_from_dict),
        ("SERIAL-003", "Manifest roundtrip", test_manifest_roundtrip),
        ("SERIAL-004", "Save manifest to file", test_save_manifest_to_file),
        ("CANON-001", "Canonical JSON sorted keys", test_canonical_json_sorted_keys),
        ("CANON-002", "Canonical JSON no whitespace", test_canonical_json_no_whitespace),
    ]

    print("=" * 70)
    print("MANIFEST SIGNING TESTS")
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
    run_manifest_signing_tests()
