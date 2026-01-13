#!/usr/bin/env python3
"""
=============================================================================
FILE HASH VERIFICATION TESTS
=============================================================================

PURPOSE: Test SHA-256 file hash verification functionality.
These tests verify that:

1. File hashes are computed correctly using SHA-256
2. Hash mismatches are detected
3. Missing files are detected
4. File size mismatches are detected
5. Various file types are handled correctly
6. Large files and binary files work correctly

=============================================================================
"""
import hashlib
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
# SHA-256 HASH COMPUTATION TESTS
# =============================================================================

def test_sha256_hash_format():
    """
    TEST: File hash is in correct SHA-256 format.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        file_hash = verifier._compute_file_hash(policy_dir / "policy.yaml")

        assert file_hash.startswith("sha256:"), \
            f"Hash should start with sha256: got {file_hash}"

        hex_part = file_hash.replace("sha256:", "")
        assert len(hex_part) == 64, f"SHA-256 hex should be 64 chars, got {len(hex_part)}"

        # Verify it's valid hex
        int(hex_part, 16)

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_sha256_hash_correctness():
    """
    TEST: SHA-256 hash is computed correctly.
    """
    policy_dir = create_test_policy_dir()
    content = "rules:\n  - name: test-rule\n    action: block\n"

    try:
        create_policy_file(policy_dir, "policy.yaml", content)

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        computed_hash = verifier._compute_file_hash(policy_dir / "policy.yaml")

        # Compute expected hash
        expected = "sha256:" + hashlib.sha256(content.encode()).hexdigest()

        assert computed_hash == expected, \
            f"Hash mismatch: {computed_hash} != {expected}"

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_hash_deterministic():
    """
    TEST: Same file produces same hash each time.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))

        hash1 = verifier._compute_file_hash(policy_dir / "policy.yaml")
        hash2 = verifier._compute_file_hash(policy_dir / "policy.yaml")
        hash3 = verifier._compute_file_hash(policy_dir / "policy.yaml")

        assert hash1 == hash2 == hash3

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_different_content_different_hash():
    """
    TEST: Different content produces different hashes.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy1.yaml", "rules: [a]")
        create_policy_file(policy_dir, "policy2.yaml", "rules: [b]")

        verifier = CryptographicPolicyVerifier(str(policy_dir))

        hash1 = verifier._compute_file_hash(policy_dir / "policy1.yaml")
        hash2 = verifier._compute_file_hash(policy_dir / "policy2.yaml")

        assert hash1 != hash2

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# FILE MODIFICATION DETECTION TESTS
# =============================================================================

def test_modified_file_detected():
    """
    TEST: Modified file content is detected (hash mismatch).
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: [original]")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Modify the file
        create_policy_file(policy_dir, "policy.yaml", "rules: [modified]")

        try:
            verifier.verify()
            raise AssertionError("Modified file should be detected")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.FILE_HASH_MISMATCH
            assert "policy.yaml" in str(e)

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_single_byte_change_detected():
    """
    TEST: Even a single byte change is detected.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: [test]")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Change single byte
        create_policy_file(policy_dir, "policy.yaml", "rules: [tesT]")  # t -> T

        try:
            verifier.verify()
            raise AssertionError("Single byte change should be detected")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.FILE_HASH_MISMATCH

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_appended_content_detected():
    """
    TEST: Appended content is detected.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Append content
        with open(policy_dir / "policy.yaml", 'a') as f:
            f.write("\n# malicious comment")

        try:
            verifier.verify()
            raise AssertionError("Appended content should be detected")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.FILE_HASH_MISMATCH

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_truncated_file_detected():
    """
    TEST: Truncated file is detected.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: [one, two, three]")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Truncate file
        create_policy_file(policy_dir, "policy.yaml", "rules: [one")

        try:
            verifier.verify()
            raise AssertionError("Truncated file should be detected")
        except SecurityError as e:
            assert e.code in [SecurityErrorCode.FILE_HASH_MISMATCH,
                              SecurityErrorCode.FILE_SIZE_MISMATCH]

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_replaced_file_detected():
    """
    TEST: Completely replaced file is detected.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules:\n  - name: safe\n")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Replace with different content
        create_policy_file(policy_dir, "policy.yaml", "malicious:\n  - exploit: true\n")

        try:
            verifier.verify()
            raise AssertionError("Replaced file should be detected")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.FILE_HASH_MISMATCH

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# MISSING FILE TESTS
# =============================================================================

def test_missing_file_detected():
    """
    TEST: Missing file raises SecurityError.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Delete the file
        (policy_dir / "policy.yaml").unlink()

        try:
            verifier.verify()
            raise AssertionError("Missing file should be detected")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.FILE_MISSING
            assert "policy.yaml" in str(e)

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_one_of_many_missing():
    """
    TEST: One missing file among many is detected.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")
        create_policy_file(policy_dir, "budget.yaml", "limits: {}")
        create_policy_file(policy_dir, "security.yaml", "checks: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Delete just one
        (policy_dir / "budget.yaml").unlink()

        try:
            verifier.verify()
            raise AssertionError("Missing file should be detected")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.FILE_MISSING
            assert "budget.yaml" in str(e)

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_renamed_file_detected():
    """
    TEST: Renamed file is detected (original missing).
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Rename file
        (policy_dir / "policy.yaml").rename(policy_dir / "renamed.yaml")

        try:
            verifier.verify()
            raise AssertionError("Renamed file should be detected as missing")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.FILE_MISSING

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# FILE SIZE VERIFICATION TESTS
# =============================================================================

def test_file_size_mismatch_detected():
    """
    TEST: File size mismatch is detected.
    """
    policy_dir = create_test_policy_dir()

    try:
        original_content = "x" * 1000
        create_policy_file(policy_dir, "policy.yaml", original_content)

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Change content with different size
        new_content = "y" * 500
        create_policy_file(policy_dir, "policy.yaml", new_content)

        try:
            verifier.verify()
            raise AssertionError("Size mismatch should be detected")
        except SecurityError as e:
            # Could be either hash or size mismatch
            assert e.code in [SecurityErrorCode.FILE_HASH_MISMATCH,
                              SecurityErrorCode.FILE_SIZE_MISMATCH]

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_file_size_computed_correctly():
    """
    TEST: File size is computed correctly.
    """
    policy_dir = create_test_policy_dir()
    content = "rules: []\n"

    try:
        create_policy_file(policy_dir, "policy.yaml", content)

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        size = verifier._get_file_size(policy_dir / "policy.yaml")

        expected_size = len(content.encode('utf-8'))
        assert size == expected_size, f"Size mismatch: {size} != {expected_size}"

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# SPECIAL FILE CONTENT TESTS
# =============================================================================

def test_empty_file():
    """
    TEST: Empty file hash and verification works.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "empty.yaml", "")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        result = verifier.verify()
        assert result.verified == True

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_binary_content():
    """
    TEST: Binary file content is hashed correctly.
    """
    policy_dir = create_test_policy_dir()

    try:
        # Create file with binary content
        binary_content = bytes(range(256))
        with open(policy_dir / "binary.yaml", 'wb') as f:
            f.write(binary_content)

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        file_hash = verifier._compute_file_hash(policy_dir / "binary.yaml")

        expected = "sha256:" + hashlib.sha256(binary_content).hexdigest()
        assert file_hash == expected

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_unicode_content():
    """
    TEST: Unicode content is hashed correctly.
    """
    policy_dir = create_test_policy_dir()
    content = "rules:\n  - name: 日本語ルール\n  - emoji: 🔐🛡️\n"

    try:
        create_policy_file(policy_dir, "policy.yaml", content)

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        result = verifier.verify()
        assert result.verified == True

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_large_file():
    """
    TEST: Large file (1MB) is hashed correctly.
    """
    policy_dir = create_test_policy_dir()
    content = "x" * (1024 * 1024)  # 1MB

    try:
        create_policy_file(policy_dir, "large.yaml", content)

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        result = verifier.verify()
        assert result.verified == True

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_newline_variations():
    """
    TEST: Different newline styles are handled correctly.
    """
    policy_dir = create_test_policy_dir()

    try:
        # Unix style
        with open(policy_dir / "unix.yaml", 'wb') as f:
            f.write(b"rules:\n  - a\n  - b\n")

        # Windows style
        with open(policy_dir / "windows.yaml", 'wb') as f:
            f.write(b"rules:\r\n  - a\r\n  - b\r\n")

        verifier = CryptographicPolicyVerifier(str(policy_dir))

        hash_unix = verifier._compute_file_hash(policy_dir / "unix.yaml")
        hash_windows = verifier._compute_file_hash(policy_dir / "windows.yaml")

        # Hashes should be different (preserves exact bytes)
        assert hash_unix != hash_windows

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# SUPPORTED FILE TYPES TESTS
# =============================================================================

def test_yaml_files_included():
    """
    TEST: .yaml files are included in manifest.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()

        assert "policy.yaml" in manifest.files

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_yml_files_included():
    """
    TEST: .yml files are included in manifest.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()

        assert "policy.yml" in manifest.files

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_json_files_included():
    """
    TEST: .json files are included in manifest.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.json", '{"rules": []}')

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()

        assert "policy.json" in manifest.files

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_rego_files_included():
    """
    TEST: .rego files (OPA) are included in manifest.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.rego",
            "package scalpel\n\ndefault allow = false\n")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()

        assert "policy.rego" in manifest.files

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_unsupported_extensions_excluded():
    """
    TEST: Unsupported file extensions are excluded.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "readme.txt", "This is a readme")
        create_policy_file(policy_dir, "script.py", "print('hello')")
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()

        assert "policy.yaml" in manifest.files
        assert "readme.txt" not in manifest.files
        assert "script.py" not in manifest.files

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# MULTIPLE FILES TESTS
# =============================================================================

def test_multiple_files_all_verified():
    """
    TEST: All files in manifest are verified.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")
        create_policy_file(policy_dir, "budget.yaml", "limits: {}")
        create_policy_file(policy_dir, "security.json", '{"checks": []}')

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        result = verifier.verify()

        assert result.verified == True
        assert result.files_checked == 3
        assert len(result.file_results) == 3

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_partial_modification_detected():
    """
    TEST: Modification of one file among many is detected.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")
        create_policy_file(policy_dir, "budget.yaml", "limits: {}")
        create_policy_file(policy_dir, "security.yaml", "checks: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Modify just one file
        create_policy_file(policy_dir, "budget.yaml", "limits: {modified: true}")

        try:
            verifier.verify()
            raise AssertionError("Modified file should be detected")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.FILE_HASH_MISMATCH
            assert "budget.yaml" in str(e)

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# SECURITY ERROR DETAILS TESTS
# =============================================================================

def test_hash_mismatch_error_includes_details():
    """
    TEST: FILE_HASH_MISMATCH error includes expected and actual hashes.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "original")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        create_policy_file(policy_dir, "policy.yaml", "modified")

        try:
            verifier.verify()
            raise AssertionError("Should detect modification")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.FILE_HASH_MISMATCH
            assert "file" in e.details
            assert "expected_hash" in e.details
            assert "actual_hash" in e.details
            assert e.details["expected_hash"] != e.details["actual_hash"]

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_missing_file_error_includes_path():
    """
    TEST: FILE_MISSING error includes file path.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        (policy_dir / "policy.yaml").unlink()

        try:
            verifier.verify()
            raise AssertionError("Should detect missing file")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.FILE_MISSING
            assert "file" in e.details
            assert e.details["file"] == "policy.yaml"

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_file_hash_tests():
    """Run all file hash verification tests."""
    tests = [
        ("HASH-001", "SHA-256 hash format", test_sha256_hash_format),
        ("HASH-002", "SHA-256 hash correctness", test_sha256_hash_correctness),
        ("HASH-003", "Hash deterministic", test_hash_deterministic),
        ("HASH-004", "Different content different hash", test_different_content_different_hash),
        ("MOD-001", "Modified file detected", test_modified_file_detected),
        ("MOD-002", "Single byte change detected", test_single_byte_change_detected),
        ("MOD-003", "Appended content detected", test_appended_content_detected),
        ("MOD-004", "Truncated file detected", test_truncated_file_detected),
        ("MOD-005", "Replaced file detected", test_replaced_file_detected),
        ("MISSING-001", "Missing file detected", test_missing_file_detected),
        ("MISSING-002", "One of many missing", test_one_of_many_missing),
        ("MISSING-003", "Renamed file detected", test_renamed_file_detected),
        ("SIZE-001", "File size mismatch detected", test_file_size_mismatch_detected),
        ("SIZE-002", "File size computed correctly", test_file_size_computed_correctly),
        ("CONTENT-001", "Empty file", test_empty_file),
        ("CONTENT-002", "Binary content", test_binary_content),
        ("CONTENT-003", "Unicode content", test_unicode_content),
        ("CONTENT-004", "Large file", test_large_file),
        ("CONTENT-005", "Newline variations", test_newline_variations),
        ("EXT-001", "YAML files included", test_yaml_files_included),
        ("EXT-002", "YML files included", test_yml_files_included),
        ("EXT-003", "JSON files included", test_json_files_included),
        ("EXT-004", "Rego files included", test_rego_files_included),
        ("EXT-005", "Unsupported extensions excluded", test_unsupported_extensions_excluded),
        ("MULTI-001", "Multiple files all verified", test_multiple_files_all_verified),
        ("MULTI-002", "Partial modification detected", test_partial_modification_detected),
        ("ERR-001", "Hash mismatch error includes details", test_hash_mismatch_error_includes_details),
        ("ERR-002", "Missing file error includes path", test_missing_file_error_includes_path),
    ]

    print("=" * 70)
    print("FILE HASH VERIFICATION TESTS")
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
    run_file_hash_tests()
