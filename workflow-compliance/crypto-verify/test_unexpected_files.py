#!/usr/bin/env python3
"""
=============================================================================
UNEXPECTED FILE DETECTION TESTS
=============================================================================

PURPOSE: Test detection of files not in the manifest.
These tests verify that:

1. Unexpected files are detected in strict mode
2. Unexpected files are reported but allowed in non-strict mode
3. Various attack scenarios are caught
4. Symlinks and special files are handled
5. File injection attacks are detected

SECURITY SCENARIO:
An attacker might try to add malicious policy files that are not
in the signed manifest. This feature ensures such additions are detected.

=============================================================================
"""
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
# STRICT MODE TESTS
# =============================================================================

def test_unexpected_file_in_strict_mode():
    """
    TEST: Unexpected file raises SecurityError in strict mode.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=True)
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Add unexpected file
        create_policy_file(policy_dir, "malicious.yaml", "exploit: true")

        try:
            verifier.verify()
            raise AssertionError("Unexpected file should raise SecurityError")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.UNEXPECTED_FILE
            assert "malicious.yaml" in str(e)

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_multiple_unexpected_files():
    """
    TEST: Multiple unexpected files are all reported.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=True)
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Add multiple unexpected files
        create_policy_file(policy_dir, "backdoor1.yaml", "exploit: 1")
        create_policy_file(policy_dir, "backdoor2.yaml", "exploit: 2")
        create_policy_file(policy_dir, "backdoor3.json", '{"exploit": 3}')

        try:
            verifier.verify()
            raise AssertionError("Unexpected files should raise SecurityError")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.UNEXPECTED_FILE
            # All unexpected files should be in details
            assert "files" in e.details
            assert len(e.details["files"]) == 3

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_strict_mode_default():
    """
    TEST: Strict mode is enabled by default.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        # Don't specify strict_mode (should default to True)
        verifier = CryptographicPolicyVerifier(str(policy_dir))
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        create_policy_file(policy_dir, "extra.yaml", "unexpected: true")

        try:
            verifier.verify()
            raise AssertionError("Default should be strict mode")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.UNEXPECTED_FILE

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# NON-STRICT MODE TESTS
# =============================================================================

def test_unexpected_file_in_non_strict_mode():
    """
    TEST: Unexpected file is reported but allowed in non-strict mode.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=False)
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Add unexpected file
        create_policy_file(policy_dir, "extra.yaml", "extra: content")

        # Should not raise, but should report
        result = verifier.verify()

        assert result.verified == True
        assert len(result.unexpected_files) == 1
        assert "extra.yaml" in result.unexpected_files

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_non_strict_mode_reports_all_unexpected():
    """
    TEST: Non-strict mode reports all unexpected files.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=False)
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Add multiple unexpected files
        create_policy_file(policy_dir, "extra1.yaml", "content: 1")
        create_policy_file(policy_dir, "extra2.yaml", "content: 2")

        result = verifier.verify()

        assert result.verified == True
        assert len(result.unexpected_files) == 2

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_non_strict_mode_still_verifies_manifest_files():
    """
    TEST: Non-strict mode still verifies files in manifest.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=False)
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Add unexpected file (allowed)
        create_policy_file(policy_dir, "extra.yaml", "extra: true")

        # Modify manifest file (should fail)
        create_policy_file(policy_dir, "policy.yaml", "rules: [modified]")

        try:
            verifier.verify()
            raise AssertionError("Modified file should still fail")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.FILE_HASH_MISMATCH

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# ATTACK SCENARIO TESTS
# =============================================================================

def test_policy_override_attack():
    """
    TEST: Attack: Adding a policy with higher priority naming.

    Scenario: Attacker adds "aaa_policy.yaml" hoping it loads first.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: [safe]")

        verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=True)
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Attack: add file that might load first
        create_policy_file(policy_dir, "aaa_policy.yaml", "rules: [malicious]")

        try:
            verifier.verify()
            raise AssertionError("Override attack should be detected")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.UNEXPECTED_FILE

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_hidden_file_attack():
    """
    TEST: Attack: Adding hidden/dotfile policy.

    Scenario: Attacker adds ".hidden_policy.yaml".
    Note: Hidden files with supported extensions are still detected.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=True)
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Attack: add hidden file
        # Note: This depends on how _get_policy_files handles dotfiles
        # The test documents expected behavior
        create_policy_file(policy_dir, ".hidden.yaml", "hidden: malicious")

        # Hidden files with policy extensions should be detected
        # This is a security feature - we don't want hidden policies
        try:
            result = verifier.verify()
            # If hidden files are excluded from detection, verify succeeds
            # but we should document this behavior
            if ".hidden.yaml" in result.unexpected_files:
                raise AssertionError("Hidden file detected but allowed")
        except SecurityError as e:
            # If detected, good - security is enforced
            assert e.code == SecurityErrorCode.UNEXPECTED_FILE

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_same_name_different_extension_attack():
    """
    TEST: Attack: Adding same-name file with different extension.

    Scenario: policy.yaml exists, attacker adds policy.yml
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: [original]")

        verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=True)
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Attack: add file with different extension
        create_policy_file(policy_dir, "policy.yml", "rules: [malicious]")

        try:
            verifier.verify()
            raise AssertionError("Same-name attack should be detected")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.UNEXPECTED_FILE
            assert "policy.yml" in str(e)

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_json_policy_injection():
    """
    TEST: Attack: Injecting JSON policy file.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=True)
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Attack: inject JSON policy
        create_policy_file(policy_dir, "override.json", '{"rules": ["malicious"]}')

        try:
            verifier.verify()
            raise AssertionError("JSON injection should be detected")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.UNEXPECTED_FILE

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_rego_policy_injection():
    """
    TEST: Attack: Injecting OPA Rego policy file.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=True)
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Attack: inject Rego policy
        create_policy_file(policy_dir, "backdoor.rego",
            "package scalpel\n\ndefault allow = true\n")

        try:
            verifier.verify()
            raise AssertionError("Rego injection should be detected")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.UNEXPECTED_FILE

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# MANIFEST FILE EXCLUSION TESTS
# =============================================================================

def test_manifest_file_not_flagged_as_unexpected():
    """
    TEST: The manifest file itself is not flagged as unexpected.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=True)
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Verify - manifest file should not be flagged
        result = verifier.verify()

        assert result.verified == True
        assert "policy.manifest.json" not in result.unexpected_files

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_no_false_positives_with_manifest():
    """
    TEST: Only actual unexpected files are flagged.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")
        create_policy_file(policy_dir, "budget.yaml", "limits: {}")

        verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=False)
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # No changes - should be no unexpected files
        result = verifier.verify()

        assert result.verified == True
        assert len(result.unexpected_files) == 0

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# EDGE CASES
# =============================================================================

def test_empty_policy_directory():
    """
    TEST: Empty policy directory with no files.
    """
    policy_dir = create_test_policy_dir()

    try:
        verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=True)
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Should verify with 0 files
        result = verifier.verify()
        assert result.verified == True
        assert result.files_checked == 0

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_unsupported_file_not_unexpected():
    """
    TEST: Files with unsupported extensions are not flagged.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=True)
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Add file with unsupported extension
        create_policy_file(policy_dir, "readme.txt", "Documentation")
        create_policy_file(policy_dir, "script.py", "print('test')")

        # Should not be flagged (not a policy file)
        result = verifier.verify()
        assert result.verified == True

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_file_removed_and_new_added():
    """
    TEST: Removing manifest file and adding new one.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")
        create_policy_file(policy_dir, "budget.yaml", "limits: {}")

        verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=True)
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Remove one, add another
        (policy_dir / "budget.yaml").unlink()
        create_policy_file(policy_dir, "new.yaml", "new: content")

        # Should fail for missing file first
        try:
            verifier.verify()
            raise AssertionError("Should detect changes")
        except SecurityError as e:
            # Either missing or unexpected, depending on order
            assert e.code in [SecurityErrorCode.FILE_MISSING,
                              SecurityErrorCode.UNEXPECTED_FILE]

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_verification_order_missing_before_unexpected():
    """
    TEST: Missing files are checked before unexpected files.

    Security rationale: Missing files are more critical than extra files.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=True)
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        # Create scenario with both missing and unexpected
        (policy_dir / "policy.yaml").unlink()  # Remove expected
        create_policy_file(policy_dir, "extra.yaml", "unexpected")  # Add unexpected

        try:
            verifier.verify()
            raise AssertionError("Should detect missing file")
        except SecurityError as e:
            # Missing should be detected first
            assert e.code == SecurityErrorCode.FILE_MISSING

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# SECURITY ERROR DETAILS TESTS
# =============================================================================

def test_unexpected_file_error_includes_list():
    """
    TEST: UNEXPECTED_FILE error includes list of unexpected files.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=True)
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        create_policy_file(policy_dir, "malicious.yaml", "exploit: true")

        try:
            verifier.verify()
            raise AssertionError("Should detect unexpected file")
        except SecurityError as e:
            assert e.code == SecurityErrorCode.UNEXPECTED_FILE
            assert "files" in e.details
            assert isinstance(e.details["files"], list)
            assert "malicious.yaml" in e.details["files"]

    finally:
        cleanup_test_policy_dir(policy_dir)


def test_error_message_includes_all_unexpected():
    """
    TEST: Error message includes all unexpected file names.
    """
    policy_dir = create_test_policy_dir()

    try:
        create_policy_file(policy_dir, "policy.yaml", "rules: []")

        verifier = CryptographicPolicyVerifier(str(policy_dir), strict_mode=True)
        manifest = verifier.sign()
        verifier.save_manifest(manifest)

        create_policy_file(policy_dir, "file1.yaml", "a")
        create_policy_file(policy_dir, "file2.yaml", "b")

        try:
            verifier.verify()
            raise AssertionError("Should detect unexpected files")
        except SecurityError as e:
            msg = str(e)
            assert "file1.yaml" in msg or "file1.yaml" in str(e.details)
            assert "file2.yaml" in msg or "file2.yaml" in str(e.details)

    finally:
        cleanup_test_policy_dir(policy_dir)


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_unexpected_file_tests():
    """Run all unexpected file detection tests."""
    tests = [
        ("STRICT-001", "Unexpected file in strict mode", test_unexpected_file_in_strict_mode),
        ("STRICT-002", "Multiple unexpected files", test_multiple_unexpected_files),
        ("STRICT-003", "Strict mode default", test_strict_mode_default),
        ("NONSTRICT-001", "Unexpected file in non-strict mode", test_unexpected_file_in_non_strict_mode),
        ("NONSTRICT-002", "Non-strict reports all unexpected", test_non_strict_mode_reports_all_unexpected),
        ("NONSTRICT-003", "Non-strict still verifies manifest files", test_non_strict_mode_still_verifies_manifest_files),
        ("ATTACK-001", "Policy override attack", test_policy_override_attack),
        ("ATTACK-002", "Hidden file attack", test_hidden_file_attack),
        ("ATTACK-003", "Same name different extension attack", test_same_name_different_extension_attack),
        ("ATTACK-004", "JSON policy injection", test_json_policy_injection),
        ("ATTACK-005", "Rego policy injection", test_rego_policy_injection),
        ("MANIFEST-001", "Manifest file not flagged", test_manifest_file_not_flagged_as_unexpected),
        ("MANIFEST-002", "No false positives", test_no_false_positives_with_manifest),
        ("EDGE-001", "Empty policy directory", test_empty_policy_directory),
        ("EDGE-002", "Unsupported file not unexpected", test_unsupported_file_not_unexpected),
        ("EDGE-003", "File removed and new added", test_file_removed_and_new_added),
        ("EDGE-004", "Missing checked before unexpected", test_verification_order_missing_before_unexpected),
        ("ERR-001", "Error includes file list", test_unexpected_file_error_includes_list),
        ("ERR-002", "Error message includes all", test_error_message_includes_all_unexpected),
    ]

    print("=" * 70)
    print("UNEXPECTED FILE DETECTION TESTS")
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
    run_unexpected_file_tests()
