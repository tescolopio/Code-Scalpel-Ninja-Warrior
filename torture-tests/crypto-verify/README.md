# Cryptographic Policy Verification Test Suite

Comprehensive test suite for Code Scalpel's **Cryptographic Policy Verification** feature - detecting unauthorized modifications to policy files using SHA-256 hashes and HMAC-signed manifests.

## Overview

The Cryptographic Policy Verification feature provides:
- **SHA-256 file hashing** for integrity verification
- **HMAC-SHA256 signed manifests** for tamper detection
- **Multiple manifest sources** (file, git, environment variable)
- **Unexpected file detection** to prevent policy injection attacks
- **Strict mode** for enterprise compliance

## Test Files

| File | Purpose | Test Count |
|------|---------|------------|
| `crypto_verify_framework.py` | Core CryptographicPolicyVerifier implementation | - |
| `test_manifest_signing.py` | Manifest creation and HMAC-SHA256 signing | 21 |
| `test_manifest_verification.py` | Manifest loading and signature verification | 20 |
| `test_file_hash_verification.py` | SHA-256 file hash verification | 28 |
| `test_unexpected_files.py` | Unexpected file detection and attack prevention | 19 |
| `test_admin_workflow.py` | Administrator workflow and key management | 17 |

**Total: 105 test cases**

## Manifest Schema

```json
{
  "version": "1.0",
  "created_at": "2025-12-19T14:30:00.000Z",
  "files": {
    "policy.yaml": {
      "hash": "sha256:a1b2c3d4e5f6...",
      "size": 2048
    },
    "budget.yaml": {
      "hash": "sha256:f6e5d4c3b2a1...",
      "size": 512
    }
  },
  "signature": "hmac-sha256:abcdef123456..."
}
```

## Verification Algorithm

```
1. Load manifest from file/git/env
2. Verify manifest HMAC signature
   → Invalid? SecurityError("Manifest signature invalid")
3. For each file in manifest:
   a. Check file exists → Missing? SecurityError
   b. Compute SHA-256 of current file
   c. Compare to manifest hash → Mismatch? SecurityError
4. Check for unexpected files in policy_dir
   → Found in strict mode? SecurityError("Unexpected policy file")
5. Return success
```

## Security Error Codes

| Code | Description |
|------|-------------|
| `MANIFEST_NOT_FOUND` | Manifest file missing |
| `MANIFEST_SIGNATURE_INVALID` | HMAC signature verification failed |
| `MANIFEST_PARSE_ERROR` | Invalid JSON in manifest |
| `MANIFEST_SCHEMA_INVALID` | Missing required fields |
| `FILE_MISSING` | Policy file in manifest not found |
| `FILE_HASH_MISMATCH` | SHA-256 hash doesn't match |
| `FILE_SIZE_MISMATCH` | File size doesn't match |
| `UNEXPECTED_FILE` | Policy file not in manifest |

## Administrator Workflow

### Initial Setup

```bash
# Set secret key
export SCALPEL_POLICY_SECRET="your-secret-key"

# Create and sign manifest
python -m code_scalpel.policy_engine.crypto_verify sign --policy-dir .code-scalpel

# Commit manifest
git add .code-scalpel/policy.manifest.json
git commit -m "Add signed policy manifest"
```

### Updating Policies

```bash
# Make policy changes
vim .code-scalpel/policy.yaml

# Re-sign
python -m code_scalpel.policy_engine.crypto_verify sign --policy-dir .code-scalpel

# Commit
git add .code-scalpel/policy.manifest.json
git commit -m "Update policy manifest"
```

### Key Rotation

```bash
# Switch to new key
export SCALPEL_POLICY_SECRET="new-secret-key"

# Re-sign all policies
python -m code_scalpel.policy_engine.crypto_verify sign --policy-dir .code-scalpel

# Commit and distribute new key to team
git add .code-scalpel/policy.manifest.json
git commit -m "Rotate policy signing key"
```

## Running Tests

```bash
cd torture-tests/crypto-verify

# Run individual test files
python test_manifest_signing.py
python test_manifest_verification.py
python test_file_hash_verification.py
python test_unexpected_files.py
python test_admin_workflow.py

# Run all tests
for f in test_*.py; do python "$f"; done
```

### Expected Output

```
======================================================================
MANIFEST SIGNING TESTS
======================================================================

✓ PASS: [CREATE-001] Sign creates manifest
✓ PASS: [CREATE-002] Manifest includes all files
✓ PASS: [SIG-001] Signature is HMAC-SHA256
...

Results: 21 passed, 0 failed
======================================================================
```

## Configuration

### Secret Key

Set the HMAC secret via environment variable:

```bash
export SCALPEL_POLICY_SECRET="your-secret-key"
```

If not set, a default secret is used (suitable for testing only).

### Manifest Sources

| Source | Description | Use Case |
|--------|-------------|----------|
| `file` | Load from `policy.manifest.json` | Default, local development |
| `git` | Load from last committed version | Detect local tampering |
| `env` | Load from `SCALPEL_POLICY_MANIFEST` env var (base64) | CI/CD pipelines |

### Strict Mode

| Mode | Behavior | Use Case |
|------|----------|----------|
| `strict=True` | Fail on unexpected files | Production, compliance |
| `strict=False` | Warn on unexpected files | Development, debugging |

## Integration Example

```python
from crypto_verify_framework import CryptographicPolicyVerifier, SecurityError

# Initialize verifier
verifier = CryptographicPolicyVerifier(
    policy_dir=".code-scalpel",
    manifest_source="file",
    strict_mode=True
)

# Verify policies
try:
    result = verifier.verify()
    print(f"✓ Verified {result.files_checked} policy files")
except SecurityError as e:
    print(f"✗ Security error: {e.code}")
    print(f"  Details: {e.details}")
```

## Attack Scenarios Tested

### Policy File Modification
- Single byte changes detected
- Appended content detected
- Truncated files detected
- Complete replacement detected

### Policy Injection
- Unexpected YAML files detected
- Unexpected JSON files detected
- Unexpected Rego files detected
- Hidden files handled appropriately

### Manifest Tampering
- Modified file hashes detected
- Modified file sizes detected
- Removed signatures detected
- Truncated signatures detected

### Key Compromise
- Different keys produce different signatures
- Old manifests fail with new keys
- Cross-instance verification works with same key

## Test Categories

### Manifest Signing Tests (21)
- Manifest creation and structure
- HMAC-SHA256 signature generation
- Secret key management
- Canonical JSON serialization

### Manifest Verification Tests (20)
- Signature verification
- Manifest loading from multiple sources
- Schema validation
- Cross-instance verification

### File Hash Verification Tests (28)
- SHA-256 hash computation
- File modification detection
- Missing file detection
- Various file types and content

### Unexpected File Detection Tests (19)
- Strict mode enforcement
- Non-strict mode warnings
- Attack scenario prevention
- Edge cases

### Administrator Workflow Tests (17)
- Initial setup workflows
- Policy update workflows
- Secret key rotation
- Error recovery
