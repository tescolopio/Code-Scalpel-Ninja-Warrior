# Code Scalpel Configuration Directory

This directory contains configuration files for Code Scalpel policy engine and governance features.

## Files

- `policy.yaml` - Main policy configuration (security rules, enforcement mode)
- `budget.yaml` - Change budget limits (blast radius control)
- `policy.manifest.json` - Signed manifest for tamper detection (optional)
- `audit.log` - Audit trail of policy decisions (auto-generated)
- `autonomy_audit/` - Autonomy engine audit logs (auto-generated)

## Getting Started

1. **Review `policy.yaml`** - Configure security rules and enforcement mode
2. **Review `budget.yaml`** - Set change budget limits (optional)
3. **Enable audit logging** - Track all policy decisions

## Documentation

- [Policy Engine Guide](https://github.com/tescolopio/code-scalpel/blob/main/docs/policy_engine_guide.md)
- [Change Budgeting Guide](https://github.com/tescolopio/code-scalpel/blob/main/docs/guides/change_budgeting.md)
- [Tamper Resistance](https://github.com/tescolopio/code-scalpel/blob/main/docs/security/tamper_resistance.md)

## Cryptographic Verification (Optional)

To enable tamper-resistant policies:

```bash
# Generate signed manifest
code-scalpel policy sign

# Verify integrity
code-scalpel policy verify
```

Learn more: https://github.com/tescolopio/code-scalpel
