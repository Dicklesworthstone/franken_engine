# Known Conformance Divergences

This document tracks all intentional divergences from the cd3d2b4d proof-artifact contract.

**Rule:** Every divergence gets a sequential ID (DISC-NNN) and must state whether ACCEPTED, INVESTIGATING, or WILL-FIX.

---

## DISC-001: Optional SHA256 for redaction policy artifacts
- **Contract expectation:** All generated artifacts have SHA256 hashes
- **Our implementation:** Redaction policy artifacts have `null` SHA256 hash
- **Impact:** Redaction policies are not hash-verified in the integrity chain
- **Resolution:** ACCEPTED — redaction policies are configuration, not runtime evidence
- **Why:** Redaction policies may be shared across multiple bundles and don't represent gate-specific evidence
- **How to apply:** Tests accept `null` SHA256 for artifacts with role "redaction_policy"
- **Tests affected:** hash_chain_integrity_validation, artifact_hash_test
- **Review date:** 2026-05-01

## DISC-002: Empty commands.txt accepted
- **Contract expectation:** Commands transcript should contain executed commands
- **Our implementation:** Empty commands.txt file with matching hash is valid
- **Impact:** Some bundles have no recorded command transcript
- **Resolution:** ACCEPTED — certain gates may not execute commands requiring transcript
- **Why:** Validation-only gates may analyze existing artifacts without executing new commands
- **How to apply:** Empty commands.txt with correct hash (empty file hash) is conformant
- **Tests affected:** bundle_structure_test, hash_chain_integrity_validation
- **Review date:** 2026-05-01

## DISC-003: Freshness validation lenient
- **Contract expectation:** Strict freshness validation on all bundles
- **Our implementation:** Freshness validation allows wider tolerance for test environments
- **Impact:** Test bundles may have relaxed freshness requirements
- **Resolution:** INVESTIGATING — may need stricter enforcement in production
- **Why:** Test environments need deterministic timestamps that may not reflect real generation time
- **How to apply:** Conformance tests use synthetic timestamps, production gates should use real-time validation
- **Tests affected:** manifest_required_fields_validation
- **Review date:** 2026-06-01

## Future Divergences

Additional intentional divergences will be documented here as they are discovered and approved.

### Template for New Divergences

```
## DISC-XXX: Brief description
- **Contract expectation:** What the spec says
- **Our implementation:** What we actually do
- **Impact:** Effect on interoperability/compliance
- **Resolution:** ACCEPTED/INVESTIGATING/WILL-FIX
- **Why:** Business/technical justification  
- **How to apply:** When this divergence applies
- **Tests affected:** List of test cases
- **Review date:** YYYY-MM-DD
```

---

## Review Schedule

This document should be reviewed quarterly to:
1. Re-evaluate INVESTIGATING items
2. Update review dates for ACCEPTED items  
3. Remove or archive WILL-FIX items that have been resolved
4. Assess if any ACCEPTED divergences have become problematic

**Next review:** 2026-08-01