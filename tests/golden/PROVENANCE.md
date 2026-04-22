# Golden File Provenance

This directory contains golden artifact files that lock down the deterministic behavior of decode/encode operations.

## Generation

Generated with:
```bash
UPDATE_GOLDENS=1 cargo test decode_golden_artifacts --lib
```

## Environment

- **Date:** 2026-04-22
- **Rust version:** nightly-x86_64-unknown-linux-gnu
- **Engine crate:** frankenengine-engine v0.1.0
- **Generator:** decode_golden_artifacts.rs

## Golden Files

| File | Test | Purpose |
|------|------|---------|
| `decode_encode_roundtrip.golden` | `test_decode_encode_roundtrip_golden` | Locks down encode/decode roundtrip behavior for synthetic values |
| `malformed_input_behavior.golden` | `test_malformed_input_behavior_golden` | Ensures consistent error handling for malformed inputs |
| `schema_hash_determinism.golden` | `test_schema_hash_determinism_golden` | Verifies deterministic schema hash computation |

## Review Notes

All golden files were generated from deterministic test inputs (fixed seeds, known malformed inputs, predefined schemas). No dynamic values like timestamps or UUIDs are included.

## Update Workflow

To update goldens after intentional changes:
```bash
UPDATE_GOLDENS=1 cargo test decode_golden_artifacts --lib
git diff tests/golden/
# Review ALL changes before committing
git add tests/golden/
git commit -m "Update decode goldens: [reason for change]"
```