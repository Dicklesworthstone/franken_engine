# Proof Bundle Specimens Test Fixtures

## Purpose
Test fixtures containing proof bundle specimens for validation testing. Referenced by:
- Y.4 operator runbook tests

## Contents
- `bundle_001_complete.tar.gz`: Complete valid proof bundle
- `bundle_002_incomplete.tar.gz`: Incomplete bundle missing artifacts
- `bundle_003_corrupted_manifest.tar.gz`: Bundle with corrupted manifest
- `bundle_004_invalid_signatures.tar.gz`: Bundle with invalid signatures
- `bundle_005_mixed_epochs.tar.gz`: Bundle spanning multiple security epochs

## Generation
These specimens are captured from actual proof bundle generation runs.
They represent the variety of bundle states that operators may encounter.

## Bundle Validation
Each specimen includes:
- Bundle metadata and provenance information
- Artifact inventory and content hashes
- Signature chains and verification data
- Validation status and any detected issues

## Operator Testing
Specimens are used to test operator procedures for:
- Bundle integrity verification
- Signature validation workflows
- Corruption detection and recovery
- Escalation procedures for invalid bundles

## Validation
Content hashes are recorded in `fixture_manifest.json`.
Bundles are validated for format compliance and test coverage.