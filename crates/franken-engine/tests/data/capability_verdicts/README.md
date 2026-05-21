# Capability Verdicts Test Fixtures

## Purpose
Test fixtures containing recorded capability test verdicts for regression testing. Referenced by:
- PP.4 negative test (prior capability test verdicts must remain unchanged after algebraic effects refactor)

## Contents
- `verdict_001_compute_only.json`: Compute-only capability profile verdict
- `verdict_002_filesystem_read.json`: Filesystem read capability verdict
- `verdict_003_network_access.json`: Network access capability verdict
- `verdict_004_capability_escalation.json`: Capability escalation attempt verdict
- `verdict_005_mixed_capabilities.json`: Mixed capability profile verdict

## Generation
These verdicts are captured from prior CI runs of the capability_profile_security_algebra test suite.
They represent the baseline behavior that must be preserved byte-for-byte after the algebraic effects refactor.

## Critical Note
These fixtures represent the CURRENT implementation behavior, not the specification.
If the prior implementation had bugs, those bugs become the specification for regression testing.
The Track G formal proof and metamorphic testing should catch genuine spec violations.

## Validation
Content hashes are recorded in `fixture_manifest.json`.
Any change to these files indicates a regression in the algebraic effects refactor.

## Schema Compliance
All verdicts conform to the capability verdict schema used by the security algebra tests.