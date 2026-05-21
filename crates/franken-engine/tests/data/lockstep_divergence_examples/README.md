# Lockstep Divergence Examples Test Fixtures

## Purpose
Test fixtures for lockstep oracle divergence analysis. Referenced by:
- I.6 operator runbook (lockstep oracle divergence triage operator surface)

## Contents
- `divergence_001_floating_point.json`: Floating point precision divergence
- `divergence_002_timing_dependent.json`: Timing-dependent execution divergence
- `divergence_003_memory_layout.json`: Memory layout difference divergence
- `divergence_004_optimization_level.json`: Compiler optimization level divergence
- `divergence_005_platform_specific.json`: Platform-specific behavior divergence

## Generation
These examples capture real divergence scenarios detected by the lockstep oracle.
Each example includes the divergence point, root cause analysis, and triage guidance.

## Operator Triage
Each divergence example includes:
- Divergence signature and detection metadata
- Root cause classification
- Severity assessment
- Recommended operator action
- Escalation criteria

## Validation
Content hashes are recorded in `fixture_manifest.json`.
Examples are validated for completeness and operator readability.