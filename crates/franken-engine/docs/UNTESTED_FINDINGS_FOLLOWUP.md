# Untested Findings Followup - Review Beads Created

## Summary

Following the untested modules audit (commit 1c96cff3), three critical review beads have been created to address the highest-priority testing gaps in infrastructure-critical modules.

## Created Review Beads

### 1. Security Critical (P1)
**Bead ID**: `bd-3lwu2`
**Title**: [review][guardplane_adapter] Add integration tests for security enforcement and containment policy validation
**Risk Level**: CRITICAL SECURITY
**Module**: `crates/franken-engine/src/guardplane_adapter.rs`
**Gap**: Untested security boundary could allow containment bypass

### 2. Compatibility Critical (P1)  
**Bead ID**: `bd-2pepu`
**Title**: [review][json_capabilities] Add integration tests for capability name resolution and ABI compatibility
**Risk Level**: HIGH COMPATIBILITY  
**Module**: `crates/franken-engine/src/json_capabilities.rs`
**Gap**: Directly related to dispatch divergence findings - untested capability routing

### 3. Scientific Integrity (P1)
**Bead ID**: `bd-1jmzj`
**Title**: [review][replication_checklist] Add integration tests for scientific reproducibility workflow validation
**Risk Level**: MEDIUM SCIENTIFIC
**Module**: `crates/franken-engine/src/replication_checklist.rs`
**Gap**: Untested validation could allow incomplete replication packages

## Implementation Priority

1. **bd-3lwu2** (Security): Immediate priority - containment boundary testing
2. **bd-2pepu** (Compatibility): High priority - JSON capability routing validation  
3. **bd-1jmzj** (Scientific): Medium priority - replication workflow integrity

## Validation Status

- **Cargo Check**: Executed `cargo check --lib` - compilation validated
- **Bead Creation**: All 3 beads successfully created with P1 priority
- **Review Type**: All beads tagged with `[review]` prefix for infrastructure testing

---

*Created 2026-04-20 following untested modules audit findings.*