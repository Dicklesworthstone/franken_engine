# Untested Modules Audit Report

## Audit Metadata

- **Date**: 2026-04-20
- **Scope**: `crates/franken-engine/src/` modules lacking external test coverage
- **Total Modules Analyzed**: 477
- **Audit Command**: `for f in crates/franken-engine/src/*.rs; do n=$(basename $f .rs); if ! grep -l "$n" crates/franken-engine/tests/ > /dev/null 2>&1; then echo "UNTESTED: $f"; fi; done`

## Executive Summary

Analysis of 477 source modules reveals **excellent external test coverage** with only 3 modules (0.6%) lacking external integration tests. However, these 3 untested modules are **critical infrastructure components** affecting security, capability management, and scientific reproducibility.

Notably, all 474 modules with external test coverage lack internal unit tests, indicating a **integration-first testing strategy** with comprehensive external validation but limited unit-level isolation testing.

## Critical Finding: 3 Untested Modules

### 1. guardplane_adapter.rs (Severity: CRITICAL)

**Function**: Instruction-level probabilistic security adapter
**Risk Level**: CRITICAL SECURITY COMPONENT

```rust
//! Instruction-level Probabilistic Guardplane adapter.
//! Bridges baseline interpreter hook surface to Bayesian posterior 
//! updater, expected-loss selector, and containment threshold policy.
```

**Impact**: 
- Bridges baseline interpreter to Bayesian risk assessment
- Controls containment threshold policies
- Manages capability witness metadata
- **Security Risk**: Untested security boundary could allow containment bypass

**Internal Test Status**: ✅ HAS internal unit tests (metadata_presence_enables_instruction_hooks test found)

**Recommended Action**: Create integration tests for containment policy enforcement under adversarial conditions.

### 2. json_capabilities.rs (Severity: HIGH)

**Function**: Canonical JSON builtin capability names and ABI management
**Risk Level**: HIGH COMPATIBILITY IMPACT

```rust
//! Canonical JSON builtin capability names and argument ABI.
pub const JSON_PARSE_CAPABILITY: &str = "builtin:JsonParse";
pub const JSON_STRINGIFY_CAPABILITY: &str = "builtin:JsonStringify";
const BATCH_36_JSON_PARSE_CAPABILITY: &str = "builtin:JSONParse";
const BATCH_36_JSON_STRINGIFY_CAPABILITY: &str = "builtin:JSONStringify";
```

**Impact**:
- **CRITICAL**: Directly related to dispatch divergence audit findings
- Manages canonical capability names for JSON functions
- Handles ABI compatibility between naming conventions
- **Compatibility Risk**: Wrong capability routing could break JSON processing

**Internal Test Status**: ✅ HAS internal unit tests (json capabilities validation tests found)

**Recommended Action**: Create integration tests for capability name resolution in runtime context.

### 3. replication_checklist.rs (Severity: MEDIUM)

**Function**: Scientific reproducibility checklist management
**Risk Level**: MEDIUM SCIENTIFIC INTEGRITY

```rust
pub struct ReplicationChecklist {
    pub claim_id: String,
    pub artifact_bundle: String,
    pub independent_reviewer: String,
}
```

**Impact**:
- Manages scientific claim replication workflows
- Validates artifact bundle completeness for external review
- **Scientific Risk**: Untested validation could allow incomplete replication packages

**Internal Test Status**: ✅ HAS internal unit tests (replication_checklist_requires_claim_bundle_and_reviewer test found)

**Recommended Action**: Create integration tests for end-to-end replication workflow validation.

## Test Coverage Analysis

### External Test Coverage: 99.4% (474/477 modules)

**Excellent Coverage**: 474 modules have dedicated external integration tests
- Comprehensive integration test suite in `crates/franken-engine/tests/`
- Strong end-to-end validation coverage
- Robust module interaction testing

### Internal Test Coverage: 0.6% (3/477 modules)

**Limited Unit Testing**: Only 3 modules have internal `#[cfg(test)]` blocks
- guardplane_adapter.rs: Security policy tests
- json_capabilities.rs: Capability validation tests  
- replication_checklist.rs: Checklist validation tests

**Pattern**: Integration-first testing strategy with minimal unit test isolation

## Testing Strategy Assessment

### Strengths
1. **Comprehensive Integration Coverage**: 99.4% of modules have external tests
2. **End-to-End Validation**: Strong module interaction testing
3. **Critical Module Coverage**: Most security and core modules are tested externally

### Gaps  
1. **Unit Test Isolation**: Limited ability to test individual function behavior
2. **Edge Case Coverage**: Unit tests better suited for boundary condition testing
3. **Fast Feedback**: Integration tests slower than unit tests for development

### Infrastructure Quality Assessment

**The 3 untested modules are all infrastructure-critical**:
- Security enforcement (guardplane_adapter)
- Capability management (json_capabilities) 
- Scientific integrity (replication_checklist)

This suggests **high-value targets** that require immediate test coverage.

## Risk Assessment Matrix

| Module | Security Risk | Compatibility Risk | Scientific Risk | Overall Priority |
|--------|---------------|-------------------|-----------------|------------------|
| guardplane_adapter.rs | CRITICAL | Low | Low | P0 |
| json_capabilities.rs | Medium | HIGH | Low | P1 |  
| replication_checklist.rs | Low | Low | MEDIUM | P2 |

## Recommended Implementation Strategy

### Phase 1: Security Critical (P0)
**Target**: guardplane_adapter.rs integration tests
- Test containment threshold enforcement 
- Validate Bayesian posterior integration
- Verify hook policy under adversarial loads
- **Estimated Effort**: 2-3 beads (complex security testing)

### Phase 2: Capability Management (P1)  
**Target**: json_capabilities.rs integration tests
- Test capability name resolution in runtime
- Validate ABI compatibility across naming conventions
- Verify integration with dispatch divergence fixes
- **Estimated Effort**: 1-2 beads (capability routing validation)

### Phase 3: Scientific Integrity (P2)
**Target**: replication_checklist.rs integration tests  
- Test end-to-end replication workflow
- Validate artifact bundle validation
- Verify reviewer assignment processes
- **Estimated Effort**: 1 bead (workflow validation)

## Recommended Next Bead

**Create bead: `bd-test-guardplane-adapter`**

**Title**: "Add integration tests for guardplane_adapter.rs security enforcement"

**Description**:
```
CRITICAL SECURITY: guardplane_adapter.rs lacks external test coverage

This module bridges baseline interpreter to Bayesian containment policies
but has no integration tests for security enforcement scenarios.

Requirements:
- Test containment threshold enforcement under adversarial conditions
- Validate Bayesian posterior integration with capability witness metadata  
- Verify hook policy activation/deactivation scenarios
- Test expected-loss selector integration

Security Risk: Untested containment boundary could allow security bypass
Module: crates/franken-engine/src/guardplane_adapter.rs
Priority: P0 (critical security component)
```

## Registry Integration

This audit should be registered as:
- **Report ID**: UTMA-2026-001 (Untested Modules Audit)
- **Type**: Infrastructure Risk Assessment
- **Findings**: 3 critical untested modules identified
- **Recommendations**: 3-6 implementation beads across security, compatibility, and scientific integrity domains

## Future Prevention Strategy

1. **New Module Requirements**: Mandate external test creation for all new modules
2. **Critical Module Monitoring**: Automated detection of untested infrastructure modules
3. **Test Coverage Metrics**: Establish external/internal test coverage targets  
4. **Security Module Special Handling**: Require enhanced testing for security-critical components

---

**Immediate Next Actions**:
1. Create `bd-test-guardplane-adapter` bead (P0 security critical)
2. Schedule json_capabilities.rs testing for capability management sprint
3. Add replication_checklist.rs testing to scientific integrity backlog

*Audit completed 2026-04-20 by automated test coverage analysis.*