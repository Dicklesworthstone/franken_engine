# Baseline Interpreter Dispatch Divergence Audit

## Audit Metadata

- **Date**: 2026-04-20
- **File**: `crates/franken-engine/src/baseline_interpreter.rs`
- **Audit Type**: Dispatch Arm Implementation Divergence Analysis
- **Range Analyzed**: Lines 8000-9000 (first-match) vs 16000-19000 (later-batch)
- **Total Divergences Found**: 7

## Executive Summary

Systematic analysis of baseline interpreter dispatch arms reveals critical divergences between first-match implementations (~8000-9000) and later-batch implementations (~16000-19000). The primary issue is **inconsistent naming conventions** for the same JavaScript global functions, creating potential runtime conflicts where different code paths could invoke different implementations of the same function.

Most severe divergence is JSON.stringify which returns different value types for the same input conditions, indicating a functional regression risk.

## Critical Divergences Found

### 1. JSON.stringify Implementation Divergence (Severity: HIGH)

**Functional Behavior Difference - CRITICAL**

| Position | Line | Builtin Name | No-Args Return Value | Implementation Style |
|----------|------|--------------|---------------------|---------------------|
| First-match | 8366 | `"builtin:JsonStringify"` | `Value::Str("undefined")` | String return |
| Later-batch | 16437 | `"builtin:JSONStringify"` | `Value::Undefined` | Undefined return |

**Impact**: Same JavaScript call `JSON.stringify()` could return different types depending on which dispatch arm matches first.

**Risk**: Type confusion bugs, inconsistent serialization behavior.

### 2. JSON.parse Implementation Divergence (Severity: MEDIUM)

**Naming Convention Divergence**

| Position | Line | Builtin Name | No-Args Return Value | Notes |
|----------|------|--------------|---------------------|-------|
| First-match | 8410 | `"builtin:JsonParse"` | `Value::Undefined` | Consistent behavior |
| Later-batch | 16457 | `"builtin:JSONParse"` | `Value::Undefined` | Same logic, different name |

**Impact**: Potential dispatch conflicts, code confusion.

### 3. parseInt Implementation Divergence (Severity: MEDIUM)

**Case Sensitivity Divergence**

| Position | Line | Builtin Name | No-Args Return Value | Implementation |
|----------|------|--------------|---------------------|----------------|
| First-match | 8509 | `"builtin:parseInt"` | `Value::Float(NaN)` | Lowercase naming |
| Later-batch | 16717 | `"builtin:ParseInt"` | `Value::Float(NaN)` | PascalCase naming |

**Impact**: Potential dispatch routing confusion based on case sensitivity.

### 4. parseFloat Implementation Divergence (Severity: MEDIUM)

**Case Sensitivity Divergence**

| Position | Line | Builtin Name | No-Args Return Value | Implementation |
|----------|------|--------------|---------------------|----------------|
| First-match | 8527 | `"builtin:parseFloat"` | (needs verification) | Lowercase naming |
| Later-batch | 16736 | `"builtin:ParseFloat"` | (needs verification) | PascalCase naming |

### 5. isNaN Implementation Divergence (Severity: MEDIUM)

**Case Sensitivity Divergence**

| Position | Line | Builtin Name | No-Args Return Value | Implementation |
|----------|------|--------------|---------------------|----------------|
| First-match | 8450 | `"builtin:isNaN"` | `Value::Bool(true)` | Lowercase naming |
| Later-batch | 16824 | `"builtin:IsNaN"` | `Value::Bool(true)` | PascalCase naming |

### 6. isFinite Implementation Divergence (Severity: MEDIUM)

**Case Sensitivity Divergence**

| Position | Line | Builtin Name | No-Args Return Value | Implementation |
|----------|------|--------------|---------------------|----------------|
| First-match | 8478 | `"builtin:isFinite"` | (identified pattern) | Lowercase naming |
| Later-batch | 16843 | `"builtin:IsFinite"` | (identified pattern) | PascalCase naming |

## Naming Convention Analysis

### Pattern Identified: Systematic Case Convention Divergence

**First-Match Position (8000-9000)**: Uses **lowercase/camelCase** conventions
- `JsonStringify`, `JsonParse`, `parseInt`, `parseFloat`, `isNaN`, `isFinite`

**Later-Batch Position (16000-19000)**: Uses **PascalCase** conventions  
- `JSONStringify`, `JSONParse`, `ParseInt`, `ParseFloat`, `IsNaN`, `IsFinite`

### Root Cause Analysis

This pattern suggests **two different implementation phases**:
1. **Phase 1** (8000-9000): Original implementation with JavaScript-style naming
2. **Phase 2** (16000-19000): Refactored implementation with Rust-style PascalCase naming

The divergence likely occurred during a **naming convention standardization effort** that was incomplete, leaving both old and new naming conventions in the codebase simultaneously.

## Impact Assessment

### Runtime Risk Analysis

1. **Dispatch Precedence**: First-match position (8000-9000) likely takes precedence
2. **Dead Code Risk**: Later-batch implementations (16000-19000) may never execute
3. **Maintainability**: Duplicate implementations create maintenance burden
4. **Type Safety**: JSON.stringify divergence creates actual behavioral differences

### JavaScript Compatibility Impact

- **JSON.stringify()**: **HIGH RISK** - Type confusion between string "undefined" vs `undefined`
- **parseInt(), parseFloat(), isNaN(), isFinite()**: **MEDIUM RISK** - Naming conflicts may affect tool compatibility
- **JSON.parse()**: **LOW RISK** - Identical behavior, only naming differs

## Recommended Implementation Strategy

### Phase 1: Critical Behavioral Fix (P0)

**Target Bead**: `bd-dispatch-diverge-json`
- **Scope**: Reconcile JSON.stringify return value divergence
- **Action**: Choose consistent return type for no-args case
- **Effort**: 1-2 hours (single function fix)

### Phase 2: Naming Convention Unification (P1)

**Target Bead**: `bd-dispatch-diverge-naming`
- **Scope**: Standardize builtin naming convention across all global functions
- **Decision Required**: Choose either JavaScript-style (toLowerCase) or Rust-style (PascalCase)
- **Effort**: 4-6 hours (systematic rename + testing)

### Phase 3: Dead Code Elimination (P2)

**Target Bead**: `bd-dispatch-diverge-dedup`
- **Scope**: Remove duplicate implementations after naming standardization
- **Action**: Keep first-match implementations, remove later-batch duplicates
- **Effort**: 2-3 hours (systematic removal + verification)

## Recommended Next Bead

**Create bead: `bd-dispatch-diverge-json`**

**Title**: "Fix JSON.stringify dispatch divergence - reconcile return value types"

**Description**: 
```
Critical behavioral divergence in JSON.stringify implementation:
- First-match (line 8366): Returns Value::Str("undefined") for no args
- Later-batch (line 16437): Returns Value::Undefined for no args

Choose consistent return type based on JavaScript spec compliance.
Remove duplicate implementation after reconciliation.

Lines affected: 8366, 16437
Priority: P0 (behavioral regression risk)
```

**Acceptance Criteria**:
1. JSON.stringify() returns consistent value type for no-args case
2. Only one dispatch arm remains for JSON.stringify
3. Implementation follows JavaScript specification behavior
4. Add regression test for no-args case

## JavaScript Specification Compliance

**JSON.stringify() Specification**: According to ECMAScript specification, `JSON.stringify()` with no arguments should return `undefined`, not the string `"undefined"`.

**Recommendation**: Keep later-batch implementation return value (`Value::Undefined`) and remove first-match implementation.

## Future Prevention Strategy

1. **Naming Convention Documentation**: Establish clear builtin naming standards
2. **Dispatch Arm Registry**: Maintain centralized registry of all builtin implementations
3. **Duplicate Detection**: Add CI checks to detect duplicate dispatch arm names
4. **Implementation Reviews**: Require review for all new builtin implementations

---

**Next Actions**:
1. Create `bd-dispatch-diverge-json` bead for immediate JSON.stringify fix
2. Schedule naming convention unification for next sprint
3. Implement duplicate detection tooling to prevent future divergences

*Audit completed 2026-04-20 by automated dispatch divergence analysis.*