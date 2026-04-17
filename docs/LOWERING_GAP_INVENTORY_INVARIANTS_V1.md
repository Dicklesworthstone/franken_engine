# Lowering Gap Inventory Invariants V1

Status: active
Primary bead: bd-2muur.4.1
Track id: RGC-920D.1
Implementation beads: bd-2muur.4.2, bd-2muur.4.3

## Purpose

This document defines the invariant relationship between lowering status fields and execution-readiness flags in the lowering gap inventory system.

## Core Invariant

The relationship between `LoweringGapStatus` and `execution_ready_semantics` must be consistent and deterministic:

```rust
pub const fn execution_ready_semantics(self) -> bool {
    matches!(self.status(), LoweringGapStatus::Resolved)
}
```

## Status-to-Readiness Mapping

| Status | execution_ready_semantics | parser_ready_syntax | Meaning |
|--------|--------------------------|-------------------|----------|
| `Resolved` | `true` | `true` | Site is fully implemented and ready for execution |
| `OpenPlaceholder` | `false` | `true` | Parser handles syntax but lowering emits placeholder |
| `FailClosed` | `false` | `false` | Site fails closed at parse time |

## Implementation Rules

### Rule 1: Derived State
- `execution_ready_semantics` MUST be derived from `status()`, never hardcoded
- `parser_ready_syntax` MUST be derived from `status()`, never hardcoded  

### Rule 2: Status Consistency
- If `status() == LoweringGapStatus::Resolved`, then `execution_ready_semantics() == true`
- If `status() == LoweringGapStatus::OpenPlaceholder`, then `execution_ready_semantics() == false` and `parser_ready_syntax() == true`
- If `status() == LoweringGapStatus::FailClosed`, then both flags are `false`

### Rule 3: No Contradictory States
- A site CANNOT have `status == Resolved` and `execution_ready_semantics == false`
- A site CANNOT have `status == FailClosed` and `parser_ready_syntax == true`

## LoweringGapSiteDescriptor Invariants

When creating `LoweringGapSiteDescriptor` from `LoweringGapSiteId`:

```rust
impl LoweringGapSiteDescriptor {
    pub fn from_site(site: LoweringGapSiteId) -> Self {
        Self {
            // ... other fields ...
            status: site.status(),
            parser_ready_syntax: site.parser_ready_syntax(),
            execution_ready_semantics: site.execution_ready_semantics(),
            // ... other fields ...
        }
    }
}
```

The descriptor fields MUST match the site's derived values:
- `descriptor.status == site.status()`
- `descriptor.parser_ready_syntax == site.parser_ready_syntax()`
- `descriptor.execution_ready_semantics == site.execution_ready_semantics()`

## Validation Rules

### Inventory Validation
- Count methods (`execution_ready_site_count()`, etc.) must reflect actual status distribution
- No site should have contradictory status/readiness combinations
- `resolved_site_count()` should equal `execution_ready_site_count()` when all resolved sites are execution-ready

### Test Requirements
- Integration tests MUST verify the invariant holds for all sites
- Unit tests MUST verify derived state consistency
- Tests MUST NOT manually set contradictory field combinations

## Contract Violations

The following patterns are FORBIDDEN:

```rust
// FORBIDDEN: Hardcoded execution_ready_semantics
pub const fn execution_ready_semantics(self) -> bool {
    false  // WRONG: Should derive from status
}

// FORBIDDEN: Contradictory descriptor
LoweringGapSiteDescriptor {
    status: LoweringGapStatus::Resolved,
    execution_ready_semantics: false,  // CONTRADICTION
    // ...
}

// FORBIDDEN: Manual override in from_site
pub fn from_site(site: LoweringGapSiteId) -> Self {
    Self {
        status: site.status(),
        execution_ready_semantics: false,  // WRONG: Should use site.execution_ready_semantics()
        // ...
    }
}
```

## Current Implementation Status

As of bd-2muur.4, all `LoweringGapSiteId` variants return `LoweringGapStatus::Resolved`, which means:
- All sites have `execution_ready_semantics() == true`
- All sites have `parser_ready_syntax() == true`
- The inventory contains no placeholder or fail-closed sites

## Enforcement

This invariant is enforced through:
1. Const methods that derive readiness from status
2. Integration tests that validate the relationship
3. Code review requirements for consistency
4. Static analysis to detect hardcoded contradictions

## Migration Path

If new sites are added with different status values:
1. Update the `status()` method to return the appropriate `LoweringGapStatus`
2. Verify that `execution_ready_semantics()` and `parser_ready_syntax()` derive correctly
3. Add tests to validate the new site follows the invariant
4. Update documentation if new status combinations are introduced