# Baseline Interpreter Commit Conventions Checklist

This document standardizes commit message conventions for baseline interpreter work based on analysis of recent commits.

## Required Format

### Core Convention
```
<type>(<scope>): <description>

<body>

<bead-reference>

Co-Authored-By: Claude Sonnet 4 <noreply@anthropic.com>
```

### Type Classification
- `fix`: Bug fixes, corrections, fail-closed implementations
- `feat`: New features, deduplication work, performance improvements  
- `refactor`: Code organization improvements without behavior change
- `test`: Test additions or improvements
- `docs`: Documentation updates

### Scope Standards
- **Production code**: `baseline_interpreter` (not `baseline`)
- **Test code**: `baseline_interpreter` (consistent with production)
- **Documentation**: `baseline_interpreter` or `baseline` (shorter acceptable for docs)

### Bead Reference Format
All baseline interpreter commits MUST include bead reference in body:
```
BD-<bead-id>: <bead-title>
```

Example:
```
BD-1431g: Make baseline Array.prototype.forEach invoke callbacks
```

## Audit Results (April 2026)

### ✅ Commits Following Convention
- `a89fe3ec` - Correct type/scope, missing bead ID
- `92b47c1b` - Correct type/scope, missing bead ID
- `de0c1906` - Correct type/scope, missing bead ID  
- `3b448a39` - Correct type/scope, missing bead ID
- `5ab2773a` - Correct type/scope, missing bead ID
- `8df95361` - Correct type/scope, missing bead ID

### ✅ Exemplary Commit
- `d1018316` - ✅ Correct type/scope + includes bead ID: "BD-1431g"

### ❌ Convention Violations
- `b5e1f273` - Uses `docs(baseline)` instead of conventional pattern
- Multiple commits missing bead ID references

## Enforcement Guidelines

1. **Always include bead ID** in commit body when working on assigned beads
2. **Use consistent scope**: `baseline_interpreter` for all baseline interpreter work
3. **Clear description**: Present tense, imperative mood ("implement", "fix", "add")
4. **Detailed body**: Explain what changed and why, list key changes
5. **Co-authorship**: Always include Claude Sonnet 4 co-author line

## Examples

### Good Examples
```
fix(baseline_interpreter): implement fail-closed Array.prototype.forEach with callback validation

Remove duplicate forEach implementation. Keep the fail-closed version at line 9000
with proper callback argument validation and clear error messaging until
full callback dispatch infrastructure is available.

BD-1431g: Make baseline Array.prototype.forEach invoke callbacks

Co-Authored-By: Claude Sonnet 4 <noreply@anthropic.com>
```

### Bad Examples
```
docs(baseline): add dedup review audit  // Missing bead ID, inconsistent scope
fix baseline stuff                      // No scope, vague description  
BD-123: fixed bug                       // Bead ID in wrong place, past tense
```

## Migration Notes

Recent baseline interpreter commits show excellent technical content but need:
1. **Consistent bead ID inclusion** in commit body  
2. **Standardized scope naming** (`baseline_interpreter` throughout)
3. **Conventional format adherence** for all commit types

This checklist should be followed for all future baseline interpreter work to maintain consistency and traceability.