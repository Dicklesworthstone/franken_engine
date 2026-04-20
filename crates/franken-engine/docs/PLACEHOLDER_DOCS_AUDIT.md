# Documentation Placeholder Content Audit

**Date**: 2026-04-20  
**Auditor**: Claude Code Review System  
**Scope**: All markdown files in `crates/franken-engine/docs/`

## Executive Summary

Found multiple categories of placeholder content across 31 documentation files. Most significant issues are incomplete baseline measurements in testing manifests and placeholder entries in the technical reports registry.

## Template Files (Intentional Placeholders)

These files are structural templates and appropriately contain placeholder content:

### 1. RESEARCH_ARTIFACT_TEMPLATE.md
- **Lines 1-50+**: Entire file is template structure with example formats
- **Purpose**: Standard template for research artifacts
- **Status**: ✅ Appropriate placeholder content

### 2. TECHNICAL_REPORT_TEMPLATE.md  
- **Lines 1-50+**: Template with bracket placeholders `[Descriptive title]`, `[Author list]`, etc.
- **Purpose**: Standard template for technical reports
- **Status**: ✅ Appropriate placeholder content

### 3. PROOF_SKETCH_TEMPLATE.md
- **Lines 1-30+**: Template structure for proof documentation
- **Purpose**: Standard template for formal proof sketches  
- **Status**: ✅ Appropriate placeholder content

## Content Files with Placeholder Issues

### 4. CONFORMANCE_HARNESS_MANIFEST.md
- **Lines 73-76**: Table entries with "TBD" status for conformance measurements
  ```
  | ECMAScript baseline builtins | TBD | TBD | 0 | 0 | 0 | 0.00 | Not conformant |
  | Replay receipt schemas | TBD | TBD | 0 | 0 | 0 | 0.00 | Not conformant |
  | Policy decision tables | TBD | TBD | 0 | 0 | 0 | 0.00 | Not conformant |
  | Artifact bundle manifests | TBD | TBD | 0 | 0 | 0 | 0.00 | Not conformant |
  ```
- **Status**: ⚠️ Needs baseline measurements

### 5. MUTATION_TESTING_MANIFEST.md
- **Lines 61-65**: Mutation testing coverage entries with "TBD" status
  ```
  | Parser and lowering invariants | TBD | 0.85 | Start with grammar... |
  | Baseline interpreter builtins | TBD | 0.80 | Require compatibility... |
  | Policy and capability gates | TBD | 0.95 | Security-critical... |
  | Artifact and replay validators | TBD | 0.90 | Missing-hash... |
  | CLI fail-closed gates | TBD | 0.90 | Unknown-option... |
  ```
- **Status**: ⚠️ Needs actual mutation testing baseline measurements

### 6. technical_reports_registry.json
- **Lines 8, 27**: Placeholder report titles
  ```json
  "title": "[PLACEHOLDER] Runtime Security Isolation in WebAssembly Extensions"
  "title": "[PLACEHOLDER] Deterministic Replay for WebAssembly Security Analysis"
  ```
- **Lines 10, 29**: TBD publication dates (`"date": "2026-TBD"`)
- **Line 173**: TBD replication team assignment (`"replication_team": "TBD"`)
- **Status**: ⚠️ Needs completion of placeholder entries

### 7. BASELINE_UNIMPLEMENTED_AUDIT.md
- **Lines 7-8**: References audit of TODO items
- **Lines 76-80**: Section documenting test infrastructure TODOs
- **Status**: ✅ Legitimate documentation of existing TODOs (not placeholders)

### 8. BD2501_AUDIT_REPORT.md
- **Lines 55-82**: Documents TBD findings in other files (meta-audit)
- **Status**: ✅ Legitimate audit documentation

## Recommendations

### High Priority
1. **Complete Baseline Measurements**: Replace TBD entries in `MUTATION_TESTING_MANIFEST.md` and `CONFORMANCE_HARNESS_MANIFEST.md` with actual baseline measurements
2. **Registry Completion**: Update `technical_reports_registry.json` placeholder entries with real publication metadata

### Medium Priority  
3. **Measurement Infrastructure**: Establish systematic baseline measurement collection for testing manifests
4. **Registry Validation**: Add CI checks to prevent future TBD entries in production manifests

### Low Priority
5. **Template Organization**: Consider moving template files to separate `templates/` directory for clarity

## File Summary

| File | Template | Placeholder Issues | Action Required |
|------|----------|-------------------|----------------|
| RESEARCH_ARTIFACT_TEMPLATE.md | ✅ | None | None |
| TECHNICAL_REPORT_TEMPLATE.md | ✅ | None | None |  
| PROOF_SKETCH_TEMPLATE.md | ✅ | None | None |
| CONFORMANCE_HARNESS_MANIFEST.md | ❌ | 4 TBD entries | Baseline measurements |
| MUTATION_TESTING_MANIFEST.md | ❌ | 5 TBD entries | Baseline measurements |
| technical_reports_registry.json | ❌ | 5 placeholder entries | Complete metadata |
| BASELINE_UNIMPLEMENTED_AUDIT.md | ❌ | TODO documentation | None (legitimate) |
| BD2501_AUDIT_REPORT.md | ❌ | Meta-audit | None (legitimate) |

## Audit Conclusion

**Template files**: 3 files with appropriate placeholder content  
**Content files with issues**: 3 files requiring completion  
**Critical path**: Baseline measurement infrastructure for testing manifests

Documentation structure is sound but requires completion of concrete baseline measurements to replace TBD placeholders in testing manifests.