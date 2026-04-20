# Baseline Interpreter Deduplication Follow-up Beads

**Date:** 2026-04-20  
**Related Audit:** `docs/BASELINE_DUPLICATE_BUILTIN_ID_AUDIT.md`

## Created Review Beads

Following the baseline interpreter duplicate BuiltinId audit, the following review beads have been created to address the most critical deduplication opportunities:

### bd-voreh - ArrayPrototypeSort Deduplication
- **Type:** task
- **Priority:** P2  
- **Title:** `[review][baseline_interpreter] Dedup ArrayPrototypeSort: 7 duplicate match arms cause unreachable code, known issue per line 23027 comment`
- **Occurrences:** 7 duplicates at lines [9432, 17192, 17300, 17437, 23027, 23089, 23096]
- **Context:** Known issue documented in source comments, causing unreachable match arms

### bd-23w2p - ParseFloat Deduplication  
- **Type:** task
- **Priority:** P2
- **Title:** `[review][baseline_interpreter] Dedup ParseFloat: 13 duplicate match arms, highest occurrence count causing significant dead code`
- **Occurrences:** 13 duplicates at lines [16736, 17430, 23447, 23468, 23815, 23832, 23858, 23879, 23901, 23922, 23943, 23969, 23990]
- **Context:** Highest duplication count in entire audit, significant code bloat

### bd-5wpm4 - StringPrototypeSplit Deduplication
- **Type:** task
- **Priority:** P2  
- **Title:** `[review][baseline_interpreter] Dedup StringPrototypeSplit: 13 duplicate match arms across main dispatcher and test code sections`
- **Occurrences:** 13 duplicates at lines [16227, 17128, 17408, 18729, 18738, 18752, 18761, 18775, 18784, 18798, 18807, 18822, 18837]
- **Context:** Spans main dispatcher and test code sections, indicating systematic duplication

## Priority Recommendations

1. **bd-voreh (ArrayPrototypeSort)** - Start here due to existing documentation of the issue
2. **bd-23w2p (ParseFloat)** - Critical due to highest occurrence count  
3. **bd-5wpm4 (StringPrototypeSplit)** - Important due to cross-section duplication pattern

## Related Work

These beads address the 99.7% duplication rate found in the baseline interpreter audit. Resolving these three patterns will eliminate 33 of the 587 duplicate occurrences (5.6% reduction) while targeting the most problematic cases.

## Implementation Notes

- Focus on consolidating match arms in the main dispatcher function (`dispatch_builtin_hostcall`)
- Preserve test functionality while eliminating duplicate code paths
- Verify behavior consistency across all consolidated arms
- Consider whether ID mapping section (lines 17100+) should be the single source of truth