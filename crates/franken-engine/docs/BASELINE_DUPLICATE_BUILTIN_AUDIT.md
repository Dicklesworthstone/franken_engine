# Baseline Interpreter Duplicate Builtin Dispatch Audit

**Audit Date:** 2026-04-20  
**Total Dispatch Arms Found:** 614  
**Functions With Duplicates:** 52  
**Total Duplicate Instances:** 105+  

## Executive Summary

Systematic scan of `baseline_interpreter.rs` reveals significant duplication in builtin function dispatch arms. Multiple functions have 2-3 duplicate implementations, creating unreachable code patterns and maintenance overhead.

## Critical Duplicates (3+ instances)

### StringPrototypeToUpperCase (3 instances)
- **Lines:** 8134, 14492, 15868
- **Priority:** HIGH - String manipulation core function
- **Impact:** 2 unreachable arms

### StringPrototypeToLowerCase (3 instances)  
- **Lines:** 8121, 14398, 15860
- **Priority:** HIGH - String manipulation core function
- **Impact:** 2 unreachable arms

### StringPrototypeEndsWith (3 instances)
- **Lines:** 8981, 12639, 15943
- **Priority:** HIGH - String comparison function
- **Impact:** 2 unreachable arms

### ObjectGetOwnPropertyNames (3 instances)
- **Lines:** 10952, 13603, 16180
- **Priority:** HIGH - Object introspection critical path
- **Impact:** 2 unreachable arms

### ArrayPrototypeReverse (3 instances)
- **Lines:** 8845, 12985, 15814  
- **Priority:** HIGH - Array mutation function
- **Impact:** 2 unreachable arms

### ArrayPrototypeFindIndex (3 instances)
- **Lines:** 10858, 13556, 16532
- **Priority:** HIGH - Array search function
- **Impact:** 2 unreachable arms

### ArrayPrototypeFind (3 instances)
- **Lines:** 9045, 12535, 16492
- **Priority:** HIGH - Array search function  
- **Impact:** 2 unreachable arms

## Major Duplicates (2 instances)

### String Functions
- **StringPrototypeTrim:** 8147, 15906
- **StringPrototypeSubstring:** 7967, 16085  
- **StringPrototypeSubstr:** 11266, 15163
- **StringPrototypeStartsWith:** 8930, 12426
- **StringPrototypeSearch:** 10091, 14993
- **StringPrototypeRepeat:** 9269, 12617
- **StringPrototypePadStart:** 9383, 12220
- **StringPrototypePadEnd:** 9589, 12281
- **StringPrototypeNormalize:** 12302, 13657
- **StringPrototypeIncludes:** 8794, 12758
- **StringPrototypeCodePointAt:** 11777, 13500
- **StringPrototypeCharAt:** 7862, 16010
- **StringPrototypeAt:** 11923, 14014

### Math Functions  
- **MathTrunc:** 9652, 14823
- **MathSign:** 10139, 14651
- **MathImul:** 11844, 14460
- **MathHypot:** 11568, 14292
- **MathClz32:** 12032, 13830
- **MathAtan2:** 11064, 13192
- **MathAsin:** 11111, 13531
- **MathAcos:** 11128, 13378

### Object Functions
- **ObjectSetPrototypeOf:** 12248, 14376
- **ObjectPrototypeValueOf:** 11479, 13247
- **ObjectPrototypeToString:** 13532, 15876
- **ObjectGetPrototypeOf:** 11010, 14059
- **ObjectDefineProperty:** 10175, 13913

### Array Functions
- **ArrayPrototypeValues:** 12182, 15445
- **ArrayPrototypeReduceRight:** 11183, 13283
- **ArrayPrototypeReduce:** 9324, 16135
- **ArrayPrototypeLastIndexOf:** 10793, 13403  
- **ArrayPrototypeKeys:** 12116, 15589
- **ArrayPrototypeFlatMap:** 11523, 13850
- **ArrayPrototypeFlat:** 9937, 13695
- **ArrayPrototypeFill:** 11705, 13050
- **ArrayPrototypeEntries:** 12050, 15710
- **ArrayPrototypeCopyWithin:** 11607, 15254
- **ArrayPrototypeAt:** 11870, 14016

### Other Functions
- **NumberPrototypeToString:** 11288, 16062
- **NumberIsNaN:** 8615, 15976
- **NumberIsInteger:** 12736, 15924
- **NumberIsFinite:** 8627, 15991
- **StringFromCharCode:** 10927, 13351
- **PromiseResolve:** 9259, 13761
- **DateNow:** 8680, 16328

## Recommended Deduplication Beads

### Batch 1: Critical String Functions (High Impact)
- **BD-STR-UPPER-DEDUP:** Consolidate StringPrototypeToUpperCase (3→1)
- **BD-STR-LOWER-DEDUP:** Consolidate StringPrototypeToLowerCase (3→1)  
- **BD-STR-ENDSWITH-DEDUP:** Consolidate StringPrototypeEndsWith (3→1)

### Batch 2: Critical Object/Array Functions
- **BD-OBJ-GETNAMES-DEDUP:** Consolidate ObjectGetOwnPropertyNames (3→1)
- **BD-ARR-REVERSE-DEDUP:** Consolidate ArrayPrototypeReverse (3→1)
- **BD-ARR-FINDINDEX-DEDUP:** Consolidate ArrayPrototypeFindIndex (3→1)
- **BD-ARR-FIND-DEDUP:** Consolidate ArrayPrototypeFind (3→1)

### Batch 3: String Manipulation Functions
- **BD-STR-SUBSTR-DEDUP:** Consolidate substring/substr functions (4 total)
- **BD-STR-PAD-DEDUP:** Consolidate pad functions (4 total)  
- **BD-STR-TRIM-DEDUP:** Consolidate trim functions (6 total)

### Batch 4: Math Functions
- **BD-MATH-TRIG-DEDUP:** Consolidate trigonometric functions (6 total)
- **BD-MATH-UTIL-DEDUP:** Consolidate utility functions (8 total)

### Batch 5: Remaining Object/Array Functions  
- **BD-OBJ-PROTO-DEDUP:** Consolidate Object.prototype functions (6 total)
- **BD-ARR-SEARCH-DEDUP:** Consolidate Array search functions (8 total)
- **BD-ARR-TRANSFORM-DEDUP:** Consolidate Array transform functions (10 total)

## Impact Analysis

### Code Quality
- **Unreachable Code:** 105+ unreachable dispatch arms
- **Maintenance Burden:** Multiple implementations to keep in sync
- **Test Coverage:** Potentially testing only first implementation

### Performance  
- **Binary Size:** Duplicate implementations increase binary footprint
- **Compilation Time:** Extra code paths slow builds
- **Branch Prediction:** Multiple patterns may confuse CPU prediction

### Risk Assessment
- **Consistency Risk:** Different implementations may have divergent behavior
- **Security Risk:** Bug fixes may miss duplicate implementations  
- **Regression Risk:** Changes to one implementation may miss others

## Implementation Strategy

1. **Validate First Implementation:** For each duplicate, identify the correct/complete implementation
2. **Remove Downstream Duplicates:** Delete unreachable arms (typically later line numbers)
3. **Update Tests:** Ensure test coverage hits the remaining implementation
4. **Verify Consistency:** Compare behavior across implementations before removal

## Success Criteria

- **Zero Duplicate Dispatch Arms:** No function handled multiple times
- **Clean Compilation:** All unreachable pattern warnings resolved  
- **Test Coverage Maintained:** All deduped functions retain test coverage
- **Consistent Behavior:** No functional regressions from consolidation

## Priority Queue

Focus on **Batch 1** (critical string functions) and **Batch 2** (critical object/array functions) first, as these are core JavaScript operations with 3 duplicate implementations each.

**Estimated Impact:** Removing 105+ duplicate dispatch arms will eliminate significant unreachable code and simplify the baseline interpreter dispatch logic.