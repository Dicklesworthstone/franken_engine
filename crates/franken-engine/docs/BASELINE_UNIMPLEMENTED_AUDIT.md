# Baseline Interpreter Unimplemented Features Audit

## Audit Metadata

- **Date**: 2026-04-20
- **File**: `crates/franken-engine/src/baseline_interpreter.rs`
- **Audit Type**: Placeholder/TODO Implementation Review
- **Total TODOs Found**: 42

## Executive Summary

Comprehensive audit of baseline interpreter implementation reveals 42 TODO items indicating unimplemented or simplified functionality. The majority fall into 5 critical categories affecting JavaScript runtime completeness. Most severe issues relate to callback function execution and async function support, which limit the engine's ability to run real-world JavaScript applications.

## Critical Unimplemented Features

### 1. Callback Function Execution (Severity: HIGH)

**Impact**: Array methods and higher-order functions return placeholder values instead of executing callbacks.

| Line | Method | Issue | Placeholder Return |
|------|--------|-------|-------------------|
| 10885 | ArrayPrototypeFindIndex | No callback execution mechanism | `Value::Int(-1)` |
| 11092 | ArrayPrototypeEvery | No function call support | `Value::Bool(true)` (incorrect) |
| 11215 | ArrayPrototypeReduceRight | No callback execution | `Value::Int(-1)` |
| 11562 | ArrayPrototypeFlatMap | No flatMap callback support | Simplified array copy |

**Recommended Fix**: Create beads for implementing function call mechanism with proper context binding and argument passing.

### 2. Async Function Execution (Severity: HIGH)

**Impact**: Async/await functionality incomplete, affecting Promise-based code execution.

| Line | Feature | Issue |
|------|---------|-------|
| 3575 | Async function start | Missing immediate execution trigger |
| 4776 | Async suspension | No microtask registration |
| 4788 | Async return | No current async context tracking |
| 4805 | Async error | No promise rejection tracking |

**Recommended Fix**: Create epic for comprehensive async execution engine with microtask queue and Promise integration.

### 3. Object Property System (Severity: MEDIUM)

**Impact**: Incomplete object model affects property enumeration and prototype chains.

| Line | Feature | Issue |
|------|---------|-------|
| 7819 | Object.freeze | No frozen flag implementation |
| 7857 | Object.create | Missing property descriptors |
| 7858 | Object.create | No prototype chain inheritance |

**Recommended Fix**: Implement proper property descriptor system and prototype chain traversal.

### 4. Collection Initialization (Severity: MEDIUM)

**Impact**: Map, Set, WeakMap, WeakSet constructors don't accept iterable arguments.

| Line | Constructor | Missing Feature |
|------|-------------|----------------|
| 10240 | Map | Iterable argument initialization |
| 10267 | Set | Iterable argument initialization |
| 10295 | WeakMap | Iterable argument initialization |
| 10323 | WeakSet | Iterable argument initialization |

**Recommended Fix**: Implement iterable processing for collection constructors.

### 5. Advanced String Processing (Severity: LOW)

**Impact**: Missing advanced text processing features.

| Line | Method | Issue |
|------|--------|-------|
| 12330 | String.normalize | No Unicode normalization forms |
| 11464 | Date formatting | No locale-aware formatting |

## Test Infrastructure TODOs

The following TODOs are in test code and represent missing test coverage rather than runtime issues:

- Lines 21512-21971: 18 test TODOs covering class methods, inheritance, timer behavior
- These should be addressed for comprehensive test coverage but don't affect runtime functionality

## Implementation Priority Matrix

### P0 (Critical) - Blocks Real Applications
1. **Callback Function Engine** (Lines: 10885, 11092, 11215, 11562)
   - Required for: Array methods, event handling, async programming
   - Estimated beads: 3-4 (function dispatch, context binding, argument handling)

2. **Async Execution Engine** (Lines: 3575, 4776, 4788, 4805)
   - Required for: Promise-based code, async/await, fetch APIs
   - Estimated beads: 4-5 (microtask queue, async state tracking, Promise integration)

### P1 (High) - Affects Object Model
3. **Property Descriptor System** (Lines: 7819, 7857, 7858)
   - Required for: Advanced object manipulation, framework compatibility
   - Estimated beads: 2-3 (descriptors, prototype chains, property attributes)

### P2 (Medium) - Enhances Compatibility  
4. **Collection Iterables** (Lines: 10240, 10267, 10295, 10323)
   - Required for: Modern collection usage patterns
   - Estimated beads: 2 (iterable processing, collection initialization)

### P3 (Low) - Nice-to-Have
5. **Advanced Text/Locale** (Lines: 12330, 11464)
   - Required for: Internationalization, advanced text processing
   - Estimated beads: 1-2 (Unicode normalization, locale formatting)

## Recommended Implementation Strategy

1. **Phase 1**: Implement callback function execution engine (P0)
   - Enables Array methods to work correctly
   - Foundation for higher-order function support

2. **Phase 2**: Build async execution infrastructure (P0)
   - Critical for Promise-based modern JavaScript
   - Enables async/await syntax support

3. **Phase 3**: Complete object model (P1)
   - Ensures compatibility with object-oriented frameworks
   - Required for advanced property manipulation

4. **Phase 4**: Collection and advanced features (P2-P3)
   - Enhances compatibility with modern JavaScript patterns
   - Addresses remaining edge cases

## Conclusion

The baseline interpreter has solid foundation but requires critical callback and async execution capabilities to support real-world JavaScript applications. Priority should be given to P0 items which currently cause methods to return incorrect placeholder values instead of executing proper JavaScript semantics.

**Next Actions**:
1. Create callback execution engine epic with 3-4 implementation beads
2. Create async execution infrastructure epic with 4-5 implementation beads  
3. Schedule property descriptor and collection initialization for subsequent sprints

---

*Audit completed 2026-04-20 by automated baseline interpreter review process.*