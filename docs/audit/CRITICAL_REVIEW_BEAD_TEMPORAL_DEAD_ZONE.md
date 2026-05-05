# [CRITICAL][REVIEW] Temporal Dead Zone Violations in Loop Headers

**Bead ID:** REVIEW-TDZ-LOOP-HEADERS-CRITICAL  
**Severity:** CRITICAL  
**Spec Section:** ECMAScript 2020 Section 13.2.4.8 (for Statement), Section 8.1.1.1.6 (TDZ)  
**Review Date:** 2026-05-02  

## Issue Summary
FrankenEngine **lacks Temporal Dead Zone validation** in loop headers. No conformance tests exist for let/const TDZ behavior in iteration statements, indicating missing ES2015+ scoping semantics.

## Spec Violation Details

### **Required by ES2020 Spec (Section 8.1.1.1.6):**
```javascript
// MUST throw ReferenceError - accessing let variable before declaration
for (let x = x + 1; x < 10; x++) {
    // x accessed in initializer before declaration completes
}
// ↑ Should throw: ReferenceError: Cannot access 'x' before initialization
```

### **What FrankenEngine Likely Returns:**
- **No error** - incorrectly allows TDZ violations
- **Runtime undefined behavior** instead of proper ReferenceError
- **Missing block scope isolation** per iteration

### **Expected Behavior (ES2015+ Spec):**
1. let/const declarations create bindings in temporal dead zone
2. Accessing binding before initialization completes throws ReferenceError  
3. Each loop iteration creates fresh lexical environment for let/const

### **Missing Test Cases:**
Current conformance suite has **ZERO** TDZ tests for:
- Self-referential initialization: `for (let x = x; ...)`
- Block scope isolation: `for (let i...) { closures.push(() => i); }`
- const re-assignment detection in loop headers

## Critical Test Cases
```javascript
// Test 1: TDZ in for loop initialization
try {
    for (let x = (x = 1); x < 2; x++) {}
    throw new Error("FAIL: Should have thrown ReferenceError");
} catch (e) {
    console.assert(e instanceof ReferenceError, "Must be ReferenceError");
}

// Test 2: Block scope per iteration (closure capture)
let closures = [];
for (let i = 0; i < 3; i++) {
    closures.push(() => i);
}
// Each closure should capture different 'i' value
console.assert(closures[0]() === 0, "First closure should capture 0");
console.assert(closures[2]() === 2, "Last closure should capture 2");

// Test 3: const assignment in loop header
try {
    for (const x = 1; x < 10; x++) {} // Assignment to const in update
    throw new Error("FAIL: Should have thrown TypeError");  
} catch (e) {
    console.assert(e instanceof TypeError, "Must be TypeError for const assignment");
}
```

## Impact Assessment
- **ES2015+ Scoping Violations** - Fundamental scoping rules not enforced
- **Silent Bugs** - Code that should error runs with undefined behavior  
- **Memory Leaks** - Incorrect closure capture in loops
- **Security Risk** - TDZ enforcement prevents certain variable hoisting attacks

## Evidence of Missing Coverage
`iteration_statements_test262_conformance.rs` has:
- ✅ Basic variable declarations (`let x = 0`)
- ❌ **ZERO** TDZ violation tests
- ❌ **ZERO** block scope isolation tests  
- ❌ **ZERO** const re-assignment tests

## Recommended Priority
**P0 - CRITICAL:** TDZ is a fundamental ES2015+ scoping mechanism. Missing implementation affects correctness of modern JavaScript execution and can lead to security vulnerabilities.