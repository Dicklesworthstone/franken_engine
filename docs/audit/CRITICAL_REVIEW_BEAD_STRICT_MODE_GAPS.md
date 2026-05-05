# [CRITICAL][REVIEW] ES2020 Strict Mode Implementation Gaps

**Bead ID:** REVIEW-STRICT-MODE-GAPS-CRITICAL  
**Severity:** CRITICAL  
**Spec Section:** ECMAScript 2020 Section 10.2.1 (Strict Mode Code)  
**Review Date:** 2026-05-02  

## Issue Summary

FrankenEngine has **partial strict mode implementation** with critical gaps. Some strict mode restrictions are implemented (reserved word bindings, duplicate parameters) but fundamental syntax restrictions are missing, allowing code that should be rejected per ES2020 spec.

## Evidence of Missing Implementation

### **✅ IMPLEMENTED (verified in static_semantics.rs):**
- `ReservedWordBinding` - ES2020 §12.1.1 reserved words in strict mode  
- `DuplicateParameter` - ES2020 §14.1.2 function parameter conflicts  
- `DeleteOfIdentifier` - ES2020 §12.5.4.2 delete of unqualified identifiers  
- `EvalArgumentsBinding` - ES2020 §12.1.1 eval/arguments restrictions  

### **❌ MISSING CRITICAL GAPS:**

#### 1. **with Statement Rejection (ES2020 §13.11.1)**
**Expected:** `"use strict"; with (obj) { x = 1; }` → SyntaxError  
**Actual:** No `WithStatement` variant in AST enum (ast.rs:Statement)  
**Impact:** Fundamental strict mode restriction not enforced  

#### 2. **Octal Literal Rejection (ES2020 §11.8.3)** 
**Expected:** `"use strict"; var x = 077;` → SyntaxError  
**Evidence:** Parser has `StrictModeOctalLiteral` error type but AST stores `NumericLiteral(i64)` losing source representation needed for validation  
**Impact:** Silent acceptance of non-portable numeric literals  

#### 3. **Runtime this Binding (ES2020 §10.2.1.1)**
**Expected:** `"use strict"; function f() { return this; } f() === undefined`  
**Status:** Requires runtime interpreter validation (not just parser)  

#### 4. **Undeclared Assignment (ES2020 §8.1.1.2.1)**  
**Expected:** `"use strict"; undeclaredVar = 42;` → ReferenceError at runtime  
**Status:** Requires runtime interpreter validation  

## Test Cases for Validation

Created comprehensive test suite: `crates/franken-engine/tests/strict_mode_test262_conformance.rs`

**Critical failing cases (predicted):**
```javascript
// Test 1: with statement (should parse as SyntaxError)
"use strict"; with (obj) { x = 1; }

// Test 2: octal literal (should parse as SyntaxError)  
"use strict"; var x = 077;
```

## Impact Assessment

- **ES2020 Compliance Gap** - Fundamental strict mode features missing
- **Silent Bugs** - Code that should error runs with undefined behavior  
- **Cross-Engine Inconsistency** - Code accepted by FrankenEngine rejected by V8/SpiderMonkey/JavaScriptCore
- **Security Risk** - `with` statements create variable hoisting vulnerabilities strict mode prevents

## Implementation Requirements

### Phase 1: Parser Extensions
1. **Add `WithStatement` AST variant** - implement parsing but reject in strict mode
2. **Octal literal detection** - track source representation or detect during lexing
3. **Strict mode context threading** - ensure strict mode flags flow through parser

### Phase 2: Runtime Enforcement  
1. **this binding semantics** - undefined vs global object in function calls
2. **Undeclared assignment detection** - ReferenceError for implicit globals

## Verification Approach

Run strict mode conformance test and verify expected parse errors:
```bash
cargo test strict_mode_test262_conformance --lib
```

**Expected false acceptance count:** 2+ (with statement, octal literal)

## Recommended Priority

**P0 - CRITICAL:** Strict mode is fundamental to ES2015+ JavaScript execution. Missing implementation breaks real-world code compatibility and security guarantees.