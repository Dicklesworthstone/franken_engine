# [CRITICAL][REVIEW] `with` Statement Implementation Gap (ES2020 §13.11.1)

**Bead ID:** REVIEW-WITH-STATEMENT-GAP-CRITICAL  
**Severity:** CRITICAL  
**Spec Section:** ECMAScript 2020 Section 13.11.1 (with Statement)  
**Review Date:** 2026-05-02  

## Issue Summary

FrankenEngine **lacks `with` statement implementation entirely**. The parser does not support `with` syntax at all, which blocks proper strict mode validation per ES2020 §13.11.1. This is a fundamental JavaScript syntax gap, not just a strict mode issue.

## Evidence of Missing Implementation

### **Executable Test Created:**
`crates/franken-engine/tests/strict_mode_with_statement_rejection.rs`

**Critical test case:**
```javascript
// Should be SyntaxError in strict mode (ES2020 §13.11.1)
"use strict"; with (obj) { x = 1; }
```

### **AST Analysis Confirms Gap:**
Examined `crates/franken-engine/src/ast.rs` Statement enum - **no `WithStatement` variant exists**:
```rust
pub enum Statement {
    Import(ImportDeclaration),
    Export(ExportDeclaration),
    VariableDeclaration(VariableDeclaration),
    // ... other statements
    // ❌ MISSING: WithStatement variant
}
```

### **Expected vs Actual Behavior:**

**ES2020 Spec Requirements:**
1. Non-strict mode: `with (obj) { }` should parse successfully
2. Strict mode: `with (obj) { }` should be SyntaxError with specific error code
3. Function strict mode: Same rejection as global strict mode

**Predicted FrankenEngine Behavior:**
- **All contexts**: `with` statements fail with generic "unsupported syntax" error
- **Missing**: Both parsing support AND strict mode validation
- **Root cause**: No AST representation for `with` statements

## Test Implementation Strategy

Created comprehensive test with 5 scenarios:
1. `strict_mode_with_statement_global_context_rejection` - ES2020 §13.11.1 validation
2. `strict_mode_with_statement_function_context_rejection` - Function strict mode
3. `non_strict_mode_with_statement_should_parse` - Control test (should pass)
4. `strict_mode_valid_code_should_parse` - Baseline validation
5. `inspect_with_statement_error_details` - Diagnostic error reporting

## Implementation Requirements

### **Phase 1: Parser Extensions**
1. **Add `WithStatement` AST variant** to Statement enum
2. **Implement `with` statement parsing** in parser grammar
3. **Add statement execution** in interpreter

### **Phase 2: Strict Mode Validation**  
1. **Thread strict mode context** through parser
2. **Add strict mode check** for `with` statements
3. **Emit `strict_mode_with_statement` error code** per ES2020 §13.11.1

### **Phase 3: Verification**
1. **Non-strict mode**: `with (obj) { }` parses and executes
2. **Strict mode**: `with (obj) { }` throws SyntaxError with correct error code
3. **Function strict mode**: Same behavior as global strict mode

## Test Validation Approach

```bash
# Run the executable test suite
cargo test strict_mode_with_statement_rejection --lib

# Expected results BEFORE fix:
# - All with statement tests fail with "unsupported syntax"
# - Confirms missing parser implementation

# Expected results AFTER fix:
# - Non-strict mode: test passes (parsing succeeds)  
# - Strict mode: test passes (correct SyntaxError thrown)
```

## Impact Assessment

- **P0 Critical**: Missing fundamental JavaScript syntax
- **ES2020 Compliance**: Major spec violation beyond strict mode
- **Cross-engine compatibility**: Code using `with` statements (legacy codebases) will fail
- **Security impact**: Cannot enforce strict mode `with` restrictions without basic parsing

## Recommended Priority

**P0 - CRITICAL:** This is not just a strict mode gap but a missing JavaScript language feature. Implementation required for ES2020 baseline compliance.