# [REVIEW][P0 Critical] Missing Strict Mode Validation for `with` Statements

**Priority**: P0 Critical - ES2020 baseline compliance failure
**Type**: REVIEW (spec gap with implementation roadmap)
**Component**: Parser strict mode validation
**Spec Reference**: ES2020 §13.11.1, §10.2.1

## Verified Spec Gap

**FALSE ACCEPTANCE**: FrankenEngine incorrectly accepts `with` statements in strict mode contexts, violating ES2020 §13.11.1.

### Test Evidence

```bash
cargo test --test strict_mode_with_statement_rejection
```

**Results**:
- ❌ `strict_mode_with_statement_global_context_rejection` - **FAILED**: `"use strict"; with (obj) { x = 1; }"` parsed successfully
- ❌ `strict_mode_with_statement_function_context_rejection` - **FAILED**: `function f() { "use strict"; with (obj) { } }"` parsed successfully  
- ✅ `non_strict_mode_with_statement_should_parse` - **PASSED**: `with` statements work in non-strict mode
- ✅ `strict_mode_valid_code_should_parse` - **PASSED**: Normal strict mode validation works

**Root Cause**: Parser implements `with` statement AST parsing but lacks strict mode validation hook.

## ES2020 Specification Requirements

**§13.11.1 Static Semantics: Early Errors**
```
WithStatement : with ( Expression ) Statement
  - It is a Syntax Error if this production is contained in strict mode code.
```

**§10.2.1 Strict Mode Code**
```
- Global code is strict mode code if it begins with a Directive Prologue containing a Use Strict Directive
- Function code is strict mode code if the associated FunctionDeclaration is contained in strict mode code or if the function code begins with a Directive Prologue containing a Use Strict Directive
```

## Implementation Roadmap

### Phase 1: Parser Context Tracking
```rust
// In parser.rs
struct ParseContext {
    strict_mode: bool,
    // ... existing fields
}

impl Parser {
    fn enter_strict_mode(&mut self) {
        self.context.strict_mode = true;
    }
    
    fn is_strict_mode(&self) -> bool {
        self.context.strict_mode
    }
}
```

### Phase 2: Strict Mode Detection
```rust
// Directive prologue parsing
fn parse_directive_prologue(&mut self) -> Result<Vec<Directive>, ParseError> {
    let directives = self.parse_directives()?;
    if directives.iter().any(|d| d.is_use_strict()) {
        self.enter_strict_mode();
    }
    Ok(directives)
}

// Function context inheritance  
fn parse_function_body(&mut self, parent_strict: bool) -> Result<FunctionBody, ParseError> {
    let saved_strict = self.context.strict_mode;
    if parent_strict {
        self.enter_strict_mode();
    }
    
    let directives = self.parse_directive_prologue()?;
    let body = self.parse_statement_list()?;
    
    self.context.strict_mode = saved_strict;
    Ok(FunctionBody { directives, body })
}
```

### Phase 3: WithStatement Strict Mode Validation
```rust
fn parse_with_statement(&mut self) -> Result<Statement, ParseError> {
    // Early error check per ES2020 §13.11.1
    if self.is_strict_mode() {
        return Err(ParseError::new(
            ParseErrorCode::StrictModeWithStatement,
            "with statement not allowed in strict mode",
            self.current_span()
        ));
    }
    
    // Existing parsing logic...
    self.expect_token(Token::With)?;
    // ...
}
```

### Phase 4: Error Code Extension
```rust
// In parser.rs ParseErrorCode enum
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ParseErrorCode {
    // ... existing variants
    StrictModeWithStatement,
}
```

## Test Coverage Requirements

The existing test suite in `tests/strict_mode_with_statement_rejection.rs` provides comprehensive coverage:

1. **Global strict mode rejection**: `"use strict"; with (obj) { }`
2. **Function strict mode rejection**: `function f() { "use strict"; with (obj) { } }`
3. **Non-strict mode acceptance**: `with (obj) { }` (control test)
4. **Strict mode baseline**: `"use strict"; var x = 1;` (control test)
5. **Diagnostic inspection**: Error details for debugging

## Verification Plan

1. **Implement strict mode tracking** in ParseContext
2. **Add StrictModeWithStatement error variant** 
3. **Hook validation in parse_with_statement()**
4. **Run test suite**: All 5 tests should pass
5. **Regression check**: Ensure non-strict `with` statements still work

## Compliance Impact

**Without this fix**:
- ❌ ES2020 §13.11.1 violation (syntax errors not detected)
- ❌ Test262 strict mode conformance failures
- ❌ Semantic mismatch with spec-compliant engines

**With this fix**:
- ✅ Full ES2020 baseline compliance for `with` statement semantics
- ✅ Proper strict mode error reporting
- ✅ Test262 conformance alignment

## Timeline

**Effort**: ~4-6 hours implementation + testing
**Dependencies**: None (parser infrastructure exists)
**Risk**: Low (additive validation, no semantic changes)

---

**Next Action**: Assign to parser team for strict mode validation implementation.
**Test Framework**: `tests/strict_mode_with_statement_rejection.rs` ready for validation.