# Security Commit Follow-up Analysis
*Phase D Final Review - 2026-04-22*

## Finding 1: HMAC Key Size Validation Missing (CRITICAL)
**Commit:** 4792fb15 - "security: use HMAC-SHA256 for evidence receipts"  
**Location:** `baseline_interpreter.rs:1146`

### Issue
```rust
let mut mac = Hmac::<Sha256>::new_from_slice(&self.signing_key)
    .expect("HMAC-SHA256 accepts fixed-size evidence signing keys");
```

**Problem:** The `expect()` assumes all signing keys are valid, but `new_from_slice()` fails for empty keys or extremely large keys. Production evidence logging could panic if:
- Key is empty (`&[]`)  
- Key exceeds HMAC implementation limits
- Key contains only null bytes (weak key)

### Regression Risk
- Receipt chain becomes unverifiable if any receipt panics during signing
- Evidence tampering could exploit panic-based DoS by providing malformed keys
- Key rotation scenarios might hit edge cases in key validation

### Missing Test Coverage
```rust
// Missing tests:
#[test] fn empty_signing_key_should_error_not_panic()
#[test] fn oversized_signing_key_handling()  
#[test] fn null_key_bytes_handled_safely()
```

---

## Finding 2: Publication Gate Evaluation Bypass via Direct API
**Commit:** 53b79469 - "fix(supremacy): remove placeholder publication verdict"  
**Location:** `supremacy_evidence_bundle.rs:666`

### Issue
The refactoring created two evaluation paths:
1. `evaluate_publication_gate(bundle, config)` - bundle-based (public API)
2. `evaluate_publication_gate_inputs(cells, stats, epoch, config)` - direct inputs (private)

**Problem:** The direct input function bypasses bundle integrity validation that the public API might perform. If callers use the wrong function, they could skip validation steps.

### Regression Risk
- Direct callers bypass bundle hash verification
- Coverage stats could be inconsistent with cells (no cross-validation)
- Creation epoch could be forged without bundle-level constraints
- Missing audit trail for publication decisions

### Missing Invariant Checks
```rust
// Missing validations in evaluate_publication_gate_inputs:
// - cells.len() consistency with coverage_stats.total_cells  
// - creation_epoch reasonableness (not far future/past)
// - coverage_stats derived correctly from provided cells
```

---

## Finding 3: Development Trust Content Hash Race Condition
**Commit:** 43d1bc60 - "fix(extension-host): bind development trust to content hash"  
**Location:** `franken-extension-host/src/lib.rs:701`

### Issue
```rust
// Before: if (has_signature || has_trust_chain) && !hash_matches
// After:  if !hash_matches  
```

**Problem:** The fix now requires content hash validation for ALL development trust manifests, but there's no atomic verification that the hash was computed from the same content being validated.

### Regression Risk
- Time-of-check vs time-of-use: content could change between hash computation and validation
- Development manifests might be rejected during legitimate hot-reload scenarios  
- Hash computation might use different content normalization than validation

### Missing Test Coverage
```rust
// Missing tests:
#[test] fn development_trust_concurrent_content_modification()
#[test] fn development_trust_hash_computation_consistency()
#[test] fn development_trust_with_signature_and_hash_mismatch()
```

---

## Summary
- **3 specific follow-up findings documented**
- **1 CRITICAL** (HMAC key validation)  
- **2 HIGH** (publication bypass, hash race condition)
- All findings have concrete regression scenarios and missing test recommendations
- Focus on edge cases that real-world usage could trigger

## Recommended Immediate Actions
1. Add HMAC key validation with proper error handling (don't panic)
2. Add invariant checks to direct publication gate evaluation  
3. Add atomic content hash validation for development trust manifests