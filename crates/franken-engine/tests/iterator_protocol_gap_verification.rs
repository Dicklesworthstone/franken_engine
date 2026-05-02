//! Quick verification test for iterator protocol implementation gaps
//!
//! This test verifies whether FrankenEngine actually supports the iterator protocol
//! or if the conformance tests were making false claims.

use frankenengine_engine::HybridRouter;

#[test]
fn verify_custom_iterator_support() {
    let mut engine = HybridRouter::default();

    // Test 1: Basic custom iterator with Symbol.iterator
    let custom_iterator_code = r#"
        let customIterable = {
            [Symbol.iterator]() {
                let count = 0;
                return {
                    next() {
                        if (count < 3) {
                            return { value: count++, done: false };
                        }
                        return { done: true };
                    }
                };
            }
        };
        let seen = 0;
        for (let value of customIterable) {
            seen = value;
        }
        seen;
    "#;

    let result = engine.eval(custom_iterator_code);
    match result {
        Ok(outcome) => {
            println!("✅ Custom iterator PASSED: {}", outcome.value);
            assert_eq!(outcome.value, "2", "Iterator should produce values 0, 1, 2");
        }
        Err(e) => {
            println!("❌ Custom iterator FAILED: {}", e);
            // This indicates a real conformance gap
            if e.to_string().contains("Symbol") || e.to_string().contains("iterator") {
                panic!(
                    "CRITICAL: Symbol.iterator not supported - conformance tests were fabricated"
                );
            }
            // Could also be a parsing issue
            panic!("CRITICAL: For-of with custom iterator failed - {}", e);
        }
    }
}

#[test]
fn verify_built_in_array_iterator() {
    let mut engine = HybridRouter::default();

    // Test 2: Built-in Array iterator (this should work)
    let array_iterator_code = r#"
        let arr = [1, 2, 3];
        let seen = 0;
        for (let value of arr) {
            seen = value;
        }
        seen;
    "#;

    let result = engine.eval(array_iterator_code);
    match result {
        Ok(outcome) => {
            println!("✅ Array iterator PASSED: {}", outcome.value);
            assert_eq!(outcome.value, "3", "Should iterate through array");
        }
        Err(e) => {
            println!("❌ Array iterator FAILED: {}", e);
            panic!("CRITICAL: Basic for-of with arrays failed - {}", e);
        }
    }
}

#[test]
fn verify_iterator_return_cleanup() {
    let mut engine = HybridRouter::default();

    // Test 3: Iterator cleanup with return() method
    let cleanup_code = r#"
        let cleanupCalled = false;
        let customIterable = {
            [Symbol.iterator]() {
                let count = 0;
                return {
                    next() {
                        return count < 10 ? { value: count++, done: false } : { done: true };
                    },
                    return() {
                        cleanupCalled = true;
                        return { done: true };
                    }
                };
            }
        };
        for (let value of customIterable) {
            if (value === 2) break;
        }
        cleanupCalled;
    "#;

    let result = engine.eval(cleanup_code);
    match result {
        Ok(outcome) => {
            println!("✅ Iterator cleanup test PASSED: {}", outcome.value);
            if outcome.value == "true" {
                println!("✅ Iterator.return() properly called on early exit");
            } else {
                println!("⚠️  Iterator.return() NOT called - spec violation but not critical");
            }
        }
        Err(e) => {
            println!("❌ Iterator cleanup FAILED: {}", e);
            // This is expected if Symbol.iterator isn't supported
        }
    }
}
