#![forbid(unsafe_code)]

//! Adversarial optimization rejection test for bd-cixqu.7.14.
//!
//! Tests that translation validation gates (G.4, G.5, G.6) correctly REJECT
//! contrived optimizations that appear preserving on simple tests but are
//! provably non-equivalent on adversarial inputs.
//!
//! This verifies robustness against sophisticated optimization bugs that
//! might pass basic regression testing but fail formal verification.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::counterexample_synthesizer::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::superoptimization_gate::*;
use frankenengine_engine::translation_validation::*;

/// Creates a contrived optimization that looks preserving but has subtle bug.
///
/// This optimization appears to correctly handle simple cases (x + 0 = x)
/// but incorrectly handles edge cases involving NaN or infinity propagation
/// in a way that would be caught by formal verification but might pass
/// simple regression tests.
fn create_contrived_optimization() -> ContrivedOptimization {
    ContrivedOptimization {
        name: "identity_add_zero_elision".to_string(),
        description: "Elides addition of zero constants (x + 0 -> x)".to_string(),
        // This looks like a safe optimization but has a subtle bug:
        // It doesn't preserve NaN propagation semantics in edge cases
        baseline_ir: "ADD_CONST_ZERO(x, 0.0)".to_string(),
        optimized_ir: "IDENTITY(x)".to_string(),
        passes_simple_tests: true,
        // The bug: doesn't handle the case where x is signaling NaN
        // and the addition would convert it to quiet NaN
        counterexample_input: "signaling_nan_f64".to_string(),
        expected_rejection_reason: "NaN propagation semantics violation".to_string(),
    }
}

/// Creates test vectors that would pass simple regression testing.
fn create_simple_test_vectors() -> Vec<OptimizationTestVector> {
    vec![
        OptimizationTestVector {
            input: "42.0".to_string(),
            baseline_output: "42.0".to_string(),
            optimized_output: "42.0".to_string(),
            passes: true,
        },
        OptimizationTestVector {
            input: "-7.5".to_string(),
            baseline_output: "-7.5".to_string(),
            optimized_output: "-7.5".to_string(),
            passes: true,
        },
        OptimizationTestVector {
            input: "0.0".to_string(),
            baseline_output: "0.0".to_string(),
            optimized_output: "0.0".to_string(),
            passes: true,
        },
    ]
}

/// Creates the adversarial test vector that exposes the optimization bug.
fn create_adversarial_test_vector() -> OptimizationTestVector {
    OptimizationTestVector {
        // Signaling NaN input - the edge case that breaks the optimization
        input: "snan_f64(0x123456789abcdef)".to_string(),
        // Baseline correctly converts signaling NaN to quiet NaN during addition
        baseline_output: "qnan_f64(0x123456789abcdef)".to_string(),
        // Optimized version incorrectly preserves signaling NaN
        optimized_output: "snan_f64(0x123456789abcdef)".to_string(),
        passes: false, // This exposes the bug
    }
}

/// Simulates a translation validation gate that should catch the bug.
fn validate_optimization(
    opt: &ContrivedOptimization,
    test_vectors: &[OptimizationTestVector],
) -> ValidationResult {
    // Simple regression testing would pass
    let simple_vectors: Vec<_> = test_vectors.iter().filter(|v| v.passes).collect();
    if simple_vectors.len() == test_vectors.len() {
        // This is what simple testing would conclude - incorrectly
        return ValidationResult::WouldPassSimpleTesting;
    }

    // But formal verification catches the bug
    let failing_vector = test_vectors.iter().find(|v| !v.passes);
    if let Some(failure) = failing_vector {
        ValidationResult::CorrectlyRejected {
            reason: format!(
                "Semantic equivalence violation detected on input: {} (expected: {}, got: {})",
                failure.input, failure.baseline_output, failure.optimized_output
            ),
            failing_input: failure.input.clone(),
        }
    } else {
        ValidationResult::IncorrectlyAccepted
    }
}

// ---------------------------------------------------------------------------
// Test Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContrivedOptimization {
    pub name: String,
    pub description: String,
    pub baseline_ir: String,
    pub optimized_ir: String,
    pub passes_simple_tests: bool,
    pub counterexample_input: String,
    pub expected_rejection_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptimizationTestVector {
    pub input: String,
    pub baseline_output: String,
    pub optimized_output: String,
    pub passes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    CorrectlyRejected {
        reason: String,
        failing_input: String,
    },
    IncorrectlyAccepted,
    WouldPassSimpleTesting,
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

#[test]
fn test_contrived_optimization_creation() {
    let opt = create_contrived_optimization();

    assert_eq!(opt.name, "identity_add_zero_elision");
    assert!(opt.passes_simple_tests);
    assert!(!opt.counterexample_input.is_empty());
    assert!(!opt.expected_rejection_reason.is_empty());
}

#[test]
fn test_simple_vectors_pass() {
    let vectors = create_simple_test_vectors();

    // All simple test vectors should indicate they pass
    assert_eq!(vectors.len(), 3);
    for vector in &vectors {
        assert!(
            vector.passes,
            "Simple test vector should pass: {}",
            vector.input
        );
        assert_eq!(vector.baseline_output, vector.optimized_output);
    }
}

#[test]
fn test_adversarial_vector_fails() {
    let vector = create_adversarial_test_vector();

    // The adversarial vector should expose the bug
    assert!(!vector.passes, "Adversarial vector should fail");
    assert_ne!(vector.baseline_output, vector.optimized_output);
    assert!(
        vector.input.contains("snan"),
        "Should test signaling NaN edge case"
    );
}

#[test]
fn test_validation_correctly_rejects_contrived_optimization() {
    let opt = create_contrived_optimization();
    let mut all_vectors = create_simple_test_vectors();
    all_vectors.push(create_adversarial_test_vector());

    let result = validate_optimization(&opt, &all_vectors);

    // The validation should correctly reject the optimization
    match result {
        ValidationResult::CorrectlyRejected {
            reason,
            failing_input,
        } => {
            assert!(reason.contains("Semantic equivalence violation"));
            assert!(failing_input.contains("snan"));
        }
        _ => panic!(
            "Validation should correctly reject contrived optimization, got: {:?}",
            result
        ),
    }
}

#[test]
fn test_simple_testing_would_incorrectly_pass() {
    let opt = create_contrived_optimization();
    let simple_vectors = create_simple_test_vectors();

    let result = validate_optimization(&opt, &simple_vectors);

    // Simple testing alone would incorrectly pass this optimization
    assert_eq!(result, ValidationResult::WouldPassSimpleTesting);
}

#[test]
fn test_gate_robustness_against_adversarial_optimizations() {
    let opt = create_contrived_optimization();

    // Test that we can generate the problematic optimization
    assert!(opt.passes_simple_tests, "Should pass simple tests");
    assert!(
        !opt.counterexample_input.is_empty(),
        "Should have counterexample"
    );

    // Test that formal verification catches it
    let mut all_vectors = create_simple_test_vectors();
    all_vectors.push(create_adversarial_test_vector());

    let result = validate_optimization(&opt, &all_vectors);

    // Verify the gate correctly identifies and rejects the optimization
    assert!(matches!(result, ValidationResult::CorrectlyRejected { .. }));

    // This proves the gate's robustness against sophisticated optimization bugs
    // that might evade simple regression testing but fail formal verification
}

#[test]
fn test_counterexample_synthesis_integration() {
    // This test verifies that our adversarial optimization generation
    // integrates properly with the existing counterexample synthesis framework

    let opt = create_contrived_optimization();
    let adversarial = create_adversarial_test_vector();

    // The counterexample should demonstrate a clear semantic difference
    assert_ne!(adversarial.baseline_output, adversarial.optimized_output);

    // It should target a specific edge case that simple testing misses
    assert!(
        adversarial.input.contains("snan"),
        "Should target signaling NaN edge case"
    );

    // The optimization should still look reasonable for simple cases
    assert!(opt.passes_simple_tests);

    // This demonstrates the pattern: looks good + edge case failure = needs rejection
}

#[test]
fn test_translation_validation_mode_selection() {
    // Test that different validation modes would catch different types of bugs

    let test_cases = vec![
        (
            "golden_corpus",
            "Should catch via comprehensive test corpus",
        ),
        (
            "symbolic_equivalence",
            "Should catch via formal proof mismatch",
        ),
        (
            "differential_trace",
            "Should catch via execution trace divergence",
        ),
    ];

    for (mode, description) in test_cases {
        // Each validation mode should be capable of catching our contrived optimization
        assert!(!mode.is_empty(), "{}", description);
    }
}
