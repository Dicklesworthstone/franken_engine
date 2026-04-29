//! Integration tests for RGC-804: Cross-Arch Reproducibility and Deterministic Replay Contract
//!
//! Exercises the public API for cross-architecture reproducibility verification
//! from outside the crate boundary. Tests deterministic replay across repeated
//! runs and simulated architecture differences.

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

use frankenengine_engine::deterministic_replay::{NondeterminismSource, NondeterminismTrace};
use frankenengine_engine::rgc_cross_arch_reproducibility::{
    ArchitectureId, CrossArchComparison, CrossArchConfig, CrossArchController, CrossArchError,
    DivergenceSeverity, ReproducibilityAssessment, TraceDivergence,
    verify_cross_arch_reproducibility, verify_cross_arch_reproducibility_with_config,
};

// ---------------------------------------------------------------------------
// Architecture identification tests
// ---------------------------------------------------------------------------

#[test]
fn architecture_id_current_returns_recognized_arch() {
    let arch = ArchitectureId::current();

    // Should be one of the known architectures or unknown
    match arch {
        ArchitectureId::X86_64 => assert_eq!(arch.as_str(), "x86_64"),
        ArchitectureId::Aarch64 => assert_eq!(arch.as_str(), "aarch64"),
        ArchitectureId::Unknown => assert_eq!(arch.as_str(), "unknown"),
    }
}

#[test]
fn architecture_id_string_conversion() {
    assert_eq!(ArchitectureId::X86_64.as_str(), "x86_64");
    assert_eq!(ArchitectureId::Aarch64.as_str(), "aarch64");
    assert_eq!(ArchitectureId::Unknown.as_str(), "unknown");
}

#[test]
fn architecture_id_ordering() {
    // Test deterministic ordering for BTreeMap keys
    let mut archs = vec![
        ArchitectureId::Unknown,
        ArchitectureId::X86_64,
        ArchitectureId::Aarch64,
    ];
    archs.sort();

    // Should sort consistently
    assert_eq!(archs[0], ArchitectureId::Aarch64);
    assert_eq!(archs[1], ArchitectureId::Unknown);
    assert_eq!(archs[2], ArchitectureId::X86_64);
}

// ---------------------------------------------------------------------------
// Configuration tests
// ---------------------------------------------------------------------------

#[test]
fn cross_arch_config_default_values() {
    let config = CrossArchConfig::default();

    assert_eq!(config.target_architectures.len(), 2);
    assert!(
        config
            .target_architectures
            .contains(&ArchitectureId::X86_64)
    );
    assert!(
        config
            .target_architectures
            .contains(&ArchitectureId::Aarch64)
    );
    assert_eq!(config.replay_iterations, 3);
    assert!(config.capture_fp_divergences);
    assert!(config.strict_determinism);
    assert_eq!(config.max_divergent_events, 0);
}

#[test]
fn cross_arch_config_custom_values() {
    let config = CrossArchConfig {
        target_architectures: vec![ArchitectureId::X86_64],
        replay_iterations: 5,
        capture_fp_divergences: false,
        strict_determinism: false,
        max_divergent_events: 10,
    };

    assert_eq!(config.target_architectures.len(), 1);
    assert_eq!(config.replay_iterations, 5);
    assert!(!config.capture_fp_divergences);
    assert!(!config.strict_determinism);
    assert_eq!(config.max_divergent_events, 10);
}

// ---------------------------------------------------------------------------
// Controller tests
// ---------------------------------------------------------------------------

#[test]
fn cross_arch_controller_creation() {
    let controller = CrossArchController::with_defaults();

    // Should start with no reference traces
    let result = controller.compare_trace(
        "nonexistent-session",
        &NondeterminismTrace::new("test"),
        ArchitectureId::X86_64,
    );

    assert!(matches!(result, Err(CrossArchError::MissingReferenceTrace)));
}

#[test]
fn cross_arch_controller_record_and_compare() {
    let mut controller = CrossArchController::with_defaults();

    // Create a reference trace
    let mut reference_trace = NondeterminismTrace::new("test-session");
    reference_trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![42, 43, 44],
        1000,
        "test_component",
    );

    // Record it
    controller.record_reference_trace("test-session".to_string(), reference_trace.clone());

    // Compare against identical trace
    let result = controller
        .compare_trace("test-session", &reference_trace, ArchitectureId::X86_64)
        .unwrap();

    assert!(result.traces_identical);
    assert_eq!(result.matching_events, 1);
    assert_eq!(result.divergent_events, 0);
    assert!(result.divergences.is_empty());
    assert_eq!(result.assessment, ReproducibilityAssessment::Perfect);
}

#[test]
fn cross_arch_controller_detects_divergence() {
    let mut controller = CrossArchController::with_defaults();

    // Create reference trace
    let mut reference_trace = NondeterminismTrace::new("test-session");
    reference_trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![42],
        1000,
        "test_component",
    );

    // Create different target trace
    let mut target_trace = NondeterminismTrace::new("test-session");
    target_trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![99], // Different value
        1000,
        "test_component",
    );

    controller.record_reference_trace("test-session".to_string(), reference_trace);

    let result = controller
        .compare_trace("test-session", &target_trace, ArchitectureId::Aarch64)
        .unwrap();

    assert!(!result.traces_identical);
    assert_eq!(result.matching_events, 0);
    assert_eq!(result.divergent_events, 1);
    assert_eq!(result.divergences.len(), 1);

    let divergence = &result.divergences[0];
    assert_eq!(divergence.event_index, 0);
    assert_eq!(divergence.severity, DivergenceSeverity::Critical);
    assert_eq!(result.assessment, ReproducibilityAssessment::Failed);
}

#[test]
fn cross_arch_controller_missing_events() {
    let mut controller = CrossArchController::with_defaults();

    // Reference trace with multiple events
    let mut reference_trace = NondeterminismTrace::new("test-session");
    reference_trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![1],
        100,
        "component1",
    );
    reference_trace.capture(NondeterminismSource::TimerRead, vec![2], 200, "component2");

    // Target trace with only one event
    let mut target_trace = NondeterminismTrace::new("test-session");
    target_trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![1],
        100,
        "component1",
    );

    controller.record_reference_trace("test-session".to_string(), reference_trace);

    let result = controller
        .compare_trace("test-session", &target_trace, ArchitectureId::Aarch64)
        .unwrap();

    assert!(!result.traces_identical);
    assert_eq!(result.matching_events, 1);
    assert_eq!(result.divergent_events, 1);

    // Should detect missing event
    let divergence = &result.divergences[0];
    assert_eq!(divergence.event_index, 1);
    assert!(divergence.description.contains("Missing event"));
    assert_eq!(divergence.severity, DivergenceSeverity::Critical);
}

#[test]
fn cross_arch_controller_extra_events() {
    let mut controller = CrossArchController::with_defaults();

    // Reference trace with one event
    let mut reference_trace = NondeterminismTrace::new("test-session");
    reference_trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![1],
        100,
        "component1",
    );

    // Target trace with extra event
    let mut target_trace = NondeterminismTrace::new("test-session");
    target_trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![1],
        100,
        "component1",
    );
    target_trace.capture(NondeterminismSource::TimerRead, vec![2], 200, "component2");

    controller.record_reference_trace("test-session".to_string(), reference_trace);

    let result = controller
        .compare_trace("test-session", &target_trace, ArchitectureId::Aarch64)
        .unwrap();

    assert!(!result.traces_identical);
    assert_eq!(result.matching_events, 1);
    assert_eq!(result.divergent_events, 1);

    // Should detect extra event
    let divergence = &result.divergences[0];
    assert_eq!(divergence.event_index, 1);
    assert!(divergence.description.contains("Extra event"));
    assert_eq!(divergence.severity, DivergenceSeverity::Critical);
}

// ---------------------------------------------------------------------------
// Report generation tests
// ---------------------------------------------------------------------------

#[test]
fn cross_arch_controller_generate_report() {
    let mut controller = CrossArchController::with_defaults();

    // Create and record a trace
    let mut trace = NondeterminismTrace::new("report-session");
    trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![42],
        1000,
        "test_component",
    );

    controller.record_reference_trace("report-session".to_string(), trace);

    let report = controller.generate_report("report-session").unwrap();

    assert_eq!(report.session_id, "report-session");
    assert_eq!(report.reference_arch, ArchitectureId::current());
    assert_eq!(report.reference_event_count, 1);
    assert!(!report.timestamp_utc.is_empty());
}

#[test]
fn cross_arch_controller_generate_report_missing_session() {
    let controller = CrossArchController::with_defaults();

    let result = controller.generate_report("nonexistent-session");
    assert!(matches!(result, Err(CrossArchError::MissingReferenceTrace)));
}

// ---------------------------------------------------------------------------
// Assessment tests
// ---------------------------------------------------------------------------

#[test]
fn reproducibility_assessment_levels() {
    let strict_config = CrossArchConfig {
        strict_determinism: true,
        max_divergent_events: 0,
        ..Default::default()
    };
    let controller = CrossArchController::new(strict_config);

    // Perfect - no divergences
    let assessment = controller.assess_reproducibility(&[]);
    assert_eq!(assessment, ReproducibilityAssessment::Perfect);

    // Failed - has critical divergences above max = 0
    let divergences = vec![TraceDivergence {
        event_index: 0,
        description: "Test".to_string(),
        severity: DivergenceSeverity::Critical,
        reference_value: "a".to_string(),
        target_value: "b".to_string(),
    }];
    let assessment = controller.assess_reproducibility(&divergences);
    assert_eq!(assessment, ReproducibilityAssessment::Failed);
}

#[test]
fn reproducibility_assessment_with_tolerance() {
    let tolerant_config = CrossArchConfig {
        strict_determinism: false,
        max_divergent_events: 5,
        ..Default::default()
    };
    let controller = CrossArchController::new(tolerant_config);

    // Acceptable - only warnings
    let divergences = vec![TraceDivergence {
        event_index: 0,
        description: "Test".to_string(),
        severity: DivergenceSeverity::Warning,
        reference_value: "a".to_string(),
        target_value: "b".to_string(),
    }];
    let assessment = controller.assess_reproducibility(&divergences);
    assert_eq!(assessment, ReproducibilityAssessment::Acceptable);
}

// ---------------------------------------------------------------------------
// High-level verification tests
// ---------------------------------------------------------------------------

#[test]
fn verify_cross_arch_reproducibility_success() {
    let result = verify_cross_arch_reproducibility("integration-test", 1);
    assert!(result.is_ok());

    let comparison = result.unwrap();
    assert!(comparison.traces_identical);
    let expected_comparisons = 1 + CrossArchConfig::default()
        .target_architectures
        .iter()
        .filter(|arch| **arch != ArchitectureId::current())
        .count();
    assert_eq!(comparison.matching_events, expected_comparisons);
    assert_eq!(comparison.divergent_events, 0);
    assert_eq!(comparison.assessment, ReproducibilityAssessment::Perfect);
}

#[test]
fn verify_cross_arch_reproducibility_multiple_iterations() {
    // Test that different iterations produce different evidence
    let result_1 = verify_cross_arch_reproducibility("multi-iteration-test-1", 1);
    let result_3 = verify_cross_arch_reproducibility("multi-iteration-test-3", 3);

    assert!(result_1.is_ok());
    assert!(result_3.is_ok());

    let comparison_1 = result_1.unwrap();
    let comparison_3 = result_3.unwrap();

    // Both should be perfect, but verify different iterations produce distinguishable results
    assert!(comparison_1.traces_identical);
    assert!(comparison_3.traces_identical);

    // The function should exercise multiple iterations, producing different trace counts
    // This proves iterations parameter is actually honored
    assert_ne!(
        comparison_1.matching_events, comparison_3.matching_events,
        "1 vs 3 iterations should produce different matching event counts"
    );
}

#[test]
fn verify_cross_arch_reproducibility_zero_iterations_fails() {
    // Test that 0 iterations fails closed
    let result = verify_cross_arch_reproducibility("zero-iterations-test", 0);
    assert!(result.is_err());

    if let Err(error) = result {
        assert!(matches!(error, frankenengine_engine::rgc_cross_arch_reproducibility::CrossArchError::NoIterationsSpecified));
    }
}

#[test]
fn verify_cross_arch_reproducibility_exercises_target_architectures() {
    // Test with custom config to verify target architectures are exercised
    let config = CrossArchConfig {
        target_architectures: vec![ArchitectureId::X86_64, ArchitectureId::Aarch64],
        replay_iterations: 2,
        capture_fp_divergences: true,
        strict_determinism: true,
        max_divergent_events: 0,
    };

    let result = verify_cross_arch_reproducibility_with_config("arch-matrix-test", config);
    assert!(result.is_ok());

    let comparison = result.unwrap();
    // Should exercise both x86_64 and aarch64 architectures in matrix
    // Even if current arch is one of them, it should test cross-arch differences
    assert!(
        comparison.matching_events > 0,
        "Should have executed cross-architecture comparisons"
    );
}

#[test]
fn verify_cross_arch_reproducibility_zero_iterations_fails_closed() {
    // Should fail closed when no iterations specified
    let result = verify_cross_arch_reproducibility("zero-iteration-test", 0);

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CrossArchError::NoIterationsSpecified
    ));
}

#[test]
fn verify_cross_arch_reproducibility_default_path_exercises_target_architectures() {
    // Test that target architectures from config are actually consulted
    // Current implementation should attempt cross-arch validation for configured targets
    let result = verify_cross_arch_reproducibility("cross-arch-test", 2);

    assert!(result.is_ok());

    let comparison = result.unwrap();
    // Should succeed with proper cross-architecture consideration
    // (The implementation will test current arch + any configured target archs)
    assert!(comparison.traces_identical);
}

#[test]
fn verify_cross_arch_reproducibility_honors_iteration_parameter() {
    let result_param_1 = verify_cross_arch_reproducibility("config-test-1", 1);
    let result_param_5 = verify_cross_arch_reproducibility("config-test-5", 5);

    assert!(result_param_1.is_ok());
    assert!(result_param_5.is_ok());

    // Both should behave identically because they use the same config.replay_iterations
    let comparison_1 = result_param_1.unwrap();
    let comparison_5 = result_param_5.unwrap();

    assert_ne!(
        comparison_1.matching_events, comparison_5.matching_events,
        "1 vs 5 iterations should exercise different replay counts"
    );
    assert_eq!(comparison_1.assessment, comparison_5.assessment);
    assert!(comparison_1.traces_identical);
    assert!(comparison_5.traces_identical);
}

#[test]
fn verify_cross_arch_reproducibility_with_custom_config() {
    use frankenengine_engine::rgc_cross_arch_reproducibility::{
        ArchitectureId, CrossArchConfig, verify_cross_arch_reproducibility_with_config,
    };

    // Test custom config with 1 iteration vs 5 iterations
    let config_1_iter = CrossArchConfig {
        target_architectures: vec![ArchitectureId::X86_64],
        replay_iterations: 1,
        capture_fp_divergences: false,
        strict_determinism: true,
        max_divergent_events: 0,
    };

    let config_5_iter = CrossArchConfig {
        target_architectures: vec![ArchitectureId::X86_64],
        replay_iterations: 5,
        capture_fp_divergences: false,
        strict_determinism: true,
        max_divergent_events: 0,
    };

    let result_1 = verify_cross_arch_reproducibility_with_config("custom-1", config_1_iter);
    let result_5 = verify_cross_arch_reproducibility_with_config("custom-5", config_5_iter);

    assert!(result_1.is_ok());
    assert!(result_5.is_ok());

    // Both should succeed but with different iteration counts exercised
    let comparison_1 = result_1.unwrap();
    let comparison_5 = result_5.unwrap();

    assert!(comparison_1.traces_identical);
    assert!(comparison_5.traces_identical);
    assert_eq!(comparison_1.assessment, ReproducibilityAssessment::Perfect);
    assert_eq!(comparison_5.assessment, ReproducibilityAssessment::Perfect);
}

#[test]
fn verify_cross_arch_config_fail_closed_no_iterations() {
    use frankenengine_engine::rgc_cross_arch_reproducibility::{
        ArchitectureId, CrossArchConfig, CrossArchError,
        verify_cross_arch_reproducibility_with_config,
    };

    let config_zero_iter = CrossArchConfig {
        target_architectures: vec![ArchitectureId::X86_64],
        replay_iterations: 0, // Should fail closed
        capture_fp_divergences: false,
        strict_determinism: true,
        max_divergent_events: 0,
    };

    let result = verify_cross_arch_reproducibility_with_config("zero-config", config_zero_iter);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CrossArchError::NoIterationsSpecified
    ));
}

#[test]
fn verify_cross_arch_config_fail_closed_no_targets() {
    use frankenengine_engine::rgc_cross_arch_reproducibility::{
        CrossArchConfig, CrossArchError, verify_cross_arch_reproducibility_with_config,
    };

    let config_no_targets = CrossArchConfig {
        target_architectures: vec![], // Should fail closed
        replay_iterations: 3,
        capture_fp_divergences: false,
        strict_determinism: true,
        max_divergent_events: 0,
    };

    let result = verify_cross_arch_reproducibility_with_config("no-targets", config_no_targets);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CrossArchError::Configuration(_)
    ));
}

// ---------------------------------------------------------------------------
// Error handling tests
// ---------------------------------------------------------------------------

#[test]
fn cross_arch_error_display() {
    let errors = vec![
        CrossArchError::MissingReferenceTrace,
        CrossArchError::IdGeneration("test error".to_string()),
        CrossArchError::ReplayEngine("engine error".to_string()),
        CrossArchError::Configuration("config error".to_string()),
    ];

    for error in errors {
        let message = format!("{}", error);
        assert!(!message.is_empty());
        assert!(message.len() > 10); // Should have meaningful content
    }
}

#[test]
fn cross_arch_error_equality() {
    assert_eq!(
        CrossArchError::MissingReferenceTrace,
        CrossArchError::MissingReferenceTrace
    );

    assert_eq!(
        CrossArchError::IdGeneration("test".to_string()),
        CrossArchError::IdGeneration("test".to_string())
    );

    assert_ne!(
        CrossArchError::IdGeneration("test1".to_string()),
        CrossArchError::IdGeneration("test2".to_string())
    );
}

// ---------------------------------------------------------------------------
// Serialization tests
// ---------------------------------------------------------------------------

#[test]
fn cross_arch_comparison_serialization() {
    let comparison = CrossArchComparison {
        reference_arch: ArchitectureId::X86_64,
        target_arch: ArchitectureId::Aarch64,
        traces_identical: true,
        matching_events: 10,
        divergent_events: 0,
        divergences: vec![],
        assessment: ReproducibilityAssessment::Perfect,
    };

    let serialized = serde_json::to_string(&comparison).unwrap();
    let deserialized: CrossArchComparison = serde_json::from_str(&serialized).unwrap();

    assert_eq!(comparison, deserialized);
}

#[test]
fn trace_divergence_serialization() {
    let divergence = TraceDivergence {
        event_index: 5,
        description: "Test divergence".to_string(),
        severity: DivergenceSeverity::Warning,
        reference_value: "ref_value".to_string(),
        target_value: "target_value".to_string(),
    };

    let serialized = serde_json::to_string(&divergence).unwrap();
    let deserialized: TraceDivergence = serde_json::from_str(&serialized).unwrap();

    assert_eq!(divergence, deserialized);
}

#[test]
fn cross_arch_config_serialization() {
    let config = CrossArchConfig {
        target_architectures: vec![ArchitectureId::X86_64, ArchitectureId::Aarch64],
        replay_iterations: 5,
        capture_fp_divergences: true,
        strict_determinism: false,
        max_divergent_events: 2,
    };

    let serialized = serde_json::to_string(&config).unwrap();
    let deserialized: CrossArchConfig = serde_json::from_str(&serialized).unwrap();

    assert_eq!(
        config.target_architectures,
        deserialized.target_architectures
    );
    assert_eq!(config.replay_iterations, deserialized.replay_iterations);
    assert_eq!(
        config.capture_fp_divergences,
        deserialized.capture_fp_divergences
    );
    assert_eq!(config.strict_determinism, deserialized.strict_determinism);
    assert_eq!(
        config.max_divergent_events,
        deserialized.max_divergent_events
    );
}
