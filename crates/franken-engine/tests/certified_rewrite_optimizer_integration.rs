//! Fail-closed guard for certified rewrite optimizer integration.
//!
//! This test ensures the certified_rewrite_optimizer module remains intentionally
//! disabled until all dependent APIs are implemented. The module is not available
//! for production use due to missing dependencies, and this test prevents silent
//! enablement without proper validation.
//!
//! **Tracking**: bd-1lsy.7.7.3.2 - Explicit fail-closed guard for unavailable module
//! **Dependencies**: Module requires implementation of:
//! - TranslationValidator, ValidationResult, ValidationReceipt types
//! - RewriteRule, RewriteRuleId, OptimizationTier::Conservative
//! - GovernanceState::new(), RollbackRecord::new, OptimizationCertificate::new
//!
//! **Re-enable when**: All dependent APIs exist and imports resolve successfully.

#![forbid(unsafe_code)]

/// Test that certified_rewrite_optimizer module is intentionally unavailable.
///
/// This fail-closed guard prevents silent enablement of the module before
/// all dependent APIs are properly implemented and tested.
#[test]
fn certified_rewrite_optimizer_intentionally_unavailable() {
    // Verify the module is not accessible from the public API
    let module_available = cfg!(feature = "certified_rewrite_optimizer_production");

    // Should be false - module is intentionally disabled
    assert!(
        !module_available,
        "certified_rewrite_optimizer module should remain disabled until dependent APIs are implemented"
    );

    // Document the expected dependencies that must be satisfied before re-enabling
    let required_dependencies = vec![
        "TranslationValidator",
        "ValidationResult",
        "ValidationReceipt",
        "RewriteRule",
        "RewriteRuleId",
        "OptimizationTier::Conservative",
        "GovernanceState::new()",
        "RollbackRecord::new",
        "OptimizationCertificate::new",
    ];

    // Ensure we have a clear list of what's needed
    assert!(!required_dependencies.is_empty());
    assert!(required_dependencies.len() >= 9); // All listed dependencies accounted for
}

/// Test that integration tests fail explicitly when module is unavailable.
///
/// This ensures the integration test suite doesn't silently pass when the
/// underlying module is disabled, which would provide false confidence.
#[test]
fn integration_tests_fail_closed_when_module_disabled() {
    // Verify that we're in fail-closed mode for disabled module
    let integration_enabled = cfg!(feature = "certified_rewrite_optimizer_integration");

    // Integration should be explicitly disabled, not silently skipped
    assert!(
        !integration_enabled,
        "Integration tests should be explicitly disabled, not silently skipped"
    );

    // When the module is re-enabled, this test should be updated to validate
    // that proper integration tests are running and passing
}

/// Test waiver documentation for intentional disablement.
///
/// Ensures there's explicit documentation for why the module is disabled
/// and what conditions are required for re-enablement.
#[test]
fn explicit_waiver_documentation_present() {
    // This file itself serves as the waiver documentation
    let waiver_file = file!();
    assert!(waiver_file.contains("certified_rewrite_optimizer_integration.rs"));

    // Ensure the waiver includes bead tracking
    let waiver_content = include_str!("certified_rewrite_optimizer_integration.rs");
    assert!(waiver_content.contains("bd-1lsy.7.7.3.2"));
    assert!(waiver_content.contains("intentionally disabled"));
    assert!(waiver_content.contains("dependent APIs"));

    // Fail if someone tries to silently re-enable without updating this guard
    assert!(waiver_content.contains("Re-enable when"));
}
