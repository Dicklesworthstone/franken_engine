//! Integration tests for control_plane_policy_diagnostics module.

use std::collections::BTreeSet;

use frankenengine_engine::budget_propagation_contract::{
    BudgetBoundaryKind, BudgetPropagationError, BudgetPropagationValidator,
};
use frankenengine_engine::control_plane_policy_diagnostics::{
    ControlPlaneDiagnostic, DiagnosticCategory, DiagnosticEmitter, DiagnosticReport,
    DiagnosticSeverity, RemediationGuidance,
};
use frankenengine_engine::outcome_capability_narrowing::{
    BoundaryOutcome, CapabilityGrant, CapabilityNarrowingValidator, CapabilityToken,
    NarrowingViolation,
};

// ---------------------------------------------------------------------------
// Budget error to diagnostic integration
// ---------------------------------------------------------------------------

#[test]
fn integration_all_budget_errors_produce_diagnostics() {
    let errors = vec![
        BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 5,
            minimum_ms: 10,
            parent_remaining_ms: 20,
        },
        BudgetPropagationError::NoRuleForBoundary {
            boundary: BudgetBoundaryKind::OrchestratorToCellClose,
        },
        BudgetPropagationError::ParentExhausted {
            boundary: BudgetBoundaryKind::ParentToChildSession,
            parent_remaining_ms: 0,
        },
        BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 5000,
            parent_remaining_ms: 1000,
        },
        BudgetPropagationError::ChildExceedsParent {
            child_ms: 200,
            parent_ms: 100,
        },
    ];

    let mut emitter = DiagnosticEmitter::with_defaults();
    for (i, err) in errors.iter().enumerate() {
        emitter.emit_budget_error(err, &format!("trace-{}", i));
    }

    assert_eq!(emitter.diagnostics().len(), 5);

    // Each should have a unique error code
    let codes: BTreeSet<String> = emitter
        .diagnostics()
        .iter()
        .map(|d| d.error_code.code.clone())
        .collect();
    assert_eq!(codes.len(), 5);
}

#[test]
fn integration_budget_errors_have_correct_severity() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    // InsufficientBudget → Error
    emitter.emit_budget_error(
        &BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 1,
            minimum_ms: 10,
            parent_remaining_ms: 5,
        },
        "t1",
    );
    assert_eq!(
        emitter.diagnostics()[0].error_code.severity,
        DiagnosticSeverity::Error
    );

    // NoRuleForBoundary → Critical
    emitter.emit_budget_error(
        &BudgetPropagationError::NoRuleForBoundary {
            boundary: BudgetBoundaryKind::OrchestratorToCellClose,
        },
        "t2",
    );
    assert_eq!(
        emitter.diagnostics()[1].error_code.severity,
        DiagnosticSeverity::Critical
    );

    // CleanupExceedsParent → Warning
    emitter.emit_budget_error(
        &BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 200,
            parent_remaining_ms: 100,
        },
        "t3",
    );
    assert_eq!(
        emitter.diagnostics()[2].error_code.severity,
        DiagnosticSeverity::Warning
    );
}

// ---------------------------------------------------------------------------
// Narrowing violation to diagnostic integration
// ---------------------------------------------------------------------------

#[test]
fn integration_all_narrowing_violations_produce_diagnostics() {
    let violations = vec![
        NarrowingViolation::CapabilityWidening {
            boundary_label: "spawn".to_owned(),
            widened_tokens: {
                let mut s = BTreeSet::new();
                s.insert(CapabilityToken::NetworkAccess);
                s
            },
        },
        NarrowingViolation::OutcomeUpgrade {
            boundary_label: "close".to_owned(),
            child_outcome: BoundaryOutcome::Timeout,
            propagated_outcome: BoundaryOutcome::Failure,
        },
        NarrowingViolation::UnknownOutcomeNotFailClosed {
            boundary_label: "external".to_owned(),
        },
    ];

    let mut emitter = DiagnosticEmitter::with_defaults();
    for (i, v) in violations.iter().enumerate() {
        emitter.emit_narrowing_violation(v, &format!("trace-{}", i));
    }

    assert_eq!(emitter.diagnostics().len(), 3);

    // Capability widening is Critical
    assert_eq!(
        emitter.diagnostics()[0].error_code.severity,
        DiagnosticSeverity::Critical
    );

    // Outcome upgrade is Error
    assert_eq!(
        emitter.diagnostics()[1].error_code.severity,
        DiagnosticSeverity::Error
    );

    // Unknown outcome is Critical
    assert_eq!(
        emitter.diagnostics()[2].error_code.severity,
        DiagnosticSeverity::Critical
    );
}

#[test]
fn integration_diagnostics_have_boundary_labels() {
    let mut emitter = DiagnosticEmitter::with_defaults();
    let violation = NarrowingViolation::CapabilityWidening {
        boundary_label: "test_boundary".to_owned(),
        widened_tokens: {
            let mut s = BTreeSet::new();
            s.insert(CapabilityToken::FileSystemWrite);
            s
        },
    };
    emitter.emit_narrowing_violation(&violation, "trace");

    assert_eq!(
        emitter.diagnostics()[0].boundary_label,
        Some("test_boundary".to_owned())
    );
}

// ---------------------------------------------------------------------------
// End-to-end: validator → emitter → report
// ---------------------------------------------------------------------------

#[test]
fn integration_e2e_budget_validator_to_report() {
    let mut validator = BudgetPropagationValidator::with_defaults();
    let mut emitter = DiagnosticEmitter::with_defaults();

    // Force a failure
    let result = validator.derive_child_budget(
        "parent",
        "child",
        0,
        BudgetBoundaryKind::ParentToChildExtension,
    );
    if let Err(err) = result {
        emitter.emit_budget_error(&err, "parent");
    }

    let report = emitter.build_report();
    assert!(!report.is_clean());
    assert!(report.release_blocked);
    assert_eq!(report.total_diagnostics, 1);
    assert!(report.category_counts.contains_key("budget_propagation"));
}

#[test]
fn integration_e2e_narrowing_validator_to_report() {
    let mut nv = CapabilityNarrowingValidator::with_defaults();
    let mut emitter = DiagnosticEmitter::with_defaults();

    // Force a widening violation
    let parent = CapabilityGrant::sandbox();
    let child = CapabilityGrant::full();
    nv.validate_narrowing("p", "c", "bad_spawn", &parent, &child);

    // Emit all violations
    for v in nv.violations() {
        emitter.emit_narrowing_violation(v, "p");
    }

    let report = emitter.build_report();
    assert!(!report.is_clean());
    assert!(report.release_blocked);
    assert!(report.category_counts.contains_key("capability_narrowing"));
}

#[test]
fn integration_e2e_clean_run() {
    let mut validator = BudgetPropagationValidator::with_defaults();
    let mut nv = CapabilityNarrowingValidator::with_defaults();
    let emitter = DiagnosticEmitter::with_defaults();

    // Successful budget derivation
    let _ = validator
        .derive_child_budget(
            "parent",
            "child",
            10_000,
            BudgetBoundaryKind::ParentToChildExtension,
        )
        .unwrap();

    // Successful narrowing
    nv.validate_narrowing(
        "parent",
        "child",
        "spawn",
        &CapabilityGrant::full(),
        &CapabilityGrant::sandbox(),
    );

    // No violations to emit
    assert!(!validator.has_violations());
    assert!(!nv.has_violations());

    let report = emitter.build_report();
    assert!(report.is_clean());
    assert!(!report.release_blocked);
}

// ---------------------------------------------------------------------------
// Report quality
// ---------------------------------------------------------------------------

#[test]
fn integration_report_severity_counts_correct() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    // 2 warnings
    for i in 0..2 {
        emitter.emit_budget_error(
            &BudgetPropagationError::CleanupExceedsParent {
                cleanup_total_ms: 200,
                parent_remaining_ms: 100,
            },
            &format!("tw-{}", i),
        );
    }

    // 1 error
    emitter.emit_budget_error(
        &BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 1,
            minimum_ms: 10,
            parent_remaining_ms: 5,
        },
        "te",
    );

    // 1 critical
    emitter.emit_budget_error(
        &BudgetPropagationError::NoRuleForBoundary {
            boundary: BudgetBoundaryKind::OrchestratorToCellClose,
        },
        "tc",
    );

    let report = emitter.build_report();
    assert_eq!(*report.severity_counts.get("warning").unwrap(), 2);
    assert_eq!(*report.severity_counts.get("error").unwrap(), 1);
    assert_eq!(*report.severity_counts.get("critical").unwrap(), 1);
    assert_eq!(report.total_diagnostics, 4);
    assert_eq!(report.max_severity, Some(DiagnosticSeverity::Critical));
}

#[test]
fn integration_report_json_roundtrip() {
    let mut emitter = DiagnosticEmitter::with_defaults();
    emitter.emit_budget_error(
        &BudgetPropagationError::ParentExhausted {
            boundary: BudgetBoundaryKind::ParentToChildSession,
            parent_remaining_ms: 0,
        },
        "trace",
    );

    let report = emitter.build_report();
    let json = serde_json::to_string_pretty(&report).unwrap();
    let round: DiagnosticReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, round);
}

#[test]
fn integration_report_hash_deterministic() {
    let make_report = || {
        let mut e = DiagnosticEmitter::with_defaults();
        e.emit_budget_error(
            &BudgetPropagationError::ParentExhausted {
                boundary: BudgetBoundaryKind::ParentToChildSession,
                parent_remaining_ms: 0,
            },
            "trace",
        );
        e.build_report()
    };

    let r1 = make_report();
    let r2 = make_report();
    assert_eq!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// Remediation guidance quality
// ---------------------------------------------------------------------------

#[test]
fn integration_all_diagnostics_have_remediation() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    // Emit all error types
    let errors: Vec<BudgetPropagationError> = vec![
        BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 1,
            minimum_ms: 10,
            parent_remaining_ms: 5,
        },
        BudgetPropagationError::NoRuleForBoundary {
            boundary: BudgetBoundaryKind::OrchestratorToCellClose,
        },
        BudgetPropagationError::ParentExhausted {
            boundary: BudgetBoundaryKind::ParentToChildSession,
            parent_remaining_ms: 0,
        },
    ];

    for err in &errors {
        emitter.emit_budget_error(err, "trace");
    }

    for diag in emitter.diagnostics() {
        assert!(!diag.remediation.summary.is_empty(), "missing summary");
        assert!(!diag.remediation.detail.is_empty(), "missing detail");
        assert!(!diag.remediation.steps.is_empty(), "missing steps");
        assert!(!diag.remediation.doc_refs.is_empty(), "missing doc_refs");
    }
}

#[test]
fn integration_diagnostic_serde_roundtrip() {
    let mut emitter = DiagnosticEmitter::with_defaults();
    emitter.emit_budget_error(
        &BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 1,
            minimum_ms: 10,
            parent_remaining_ms: 5,
        },
        "trace",
    );

    let diag = &emitter.diagnostics()[0];
    let json = serde_json::to_string(diag).unwrap();
    let round: ControlPlaneDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(*diag, round);
}

// ---------------------------------------------------------------------------
// Severity filtering
// ---------------------------------------------------------------------------

#[test]
fn integration_severity_filter_correctness() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    // Warning
    emitter.emit_budget_error(
        &BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 200,
            parent_remaining_ms: 100,
        },
        "tw",
    );

    // Error
    emitter.emit_budget_error(
        &BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 1,
            minimum_ms: 10,
            parent_remaining_ms: 5,
        },
        "te",
    );

    // Critical
    emitter.emit_budget_error(
        &BudgetPropagationError::ChildExceedsParent {
            child_ms: 200,
            parent_ms: 100,
        },
        "tc",
    );

    assert_eq!(
        emitter
            .diagnostics_at_severity(DiagnosticSeverity::Info)
            .len(),
        3
    ); // all
    assert_eq!(
        emitter
            .diagnostics_at_severity(DiagnosticSeverity::Warning)
            .len(),
        3
    ); // all
    assert_eq!(
        emitter
            .diagnostics_at_severity(DiagnosticSeverity::Error)
            .len(),
        2
    ); // error + critical
    assert_eq!(
        emitter
            .diagnostics_at_severity(DiagnosticSeverity::Critical)
            .len(),
        1
    ); // critical only
}

// ---------------------------------------------------------------------------
// Category coverage
// ---------------------------------------------------------------------------

#[test]
fn integration_budget_diagnostics_have_correct_category() {
    let mut emitter = DiagnosticEmitter::with_defaults();
    emitter.emit_budget_error(
        &BudgetPropagationError::ParentExhausted {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            parent_remaining_ms: 0,
        },
        "trace",
    );

    assert_eq!(
        emitter.diagnostics()[0].error_code.category,
        DiagnosticCategory::BudgetPropagation
    );
}

#[test]
fn integration_narrowing_diagnostics_have_correct_category() {
    let mut emitter = DiagnosticEmitter::with_defaults();
    emitter.emit_narrowing_violation(
        &NarrowingViolation::CapabilityWidening {
            boundary_label: "test".to_owned(),
            widened_tokens: {
                let mut s = BTreeSet::new();
                s.insert(CapabilityToken::NetworkAccess);
                s
            },
        },
        "trace",
    );

    assert_eq!(
        emitter.diagnostics()[0].error_code.category,
        DiagnosticCategory::CapabilityNarrowing
    );
}

#[test]
fn integration_outcome_diagnostics_have_correct_category() {
    let mut emitter = DiagnosticEmitter::with_defaults();
    emitter.emit_narrowing_violation(
        &NarrowingViolation::OutcomeUpgrade {
            boundary_label: "test".to_owned(),
            child_outcome: BoundaryOutcome::Timeout,
            propagated_outcome: BoundaryOutcome::Failure,
        },
        "trace",
    );

    assert_eq!(
        emitter.diagnostics()[0].error_code.category,
        DiagnosticCategory::OutcomePropagation
    );
}
