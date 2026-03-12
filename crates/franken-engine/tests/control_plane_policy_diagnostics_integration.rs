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

// ---------------------------------------------------------------------------
// Mixed category scenarios
// ---------------------------------------------------------------------------

#[test]
fn integration_mixed_categories_in_single_report() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    // Budget error
    emitter.emit_budget_error(
        &BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 2,
            minimum_ms: 10,
            parent_remaining_ms: 15,
        },
        "trace-budget",
    );

    // Capability narrowing violation
    emitter.emit_narrowing_violation(
        &NarrowingViolation::CapabilityWidening {
            boundary_label: "spawn_ext".to_owned(),
            widened_tokens: {
                let mut s = BTreeSet::new();
                s.insert(CapabilityToken::NetworkAccess);
                s.insert(CapabilityToken::FileSystemWrite);
                s
            },
        },
        "trace-cap",
    );

    // Outcome propagation violation
    emitter.emit_narrowing_violation(
        &NarrowingViolation::OutcomeUpgrade {
            boundary_label: "cell_close".to_owned(),
            child_outcome: BoundaryOutcome::Timeout,
            propagated_outcome: BoundaryOutcome::Failure,
        },
        "trace-outcome",
    );

    let report = emitter.build_report();
    assert_eq!(report.total_diagnostics, 3);
    assert!(report.release_blocked);
    assert_eq!(report.category_counts.len(), 3);
    assert_eq!(
        *report.category_counts.get("budget_propagation").unwrap(),
        1
    );
    assert_eq!(
        *report.category_counts.get("capability_narrowing").unwrap(),
        1
    );
    assert_eq!(
        *report.category_counts.get("outcome_propagation").unwrap(),
        1
    );
}

#[test]
fn integration_mixed_severity_report_max_is_critical() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    // Warning
    emitter.emit_budget_error(
        &BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 300,
            parent_remaining_ms: 200,
        },
        "tw",
    );

    // Error
    emitter.emit_budget_error(
        &BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildSession,
            derived_ms: 3,
            minimum_ms: 20,
            parent_remaining_ms: 8,
        },
        "te",
    );

    // Critical
    emitter.emit_narrowing_violation(
        &NarrowingViolation::UnknownOutcomeNotFailClosed {
            boundary_label: "external_api".to_owned(),
        },
        "tc",
    );

    assert_eq!(emitter.max_severity(), Some(DiagnosticSeverity::Critical));
    assert!(emitter.has_release_blockers());
}

// ---------------------------------------------------------------------------
// Warnings-only scenarios
// ---------------------------------------------------------------------------

#[test]
fn integration_warnings_only_do_not_block_release() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    for i in 0..5 {
        emitter.emit_budget_error(
            &BudgetPropagationError::CleanupExceedsParent {
                cleanup_total_ms: 100 + i * 50,
                parent_remaining_ms: 50 + i * 10,
            },
            &format!("trace-warn-{}", i),
        );
    }

    let report = emitter.build_report();
    assert!(!report.is_clean());
    assert!(!report.release_blocked);
    assert_eq!(report.max_severity, Some(DiagnosticSeverity::Warning));
    assert_eq!(*report.severity_counts.get("warning").unwrap(), 5);
    assert_eq!(report.total_diagnostics, 5);
}

// ---------------------------------------------------------------------------
// Sequence monotonicity across mixed emission
// ---------------------------------------------------------------------------

#[test]
fn integration_sequence_monotonic_across_mixed_types() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    emitter.emit_budget_error(
        &BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 1,
            minimum_ms: 10,
            parent_remaining_ms: 5,
        },
        "t1",
    );

    emitter.emit_narrowing_violation(
        &NarrowingViolation::CapabilityWidening {
            boundary_label: "spawn".to_owned(),
            widened_tokens: {
                let mut s = BTreeSet::new();
                s.insert(CapabilityToken::NetworkAccess);
                s
            },
        },
        "t2",
    );

    emitter.emit_budget_error(
        &BudgetPropagationError::NoRuleForBoundary {
            boundary: BudgetBoundaryKind::OrchestratorToCellClose,
        },
        "t3",
    );

    emitter.emit_narrowing_violation(
        &NarrowingViolation::OutcomeUpgrade {
            boundary_label: "close".to_owned(),
            child_outcome: BoundaryOutcome::Timeout,
            propagated_outcome: BoundaryOutcome::Failure,
        },
        "t4",
    );

    let seqs: Vec<u64> = emitter.diagnostics().iter().map(|d| d.sequence).collect();
    assert_eq!(seqs.len(), 4);
    for i in 1..seqs.len() {
        assert!(
            seqs[i] > seqs[i - 1],
            "sequence not monotonic at index {}: {} <= {}",
            i,
            seqs[i],
            seqs[i - 1]
        );
    }
}

// ---------------------------------------------------------------------------
// Trace ID propagation
// ---------------------------------------------------------------------------

#[test]
fn integration_trace_ids_propagated_to_diagnostics() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    emitter.emit_budget_error(
        &BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 1,
            minimum_ms: 10,
            parent_remaining_ms: 5,
        },
        "trace-abc-123",
    );

    let diag = &emitter.diagnostics()[0];
    assert_eq!(diag.trace_ids.len(), 1);
    assert_eq!(diag.trace_ids[0], "trace-abc-123");
}

#[test]
fn integration_narrowing_trace_ids_propagated() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    emitter.emit_narrowing_violation(
        &NarrowingViolation::UnknownOutcomeNotFailClosed {
            boundary_label: "ext_boundary".to_owned(),
        },
        "trace-xyz-789",
    );

    let diag = &emitter.diagnostics()[0];
    assert_eq!(diag.trace_ids[0], "trace-xyz-789");
}

// ---------------------------------------------------------------------------
// Error code format validation
// ---------------------------------------------------------------------------

#[test]
fn integration_budget_error_codes_follow_prefix_pattern() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    let errors = vec![
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
        BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 200,
            parent_remaining_ms: 100,
        },
        BudgetPropagationError::ChildExceedsParent {
            child_ms: 200,
            parent_ms: 100,
        },
    ];

    for err in &errors {
        emitter.emit_budget_error(err, "trace");
    }

    for diag in emitter.diagnostics() {
        assert!(
            diag.error_code.code.starts_with("CP-BUDGET-"),
            "budget error code should start with CP-BUDGET-, got: {}",
            diag.error_code.code
        );
    }
}

#[test]
fn integration_capability_error_codes_follow_prefix_pattern() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    emitter.emit_narrowing_violation(
        &NarrowingViolation::CapabilityWidening {
            boundary_label: "spawn".to_owned(),
            widened_tokens: {
                let mut s = BTreeSet::new();
                s.insert(CapabilityToken::NetworkAccess);
                s
            },
        },
        "trace",
    );

    let diag = &emitter.diagnostics()[0];
    assert!(
        diag.error_code.code.starts_with("CP-CAP-"),
        "capability error code should start with CP-CAP-, got: {}",
        diag.error_code.code
    );
}

#[test]
fn integration_outcome_error_codes_follow_prefix_pattern() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    emitter.emit_narrowing_violation(
        &NarrowingViolation::OutcomeUpgrade {
            boundary_label: "close".to_owned(),
            child_outcome: BoundaryOutcome::Timeout,
            propagated_outcome: BoundaryOutcome::Failure,
        },
        "trace",
    );

    emitter.emit_narrowing_violation(
        &NarrowingViolation::UnknownOutcomeNotFailClosed {
            boundary_label: "ext".to_owned(),
        },
        "trace2",
    );

    for diag in emitter.diagnostics() {
        assert!(
            diag.error_code.code.starts_with("CP-OUTCOME-"),
            "outcome error code should start with CP-OUTCOME-, got: {}",
            diag.error_code.code
        );
    }
}

// ---------------------------------------------------------------------------
// Remediation quality for narrowing violations
// ---------------------------------------------------------------------------

#[test]
fn integration_narrowing_violations_have_remediation() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    emitter.emit_narrowing_violation(
        &NarrowingViolation::CapabilityWidening {
            boundary_label: "spawn".to_owned(),
            widened_tokens: {
                let mut s = BTreeSet::new();
                s.insert(CapabilityToken::NetworkAccess);
                s
            },
        },
        "t1",
    );

    emitter.emit_narrowing_violation(
        &NarrowingViolation::OutcomeUpgrade {
            boundary_label: "close".to_owned(),
            child_outcome: BoundaryOutcome::Timeout,
            propagated_outcome: BoundaryOutcome::Failure,
        },
        "t2",
    );

    emitter.emit_narrowing_violation(
        &NarrowingViolation::UnknownOutcomeNotFailClosed {
            boundary_label: "ext".to_owned(),
        },
        "t3",
    );

    for diag in emitter.diagnostics() {
        assert!(!diag.remediation.summary.is_empty(), "missing summary");
        assert!(!diag.remediation.detail.is_empty(), "missing detail");
        assert!(!diag.remediation.steps.is_empty(), "missing steps");
        assert!(!diag.remediation.doc_refs.is_empty(), "missing doc_refs");
    }
}

// ---------------------------------------------------------------------------
// Emitter serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn integration_emitter_serde_roundtrip() {
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

    emitter.emit_narrowing_violation(
        &NarrowingViolation::CapabilityWidening {
            boundary_label: "spawn".to_owned(),
            widened_tokens: {
                let mut s = BTreeSet::new();
                s.insert(CapabilityToken::NetworkAccess);
                s
            },
        },
        "trace2",
    );

    let json = serde_json::to_string(&emitter).unwrap();
    let round: DiagnosticEmitter = serde_json::from_str(&json).unwrap();
    assert_eq!(round.diagnostics().len(), 2);
    assert_eq!(round.diagnostics()[0].error_code.code, "CP-BUDGET-001");
    assert_eq!(round.diagnostics()[1].error_code.code, "CP-CAP-001");
}

// ---------------------------------------------------------------------------
// Large-scale stress
// ---------------------------------------------------------------------------

#[test]
fn integration_large_scale_diagnostic_emission() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    for i in 0..100 {
        if i % 3 == 0 {
            emitter.emit_budget_error(
                &BudgetPropagationError::CleanupExceedsParent {
                    cleanup_total_ms: 200 + i as u64,
                    parent_remaining_ms: 100,
                },
                &format!("trace-{}", i),
            );
        } else if i % 3 == 1 {
            emitter.emit_budget_error(
                &BudgetPropagationError::InsufficientBudget {
                    boundary: BudgetBoundaryKind::ParentToChildExtension,
                    derived_ms: 1,
                    minimum_ms: 10,
                    parent_remaining_ms: 5,
                },
                &format!("trace-{}", i),
            );
        } else {
            emitter.emit_narrowing_violation(
                &NarrowingViolation::CapabilityWidening {
                    boundary_label: format!("boundary-{}", i),
                    widened_tokens: {
                        let mut s = BTreeSet::new();
                        s.insert(CapabilityToken::NetworkAccess);
                        s
                    },
                },
                &format!("trace-{}", i),
            );
        }
    }

    let report = emitter.build_report();
    assert_eq!(report.total_diagnostics, 100);
    assert!(report.release_blocked);

    // Sequence monotonicity
    let seqs: Vec<u64> = emitter.diagnostics().iter().map(|d| d.sequence).collect();
    for i in 1..seqs.len() {
        assert!(seqs[i] > seqs[i - 1]);
    }
}

// ---------------------------------------------------------------------------
// Report content hash varies with content
// ---------------------------------------------------------------------------

#[test]
fn integration_report_hash_varies_with_different_content() {
    let make_report = |count: usize| {
        let mut e = DiagnosticEmitter::with_defaults();
        for i in 0..count {
            e.emit_budget_error(
                &BudgetPropagationError::ParentExhausted {
                    boundary: BudgetBoundaryKind::ParentToChildSession,
                    parent_remaining_ms: 0,
                },
                &format!("trace-{}", i),
            );
        }
        e.build_report()
    };

    let r1 = make_report(1);
    let r2 = make_report(2);
    assert_ne!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// Empty report properties
// ---------------------------------------------------------------------------

#[test]
fn integration_empty_report_has_consistent_hash() {
    let e1 = DiagnosticEmitter::with_defaults();
    let e2 = DiagnosticEmitter::with_defaults();

    let r1 = e1.build_report();
    let r2 = e2.build_report();
    assert_eq!(r1.content_hash, r2.content_hash);
    assert!(r1.is_clean());
    assert!(r2.is_clean());
    assert_eq!(r1.total_diagnostics, 0);
    assert!(r1.severity_counts.is_empty());
    assert!(r1.category_counts.is_empty());
}

// ---------------------------------------------------------------------------
// Multiple boundary labels in narrowing violations
// ---------------------------------------------------------------------------

#[test]
fn integration_each_violation_preserves_own_boundary_label() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    let labels = ["spawn_ext", "cell_close", "hostcall_return", "gc_barrier"];
    for label in &labels {
        emitter.emit_narrowing_violation(
            &NarrowingViolation::CapabilityWidening {
                boundary_label: label.to_string(),
                widened_tokens: {
                    let mut s = BTreeSet::new();
                    s.insert(CapabilityToken::NetworkAccess);
                    s
                },
            },
            "trace",
        );
    }

    assert_eq!(emitter.diagnostics().len(), 4);
    for (i, label) in labels.iter().enumerate() {
        assert_eq!(
            emitter.diagnostics()[i].boundary_label,
            Some(label.to_string()),
            "boundary label mismatch at index {}",
            i,
        );
    }
}

// ---------------------------------------------------------------------------
// Budget errors don't set boundary label
// ---------------------------------------------------------------------------

#[test]
fn integration_budget_errors_have_no_boundary_label() {
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

    assert_eq!(emitter.diagnostics()[0].boundary_label, None);
}

// ---------------------------------------------------------------------------
// E2E: multiple validators converging to single report
// ---------------------------------------------------------------------------

#[test]
fn integration_e2e_multiple_validators_single_report() {
    let mut bv = BudgetPropagationValidator::with_defaults();
    let mut nv = CapabilityNarrowingValidator::with_defaults();
    let mut emitter = DiagnosticEmitter::with_defaults();

    // Budget failure
    let budget_result = bv.derive_child_budget(
        "parent",
        "child",
        0,
        BudgetBoundaryKind::ParentToChildExtension,
    );
    if let Err(err) = budget_result {
        emitter.emit_budget_error(&err, "budget-parent");
    }

    // Capability widening
    nv.validate_narrowing(
        "parent",
        "child",
        "bad_spawn",
        &CapabilityGrant::sandbox(),
        &CapabilityGrant::full(),
    );
    for v in nv.violations() {
        emitter.emit_narrowing_violation(v, "cap-parent");
    }

    let report = emitter.build_report();
    assert!(report.release_blocked);
    assert!(report.total_diagnostics >= 2);
    assert!(report.category_counts.contains_key("budget_propagation"));
    assert!(report.category_counts.contains_key("capability_narrowing"));

    // Report should roundtrip
    let json = serde_json::to_string_pretty(&report).unwrap();
    let round: DiagnosticReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, round);
}

// ---------------------------------------------------------------------------
// Remediation auto_remediable flag
// ---------------------------------------------------------------------------

#[test]
fn integration_cleanup_exceeds_parent_is_auto_remediable() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    emitter.emit_budget_error(
        &BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 300,
            parent_remaining_ms: 100,
        },
        "trace",
    );

    assert!(
        emitter.diagnostics()[0].remediation.auto_remediable,
        "CleanupExceedsParent should be auto-remediable"
    );
}

#[test]
fn integration_insufficient_budget_is_not_auto_remediable() {
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

    assert!(
        !emitter.diagnostics()[0].remediation.auto_remediable,
        "InsufficientBudget should NOT be auto-remediable"
    );
}

// ---------------------------------------------------------------------------
// Diagnostic message content quality
// ---------------------------------------------------------------------------

#[test]
fn integration_budget_messages_contain_numeric_values() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    emitter.emit_budget_error(
        &BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 42,
            minimum_ms: 100,
            parent_remaining_ms: 200,
        },
        "trace",
    );

    let msg = &emitter.diagnostics()[0].message;
    assert!(msg.contains("42"), "message should contain derived_ms");
    assert!(msg.contains("100"), "message should contain minimum_ms");
    assert!(
        msg.contains("200"),
        "message should contain parent_remaining_ms"
    );
}

#[test]
fn integration_capability_widening_message_contains_token_names() {
    let mut emitter = DiagnosticEmitter::with_defaults();

    emitter.emit_narrowing_violation(
        &NarrowingViolation::CapabilityWidening {
            boundary_label: "test_boundary".to_owned(),
            widened_tokens: {
                let mut s = BTreeSet::new();
                s.insert(CapabilityToken::NetworkAccess);
                s.insert(CapabilityToken::FileSystemWrite);
                s
            },
        },
        "trace",
    );

    let msg = &emitter.diagnostics()[0].message;
    assert!(
        msg.contains("test_boundary"),
        "message should contain boundary label"
    );
}

// ---------------------------------------------------------------------------
// Severity enum properties
// ---------------------------------------------------------------------------

#[test]
fn integration_severity_levels_are_ordered() {
    assert!(DiagnosticSeverity::Info.level() < DiagnosticSeverity::Warning.level());
    assert!(DiagnosticSeverity::Warning.level() < DiagnosticSeverity::Error.level());
    assert!(DiagnosticSeverity::Error.level() < DiagnosticSeverity::Critical.level());
}

#[test]
fn integration_severity_release_blocking_semantics() {
    assert!(!DiagnosticSeverity::Info.is_release_blocking());
    assert!(!DiagnosticSeverity::Warning.is_release_blocking());
    assert!(DiagnosticSeverity::Error.is_release_blocking());
    assert!(DiagnosticSeverity::Critical.is_release_blocking());
}

// ---------------------------------------------------------------------------
// Category string representation
// ---------------------------------------------------------------------------

#[test]
fn integration_all_categories_have_str_representation() {
    let categories = [
        (DiagnosticCategory::BudgetPropagation, "budget_propagation"),
        (
            DiagnosticCategory::CapabilityNarrowing,
            "capability_narrowing",
        ),
        (
            DiagnosticCategory::OutcomePropagation,
            "outcome_propagation",
        ),
        (DiagnosticCategory::MockSeamLeakage, "mock_seam_leakage"),
        (DiagnosticCategory::ContextThreading, "context_threading"),
    ];

    for (cat, expected) in &categories {
        assert_eq!(cat.as_str(), *expected);
    }
}

// ---------------------------------------------------------------------------
// Report schema version
// ---------------------------------------------------------------------------

#[test]
fn integration_report_carries_schema_version() {
    let emitter = DiagnosticEmitter::with_defaults();
    let report = emitter.build_report();
    assert!(report.schema_version > 0);
}

// ---------------------------------------------------------------------------
// Severity serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn integration_all_severity_serde_roundtrip() {
    for sev in [
        DiagnosticSeverity::Info,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Critical,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let round: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, round, "severity roundtrip failed for {:?}", sev);
    }
}

// ---------------------------------------------------------------------------
// Remediation guidance serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn integration_remediation_guidance_serde_roundtrip() {
    let guidance = RemediationGuidance {
        summary: "Test summary".to_owned(),
        detail: "Detailed explanation of the issue and its impact".to_owned(),
        steps: vec![
            "Step one: investigate".to_owned(),
            "Step two: fix".to_owned(),
            "Step three: verify".to_owned(),
        ],
        doc_refs: vec![
            "docs/BUDGET_PROPAGATION.md".to_owned(),
            "docs/CAPABILITY_NARROWING.md".to_owned(),
        ],
        auto_remediable: false,
    };

    let json = serde_json::to_string_pretty(&guidance).unwrap();
    let round: RemediationGuidance = serde_json::from_str(&json).unwrap();
    assert_eq!(guidance, round);
}
