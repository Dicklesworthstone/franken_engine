//! Deep integration tests for control_plane_policy_diagnostics module.
//!
//! Covers: diagnostic emitter lifecycle, severity filtering, release-blocking
//! detection, report content-hash stability, serde roundtrips, error code
//! structure, remediation guidance validation, and multi-category diagnostics.

use frankenengine_engine::budget_propagation_contract::{
    BudgetBoundaryKind, BudgetPropagationError,
};
use frankenengine_engine::control_plane_policy_diagnostics::{
    ControlPlaneDiagnostic, DiagnosticCategory, DiagnosticEmitter, DiagnosticErrorCode,
    DiagnosticReport, DiagnosticSeverity, RemediationGuidance,
};
use frankenengine_engine::outcome_capability_narrowing::{
    BoundaryOutcome, CapabilityToken, NarrowingViolation,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// ---------------------------------------------------------------------------
// DiagnosticSeverity exhaustive
// ---------------------------------------------------------------------------

#[test]
fn deep_severity_ordering_all() {
    let severities = [
        DiagnosticSeverity::Info,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Critical,
    ];
    for window in severities.windows(2) {
        assert!(
            window[0].level() < window[1].level(),
            "{} should be < {}",
            window[0].as_str(),
            window[1].as_str()
        );
    }
}

#[test]
fn deep_severity_as_str_all() {
    assert_eq!(DiagnosticSeverity::Info.as_str(), "info");
    assert_eq!(DiagnosticSeverity::Warning.as_str(), "warning");
    assert_eq!(DiagnosticSeverity::Error.as_str(), "error");
    assert_eq!(DiagnosticSeverity::Critical.as_str(), "critical");
}

#[test]
fn deep_severity_release_blocking_exhaustive() {
    assert!(!DiagnosticSeverity::Info.is_release_blocking());
    assert!(!DiagnosticSeverity::Warning.is_release_blocking());
    assert!(DiagnosticSeverity::Error.is_release_blocking());
    assert!(DiagnosticSeverity::Critical.is_release_blocking());
}

#[test]
fn deep_severity_serde_roundtrip() {
    let severities = [
        DiagnosticSeverity::Info,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Critical,
    ];
    for sev in severities {
        let json = serde_json::to_string(&sev).unwrap();
        let decoded: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, decoded);
    }
}

// ---------------------------------------------------------------------------
// DiagnosticCategory
// ---------------------------------------------------------------------------

#[test]
fn deep_category_as_str_all() {
    assert_eq!(
        DiagnosticCategory::BudgetPropagation.as_str(),
        "budget_propagation"
    );
    assert_eq!(
        DiagnosticCategory::CapabilityNarrowing.as_str(),
        "capability_narrowing"
    );
    assert_eq!(
        DiagnosticCategory::OutcomePropagation.as_str(),
        "outcome_propagation"
    );
    assert_eq!(
        DiagnosticCategory::MockSeamLeakage.as_str(),
        "mock_seam_leakage"
    );
    assert_eq!(
        DiagnosticCategory::ContextThreading.as_str(),
        "context_threading"
    );
}

#[test]
fn deep_category_serde_roundtrip() {
    let categories = [
        DiagnosticCategory::BudgetPropagation,
        DiagnosticCategory::CapabilityNarrowing,
        DiagnosticCategory::OutcomePropagation,
        DiagnosticCategory::MockSeamLeakage,
        DiagnosticCategory::ContextThreading,
    ];
    for cat in categories {
        let json = serde_json::to_string(&cat).unwrap();
        let decoded: DiagnosticCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, decoded);
    }
}

// ---------------------------------------------------------------------------
// DiagnosticErrorCode
// ---------------------------------------------------------------------------

#[test]
fn deep_error_code_serde_roundtrip() {
    let code = DiagnosticErrorCode {
        code: "CP-BUDGET-001".to_string(),
        category: DiagnosticCategory::BudgetPropagation,
        severity: DiagnosticSeverity::Error,
    };
    let json = serde_json::to_string(&code).unwrap();
    let decoded: DiagnosticErrorCode = serde_json::from_str(&json).unwrap();
    assert_eq!(code, decoded);
}

#[test]
fn deep_error_code_display() {
    let code = DiagnosticErrorCode {
        code: "CP-CAP-001".to_string(),
        category: DiagnosticCategory::CapabilityNarrowing,
        severity: DiagnosticSeverity::Critical,
    };
    assert_eq!(format!("{}", code), "CP-CAP-001");
}

// ---------------------------------------------------------------------------
// RemediationGuidance
// ---------------------------------------------------------------------------

#[test]
fn deep_remediation_serde_roundtrip() {
    let guidance = RemediationGuidance {
        summary: "Test issue summary".to_string(),
        detail: "Detailed description of the issue".to_string(),
        steps: vec![
            "Step 1: investigate".to_string(),
            "Step 2: fix".to_string(),
            "Step 3: verify".to_string(),
        ],
        doc_refs: vec!["docs/TESTING.md".to_string()],
        auto_remediable: false,
    };
    let json = serde_json::to_string(&guidance).unwrap();
    let decoded: RemediationGuidance = serde_json::from_str(&json).unwrap();
    assert_eq!(guidance, decoded);
}

#[test]
fn deep_remediation_auto_remediable_flag() {
    let guidance_auto = RemediationGuidance {
        summary: "Auto-fixable".to_string(),
        detail: "Can be auto-remediated".to_string(),
        steps: vec!["Run auto-fix".to_string()],
        doc_refs: vec![],
        auto_remediable: true,
    };
    assert!(guidance_auto.auto_remediable);

    let guidance_manual = RemediationGuidance {
        summary: "Manual fix".to_string(),
        detail: "Must be fixed manually".to_string(),
        steps: vec!["Manually update config".to_string()],
        doc_refs: vec![],
        auto_remediable: false,
    };
    assert!(!guidance_manual.auto_remediable);
}

// ---------------------------------------------------------------------------
// DiagnosticEmitter — budget error emission
// ---------------------------------------------------------------------------

#[test]
fn deep_emitter_budget_insufficient() {
    let mut emitter = DiagnosticEmitter::new(epoch(1));
    let err = BudgetPropagationError::InsufficientBudget {
        boundary: BudgetBoundaryKind::ParentToChildExtension,
        derived_ms: 5,
        minimum_ms: 50,
        parent_remaining_ms: 100,
    };
    emitter.emit_budget_error(&err, "trace-001");

    assert_eq!(emitter.diagnostics().len(), 1);
    let diag = &emitter.diagnostics()[0];
    assert_eq!(diag.error_code.code, "CP-BUDGET-001");
    assert_eq!(diag.error_code.severity, DiagnosticSeverity::Error);
    assert_eq!(
        diag.error_code.category,
        DiagnosticCategory::BudgetPropagation
    );
    assert!(diag.message.contains("Insufficient budget"));
    assert!(diag.remediation.steps.len() >= 2);
    assert_eq!(diag.trace_ids, vec!["trace-001"]);
}

#[test]
fn deep_emitter_budget_no_rule() {
    let mut emitter = DiagnosticEmitter::new(epoch(1));
    let err = BudgetPropagationError::NoRuleForBoundary {
        boundary: BudgetBoundaryKind::ParentToChildSession,
    };
    emitter.emit_budget_error(&err, "trace-002");

    let diag = &emitter.diagnostics()[0];
    assert_eq!(diag.error_code.code, "CP-BUDGET-002");
    assert_eq!(diag.error_code.severity, DiagnosticSeverity::Critical);
}

#[test]
fn deep_emitter_budget_parent_exhausted() {
    let mut emitter = DiagnosticEmitter::new(epoch(1));
    let err = BudgetPropagationError::ParentExhausted {
        boundary: BudgetBoundaryKind::ParentToChildDelegate,
        parent_remaining_ms: 0,
    };
    emitter.emit_budget_error(&err, "trace-003");

    let diag = &emitter.diagnostics()[0];
    assert_eq!(diag.error_code.code, "CP-BUDGET-003");
    assert_eq!(diag.error_code.severity, DiagnosticSeverity::Error);
    assert!(diag.message.contains("exhausted"));
}

#[test]
fn deep_emitter_budget_cleanup_exceeds() {
    let mut emitter = DiagnosticEmitter::new(epoch(1));
    let err = BudgetPropagationError::CleanupExceedsParent {
        cleanup_total_ms: 200,
        parent_remaining_ms: 100,
    };
    emitter.emit_budget_error(&err, "trace-004");

    let diag = &emitter.diagnostics()[0];
    assert_eq!(diag.error_code.code, "CP-BUDGET-004");
    assert_eq!(diag.error_code.severity, DiagnosticSeverity::Warning);
    assert!(diag.remediation.auto_remediable);
}

#[test]
fn deep_emitter_budget_child_exceeds() {
    let mut emitter = DiagnosticEmitter::new(epoch(1));
    let err = BudgetPropagationError::ChildExceedsParent {
        child_ms: 500,
        parent_ms: 200,
    };
    emitter.emit_budget_error(&err, "trace-005");

    let diag = &emitter.diagnostics()[0];
    assert_eq!(diag.error_code.code, "CP-BUDGET-005");
    assert_eq!(diag.error_code.severity, DiagnosticSeverity::Critical);
    assert!(!diag.remediation.auto_remediable);
    assert!(diag.message.contains("500"));
    assert!(diag.message.contains("200"));
}

// ---------------------------------------------------------------------------
// DiagnosticEmitter — narrowing violation emission
// ---------------------------------------------------------------------------

#[test]
fn deep_emitter_capability_widening() {
    let mut emitter = DiagnosticEmitter::new(epoch(2));
    let mut tokens = std::collections::BTreeSet::new();
    tokens.insert(CapabilityToken::NetworkAccess);
    tokens.insert(CapabilityToken::FileSystemWrite);

    let violation = NarrowingViolation::CapabilityWidening {
        boundary_label: "test_boundary".to_string(),
        widened_tokens: tokens,
    };
    emitter.emit_narrowing_violation(&violation, "trace-nar-001");

    let diag = &emitter.diagnostics()[0];
    assert_eq!(diag.error_code.code, "CP-CAP-001");
    assert_eq!(diag.error_code.severity, DiagnosticSeverity::Critical);
    assert_eq!(
        diag.error_code.category,
        DiagnosticCategory::CapabilityNarrowing
    );
    assert!(diag.message.contains("Capability widening"));
    assert!(diag.message.contains("network"));
    assert_eq!(diag.boundary_label.as_deref(), Some("test_boundary"));
}

#[test]
fn deep_emitter_outcome_upgrade() {
    let mut emitter = DiagnosticEmitter::new(epoch(2));
    let violation = NarrowingViolation::OutcomeUpgrade {
        boundary_label: "upgrade_boundary".to_string(),
        child_outcome: BoundaryOutcome::Timeout,
        propagated_outcome: BoundaryOutcome::Success,
    };
    emitter.emit_narrowing_violation(&violation, "trace-nar-002");

    let diag = &emitter.diagnostics()[0];
    assert_eq!(diag.error_code.code, "CP-OUTCOME-001");
    assert_eq!(diag.error_code.severity, DiagnosticSeverity::Error);
    assert_eq!(
        diag.error_code.category,
        DiagnosticCategory::OutcomePropagation
    );
    assert!(diag.message.contains("Outcome upgrade"));
    assert_eq!(diag.boundary_label.as_deref(), Some("upgrade_boundary"));
}

#[test]
fn deep_emitter_unknown_outcome() {
    let mut emitter = DiagnosticEmitter::new(epoch(2));
    let violation = NarrowingViolation::UnknownOutcomeNotFailClosed {
        boundary_label: "unknown_boundary".to_string(),
    };
    emitter.emit_narrowing_violation(&violation, "trace-nar-003");

    let diag = &emitter.diagnostics()[0];
    assert_eq!(diag.error_code.code, "CP-OUTCOME-002");
    assert_eq!(diag.error_code.severity, DiagnosticSeverity::Critical);
    assert!(diag.message.contains("Unknown outcome"));
    assert_eq!(diag.boundary_label.as_deref(), Some("unknown_boundary"));
}

// ---------------------------------------------------------------------------
// Severity filtering
// ---------------------------------------------------------------------------

#[test]
fn deep_emitter_filter_by_severity() {
    let mut emitter = DiagnosticEmitter::new(epoch(3));

    // Warning
    emitter.emit_budget_error(
        &BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 200,
            parent_remaining_ms: 100,
        },
        "t1",
    );
    // Error
    emitter.emit_budget_error(
        &BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 5,
            minimum_ms: 50,
            parent_remaining_ms: 100,
        },
        "t2",
    );
    // Critical
    emitter.emit_budget_error(
        &BudgetPropagationError::NoRuleForBoundary {
            boundary: BudgetBoundaryKind::ParentToChildSession,
        },
        "t3",
    );

    assert_eq!(emitter.diagnostics().len(), 3);

    // Filter at Warning: all 3
    let warning_up = emitter.diagnostics_at_severity(DiagnosticSeverity::Warning);
    assert_eq!(warning_up.len(), 3);

    // Filter at Error: 2 (error + critical)
    let error_up = emitter.diagnostics_at_severity(DiagnosticSeverity::Error);
    assert_eq!(error_up.len(), 2);

    // Filter at Critical: 1
    let critical = emitter.diagnostics_at_severity(DiagnosticSeverity::Critical);
    assert_eq!(critical.len(), 1);

    // Filter at Info: all
    let info_up = emitter.diagnostics_at_severity(DiagnosticSeverity::Info);
    assert_eq!(info_up.len(), 3);
}

// ---------------------------------------------------------------------------
// Release blocking detection
// ---------------------------------------------------------------------------

#[test]
fn deep_emitter_no_release_blockers_on_warnings_only() {
    let mut emitter = DiagnosticEmitter::new(epoch(4));
    emitter.emit_budget_error(
        &BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 200,
            parent_remaining_ms: 100,
        },
        "t1",
    );
    assert!(!emitter.has_release_blockers());
}

#[test]
fn deep_emitter_release_blocked_on_error() {
    let mut emitter = DiagnosticEmitter::new(epoch(4));
    emitter.emit_budget_error(
        &BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 5,
            minimum_ms: 50,
            parent_remaining_ms: 100,
        },
        "t1",
    );
    assert!(emitter.has_release_blockers());
}

#[test]
fn deep_emitter_release_blocked_on_critical() {
    let mut emitter = DiagnosticEmitter::new(epoch(4));
    emitter.emit_budget_error(
        &BudgetPropagationError::NoRuleForBoundary {
            boundary: BudgetBoundaryKind::ParentToChildSession,
        },
        "t1",
    );
    assert!(emitter.has_release_blockers());
}

// ---------------------------------------------------------------------------
// Max severity
// ---------------------------------------------------------------------------

#[test]
fn deep_emitter_max_severity_empty() {
    let emitter = DiagnosticEmitter::new(epoch(5));
    assert_eq!(emitter.max_severity(), None);
}

#[test]
fn deep_emitter_max_severity_mixed() {
    let mut emitter = DiagnosticEmitter::new(epoch(5));

    // Warning
    emitter.emit_budget_error(
        &BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 200,
            parent_remaining_ms: 100,
        },
        "t1",
    );
    assert_eq!(emitter.max_severity(), Some(DiagnosticSeverity::Warning));

    // Error
    emitter.emit_budget_error(
        &BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 5,
            minimum_ms: 50,
            parent_remaining_ms: 100,
        },
        "t2",
    );
    assert_eq!(emitter.max_severity(), Some(DiagnosticSeverity::Error));

    // Critical
    emitter.emit_budget_error(
        &BudgetPropagationError::ChildExceedsParent {
            child_ms: 500,
            parent_ms: 200,
        },
        "t3",
    );
    assert_eq!(emitter.max_severity(), Some(DiagnosticSeverity::Critical));
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

#[test]
fn deep_report_empty_is_clean() {
    let emitter = DiagnosticEmitter::new(epoch(6));
    let report = emitter.build_report();
    assert!(report.is_clean());
    assert_eq!(report.total_diagnostics, 0);
    assert!(!report.release_blocked);
    assert_eq!(report.max_severity, None);
}

#[test]
fn deep_report_counts_correct() {
    let mut emitter = DiagnosticEmitter::new(epoch(6));

    // 1 warning (budget)
    emitter.emit_budget_error(
        &BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 200,
            parent_remaining_ms: 100,
        },
        "t1",
    );
    // 1 critical (capability)
    let mut tokens = std::collections::BTreeSet::new();
    tokens.insert(CapabilityToken::NetworkAccess);
    emitter.emit_narrowing_violation(
        &NarrowingViolation::CapabilityWidening {
            boundary_label: "b1".to_string(),
            widened_tokens: tokens,
        },
        "t2",
    );
    // 1 error (outcome)
    emitter.emit_narrowing_violation(
        &NarrowingViolation::OutcomeUpgrade {
            boundary_label: "b2".to_string(),
            child_outcome: BoundaryOutcome::Timeout,
            propagated_outcome: BoundaryOutcome::Success,
        },
        "t3",
    );

    let report = emitter.build_report();
    assert_eq!(report.total_diagnostics, 3);
    assert!(report.release_blocked);
    assert_eq!(report.max_severity, Some(DiagnosticSeverity::Critical));
    assert_eq!(*report.severity_counts.get("warning").unwrap_or(&0), 1);
    assert_eq!(*report.severity_counts.get("critical").unwrap_or(&0), 1);
    assert_eq!(*report.severity_counts.get("error").unwrap_or(&0), 1);
    assert_eq!(
        *report
            .category_counts
            .get("budget_propagation")
            .unwrap_or(&0),
        1
    );
    assert_eq!(
        *report
            .category_counts
            .get("capability_narrowing")
            .unwrap_or(&0),
        1
    );
    assert_eq!(
        *report
            .category_counts
            .get("outcome_propagation")
            .unwrap_or(&0),
        1
    );
}

#[test]
fn deep_report_content_hash_deterministic() {
    let build = || {
        let mut emitter = DiagnosticEmitter::new(epoch(7));
        emitter.emit_budget_error(
            &BudgetPropagationError::InsufficientBudget {
                boundary: BudgetBoundaryKind::ParentToChildExtension,
                derived_ms: 5,
                minimum_ms: 50,
                parent_remaining_ms: 100,
            },
            "t1",
        );
        emitter.build_report()
    };

    let r1 = build();
    let r2 = build();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn deep_report_content_hash_changes_with_different_diagnostics() {
    let mut e1 = DiagnosticEmitter::new(epoch(7));
    e1.emit_budget_error(
        &BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 5,
            minimum_ms: 50,
            parent_remaining_ms: 100,
        },
        "t1",
    );
    let r1 = e1.build_report();

    let mut e2 = DiagnosticEmitter::new(epoch(7));
    e2.emit_budget_error(
        &BudgetPropagationError::ChildExceedsParent {
            child_ms: 500,
            parent_ms: 200,
        },
        "t1",
    );
    let r2 = e2.build_report();

    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn deep_report_serde_roundtrip() {
    let mut emitter = DiagnosticEmitter::new(epoch(8));
    emitter.emit_budget_error(
        &BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 5,
            minimum_ms: 50,
            parent_remaining_ms: 100,
        },
        "t1",
    );
    let report = emitter.build_report();
    let json = serde_json::to_string(&report).unwrap();
    let decoded: DiagnosticReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, decoded);
}

// ---------------------------------------------------------------------------
// Sequence numbering
// ---------------------------------------------------------------------------

#[test]
fn deep_emitter_sequence_numbers_monotonic() {
    let mut emitter = DiagnosticEmitter::new(epoch(9));

    emitter.emit_budget_error(
        &BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 200,
            parent_remaining_ms: 100,
        },
        "t1",
    );
    emitter.emit_budget_error(
        &BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 5,
            minimum_ms: 50,
            parent_remaining_ms: 100,
        },
        "t2",
    );
    let mut tokens = std::collections::BTreeSet::new();
    tokens.insert(CapabilityToken::NetworkAccess);
    emitter.emit_narrowing_violation(
        &NarrowingViolation::CapabilityWidening {
            boundary_label: "b1".to_string(),
            widened_tokens: tokens,
        },
        "t3",
    );

    let seqs: Vec<u64> = emitter.diagnostics().iter().map(|d| d.sequence).collect();
    assert_eq!(seqs, vec![1, 2, 3]);
    for window in seqs.windows(2) {
        assert!(window[0] < window[1]);
    }
}

// ---------------------------------------------------------------------------
// Emitter serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn deep_emitter_serde_roundtrip() {
    let mut emitter = DiagnosticEmitter::new(epoch(10));
    emitter.emit_budget_error(
        &BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 5,
            minimum_ms: 50,
            parent_remaining_ms: 100,
        },
        "t1",
    );

    let json = serde_json::to_string(&emitter).unwrap();
    let decoded: DiagnosticEmitter = serde_json::from_str(&json).unwrap();
    assert_eq!(emitter.diagnostics().len(), decoded.diagnostics().len());
    assert_eq!(
        emitter.has_release_blockers(),
        decoded.has_release_blockers()
    );
}

// ---------------------------------------------------------------------------
// Epoch propagation
// ---------------------------------------------------------------------------

#[test]
fn deep_report_preserves_epoch() {
    let e = epoch(42);
    let emitter = DiagnosticEmitter::new(e);
    let report = emitter.build_report();
    assert_eq!(report.epoch, e);
}

// ---------------------------------------------------------------------------
// ControlPlaneDiagnostic serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn deep_diagnostic_serde_roundtrip() {
    let diag = ControlPlaneDiagnostic {
        error_code: DiagnosticErrorCode {
            code: "CP-TEST-001".to_string(),
            category: DiagnosticCategory::BudgetPropagation,
            severity: DiagnosticSeverity::Error,
        },
        message: "Test diagnostic message".to_string(),
        remediation: RemediationGuidance {
            summary: "Fix the issue".to_string(),
            detail: "Detailed instructions".to_string(),
            steps: vec!["Step 1".to_string()],
            doc_refs: vec!["docs/TEST.md".to_string()],
            auto_remediable: false,
        },
        trace_ids: vec!["trace-001".to_string()],
        boundary_label: Some("test_boundary".to_string()),
        context: std::collections::BTreeMap::new(),
        sequence: 1,
    };
    let json = serde_json::to_string(&diag).unwrap();
    let decoded: ControlPlaneDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, decoded);
}

// ---------------------------------------------------------------------------
// Mixed budget + narrowing diagnostics
// ---------------------------------------------------------------------------

#[test]
fn deep_mixed_diagnostics_all_categories() {
    let mut emitter = DiagnosticEmitter::new(epoch(11));

    // Budget error
    emitter.emit_budget_error(
        &BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 5,
            minimum_ms: 50,
            parent_remaining_ms: 100,
        },
        "t1",
    );

    // Capability widening
    let mut tokens = std::collections::BTreeSet::new();
    tokens.insert(CapabilityToken::ProcessSpawn);
    emitter.emit_narrowing_violation(
        &NarrowingViolation::CapabilityWidening {
            boundary_label: "cap_test".to_string(),
            widened_tokens: tokens,
        },
        "t2",
    );

    // Outcome upgrade
    emitter.emit_narrowing_violation(
        &NarrowingViolation::OutcomeUpgrade {
            boundary_label: "outcome_test".to_string(),
            child_outcome: BoundaryOutcome::Cancelled,
            propagated_outcome: BoundaryOutcome::Success,
        },
        "t3",
    );

    assert_eq!(emitter.diagnostics().len(), 3);
    assert!(emitter.has_release_blockers());

    let report = emitter.build_report();
    assert!(!report.is_clean());
    assert_eq!(report.total_diagnostics, 3);
    assert!(report.category_counts.contains_key("budget_propagation"));
    assert!(report.category_counts.contains_key("capability_narrowing"));
    assert!(report.category_counts.contains_key("outcome_propagation"));
}

// ---------------------------------------------------------------------------
// Remediation guidance structure
// ---------------------------------------------------------------------------

#[test]
fn deep_all_budget_errors_have_nonempty_remediation() {
    let errors = [
        BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 5,
            minimum_ms: 50,
            parent_remaining_ms: 100,
        },
        BudgetPropagationError::NoRuleForBoundary {
            boundary: BudgetBoundaryKind::ParentToChildSession,
        },
        BudgetPropagationError::ParentExhausted {
            boundary: BudgetBoundaryKind::ParentToChildDelegate,
            parent_remaining_ms: 0,
        },
        BudgetPropagationError::CleanupExceedsParent {
            cleanup_total_ms: 200,
            parent_remaining_ms: 100,
        },
        BudgetPropagationError::ChildExceedsParent {
            child_ms: 500,
            parent_ms: 200,
        },
    ];

    for err in &errors {
        let mut emitter = DiagnosticEmitter::new(epoch(12));
        emitter.emit_budget_error(err, "trace");
        let diag = &emitter.diagnostics()[0];
        assert!(!diag.remediation.summary.is_empty());
        assert!(!diag.remediation.detail.is_empty());
        assert!(!diag.remediation.steps.is_empty());
        assert!(!diag.remediation.doc_refs.is_empty());
    }
}

#[test]
fn deep_all_narrowing_violations_have_nonempty_remediation() {
    let mut tokens = std::collections::BTreeSet::new();
    tokens.insert(CapabilityToken::NetworkAccess);

    let violations = [
        NarrowingViolation::CapabilityWidening {
            boundary_label: "b1".to_string(),
            widened_tokens: tokens,
        },
        NarrowingViolation::OutcomeUpgrade {
            boundary_label: "b2".to_string(),
            child_outcome: BoundaryOutcome::Timeout,
            propagated_outcome: BoundaryOutcome::Success,
        },
        NarrowingViolation::UnknownOutcomeNotFailClosed {
            boundary_label: "b3".to_string(),
        },
    ];

    for violation in &violations {
        let mut emitter = DiagnosticEmitter::new(epoch(13));
        emitter.emit_narrowing_violation(violation, "trace");
        let diag = &emitter.diagnostics()[0];
        assert!(!diag.remediation.summary.is_empty());
        assert!(!diag.remediation.detail.is_empty());
        assert!(!diag.remediation.steps.is_empty());
    }
}
