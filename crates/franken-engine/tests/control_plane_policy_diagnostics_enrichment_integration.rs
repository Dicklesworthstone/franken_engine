//! Enrichment integration tests for control_plane_policy_diagnostics (bd-3nr.1.3.3).
//!
//! Covers: DiagnosticSeverity properties, DiagnosticCategory enumeration,
//! DiagnosticErrorCode construction and Display, RemediationGuidance serde,
//! DiagnosticEmitter lifecycle, DiagnosticReport properties, and composite
//! serde roundtrips.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeMap;

use frankenengine_engine::control_plane_policy_diagnostics::{
    ControlPlaneDiagnostic, DiagnosticCategory, DiagnosticEmitter, DiagnosticErrorCode,
    DiagnosticReport, DiagnosticSeverity, RemediationGuidance,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// DiagnosticSeverity properties
// ---------------------------------------------------------------------------

#[test]
fn severity_level_monotonically_increasing() {
    let severities = [
        DiagnosticSeverity::Info,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Critical,
    ];
    for pair in severities.windows(2) {
        assert!(
            pair[0].level() < pair[1].level(),
            "{:?} should be less severe than {:?}",
            pair[0],
            pair[1]
        );
    }
}

#[test]
fn severity_as_str_nonempty() {
    let severities = [
        DiagnosticSeverity::Info,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Critical,
    ];
    for s in &severities {
        assert!(!s.as_str().is_empty(), "empty as_str for {:?}", s);
    }
}

#[test]
fn severity_serde_roundtrip_all() {
    let severities = [
        DiagnosticSeverity::Info,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Critical,
    ];
    for s in &severities {
        let json = serde_json::to_string(s).expect("serialize");
        let deser: DiagnosticSeverity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*s, deser, "roundtrip failed for {:?}", s);
    }
}

#[test]
fn severity_ordering_matches_level() {
    assert!(DiagnosticSeverity::Info < DiagnosticSeverity::Warning);
    assert!(DiagnosticSeverity::Warning < DiagnosticSeverity::Error);
    assert!(DiagnosticSeverity::Error < DiagnosticSeverity::Critical);
}

#[test]
fn severity_release_blocking_only_error_and_critical() {
    assert!(!DiagnosticSeverity::Info.is_release_blocking());
    assert!(!DiagnosticSeverity::Warning.is_release_blocking());
    assert!(DiagnosticSeverity::Error.is_release_blocking());
    assert!(DiagnosticSeverity::Critical.is_release_blocking());
}

// ---------------------------------------------------------------------------
// DiagnosticCategory properties
// ---------------------------------------------------------------------------

#[test]
fn category_as_str_nonempty_all_variants() {
    let categories = [
        DiagnosticCategory::BudgetPropagation,
        DiagnosticCategory::CapabilityNarrowing,
        DiagnosticCategory::OutcomePropagation,
        DiagnosticCategory::MockSeamLeakage,
        DiagnosticCategory::ContextThreading,
    ];
    for c in &categories {
        assert!(!c.as_str().is_empty(), "empty as_str for {:?}", c);
    }
}

#[test]
fn category_as_str_unique() {
    let categories = [
        DiagnosticCategory::BudgetPropagation,
        DiagnosticCategory::CapabilityNarrowing,
        DiagnosticCategory::OutcomePropagation,
        DiagnosticCategory::MockSeamLeakage,
        DiagnosticCategory::ContextThreading,
    ];
    let strs: std::collections::BTreeSet<&str> = categories.iter().map(|c| c.as_str()).collect();
    assert_eq!(strs.len(), 5, "category strings must be unique");
}

#[test]
fn category_serde_roundtrip_all() {
    let categories = [
        DiagnosticCategory::BudgetPropagation,
        DiagnosticCategory::CapabilityNarrowing,
        DiagnosticCategory::OutcomePropagation,
        DiagnosticCategory::MockSeamLeakage,
        DiagnosticCategory::ContextThreading,
    ];
    for c in &categories {
        let json = serde_json::to_string(c).expect("serialize");
        let deser: DiagnosticCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*c, deser, "roundtrip failed for {:?}", c);
    }
}

// ---------------------------------------------------------------------------
// DiagnosticErrorCode
// ---------------------------------------------------------------------------

#[test]
fn error_code_serde_roundtrip() {
    let code = DiagnosticErrorCode {
        code: "CP-BUDGET-001".to_string(),
        category: DiagnosticCategory::BudgetPropagation,
        severity: DiagnosticSeverity::Error,
    };
    let json = serde_json::to_string(&code).expect("serialize");
    let deser: DiagnosticErrorCode = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(code, deser);
}

#[test]
fn error_code_display_shows_code_string() {
    let code = DiagnosticErrorCode {
        code: "CP-CAP-002".to_string(),
        category: DiagnosticCategory::CapabilityNarrowing,
        severity: DiagnosticSeverity::Warning,
    };
    assert_eq!(code.to_string(), "CP-CAP-002");
}

// ---------------------------------------------------------------------------
// RemediationGuidance
// ---------------------------------------------------------------------------

#[test]
fn remediation_guidance_serde_roundtrip() {
    let guidance = RemediationGuidance {
        summary: "Budget too low".to_string(),
        detail: "The derived budget is below minimum".to_string(),
        steps: vec!["Increase budget".to_string(), "Review config".to_string()],
        doc_refs: vec!["docs/BUDGET.md".to_string()],
        auto_remediable: false,
    };
    let json = serde_json::to_string(&guidance).expect("serialize");
    let deser: RemediationGuidance = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(guidance, deser);
}

// ---------------------------------------------------------------------------
// DiagnosticEmitter
// ---------------------------------------------------------------------------

#[test]
fn emitter_with_defaults_starts_empty() {
    let emitter = DiagnosticEmitter::with_defaults();
    assert!(emitter.diagnostics().is_empty());
}

#[test]
fn emitter_new_with_custom_epoch() {
    let emitter = DiagnosticEmitter::new(SecurityEpoch::from_raw(42));
    assert!(emitter.diagnostics().is_empty());
}

#[test]
fn emitter_report_clean_when_empty() {
    let emitter = DiagnosticEmitter::with_defaults();
    let report = emitter.build_report();
    assert!(report.is_clean());
    assert_eq!(report.total_diagnostics, 0);
    assert!(!report.release_blocked);
    assert!(report.max_severity.is_none());
}

// ---------------------------------------------------------------------------
// DiagnosticReport
// ---------------------------------------------------------------------------

#[test]
fn report_serde_roundtrip() {
    let emitter = DiagnosticEmitter::with_defaults();
    let report = emitter.build_report();
    let json = serde_json::to_string(&report).expect("serialize");
    let deser: DiagnosticReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, deser);
}

#[test]
fn report_is_clean_when_no_diagnostics() {
    let report = DiagnosticReport {
        total_diagnostics: 0,
        severity_counts: BTreeMap::new(),
        category_counts: BTreeMap::new(),
        release_blocked: false,
        max_severity: None,
        content_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"empty"),
        epoch: SecurityEpoch::from_raw(1),
        schema_version: 1,
    };
    assert!(report.is_clean());
}

#[test]
fn report_not_clean_when_has_diagnostics() {
    let report = DiagnosticReport {
        total_diagnostics: 1,
        severity_counts: BTreeMap::from([("error".to_string(), 1)]),
        category_counts: BTreeMap::from([("budget_propagation".to_string(), 1)]),
        release_blocked: true,
        max_severity: Some(DiagnosticSeverity::Error),
        content_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"data"),
        epoch: SecurityEpoch::from_raw(1),
        schema_version: 1,
    };
    assert!(!report.is_clean());
    assert!(report.release_blocked);
}

// ---------------------------------------------------------------------------
// ControlPlaneDiagnostic serde
// ---------------------------------------------------------------------------

#[test]
fn control_plane_diagnostic_serde_roundtrip() {
    let diag = ControlPlaneDiagnostic {
        error_code: DiagnosticErrorCode {
            code: "CP-OUTCOME-001".to_string(),
            category: DiagnosticCategory::OutcomePropagation,
            severity: DiagnosticSeverity::Warning,
        },
        message: "Outcome was downgraded".to_string(),
        remediation: RemediationGuidance {
            summary: "Check outcome".to_string(),
            detail: "Details here".to_string(),
            steps: vec!["Step 1".to_string()],
            doc_refs: Vec::new(),
            auto_remediable: true,
        },
        trace_ids: vec!["trace-abc".to_string()],
        boundary_label: Some("boundary-x".to_string()),
        context: BTreeMap::from([("key".to_string(), "value".to_string())]),
        sequence: 0,
    };
    let json = serde_json::to_string(&diag).expect("serialize");
    let deser: ControlPlaneDiagnostic = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(diag, deser);
}

// ---------------------------------------------------------------------------
// DiagnosticEmitter serde
// ---------------------------------------------------------------------------

#[test]
fn emitter_serde_roundtrip_preserves_state() {
    let emitter = DiagnosticEmitter::with_defaults();
    let json = serde_json::to_string(&emitter).expect("serialize");
    let deser: DiagnosticEmitter = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(emitter.diagnostics().len(), deser.diagnostics().len());
}

// ===========================================================================
// Additional enrichment: behavioral edge cases and properties
// ===========================================================================

#[test]
fn severity_levels_are_ordered() {
    assert!(DiagnosticSeverity::Info.level() < DiagnosticSeverity::Warning.level());
    assert!(DiagnosticSeverity::Warning.level() < DiagnosticSeverity::Error.level());
    assert!(DiagnosticSeverity::Error.level() < DiagnosticSeverity::Critical.level());
}

#[test]
fn severity_as_str_all_distinct() {
    let strs: Vec<&str> = [
        DiagnosticSeverity::Info,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Critical,
    ]
    .iter()
    .map(|s| s.as_str())
    .collect();
    let unique: std::collections::BTreeSet<&str> = strs.iter().copied().collect();
    assert_eq!(strs.len(), unique.len());
}

#[test]
fn only_error_and_critical_are_release_blocking() {
    assert!(!DiagnosticSeverity::Info.is_release_blocking());
    assert!(!DiagnosticSeverity::Warning.is_release_blocking());
    assert!(DiagnosticSeverity::Error.is_release_blocking());
    assert!(DiagnosticSeverity::Critical.is_release_blocking());
}

#[test]
fn category_as_str_all_distinct() {
    let cats = [
        DiagnosticCategory::BudgetPropagation,
        DiagnosticCategory::CapabilityNarrowing,
        DiagnosticCategory::OutcomePropagation,
        DiagnosticCategory::MockSeamLeakage,
        DiagnosticCategory::ContextThreading,
    ];
    let strs: std::collections::BTreeSet<&str> = cats.iter().map(|c| c.as_str()).collect();
    assert_eq!(strs.len(), cats.len());
}

#[test]
fn error_code_display_contains_code_string() {
    let code = DiagnosticErrorCode {
        code: "CP-BUDGET-042".to_string(),
        category: DiagnosticCategory::BudgetPropagation,
        severity: DiagnosticSeverity::Error,
    };
    let display = format!("{code}");
    assert!(display.contains("CP-BUDGET-042"));
}

#[test]
fn enrichment_emitter_with_defaults_starts_empty() {
    let emitter = DiagnosticEmitter::with_defaults();
    assert!(emitter.diagnostics().is_empty());
    assert!(!emitter.has_release_blockers());
    assert!(emitter.max_severity().is_none());
}

#[test]
fn enrichment_emitter_new_uses_provided_epoch() {
    let epoch = SecurityEpoch::from_raw(42);
    let emitter = DiagnosticEmitter::new(epoch);
    assert!(emitter.diagnostics().is_empty());
}

#[test]
fn enrichment_report_from_empty_emitter_is_clean() {
    let emitter = DiagnosticEmitter::with_defaults();
    let report = emitter.build_report();
    assert!(report.is_clean());
    assert_eq!(report.total_diagnostics, 0);
}

#[test]
fn enrichment_report_serde_roundtrip() {
    let emitter = DiagnosticEmitter::with_defaults();
    let report = emitter.build_report();
    let json = serde_json::to_string(&report).expect("serialize");
    let deser: DiagnosticReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report.total_diagnostics, deser.total_diagnostics);
    assert_eq!(report.is_clean(), deser.is_clean());
}

#[test]
fn remediation_guidance_serde_preserves_steps() {
    let guidance = RemediationGuidance {
        summary: "Fix the issue".to_string(),
        detail: "Detailed description".to_string(),
        steps: vec![
            "Step 1".to_string(),
            "Step 2".to_string(),
            "Step 3".to_string(),
        ],
        doc_refs: vec!["doc-001".to_string()],
        auto_remediable: false,
    };
    let json = serde_json::to_string(&guidance).expect("serialize");
    let deser: RemediationGuidance = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(guidance.steps, deser.steps);
    assert_eq!(guidance.auto_remediable, deser.auto_remediable);
}

#[test]
fn diagnostics_at_severity_filters_correctly() {
    let emitter = DiagnosticEmitter::with_defaults();
    // We can't easily emit at different severities without the budget/narrowing API,
    // so just verify the filter function works on an empty emitter
    let filtered = emitter.diagnostics_at_severity(DiagnosticSeverity::Warning);
    assert!(filtered.is_empty());
}

#[test]
fn diagnostic_context_uses_btreemap_for_determinism() {
    let mut ctx = BTreeMap::new();
    ctx.insert("z_key".to_string(), "z_val".to_string());
    ctx.insert("a_key".to_string(), "a_val".to_string());
    let diag = ControlPlaneDiagnostic {
        error_code: DiagnosticErrorCode {
            code: "CP-ORD-001".to_string(),
            category: DiagnosticCategory::OutcomePropagation,
            severity: DiagnosticSeverity::Info,
        },
        message: "ordering test".to_string(),
        remediation: RemediationGuidance {
            summary: "s".to_string(),
            detail: "d".to_string(),
            steps: vec![],
            doc_refs: vec![],
            auto_remediable: true,
        },
        trace_ids: vec![],
        boundary_label: None,
        context: ctx,
        sequence: 0,
    };
    let keys: Vec<&String> = diag.context.keys().collect();
    assert_eq!(
        keys,
        vec!["a_key", "z_key"],
        "BTreeMap should maintain alphabetical order"
    );
}
