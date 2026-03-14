//! Enrichment integration tests for frankenlab_release_gate_promotion (bd-3nr.1.4.3).
//!
//! Covers: PromotedGateKind properties, PromotionStatus transitions,
//! BlockerThreshold logic, TriageBundle construction and filtering,
//! GatePromotionEntry pass rate, Display formatting, serde roundtrips,
//! and TriageSeverity blocking semantics.

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

use std::collections::BTreeSet;

use frankenengine_engine::frankenlab_release_gate_promotion::{
    BlockerThreshold, GatePromotionEntry, PromotedGateKind, PromotionStatus,
    RELEASE_GATE_PROMOTION_BEAD_ID, RELEASE_GATE_PROMOTION_SCHEMA_VERSION, TriageBundle,
    TriageFinding, TriageSeverity,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_contains_release_gate() {
    assert!(RELEASE_GATE_PROMOTION_SCHEMA_VERSION.contains("release-gate"));
}

#[test]
fn bead_id_is_expected() {
    assert_eq!(RELEASE_GATE_PROMOTION_BEAD_ID, "bd-3nr.1.4.3");
}

// ---------------------------------------------------------------------------
// PromotedGateKind properties
// ---------------------------------------------------------------------------

#[test]
fn promoted_gate_kind_all_has_eight_variants() {
    assert_eq!(PromotedGateKind::ALL.len(), 8);
}

#[test]
fn promoted_gate_kind_display_nonempty() {
    for kind in &PromotedGateKind::ALL {
        let display = kind.to_string();
        assert!(!display.is_empty(), "empty display for {:?}", kind);
    }
}

#[test]
fn promoted_gate_kind_display_unique() {
    let displays: BTreeSet<String> = PromotedGateKind::ALL
        .iter()
        .map(|k| k.to_string())
        .collect();
    assert_eq!(displays.len(), 8, "display strings must be unique");
}

#[test]
fn promoted_gate_kind_original_vs_correction_partition() {
    let original_count = PromotedGateKind::ALL
        .iter()
        .filter(|k| k.is_original_gate())
        .count();
    let correction_count = PromotedGateKind::ALL
        .iter()
        .filter(|k| k.is_correction_wave_gate())
        .count();

    assert_eq!(original_count, 4);
    assert_eq!(correction_count, 4);
    assert_eq!(original_count + correction_count, 8);
}

#[test]
fn promoted_gate_kind_original_and_correction_mutually_exclusive() {
    for kind in &PromotedGateKind::ALL {
        assert_ne!(
            kind.is_original_gate(),
            kind.is_correction_wave_gate(),
            "{:?} must be one or the other",
            kind
        );
    }
}

#[test]
fn promoted_gate_kind_serde_roundtrip_all() {
    for kind in &PromotedGateKind::ALL {
        let json = serde_json::to_string(kind).expect("serialize");
        let deser: PromotedGateKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*kind, deser, "roundtrip failed for {:?}", kind);
    }
}

// ---------------------------------------------------------------------------
// PromotionStatus properties
// ---------------------------------------------------------------------------

#[test]
fn promotion_status_oracle_backed_for_oracle_backed() {
    assert!(PromotionStatus::OracleBacked.is_oracle_backed());
}

#[test]
fn promotion_status_oracle_backed_for_fully_promoted() {
    assert!(PromotionStatus::FullyPromoted.is_oracle_backed());
}

#[test]
fn promotion_status_not_oracle_backed_for_assertion_based() {
    assert!(!PromotionStatus::AssertionBased.is_oracle_backed());
}

#[test]
fn promotion_status_not_oracle_backed_for_oracle_wired() {
    assert!(!PromotionStatus::OracleWired.is_oracle_backed());
}

#[test]
fn promotion_status_display_all() {
    let statuses = [
        PromotionStatus::AssertionBased,
        PromotionStatus::OracleWired,
        PromotionStatus::OracleBacked,
        PromotionStatus::FullyPromoted,
    ];
    for s in &statuses {
        let display = s.to_string();
        assert!(!display.is_empty(), "empty display for {:?}", s);
    }
}

#[test]
fn promotion_status_serde_roundtrip_all() {
    let statuses = [
        PromotionStatus::AssertionBased,
        PromotionStatus::OracleWired,
        PromotionStatus::OracleBacked,
        PromotionStatus::FullyPromoted,
    ];
    for s in &statuses {
        let json = serde_json::to_string(s).expect("serialize");
        let deser: PromotionStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*s, deser, "roundtrip failed for {:?}", s);
    }
}

// ---------------------------------------------------------------------------
// BlockerThreshold
// ---------------------------------------------------------------------------

#[test]
fn strict_threshold_zero_tolerance() {
    let t = BlockerThreshold::strict(PromotedGateKind::ReplayDeterminism);
    assert_eq!(t.max_failures, 0);
    assert_eq!(t.min_pass_rate_millionths, 1_000_000);
    assert!(t.infra_errors_block);
    assert!(t.timeouts_block);
}

#[test]
fn relaxed_threshold_allows_some_failures() {
    let t = BlockerThreshold::relaxed(PromotedGateKind::EvidenceCompleteness);
    assert!(t.max_failures > 0);
    assert!(t.min_pass_rate_millionths < 1_000_000);
}

#[test]
fn strict_would_block_on_any_failure() {
    let t = BlockerThreshold::strict(PromotedGateKind::LifecycleScenarios);
    assert!(t.would_block(1_000_000, 1)); // 100% pass rate but 1 failure
    assert!(t.would_block(999_999, 0)); // <100% pass rate
}

#[test]
fn strict_would_not_block_on_perfect() {
    let t = BlockerThreshold::strict(PromotedGateKind::LifecycleScenarios);
    assert!(!t.would_block(1_000_000, 0));
}

#[test]
fn with_rationale_sets_rationale() {
    let t = BlockerThreshold::strict(PromotedGateKind::MockSeamAbsence)
        .with_rationale("zero mock seams in production");
    assert_eq!(t.rationale, "zero mock seams in production");
}

#[test]
fn blocker_threshold_serde_roundtrip() {
    let t = BlockerThreshold::strict(PromotedGateKind::BudgetPropagation)
        .with_rationale("budget must propagate");
    let json = serde_json::to_string(&t).expect("serialize");
    let deser: BlockerThreshold = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(t.gate, deser.gate);
    assert_eq!(t.max_failures, deser.max_failures);
    assert_eq!(t.rationale, deser.rationale);
}

// ---------------------------------------------------------------------------
// TriageSeverity
// ---------------------------------------------------------------------------

#[test]
fn triage_severity_info_not_blocking() {
    assert!(!TriageSeverity::Info.is_release_blocking());
}

#[test]
fn triage_severity_warning_not_blocking() {
    assert!(!TriageSeverity::Warning.is_release_blocking());
}

#[test]
fn triage_severity_error_is_blocking() {
    assert!(TriageSeverity::Error.is_release_blocking());
}

#[test]
fn triage_severity_critical_is_blocking() {
    assert!(TriageSeverity::Critical.is_release_blocking());
}

#[test]
fn triage_severity_ordering() {
    assert!(TriageSeverity::Info < TriageSeverity::Warning);
    assert!(TriageSeverity::Warning < TriageSeverity::Error);
    assert!(TriageSeverity::Error < TriageSeverity::Critical);
}

#[test]
fn triage_severity_display_all() {
    let severities = [
        TriageSeverity::Info,
        TriageSeverity::Warning,
        TriageSeverity::Error,
        TriageSeverity::Critical,
    ];
    for s in &severities {
        assert!(!s.to_string().is_empty(), "empty display for {:?}", s);
    }
}

#[test]
fn triage_severity_serde_roundtrip_all() {
    let severities = [
        TriageSeverity::Info,
        TriageSeverity::Warning,
        TriageSeverity::Error,
        TriageSeverity::Critical,
    ];
    for s in &severities {
        let json = serde_json::to_string(s).expect("serialize");
        let deser: TriageSeverity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*s, deser, "roundtrip failed for {:?}", s);
    }
}

// ---------------------------------------------------------------------------
// TriageBundle
// ---------------------------------------------------------------------------

fn make_finding(gate: PromotedGateKind, severity: TriageSeverity, summary: &str) -> TriageFinding {
    TriageFinding {
        gate,
        severity,
        summary: summary.to_string(),
        detail: String::new(),
        remediation_steps: Vec::new(),
        scenario_id: None,
        oracle_invariant: None,
    }
}

#[test]
fn empty_triage_bundle_is_clean() {
    let bundle = TriageBundle::from_findings(vec![]);
    assert!(bundle.is_clean());
    assert!(!bundle.has_blockers());
    assert_eq!(bundle.blocking_count, 0);
    assert!(bundle.max_severity.is_none());
}

#[test]
fn triage_bundle_with_info_only_no_blockers() {
    let bundle = TriageBundle::from_findings(vec![make_finding(
        PromotedGateKind::ReplayDeterminism,
        TriageSeverity::Info,
        "info finding",
    )]);
    assert!(!bundle.has_blockers());
    assert_eq!(bundle.blocking_count, 0);
    assert_eq!(bundle.max_severity, Some(TriageSeverity::Info));
}

#[test]
fn triage_bundle_with_error_has_blockers() {
    let bundle = TriageBundle::from_findings(vec![make_finding(
        PromotedGateKind::MockSeamAbsence,
        TriageSeverity::Error,
        "mock seam found",
    )]);
    assert!(bundle.has_blockers());
    assert_eq!(bundle.blocking_count, 1);
    assert_eq!(bundle.max_severity, Some(TriageSeverity::Error));
}

#[test]
fn triage_bundle_max_severity_is_highest() {
    let bundle = TriageBundle::from_findings(vec![
        make_finding(
            PromotedGateKind::BudgetPropagation,
            TriageSeverity::Warning,
            "w",
        ),
        make_finding(
            PromotedGateKind::CapabilityNarrowing,
            TriageSeverity::Critical,
            "c",
        ),
        make_finding(
            PromotedGateKind::OutcomePropagation,
            TriageSeverity::Info,
            "i",
        ),
    ]);
    assert_eq!(bundle.max_severity, Some(TriageSeverity::Critical));
}

#[test]
fn triage_bundle_gates_involved_correct() {
    let bundle = TriageBundle::from_findings(vec![
        make_finding(
            PromotedGateKind::ReplayDeterminism,
            TriageSeverity::Info,
            "a",
        ),
        make_finding(
            PromotedGateKind::MockSeamAbsence,
            TriageSeverity::Warning,
            "b",
        ),
    ]);
    assert_eq!(bundle.gates_involved.len(), 2);
    assert!(bundle.gates_involved.contains("replay_determinism"));
    assert!(bundle.gates_involved.contains("mock_seam_absence"));
}

#[test]
fn triage_bundle_findings_for_gate_filters() {
    let bundle = TriageBundle::from_findings(vec![
        make_finding(
            PromotedGateKind::ReplayDeterminism,
            TriageSeverity::Info,
            "a",
        ),
        make_finding(
            PromotedGateKind::MockSeamAbsence,
            TriageSeverity::Warning,
            "b",
        ),
        make_finding(
            PromotedGateKind::ReplayDeterminism,
            TriageSeverity::Error,
            "c",
        ),
    ]);
    let replay = bundle.findings_for_gate(PromotedGateKind::ReplayDeterminism);
    assert_eq!(replay.len(), 2);
}

#[test]
fn triage_bundle_findings_at_severity_filters() {
    let bundle = TriageBundle::from_findings(vec![
        make_finding(
            PromotedGateKind::BudgetPropagation,
            TriageSeverity::Info,
            "i",
        ),
        make_finding(
            PromotedGateKind::BudgetPropagation,
            TriageSeverity::Error,
            "e",
        ),
        make_finding(
            PromotedGateKind::BudgetPropagation,
            TriageSeverity::Critical,
            "c",
        ),
    ]);
    let blocking = bundle.findings_at_severity(TriageSeverity::Error);
    assert_eq!(blocking.len(), 2); // Error + Critical
}

#[test]
fn triage_bundle_display_format() {
    let bundle = TriageBundle::from_findings(vec![make_finding(
        PromotedGateKind::EvidenceCompleteness,
        TriageSeverity::Warning,
        "w",
    )]);
    let display = bundle.to_string();
    assert!(display.contains("TriageBundle"));
    assert!(display.contains("findings=1"));
    assert!(display.contains("blockers=0"));
}

#[test]
fn triage_bundle_content_hash_deterministic() {
    let build = || {
        TriageBundle::from_findings(vec![make_finding(
            PromotedGateKind::LifecycleScenarios,
            TriageSeverity::Info,
            "deterministic test",
        )])
    };
    assert_eq!(build().content_hash, build().content_hash);
}

// ---------------------------------------------------------------------------
// GatePromotionEntry
// ---------------------------------------------------------------------------

#[test]
fn gate_promotion_entry_assertion_based_defaults() {
    let entry = GatePromotionEntry::assertion_based(PromotedGateKind::LifecycleScenarios);
    assert_eq!(entry.status, PromotionStatus::AssertionBased);
    assert!(entry.oracle_invariants.is_empty());
    assert!(!entry.cross_validated);
    assert_eq!(entry.evaluation_runs, 0);
    assert_eq!(entry.passing_runs, 0);
}

#[test]
fn gate_promotion_entry_pass_rate_zero_runs() {
    let entry = GatePromotionEntry::assertion_based(PromotedGateKind::ReplayDeterminism);
    assert_eq!(entry.pass_rate_millionths(), 0);
}

#[test]
fn gate_promotion_entry_pass_rate_all_passing() {
    let mut entry = GatePromotionEntry::assertion_based(PromotedGateKind::ObligationResolution);
    entry.evaluation_runs = 100;
    entry.passing_runs = 100;
    assert_eq!(entry.pass_rate_millionths(), 1_000_000);
}

#[test]
fn gate_promotion_entry_pass_rate_half_passing() {
    let mut entry = GatePromotionEntry::assertion_based(PromotedGateKind::BudgetPropagation);
    entry.evaluation_runs = 10;
    entry.passing_runs = 5;
    assert_eq!(entry.pass_rate_millionths(), 500_000);
}

#[test]
fn gate_promotion_entry_serde_roundtrip() {
    let mut entry = GatePromotionEntry::assertion_based(PromotedGateKind::MockSeamAbsence);
    entry.status = PromotionStatus::OracleBacked;
    entry.oracle_invariants.insert("inv-001".to_string());
    entry.evaluation_runs = 50;
    entry.passing_runs = 48;
    entry.cross_validated = true;

    let json = serde_json::to_string(&entry).expect("serialize");
    let deser: GatePromotionEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry.gate, deser.gate);
    assert_eq!(entry.status, deser.status);
    assert_eq!(entry.oracle_invariants, deser.oracle_invariants);
    assert_eq!(entry.evaluation_runs, deser.evaluation_runs);
    assert_eq!(entry.passing_runs, deser.passing_runs);
    assert_eq!(entry.cross_validated, deser.cross_validated);
}
