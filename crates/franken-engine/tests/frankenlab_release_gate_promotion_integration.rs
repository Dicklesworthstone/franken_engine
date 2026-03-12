//! Integration tests for frankenlab_release_gate_promotion module.

use std::collections::BTreeSet;

use frankenengine_engine::frankenlab_release_gate_promotion::{
    BlockerThreshold, GatePromotionEntry, PromotedGateKind, PromotionStatus,
    RELEASE_GATE_PROMOTION_BEAD_ID, RELEASE_GATE_PROMOTION_SCHEMA_VERSION,
    ReleaseGatePromotionRegistry, ReleaseGatePromotionReport, TriageBundle, TriageFinding,
    TriageSeverity,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(600)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn integration_schema_version_present() {
    assert!(!RELEASE_GATE_PROMOTION_SCHEMA_VERSION.is_empty());
    assert!(RELEASE_GATE_PROMOTION_SCHEMA_VERSION.contains("release-gate-promotion"));
}

#[test]
fn integration_bead_id() {
    assert_eq!(RELEASE_GATE_PROMOTION_BEAD_ID, "bd-3nr.1.4.3");
}

// ---------------------------------------------------------------------------
// PromotedGateKind
// ---------------------------------------------------------------------------

#[test]
fn integration_gate_kinds_unique() {
    let set: BTreeSet<PromotedGateKind> = PromotedGateKind::ALL.iter().copied().collect();
    assert_eq!(set.len(), PromotedGateKind::ALL.len());
}

#[test]
fn integration_gate_kinds_original_vs_correction() {
    let original: Vec<_> = PromotedGateKind::ALL
        .iter()
        .filter(|g| g.is_original_gate())
        .collect();
    let correction: Vec<_> = PromotedGateKind::ALL
        .iter()
        .filter(|g| g.is_correction_wave_gate())
        .collect();

    // 4 original + 4 correction = 8 total
    assert_eq!(original.len() + correction.len(), 8);
    assert_eq!(original.len(), 4);
    assert_eq!(correction.len(), 4);
}

#[test]
fn integration_gate_kinds_display_all_nonempty() {
    for gate in PromotedGateKind::ALL {
        let s = gate.to_string();
        assert!(!s.is_empty());
        assert!(!s.contains(char::is_uppercase));
    }
}

// ---------------------------------------------------------------------------
// PromotionStatus
// ---------------------------------------------------------------------------

#[test]
fn integration_promotion_status_ordering() {
    assert!(PromotionStatus::AssertionBased < PromotionStatus::OracleWired);
    assert!(PromotionStatus::OracleWired < PromotionStatus::OracleBacked);
    assert!(PromotionStatus::OracleBacked < PromotionStatus::FullyPromoted);
}

// ---------------------------------------------------------------------------
// BlockerThreshold
// ---------------------------------------------------------------------------

#[test]
fn integration_threshold_strict_vs_relaxed() {
    let strict = BlockerThreshold::strict(PromotedGateKind::LifecycleScenarios);
    let relaxed = BlockerThreshold::relaxed(PromotedGateKind::LifecycleScenarios);

    // Strict is tighter
    assert!(strict.min_pass_rate_millionths >= relaxed.min_pass_rate_millionths);
    assert!(strict.max_failures <= relaxed.max_failures);
    assert!(strict.infra_errors_block);
}

#[test]
fn integration_threshold_boundary_conditions() {
    let t = BlockerThreshold::strict(PromotedGateKind::LifecycleScenarios);

    // Exactly at threshold should not block
    assert!(!t.would_block(1_000_000, 0));

    // Just below should block
    assert!(t.would_block(999_999, 0));

    // Zero failures at threshold should not block
    assert!(!t.would_block(1_000_000, 0));
}

#[test]
fn integration_threshold_serde_with_rationale() {
    let t = BlockerThreshold::strict(PromotedGateKind::BudgetPropagation)
        .with_rationale("budget violations indicate real cost overruns");
    let json = serde_json::to_string(&t).unwrap();
    let round: BlockerThreshold = serde_json::from_str(&json).unwrap();
    assert_eq!(t, round);
    assert_eq!(
        round.rationale,
        "budget violations indicate real cost overruns"
    );
}

// ---------------------------------------------------------------------------
// TriageSeverity
// ---------------------------------------------------------------------------

#[test]
fn integration_triage_severity_serde_all() {
    for sev in [
        TriageSeverity::Info,
        TriageSeverity::Warning,
        TriageSeverity::Error,
        TriageSeverity::Critical,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let round: TriageSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, round);
    }
}

// ---------------------------------------------------------------------------
// TriageBundle
// ---------------------------------------------------------------------------

#[test]
fn integration_triage_bundle_from_multiple_gates() {
    let findings = vec![
        TriageFinding {
            gate: PromotedGateKind::LifecycleScenarios,
            severity: TriageSeverity::Info,
            summary: "scenario note".to_owned(),
            detail: String::new(),
            remediation_steps: vec![],
            scenario_id: Some("startup".to_owned()),
            oracle_invariant: None,
        },
        TriageFinding {
            gate: PromotedGateKind::BudgetPropagation,
            severity: TriageSeverity::Error,
            summary: "budget violation".to_owned(),
            detail: "child exceeded parent".to_owned(),
            remediation_steps: vec!["review budget rules".to_owned()],
            scenario_id: None,
            oracle_invariant: Some("budget_narrowing".to_owned()),
        },
        TriageFinding {
            gate: PromotedGateKind::MockSeamAbsence,
            severity: TriageSeverity::Critical,
            summary: "mock in production".to_owned(),
            detail: "MockCx found in orchestrator".to_owned(),
            remediation_steps: vec![
                "replace with canonical Cx".to_owned(),
                "run mock inventory scan".to_owned(),
            ],
            scenario_id: None,
            oracle_invariant: None,
        },
    ];

    let bundle = TriageBundle::from_findings(findings);
    assert_eq!(bundle.findings.len(), 3);
    assert_eq!(bundle.blocking_count, 2); // Error + Critical
    assert_eq!(bundle.max_severity, Some(TriageSeverity::Critical));
    assert_eq!(bundle.gates_involved.len(), 3);
    assert!(bundle.has_blockers());
}

#[test]
fn integration_triage_bundle_content_hash_deterministic() {
    let make = || {
        TriageBundle::from_findings(vec![TriageFinding {
            gate: PromotedGateKind::LifecycleScenarios,
            severity: TriageSeverity::Warning,
            summary: "test".to_owned(),
            detail: String::new(),
            remediation_steps: vec![],
            scenario_id: None,
            oracle_invariant: None,
        }])
    };
    let b1 = make();
    let b2 = make();
    assert_eq!(b1.content_hash, b2.content_hash);
}

#[test]
fn integration_triage_bundle_display() {
    let bundle = TriageBundle::from_findings(vec![]);
    let s = format!("{bundle}");
    assert!(s.contains("TriageBundle"));
    assert!(s.contains("findings=0"));
}

// ---------------------------------------------------------------------------
// GatePromotionEntry
// ---------------------------------------------------------------------------

#[test]
fn integration_gate_entry_full_lifecycle() {
    let mut entry = GatePromotionEntry::assertion_based(PromotedGateKind::LifecycleScenarios);
    assert_eq!(entry.status, PromotionStatus::AssertionBased);
    assert!(entry.blocks_release()); // no data → fail-closed

    // Record some runs while assertion-based
    entry.record_run(true);
    entry.record_run(true);
    assert_eq!(entry.pass_rate_millionths(), 1_000_000);
    assert!(!entry.blocks_release());

    // Wire oracles
    let mut invariants = BTreeSet::new();
    invariants.insert("safety".to_owned());
    invariants.insert("liveness".to_owned());
    entry.wire_oracles(invariants);
    assert_eq!(entry.status, PromotionStatus::OracleWired);
    assert_eq!(entry.oracle_invariants.len(), 2);

    // Promote to oracle-backed
    entry.promote_to_oracle_backed();
    assert!(entry.status.is_oracle_backed());

    // Fully promote
    entry.promote_fully();
    assert_eq!(entry.status, PromotionStatus::FullyPromoted);
    assert!(entry.cross_validated);
}

#[test]
fn integration_gate_entry_pass_rate_precision() {
    let mut entry = GatePromotionEntry::assertion_based(PromotedGateKind::ReplayDeterminism);

    // 7/10 pass rate
    for i in 0..10 {
        entry.record_run(i < 7);
    }
    assert_eq!(entry.pass_rate_millionths(), 700_000);
    assert_eq!(entry.evaluation_runs, 10);
    assert_eq!(entry.passing_runs, 7);
}

#[test]
fn integration_gate_entry_serde_roundtrip() {
    let mut entry = GatePromotionEntry::assertion_based(PromotedGateKind::CapabilityNarrowing);
    let mut invariants = BTreeSet::new();
    invariants.insert("narrowing_check".to_owned());
    entry.wire_oracles(invariants);
    entry.record_run(true);
    entry.record_run(false);

    let json = serde_json::to_string(&entry).unwrap();
    let round: GatePromotionEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, round);
}

// ---------------------------------------------------------------------------
// ReleaseGatePromotionRegistry
// ---------------------------------------------------------------------------

#[test]
fn integration_registry_all_gates_present() {
    let reg = ReleaseGatePromotionRegistry::with_defaults(epoch());
    for gate_kind in PromotedGateKind::ALL {
        assert!(
            reg.gate(gate_kind).is_some(),
            "missing gate entry for {:?}",
            gate_kind,
        );
    }
}

#[test]
fn integration_registry_mutable_access() {
    let mut reg = ReleaseGatePromotionRegistry::with_defaults(epoch());
    reg.gate_mut(PromotedGateKind::LifecycleScenarios)
        .unwrap()
        .record_run(true);
    assert_eq!(
        reg.gate(PromotedGateKind::LifecycleScenarios)
            .unwrap()
            .evaluation_runs,
        1,
    );
}

#[test]
fn integration_registry_promotion_progress() {
    let mut reg = ReleaseGatePromotionRegistry::with_defaults(epoch());
    assert_eq!(reg.promotion_progress_millionths(), 0);

    // Promote 4 of 8 gates
    for gate_kind in [
        PromotedGateKind::LifecycleScenarios,
        PromotedGateKind::ReplayDeterminism,
        PromotedGateKind::BudgetPropagation,
        PromotedGateKind::CapabilityNarrowing,
    ] {
        let gate = reg.gate_mut(gate_kind).unwrap();
        let mut invariants = BTreeSet::new();
        invariants.insert(format!("{gate_kind}_oracle"));
        gate.wire_oracles(invariants);
        gate.promote_to_oracle_backed();
    }

    assert_eq!(reg.oracle_backed_count(), 4);
    assert_eq!(reg.promotion_progress_millionths(), 500_000);
}

#[test]
fn integration_registry_serde_roundtrip() {
    let mut reg = ReleaseGatePromotionRegistry::with_defaults(epoch());
    reg.gate_mut(PromotedGateKind::LifecycleScenarios)
        .unwrap()
        .record_run(true);
    let json = serde_json::to_string_pretty(&reg).unwrap();
    let round: ReleaseGatePromotionRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, round);
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

#[test]
fn integration_report_initial() {
    let reg = ReleaseGatePromotionRegistry::with_defaults(epoch());
    let report = reg.build_report();
    assert!(!report.fully_promoted());
    assert_eq!(report.total_gates, 8);
    assert_eq!(report.oracle_backed_count, 0);
    assert_eq!(report.overall_pass_rate_millionths(), 0);
}

#[test]
fn integration_report_fully_promoted() {
    let mut reg = ReleaseGatePromotionRegistry::with_defaults(epoch());

    for gate_kind in PromotedGateKind::ALL {
        let gate = reg.gate_mut(gate_kind).unwrap();
        let mut invariants = BTreeSet::new();
        invariants.insert(format!("{gate_kind}_oracle"));
        gate.wire_oracles(invariants);
        gate.promote_fully();
        gate.record_run(true);
        gate.record_run(true);
    }

    let report = reg.build_report();
    assert!(report.fully_promoted());
    assert_eq!(report.oracle_backed_count, 8);
    assert_eq!(report.promotion_progress_millionths, 1_000_000);
    assert_eq!(report.total_evaluation_runs, 16);
    assert_eq!(report.total_passing_runs, 16);
    assert_eq!(report.cross_validated_count, 8);
    assert_eq!(report.overall_pass_rate_millionths(), 1_000_000);
    assert!(!report.release_blocked);
}

#[test]
fn integration_report_with_failures() {
    let mut reg = ReleaseGatePromotionRegistry::with_defaults(epoch());

    let gate = reg.gate_mut(PromotedGateKind::LifecycleScenarios).unwrap();
    gate.record_run(true);
    gate.record_run(false); // failure
    // strict threshold: any failure blocks

    let report = reg.build_report();
    assert!(report.release_blocked);
}

#[test]
fn integration_report_json_roundtrip() {
    let reg = ReleaseGatePromotionRegistry::with_defaults(epoch());
    let report = reg.build_report();
    let json = serde_json::to_string_pretty(&report).unwrap();
    let round: ReleaseGatePromotionReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, round);
}

#[test]
fn integration_report_hash_deterministic() {
    let make = || {
        let reg = ReleaseGatePromotionRegistry::with_defaults(epoch());
        reg.build_report()
    };
    let r1 = make();
    let r2 = make();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn integration_report_display() {
    let reg = ReleaseGatePromotionRegistry::with_defaults(epoch());
    let report = reg.build_report();
    let s = format!("{report}");
    assert!(s.contains("ReleaseGatePromotionReport"));
    assert!(s.contains("oracle-backed"));
}

// ---------------------------------------------------------------------------
// E2E: Progressive promotion workflow
// ---------------------------------------------------------------------------

#[test]
fn integration_e2e_progressive_promotion() {
    let mut reg = ReleaseGatePromotionRegistry::with_defaults(epoch());

    // Phase 1: Wire oracles for original gates
    for gate_kind in [
        PromotedGateKind::LifecycleScenarios,
        PromotedGateKind::ReplayDeterminism,
        PromotedGateKind::ObligationResolution,
        PromotedGateKind::EvidenceCompleteness,
    ] {
        let gate = reg.gate_mut(gate_kind).unwrap();
        let mut invariants = BTreeSet::new();
        invariants.insert(format!("{gate_kind}_primary"));
        gate.wire_oracles(invariants);
    }

    let r1 = reg.build_report();
    assert_eq!(r1.oracle_backed_count, 0); // wired but not backed

    // Phase 2: Promote original gates and run evaluations
    for gate_kind in [
        PromotedGateKind::LifecycleScenarios,
        PromotedGateKind::ReplayDeterminism,
        PromotedGateKind::ObligationResolution,
        PromotedGateKind::EvidenceCompleteness,
    ] {
        let gate = reg.gate_mut(gate_kind).unwrap();
        gate.promote_to_oracle_backed();
        gate.record_run(true);
        gate.record_run(true);
        gate.record_run(true);
    }

    let r2 = reg.build_report();
    assert_eq!(r2.oracle_backed_count, 4);
    assert_eq!(r2.promotion_progress_millionths, 500_000);
    assert!(!r2.release_blocked);

    // Phase 3: Wire and promote correction-wave gates
    for gate_kind in [
        PromotedGateKind::BudgetPropagation,
        PromotedGateKind::CapabilityNarrowing,
        PromotedGateKind::MockSeamAbsence,
        PromotedGateKind::OutcomePropagation,
    ] {
        let gate = reg.gate_mut(gate_kind).unwrap();
        let mut invariants = BTreeSet::new();
        invariants.insert(format!("{gate_kind}_oracle"));
        gate.wire_oracles(invariants);
        gate.promote_fully();
        gate.record_run(true);
        gate.record_run(true);
    }

    let r3 = reg.build_report();
    assert!(r3.fully_promoted());
    assert_eq!(r3.oracle_backed_count, 8);
    assert!(!r3.release_blocked);
}

#[test]
fn integration_e2e_triage_identifies_issues() {
    let mut reg = ReleaseGatePromotionRegistry::with_defaults(epoch());

    // Incorrectly promote a gate without invariants
    reg.gate_mut(PromotedGateKind::MockSeamAbsence)
        .unwrap()
        .status = PromotionStatus::OracleBacked;

    // Promote a gate with no runs
    let gate = reg.gate_mut(PromotedGateKind::BudgetPropagation).unwrap();
    let mut invariants = BTreeSet::new();
    invariants.insert("budget_check".to_owned());
    gate.wire_oracles(invariants);
    gate.promote_to_oracle_backed();

    let bundle = reg.evaluate_and_triage();
    assert!(!bundle.is_clean());

    // Should have critical finding for no-invariant gate
    let critical = bundle.findings_at_severity(TriageSeverity::Critical);
    assert!(!critical.is_empty());

    // Should have warning for no-runs gate
    let warnings = bundle.findings_at_severity(TriageSeverity::Warning);
    assert!(warnings.len() >= 1);
}
