//! Integration tests for the `engine_product_blocker_ledger` module.
//!
//! Covers blocker ledger operations, cohort rollups, gate evaluation,
//! severity/surface distributions, serde roundtrips, and edge cases.

#![forbid(unsafe_code)]
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

use std::collections::BTreeSet;

use frankenengine_engine::engine_product_blocker_ledger::{
    BEAD_ID, BlockerEntry, BlockerLedger, BlockerLedgerGate, BlockerSeverity, BlockerSurface,
    COMPONENT, CohortReadiness, CohortRollup, GateReport, GateVerdict, LedgerError,
    RejectionReason, RemediationStatus, SCHEMA_VERSION,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_blocker(id: &str, surface: BlockerSurface, severity: BlockerSeverity) -> BlockerEntry {
    BlockerEntry {
        id: id.to_string(),
        title: format!("Blocker {id}"),
        surface,
        severity,
        remediation: RemediationStatus::Unowned,
        tracking_bead: Some(format!("bd-{id}")),
        evidence_hash: None,
        owner: None,
        user_impact: "users affected".to_string(),
        tags: BTreeSet::new(),
    }
}

fn make_resolved_blocker(id: &str) -> BlockerEntry {
    BlockerEntry {
        id: id.to_string(),
        title: format!("Resolved {id}"),
        surface: BlockerSurface::Runtime,
        severity: BlockerSeverity::Blocking,
        remediation: RemediationStatus::Verified,
        tracking_bead: None,
        evidence_hash: None,
        owner: Some("PearlTower".to_string()),
        user_impact: "none — fixed".to_string(),
        tags: BTreeSet::from(["resolved".to_string()]),
    }
}

fn make_cohort(name: &str, readiness: CohortReadiness) -> CohortRollup {
    CohortRollup {
        cohort_name: name.to_string(),
        readiness,
        blocker_count: 0,
        blocking_count: 0,
        degraded_count: 0,
        resolved_count: 0,
        readiness_rate_millionths: match readiness {
            CohortReadiness::Ready => 1_000_000,
            CohortReadiness::ReadyWithAdvisories => 900_000,
            CohortReadiness::PartiallyBlocked => 500_000,
            CohortReadiness::Blocked => 0,
            CohortReadiness::NotEvaluated => 0,
        },
        blocker_ids: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("blocker-ledger"));
}

#[test]
fn component_is_nonempty() {
    assert!(!COMPONENT.is_empty());
}

#[test]
fn bead_id_is_nonempty() {
    assert!(BEAD_ID.starts_with("bd-"));
}

// ---------------------------------------------------------------------------
// BlockerSurface
// ---------------------------------------------------------------------------

#[test]
fn blocker_surface_all_variants_listed() {
    assert_eq!(BlockerSurface::ALL.len(), 15);
    for surface in BlockerSurface::ALL {
        assert!(!surface.as_str().is_empty());
        assert!(!surface.to_string().is_empty());
    }
}

#[test]
fn blocker_surface_serde_roundtrip() {
    let s = BlockerSurface::ReactLane;
    let json = serde_json::to_string(&s).unwrap();
    let parsed: BlockerSurface = serde_json::from_str(&json).unwrap();
    assert_eq!(s, parsed);
}

// ---------------------------------------------------------------------------
// BlockerSeverity
// ---------------------------------------------------------------------------

#[test]
fn blocker_severity_release_blocking() {
    assert!(BlockerSeverity::Blocking.is_release_blocking());
    assert!(!BlockerSeverity::Degraded.is_release_blocking());
    assert!(!BlockerSeverity::Cosmetic.is_release_blocking());
    assert!(!BlockerSeverity::Informational.is_release_blocking());
}

#[test]
fn blocker_severity_weight_ordering() {
    assert!(
        BlockerSeverity::Blocking.weight_millionths()
            > BlockerSeverity::Degraded.weight_millionths()
    );
    assert!(
        BlockerSeverity::Degraded.weight_millionths()
            > BlockerSeverity::Cosmetic.weight_millionths()
    );
    assert_eq!(BlockerSeverity::Informational.weight_millionths(), 0);
}

#[test]
fn blocker_severity_serde_roundtrip() {
    let s = BlockerSeverity::Degraded;
    let json = serde_json::to_string(&s).unwrap();
    let parsed: BlockerSeverity = serde_json::from_str(&json).unwrap();
    assert_eq!(s, parsed);
}

// ---------------------------------------------------------------------------
// RemediationStatus
// ---------------------------------------------------------------------------

#[test]
fn remediation_status_resolved() {
    assert!(!RemediationStatus::Unowned.is_resolved());
    assert!(!RemediationStatus::Investigating.is_resolved());
    assert!(!RemediationStatus::InProgress.is_resolved());
    assert!(!RemediationStatus::FixLanded.is_resolved());
    assert!(RemediationStatus::Verified.is_resolved());
    assert!(RemediationStatus::WontFix.is_resolved());
}

#[test]
fn remediation_status_serde_roundtrip() {
    let s = RemediationStatus::InProgress;
    let json = serde_json::to_string(&s).unwrap();
    let parsed: RemediationStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(s, parsed);
}

// ---------------------------------------------------------------------------
// CohortReadiness
// ---------------------------------------------------------------------------

#[test]
fn cohort_readiness_permits_release() {
    assert!(CohortReadiness::Ready.permits_release());
    assert!(CohortReadiness::ReadyWithAdvisories.permits_release());
    assert!(!CohortReadiness::PartiallyBlocked.permits_release());
    assert!(!CohortReadiness::Blocked.permits_release());
    assert!(!CohortReadiness::NotEvaluated.permits_release());
}

#[test]
fn cohort_readiness_serde_roundtrip() {
    let r = CohortReadiness::PartiallyBlocked;
    let json = serde_json::to_string(&r).unwrap();
    let parsed: CohortReadiness = serde_json::from_str(&json).unwrap();
    assert_eq!(r, parsed);
}

// ---------------------------------------------------------------------------
// BlockerLedger
// ---------------------------------------------------------------------------

#[test]
fn empty_ledger_has_zero_counts() {
    let ledger = BlockerLedger::new();
    assert_eq!(ledger.blocker_count(), 0);
    assert!(ledger.release_blockers().is_empty());
    assert!(ledger.unresolved_blockers().is_empty());
}

#[test]
fn add_blocker_increments_count() {
    let mut ledger = BlockerLedger::new();
    ledger
        .add_blocker(make_blocker(
            "b1",
            BlockerSurface::Parser,
            BlockerSeverity::Blocking,
        ))
        .unwrap();
    assert_eq!(ledger.blocker_count(), 1);
}

#[test]
fn duplicate_blocker_id_rejected() {
    let mut ledger = BlockerLedger::new();
    ledger
        .add_blocker(make_blocker(
            "b1",
            BlockerSurface::Parser,
            BlockerSeverity::Blocking,
        ))
        .unwrap();
    let result = ledger.add_blocker(make_blocker(
        "b1",
        BlockerSurface::Runtime,
        BlockerSeverity::Degraded,
    ));
    assert!(result.is_err());
    match result.unwrap_err() {
        LedgerError::DuplicateBlocker { id } => assert_eq!(id, "b1"),
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn release_blockers_only_returns_unresolved_blocking() {
    let mut ledger = BlockerLedger::new();
    ledger
        .add_blocker(make_blocker(
            "b1",
            BlockerSurface::Parser,
            BlockerSeverity::Blocking,
        ))
        .unwrap();
    ledger
        .add_blocker(make_blocker(
            "b2",
            BlockerSurface::Runtime,
            BlockerSeverity::Degraded,
        ))
        .unwrap();
    ledger.add_blocker(make_resolved_blocker("b3")).unwrap();

    let release = ledger.release_blockers();
    assert_eq!(release.len(), 1);
    assert_eq!(release[0].id, "b1");
}

#[test]
fn unresolved_blockers_excludes_verified_and_wontfix() {
    let mut ledger = BlockerLedger::new();
    ledger
        .add_blocker(make_blocker(
            "b1",
            BlockerSurface::Parser,
            BlockerSeverity::Blocking,
        ))
        .unwrap();
    ledger.add_blocker(make_resolved_blocker("b2")).unwrap();

    let unresolved = ledger.unresolved_blockers();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].id, "b1");
}

#[test]
fn blockers_by_surface_distribution() {
    let mut ledger = BlockerLedger::new();
    ledger
        .add_blocker(make_blocker(
            "b1",
            BlockerSurface::Parser,
            BlockerSeverity::Blocking,
        ))
        .unwrap();
    ledger
        .add_blocker(make_blocker(
            "b2",
            BlockerSurface::Parser,
            BlockerSeverity::Degraded,
        ))
        .unwrap();
    ledger
        .add_blocker(make_blocker(
            "b3",
            BlockerSurface::Runtime,
            BlockerSeverity::Cosmetic,
        ))
        .unwrap();

    let by_surface = ledger.blockers_by_surface();
    assert_eq!(*by_surface.get(&BlockerSurface::Parser).unwrap_or(&0), 2);
    assert_eq!(*by_surface.get(&BlockerSurface::Runtime).unwrap_or(&0), 1);
}

#[test]
fn blockers_by_severity_distribution() {
    let mut ledger = BlockerLedger::new();
    ledger
        .add_blocker(make_blocker(
            "b1",
            BlockerSurface::Parser,
            BlockerSeverity::Blocking,
        ))
        .unwrap();
    ledger
        .add_blocker(make_blocker(
            "b2",
            BlockerSurface::Runtime,
            BlockerSeverity::Blocking,
        ))
        .unwrap();
    ledger
        .add_blocker(make_blocker(
            "b3",
            BlockerSurface::Stdlib,
            BlockerSeverity::Degraded,
        ))
        .unwrap();

    let by_sev = ledger.blockers_by_severity();
    assert_eq!(*by_sev.get(&BlockerSeverity::Blocking).unwrap_or(&0), 2);
    assert_eq!(*by_sev.get(&BlockerSeverity::Degraded).unwrap_or(&0), 1);
}

#[test]
fn content_hash_deterministic() {
    let mut l1 = BlockerLedger::new();
    l1.add_blocker(make_blocker(
        "b1",
        BlockerSurface::Parser,
        BlockerSeverity::Blocking,
    ))
    .unwrap();
    let mut l2 = BlockerLedger::new();
    l2.add_blocker(make_blocker(
        "b1",
        BlockerSurface::Parser,
        BlockerSeverity::Blocking,
    ))
    .unwrap();
    assert_eq!(l1.content_hash(), l2.content_hash());
}

#[test]
fn content_hash_differs_with_different_blockers() {
    let mut l1 = BlockerLedger::new();
    l1.add_blocker(make_blocker(
        "b1",
        BlockerSurface::Parser,
        BlockerSeverity::Blocking,
    ))
    .unwrap();
    let mut l2 = BlockerLedger::new();
    l2.add_blocker(make_blocker(
        "b2",
        BlockerSurface::Runtime,
        BlockerSeverity::Degraded,
    ))
    .unwrap();
    assert_ne!(l1.content_hash(), l2.content_hash());
}

#[test]
fn ledger_serde_roundtrip() {
    let mut ledger = BlockerLedger::new();
    ledger
        .add_blocker(make_blocker(
            "b1",
            BlockerSurface::Parser,
            BlockerSeverity::Blocking,
        ))
        .unwrap();
    ledger
        .add_cohort_rollup(make_cohort("tier_1", CohortReadiness::Ready))
        .unwrap();
    let json = serde_json::to_string(&ledger).unwrap();
    let parsed: BlockerLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(ledger, parsed);
}

// ---------------------------------------------------------------------------
// Gate evaluation
// ---------------------------------------------------------------------------

#[test]
fn gate_fails_on_empty_ledger() {
    let gate = BlockerLedgerGate::with_defaults();
    let ledger = BlockerLedger::new();
    let report = gate.evaluate(&ledger);
    assert!(!report.verdict.is_pass());
    match &report.verdict {
        GateVerdict::Fail { reasons } => {
            assert!(
                reasons
                    .iter()
                    .any(|r| matches!(r, RejectionReason::EmptyLedger))
            );
        }
        _ => panic!("expected Fail verdict"),
    }
}

#[test]
fn gate_fails_on_release_blockers() {
    let gate = BlockerLedgerGate::with_defaults();
    let mut ledger = BlockerLedger::new();
    ledger
        .add_blocker(make_blocker(
            "b1",
            BlockerSurface::Parser,
            BlockerSeverity::Blocking,
        ))
        .unwrap();
    ledger
        .add_cohort_rollup(make_cohort("tier_1", CohortReadiness::Ready))
        .unwrap();
    let report = gate.evaluate(&ledger);
    assert!(!report.verdict.is_pass());
    assert_eq!(report.release_blocker_count, 1);
}

#[test]
fn gate_passes_when_all_blockers_resolved() {
    let gate = BlockerLedgerGate::with_defaults();
    let mut ledger = BlockerLedger::new();
    ledger.add_blocker(make_resolved_blocker("b1")).unwrap();
    ledger
        .add_cohort_rollup(make_cohort("tier_1", CohortReadiness::Ready))
        .unwrap();
    let report = gate.evaluate(&ledger);
    assert!(report.verdict.is_pass());
    assert_eq!(report.release_blocker_count, 0);
    assert_eq!(report.resolved_count, 1);
}

#[test]
fn gate_report_schema_matches() {
    let gate = BlockerLedgerGate::with_defaults();
    let mut ledger = BlockerLedger::new();
    ledger.add_blocker(make_resolved_blocker("b1")).unwrap();
    ledger
        .add_cohort_rollup(make_cohort("tier_1", CohortReadiness::Ready))
        .unwrap();
    let report = gate.evaluate(&ledger);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.component, COMPONENT);
    assert_eq!(report.bead_id, BEAD_ID);
}

#[test]
fn gate_report_serde_roundtrip() {
    let gate = BlockerLedgerGate::with_defaults();
    let mut ledger = BlockerLedger::new();
    ledger.add_blocker(make_resolved_blocker("b1")).unwrap();
    ledger
        .add_cohort_rollup(make_cohort("tier_1", CohortReadiness::Ready))
        .unwrap();
    let report = gate.evaluate(&ledger);
    let json = serde_json::to_string(&report).unwrap();
    let parsed: GateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, parsed);
}

#[test]
fn gate_verdict_display() {
    assert_eq!(GateVerdict::Pass.to_string(), "PASS");
    let fail = GateVerdict::Fail {
        reasons: vec![RejectionReason::EmptyLedger],
    };
    assert!(fail.to_string().starts_with("FAIL"));
}

#[test]
fn rejection_reason_display_nonempty() {
    let reasons = vec![
        RejectionReason::EmptyLedger,
        RejectionReason::ReleaseBlockersPresent {
            count: 3,
            ids: vec!["b1".to_string()],
        },
        RejectionReason::ExcessiveDegraded { count: 15, max: 10 },
        RejectionReason::CohortNotReady {
            cohort: "react".to_string(),
            readiness: CohortReadiness::Blocked,
        },
        RejectionReason::LowCohortReadinessRate {
            rate_millionths: 500_000,
            threshold: 800_000,
        },
    ];
    for r in reasons {
        assert!(!r.to_string().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[test]
fn ledger_error_display_nonempty() {
    let e1 = LedgerError::LedgerOverflow {
        max: 5000,
        attempted: 5001,
    };
    assert!(!e1.to_string().is_empty());
    let e2 = LedgerError::DuplicateBlocker {
        id: "b1".to_string(),
    };
    assert!(!e2.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// Blocker entry
// ---------------------------------------------------------------------------

#[test]
fn blocker_entry_serde_roundtrip() {
    let entry = make_blocker("b1", BlockerSurface::ReactLane, BlockerSeverity::Degraded);
    let json = serde_json::to_string(&entry).unwrap();
    let parsed: BlockerEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, parsed);
}

#[test]
fn blocker_entry_with_tags() {
    let mut entry = make_blocker("b1", BlockerSurface::Parser, BlockerSeverity::Blocking);
    entry.tags.insert("critical".to_string());
    entry.tags.insert("react".to_string());
    assert_eq!(entry.tags.len(), 2);
}

// ---------------------------------------------------------------------------
// Cohort rollup
// ---------------------------------------------------------------------------

#[test]
fn cohort_rollup_serde_roundtrip() {
    let rollup = make_cohort("tier_1", CohortReadiness::Ready);
    let json = serde_json::to_string(&rollup).unwrap();
    let parsed: CohortRollup = serde_json::from_str(&json).unwrap();
    assert_eq!(rollup, parsed);
}
