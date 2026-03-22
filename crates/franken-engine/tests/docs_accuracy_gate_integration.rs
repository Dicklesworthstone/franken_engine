//! Integration tests for the `docs_accuracy_gate` module.
//!
//! Covers inventory construction, drift classification, gate evaluation,
//! verdict production, serde roundtrips, and edge cases.

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

use frankenengine_engine::docs_accuracy_gate::{
    BEAD_ID, COMPONENT, DocSource, DocsAccuracyGate, DocsAccuracyInventory, DocumentedSurface,
    DriftClass, GateConfig, GateError, GateReport, GateVerdict, RejectionReason, SCHEMA_VERSION,
    SurfaceType, UnsupportedSurfaceContract,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn aligned_surface(id: &str, name: &str) -> DocumentedSurface {
    DocumentedSurface {
        id: id.to_string(),
        name: name.to_string(),
        surface_type: SurfaceType::Command,
        sources: BTreeSet::from([DocSource::Readme]),
        documented_behavior: "does X".to_string(),
        shipped_behavior: "does X".to_string(),
        drift_class: DriftClass::Aligned,
        drift_notes: String::new(),
        explicitly_unsupported: false,
    }
}

fn drifted_surface(id: &str, drift: DriftClass) -> DocumentedSurface {
    DocumentedSurface {
        id: id.to_string(),
        name: format!("surface-{id}"),
        surface_type: SurfaceType::Command,
        sources: BTreeSet::from([DocSource::Readme, DocSource::CliHelp]),
        documented_behavior: "claims X".to_string(),
        shipped_behavior: "does Y".to_string(),
        drift_class: drift,
        drift_notes: "drift detected".to_string(),
        explicitly_unsupported: false,
    }
}

fn make_unsupported(name: &str) -> UnsupportedSurfaceContract {
    UnsupportedSurfaceContract {
        surface_name: name.to_string(),
        reason: "not implemented yet".to_string(),
        workaround: None,
        planned_support: true,
        tracking_bead: Some("bd-test".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("docs-accuracy-gate"));
}

#[test]
fn component_is_nonempty() {
    assert!(!COMPONENT.is_empty());
    assert_eq!(COMPONENT, "docs_accuracy_gate");
}

#[test]
fn bead_id_is_nonempty() {
    assert!(!BEAD_ID.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
}

// ---------------------------------------------------------------------------
// DocSource
// ---------------------------------------------------------------------------

#[test]
fn doc_source_all_variants_have_nonempty_str() {
    let variants = [
        DocSource::Readme,
        DocSource::CliHelp,
        DocSource::OperatorDocs,
        DocSource::InlineComments,
        DocSource::ExternalReference,
    ];
    for v in variants {
        assert!(!v.as_str().is_empty());
        assert!(!v.to_string().is_empty());
    }
}

#[test]
fn doc_source_serde_roundtrip() {
    let sources = vec![DocSource::Readme, DocSource::CliHelp];
    let json = serde_json::to_string(&sources).unwrap();
    let parsed: Vec<DocSource> = serde_json::from_str(&json).unwrap();
    assert_eq!(sources, parsed);
}

// ---------------------------------------------------------------------------
// SurfaceType
// ---------------------------------------------------------------------------

#[test]
fn surface_type_all_variants_have_nonempty_str() {
    let variants = [
        SurfaceType::Command,
        SurfaceType::Flag,
        SurfaceType::Subcommand,
        SurfaceType::ConfigOption,
        SurfaceType::RuntimeBehavior,
        SurfaceType::ApiSurface,
        SurfaceType::OutputFormat,
    ];
    for v in variants {
        assert!(!v.as_str().is_empty());
        assert!(!v.to_string().is_empty());
    }
}

#[test]
fn surface_type_serde_roundtrip() {
    let st = SurfaceType::RuntimeBehavior;
    let json = serde_json::to_string(&st).unwrap();
    let parsed: SurfaceType = serde_json::from_str(&json).unwrap();
    assert_eq!(st, parsed);
}

// ---------------------------------------------------------------------------
// DriftClass
// ---------------------------------------------------------------------------

#[test]
fn drift_class_acceptability() {
    assert!(DriftClass::Aligned.is_acceptable());
    assert!(DriftClass::MinorSyntaxDrift.is_acceptable());
    assert!(!DriftClass::AspirationalClaim.is_acceptable());
    assert!(!DriftClass::UndocumentedFeature.is_acceptable());
    assert!(!DriftClass::ContradictoryBehavior.is_acceptable());
    assert!(!DriftClass::DeprecatedReference.is_acceptable());
    assert!(!DriftClass::BrokenExample.is_acceptable());
}

#[test]
fn drift_class_severity_monotonic_for_critical_classes() {
    assert!(
        DriftClass::ContradictoryBehavior.severity_millionths()
            > DriftClass::BrokenExample.severity_millionths()
    );
    assert!(
        DriftClass::BrokenExample.severity_millionths()
            > DriftClass::AspirationalClaim.severity_millionths()
    );
    assert!(
        DriftClass::AspirationalClaim.severity_millionths()
            > DriftClass::DeprecatedReference.severity_millionths()
    );
}

#[test]
fn drift_class_aligned_has_zero_severity() {
    assert_eq!(DriftClass::Aligned.severity_millionths(), 0);
}

#[test]
fn drift_class_serde_roundtrip() {
    let dc = DriftClass::ContradictoryBehavior;
    let json = serde_json::to_string(&dc).unwrap();
    let parsed: DriftClass = serde_json::from_str(&json).unwrap();
    assert_eq!(dc, parsed);
}

// ---------------------------------------------------------------------------
// DocsAccuracyInventory
// ---------------------------------------------------------------------------

#[test]
fn empty_inventory_has_zero_counts() {
    let inv = DocsAccuracyInventory::new();
    assert_eq!(inv.surface_count(), 0);
    assert!(inv.drifted_surfaces().is_empty());
    assert!(inv.surfaces_by_drift().is_empty());
    assert!(inv.surfaces_by_source().is_empty());
}

#[test]
fn add_surface_increments_count() {
    let mut inv = DocsAccuracyInventory::new();
    inv.add_surface(aligned_surface("s1", "compile")).unwrap();
    assert_eq!(inv.surface_count(), 1);
    inv.add_surface(aligned_surface("s2", "run")).unwrap();
    assert_eq!(inv.surface_count(), 2);
}

#[test]
fn duplicate_surface_id_rejected() {
    let mut inv = DocsAccuracyInventory::new();
    inv.add_surface(aligned_surface("s1", "compile")).unwrap();
    let result = inv.add_surface(aligned_surface("s1", "run"));
    assert!(result.is_err());
    match result.unwrap_err() {
        GateError::DuplicateSurface { id } => assert_eq!(id, "s1"),
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn drifted_surfaces_only_returns_unacceptable() {
    let mut inv = DocsAccuracyInventory::new();
    inv.add_surface(aligned_surface("s1", "compile")).unwrap();
    inv.add_surface(drifted_surface("s2", DriftClass::MinorSyntaxDrift))
        .unwrap();
    inv.add_surface(drifted_surface("s3", DriftClass::AspirationalClaim))
        .unwrap();
    inv.add_surface(drifted_surface("s4", DriftClass::ContradictoryBehavior))
        .unwrap();

    let drifted = inv.drifted_surfaces();
    assert_eq!(drifted.len(), 2); // only aspirational + contradictory
    assert!(drifted.iter().any(|s| s.id == "s3"));
    assert!(drifted.iter().any(|s| s.id == "s4"));
}

#[test]
fn surfaces_by_drift_counts_correctly() {
    let mut inv = DocsAccuracyInventory::new();
    inv.add_surface(aligned_surface("s1", "compile")).unwrap();
    inv.add_surface(aligned_surface("s2", "run")).unwrap();
    inv.add_surface(drifted_surface("s3", DriftClass::BrokenExample))
        .unwrap();

    let dist = inv.surfaces_by_drift();
    assert_eq!(*dist.get(&DriftClass::Aligned).unwrap_or(&0), 2);
    assert_eq!(*dist.get(&DriftClass::BrokenExample).unwrap_or(&0), 1);
}

#[test]
fn surfaces_by_source_counts_multi_source_entries() {
    let mut inv = DocsAccuracyInventory::new();
    // drifted_surface has both Readme and CliHelp sources
    inv.add_surface(drifted_surface("s1", DriftClass::AspirationalClaim))
        .unwrap();

    let by_source = inv.surfaces_by_source();
    assert_eq!(*by_source.get(&DocSource::Readme).unwrap_or(&0), 1);
    assert_eq!(*by_source.get(&DocSource::CliHelp).unwrap_or(&0), 1);
}

#[test]
fn content_hash_deterministic() {
    let mut inv1 = DocsAccuracyInventory::new();
    inv1.add_surface(aligned_surface("s1", "compile")).unwrap();
    let mut inv2 = DocsAccuracyInventory::new();
    inv2.add_surface(aligned_surface("s1", "compile")).unwrap();
    assert_eq!(inv1.content_hash(), inv2.content_hash());
}

#[test]
fn content_hash_differs_with_different_surfaces() {
    let mut inv1 = DocsAccuracyInventory::new();
    inv1.add_surface(aligned_surface("s1", "compile")).unwrap();
    let mut inv2 = DocsAccuracyInventory::new();
    inv2.add_surface(aligned_surface("s2", "run")).unwrap();
    assert_ne!(inv1.content_hash(), inv2.content_hash());
}

#[test]
fn inventory_serde_roundtrip() {
    let mut inv = DocsAccuracyInventory::new();
    inv.add_surface(aligned_surface("s1", "compile")).unwrap();
    inv.add_surface(drifted_surface("s2", DriftClass::BrokenExample))
        .unwrap();
    inv.add_unsupported(make_unsupported("workspace init"));

    let json = serde_json::to_string(&inv).unwrap();
    let parsed: DocsAccuracyInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, parsed);
}

// ---------------------------------------------------------------------------
// UnsupportedSurfaceContract
// ---------------------------------------------------------------------------

#[test]
fn unsupported_contract_serde_roundtrip() {
    let contract = make_unsupported("tui dashboard");
    let json = serde_json::to_string(&contract).unwrap();
    let parsed: UnsupportedSurfaceContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, parsed);
}

// ---------------------------------------------------------------------------
// Gate evaluation
// ---------------------------------------------------------------------------

#[test]
fn gate_passes_with_fully_aligned_inventory() {
    let gate = DocsAccuracyGate::with_defaults();
    let mut inv = DocsAccuracyInventory::new();
    for i in 0..10 {
        inv.add_surface(aligned_surface(&format!("s{i}"), &format!("cmd-{i}")))
            .unwrap();
    }
    let report = gate.evaluate(&inv);
    assert!(report.verdict.is_pass());
    assert_eq!(report.aligned_count, 10);
    assert_eq!(report.drifted_count, 0);
    assert_eq!(report.alignment_rate_millionths, 1_000_000);
}

#[test]
fn gate_fails_on_empty_inventory() {
    let gate = DocsAccuracyGate::with_defaults();
    let inv = DocsAccuracyInventory::new();
    let report = gate.evaluate(&inv);
    assert!(!report.verdict.is_pass());
    match &report.verdict {
        GateVerdict::Fail { reasons } => {
            assert!(
                reasons
                    .iter()
                    .any(|r| matches!(r, RejectionReason::EmptyInventory))
            );
        }
        _ => panic!("expected Fail verdict"),
    }
}

#[test]
fn gate_fails_on_contradictory_behavior() {
    let gate = DocsAccuracyGate::with_defaults();
    let mut inv = DocsAccuracyInventory::new();
    for i in 0..9 {
        inv.add_surface(aligned_surface(&format!("s{i}"), &format!("cmd-{i}")))
            .unwrap();
    }
    inv.add_surface(drifted_surface("bad", DriftClass::ContradictoryBehavior))
        .unwrap();
    let report = gate.evaluate(&inv);
    assert!(!report.verdict.is_pass());
}

#[test]
fn gate_fails_on_aspirational_claim_when_max_is_zero() {
    let gate = DocsAccuracyGate::with_defaults(); // max_aspirational_claims = 0
    let mut inv = DocsAccuracyInventory::new();
    for i in 0..9 {
        inv.add_surface(aligned_surface(&format!("s{i}"), &format!("cmd-{i}")))
            .unwrap();
    }
    inv.add_surface(drifted_surface("asp", DriftClass::AspirationalClaim))
        .unwrap();
    let report = gate.evaluate(&inv);
    assert!(!report.verdict.is_pass());
}

#[test]
fn gate_passes_with_minor_syntax_drift() {
    let gate = DocsAccuracyGate::with_defaults();
    let mut inv = DocsAccuracyInventory::new();
    for i in 0..19 {
        inv.add_surface(aligned_surface(&format!("s{i}"), &format!("cmd-{i}")))
            .unwrap();
    }
    inv.add_surface(drifted_surface("minor", DriftClass::MinorSyntaxDrift))
        .unwrap();
    let report = gate.evaluate(&inv);
    // Minor syntax drift is acceptable, so alignment rate = 20/20 = 100%
    assert!(report.verdict.is_pass());
}

#[test]
fn gate_report_schema_version_matches() {
    let gate = DocsAccuracyGate::with_defaults();
    let mut inv = DocsAccuracyInventory::new();
    inv.add_surface(aligned_surface("s1", "compile")).unwrap();
    let report = gate.evaluate(&inv);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.component, COMPONENT);
    assert_eq!(report.bead_id, BEAD_ID);
}

#[test]
fn gate_report_drift_distribution_is_deterministic() {
    let gate = DocsAccuracyGate::with_defaults();
    let mut inv = DocsAccuracyInventory::new();
    inv.add_surface(aligned_surface("s1", "compile")).unwrap();
    inv.add_surface(aligned_surface("s2", "run")).unwrap();
    let report1 = gate.evaluate(&inv);
    let report2 = gate.evaluate(&inv);
    assert_eq!(report1.drift_distribution, report2.drift_distribution);
    assert_eq!(report1.inventory_hash, report2.inventory_hash);
}

#[test]
fn gate_report_serde_roundtrip() {
    let gate = DocsAccuracyGate::with_defaults();
    let mut inv = DocsAccuracyInventory::new();
    inv.add_surface(aligned_surface("s1", "compile")).unwrap();
    inv.add_unsupported(make_unsupported("workspace init"));
    let report = gate.evaluate(&inv);
    let json = serde_json::to_string(&report).unwrap();
    let parsed: GateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, parsed);
}

#[test]
fn gate_verdict_display_pass() {
    let v = GateVerdict::Pass;
    assert_eq!(v.to_string(), "PASS");
    assert!(v.is_pass());
}

#[test]
fn gate_verdict_display_fail() {
    let v = GateVerdict::Fail {
        reasons: vec![RejectionReason::EmptyInventory],
    };
    assert!(v.to_string().starts_with("FAIL"));
    assert!(!v.is_pass());
}

#[test]
fn rejection_reason_display_nonempty() {
    let reasons = vec![
        RejectionReason::EmptyInventory,
        RejectionReason::ExcessiveAspirations { count: 5, max: 0 },
        RejectionReason::ExcessiveBrokenExamples { count: 3, max: 0 },
        RejectionReason::ContradictoryBehaviorFound { count: 2 },
        RejectionReason::ExcessiveSeverity {
            avg_millionths: 100_000,
            threshold: 50_000,
        },
        RejectionReason::LowAlignmentRate {
            rate_millionths: 800_000,
            threshold: 950_000,
        },
    ];
    for r in reasons {
        assert!(!r.to_string().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Custom config
// ---------------------------------------------------------------------------

#[test]
fn custom_config_allows_aspirational_claims() {
    let config = GateConfig {
        max_aspirational_claims: 5,
        max_broken_examples: 0,
        fail_on_contradictory: true,
        max_avg_severity_millionths: 500_000,
        min_alignment_rate_millionths: 500_000,
    };
    let gate = DocsAccuracyGate::new(config);
    let mut inv = DocsAccuracyInventory::new();
    for i in 0..10 {
        inv.add_surface(aligned_surface(&format!("s{i}"), &format!("cmd-{i}")))
            .unwrap();
    }
    for i in 0..3 {
        inv.add_surface(drifted_surface(
            &format!("asp{i}"),
            DriftClass::AspirationalClaim,
        ))
        .unwrap();
    }
    let report = gate.evaluate(&inv);
    // 3 aspirational <= 5 max, and alignment rate is 10/13 = 769230 > 500000
    assert!(report.verdict.is_pass());
}

#[test]
fn gate_unsupported_contract_count_in_report() {
    let gate = DocsAccuracyGate::with_defaults();
    let mut inv = DocsAccuracyInventory::new();
    inv.add_surface(aligned_surface("s1", "compile")).unwrap();
    inv.add_unsupported(make_unsupported("workspace init"));
    inv.add_unsupported(make_unsupported("tui dashboard"));
    let report = gate.evaluate(&inv);
    assert_eq!(report.unsupported_contract_count, 2);
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[test]
fn gate_error_display_nonempty() {
    let e1 = GateError::InventoryOverflow {
        max: 1000,
        attempted: 1001,
    };
    assert!(!e1.to_string().is_empty());
    let e2 = GateError::DuplicateSurface {
        id: "s1".to_string(),
    };
    assert!(!e2.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// Documented surface
// ---------------------------------------------------------------------------

#[test]
fn documented_surface_serde_roundtrip() {
    let surface = drifted_surface("s1", DriftClass::DeprecatedReference);
    let json = serde_json::to_string(&surface).unwrap();
    let parsed: DocumentedSurface = serde_json::from_str(&json).unwrap();
    assert_eq!(surface, parsed);
}

#[test]
fn documented_surface_explicitly_unsupported_flag() {
    let mut surface = aligned_surface("s1", "compile");
    assert!(!surface.explicitly_unsupported);
    surface.explicitly_unsupported = true;
    assert!(surface.explicitly_unsupported);
}
