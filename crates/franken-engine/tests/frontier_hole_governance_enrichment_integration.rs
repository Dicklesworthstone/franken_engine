//! Enrichment integration tests for `frontier_hole_governance`.
//!
//! Covers Copy/Clone semantics, BTreeSet dedup, Debug/Display uniqueness,
//! serde JSON field stability, Clone independence, determinism, boundary
//! conditions, and cross-cutting invariants NOT already tested in the base
//! integration file.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::frontier_hole_governance::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hole(id: &str, surface: &str, persistent: bool, structural: bool) -> GovernanceHoleEntry {
    GovernanceHoleEntry {
        hole_id: id.to_string(),
        surface: surface.to_string(),
        is_persistent: persistent,
        is_structural: structural,
        persistence_millionths: if structural {
            u64::MAX
        } else if persistent {
            200_000
        } else {
            10_000
        },
        has_witness: true,
        dimension: 1,
    }
}

fn cfg() -> GovernanceConfig {
    GovernanceConfig::default()
}

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// ===========================================================================
// HoleGovernanceSeverity enrichment
// ===========================================================================

#[test]
fn enrichment_severity_copy_semantics() {
    let a = HoleGovernanceSeverity::Critical;
    let b = a;
    assert_eq!(a, b);
    assert_eq!(format!("{a}"), "critical");
}

#[test]
fn enrichment_severity_btreeset_dedup() {
    let all = [
        HoleGovernanceSeverity::Informational,
        HoleGovernanceSeverity::Warning,
        HoleGovernanceSeverity::Blocking,
        HoleGovernanceSeverity::Critical,
    ];
    let mut set = BTreeSet::new();
    for &s in &all {
        set.insert(s);
        set.insert(s);
    }
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_severity_debug_all_unique() {
    let all = [
        HoleGovernanceSeverity::Informational,
        HoleGovernanceSeverity::Warning,
        HoleGovernanceSeverity::Blocking,
        HoleGovernanceSeverity::Critical,
    ];
    let debugs: BTreeSet<String> = all.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn enrichment_severity_display_all_unique() {
    let all = [
        HoleGovernanceSeverity::Informational,
        HoleGovernanceSeverity::Warning,
        HoleGovernanceSeverity::Blocking,
        HoleGovernanceSeverity::Critical,
    ];
    let displays: BTreeSet<String> = all.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_severity_ordering() {
    assert!(HoleGovernanceSeverity::Informational < HoleGovernanceSeverity::Warning);
    assert!(HoleGovernanceSeverity::Warning < HoleGovernanceSeverity::Blocking);
    assert!(HoleGovernanceSeverity::Blocking < HoleGovernanceSeverity::Critical);
}

// ===========================================================================
// ClaimCategory enrichment
// ===========================================================================

#[test]
fn enrichment_claim_category_copy_semantics() {
    let a = ClaimCategory::Supremacy;
    let b = a;
    assert_eq!(a, b);
    assert_eq!(format!("{a}"), "supremacy");
}

#[test]
fn enrichment_claim_category_btreeset_dedup() {
    let all = [
        ClaimCategory::Supremacy,
        ClaimCategory::Parity,
        ClaimCategory::Experimental,
    ];
    let mut set = BTreeSet::new();
    for &c in &all {
        set.insert(c);
        set.insert(c);
    }
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_claim_category_debug_all_unique() {
    let all = [
        ClaimCategory::Supremacy,
        ClaimCategory::Parity,
        ClaimCategory::Experimental,
    ];
    let debugs: BTreeSet<String> = all.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 3);
}

#[test]
fn enrichment_claim_category_display_all_unique() {
    let all = [
        ClaimCategory::Supremacy,
        ClaimCategory::Parity,
        ClaimCategory::Experimental,
    ];
    let displays: BTreeSet<String> = all.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 3);
}

// ===========================================================================
// GovernanceAction enrichment
// ===========================================================================

#[test]
fn enrichment_action_copy_semantics() {
    let a = GovernanceAction::ForceExperiment;
    let b = a;
    assert_eq!(a, b);
    assert_eq!(format!("{a}"), "force_experiment");
}

#[test]
fn enrichment_action_btreeset_dedup() {
    let all = [
        GovernanceAction::AllowClaim,
        GovernanceAction::DowngradeClaim,
        GovernanceAction::SuppressClaim,
        GovernanceAction::RequireEvidence,
        GovernanceAction::ForceExperiment,
    ];
    let mut set = BTreeSet::new();
    for &a in &all {
        set.insert(a);
        set.insert(a);
    }
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_action_debug_all_unique() {
    let all = [
        GovernanceAction::AllowClaim,
        GovernanceAction::DowngradeClaim,
        GovernanceAction::SuppressClaim,
        GovernanceAction::RequireEvidence,
        GovernanceAction::ForceExperiment,
    ];
    let debugs: BTreeSet<String> = all.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 5);
}

#[test]
fn enrichment_action_display_all_unique() {
    let all = [
        GovernanceAction::AllowClaim,
        GovernanceAction::DowngradeClaim,
        GovernanceAction::SuppressClaim,
        GovernanceAction::RequireEvidence,
        GovernanceAction::ForceExperiment,
    ];
    let displays: BTreeSet<String> = all.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 5);
}

// ===========================================================================
// GovernanceOutcome enrichment
// ===========================================================================

#[test]
fn enrichment_outcome_copy_semantics() {
    let a = GovernanceOutcome::Downgraded;
    let b = a;
    assert_eq!(a, b);
    assert_eq!(format!("{a}"), "downgraded");
}

#[test]
fn enrichment_outcome_display_all_unique() {
    let all = [
        GovernanceOutcome::AllClear,
        GovernanceOutcome::Downgraded,
        GovernanceOutcome::Suppressed,
        GovernanceOutcome::FullSuppression,
    ];
    let displays: BTreeSet<String> = all.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_outcome_debug_all_unique() {
    let all = [
        GovernanceOutcome::AllClear,
        GovernanceOutcome::Downgraded,
        GovernanceOutcome::Suppressed,
        GovernanceOutcome::FullSuppression,
    ];
    let debugs: BTreeSet<String> = all.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 4);
}

// ===========================================================================
// GovernanceHoleEntry enrichment
// ===========================================================================

#[test]
fn enrichment_hole_entry_clone_independence() {
    let original = hole("h1", "parser", true, false);
    let mut cloned = original.clone();
    cloned.hole_id = "h2".to_string();
    assert_eq!(original.hole_id, "h1");
    assert_eq!(cloned.hole_id, "h2");
}

#[test]
fn enrichment_hole_entry_json_field_names() {
    let h = hole("h1", "parser", true, false);
    let json = serde_json::to_string(&h).unwrap();
    assert!(json.contains("\"hole_id\""));
    assert!(json.contains("\"surface\""));
    assert!(json.contains("\"is_persistent\""));
    assert!(json.contains("\"is_structural\""));
    assert!(json.contains("\"persistence_millionths\""));
    assert!(json.contains("\"has_witness\""));
    assert!(json.contains("\"dimension\""));
}

#[test]
fn enrichment_hole_entry_debug_nonempty() {
    let h = hole("h1", "parser", true, false);
    let dbg = format!("{h:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("GovernanceHoleEntry"));
}

#[test]
fn enrichment_hole_entry_is_actionable_persistent() {
    let h = hole("h1", "parser", true, false);
    assert!(h.is_actionable());
}

#[test]
fn enrichment_hole_entry_is_actionable_structural() {
    let h = hole("h1", "parser", false, true);
    assert!(h.is_actionable());
}

#[test]
fn enrichment_hole_entry_not_actionable_noise() {
    let h = hole("h1", "parser", false, false);
    assert!(!h.is_actionable());
}

#[test]
fn enrichment_hole_entry_content_hash_deterministic() {
    let h1 = hole("h1", "parser", true, false);
    let h2 = hole("h1", "parser", true, false);
    assert_eq!(h1.content_hash(), h2.content_hash());
}

#[test]
fn enrichment_hole_entry_content_hash_varies_by_persistence() {
    let h1 = hole("h1", "parser", true, false);
    let h2 = hole("h1", "parser", false, false);
    assert_ne!(h1.content_hash(), h2.content_hash());
}

// ===========================================================================
// SupportBoundary enrichment
// ===========================================================================

#[test]
fn enrichment_boundary_clone_independence() {
    let original = SupportBoundary {
        surface: "parser".into(),
        fully_supported: true,
        coverage_millionths: 1_000_000,
        persistent_holes: 0,
        structural_holes: 0,
        blocking_hole_ids: vec![],
        boundary_statement: "parser: fully supported".into(),
    };
    let mut cloned = original.clone();
    cloned.surface = "runtime".to_string();
    assert_eq!(original.surface, "parser");
    assert_eq!(cloned.surface, "runtime");
}

#[test]
fn enrichment_boundary_json_field_names() {
    let b = SupportBoundary {
        surface: "parser".into(),
        fully_supported: false,
        coverage_millionths: 500_000,
        persistent_holes: 2,
        structural_holes: 1,
        blocking_hole_ids: vec!["h1".into()],
        boundary_statement: "test".into(),
    };
    let json = serde_json::to_string(&b).unwrap();
    assert!(json.contains("\"surface\""));
    assert!(json.contains("\"fully_supported\""));
    assert!(json.contains("\"coverage_millionths\""));
    assert!(json.contains("\"persistent_holes\""));
    assert!(json.contains("\"structural_holes\""));
    assert!(json.contains("\"blocking_hole_ids\""));
    assert!(json.contains("\"boundary_statement\""));
}

#[test]
fn enrichment_boundary_content_hash_deterministic() {
    let b1 = SupportBoundary {
        surface: "parser".into(),
        fully_supported: true,
        coverage_millionths: 1_000_000,
        persistent_holes: 0,
        structural_holes: 0,
        blocking_hole_ids: vec![],
        boundary_statement: "x".into(),
    };
    let b2 = b1.clone();
    assert_eq!(b1.content_hash(), b2.content_hash());
}

#[test]
fn enrichment_boundary_debug_nonempty() {
    let b = SupportBoundary {
        surface: "parser".into(),
        fully_supported: true,
        coverage_millionths: 1_000_000,
        persistent_holes: 0,
        structural_holes: 0,
        blocking_hole_ids: vec![],
        boundary_statement: "x".into(),
    };
    let dbg = format!("{b:?}");
    assert!(dbg.contains("SupportBoundary"));
}

// ===========================================================================
// GovernanceConfig enrichment
// ===========================================================================

#[test]
fn enrichment_config_clone_independence() {
    let original = cfg();
    let mut cloned = original.clone();
    cloned.max_persistent_holes = 100;
    assert_eq!(original.max_persistent_holes, DEFAULT_MAX_PERSISTENT_HOLES);
    assert_eq!(cloned.max_persistent_holes, 100);
}

#[test]
fn enrichment_config_json_field_names() {
    let c = cfg();
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("\"max_persistent_holes\""));
    assert!(json.contains("\"max_structural_holes\""));
    assert!(json.contains("\"min_supremacy_coverage_millionths\""));
    assert!(json.contains("\"min_parity_coverage_millionths\""));
    assert!(json.contains("\"ratchet_decay_millionths\""));
    assert!(json.contains("\"critical_surfaces\""));
}

#[test]
fn enrichment_config_default_matches_constants() {
    let c = cfg();
    assert_eq!(c.max_persistent_holes, DEFAULT_MAX_PERSISTENT_HOLES);
    assert_eq!(c.max_structural_holes, DEFAULT_MAX_STRUCTURAL_HOLES);
    assert_eq!(
        c.min_supremacy_coverage_millionths,
        DEFAULT_MIN_SUPREMACY_COVERAGE
    );
    assert_eq!(
        c.min_parity_coverage_millionths,
        DEFAULT_MIN_PARITY_COVERAGE
    );
    assert_eq!(c.ratchet_decay_millionths, DEFAULT_RATCHET_DECAY);
}

#[test]
fn enrichment_config_default_critical_surfaces() {
    let c = cfg();
    assert!(c.critical_surfaces.contains("parser"));
    assert!(c.critical_surfaces.contains("runtime"));
    assert_eq!(c.critical_surfaces.len(), 2);
}

#[test]
fn enrichment_config_serde_roundtrip() {
    let c = cfg();
    let json = serde_json::to_string(&c).unwrap();
    let back: GovernanceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn enrichment_config_debug_nonempty() {
    let c = cfg();
    let dbg = format!("{c:?}");
    assert!(dbg.contains("GovernanceConfig"));
}

// ===========================================================================
// RatchetState enrichment
// ===========================================================================

#[test]
fn enrichment_ratchet_clone_independence() {
    let original = RatchetState::new();
    let mut cloned = original.clone();
    cloned.initialized = true;
    assert!(!original.initialized);
    assert!(cloned.initialized);
}

#[test]
fn enrichment_ratchet_json_field_names() {
    let r = RatchetState::new();
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"surface_levels\""));
    assert!(json.contains("\"overall_level_millionths\""));
    assert!(json.contains("\"last_epoch\""));
    assert!(json.contains("\"initialized\""));
    assert!(json.contains("\"content_hash\""));
}

#[test]
fn enrichment_ratchet_seal_changes_hash() {
    let mut r = RatchetState::new();
    let hash_before = r.content_hash;
    r.initialized = true;
    r.overall_level_millionths = 500_000;
    r.seal();
    assert_ne!(hash_before, r.content_hash);
}

#[test]
fn enrichment_ratchet_seal_deterministic() {
    let mut r1 = RatchetState::new();
    r1.surface_levels.insert("parser".into(), 800_000);
    r1.initialized = true;
    r1.seal();

    let mut r2 = RatchetState::new();
    r2.surface_levels.insert("parser".into(), 800_000);
    r2.initialized = true;
    r2.seal();

    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_ratchet_default_eq_new() {
    assert_eq!(RatchetState::default(), RatchetState::new());
}

#[test]
fn enrichment_ratchet_debug_nonempty() {
    let r = RatchetState::new();
    let dbg = format!("{r:?}");
    assert!(dbg.contains("RatchetState"));
}

// ===========================================================================
// GovernanceDecision enrichment
// ===========================================================================

#[test]
fn enrichment_decision_clone_independence() {
    let holes = vec![hole("n", "parser", false, false)];
    let cov = compute_surface_coverage(&holes);
    let original = evaluate_claim(ClaimCategory::Parity, "parser", &holes, &cov, &cfg());
    let mut cloned = original.clone();
    cloned.decision_id = "mutated".to_string();
    assert_ne!(original.decision_id, "mutated");
    assert_eq!(cloned.decision_id, "mutated");
}

#[test]
fn enrichment_decision_json_field_names() {
    let holes = vec![hole("n", "parser", false, false)];
    let cov = compute_surface_coverage(&holes);
    let dec = evaluate_claim(ClaimCategory::Parity, "parser", &holes, &cov, &cfg());
    let json = serde_json::to_string(&dec).unwrap();
    assert!(json.contains("\"decision_id\""));
    assert!(json.contains("\"claim_category\""));
    assert!(json.contains("\"surface\""));
    assert!(json.contains("\"action\""));
    assert!(json.contains("\"reasons\""));
    assert!(json.contains("\"max_severity\""));
    assert!(json.contains("\"content_hash\""));
}

#[test]
fn enrichment_decision_debug_nonempty() {
    let holes = vec![hole("n", "parser", false, false)];
    let cov = compute_surface_coverage(&holes);
    let dec = evaluate_claim(ClaimCategory::Parity, "parser", &holes, &cov, &cfg());
    let dbg = format!("{dec:?}");
    assert!(dbg.contains("GovernanceDecision"));
}

#[test]
fn enrichment_decision_serde_roundtrip() {
    let holes = vec![hole("n", "parser", false, false)];
    let cov = compute_surface_coverage(&holes);
    let dec = evaluate_claim(ClaimCategory::Parity, "parser", &holes, &cov, &cfg());
    let json = serde_json::to_string(&dec).unwrap();
    let back: GovernanceDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(dec, back);
}

// ===========================================================================
// GovernanceReport enrichment
// ===========================================================================

#[test]
fn enrichment_report_clone_independence() {
    let holes = vec![hole("n", "parser", false, false)];
    let claims = vec![(ClaimCategory::Parity, "parser".to_string())];
    let original = evaluate(&holes, &claims, &RatchetState::new(), ep(1), &cfg()).unwrap();
    let mut cloned = original.clone();
    cloned.report_id = "mutated".to_string();
    assert_ne!(original.report_id, "mutated");
    assert_eq!(cloned.report_id, "mutated");
}

#[test]
fn enrichment_report_json_field_names() {
    let holes = vec![hole("n", "parser", false, false)];
    let claims = vec![(ClaimCategory::Parity, "parser".to_string())];
    let report = evaluate(&holes, &claims, &RatchetState::new(), ep(1), &cfg()).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"report_id\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"outcome\""));
    assert!(json.contains("\"decisions\""));
    assert!(json.contains("\"boundaries\""));
    assert!(json.contains("\"ratchet\""));
    assert!(json.contains("\"total_holes\""));
    assert!(json.contains("\"actionable_holes\""));
    assert!(json.contains("\"mandatory_experiments\""));
    assert!(json.contains("\"content_hash\""));
}

#[test]
fn enrichment_report_debug_nonempty() {
    let holes = vec![hole("n", "parser", false, false)];
    let claims = vec![];
    let report = evaluate(&holes, &claims, &RatchetState::new(), ep(1), &cfg()).unwrap();
    let dbg = format!("{report:?}");
    assert!(dbg.contains("GovernanceReport"));
}

// ===========================================================================
// GovernanceError enrichment
// ===========================================================================

#[test]
fn enrichment_error_display_all_unique() {
    let errors = vec![
        GovernanceError::EmptyInput,
        GovernanceError::InvalidHoleEntry("bad".into()),
        GovernanceError::RatchetRegression {
            surface: "p".into(),
            previous_millionths: 900_000,
            current_millionths: 500_000,
        },
        GovernanceError::InternalError("x".into()),
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| format!("{e}")).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_error_clone_independence() {
    let original = GovernanceError::RatchetRegression {
        surface: "parser".into(),
        previous_millionths: 900_000,
        current_millionths: 500_000,
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_error_debug_all_unique() {
    let errors = vec![
        GovernanceError::EmptyInput,
        GovernanceError::InvalidHoleEntry("bad".into()),
        GovernanceError::RatchetRegression {
            surface: "p".into(),
            previous_millionths: 900_000,
            current_millionths: 500_000,
        },
        GovernanceError::InternalError("x".into()),
    ];
    let debugs: BTreeSet<String> = errors.iter().map(|e| format!("{e:?}")).collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn enrichment_error_is_std_error() {
    let e = GovernanceError::EmptyInput;
    let err: &dyn std::error::Error = &e;
    assert!(!err.to_string().is_empty());
}

#[test]
fn enrichment_error_empty_input_display() {
    let e = GovernanceError::EmptyInput;
    assert!(format!("{e}").contains("no holes"));
}

#[test]
fn enrichment_error_ratchet_regression_display() {
    let e = GovernanceError::RatchetRegression {
        surface: "parser".into(),
        previous_millionths: 900_000,
        current_millionths: 500_000,
    };
    let s = format!("{e}");
    assert!(s.contains("parser"));
    assert!(s.contains("900000"));
    assert!(s.contains("500000"));
}

// ===========================================================================
// GovernanceSummary enrichment
// ===========================================================================

#[test]
fn enrichment_summary_clone_independence() {
    let holes = vec![hole("n", "parser", false, false)];
    let claims = vec![(ClaimCategory::Parity, "parser".to_string())];
    let report = evaluate(&holes, &claims, &RatchetState::new(), ep(1), &cfg()).unwrap();
    let original = summarize(&report);
    let mut cloned = original.clone();
    cloned.report_id = "mutated".to_string();
    assert_ne!(original.report_id, "mutated");
    assert_eq!(cloned.report_id, "mutated");
}

#[test]
fn enrichment_summary_json_field_names() {
    let holes = vec![hole("n", "parser", false, false)];
    let claims = vec![(ClaimCategory::Parity, "parser".to_string())];
    let report = evaluate(&holes, &claims, &RatchetState::new(), ep(1), &cfg()).unwrap();
    let s = summarize(&report);
    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"report_id\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"outcome\""));
    assert!(json.contains("\"total_holes\""));
    assert!(json.contains("\"actionable_holes\""));
    assert!(json.contains("\"decisions_count\""));
    assert!(json.contains("\"suppressed_count\""));
    assert!(json.contains("\"allowed_count\""));
    assert!(json.contains("\"mandatory_experiments_count\""));
    assert!(json.contains("\"overall_coverage_millionths\""));
    assert!(json.contains("\"content_hash\""));
}

#[test]
fn enrichment_summary_debug_nonempty() {
    let holes = vec![hole("n", "parser", false, false)];
    let claims = vec![];
    let report = evaluate(&holes, &claims, &RatchetState::new(), ep(1), &cfg()).unwrap();
    let s = summarize(&report);
    let dbg = format!("{s:?}");
    assert!(dbg.contains("GovernanceSummary"));
}

// ===========================================================================
// Cross-cutting: classify_severity all paths
// ===========================================================================

#[test]
fn enrichment_classify_structural_overrides_persistent() {
    // Both structural and persistent — structural takes priority (Critical)
    let h = hole("h1", "parser", true, true);
    assert_eq!(
        classify_severity(&h, &cfg()),
        HoleGovernanceSeverity::Critical
    );
}

#[test]
fn enrichment_classify_persistent_non_critical_surface_warning() {
    let h = hole("h1", "react", true, false);
    assert_eq!(
        classify_severity(&h, &cfg()),
        HoleGovernanceSeverity::Warning
    );
}

// ===========================================================================
// Cross-cutting: compute_surface_coverage edge cases
// ===========================================================================

#[test]
fn enrichment_coverage_all_actionable_is_zero() {
    let holes = vec![
        hole("p1", "parser", true, false),
        hole("p2", "parser", true, false),
    ];
    let cov = compute_surface_coverage(&holes);
    assert_eq!(*cov.get("parser").unwrap(), 0);
}

#[test]
fn enrichment_coverage_all_noise_is_million() {
    let holes = vec![
        hole("n1", "parser", false, false),
        hole("n2", "parser", false, false),
        hole("n3", "parser", false, false),
    ];
    let cov = compute_surface_coverage(&holes);
    assert_eq!(*cov.get("parser").unwrap(), 1_000_000);
}

#[test]
fn enrichment_coverage_half_actionable() {
    let holes = vec![
        hole("p1", "parser", true, false),
        hole("n1", "parser", false, false),
    ];
    let cov = compute_surface_coverage(&holes);
    assert_eq!(*cov.get("parser").unwrap(), 500_000);
}

// ===========================================================================
// Cross-cutting: overall_coverage edge cases
// ===========================================================================

#[test]
fn enrichment_overall_coverage_two_surfaces_average() {
    let mut m = BTreeMap::new();
    m.insert("parser".to_string(), 600_000u64);
    m.insert("runtime".to_string(), 800_000u64);
    assert_eq!(overall_coverage(&m), 700_000);
}

#[test]
fn enrichment_overall_coverage_three_surfaces() {
    let mut m = BTreeMap::new();
    m.insert("a".to_string(), 1_000_000u64);
    m.insert("b".to_string(), 500_000u64);
    m.insert("c".to_string(), 500_000u64);
    // (1_000_000 + 500_000 + 500_000) / 3 = 666_666
    let result = overall_coverage(&m);
    assert!((666_000..=667_000).contains(&result));
}

// ===========================================================================
// Cross-cutting: evaluate_claim boundary conditions
// ===========================================================================

#[test]
fn enrichment_parity_many_persistent_downgraded() {
    // More persistent holes than max (default 5) → Parity = DowngradeClaim
    let holes: Vec<GovernanceHoleEntry> = (0..10)
        .map(|i| hole(&format!("p{i}"), "react", true, false))
        .collect();
    let cov = compute_surface_coverage(&holes);
    let dec = evaluate_claim(ClaimCategory::Parity, "react", &holes, &cov, &cfg());
    assert_eq!(dec.action, GovernanceAction::DowngradeClaim);
}

#[test]
fn enrichment_experimental_many_persistent_requires_evidence() {
    // More persistent holes than max → Experimental = RequireEvidence
    let holes: Vec<GovernanceHoleEntry> = (0..10)
        .map(|i| hole(&format!("p{i}"), "react", true, false))
        .collect();
    let cov = compute_surface_coverage(&holes);
    let dec = evaluate_claim(ClaimCategory::Experimental, "react", &holes, &cov, &cfg());
    assert_eq!(dec.action, GovernanceAction::RequireEvidence);
}

#[test]
fn enrichment_supremacy_critical_surface_persistent_downgraded() {
    // parser is critical, 1 persistent hole within limit, but critical surface check triggers
    let holes = vec![hole("p1", "parser", true, false)];
    let cov = compute_surface_coverage(&holes);
    let dec = evaluate_claim(ClaimCategory::Supremacy, "parser", &holes, &cov, &cfg());
    // Coverage is 0 which is below 90%, so should downgrade
    assert_eq!(dec.action, GovernanceAction::DowngradeClaim);
}

#[test]
fn enrichment_claim_no_holes_on_surface_allows() {
    // Holes exist on different surface, claim on clean surface
    let holes = vec![hole("p1", "parser", true, false)];
    let cov = compute_surface_coverage(&holes);
    let dec = evaluate_claim(ClaimCategory::Supremacy, "runtime", &holes, &cov, &cfg());
    assert!(dec.is_allowed());
}

#[test]
fn enrichment_decision_has_reasons() {
    let holes = vec![hole("s1", "parser", false, true)];
    let cov = compute_surface_coverage(&holes);
    let dec = evaluate_claim(ClaimCategory::Supremacy, "parser", &holes, &cov, &cfg());
    assert!(!dec.reasons.is_empty());
}

// ===========================================================================
// Cross-cutting: update_ratchet
// ===========================================================================

#[test]
fn enrichment_ratchet_first_update_always_ok() {
    let r = RatchetState::new();
    let mut cov = BTreeMap::new();
    cov.insert("parser".into(), 800_000u64);
    let result = update_ratchet(&r, &cov, ep(1), &cfg());
    assert!(result.is_ok());
    let new_r = result.unwrap();
    assert!(new_r.initialized);
    assert_eq!(*new_r.surface_levels.get("parser").unwrap(), 800_000);
}

#[test]
fn enrichment_ratchet_improvement_ok() {
    let r = RatchetState::new();
    let mut cov1 = BTreeMap::new();
    cov1.insert("parser".into(), 500_000u64);
    let r1 = update_ratchet(&r, &cov1, ep(1), &cfg()).unwrap();

    let mut cov2 = BTreeMap::new();
    cov2.insert("parser".into(), 800_000u64);
    let r2 = update_ratchet(&r1, &cov2, ep(2), &cfg());
    assert!(r2.is_ok());
}

#[test]
fn enrichment_ratchet_regression_without_decay_fails() {
    let r = RatchetState::new();
    let mut cov1 = BTreeMap::new();
    cov1.insert("parser".into(), 800_000u64);
    let r1 = update_ratchet(&r, &cov1, ep(1), &cfg()).unwrap();

    // Same epoch, regression
    let mut cov2 = BTreeMap::new();
    cov2.insert("parser".into(), 500_000u64);
    let result = update_ratchet(&r1, &cov2, ep(1), &cfg());
    assert!(result.is_err());
}

#[test]
fn enrichment_ratchet_decay_allows_slight_regression() {
    let r = RatchetState::new();
    let mut cov1 = BTreeMap::new();
    cov1.insert("parser".into(), 800_000u64);
    let r1 = update_ratchet(&r, &cov1, ep(1), &cfg()).unwrap();

    // Epoch jumps by 2, decay = 2 * 50_000 = 100_000
    // effective_prev = 800_000 - 100_000 = 700_000
    // new_cov = 750_000 >= 700_000 → OK
    let mut cov2 = BTreeMap::new();
    cov2.insert("parser".into(), 750_000u64);
    let result = update_ratchet(&r1, &cov2, ep(3), &cfg());
    assert!(result.is_ok());
}

// ===========================================================================
// Cross-cutting: full evaluation determinism
// ===========================================================================

#[test]
fn enrichment_evaluate_determinism_five_runs() {
    let holes = vec![
        hole("p1", "parser", true, false),
        hole("n1", "runtime", false, false),
        hole("s1", "react", false, true),
    ];
    let claims = vec![
        (ClaimCategory::Supremacy, "parser".to_string()),
        (ClaimCategory::Parity, "runtime".to_string()),
        (ClaimCategory::Experimental, "react".to_string()),
    ];
    let mut hashes = BTreeSet::new();
    for _ in 0..5 {
        let report = evaluate(&holes, &claims, &RatchetState::new(), ep(1), &cfg()).unwrap();
        hashes.insert(report.content_hash);
    }
    assert_eq!(hashes.len(), 1);
}

#[test]
fn enrichment_evaluate_empty_input_error() {
    let result = evaluate(&[], &[], &RatchetState::new(), ep(1), &cfg());
    assert!(result.is_err());
    if let Err(GovernanceError::EmptyInput) = result {
        // expected
    } else {
        panic!("expected EmptyInput error");
    }
}

#[test]
fn enrichment_evaluate_report_serde_preserves_outcome() {
    let holes = vec![
        hole("p1", "parser", true, false),
        hole("n1", "runtime", false, false),
    ];
    let claims = vec![
        (ClaimCategory::Supremacy, "parser".to_string()),
        (ClaimCategory::Parity, "runtime".to_string()),
    ];
    let report = evaluate(&holes, &claims, &RatchetState::new(), ep(1), &cfg()).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: GovernanceReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report.outcome, back.outcome);
    assert_eq!(report.total_holes, back.total_holes);
    assert_eq!(report.actionable_holes, back.actionable_holes);
}

// ===========================================================================
// Cross-cutting: helper functions coverage
// ===========================================================================

#[test]
fn enrichment_suppressed_count_zero_when_clean() {
    let holes = vec![hole("n", "parser", false, false)];
    let claims = vec![(ClaimCategory::Parity, "parser".to_string())];
    let report = evaluate(&holes, &claims, &RatchetState::new(), ep(1), &cfg()).unwrap();
    assert_eq!(suppressed_count(&report), 0);
}

#[test]
fn enrichment_allowed_count_all_when_clean() {
    let holes = vec![hole("n", "parser", false, false)];
    let claims = vec![(ClaimCategory::Parity, "parser".to_string())];
    let report = evaluate(&holes, &claims, &RatchetState::new(), ep(1), &cfg()).unwrap();
    assert_eq!(allowed_count(&report), 1);
}

#[test]
fn enrichment_blocked_surfaces_empty_when_clean() {
    let holes = vec![hole("n", "parser", false, false)];
    let claims = vec![];
    let report = evaluate(&holes, &claims, &RatchetState::new(), ep(1), &cfg()).unwrap();
    let blocked = blocked_surfaces(&report);
    assert!(blocked.is_empty());
}

#[test]
fn enrichment_blocked_surfaces_includes_persistent() {
    let holes = vec![
        hole("p1", "parser", true, false),
        hole("n1", "runtime", false, false),
    ];
    let claims = vec![];
    let report = evaluate(&holes, &claims, &RatchetState::new(), ep(1), &cfg()).unwrap();
    let blocked = blocked_surfaces(&report);
    assert!(blocked.contains("parser"));
    assert!(!blocked.contains("runtime"));
}

// ===========================================================================
// Cross-cutting: constants
// ===========================================================================

#[test]
fn enrichment_constants_all_stable() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.frontier-hole-governance.v1");
    assert_eq!(BEAD_ID, "bd-1lsy.9.9.3");
    assert_eq!(COMPONENT, "frontier_hole_governance");
    assert_eq!(POLICY_ID, "RGC-809C");
    assert_eq!(DEFAULT_MAX_PERSISTENT_HOLES, 5);
    assert_eq!(DEFAULT_MIN_SUPREMACY_COVERAGE, 900_000);
    assert_eq!(DEFAULT_MIN_PARITY_COVERAGE, 800_000);
    assert_eq!(DEFAULT_MAX_STRUCTURAL_HOLES, 0);
    assert_eq!(DEFAULT_RATCHET_DECAY, 50_000);
}

// ===========================================================================
// Cross-cutting: mandatory experiments
// ===========================================================================

#[test]
fn enrichment_mandatory_experiments_persistent_critical_surface() {
    let holes = vec![
        hole("p1", "parser", true, false), // persistent + critical surface → mandatory
        hole("n1", "react", false, false), // noise → not mandatory
    ];
    let claims = vec![];
    let report = evaluate(&holes, &claims, &RatchetState::new(), ep(1), &cfg()).unwrap();
    assert!(report.mandatory_experiments.contains(&"p1".to_string()));
    assert!(!report.mandatory_experiments.contains(&"n1".to_string()));
}

#[test]
fn enrichment_mandatory_experiments_persistent_noncritical_not_mandatory() {
    let holes = vec![
        hole("p1", "react", true, false), // persistent but not critical surface
    ];
    let claims = vec![];
    let report = evaluate(&holes, &claims, &RatchetState::new(), ep(1), &cfg()).unwrap();
    assert!(!report.mandatory_experiments.contains(&"p1".to_string()));
}

// ===========================================================================
// Cross-cutting: build_boundaries edge cases
// ===========================================================================

#[test]
fn enrichment_boundary_multiple_surfaces_correct_count() {
    let holes = vec![
        hole("h1", "parser", false, false),
        hole("h2", "runtime", true, false),
        hole("h3", "react", false, true),
    ];
    let cov = compute_surface_coverage(&holes);
    let boundaries = build_boundaries(&holes, &cov, &cfg());
    assert_eq!(boundaries.len(), 3);
}

#[test]
fn enrichment_boundary_blocking_ids_match_actionable() {
    let holes = vec![
        hole("p1", "parser", true, false),
        hole("n1", "parser", false, false),
        hole("s1", "parser", false, true),
    ];
    let cov = compute_surface_coverage(&holes);
    let boundaries = build_boundaries(&holes, &cov, &cfg());
    assert_eq!(boundaries.len(), 1);
    let b = &boundaries[0];
    // p1 and s1 are actionable
    assert!(b.blocking_hole_ids.contains(&"p1".to_string()));
    assert!(b.blocking_hole_ids.contains(&"s1".to_string()));
    assert!(!b.blocking_hole_ids.contains(&"n1".to_string()));
}

// ===========================================================================
// Cross-cutting: summary counts match report
// ===========================================================================

#[test]
fn enrichment_summary_counts_match_report() {
    let holes = vec![
        hole("s1", "parser", false, true),
        hole("n1", "runtime", false, false),
        hole("p1", "react", true, false),
    ];
    let claims = vec![
        (ClaimCategory::Supremacy, "parser".to_string()),
        (ClaimCategory::Parity, "runtime".to_string()),
        (ClaimCategory::Experimental, "react".to_string()),
    ];
    let report = evaluate(&holes, &claims, &RatchetState::new(), ep(1), &cfg()).unwrap();
    let s = summarize(&report);
    assert_eq!(s.total_holes, report.total_holes);
    assert_eq!(s.actionable_holes, report.actionable_holes);
    assert_eq!(s.decisions_count, report.decisions.len() as u64);
    assert_eq!(s.suppressed_count, suppressed_count(&report) as u64);
    assert_eq!(s.allowed_count, allowed_count(&report) as u64);
    assert_eq!(
        s.mandatory_experiments_count,
        report.mandatory_experiments.len() as u64
    );
}
