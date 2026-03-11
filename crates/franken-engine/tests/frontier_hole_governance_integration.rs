//! Integration tests for frontier_hole_governance — RGC-809C (bd-1lsy.9.9.3)
//!
//! Validates governance evaluation across surfaces, claim categories,
//! ratchet behavior, support boundaries, and serde roundtrips.

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

fn ratchet() -> RatchetState {
    RatchetState::new()
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn integration_schema_version() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn integration_bead_id() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn integration_component() {
    assert!(!COMPONENT.is_empty());
}

#[test]
fn integration_policy_id() {
    assert!(POLICY_ID.starts_with("RGC-"));
}

// ---------------------------------------------------------------------------
// HoleGovernanceSeverity
// ---------------------------------------------------------------------------

#[test]
fn severity_all_variants_display() {
    let variants = [
        HoleGovernanceSeverity::Informational,
        HoleGovernanceSeverity::Warning,
        HoleGovernanceSeverity::Blocking,
        HoleGovernanceSeverity::Critical,
    ];
    for v in &variants {
        assert!(!format!("{v}").is_empty());
    }
}

#[test]
fn severity_serde_all_variants() {
    let variants = [
        HoleGovernanceSeverity::Informational,
        HoleGovernanceSeverity::Warning,
        HoleGovernanceSeverity::Blocking,
        HoleGovernanceSeverity::Critical,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: HoleGovernanceSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// ClaimCategory
// ---------------------------------------------------------------------------

#[test]
fn claim_category_serde_all() {
    let cats = [
        ClaimCategory::Supremacy,
        ClaimCategory::Parity,
        ClaimCategory::Experimental,
    ];
    for c in &cats {
        let json = serde_json::to_string(c).unwrap();
        let back: ClaimCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

// ---------------------------------------------------------------------------
// GovernanceAction
// ---------------------------------------------------------------------------

#[test]
fn action_serde_all() {
    let actions = [
        GovernanceAction::AllowClaim,
        GovernanceAction::DowngradeClaim,
        GovernanceAction::SuppressClaim,
        GovernanceAction::RequireEvidence,
        GovernanceAction::ForceExperiment,
    ];
    for a in &actions {
        let json = serde_json::to_string(a).unwrap();
        let back: GovernanceAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*a, back);
    }
}

// ---------------------------------------------------------------------------
// GovernanceOutcome
// ---------------------------------------------------------------------------

#[test]
fn outcome_serde_all() {
    let outcomes = [
        GovernanceOutcome::AllClear,
        GovernanceOutcome::Downgraded,
        GovernanceOutcome::Suppressed,
        GovernanceOutcome::FullSuppression,
    ];
    for o in &outcomes {
        let json = serde_json::to_string(o).unwrap();
        let back: GovernanceOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, back);
    }
}

// ---------------------------------------------------------------------------
// GovernanceHoleEntry
// ---------------------------------------------------------------------------

#[test]
fn hole_entry_serde_roundtrip() {
    let h = hole("h1", "parser", true, false);
    let json = serde_json::to_string(&h).unwrap();
    let back: GovernanceHoleEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(h, back);
}

#[test]
fn hole_entry_hash_varies_by_surface() {
    let h1 = hole("h1", "parser", true, false);
    let h2 = hole("h1", "runtime", true, false);
    assert_ne!(h1.content_hash(), h2.content_hash());
}

// ---------------------------------------------------------------------------
// classify_severity
// ---------------------------------------------------------------------------

#[test]
fn classify_structural_always_critical() {
    let h = hole("s", "module", false, true);
    assert_eq!(
        classify_severity(&h, &cfg()),
        HoleGovernanceSeverity::Critical
    );
}

#[test]
fn classify_persistent_critical_surface() {
    let h = hole("p", "runtime", true, false);
    assert_eq!(
        classify_severity(&h, &cfg()),
        HoleGovernanceSeverity::Blocking
    );
}

#[test]
fn classify_persistent_noncritical() {
    let h = hole("p", "react", true, false);
    assert_eq!(
        classify_severity(&h, &cfg()),
        HoleGovernanceSeverity::Warning
    );
}

#[test]
fn classify_noise() {
    let h = hole("n", "parser", false, false);
    assert_eq!(
        classify_severity(&h, &cfg()),
        HoleGovernanceSeverity::Informational
    );
}

// ---------------------------------------------------------------------------
// compute_surface_coverage
// ---------------------------------------------------------------------------

#[test]
fn coverage_empty_surface() {
    let cov = compute_surface_coverage(&[]);
    assert!(cov.is_empty());
}

#[test]
fn coverage_single_noise() {
    let holes = vec![hole("n", "parser", false, false)];
    let cov = compute_surface_coverage(&holes);
    assert_eq!(*cov.get("parser").unwrap(), 1_000_000);
}

#[test]
fn coverage_mixed() {
    let holes = vec![
        hole("p1", "parser", true, false),
        hole("n1", "parser", false, false),
        hole("n2", "parser", false, false),
    ];
    let cov = compute_surface_coverage(&holes);
    // 2 of 3 non-actionable => 666666
    let parser_cov = *cov.get("parser").unwrap();
    assert!(parser_cov > 600_000 && parser_cov < 700_000);
}

#[test]
fn coverage_multiple_surfaces() {
    let holes = vec![
        hole("p1", "parser", true, false),
        hole("n1", "runtime", false, false),
    ];
    let cov = compute_surface_coverage(&holes);
    assert_eq!(*cov.get("parser").unwrap(), 0);
    assert_eq!(*cov.get("runtime").unwrap(), 1_000_000);
}

// ---------------------------------------------------------------------------
// overall_coverage
// ---------------------------------------------------------------------------

#[test]
fn overall_empty_is_full() {
    assert_eq!(overall_coverage(&BTreeMap::new()), 1_000_000);
}

#[test]
fn overall_single_surface() {
    let mut m = BTreeMap::new();
    m.insert("parser".to_string(), 800_000u64);
    assert_eq!(overall_coverage(&m), 800_000);
}

// ---------------------------------------------------------------------------
// build_boundaries
// ---------------------------------------------------------------------------

#[test]
fn boundary_fully_supported() {
    let holes = vec![hole("n", "parser", false, false)];
    let cov = compute_surface_coverage(&holes);
    let boundaries = build_boundaries(&holes, &cov, &cfg());
    assert_eq!(boundaries.len(), 1);
    assert!(boundaries[0].fully_supported);
}

#[test]
fn boundary_not_supported_persistent() {
    let holes = vec![hole("p", "parser", true, false)];
    let cov = compute_surface_coverage(&holes);
    let boundaries = build_boundaries(&holes, &cov, &cfg());
    assert!(!boundaries[0].fully_supported);
    assert_eq!(boundaries[0].persistent_holes, 1);
}

#[test]
fn boundary_structural_statement() {
    let holes = vec![hole("s", "parser", false, true)];
    let cov = compute_surface_coverage(&holes);
    let boundaries = build_boundaries(&holes, &cov, &cfg());
    assert!(boundaries[0].boundary_statement.contains("structural"));
}

// ---------------------------------------------------------------------------
// evaluate_claim
// ---------------------------------------------------------------------------

#[test]
fn claim_supremacy_allowed_clean() {
    let holes = vec![hole("n", "parser", false, false)];
    let cov = compute_surface_coverage(&holes);
    let dec = evaluate_claim(ClaimCategory::Supremacy, "parser", &holes, &cov, &cfg());
    assert_eq!(dec.action, GovernanceAction::AllowClaim);
}

#[test]
fn claim_supremacy_suppressed_structural() {
    let holes = vec![hole("s", "parser", false, true)];
    let cov = compute_surface_coverage(&holes);
    let dec = evaluate_claim(ClaimCategory::Supremacy, "parser", &holes, &cov, &cfg());
    assert_eq!(dec.action, GovernanceAction::SuppressClaim);
}

#[test]
fn claim_supremacy_downgraded_low_coverage() {
    let holes = vec![
        hole("p1", "parser", true, false),
        hole("n1", "parser", false, false),
    ];
    let cov = compute_surface_coverage(&holes);
    let dec = evaluate_claim(ClaimCategory::Supremacy, "parser", &holes, &cov, &cfg());
    // Coverage = 50% < 90% threshold
    assert!(
        dec.action == GovernanceAction::DowngradeClaim
            || dec.action == GovernanceAction::SuppressClaim
    );
}

#[test]
fn claim_experimental_tolerant() {
    let holes = vec![
        hole("p1", "react", true, false),
        hole("n1", "react", false, false),
    ];
    let cov = compute_surface_coverage(&holes);
    let dec = evaluate_claim(ClaimCategory::Experimental, "react", &holes, &cov, &cfg());
    // Experimental doesn't need high coverage
    assert!(dec.action != GovernanceAction::SuppressClaim);
}

// ---------------------------------------------------------------------------
// RatchetState
// ---------------------------------------------------------------------------

#[test]
fn ratchet_default_uninitialized() {
    let r = RatchetState::default();
    assert!(!r.initialized);
}

#[test]
fn ratchet_serde_roundtrip() {
    let mut r = RatchetState::new();
    r.surface_levels.insert("parser".into(), 800_000);
    r.initialized = true;
    r.seal();
    let json = serde_json::to_string(&r).unwrap();
    let back: RatchetState = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn ratchet_update_tracks_epoch() {
    let r = RatchetState::new();
    let mut cov = BTreeMap::new();
    cov.insert("parser".into(), 500_000u64);
    let new_r = update_ratchet(&r, &cov, ep(5), &cfg()).unwrap();
    assert_eq!(new_r.last_epoch, ep(5));
}

// ---------------------------------------------------------------------------
// Full evaluation
// ---------------------------------------------------------------------------

#[test]
fn eval_multiple_surfaces() {
    let holes = vec![
        hole("n1", "parser", false, false),
        hole("n2", "runtime", false, false),
        hole("n3", "react", false, false),
    ];
    let claims = vec![
        (ClaimCategory::Supremacy, "parser".to_string()),
        (ClaimCategory::Parity, "runtime".to_string()),
        (ClaimCategory::Experimental, "react".to_string()),
    ];
    let report = evaluate(&holes, &claims, &ratchet(), ep(1), &cfg()).unwrap();
    assert_eq!(report.outcome, GovernanceOutcome::AllClear);
    assert_eq!(report.decisions.len(), 3);
}

#[test]
fn eval_downgraded_outcome() {
    let holes = vec![
        hole("p1", "parser", true, false),
        hole("n1", "parser", false, false),
    ];
    let claims = vec![(ClaimCategory::Supremacy, "parser".to_string())];
    let report = evaluate(&holes, &claims, &ratchet(), ep(1), &cfg()).unwrap();
    assert!(
        report.outcome == GovernanceOutcome::Downgraded
            || report.outcome == GovernanceOutcome::Suppressed
    );
}

#[test]
fn eval_full_suppression() {
    let holes = vec![hole("s1", "parser", false, true)];
    let claims = vec![(ClaimCategory::Supremacy, "parser".to_string())];
    let report = evaluate(&holes, &claims, &ratchet(), ep(1), &cfg()).unwrap();
    assert_eq!(report.outcome, GovernanceOutcome::FullSuppression);
}

#[test]
fn eval_ratchet_persists() {
    let holes = vec![hole("n1", "parser", false, false)];
    let claims = vec![];
    let report = evaluate(&holes, &claims, &ratchet(), ep(1), &cfg()).unwrap();
    assert!(report.ratchet.initialized);
    assert!(report.ratchet.surface_levels.contains_key("parser"));
}

#[test]
fn eval_mandatory_experiments_structural() {
    let holes = vec![
        hole("s1", "parser", false, true),
        hole("n1", "runtime", false, false),
    ];
    let claims = vec![];
    let report = evaluate(&holes, &claims, &ratchet(), ep(1), &cfg()).unwrap();
    assert!(report.mandatory_experiments.contains(&"s1".to_string()));
    assert!(!report.mandatory_experiments.contains(&"n1".to_string()));
}

#[test]
fn eval_invalid_hole_error() {
    let holes = vec![GovernanceHoleEntry {
        hole_id: String::new(),
        surface: "parser".into(),
        is_persistent: false,
        is_structural: false,
        persistence_millionths: 0,
        has_witness: false,
        dimension: 0,
    }];
    let err = evaluate(&holes, &[], &ratchet(), ep(1), &cfg());
    assert!(err.is_err());
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[test]
fn helper_suppressed_count() {
    let holes = vec![
        hole("s1", "parser", false, true),
        hole("n1", "runtime", false, false),
    ];
    let claims = vec![
        (ClaimCategory::Supremacy, "parser".to_string()),
        (ClaimCategory::Parity, "runtime".to_string()),
    ];
    let report = evaluate(&holes, &claims, &ratchet(), ep(1), &cfg()).unwrap();
    assert_eq!(suppressed_count(&report), 1);
    assert_eq!(allowed_count(&report), 1);
}

#[test]
fn helper_blocked_surfaces() {
    let holes = vec![
        hole("p1", "parser", true, false),
        hole("n1", "runtime", false, false),
    ];
    let claims = vec![];
    let report = evaluate(&holes, &claims, &ratchet(), ep(1), &cfg()).unwrap();
    let blocked = blocked_surfaces(&report);
    assert!(blocked.contains("parser"));
    assert!(!blocked.contains("runtime"));
}

// ---------------------------------------------------------------------------
// GovernanceSummary
// ---------------------------------------------------------------------------

#[test]
fn summary_fields_match() {
    let holes = vec![
        hole("p1", "parser", true, false),
        hole("n1", "runtime", false, false),
    ];
    let claims = vec![
        (ClaimCategory::Supremacy, "parser".to_string()),
        (ClaimCategory::Parity, "runtime".to_string()),
    ];
    let report = evaluate(&holes, &claims, &ratchet(), ep(1), &cfg()).unwrap();
    let s = summarize(&report);
    assert_eq!(s.total_holes, 2);
    assert_eq!(s.actionable_holes, 1);
    assert_eq!(s.decisions_count, 2);
}

#[test]
fn summary_serde_roundtrip() {
    let holes = vec![hole("n1", "parser", false, false)];
    let claims = vec![(ClaimCategory::Parity, "parser".to_string())];
    let report = evaluate(&holes, &claims, &ratchet(), ep(1), &cfg()).unwrap();
    let s = summarize(&report);
    let json = serde_json::to_string(&s).unwrap();
    let back: GovernanceSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[test]
fn error_display_all() {
    let errors: Vec<GovernanceError> = vec![
        GovernanceError::EmptyInput,
        GovernanceError::InvalidHoleEntry("bad".into()),
        GovernanceError::RatchetRegression {
            surface: "p".into(),
            previous_millionths: 900_000,
            current_millionths: 500_000,
        },
        GovernanceError::InternalError("x".into()),
    ];
    for e in &errors {
        assert!(!format!("{e}").is_empty());
    }
}

#[test]
fn error_serde_all() {
    let errors: Vec<GovernanceError> = vec![
        GovernanceError::EmptyInput,
        GovernanceError::InvalidHoleEntry("bad".into()),
        GovernanceError::RatchetRegression {
            surface: "p".into(),
            previous_millionths: 900_000,
            current_millionths: 500_000,
        },
        GovernanceError::InternalError("x".into()),
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: GovernanceError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[test]
fn config_custom_critical_surfaces() {
    let mut c = cfg();
    c.critical_surfaces.clear();
    c.critical_surfaces.insert("react".into());
    let h = hole("p", "react", true, false);
    assert_eq!(classify_severity(&h, &c), HoleGovernanceSeverity::Blocking);
}

#[test]
fn config_relaxed_thresholds() {
    let mut c = cfg();
    c.max_persistent_holes = 100;
    c.min_supremacy_coverage_millionths = 0;
    let holes = vec![
        hole("p1", "parser", true, false),
        hole("p2", "parser", true, false),
    ];
    let cov = compute_surface_coverage(&holes);
    let dec = evaluate_claim(ClaimCategory::Supremacy, "parser", &holes, &cov, &c);
    // With relaxed thresholds and no critical surface penalty exceeding holes...
    // persistent=2 <= max_persistent=100, coverage=0 >= min=0
    // But critical_surfaces still includes parser by default in this config
    assert!(dec.action != GovernanceAction::SuppressClaim);
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

#[test]
fn report_hash_deterministic() {
    let holes = vec![hole("n", "parser", false, false)];
    let claims = vec![(ClaimCategory::Parity, "parser".to_string())];
    let r1 = evaluate(&holes, &claims, &ratchet(), ep(1), &cfg()).unwrap();
    let r2 = evaluate(&holes, &claims, &ratchet(), ep(1), &cfg()).unwrap();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_serde_roundtrip() {
    let holes = vec![
        hole("p1", "parser", true, false),
        hole("n1", "runtime", false, false),
    ];
    let claims = vec![
        (ClaimCategory::Supremacy, "parser".to_string()),
        (ClaimCategory::Parity, "runtime".to_string()),
    ];
    let report = evaluate(&holes, &claims, &ratchet(), ep(1), &cfg()).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: GovernanceReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

#[test]
fn decision_is_allowed_vs_suppressed() {
    let holes = vec![
        hole("n", "parser", false, false),
        hole("s", "runtime", false, true),
    ];
    let cov = compute_surface_coverage(&holes);
    let d1 = evaluate_claim(ClaimCategory::Parity, "parser", &holes, &cov, &cfg());
    let d2 = evaluate_claim(ClaimCategory::Supremacy, "runtime", &holes, &cov, &cfg());
    assert!(d1.is_allowed());
    assert!(d2.is_suppressed());
}

// ---------------------------------------------------------------------------
// SupportBoundary
// ---------------------------------------------------------------------------

#[test]
fn boundary_serde_roundtrip() {
    let b = SupportBoundary {
        surface: "parser".into(),
        fully_supported: false,
        coverage_millionths: 500_000,
        persistent_holes: 2,
        structural_holes: 0,
        blocking_hole_ids: vec!["h1".into(), "h2".into()],
        boundary_statement: "parser: 2 persistent holes".into(),
    };
    let json = serde_json::to_string(&b).unwrap();
    let back: SupportBoundary = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

// ---------------------------------------------------------------------------
// Large scale
// ---------------------------------------------------------------------------

#[test]
fn many_holes_many_surfaces() {
    let mut holes = Vec::new();
    for i in 0..20 {
        let surface = match i % 4 {
            0 => "parser",
            1 => "runtime",
            2 => "react",
            _ => "module",
        };
        let persistent = i % 3 == 0;
        holes.push(hole(&format!("h{i}"), surface, persistent, false));
    }
    let claims = vec![
        (ClaimCategory::Supremacy, "parser".to_string()),
        (ClaimCategory::Parity, "runtime".to_string()),
        (ClaimCategory::Experimental, "react".to_string()),
    ];
    let report = evaluate(&holes, &claims, &ratchet(), ep(1), &cfg()).unwrap();
    assert_eq!(report.total_holes, 20);
    assert!(report.boundaries.len() >= 4);
}
