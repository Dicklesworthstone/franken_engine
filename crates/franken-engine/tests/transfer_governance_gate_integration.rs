#![forbid(unsafe_code)]

//! Integration tests for `transfer_governance_gate` (RGC-612C, bd-1lsy.7.12.3).

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::transfer_governance_gate::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn ev(dom: TransferDomain, fid: u64, drift: u64, n: u64) -> TransferEvidence {
    TransferEvidence::new(dom, "src_wl", "tgt_wl", fid, drift, n, ep(10))
}

fn ev_named(
    dom: TransferDomain,
    src: &str,
    tgt: &str,
    fid: u64,
    drift: u64,
    n: u64,
) -> TransferEvidence {
    TransferEvidence::new(dom, src, tgt, fid, drift, n, ep(10))
}

fn cov(dom: TransferDomain, reg: &str, lvl: CoverageLevel) -> CoverageRecord {
    CoverageRecord::new(dom, reg, lvl, ContentHash::compute(b"cov"), ep(5))
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_contains_module_name() {
    assert!(SCHEMA_VERSION.contains("transfer-governance-gate"));
    assert!(SCHEMA_VERSION.contains("v1"));
}

#[test]
fn test_component_name() {
    assert_eq!(COMPONENT, "transfer_governance_gate");
}

#[test]
fn test_bead_id() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.12.3");
}

#[test]
fn test_policy_id() {
    assert_eq!(POLICY_ID, "RGC-612C");
}

#[test]
fn test_default_thresholds_ordering() {
    assert!(DEFAULT_HIGH_FIDELITY_THRESHOLD > DEFAULT_MODERATE_FIDELITY_THRESHOLD);
    assert!(DEFAULT_MODERATE_FIDELITY_THRESHOLD > DEFAULT_DRIFT_ALARM_THRESHOLD);
}

#[test]
fn test_default_min_sample_count() {
    assert_eq!(DEFAULT_MIN_SAMPLE_COUNT, 30);
}

#[test]
fn test_default_min_coverage_fraction() {
    assert_eq!(DEFAULT_MIN_COVERAGE_FRACTION, 800_000);
}

#[test]
fn test_default_max_batch_size() {
    assert_eq!(DEFAULT_MAX_BATCH_SIZE, 512);
}

// ---------------------------------------------------------------------------
// TransferDomain
// ---------------------------------------------------------------------------

#[test]
fn test_domain_all_variants_count() {
    assert_eq!(TransferDomain::ALL.len(), 6);
}

#[test]
fn test_domain_display_all() {
    let expected = [
        "rewrite_prior",
        "tiering_policy",
        "cache_policy",
        "scheduling_heuristic",
        "inlining_decision",
        "specialization_strategy",
    ];
    for (dom, exp) in TransferDomain::ALL.iter().zip(expected.iter()) {
        assert_eq!(dom.to_string(), *exp);
    }
}

#[test]
fn test_domain_serde_roundtrip_all() {
    for d in TransferDomain::ALL {
        let json = serde_json::to_string(d).unwrap();
        let back: TransferDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

#[test]
fn test_domain_as_str_matches_display() {
    for d in TransferDomain::ALL {
        assert_eq!(d.as_str(), d.to_string());
    }
}

// ---------------------------------------------------------------------------
// TransferVerdict
// ---------------------------------------------------------------------------

#[test]
fn test_verdict_display_all() {
    assert_eq!(TransferVerdict::Validated.to_string(), "validated");
    assert_eq!(TransferVerdict::ConditionallyValid.to_string(), "conditionally_valid");
    assert_eq!(TransferVerdict::DriftDetected.to_string(), "drift_detected");
    assert_eq!(TransferVerdict::Rejected.to_string(), "rejected");
    assert_eq!(TransferVerdict::InsufficientEvidence.to_string(), "insufficient_evidence");
}

#[test]
fn test_verdict_serde_roundtrip_all() {
    let all = [
        TransferVerdict::Validated,
        TransferVerdict::ConditionallyValid,
        TransferVerdict::DriftDetected,
        TransferVerdict::Rejected,
        TransferVerdict::InsufficientEvidence,
    ];
    for v in &all {
        let json = serde_json::to_string(v).unwrap();
        let back: TransferVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn test_verdict_allows_unconditional_rollout() {
    assert!(TransferVerdict::Validated.allows_unconditional_rollout());
    assert!(!TransferVerdict::ConditionallyValid.allows_unconditional_rollout());
    assert!(!TransferVerdict::DriftDetected.allows_unconditional_rollout());
    assert!(!TransferVerdict::Rejected.allows_unconditional_rollout());
    assert!(!TransferVerdict::InsufficientEvidence.allows_unconditional_rollout());
}

// ---------------------------------------------------------------------------
// CoverageLevel
// ---------------------------------------------------------------------------

#[test]
fn test_coverage_level_display_all() {
    assert_eq!(CoverageLevel::Full.to_string(), "full");
    assert_eq!(CoverageLevel::Partial.to_string(), "partial");
    assert_eq!(CoverageLevel::Sparse.to_string(), "sparse");
    assert_eq!(CoverageLevel::Uncovered.to_string(), "uncovered");
}

#[test]
fn test_coverage_level_serde_roundtrip() {
    let all = [CoverageLevel::Full, CoverageLevel::Partial, CoverageLevel::Sparse, CoverageLevel::Uncovered];
    for lvl in &all {
        let json = serde_json::to_string(lvl).unwrap();
        let back: CoverageLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(*lvl, back);
    }
}

#[test]
fn test_coverage_sufficient_for_rollout() {
    assert!(CoverageLevel::Full.sufficient_for_rollout());
    assert!(CoverageLevel::Partial.sufficient_for_rollout());
    assert!(!CoverageLevel::Sparse.sufficient_for_rollout());
    assert!(!CoverageLevel::Uncovered.sufficient_for_rollout());
}

// ---------------------------------------------------------------------------
// GovernanceAction
// ---------------------------------------------------------------------------

#[test]
fn test_action_display_all() {
    assert_eq!(GovernanceAction::AllowRollout.to_string(), "allow_rollout");
    assert_eq!(GovernanceAction::ConditionalRollout.to_string(), "conditional_rollout");
    assert_eq!(GovernanceAction::BlockRollout.to_string(), "block_rollout");
    assert_eq!(GovernanceAction::RequireFreshEvidence.to_string(), "require_fresh_evidence");
    assert_eq!(GovernanceAction::DowngradeSupremacy.to_string(), "downgrade_supremacy");
}

#[test]
fn test_action_serde_roundtrip() {
    let all = [
        GovernanceAction::AllowRollout,
        GovernanceAction::ConditionalRollout,
        GovernanceAction::BlockRollout,
        GovernanceAction::RequireFreshEvidence,
        GovernanceAction::DowngradeSupremacy,
    ];
    for a in &all {
        let json = serde_json::to_string(a).unwrap();
        let back: GovernanceAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*a, back);
    }
}

// ---------------------------------------------------------------------------
// TransferEvidence
// ---------------------------------------------------------------------------

#[test]
fn test_evidence_creation_fields() {
    let e = ev(TransferDomain::CachePolicy, 950_000, 10_000, 100);
    assert_eq!(e.domain, TransferDomain::CachePolicy);
    assert_eq!(e.source_workload_id, "src_wl");
    assert_eq!(e.target_workload_id, "tgt_wl");
    assert_eq!(e.transfer_fidelity, 950_000);
    assert_eq!(e.drift_magnitude, 10_000);
    assert_eq!(e.sample_count, 100);
    assert_eq!(e.epoch.as_u64(), 10);
}

#[test]
fn test_evidence_hash_deterministic() {
    let a = ev(TransferDomain::RewritePrior, 900_000, 50_000, 50);
    let b = ev(TransferDomain::RewritePrior, 900_000, 50_000, 50);
    assert_eq!(a.evidence_hash, b.evidence_hash);
}

#[test]
fn test_evidence_hash_differs_on_domain() {
    let a = ev(TransferDomain::RewritePrior, 900_000, 50_000, 50);
    let b = ev(TransferDomain::CachePolicy, 900_000, 50_000, 50);
    assert_ne!(a.evidence_hash, b.evidence_hash);
}

#[test]
fn test_evidence_hash_differs_on_fidelity() {
    let a = ev(TransferDomain::RewritePrior, 900_000, 50_000, 50);
    let b = ev(TransferDomain::RewritePrior, 900_001, 50_000, 50);
    assert_ne!(a.evidence_hash, b.evidence_hash);
}

#[test]
fn test_evidence_hash_differs_on_workload() {
    let a = ev_named(TransferDomain::RewritePrior, "wl_a", "wl_b", 900_000, 0, 50);
    let b = ev_named(TransferDomain::RewritePrior, "wl_x", "wl_b", 900_000, 0, 50);
    assert_ne!(a.evidence_hash, b.evidence_hash);
}

#[test]
fn test_evidence_display_contains_domain() {
    let e = ev(TransferDomain::TieringPolicy, 800_000, 20_000, 40);
    let s = e.to_string();
    assert!(s.contains("tiering_policy"));
    assert!(s.contains("src_wl"));
    assert!(s.contains("tgt_wl"));
}

#[test]
fn test_evidence_serde_roundtrip() {
    let e = ev(TransferDomain::InliningDecision, 750_000, 100_000, 60);
    let json = serde_json::to_string(&e).unwrap();
    let back: TransferEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// CoverageRecord
// ---------------------------------------------------------------------------

#[test]
fn test_coverage_record_fields() {
    let r = cov(TransferDomain::CachePolicy, "region_a", CoverageLevel::Full);
    assert_eq!(r.domain, TransferDomain::CachePolicy);
    assert_eq!(r.region_id, "region_a");
    assert_eq!(r.coverage_level, CoverageLevel::Full);
    assert_eq!(r.last_validated_epoch.as_u64(), 5);
}

#[test]
fn test_coverage_record_hash_deterministic() {
    let a = cov(TransferDomain::RewritePrior, "r1", CoverageLevel::Full);
    let b = cov(TransferDomain::RewritePrior, "r1", CoverageLevel::Full);
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn test_coverage_record_hash_differs_on_level() {
    let a = cov(TransferDomain::RewritePrior, "r1", CoverageLevel::Full);
    let b = cov(TransferDomain::RewritePrior, "r1", CoverageLevel::Sparse);
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn test_coverage_record_hash_differs_on_region() {
    let a = cov(TransferDomain::RewritePrior, "r1", CoverageLevel::Full);
    let b = cov(TransferDomain::RewritePrior, "r2", CoverageLevel::Full);
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn test_coverage_record_display() {
    let r = cov(TransferDomain::TieringPolicy, "zone_z", CoverageLevel::Partial);
    let s = r.to_string();
    assert!(s.contains("Coverage"));
    assert!(s.contains("zone_z"));
    assert!(s.contains("partial"));
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

#[test]
fn test_config_default_values() {
    let c = GateConfig::default();
    assert_eq!(c.min_transfer_fidelity_high, DEFAULT_HIGH_FIDELITY_THRESHOLD);
    assert_eq!(c.min_transfer_fidelity_moderate, DEFAULT_MODERATE_FIDELITY_THRESHOLD);
    assert_eq!(c.drift_alarm_threshold, DEFAULT_DRIFT_ALARM_THRESHOLD);
    assert_eq!(c.min_sample_count, DEFAULT_MIN_SAMPLE_COUNT);
    assert_eq!(c.min_coverage_fraction, DEFAULT_MIN_COVERAGE_FRACTION);
    assert_eq!(c.max_batch_size, DEFAULT_MAX_BATCH_SIZE);
}

#[test]
fn test_config_custom() {
    let c = GateConfig {
        min_transfer_fidelity_high: 800_000,
        min_transfer_fidelity_moderate: 600_000,
        drift_alarm_threshold: 300_000,
        min_sample_count: 10,
        min_coverage_fraction: 500_000,
        max_batch_size: 100,
    };
    // With relaxed thresholds, 750k fidelity should be conditionally valid.
    let verdict = evaluate_transfer(
        &ev(TransferDomain::CachePolicy, 750_000, 100_000, 20),
        &c,
    );
    assert_eq!(verdict, TransferVerdict::ConditionallyValid);
}

#[test]
fn test_config_serde_roundtrip() {
    let c = GateConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn test_config_display() {
    let s = GateConfig::default().to_string();
    assert!(s.contains("GateConfig"));
    assert!(s.contains("900000"));
}

// ---------------------------------------------------------------------------
// evaluate_transfer — all verdict paths
// ---------------------------------------------------------------------------

#[test]
fn test_eval_validated_high_fidelity_low_drift() {
    let c = GateConfig::default();
    let verdict = evaluate_transfer(
        &ev(TransferDomain::RewritePrior, 950_000, 50_000, 100),
        &c,
    );
    assert_eq!(verdict, TransferVerdict::Validated);
}

#[test]
fn test_eval_conditionally_valid() {
    let c = GateConfig::default();
    let verdict = evaluate_transfer(
        &ev(TransferDomain::CachePolicy, 750_000, 100_000, 50),
        &c,
    );
    assert_eq!(verdict, TransferVerdict::ConditionallyValid);
}

#[test]
fn test_eval_rejected_low_fidelity() {
    let c = GateConfig::default();
    let verdict = evaluate_transfer(
        &ev(TransferDomain::SchedulingHeuristic, 500_000, 100_000, 50),
        &c,
    );
    assert_eq!(verdict, TransferVerdict::Rejected);
}

#[test]
fn test_eval_drift_detected() {
    let c = GateConfig::default();
    let verdict = evaluate_transfer(
        &ev(TransferDomain::RewritePrior, 990_000, 500_000, 100),
        &c,
    );
    assert_eq!(verdict, TransferVerdict::DriftDetected);
}

#[test]
fn test_eval_insufficient_evidence() {
    let c = GateConfig::default();
    let verdict = evaluate_transfer(
        &ev(TransferDomain::InliningDecision, 950_000, 0, 5),
        &c,
    );
    assert_eq!(verdict, TransferVerdict::InsufficientEvidence);
}

#[test]
fn test_eval_insufficient_trumps_drift() {
    // Insufficient samples checked before drift.
    let c = GateConfig::default();
    let verdict = evaluate_transfer(
        &ev(TransferDomain::CachePolicy, 1_000_000, 500_000, 1),
        &c,
    );
    assert_eq!(verdict, TransferVerdict::InsufficientEvidence);
}

#[test]
fn test_eval_boundary_fidelity_at_high() {
    let c = GateConfig::default();
    let verdict = evaluate_transfer(
        &ev(TransferDomain::RewritePrior, 900_000, 100_000, 50),
        &c,
    );
    assert_eq!(verdict, TransferVerdict::Validated);
}

#[test]
fn test_eval_boundary_fidelity_just_below_high() {
    let c = GateConfig::default();
    let verdict = evaluate_transfer(
        &ev(TransferDomain::RewritePrior, 899_999, 100_000, 50),
        &c,
    );
    assert_eq!(verdict, TransferVerdict::ConditionallyValid);
}

#[test]
fn test_eval_boundary_fidelity_at_moderate() {
    let c = GateConfig::default();
    let verdict = evaluate_transfer(
        &ev(TransferDomain::RewritePrior, 700_000, 100_000, 50),
        &c,
    );
    assert_eq!(verdict, TransferVerdict::ConditionallyValid);
}

#[test]
fn test_eval_boundary_fidelity_just_below_moderate() {
    let c = GateConfig::default();
    let verdict = evaluate_transfer(
        &ev(TransferDomain::RewritePrior, 699_999, 100_000, 50),
        &c,
    );
    assert_eq!(verdict, TransferVerdict::Rejected);
}

#[test]
fn test_eval_boundary_drift_at_threshold() {
    // Drift exactly at threshold is NOT over, so no DriftDetected.
    let c = GateConfig::default();
    let verdict = evaluate_transfer(
        &ev(TransferDomain::RewritePrior, 950_000, 200_000, 50),
        &c,
    );
    assert_eq!(verdict, TransferVerdict::Validated);
}

#[test]
fn test_eval_boundary_drift_just_over() {
    let c = GateConfig::default();
    let verdict = evaluate_transfer(
        &ev(TransferDomain::RewritePrior, 950_000, 200_001, 50),
        &c,
    );
    assert_eq!(verdict, TransferVerdict::DriftDetected);
}

#[test]
fn test_eval_boundary_samples_at_min() {
    let c = GateConfig::default();
    let verdict = evaluate_transfer(
        &ev(TransferDomain::RewritePrior, 950_000, 50_000, 30),
        &c,
    );
    assert_eq!(verdict, TransferVerdict::Validated);
}

#[test]
fn test_eval_boundary_samples_below_min() {
    let c = GateConfig::default();
    let verdict = evaluate_transfer(
        &ev(TransferDomain::RewritePrior, 950_000, 50_000, 29),
        &c,
    );
    assert_eq!(verdict, TransferVerdict::InsufficientEvidence);
}

// ---------------------------------------------------------------------------
// evaluate_coverage
// ---------------------------------------------------------------------------

#[test]
fn test_coverage_empty_is_uncovered() {
    assert_eq!(evaluate_coverage(&[], &GateConfig::default()), CoverageLevel::Uncovered);
}

#[test]
fn test_coverage_all_full_records() {
    let recs: Vec<_> = (0..5)
        .map(|i| cov(TransferDomain::RewritePrior, &format!("r{i}"), CoverageLevel::Full))
        .collect();
    assert_eq!(evaluate_coverage(&recs, &GateConfig::default()), CoverageLevel::Full);
}

#[test]
fn test_coverage_mixed_produces_partial() {
    // 3/4 Full/Partial = 750_000 -> Partial (below 800k min_coverage_fraction).
    let recs = vec![
        cov(TransferDomain::RewritePrior, "a", CoverageLevel::Full),
        cov(TransferDomain::CachePolicy, "b", CoverageLevel::Sparse),
        cov(TransferDomain::TieringPolicy, "c", CoverageLevel::Full),
        cov(TransferDomain::InliningDecision, "d", CoverageLevel::Full),
    ];
    assert_eq!(evaluate_coverage(&recs, &GateConfig::default()), CoverageLevel::Partial);
}

#[test]
fn test_coverage_all_sparse_is_uncovered() {
    // All Sparse -> 0 passing -> fraction = 0 -> Uncovered.
    let recs = vec![
        cov(TransferDomain::RewritePrior, "a", CoverageLevel::Sparse),
        cov(TransferDomain::CachePolicy, "b", CoverageLevel::Sparse),
    ];
    assert_eq!(evaluate_coverage(&recs, &GateConfig::default()), CoverageLevel::Uncovered);
}

#[test]
fn test_coverage_partial_records_count_as_sufficient() {
    // Partial coverage level is sufficient_for_rollout.
    let recs: Vec<_> = (0..10)
        .map(|i| cov(TransferDomain::CachePolicy, &format!("r{i}"), CoverageLevel::Partial))
        .collect();
    assert_eq!(evaluate_coverage(&recs, &GateConfig::default()), CoverageLevel::Full);
}

// ---------------------------------------------------------------------------
// GovernanceDecision
// ---------------------------------------------------------------------------

#[test]
fn test_decision_creation() {
    let h = ContentHash::compute(b"evidence_data");
    let d = GovernanceDecision::new(GovernanceAction::AllowRollout, vec![h], "validated ok", ep(10));
    assert_eq!(d.action, GovernanceAction::AllowRollout);
    assert_eq!(d.evidence_hashes.len(), 1);
    assert_eq!(d.explanation, "validated ok");
    assert_eq!(d.epoch.as_u64(), 10);
}

#[test]
fn test_decision_hash_deterministic() {
    let h = ContentHash::compute(b"ev_data");
    let a = GovernanceDecision::new(GovernanceAction::BlockRollout, vec![h], "reason", ep(5));
    let b = GovernanceDecision::new(GovernanceAction::BlockRollout, vec![h], "reason", ep(5));
    assert_eq!(a.receipt_hash, b.receipt_hash);
}

#[test]
fn test_decision_hash_differs_on_action() {
    let h = ContentHash::compute(b"ev_data");
    let a = GovernanceDecision::new(GovernanceAction::AllowRollout, vec![h], "x", ep(1));
    let b = GovernanceDecision::new(GovernanceAction::BlockRollout, vec![h], "x", ep(1));
    assert_ne!(a.receipt_hash, b.receipt_hash);
}

#[test]
fn test_decision_display() {
    let d = GovernanceDecision::new(GovernanceAction::ConditionalRollout, vec![], "c", ep(7));
    let s = d.to_string();
    assert!(s.contains("conditional_rollout"));
    assert!(s.contains("epoch=7"));
}

// ---------------------------------------------------------------------------
// RolloutGateResult constructors
// ---------------------------------------------------------------------------

#[test]
fn test_rollout_result_allowed() {
    let r = RolloutGateResult::allowed(CoverageLevel::Full);
    assert!(r.allowed);
    assert!(r.conditions.is_empty());
    assert!(r.blocking_reasons.is_empty());
    assert_eq!(r.coverage_summary, CoverageLevel::Full);
}

#[test]
fn test_rollout_result_blocked() {
    let r = RolloutGateResult::blocked(vec!["reason_1".into()], CoverageLevel::Sparse);
    assert!(!r.allowed);
    assert_eq!(r.blocking_reasons.len(), 1);
    assert!(r.conditions.is_empty());
}

#[test]
fn test_rollout_result_conditional() {
    let r = RolloutGateResult::conditional(vec!["canary_only".into()], CoverageLevel::Partial);
    assert!(r.allowed);
    assert_eq!(r.conditions.len(), 1);
    assert!(r.blocking_reasons.is_empty());
}

#[test]
fn test_rollout_display_allowed() {
    let s = RolloutGateResult::allowed(CoverageLevel::Full).to_string();
    assert!(s.contains("ALLOWED"));
}

#[test]
fn test_rollout_display_blocked() {
    let s = RolloutGateResult::blocked(vec!["x".into()], CoverageLevel::Uncovered).to_string();
    assert!(s.contains("BLOCKED"));
}

#[test]
fn test_rollout_display_conditional() {
    let s = RolloutGateResult::conditional(vec!["c".into()], CoverageLevel::Partial).to_string();
    assert!(s.contains("CONDITIONAL"));
}

// ---------------------------------------------------------------------------
// evaluate_rollout
// ---------------------------------------------------------------------------

#[test]
fn test_rollout_empty_input_blocked() {
    let r = evaluate_rollout(&[], &GateConfig::default());
    assert!(!r.allowed);
    assert!(!r.blocking_reasons.is_empty());
    assert_eq!(r.coverage_summary, CoverageLevel::Uncovered);
}

#[test]
fn test_rollout_all_validated() {
    let evs = vec![
        ev(TransferDomain::RewritePrior, 950_000, 50_000, 100),
        ev(TransferDomain::CachePolicy, 920_000, 30_000, 80),
    ];
    let r = evaluate_rollout(&evs, &GateConfig::default());
    assert!(r.allowed);
    assert!(r.conditions.is_empty());
    assert_eq!(r.coverage_summary, CoverageLevel::Full);
}

#[test]
fn test_rollout_with_drift_blocks() {
    let evs = vec![
        ev(TransferDomain::RewritePrior, 950_000, 50_000, 100),
        ev(TransferDomain::CachePolicy, 920_000, 400_000, 80),
    ];
    let r = evaluate_rollout(&evs, &GateConfig::default());
    assert!(!r.allowed);
}

#[test]
fn test_rollout_conditional_path() {
    let evs = vec![
        ev(TransferDomain::RewritePrior, 750_000, 50_000, 100),
        ev(TransferDomain::CachePolicy, 800_000, 100_000, 80),
    ];
    let r = evaluate_rollout(&evs, &GateConfig::default());
    assert!(r.allowed);
    assert!(!r.conditions.is_empty());
}

#[test]
fn test_rollout_single_rejected_blocks() {
    let evs = vec![
        ev(TransferDomain::RewritePrior, 950_000, 50_000, 100),
        ev(TransferDomain::CachePolicy, 400_000, 50_000, 80),
    ];
    let r = evaluate_rollout(&evs, &GateConfig::default());
    assert!(!r.allowed);
}

#[test]
fn test_rollout_insufficient_blocks() {
    let evs = vec![ev(TransferDomain::RewritePrior, 950_000, 0, 5)];
    let r = evaluate_rollout(&evs, &GateConfig::default());
    assert!(!r.allowed);
}

// ---------------------------------------------------------------------------
// SupremacyConstraint
// ---------------------------------------------------------------------------

#[test]
fn test_supremacy_constraint_fields() {
    let sc = SupremacyConstraint::new("claim_42", "coverage_gap", 600_000, "missing regions");
    assert_eq!(sc.claim_id, "claim_42");
    assert_eq!(sc.constraint_kind, "coverage_gap");
    assert_eq!(sc.severity, 600_000);
    assert_eq!(sc.explanation, "missing regions");
}

#[test]
fn test_supremacy_not_critical_below_800k() {
    let sc = SupremacyConstraint::new("c1", "drift", 799_999, "drift detected");
    assert!(!sc.is_critical());
}

#[test]
fn test_supremacy_critical_at_800k() {
    let sc = SupremacyConstraint::new("c2", "gap", 800_000, "gap found");
    assert!(sc.is_critical());
}

#[test]
fn test_supremacy_critical_above_800k() {
    let sc = SupremacyConstraint::new("c3", "gap", 900_000, "severe gap");
    assert!(sc.is_critical());
}

#[test]
fn test_supremacy_hash_deterministic() {
    let a = SupremacyConstraint::new("c", "k", 500_000, "explanation");
    let b = SupremacyConstraint::new("c", "k", 500_000, "explanation");
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn test_supremacy_hash_differs_on_claim() {
    let a = SupremacyConstraint::new("c1", "k", 500_000, "e");
    let b = SupremacyConstraint::new("c2", "k", 500_000, "e");
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn test_supremacy_display() {
    let s = SupremacyConstraint::new("claim_x", "drift_detected", 700_000, "x").to_string();
    assert!(s.contains("claim_x"));
    assert!(s.contains("drift_detected"));
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_creation_fields() {
    let h = ContentHash::compute(b"evidence");
    let r = DecisionReceipt::new(ep(15), GovernanceAction::AllowRollout, h);
    assert_eq!(r.component, COMPONENT);
    assert_eq!(r.epoch.as_u64(), 15);
    assert_eq!(r.action, GovernanceAction::AllowRollout);
    assert_eq!(r.evidence_hash, h);
}

#[test]
fn test_receipt_hash_deterministic() {
    let h = ContentHash::compute(b"ev");
    let a = DecisionReceipt::new(ep(10), GovernanceAction::BlockRollout, h);
    let b = DecisionReceipt::new(ep(10), GovernanceAction::BlockRollout, h);
    assert_eq!(a.receipt_hash, b.receipt_hash);
}

#[test]
fn test_receipt_hash_differs_on_action() {
    let h = ContentHash::compute(b"ev");
    let a = DecisionReceipt::new(ep(10), GovernanceAction::AllowRollout, h);
    let b = DecisionReceipt::new(ep(10), GovernanceAction::BlockRollout, h);
    assert_ne!(a.receipt_hash, b.receipt_hash);
}

#[test]
fn test_receipt_hash_differs_on_epoch() {
    let h = ContentHash::compute(b"ev");
    let a = DecisionReceipt::new(ep(10), GovernanceAction::AllowRollout, h);
    let b = DecisionReceipt::new(ep(11), GovernanceAction::AllowRollout, h);
    assert_ne!(a.receipt_hash, b.receipt_hash);
}

#[test]
fn test_receipt_hash_differs_on_evidence() {
    let h1 = ContentHash::compute(b"ev1");
    let h2 = ContentHash::compute(b"ev2");
    let a = DecisionReceipt::new(ep(10), GovernanceAction::AllowRollout, h1);
    let b = DecisionReceipt::new(ep(10), GovernanceAction::AllowRollout, h2);
    assert_ne!(a.receipt_hash, b.receipt_hash);
}

#[test]
fn test_receipt_display() {
    let h = ContentHash::compute(b"ev");
    let s = DecisionReceipt::new(ep(20), GovernanceAction::RequireFreshEvidence, h).to_string();
    assert!(s.contains("require_fresh_evidence"));
    assert!(s.contains("epoch=20"));
}

// ---------------------------------------------------------------------------
// evaluate_batch
// ---------------------------------------------------------------------------

#[test]
fn test_batch_mixed_verdicts() {
    let c = GateConfig::default();
    let evs = vec![
        ev(TransferDomain::RewritePrior, 950_000, 50_000, 100),       // Validated
        ev(TransferDomain::CachePolicy, 750_000, 100_000, 50),        // ConditionallyValid
        ev(TransferDomain::TieringPolicy, 950_000, 400_000, 60),      // DriftDetected
        ev(TransferDomain::SchedulingHeuristic, 300_000, 50_000, 40), // Rejected
        ev(TransferDomain::InliningDecision, 950_000, 0, 5),          // InsufficientEvidence
    ];
    let (decs, sum) = evaluate_batch(&evs, &c);
    assert_eq!(decs.len(), 5);
    assert_eq!(sum.validated, 1);
    assert_eq!(sum.conditionally_valid, 1);
    assert_eq!(sum.drift_detected, 1);
    assert_eq!(sum.rejected, 1);
    assert_eq!(sum.insufficient, 1);
    assert_eq!(sum.total_transfers, 5);
}

#[test]
fn test_batch_all_validated() {
    let evs = vec![
        ev(TransferDomain::RewritePrior, 950_000, 50_000, 100),
        ev(TransferDomain::CachePolicy, 920_000, 30_000, 80),
    ];
    let (decs, sum) = evaluate_batch(&evs, &GateConfig::default());
    assert_eq!(decs.len(), 2);
    assert_eq!(sum.validated, 2);
    assert_eq!(sum.coverage_fraction, 1_000_000);
}

#[test]
fn test_batch_truncated_by_max_size() {
    let c = GateConfig {
        max_batch_size: 2,
        ..GateConfig::default()
    };
    let evs = vec![
        ev(TransferDomain::RewritePrior, 950_000, 50_000, 100),
        ev(TransferDomain::CachePolicy, 920_000, 30_000, 80),
        ev(TransferDomain::TieringPolicy, 910_000, 40_000, 90),
    ];
    let (decs, sum) = evaluate_batch(&evs, &c);
    assert_eq!(decs.len(), 2);
    assert_eq!(sum.total_transfers, 2);
}

#[test]
fn test_batch_empty_input() {
    let (decs, sum) = evaluate_batch(&[], &GateConfig::default());
    assert!(decs.is_empty());
    assert_eq!(sum.total_transfers, 0);
    assert_eq!(sum.coverage_fraction, 0);
}

#[test]
fn test_batch_decision_actions_match_verdicts() {
    let c = GateConfig::default();
    let evs = vec![
        ev(TransferDomain::RewritePrior, 950_000, 50_000, 100),  // Validated -> AllowRollout
        ev(TransferDomain::CachePolicy, 750_000, 100_000, 50),   // Conditional -> ConditionalRollout
        ev(TransferDomain::TieringPolicy, 300_000, 50_000, 50),  // Rejected -> BlockRollout
        ev(TransferDomain::InliningDecision, 950_000, 500_000, 50), // Drift -> DowngradeSupremacy
        ev(TransferDomain::SchedulingHeuristic, 950_000, 0, 5),  // Insufficient -> RequireFreshEvidence
    ];
    let (decs, _) = evaluate_batch(&evs, &c);
    assert_eq!(decs[0].action, GovernanceAction::AllowRollout);
    assert_eq!(decs[1].action, GovernanceAction::ConditionalRollout);
    assert_eq!(decs[2].action, GovernanceAction::BlockRollout);
    assert_eq!(decs[3].action, GovernanceAction::DowngradeSupremacy);
    assert_eq!(decs[4].action, GovernanceAction::RequireFreshEvidence);
}

#[test]
fn test_batch_decisions_carry_evidence_hashes() {
    let evs = vec![ev(TransferDomain::RewritePrior, 950_000, 50_000, 100)];
    let (decs, _) = evaluate_batch(&evs, &GateConfig::default());
    assert_eq!(decs[0].evidence_hashes.len(), 1);
    assert_eq!(decs[0].evidence_hashes[0], evs[0].evidence_hash);
}

// ---------------------------------------------------------------------------
// GovernanceSummary
// ---------------------------------------------------------------------------

#[test]
fn test_summary_from_counts_total() {
    let s = GovernanceSummary::from_counts(3, 2, 1, 1, 1);
    assert_eq!(s.total_transfers, 8);
}

#[test]
fn test_summary_coverage_fraction() {
    // 2 validated + 2 conditional out of 5 total = 4/5 = 800_000.
    let s = GovernanceSummary::from_counts(2, 2, 1, 0, 0);
    assert_eq!(s.coverage_fraction, 800_000);
}

#[test]
fn test_summary_pass_rate() {
    // pass_rate = validated / total => 3/5 = 600_000.
    let s = GovernanceSummary::from_counts(3, 1, 1, 0, 0);
    assert_eq!(s.pass_rate(), 600_000);
}

#[test]
fn test_summary_empty_counts() {
    let s = GovernanceSummary::from_counts(0, 0, 0, 0, 0);
    assert_eq!(s.total_transfers, 0);
    assert_eq!(s.pass_rate(), 0);
    assert_eq!(s.coverage_fraction, 0);
}

#[test]
fn test_summary_all_validated() {
    let s = GovernanceSummary::from_counts(10, 0, 0, 0, 0);
    assert_eq!(s.coverage_fraction, 1_000_000);
    assert_eq!(s.pass_rate(), 1_000_000);
}

#[test]
fn test_summary_display() {
    let s = GovernanceSummary::from_counts(5, 2, 1, 1, 1).to_string();
    assert!(s.contains("GovernanceSummary"));
    assert!(s.contains("total=10"));
}

// ---------------------------------------------------------------------------
// Edge cases and cross-cutting
// ---------------------------------------------------------------------------

#[test]
fn test_evidence_zero_fidelity() {
    let e = ev(TransferDomain::RewritePrior, 0, 0, 100);
    let verdict = evaluate_transfer(&e, &GateConfig::default());
    assert_eq!(verdict, TransferVerdict::Rejected);
}

#[test]
fn test_evidence_max_fidelity() {
    let e = ev(TransferDomain::RewritePrior, 1_000_000, 0, 100);
    let verdict = evaluate_transfer(&e, &GateConfig::default());
    assert_eq!(verdict, TransferVerdict::Validated);
}

#[test]
fn test_evidence_zero_drift_zero_samples() {
    let e = ev(TransferDomain::RewritePrior, 1_000_000, 0, 0);
    let verdict = evaluate_transfer(&e, &GateConfig::default());
    assert_eq!(verdict, TransferVerdict::InsufficientEvidence);
}

#[test]
fn test_rollout_single_validated() {
    let evs = vec![ev(TransferDomain::SpecializationStrategy, 950_000, 0, 100)];
    let r = evaluate_rollout(&evs, &GateConfig::default());
    assert!(r.allowed);
    assert!(r.conditions.is_empty());
}

#[test]
fn test_rollout_conditions_preserved_in_blocked() {
    // One conditional + one rejected => blocked, but conditions still tracked.
    let evs = vec![
        ev(TransferDomain::RewritePrior, 750_000, 50_000, 100),
        ev(TransferDomain::CachePolicy, 400_000, 50_000, 80),
    ];
    let r = evaluate_rollout(&evs, &GateConfig::default());
    assert!(!r.allowed);
    assert!(!r.conditions.is_empty());
    assert!(!r.blocking_reasons.is_empty());
}

#[test]
fn test_config_with_zero_min_samples_all_pass() {
    let c = GateConfig {
        min_sample_count: 0,
        ..GateConfig::default()
    };
    // Even with 0 samples, the evidence passes the sample check.
    let verdict = evaluate_transfer(
        &ev(TransferDomain::RewritePrior, 950_000, 0, 0),
        &c,
    );
    assert_eq!(verdict, TransferVerdict::Validated);
}

#[test]
fn test_serde_governance_decision_roundtrip() {
    let h = ContentHash::compute(b"test_evidence");
    let d = GovernanceDecision::new(GovernanceAction::DowngradeSupremacy, vec![h], "drift", ep(42));
    let json = serde_json::to_string(&d).unwrap();
    let back: GovernanceDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn test_serde_rollout_gate_result_roundtrip() {
    let r = RolloutGateResult::conditional(vec!["canary_only".into()], CoverageLevel::Partial);
    let json = serde_json::to_string(&r).unwrap();
    let back: RolloutGateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn test_serde_supremacy_constraint_roundtrip() {
    let sc = SupremacyConstraint::new("claim_1", "coverage_gap", 600_000, "reason");
    let json = serde_json::to_string(&sc).unwrap();
    let back: SupremacyConstraint = serde_json::from_str(&json).unwrap();
    assert_eq!(sc, back);
}

#[test]
fn test_serde_decision_receipt_roundtrip() {
    let h = ContentHash::compute(b"ev");
    let r = DecisionReceipt::new(ep(99), GovernanceAction::RequireFreshEvidence, h);
    let json = serde_json::to_string(&r).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}
