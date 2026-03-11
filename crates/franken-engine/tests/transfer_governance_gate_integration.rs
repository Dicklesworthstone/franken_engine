#![forbid(unsafe_code)]

//! Integration tests for `transfer_governance_gate` (RGC-612C, bd-1lsy.7.12.3).

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::transfer_governance_gate::*;

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

// -- Constants ---------------------------------------------------------------

#[test]
fn test_schema_version() {
    assert!(SCHEMA_VERSION.contains("transfer-governance-gate"));
    assert!(SCHEMA_VERSION.contains("v1"));
}
#[test]
fn test_component() {
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
fn test_thresholds_ordering() {
    assert!(DEFAULT_HIGH_FIDELITY_THRESHOLD > DEFAULT_MODERATE_FIDELITY_THRESHOLD);
    assert!(DEFAULT_MODERATE_FIDELITY_THRESHOLD > DEFAULT_DRIFT_ALARM_THRESHOLD);
}
#[test]
fn test_default_min_sample_count() {
    assert_eq!(DEFAULT_MIN_SAMPLE_COUNT, 30);
}
#[test]
fn test_default_min_coverage() {
    assert_eq!(DEFAULT_MIN_COVERAGE_FRACTION, 800_000);
}
#[test]
fn test_default_max_batch() {
    assert_eq!(DEFAULT_MAX_BATCH_SIZE, 512);
}

// -- TransferDomain ----------------------------------------------------------

#[test]
fn test_domain_all_count() {
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
    for (d, e) in TransferDomain::ALL.iter().zip(expected.iter()) {
        assert_eq!(d.to_string(), *e);
    }
}
#[test]
fn test_domain_serde_roundtrip() {
    for d in TransferDomain::ALL {
        let j = serde_json::to_string(d).unwrap();
        assert_eq!(*d, serde_json::from_str::<TransferDomain>(&j).unwrap());
    }
}
#[test]
fn test_domain_as_str_matches_display() {
    for d in TransferDomain::ALL {
        assert_eq!(d.as_str(), d.to_string());
    }
}

// -- TransferVerdict ---------------------------------------------------------

#[test]
fn test_verdict_display() {
    assert_eq!(TransferVerdict::Validated.to_string(), "validated");
    assert_eq!(
        TransferVerdict::ConditionallyValid.to_string(),
        "conditionally_valid"
    );
    assert_eq!(TransferVerdict::DriftDetected.to_string(), "drift_detected");
    assert_eq!(TransferVerdict::Rejected.to_string(), "rejected");
    assert_eq!(
        TransferVerdict::InsufficientEvidence.to_string(),
        "insufficient_evidence"
    );
}
#[test]
fn test_verdict_serde_roundtrip() {
    for v in [
        TransferVerdict::Validated,
        TransferVerdict::ConditionallyValid,
        TransferVerdict::DriftDetected,
        TransferVerdict::Rejected,
        TransferVerdict::InsufficientEvidence,
    ] {
        let j = serde_json::to_string(&v).unwrap();
        assert_eq!(v, serde_json::from_str::<TransferVerdict>(&j).unwrap());
    }
}
#[test]
fn test_verdict_unconditional_rollout() {
    assert!(TransferVerdict::Validated.allows_unconditional_rollout());
    assert!(!TransferVerdict::ConditionallyValid.allows_unconditional_rollout());
    assert!(!TransferVerdict::DriftDetected.allows_unconditional_rollout());
    assert!(!TransferVerdict::Rejected.allows_unconditional_rollout());
    assert!(!TransferVerdict::InsufficientEvidence.allows_unconditional_rollout());
}

// -- CoverageLevel -----------------------------------------------------------

#[test]
fn test_coverage_level_display() {
    assert_eq!(CoverageLevel::Full.to_string(), "full");
    assert_eq!(CoverageLevel::Partial.to_string(), "partial");
    assert_eq!(CoverageLevel::Sparse.to_string(), "sparse");
    assert_eq!(CoverageLevel::Uncovered.to_string(), "uncovered");
}
#[test]
fn test_coverage_level_serde() {
    for l in [
        CoverageLevel::Full,
        CoverageLevel::Partial,
        CoverageLevel::Sparse,
        CoverageLevel::Uncovered,
    ] {
        let j = serde_json::to_string(&l).unwrap();
        assert_eq!(l, serde_json::from_str::<CoverageLevel>(&j).unwrap());
    }
}
#[test]
fn test_coverage_sufficient() {
    assert!(CoverageLevel::Full.sufficient_for_rollout());
    assert!(CoverageLevel::Partial.sufficient_for_rollout());
    assert!(!CoverageLevel::Sparse.sufficient_for_rollout());
    assert!(!CoverageLevel::Uncovered.sufficient_for_rollout());
}

// -- GovernanceAction --------------------------------------------------------

#[test]
fn test_action_display() {
    assert_eq!(GovernanceAction::AllowRollout.to_string(), "allow_rollout");
    assert_eq!(
        GovernanceAction::ConditionalRollout.to_string(),
        "conditional_rollout"
    );
    assert_eq!(GovernanceAction::BlockRollout.to_string(), "block_rollout");
    assert_eq!(
        GovernanceAction::RequireFreshEvidence.to_string(),
        "require_fresh_evidence"
    );
    assert_eq!(
        GovernanceAction::DowngradeSupremacy.to_string(),
        "downgrade_supremacy"
    );
}
#[test]
fn test_action_serde() {
    for a in [
        GovernanceAction::AllowRollout,
        GovernanceAction::ConditionalRollout,
        GovernanceAction::BlockRollout,
        GovernanceAction::RequireFreshEvidence,
        GovernanceAction::DowngradeSupremacy,
    ] {
        let j = serde_json::to_string(&a).unwrap();
        assert_eq!(a, serde_json::from_str::<GovernanceAction>(&j).unwrap());
    }
}

// -- TransferEvidence --------------------------------------------------------

#[test]
fn test_evidence_fields() {
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
fn test_evidence_hash_differs_domain() {
    let a = ev(TransferDomain::RewritePrior, 900_000, 50_000, 50);
    let b = ev(TransferDomain::CachePolicy, 900_000, 50_000, 50);
    assert_ne!(a.evidence_hash, b.evidence_hash);
}
#[test]
fn test_evidence_hash_differs_fidelity() {
    assert_ne!(
        ev(TransferDomain::RewritePrior, 900_000, 50_000, 50).evidence_hash,
        ev(TransferDomain::RewritePrior, 900_001, 50_000, 50).evidence_hash
    );
}
#[test]
fn test_evidence_hash_differs_workload() {
    let a = ev_named(TransferDomain::RewritePrior, "wl_a", "wl_b", 900_000, 0, 50);
    let b = ev_named(TransferDomain::RewritePrior, "wl_x", "wl_b", 900_000, 0, 50);
    assert_ne!(a.evidence_hash, b.evidence_hash);
}
#[test]
fn test_evidence_display() {
    let s = ev(TransferDomain::TieringPolicy, 800_000, 20_000, 40).to_string();
    assert!(s.contains("tiering_policy") && s.contains("src_wl") && s.contains("tgt_wl"));
}
#[test]
fn test_evidence_serde() {
    let e = ev(TransferDomain::InliningDecision, 750_000, 100_000, 60);
    let j = serde_json::to_string(&e).unwrap();
    assert_eq!(e, serde_json::from_str::<TransferEvidence>(&j).unwrap());
}

// -- CoverageRecord ---------------------------------------------------------

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
fn test_coverage_record_hash_differs_level() {
    let a = cov(TransferDomain::RewritePrior, "r1", CoverageLevel::Full);
    let b = cov(TransferDomain::RewritePrior, "r1", CoverageLevel::Sparse);
    assert_ne!(a.content_hash(), b.content_hash());
}
#[test]
fn test_coverage_record_hash_differs_region() {
    assert_ne!(
        cov(TransferDomain::RewritePrior, "r1", CoverageLevel::Full).content_hash(),
        cov(TransferDomain::RewritePrior, "r2", CoverageLevel::Full).content_hash()
    );
}
#[test]
fn test_coverage_record_display() {
    let s = cov(
        TransferDomain::TieringPolicy,
        "zone_z",
        CoverageLevel::Partial,
    )
    .to_string();
    assert!(s.contains("Coverage") && s.contains("zone_z") && s.contains("partial"));
}

// -- GateConfig --------------------------------------------------------------

#[test]
fn test_config_default() {
    let c = GateConfig::default();
    assert_eq!(
        c.min_transfer_fidelity_high,
        DEFAULT_HIGH_FIDELITY_THRESHOLD
    );
    assert_eq!(
        c.min_transfer_fidelity_moderate,
        DEFAULT_MODERATE_FIDELITY_THRESHOLD
    );
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
    assert_eq!(
        evaluate_transfer(&ev(TransferDomain::CachePolicy, 750_000, 100_000, 20), &c),
        TransferVerdict::ConditionallyValid
    );
}
#[test]
fn test_config_serde() {
    let c = GateConfig::default();
    let j = serde_json::to_string(&c).unwrap();
    assert_eq!(c, serde_json::from_str::<GateConfig>(&j).unwrap());
}
#[test]
fn test_config_display() {
    let s = GateConfig::default().to_string();
    assert!(s.contains("GateConfig") && s.contains("900000"));
}

// -- evaluate_transfer (all verdict paths + boundaries) ----------------------

#[test]
fn test_eval_validated() {
    let c = GateConfig::default();
    assert_eq!(
        evaluate_transfer(&ev(TransferDomain::RewritePrior, 950_000, 50_000, 100), &c),
        TransferVerdict::Validated
    );
}
#[test]
fn test_eval_conditionally_valid() {
    assert_eq!(
        evaluate_transfer(
            &ev(TransferDomain::CachePolicy, 750_000, 100_000, 50),
            &GateConfig::default()
        ),
        TransferVerdict::ConditionallyValid
    );
}
#[test]
fn test_eval_rejected() {
    assert_eq!(
        evaluate_transfer(
            &ev(TransferDomain::SchedulingHeuristic, 500_000, 100_000, 50),
            &GateConfig::default()
        ),
        TransferVerdict::Rejected
    );
}
#[test]
fn test_eval_drift() {
    assert_eq!(
        evaluate_transfer(
            &ev(TransferDomain::RewritePrior, 990_000, 500_000, 100),
            &GateConfig::default()
        ),
        TransferVerdict::DriftDetected
    );
}
#[test]
fn test_eval_insufficient() {
    assert_eq!(
        evaluate_transfer(
            &ev(TransferDomain::InliningDecision, 950_000, 0, 5),
            &GateConfig::default()
        ),
        TransferVerdict::InsufficientEvidence
    );
}
#[test]
fn test_eval_insufficient_trumps_drift() {
    assert_eq!(
        evaluate_transfer(
            &ev(TransferDomain::CachePolicy, 1_000_000, 500_000, 1),
            &GateConfig::default()
        ),
        TransferVerdict::InsufficientEvidence
    );
}
#[test]
fn test_eval_boundary_fidelity_at_high() {
    assert_eq!(
        evaluate_transfer(
            &ev(TransferDomain::RewritePrior, 900_000, 100_000, 50),
            &GateConfig::default()
        ),
        TransferVerdict::Validated
    );
}
#[test]
fn test_eval_boundary_fidelity_below_high() {
    assert_eq!(
        evaluate_transfer(
            &ev(TransferDomain::RewritePrior, 899_999, 100_000, 50),
            &GateConfig::default()
        ),
        TransferVerdict::ConditionallyValid
    );
}
#[test]
fn test_eval_boundary_fidelity_at_moderate() {
    assert_eq!(
        evaluate_transfer(
            &ev(TransferDomain::RewritePrior, 700_000, 100_000, 50),
            &GateConfig::default()
        ),
        TransferVerdict::ConditionallyValid
    );
}
#[test]
fn test_eval_boundary_fidelity_below_moderate() {
    assert_eq!(
        evaluate_transfer(
            &ev(TransferDomain::RewritePrior, 699_999, 100_000, 50),
            &GateConfig::default()
        ),
        TransferVerdict::Rejected
    );
}
#[test]
fn test_eval_boundary_drift_at_threshold() {
    assert_eq!(
        evaluate_transfer(
            &ev(TransferDomain::RewritePrior, 950_000, 200_000, 50),
            &GateConfig::default()
        ),
        TransferVerdict::Validated
    );
}
#[test]
fn test_eval_boundary_drift_over() {
    assert_eq!(
        evaluate_transfer(
            &ev(TransferDomain::RewritePrior, 950_000, 200_001, 50),
            &GateConfig::default()
        ),
        TransferVerdict::DriftDetected
    );
}
#[test]
fn test_eval_boundary_samples_at_min() {
    assert_eq!(
        evaluate_transfer(
            &ev(TransferDomain::RewritePrior, 950_000, 50_000, 30),
            &GateConfig::default()
        ),
        TransferVerdict::Validated
    );
}
#[test]
fn test_eval_boundary_samples_below_min() {
    assert_eq!(
        evaluate_transfer(
            &ev(TransferDomain::RewritePrior, 950_000, 50_000, 29),
            &GateConfig::default()
        ),
        TransferVerdict::InsufficientEvidence
    );
}

// -- evaluate_coverage -------------------------------------------------------

#[test]
fn test_coverage_empty() {
    assert_eq!(
        evaluate_coverage(&[], &GateConfig::default()),
        CoverageLevel::Uncovered
    );
}
#[test]
fn test_coverage_all_full() {
    let recs: Vec<_> = (0..5)
        .map(|i| {
            cov(
                TransferDomain::RewritePrior,
                &format!("r{i}"),
                CoverageLevel::Full,
            )
        })
        .collect();
    assert_eq!(
        evaluate_coverage(&recs, &GateConfig::default()),
        CoverageLevel::Full
    );
}
#[test]
fn test_coverage_mixed_partial() {
    let recs = vec![
        cov(TransferDomain::RewritePrior, "a", CoverageLevel::Full),
        cov(TransferDomain::CachePolicy, "b", CoverageLevel::Sparse),
        cov(TransferDomain::TieringPolicy, "c", CoverageLevel::Full),
        cov(TransferDomain::InliningDecision, "d", CoverageLevel::Full),
    ];
    assert_eq!(
        evaluate_coverage(&recs, &GateConfig::default()),
        CoverageLevel::Partial
    );
}
#[test]
fn test_coverage_all_sparse_is_uncovered() {
    let recs = vec![
        cov(TransferDomain::RewritePrior, "a", CoverageLevel::Sparse),
        cov(TransferDomain::CachePolicy, "b", CoverageLevel::Sparse),
    ];
    assert_eq!(
        evaluate_coverage(&recs, &GateConfig::default()),
        CoverageLevel::Uncovered
    );
}
#[test]
fn test_coverage_partial_records_remain_partial() {
    let recs: Vec<_> = (0..10)
        .map(|i| {
            cov(
                TransferDomain::CachePolicy,
                &format!("r{i}"),
                CoverageLevel::Partial,
            )
        })
        .collect();
    assert_eq!(
        evaluate_coverage(&recs, &GateConfig::default()),
        CoverageLevel::Partial
    );
}
#[test]
fn test_coverage_full_majority_still_counts_as_full() {
    let recs = vec![
        cov(TransferDomain::RewritePrior, "a", CoverageLevel::Full),
        cov(TransferDomain::CachePolicy, "b", CoverageLevel::Full),
        cov(TransferDomain::TieringPolicy, "c", CoverageLevel::Full),
        cov(TransferDomain::InliningDecision, "d", CoverageLevel::Full),
        cov(
            TransferDomain::SchedulingHeuristic,
            "e",
            CoverageLevel::Full,
        ),
        cov(
            TransferDomain::SpecializationStrategy,
            "f",
            CoverageLevel::Full,
        ),
        cov(TransferDomain::RewritePrior, "g", CoverageLevel::Full),
        cov(TransferDomain::CachePolicy, "h", CoverageLevel::Full),
        cov(TransferDomain::TieringPolicy, "i", CoverageLevel::Full),
        cov(
            TransferDomain::InliningDecision,
            "j",
            CoverageLevel::Partial,
        ),
    ];
    assert_eq!(
        evaluate_coverage(&recs, &GateConfig::default()),
        CoverageLevel::Full
    );
}

// -- GovernanceDecision ------------------------------------------------------

#[test]
fn test_decision_creation() {
    let h = ContentHash::compute(b"evidence_data");
    let d = GovernanceDecision::new(GovernanceAction::AllowRollout, vec![h], "ok", ep(10));
    assert_eq!(d.action, GovernanceAction::AllowRollout);
    assert_eq!(d.evidence_hashes.len(), 1);
    assert_eq!(d.explanation, "ok");
    assert_eq!(d.epoch.as_u64(), 10);
}
#[test]
fn test_decision_hash_deterministic() {
    let h = ContentHash::compute(b"ev_data");
    let a = GovernanceDecision::new(GovernanceAction::BlockRollout, vec![h.clone()], "r", ep(5));
    let b = GovernanceDecision::new(GovernanceAction::BlockRollout, vec![h], "r", ep(5));
    assert_eq!(a.receipt_hash, b.receipt_hash);
}
#[test]
fn test_decision_hash_differs() {
    let h = ContentHash::compute(b"ev_data");
    let a = GovernanceDecision::new(GovernanceAction::AllowRollout, vec![h.clone()], "x", ep(1));
    let b = GovernanceDecision::new(GovernanceAction::BlockRollout, vec![h], "x", ep(1));
    assert_ne!(a.receipt_hash, b.receipt_hash);
}
#[test]
fn test_decision_display() {
    let d = GovernanceDecision::new(GovernanceAction::ConditionalRollout, vec![], "c", ep(7));
    assert!(d.to_string().contains("conditional_rollout") && d.to_string().contains("epoch=7"));
}

// -- RolloutGateResult constructors ------------------------------------------

#[test]
fn test_rollout_result_allowed() {
    let r = RolloutGateResult::allowed(CoverageLevel::Full);
    assert!(r.allowed && r.conditions.is_empty() && r.blocking_reasons.is_empty());
    assert_eq!(r.coverage_summary, CoverageLevel::Full);
}
#[test]
fn test_rollout_result_blocked() {
    let r = RolloutGateResult::blocked(vec!["x".into()], CoverageLevel::Sparse);
    assert!(!r.allowed && r.blocking_reasons.len() == 1 && r.conditions.is_empty());
}
#[test]
fn test_rollout_result_conditional() {
    let r = RolloutGateResult::conditional(vec!["c".into()], CoverageLevel::Partial);
    assert!(r.allowed && r.conditions.len() == 1 && r.blocking_reasons.is_empty());
}
#[test]
fn test_rollout_display_allowed() {
    assert!(
        RolloutGateResult::allowed(CoverageLevel::Full)
            .to_string()
            .contains("ALLOWED")
    );
}
#[test]
fn test_rollout_display_blocked() {
    assert!(
        RolloutGateResult::blocked(vec!["x".into()], CoverageLevel::Uncovered)
            .to_string()
            .contains("BLOCKED")
    );
}
#[test]
fn test_rollout_display_conditional() {
    assert!(
        RolloutGateResult::conditional(vec!["c".into()], CoverageLevel::Partial)
            .to_string()
            .contains("CONDITIONAL")
    );
}

// -- evaluate_rollout --------------------------------------------------------

#[test]
fn test_rollout_empty_blocked() {
    let r = evaluate_rollout(&[], &GateConfig::default());
    assert!(!r.allowed && !r.blocking_reasons.is_empty());
    assert_eq!(r.coverage_summary, CoverageLevel::Uncovered);
}
#[test]
fn test_rollout_all_validated() {
    let evs = vec![
        ev(TransferDomain::RewritePrior, 950_000, 50_000, 100),
        ev(TransferDomain::CachePolicy, 920_000, 30_000, 80),
    ];
    let r = evaluate_rollout(&evs, &GateConfig::default());
    assert!(r.allowed && r.conditions.is_empty());
    assert_eq!(r.coverage_summary, CoverageLevel::Full);
}
#[test]
fn test_rollout_with_drift() {
    let evs = vec![
        ev(TransferDomain::RewritePrior, 950_000, 50_000, 100),
        ev(TransferDomain::CachePolicy, 920_000, 400_000, 80),
    ];
    assert!(!evaluate_rollout(&evs, &GateConfig::default()).allowed);
}
#[test]
fn test_rollout_conditional_path() {
    let evs = vec![
        ev(TransferDomain::RewritePrior, 750_000, 50_000, 100),
        ev(TransferDomain::CachePolicy, 800_000, 100_000, 80),
    ];
    let r = evaluate_rollout(&evs, &GateConfig::default());
    assert!(r.allowed && !r.conditions.is_empty());
    assert_eq!(r.coverage_summary, CoverageLevel::Partial);
}
#[test]
fn test_rollout_single_rejected() {
    let evs = vec![
        ev(TransferDomain::RewritePrior, 950_000, 50_000, 100),
        ev(TransferDomain::CachePolicy, 400_000, 50_000, 80),
    ];
    assert!(!evaluate_rollout(&evs, &GateConfig::default()).allowed);
}
#[test]
fn test_rollout_insufficient_blocks() {
    assert!(
        !evaluate_rollout(
            &[ev(TransferDomain::RewritePrior, 950_000, 0, 5)],
            &GateConfig::default()
        )
        .allowed
    );
}
#[test]
fn test_rollout_single_validated() {
    let r = evaluate_rollout(
        &[ev(TransferDomain::SpecializationStrategy, 950_000, 0, 100)],
        &GateConfig::default(),
    );
    assert!(r.allowed && r.conditions.is_empty());
}
#[test]
fn test_rollout_conditions_in_blocked() {
    let evs = vec![
        ev(TransferDomain::RewritePrior, 750_000, 50_000, 100),
        ev(TransferDomain::CachePolicy, 400_000, 50_000, 80),
    ];
    let r = evaluate_rollout(&evs, &GateConfig::default());
    assert!(!r.allowed && !r.conditions.is_empty() && !r.blocking_reasons.is_empty());
}

// -- SupremacyConstraint -----------------------------------------------------

#[test]
fn test_supremacy_fields() {
    let sc = SupremacyConstraint::new("claim_42", "coverage_gap", 600_000, "missing");
    assert_eq!(sc.claim_id, "claim_42");
    assert_eq!(sc.constraint_kind, "coverage_gap");
    assert_eq!(sc.severity, 600_000);
    assert_eq!(sc.explanation, "missing");
}
#[test]
fn test_supremacy_not_critical() {
    assert!(!SupremacyConstraint::new("c1", "drift", 799_999, "d").is_critical());
}
#[test]
fn test_supremacy_critical_at_800k() {
    assert!(SupremacyConstraint::new("c2", "gap", 800_000, "g").is_critical());
}
#[test]
fn test_supremacy_critical_above() {
    assert!(SupremacyConstraint::new("c3", "gap", 900_000, "g").is_critical());
}
#[test]
fn test_supremacy_hash_deterministic() {
    let a = SupremacyConstraint::new("c", "k", 500_000, "e");
    let b = SupremacyConstraint::new("c", "k", 500_000, "e");
    assert_eq!(a.content_hash(), b.content_hash());
}
#[test]
fn test_supremacy_hash_differs() {
    assert_ne!(
        SupremacyConstraint::new("c1", "k", 500_000, "e").content_hash(),
        SupremacyConstraint::new("c2", "k", 500_000, "e").content_hash()
    );
}
#[test]
fn test_supremacy_display() {
    let s = SupremacyConstraint::new("claim_x", "drift_detected", 700_000, "x").to_string();
    assert!(s.contains("claim_x") && s.contains("drift_detected"));
}

// -- DecisionReceipt ---------------------------------------------------------

#[test]
fn test_receipt_fields() {
    let h = ContentHash::compute(b"evidence");
    let r = DecisionReceipt::new(ep(15), GovernanceAction::AllowRollout, h.clone());
    assert_eq!(r.component, COMPONENT);
    assert_eq!(r.epoch.as_u64(), 15);
    assert_eq!(r.action, GovernanceAction::AllowRollout);
    assert_eq!(r.evidence_hash, h);
}
#[test]
fn test_receipt_hash_deterministic() {
    let h = ContentHash::compute(b"ev");
    let a = DecisionReceipt::new(ep(10), GovernanceAction::BlockRollout, h.clone());
    let b = DecisionReceipt::new(ep(10), GovernanceAction::BlockRollout, h);
    assert_eq!(a.receipt_hash, b.receipt_hash);
}
#[test]
fn test_receipt_hash_differs_action() {
    let h = ContentHash::compute(b"ev");
    let a = DecisionReceipt::new(ep(10), GovernanceAction::AllowRollout, h.clone());
    let b = DecisionReceipt::new(ep(10), GovernanceAction::BlockRollout, h);
    assert_ne!(a.receipt_hash, b.receipt_hash);
}
#[test]
fn test_receipt_hash_differs_epoch() {
    let h = ContentHash::compute(b"ev");
    let a = DecisionReceipt::new(ep(10), GovernanceAction::AllowRollout, h.clone());
    let b = DecisionReceipt::new(ep(11), GovernanceAction::AllowRollout, h);
    assert_ne!(a.receipt_hash, b.receipt_hash);
}
#[test]
fn test_receipt_hash_differs_evidence() {
    let a = DecisionReceipt::new(
        ep(10),
        GovernanceAction::AllowRollout,
        ContentHash::compute(b"ev1"),
    );
    let b = DecisionReceipt::new(
        ep(10),
        GovernanceAction::AllowRollout,
        ContentHash::compute(b"ev2"),
    );
    assert_ne!(a.receipt_hash, b.receipt_hash);
}
#[test]
fn test_receipt_display() {
    let s = DecisionReceipt::new(
        ep(20),
        GovernanceAction::RequireFreshEvidence,
        ContentHash::compute(b"ev"),
    )
    .to_string();
    assert!(s.contains("require_fresh_evidence") && s.contains("epoch=20"));
}

// -- evaluate_batch ----------------------------------------------------------

#[test]
fn test_batch_mixed() {
    let c = GateConfig::default();
    let evs = vec![
        ev(TransferDomain::RewritePrior, 950_000, 50_000, 100),
        ev(TransferDomain::CachePolicy, 750_000, 100_000, 50),
        ev(TransferDomain::TieringPolicy, 950_000, 400_000, 60),
        ev(TransferDomain::SchedulingHeuristic, 300_000, 50_000, 40),
        ev(TransferDomain::InliningDecision, 950_000, 0, 5),
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
fn test_batch_truncated() {
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
fn test_batch_empty() {
    let (decs, sum) = evaluate_batch(&[], &GateConfig::default());
    assert!(decs.is_empty());
    assert_eq!(sum.total_transfers, 0);
    assert_eq!(sum.coverage_fraction, 0);
}
#[test]
fn test_batch_actions_match_verdicts() {
    let c = GateConfig::default();
    let evs = vec![
        ev(TransferDomain::RewritePrior, 950_000, 50_000, 100),
        ev(TransferDomain::CachePolicy, 750_000, 100_000, 50),
        ev(TransferDomain::TieringPolicy, 300_000, 50_000, 50),
        ev(TransferDomain::InliningDecision, 950_000, 500_000, 50),
        ev(TransferDomain::SchedulingHeuristic, 950_000, 0, 5),
    ];
    let (decs, _) = evaluate_batch(&evs, &c);
    assert_eq!(decs[0].action, GovernanceAction::AllowRollout);
    assert_eq!(decs[1].action, GovernanceAction::ConditionalRollout);
    assert_eq!(decs[2].action, GovernanceAction::BlockRollout);
    assert_eq!(decs[3].action, GovernanceAction::DowngradeSupremacy);
    assert_eq!(decs[4].action, GovernanceAction::RequireFreshEvidence);
}
#[test]
fn test_batch_carries_evidence_hashes() {
    let evs = vec![ev(TransferDomain::RewritePrior, 950_000, 50_000, 100)];
    let (decs, _) = evaluate_batch(&evs, &GateConfig::default());
    assert_eq!(decs[0].evidence_hashes.len(), 1);
    assert_eq!(decs[0].evidence_hashes[0], evs[0].evidence_hash);
}

// -- GovernanceSummary -------------------------------------------------------

#[test]
fn test_summary_total() {
    assert_eq!(
        GovernanceSummary::from_counts(3, 2, 1, 1, 1).total_transfers,
        8
    );
}
#[test]
fn test_summary_coverage_fraction() {
    assert_eq!(
        GovernanceSummary::from_counts(2, 2, 1, 0, 0).coverage_fraction,
        800_000
    );
}
#[test]
fn test_summary_pass_rate() {
    assert_eq!(
        GovernanceSummary::from_counts(3, 1, 1, 0, 0).pass_rate(),
        600_000
    );
}
#[test]
fn test_summary_empty() {
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
    assert!(
        GovernanceSummary::from_counts(5, 2, 1, 1, 1)
            .to_string()
            .contains("total=10")
    );
}

// -- Edge cases & cross-cutting serde ----------------------------------------

#[test]
fn test_evidence_zero_fidelity() {
    assert_eq!(
        evaluate_transfer(
            &ev(TransferDomain::RewritePrior, 0, 0, 100),
            &GateConfig::default()
        ),
        TransferVerdict::Rejected
    );
}
#[test]
fn test_evidence_max_fidelity() {
    assert_eq!(
        evaluate_transfer(
            &ev(TransferDomain::RewritePrior, 1_000_000, 0, 100),
            &GateConfig::default()
        ),
        TransferVerdict::Validated
    );
}
#[test]
fn test_evidence_zero_samples() {
    assert_eq!(
        evaluate_transfer(
            &ev(TransferDomain::RewritePrior, 1_000_000, 0, 0),
            &GateConfig::default()
        ),
        TransferVerdict::InsufficientEvidence
    );
}
#[test]
fn test_config_zero_min_samples() {
    let c = GateConfig {
        min_sample_count: 0,
        ..GateConfig::default()
    };
    assert_eq!(
        evaluate_transfer(&ev(TransferDomain::RewritePrior, 950_000, 0, 0), &c),
        TransferVerdict::Validated
    );
}
#[test]
fn test_serde_governance_decision() {
    let h = ContentHash::compute(b"test_evidence");
    let d = GovernanceDecision::new(
        GovernanceAction::DowngradeSupremacy,
        vec![h],
        "drift",
        ep(42),
    );
    let j = serde_json::to_string(&d).unwrap();
    assert_eq!(d, serde_json::from_str::<GovernanceDecision>(&j).unwrap());
}
#[test]
fn test_serde_rollout_gate_result() {
    let r = RolloutGateResult::conditional(vec!["canary_only".into()], CoverageLevel::Partial);
    let j = serde_json::to_string(&r).unwrap();
    assert_eq!(r, serde_json::from_str::<RolloutGateResult>(&j).unwrap());
}
#[test]
fn test_serde_supremacy_constraint() {
    let sc = SupremacyConstraint::new("claim_1", "coverage_gap", 600_000, "reason");
    let j = serde_json::to_string(&sc).unwrap();
    assert_eq!(sc, serde_json::from_str::<SupremacyConstraint>(&j).unwrap());
}
#[test]
fn test_serde_decision_receipt() {
    let r = DecisionReceipt::new(
        ep(99),
        GovernanceAction::RequireFreshEvidence,
        ContentHash::compute(b"ev"),
    );
    let j = serde_json::to_string(&r).unwrap();
    assert_eq!(r, serde_json::from_str::<DecisionReceipt>(&j).unwrap());
}
