//! Enrichment integration tests for `transfer_governance_gate`.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::transfer_governance_gate::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_non_empty() {
    assert!(!SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_component_non_empty() {
    assert!(!COMPONENT.is_empty());
}

#[test]
fn enrichment_bead_id_starts_with_bd() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_policy_id_non_empty() {
    assert!(!POLICY_ID.is_empty());
}

#[test]
fn enrichment_default_thresholds_positive() {
    assert!(DEFAULT_HIGH_FIDELITY_THRESHOLD > 0);
    assert!(DEFAULT_MODERATE_FIDELITY_THRESHOLD > 0);
    assert!(DEFAULT_DRIFT_ALARM_THRESHOLD > 0);
}

// ---------------------------------------------------------------------------
// TransferDomain
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transfer_domain_all_count() {
    assert!(TransferDomain::ALL.len() >= 4);
}

#[test]
fn enrichment_transfer_domain_as_str_unique() {
    let mut strs = std::collections::BTreeSet::new();
    for d in TransferDomain::ALL {
        assert!(strs.insert(d.as_str()));
    }
}

#[test]
fn enrichment_transfer_domain_serde_roundtrip() {
    for d in TransferDomain::ALL {
        let json = serde_json::to_string(d).unwrap();
        let back: TransferDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

// ---------------------------------------------------------------------------
// TransferVerdict
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verdict_validated_allows_rollout() {
    assert!(TransferVerdict::Validated.allows_unconditional_rollout());
}

#[test]
fn enrichment_verdict_conditionally_valid_no_unconditional() {
    assert!(!TransferVerdict::ConditionallyValid.allows_unconditional_rollout());
}

#[test]
fn enrichment_verdict_serde_roundtrip() {
    for v in [
        TransferVerdict::Validated,
        TransferVerdict::ConditionallyValid,
        TransferVerdict::DriftDetected,
        TransferVerdict::Rejected,
        TransferVerdict::InsufficientEvidence,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: TransferVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ---------------------------------------------------------------------------
// CoverageLevel
// ---------------------------------------------------------------------------

#[test]
fn enrichment_coverage_full_sufficient_for_rollout() {
    assert!(CoverageLevel::Full.sufficient_for_rollout());
}

#[test]
fn enrichment_coverage_uncovered_not_sufficient() {
    assert!(!CoverageLevel::Uncovered.sufficient_for_rollout());
}

#[test]
fn enrichment_coverage_level_serde_roundtrip() {
    for level in [
        CoverageLevel::Full,
        CoverageLevel::Partial,
        CoverageLevel::Uncovered,
    ] {
        let json = serde_json::to_string(&level).unwrap();
        let back: CoverageLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(level, back);
    }
}

// ---------------------------------------------------------------------------
// GovernanceAction
// ---------------------------------------------------------------------------

#[test]
fn enrichment_governance_action_as_str_unique() {
    let mut strs = std::collections::BTreeSet::new();
    for a in [
        GovernanceAction::AllowRollout,
        GovernanceAction::ConditionalRollout,
        GovernanceAction::BlockRollout,
        GovernanceAction::RequireFreshEvidence,
        GovernanceAction::DowngradeSupremacy,
    ] {
        assert!(strs.insert(a.as_str()));
    }
}

#[test]
fn enrichment_governance_action_serde_roundtrip() {
    for a in [
        GovernanceAction::AllowRollout,
        GovernanceAction::ConditionalRollout,
        GovernanceAction::BlockRollout,
        GovernanceAction::RequireFreshEvidence,
        GovernanceAction::DowngradeSupremacy,
    ] {
        let json = serde_json::to_string(&a).unwrap();
        let back: GovernanceAction = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }
}

// ---------------------------------------------------------------------------
// TransferEvidence
// ---------------------------------------------------------------------------

fn make_evidence(fidelity: u64, drift: u64, samples: u64) -> TransferEvidence {
    TransferEvidence::new(
        TransferDomain::RewritePrior,
        "src-workload",
        "tgt-workload",
        fidelity,
        drift,
        samples,
        SecurityEpoch::from_raw(1),
    )
}

#[test]
fn enrichment_transfer_evidence_new_hash_deterministic() {
    let e1 = make_evidence(900_000, 50_000, 100);
    let e2 = make_evidence(900_000, 50_000, 100);
    assert_eq!(e1.evidence_hash, e2.evidence_hash);
}

#[test]
fn enrichment_transfer_evidence_serde_roundtrip() {
    let ev = make_evidence(800_000, 100_000, 50);
    let json = serde_json::to_string(&ev).unwrap();
    let back: TransferEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev.transfer_fidelity, back.transfer_fidelity);
}

// ---------------------------------------------------------------------------
// evaluate_transfer
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluate_high_fidelity_validates() {
    let cfg = GateConfig::default();
    let ev = make_evidence(950_000, 50_000, 100);
    let verdict = evaluate_transfer(&ev, &cfg);
    assert_eq!(verdict, TransferVerdict::Validated);
}

#[test]
fn enrichment_evaluate_moderate_fidelity_conditional() {
    let cfg = GateConfig::default();
    let ev = make_evidence(750_000, 50_000, 100);
    let verdict = evaluate_transfer(&ev, &cfg);
    assert_eq!(verdict, TransferVerdict::ConditionallyValid);
}

#[test]
fn enrichment_evaluate_drift_alarm() {
    let cfg = GateConfig::default();
    let ev = make_evidence(950_000, 250_000, 100);
    let verdict = evaluate_transfer(&ev, &cfg);
    assert_eq!(verdict, TransferVerdict::DriftDetected);
}

#[test]
fn enrichment_evaluate_insufficient_samples() {
    let cfg = GateConfig::default();
    let ev = make_evidence(950_000, 50_000, 5);
    let verdict = evaluate_transfer(&ev, &cfg);
    assert_eq!(verdict, TransferVerdict::InsufficientEvidence);
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_config_default_serde_roundtrip() {
    let cfg = GateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// RolloutGateResult
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rollout_allowed() {
    let result = RolloutGateResult::allowed(CoverageLevel::Full);
    assert!(result.allowed);
    assert!(result.blocking_reasons.is_empty());
}

#[test]
fn enrichment_rollout_blocked() {
    let result = RolloutGateResult::blocked(vec!["reason".to_string()], CoverageLevel::Uncovered);
    assert!(!result.allowed);
    assert!(!result.blocking_reasons.is_empty());
}

#[test]
fn enrichment_rollout_conditional() {
    let result = RolloutGateResult::conditional(vec!["cond".to_string()], CoverageLevel::Partial);
    assert!(result.allowed);
    assert!(!result.conditions.is_empty());
}

// ---------------------------------------------------------------------------
// SupremacyConstraint
// ---------------------------------------------------------------------------

#[test]
fn enrichment_supremacy_constraint_critical() {
    let sc = SupremacyConstraint::new("c1", "safety", 1_000_000, "critical constraint");
    assert!(sc.is_critical());
}

#[test]
fn enrichment_supremacy_constraint_not_critical() {
    let sc = SupremacyConstraint::new("c2", "advisory", 100_000, "minor constraint");
    assert!(!sc.is_critical());
}

#[test]
fn enrichment_supremacy_constraint_hash_deterministic() {
    let s1 = SupremacyConstraint::new("c1", "safety", 900_000, "explanation");
    let s2 = SupremacyConstraint::new("c1", "safety", 900_000, "explanation");
    assert_eq!(s1.content_hash(), s2.content_hash());
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn enrichment_decision_receipt_new() {
    let hash = ContentHash::compute(b"test-evidence");
    let receipt = DecisionReceipt::new(SecurityEpoch::from_raw(5), GovernanceAction::AllowRollout, hash);
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.action, GovernanceAction::AllowRollout);
}

// ---------------------------------------------------------------------------
// GovernanceSummary
// ---------------------------------------------------------------------------

#[test]
fn enrichment_governance_summary_from_counts() {
    // from_counts(validated, conditionally_valid, drift_detected, rejected, insufficient)
    let summary = GovernanceSummary::from_counts(5, 2, 1, 1, 1);
    assert_eq!(summary.total_transfers, 10); // 5+2+1+1+1
    assert_eq!(summary.validated, 5);
    assert_eq!(summary.conditionally_valid, 2);
}

#[test]
fn enrichment_governance_summary_pass_rate_all_validated() {
    // All 10 are validated
    let summary = GovernanceSummary::from_counts(10, 0, 0, 0, 0);
    assert_eq!(summary.pass_rate(), 1_000_000);
}

#[test]
fn enrichment_governance_summary_pass_rate_none_validated() {
    let summary = GovernanceSummary::from_counts(0, 0, 5, 3, 2);
    assert_eq!(summary.pass_rate(), 0);
}

#[test]
fn enrichment_governance_summary_pass_rate_zero_total() {
    let summary = GovernanceSummary::from_counts(0, 0, 0, 0, 0);
    assert_eq!(summary.pass_rate(), 0);
}
