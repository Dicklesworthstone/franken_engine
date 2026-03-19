// Enrichment integration tests for hostcall_conformance_governance module.
//
// Covers: ConformanceAxis::ALL completeness (6 entries), as_str(), Display
// uniqueness, serde roundtrips, ConformanceResult new/total_count/display,
// ReplayDropCategory ALL/is_security_sensitive/display, ReplayDropEntry new/serde,
// DegradedModeKind ALL/severity_rank/is_terminal, DegradedModePolicy for_kind/
// exceeds_duration/can_auto_recover, ObservabilityClaimDelta new/relative_drift,
// GovernanceConfig default/strict/permissive, GovernanceVerdict ALL/is_approved/
// is_failure, GovernanceEvaluator evaluate lifecycle and receipt determinism,
// all constant values, ordering.

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

use frankenengine_engine::hostcall_conformance_governance::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_constants_schema_version() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.hostcall-conformance-governance.v1");
}

#[test]
fn enrichment_constants_component() {
    assert_eq!(COMPONENT, "hostcall_conformance_governance");
}

#[test]
fn enrichment_constants_bead_id() {
    assert_eq!(BEAD_ID, "bd-1lsy.6.5.3");
}

#[test]
fn enrichment_constants_policy_id() {
    assert_eq!(POLICY_ID, "RGC-505C");
}

#[test]
fn enrichment_constants_default_min_conformance() {
    assert_eq!(DEFAULT_MIN_CONFORMANCE, 900_000);
}

#[test]
fn enrichment_constants_default_max_drop_rate() {
    assert_eq!(DEFAULT_MAX_DROP_RATE, 50_000);
}

#[test]
fn enrichment_constants_default_max_degraded_duration() {
    assert_eq!(DEFAULT_MAX_DEGRADED_DURATION_NS, 60_000_000_000);
}

#[test]
fn enrichment_constants_default_observability_tolerance() {
    assert_eq!(DEFAULT_OBSERVABILITY_TOLERANCE, 50_000);
}

#[test]
fn enrichment_constants_default_min_required_axes() {
    assert_eq!(DEFAULT_MIN_REQUIRED_AXES, 4);
}

// ===========================================================================
// ConformanceAxis
// ===========================================================================

#[test]
fn enrichment_conformance_axis_all_has_six() {
    assert_eq!(ConformanceAxis::ALL.len(), 6);
}

#[test]
fn enrichment_conformance_axis_all_unique() {
    let set: BTreeSet<ConformanceAxis> = ConformanceAxis::ALL.iter().copied().collect();
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_conformance_axis_as_str_values() {
    assert_eq!(ConformanceAxis::Protocol.as_str(), "protocol");
    assert_eq!(ConformanceAxis::Ordering.as_str(), "ordering");
    assert_eq!(ConformanceAxis::Encoding.as_str(), "encoding");
    assert_eq!(ConformanceAxis::Timeout.as_str(), "timeout");
    assert_eq!(ConformanceAxis::Authentication.as_str(), "authentication");
    assert_eq!(ConformanceAxis::Authorization.as_str(), "authorization");
}

#[test]
fn enrichment_conformance_axis_display_matches_as_str() {
    for axis in ConformanceAxis::ALL {
        assert_eq!(format!("{axis}"), axis.as_str());
    }
}

#[test]
fn enrichment_conformance_axis_display_unique() {
    let labels: BTreeSet<String> = ConformanceAxis::ALL.iter().map(|a| a.to_string()).collect();
    assert_eq!(labels.len(), 6);
}

#[test]
fn enrichment_conformance_axis_serde_roundtrip() {
    for axis in ConformanceAxis::ALL {
        let json = serde_json::to_string(axis).unwrap();
        let back: ConformanceAxis = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *axis);
    }
}

#[test]
fn enrichment_conformance_axis_ordering() {
    let mut axes: Vec<ConformanceAxis> = ConformanceAxis::ALL.to_vec();
    axes.sort();
    let mut axes2 = axes.clone();
    axes2.sort();
    assert_eq!(axes, axes2);
}

// ===========================================================================
// ConformanceResult
// ===========================================================================

#[test]
fn enrichment_conformance_result_pass() {
    let r = ConformanceResult::new(ConformanceAxis::Protocol, 950, 50, 900_000);
    assert!(r.passes);
    assert_eq!(r.total_count(), 1000);
    assert_eq!(r.conformance_ratio_millionths, 950_000);
}

#[test]
fn enrichment_conformance_result_fail() {
    let r = ConformanceResult::new(ConformanceAxis::Protocol, 800, 200, 900_000);
    assert!(!r.passes);
    assert_eq!(r.conformance_ratio_millionths, 800_000);
}

#[test]
fn enrichment_conformance_result_zero_total() {
    let r = ConformanceResult::new(ConformanceAxis::Encoding, 0, 0, 900_000);
    assert_eq!(r.conformance_ratio_millionths, 0);
    assert!(!r.passes);
}

#[test]
fn enrichment_conformance_result_serde_roundtrip() {
    let r = ConformanceResult::new(ConformanceAxis::Timeout, 99, 1, 900_000);
    let json = serde_json::to_string(&r).unwrap();
    let back: ConformanceResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

#[test]
fn enrichment_conformance_result_display_contains_axis() {
    let r = ConformanceResult::new(ConformanceAxis::Authentication, 100, 0, 900_000);
    let s = r.to_string();
    assert!(s.contains("authentication"));
}

// ===========================================================================
// ReplayDropCategory
// ===========================================================================

#[test]
fn enrichment_replay_drop_category_all_count() {
    assert_eq!(ReplayDropCategory::ALL.len(), 5);
}

#[test]
fn enrichment_replay_drop_category_display_unique() {
    let labels: BTreeSet<String> = ReplayDropCategory::ALL.iter().map(|c| c.to_string()).collect();
    assert_eq!(labels.len(), 5);
}

#[test]
fn enrichment_replay_drop_category_is_security_sensitive() {
    assert!(ReplayDropCategory::AuthenticationFailure.is_security_sensitive());
    assert!(ReplayDropCategory::PolicyViolation.is_security_sensitive());
    assert!(!ReplayDropCategory::TimeBudgetExceeded.is_security_sensitive());
    assert!(!ReplayDropCategory::ProtocolMismatch.is_security_sensitive());
    assert!(!ReplayDropCategory::EncodingError.is_security_sensitive());
}

#[test]
fn enrichment_replay_drop_category_serde_roundtrip() {
    for cat in ReplayDropCategory::ALL {
        let json = serde_json::to_string(cat).unwrap();
        let back: ReplayDropCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *cat);
    }
}

// ===========================================================================
// ReplayDropEntry
// ===========================================================================

#[test]
fn enrichment_replay_drop_entry_within_budget() {
    let e = ReplayDropEntry::new(ReplayDropCategory::TimeBudgetExceeded, 2, 1000, 50_000);
    assert!(e.within_budget);
    assert_eq!(e.drop_rate_millionths, 2000);
}

#[test]
fn enrichment_replay_drop_entry_over_budget() {
    let e = ReplayDropEntry::new(ReplayDropCategory::EncodingError, 100, 1000, 50_000);
    assert!(!e.within_budget);
    assert_eq!(e.drop_rate_millionths, 100_000);
}

#[test]
fn enrichment_replay_drop_entry_zero_replays_zero_drops() {
    let e = ReplayDropEntry::new(ReplayDropCategory::ProtocolMismatch, 0, 0, 50_000);
    assert!(e.within_budget);
    assert_eq!(e.drop_rate_millionths, 0);
}

#[test]
fn enrichment_replay_drop_entry_zero_replays_with_drops() {
    let e = ReplayDropEntry::new(ReplayDropCategory::ProtocolMismatch, 5, 0, 50_000);
    assert!(!e.within_budget);
    assert_eq!(e.drop_rate_millionths, 1_000_000);
}

#[test]
fn enrichment_replay_drop_entry_serde_roundtrip() {
    let e = ReplayDropEntry::new(ReplayDropCategory::AuthenticationFailure, 3, 100, 50_000);
    let json = serde_json::to_string(&e).unwrap();
    let back: ReplayDropEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

// ===========================================================================
// DegradedModeKind
// ===========================================================================

#[test]
fn enrichment_degraded_mode_kind_all_count() {
    assert_eq!(DegradedModeKind::ALL.len(), 5);
}

#[test]
fn enrichment_degraded_mode_kind_display_unique() {
    let labels: BTreeSet<String> = DegradedModeKind::ALL.iter().map(|k| k.to_string()).collect();
    assert_eq!(labels.len(), 5);
}

#[test]
fn enrichment_degraded_mode_kind_severity_rank_monotonic() {
    let kinds = DegradedModeKind::ALL;
    for pair in kinds.windows(2) {
        assert!(pair[0].severity_rank() < pair[1].severity_rank());
    }
}

#[test]
fn enrichment_degraded_mode_kind_is_terminal() {
    assert!(DegradedModeKind::Disconnected.is_terminal());
    assert!(!DegradedModeKind::ReducedBandwidth.is_terminal());
    assert!(!DegradedModeKind::ReadOnly.is_terminal());
}

#[test]
fn enrichment_degraded_mode_kind_serde_roundtrip() {
    for kind in DegradedModeKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: DegradedModeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *kind);
    }
}

// ===========================================================================
// DegradedModePolicy
// ===========================================================================

#[test]
fn enrichment_degraded_mode_policy_for_kind_reduced_bandwidth() {
    let p = DegradedModePolicy::for_kind(DegradedModeKind::ReducedBandwidth);
    assert!(!p.requires_operator_ack);
    assert!(p.auto_recovery);
    assert_eq!(p.max_duration_ns, DEFAULT_MAX_DEGRADED_DURATION_NS);
}

#[test]
fn enrichment_degraded_mode_policy_for_kind_disconnected() {
    let p = DegradedModePolicy::for_kind(DegradedModeKind::Disconnected);
    assert!(p.requires_operator_ack);
    assert!(!p.auto_recovery);
    assert_eq!(p.max_duration_ns, 0);
}

#[test]
fn enrichment_degraded_mode_policy_exceeds_duration() {
    let p = DegradedModePolicy::for_kind(DegradedModeKind::IncreasedLatency);
    assert!(!p.exceeds_duration(p.max_duration_ns));
    assert!(p.exceeds_duration(p.max_duration_ns + 1));
}

#[test]
fn enrichment_degraded_mode_policy_can_auto_recover() {
    assert!(DegradedModePolicy::for_kind(DegradedModeKind::ReducedBandwidth).can_auto_recover());
    assert!(!DegradedModePolicy::for_kind(DegradedModeKind::Disconnected).can_auto_recover());
    assert!(!DegradedModePolicy::for_kind(DegradedModeKind::ReadOnly).can_auto_recover());
}

#[test]
fn enrichment_degraded_mode_policy_serde_roundtrip() {
    for kind in DegradedModeKind::ALL {
        let p = DegradedModePolicy::for_kind(*kind);
        let json = serde_json::to_string(&p).unwrap();
        let back: DegradedModePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }
}

// ===========================================================================
// ObservabilityClaimDelta
// ===========================================================================

#[test]
fn enrichment_claim_delta_within_tolerance() {
    let d = ObservabilityClaimDelta::new("claim-1", 900_000, 910_000, 50_000);
    assert!(d.within_tolerance);
    assert_eq!(d.delta_millionths, 10_000);
}

#[test]
fn enrichment_claim_delta_outside_tolerance() {
    let d = ObservabilityClaimDelta::new("claim-2", 900_000, 960_000, 50_000);
    assert!(!d.within_tolerance);
    assert_eq!(d.delta_millionths, 60_000);
}

#[test]
fn enrichment_claim_delta_relative_drift() {
    let d = ObservabilityClaimDelta::new("claim-3", 1_000_000, 1_100_000, 200_000);
    assert_eq!(d.relative_drift_millionths(), 100_000);
}

#[test]
fn enrichment_claim_delta_relative_drift_zero_baseline() {
    let d = ObservabilityClaimDelta::new("claim-4", 0, 100, 200_000);
    assert_eq!(d.relative_drift_millionths(), 1_000_000);
}

#[test]
fn enrichment_claim_delta_serde_roundtrip() {
    let d = ObservabilityClaimDelta::new("claim-5", 500_000, 500_000, 50_000);
    let json = serde_json::to_string(&d).unwrap();
    let back: ObservabilityClaimDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}

// ===========================================================================
// GovernanceConfig
// ===========================================================================

#[test]
fn enrichment_governance_config_default_values() {
    let c = GovernanceConfig::default();
    assert_eq!(c.min_conformance, DEFAULT_MIN_CONFORMANCE);
    assert_eq!(c.max_drop_rate, DEFAULT_MAX_DROP_RATE);
    assert_eq!(c.max_degraded_duration, DEFAULT_MAX_DEGRADED_DURATION_NS);
    assert_eq!(c.min_observability_tolerance, DEFAULT_OBSERVABILITY_TOLERANCE);
    assert_eq!(c.required_axes, DEFAULT_MIN_REQUIRED_AXES);
}

#[test]
fn enrichment_governance_config_strict() {
    let c = GovernanceConfig::strict();
    assert!(c.min_conformance > DEFAULT_MIN_CONFORMANCE);
    assert!(c.max_drop_rate < DEFAULT_MAX_DROP_RATE);
    assert_eq!(c.required_axes, 6);
}

#[test]
fn enrichment_governance_config_permissive() {
    let c = GovernanceConfig::permissive();
    assert!(c.min_conformance < DEFAULT_MIN_CONFORMANCE);
    assert!(c.max_drop_rate > DEFAULT_MAX_DROP_RATE);
    assert_eq!(c.required_axes, 1);
}

#[test]
fn enrichment_governance_config_serde_roundtrip() {
    let c = GovernanceConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: GovernanceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

// ===========================================================================
// GovernanceVerdict
// ===========================================================================

#[test]
fn enrichment_governance_verdict_all_count() {
    assert_eq!(GovernanceVerdict::ALL.len(), 7);
}

#[test]
fn enrichment_governance_verdict_display_unique() {
    let labels: BTreeSet<String> = GovernanceVerdict::ALL.iter().map(|v| v.to_string()).collect();
    assert_eq!(labels.len(), 7);
}

#[test]
fn enrichment_governance_verdict_is_approved_flag() {
    assert!(GovernanceVerdict::Approved.is_approved());
    assert!(!GovernanceVerdict::Approved.is_failure());
    for v in GovernanceVerdict::ALL.iter().filter(|v| **v != GovernanceVerdict::Approved) {
        assert!(!v.is_approved());
        assert!(v.is_failure());
    }
}

#[test]
fn enrichment_governance_verdict_serde_roundtrip() {
    for v in GovernanceVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: GovernanceVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *v);
    }
}

// ===========================================================================
// GovernanceEvaluator — approved
// ===========================================================================

#[test]
fn enrichment_evaluator_approved_receipt() {
    let mut eval = GovernanceEvaluator::with_defaults();
    eval.add_conformance(ConformanceAxis::Protocol, 950, 50);
    eval.add_conformance(ConformanceAxis::Ordering, 950, 50);
    eval.add_conformance(ConformanceAxis::Encoding, 950, 50);
    eval.add_conformance(ConformanceAxis::Timeout, 950, 50);
    let receipt = eval.evaluate(ep(42));
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert!(receipt.is_approved());
    assert!(!receipt.has_violations());
    assert_eq!(receipt.violation_count(), 0);
    assert_eq!(receipt.conformance_count, 4);
}

// ===========================================================================
// GovernanceEvaluator — violations
// ===========================================================================

#[test]
fn enrichment_evaluator_conformance_violation() {
    let mut eval = GovernanceEvaluator::with_defaults();
    eval.add_conformance(ConformanceAxis::Protocol, 800, 200);
    eval.add_conformance(ConformanceAxis::Ordering, 950, 50);
    eval.add_conformance(ConformanceAxis::Encoding, 950, 50);
    eval.add_conformance(ConformanceAxis::Timeout, 950, 50);
    let receipt = eval.evaluate(ep(42));
    assert_eq!(receipt.verdict, GovernanceVerdict::ConformanceViolation);
    assert!(receipt.has_violations());
}

#[test]
fn enrichment_evaluator_insufficient_coverage() {
    let mut eval = GovernanceEvaluator::with_defaults();
    eval.add_conformance(ConformanceAxis::Protocol, 950, 50);
    eval.add_conformance(ConformanceAxis::Ordering, 950, 50);
    let receipt = eval.evaluate(ep(42));
    assert_eq!(receipt.verdict, GovernanceVerdict::InsufficientCoverage);
}

#[test]
fn enrichment_evaluator_drop_rate_exceeded() {
    let mut eval = GovernanceEvaluator::with_defaults();
    eval.add_conformance(ConformanceAxis::Protocol, 950, 50);
    eval.add_conformance(ConformanceAxis::Ordering, 950, 50);
    eval.add_conformance(ConformanceAxis::Encoding, 950, 50);
    eval.add_conformance(ConformanceAxis::Timeout, 950, 50);
    eval.add_replay_drop(ReplayDropCategory::TimeBudgetExceeded, 100, 1000);
    let receipt = eval.evaluate(ep(42));
    assert_eq!(receipt.verdict, GovernanceVerdict::DropRateExceeded);
}

#[test]
fn enrichment_evaluator_degraded_mode_violation() {
    let mut eval = GovernanceEvaluator::with_defaults();
    eval.add_conformance(ConformanceAxis::Protocol, 950, 50);
    eval.add_conformance(ConformanceAxis::Ordering, 950, 50);
    eval.add_conformance(ConformanceAxis::Encoding, 950, 50);
    eval.add_conformance(ConformanceAxis::Timeout, 950, 50);
    eval.add_degraded_mode(DegradedModeKind::ReducedBandwidth, u64::MAX, true);
    let receipt = eval.evaluate(ep(42));
    assert_eq!(receipt.verdict, GovernanceVerdict::DegradedModePolicyViolation);
}

#[test]
fn enrichment_evaluator_observability_drift() {
    let mut eval = GovernanceEvaluator::with_defaults();
    eval.add_conformance(ConformanceAxis::Protocol, 950, 50);
    eval.add_conformance(ConformanceAxis::Ordering, 950, 50);
    eval.add_conformance(ConformanceAxis::Encoding, 950, 50);
    eval.add_conformance(ConformanceAxis::Timeout, 950, 50);
    eval.add_claim_delta("claim-1", 900_000, 500_000);
    let receipt = eval.evaluate(ep(42));
    assert_eq!(receipt.verdict, GovernanceVerdict::ObservabilityDrift);
}

#[test]
fn enrichment_evaluator_multiple_violations() {
    let mut eval = GovernanceEvaluator::with_defaults();
    eval.add_conformance(ConformanceAxis::Protocol, 800, 200);
    eval.add_conformance(ConformanceAxis::Ordering, 950, 50);
    eval.add_conformance(ConformanceAxis::Encoding, 950, 50);
    eval.add_conformance(ConformanceAxis::Timeout, 950, 50);
    eval.add_replay_drop(ReplayDropCategory::TimeBudgetExceeded, 100, 1000);
    let receipt = eval.evaluate(ep(42));
    assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
}

// ===========================================================================
// GovernanceReceipt
// ===========================================================================

#[test]
fn enrichment_receipt_total_entries() {
    let mut eval = GovernanceEvaluator::with_defaults();
    eval.add_conformance(ConformanceAxis::Protocol, 950, 50);
    eval.add_conformance(ConformanceAxis::Ordering, 950, 50);
    eval.add_conformance(ConformanceAxis::Encoding, 950, 50);
    eval.add_conformance(ConformanceAxis::Timeout, 950, 50);
    eval.add_replay_drop(ReplayDropCategory::TimeBudgetExceeded, 1, 1000);
    eval.add_claim_delta("c1", 500_000, 500_000);
    let receipt = eval.evaluate(ep(42));
    assert_eq!(receipt.total_entries(), 6);
}

#[test]
fn enrichment_receipt_serde_roundtrip() {
    let mut eval = GovernanceEvaluator::with_defaults();
    eval.add_conformance(ConformanceAxis::Protocol, 950, 50);
    eval.add_conformance(ConformanceAxis::Ordering, 950, 50);
    eval.add_conformance(ConformanceAxis::Encoding, 950, 50);
    eval.add_conformance(ConformanceAxis::Timeout, 950, 50);
    let receipt = eval.evaluate(ep(42));
    let json = serde_json::to_string(&receipt).unwrap();
    let back: GovernanceReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back, receipt);
}

#[test]
fn enrichment_receipt_content_hash_deterministic() {
    let make = || {
        let mut eval = GovernanceEvaluator::with_defaults();
        eval.add_conformance(ConformanceAxis::Protocol, 950, 50);
        eval.add_conformance(ConformanceAxis::Ordering, 950, 50);
        eval.add_conformance(ConformanceAxis::Encoding, 950, 50);
        eval.add_conformance(ConformanceAxis::Timeout, 950, 50);
        eval.evaluate(ep(42))
    };
    let r1 = make();
    let r2 = make();
    assert_eq!(r1.content_hash, r2.content_hash);
}

// ===========================================================================
// GovernanceEvaluator — evidence_count / reset / verdict
// ===========================================================================

#[test]
fn enrichment_evaluator_evidence_count() {
    let mut eval = GovernanceEvaluator::with_defaults();
    assert_eq!(eval.evidence_count(), 0);
    eval.add_conformance(ConformanceAxis::Protocol, 950, 50);
    eval.add_replay_drop(ReplayDropCategory::EncodingError, 0, 100);
    eval.add_claim_delta("c1", 100, 100);
    assert_eq!(eval.evidence_count(), 3);
}

#[test]
fn enrichment_evaluator_reset() {
    let mut eval = GovernanceEvaluator::with_defaults();
    eval.add_conformance(ConformanceAxis::Protocol, 950, 50);
    eval.add_replay_drop(ReplayDropCategory::EncodingError, 0, 100);
    eval.reset();
    assert_eq!(eval.evidence_count(), 0);
}

#[test]
fn enrichment_evaluator_with_permissive_config() {
    let config = GovernanceConfig::permissive();
    let mut eval = GovernanceEvaluator::with_config(config);
    eval.add_conformance(ConformanceAxis::Protocol, 600, 400);
    let receipt = eval.evaluate(ep(1));
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
}

#[test]
fn enrichment_evaluator_serde_roundtrip() {
    let mut eval = GovernanceEvaluator::with_defaults();
    eval.add_conformance(ConformanceAxis::Protocol, 950, 50);
    eval.add_replay_drop(ReplayDropCategory::EncodingError, 1, 1000);
    let json = serde_json::to_string(&eval).unwrap();
    let back: GovernanceEvaluator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, eval);
}
