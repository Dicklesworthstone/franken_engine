#![forbid(unsafe_code)]

//! Integration tests for `hostcall_conformance_governance` (RGC-505C, bd-1lsy.6.5.3).

use frankenengine_engine::hostcall_conformance_governance::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn ep() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

// ============================================================================
// Constants
// ============================================================================

#[test]
fn test_schema_version_contains_module_name() {
    assert!(SCHEMA_VERSION.contains("hostcall-conformance-governance"));
}

#[test]
fn test_schema_version_v1() {
    assert!(SCHEMA_VERSION.contains("v1"));
}

#[test]
fn test_component_name() {
    assert_eq!(COMPONENT, "hostcall_conformance_governance");
}

#[test]
fn test_bead_id() {
    assert_eq!(BEAD_ID, "bd-1lsy.6.5.3");
}

#[test]
fn test_policy_id() {
    assert_eq!(POLICY_ID, "RGC-505C");
}

#[test]
fn test_default_min_conformance_in_range() {
    assert!(DEFAULT_MIN_CONFORMANCE > 0 && DEFAULT_MIN_CONFORMANCE <= 1_000_000);
    assert_eq!(DEFAULT_MIN_CONFORMANCE, 900_000);
}

#[test]
fn test_default_max_drop_rate_in_range() {
    assert!(DEFAULT_MAX_DROP_RATE > 0 && DEFAULT_MAX_DROP_RATE <= 1_000_000);
    assert_eq!(DEFAULT_MAX_DROP_RATE, 50_000);
}

#[test]
fn test_default_max_degraded_duration_ns() {
    assert_eq!(DEFAULT_MAX_DEGRADED_DURATION_NS, 60_000_000_000);
}

#[test]
fn test_default_observability_tolerance() {
    assert_eq!(DEFAULT_OBSERVABILITY_TOLERANCE, 50_000);
}

#[test]
fn test_default_min_required_axes() {
    assert_eq!(DEFAULT_MIN_REQUIRED_AXES, 4);
    assert!(DEFAULT_MIN_REQUIRED_AXES <= ConformanceAxis::ALL.len());
}

// ============================================================================
// ConformanceAxis
// ============================================================================

#[test]
fn test_conformance_axis_all_length() {
    assert_eq!(ConformanceAxis::ALL.len(), 6);
}

#[test]
fn test_conformance_axis_display_matches_as_str() {
    for axis in ConformanceAxis::ALL {
        assert_eq!(format!("{axis}"), axis.as_str());
    }
}

#[test]
fn test_conformance_axis_ordering() {
    assert!(ConformanceAxis::Protocol < ConformanceAxis::Authorization);
}

#[test]
fn test_conformance_axis_serde_roundtrip() {
    for axis in ConformanceAxis::ALL {
        let json = serde_json::to_string(axis).unwrap();
        let back: ConformanceAxis = serde_json::from_str(&json).unwrap();
        assert_eq!(*axis, back);
    }
}

// ============================================================================
// ConformanceResult
// ============================================================================

#[test]
fn test_conformance_result_perfect_pass() {
    let r = ConformanceResult::new(ConformanceAxis::Protocol, 100, 0, 900_000);
    assert!(r.passes);
    assert_eq!(r.conformance_ratio_millionths, 1_000_000);
    assert_eq!(r.total_count(), 100);
}

#[test]
fn test_conformance_result_threshold_fail() {
    let r = ConformanceResult::new(ConformanceAxis::Encoding, 80, 20, 900_000);
    assert!(!r.passes);
    assert_eq!(r.conformance_ratio_millionths, 800_000);
}

#[test]
fn test_conformance_result_zero_total() {
    let r = ConformanceResult::new(ConformanceAxis::Timeout, 0, 0, 900_000);
    assert_eq!(r.conformance_ratio_millionths, 0);
    assert_eq!(r.total_count(), 0);
    assert!(!r.passes);
}

#[test]
fn test_conformance_result_display_contains_axis() {
    let r = ConformanceResult::new(ConformanceAxis::Authentication, 95, 5, 900_000);
    let s = format!("{r}");
    assert!(s.contains("authentication"));
    assert!(s.contains("PASS"));
}

// ============================================================================
// ReplayDropCategory
// ============================================================================

#[test]
fn test_replay_drop_category_all_length() {
    assert_eq!(ReplayDropCategory::ALL.len(), 5);
}

#[test]
fn test_replay_drop_category_display() {
    for cat in ReplayDropCategory::ALL {
        assert_eq!(format!("{cat}"), cat.as_str());
    }
}

#[test]
fn test_replay_drop_category_security_sensitive() {
    assert!(ReplayDropCategory::AuthenticationFailure.is_security_sensitive());
    assert!(ReplayDropCategory::PolicyViolation.is_security_sensitive());
    assert!(!ReplayDropCategory::TimeBudgetExceeded.is_security_sensitive());
    assert!(!ReplayDropCategory::ProtocolMismatch.is_security_sensitive());
    assert!(!ReplayDropCategory::EncodingError.is_security_sensitive());
}

#[test]
fn test_replay_drop_category_serde_roundtrip() {
    for cat in ReplayDropCategory::ALL {
        let json = serde_json::to_string(cat).unwrap();
        let back: ReplayDropCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, back);
    }
}

// ============================================================================
// ReplayDropEntry
// ============================================================================

#[test]
fn test_replay_drop_entry_within_budget() {
    let e = ReplayDropEntry::new(ReplayDropCategory::TimeBudgetExceeded, 1, 1000, 50_000);
    assert!(e.within_budget);
    assert_eq!(e.drop_rate_millionths, 1000);
}

#[test]
fn test_replay_drop_entry_over_budget() {
    let e = ReplayDropEntry::new(ReplayDropCategory::ProtocolMismatch, 100, 1000, 50_000);
    assert!(!e.within_budget);
    assert_eq!(e.drop_rate_millionths, 100_000);
}

#[test]
fn test_replay_drop_entry_zero_total() {
    let e = ReplayDropEntry::new(ReplayDropCategory::EncodingError, 0, 0, 50_000);
    assert_eq!(e.drop_rate_millionths, 0);
    assert!(e.within_budget);
}

#[test]
fn test_replay_drop_entry_display() {
    let e = ReplayDropEntry::new(ReplayDropCategory::PolicyViolation, 5, 100, 50_000);
    let s = format!("{e}");
    assert!(s.contains("policy_violation"));
}

// ============================================================================
// DegradedModeKind
// ============================================================================

#[test]
fn test_degraded_mode_kind_all_length() {
    assert_eq!(DegradedModeKind::ALL.len(), 5);
}

#[test]
fn test_degraded_mode_kind_severity_ordering() {
    assert!(
        DegradedModeKind::ReducedBandwidth.severity_rank()
            < DegradedModeKind::Disconnected.severity_rank()
    );
    assert!(
        DegradedModeKind::IncreasedLatency.severity_rank()
            < DegradedModeKind::ReadOnly.severity_rank()
    );
}

#[test]
fn test_degraded_mode_kind_is_terminal() {
    assert!(DegradedModeKind::Disconnected.is_terminal());
    assert!(!DegradedModeKind::ReducedBandwidth.is_terminal());
    assert!(!DegradedModeKind::IncreasedLatency.is_terminal());
    assert!(!DegradedModeKind::PartialFunctionality.is_terminal());
    assert!(!DegradedModeKind::ReadOnly.is_terminal());
}

#[test]
fn test_degraded_mode_kind_display() {
    for kind in DegradedModeKind::ALL {
        assert_eq!(format!("{kind}"), kind.as_str());
    }
}

// ============================================================================
// DegradedModePolicy
// ============================================================================

#[test]
fn test_degraded_mode_policy_for_kind_reduced_bandwidth() {
    let p = DegradedModePolicy::for_kind(DegradedModeKind::ReducedBandwidth);
    assert_eq!(p.max_duration_ns, DEFAULT_MAX_DEGRADED_DURATION_NS);
    assert!(!p.requires_operator_ack);
    assert!(p.auto_recovery);
}

#[test]
fn test_degraded_mode_policy_for_kind_disconnected() {
    let p = DegradedModePolicy::for_kind(DegradedModeKind::Disconnected);
    assert_eq!(p.max_duration_ns, 0);
    assert!(p.requires_operator_ack);
    assert!(!p.auto_recovery);
}

#[test]
fn test_degraded_mode_policy_exceeds_duration() {
    let p = DegradedModePolicy::for_kind(DegradedModeKind::ReducedBandwidth);
    assert!(!p.exceeds_duration(DEFAULT_MAX_DEGRADED_DURATION_NS));
    assert!(p.exceeds_duration(DEFAULT_MAX_DEGRADED_DURATION_NS + 1));
}

#[test]
fn test_degraded_mode_policy_can_auto_recover() {
    let p = DegradedModePolicy::for_kind(DegradedModeKind::ReducedBandwidth);
    assert!(p.can_auto_recover());

    let p2 = DegradedModePolicy::for_kind(DegradedModeKind::Disconnected);
    assert!(!p2.can_auto_recover());

    let p3 = DegradedModePolicy::for_kind(DegradedModeKind::ReadOnly);
    assert!(!p3.can_auto_recover());
}

// ============================================================================
// ObservabilityClaimDelta
// ============================================================================

#[test]
fn test_claim_delta_within_tolerance() {
    let d = ObservabilityClaimDelta::new("claim_a", 500_000, 520_000, 50_000);
    assert!(d.within_tolerance);
    assert_eq!(d.delta_millionths, 20_000);
}

#[test]
fn test_claim_delta_exceeds_tolerance() {
    let d = ObservabilityClaimDelta::new("claim_b", 500_000, 600_000, 50_000);
    assert!(!d.within_tolerance);
    assert_eq!(d.delta_millionths, 100_000);
}

#[test]
fn test_claim_delta_negative_drift() {
    let d = ObservabilityClaimDelta::new("claim_c", 600_000, 500_000, 50_000);
    assert!(!d.within_tolerance);
    assert_eq!(d.delta_millionths, 100_000);
}

#[test]
fn test_claim_delta_relative_drift() {
    let d = ObservabilityClaimDelta::new("claim_d", 1_000_000, 900_000, 200_000);
    assert_eq!(d.relative_drift_millionths(), 100_000);
}

#[test]
fn test_claim_delta_display() {
    let d = ObservabilityClaimDelta::new("claim_e", 500_000, 550_000, 100_000);
    let s = format!("{d}");
    assert!(s.contains("claim_e"));
    assert!(s.contains("WITHIN"));
}

// ============================================================================
// GovernanceConfig
// ============================================================================

#[test]
fn test_governance_config_default() {
    let c = GovernanceConfig::default();
    assert_eq!(c.min_conformance, DEFAULT_MIN_CONFORMANCE);
    assert_eq!(c.max_drop_rate, DEFAULT_MAX_DROP_RATE);
    assert_eq!(c.max_degraded_duration, DEFAULT_MAX_DEGRADED_DURATION_NS);
    assert_eq!(
        c.min_observability_tolerance,
        DEFAULT_OBSERVABILITY_TOLERANCE
    );
    assert_eq!(c.required_axes, DEFAULT_MIN_REQUIRED_AXES);
}

#[test]
fn test_governance_config_strict() {
    let c = GovernanceConfig::strict();
    assert!(c.min_conformance > DEFAULT_MIN_CONFORMANCE);
    assert!(c.max_drop_rate < DEFAULT_MAX_DROP_RATE);
    assert_eq!(c.required_axes, 6);
}

#[test]
fn test_governance_config_permissive() {
    let c = GovernanceConfig::permissive();
    assert!(c.min_conformance < DEFAULT_MIN_CONFORMANCE);
    assert!(c.max_drop_rate > DEFAULT_MAX_DROP_RATE);
    assert_eq!(c.required_axes, 1);
}

// ============================================================================
// GovernanceVerdict
// ============================================================================

#[test]
fn test_verdict_all_length() {
    assert_eq!(GovernanceVerdict::ALL.len(), 7);
}

#[test]
fn test_verdict_approved_is_approved() {
    assert!(GovernanceVerdict::Approved.is_approved());
    assert!(!GovernanceVerdict::Approved.is_failure());
}

#[test]
fn test_verdict_failures_are_failure() {
    for v in GovernanceVerdict::ALL {
        if *v != GovernanceVerdict::Approved {
            assert!(v.is_failure());
            assert!(!v.is_approved());
        }
    }
}

#[test]
fn test_verdict_display_matches_as_str() {
    for v in GovernanceVerdict::ALL {
        assert_eq!(format!("{v}"), v.as_str());
    }
}

#[test]
fn test_verdict_serde_roundtrip() {
    for v in GovernanceVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: GovernanceVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ============================================================================
// GovernanceEvaluator lifecycle
// ============================================================================

#[test]
fn test_evaluator_with_defaults_creates_empty() {
    let ev = GovernanceEvaluator::with_defaults();
    assert_eq!(ev.evidence_count(), 0);
}

#[test]
fn test_evaluator_with_config_uses_config() {
    let cfg = GovernanceConfig::strict();
    let ev = GovernanceEvaluator::with_config(cfg.clone());
    assert_eq!(ev.config, cfg);
}

#[test]
fn test_evaluator_all_passing_conformance() {
    let mut ev = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 95, 5);
    }
    let receipt = ev.evaluate(ep());
    assert!(receipt.is_approved());
    assert_eq!(receipt.violation_count(), 0);
    assert_eq!(receipt.conformance_count, 6);
}

#[test]
fn test_evaluator_conformance_violation() {
    let mut ev = GovernanceEvaluator::with_defaults();
    ev.add_conformance(ConformanceAxis::Protocol, 50, 50);
    ev.add_conformance(ConformanceAxis::Ordering, 95, 5);
    ev.add_conformance(ConformanceAxis::Encoding, 95, 5);
    ev.add_conformance(ConformanceAxis::Timeout, 95, 5);
    let receipt = ev.evaluate(ep());
    assert!(!receipt.is_approved());
    assert!(receipt.has_violations());
}

#[test]
fn test_evaluator_drop_rate_exceeded() {
    let mut ev = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 99, 1);
    }
    ev.add_replay_drop(ReplayDropCategory::TimeBudgetExceeded, 100, 100);
    let receipt = ev.evaluate(ep());
    assert!(!receipt.is_approved());
}

#[test]
fn test_evaluator_degraded_mode_violation() {
    let mut ev = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
    ev.add_degraded_mode(DegradedModeKind::Disconnected, 1_000, false);
    let receipt = ev.evaluate(ep());
    assert!(!receipt.is_approved());
}

#[test]
fn test_evaluator_observability_drift() {
    let cfg = GovernanceConfig {
        min_observability_tolerance: 10_000,
        required_axes: 0,
        ..GovernanceConfig::default()
    };
    let mut ev = GovernanceEvaluator::with_config(cfg);
    ev.add_claim_delta("metric_x", 500_000, 600_000);
    let receipt = ev.evaluate(ep());
    assert!(!receipt.is_approved());
}

#[test]
fn test_evaluator_insufficient_coverage() {
    let mut ev = GovernanceEvaluator::with_defaults();
    ev.add_conformance(ConformanceAxis::Protocol, 99, 1);
    let receipt = ev.evaluate(ep());
    assert!(!receipt.is_approved());
}

#[test]
fn test_evaluator_multiple_violations() {
    let mut ev = GovernanceEvaluator::with_defaults();
    // Insufficient coverage (only 1 axis, need 4)
    ev.add_conformance(ConformanceAxis::Protocol, 50, 50);
    // Over-budget drop
    ev.add_replay_drop(ReplayDropCategory::ProtocolMismatch, 500, 1000);
    let receipt = ev.evaluate(ep());
    assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
}

#[test]
fn test_evaluator_reset_clears_evidence() {
    let mut ev = GovernanceEvaluator::with_defaults();
    ev.add_conformance(ConformanceAxis::Protocol, 90, 10);
    ev.add_replay_drop(ReplayDropCategory::EncodingError, 1, 100);
    assert!(ev.evidence_count() > 0);
    ev.reset();
    assert_eq!(ev.evidence_count(), 0);
}

// ============================================================================
// GovernanceReceipt
// ============================================================================

#[test]
fn test_receipt_schema_version_populated() {
    let mut ev = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 95, 5);
    }
    let receipt = ev.evaluate(ep());
    assert_eq!(receipt.schema_version, SCHEMA_VERSION);
}

#[test]
fn test_receipt_epoch_matches() {
    let mut ev = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
    ev.add_conformance(ConformanceAxis::Protocol, 100, 0);
    let receipt = ev.evaluate(ep());
    assert_eq!(receipt.epoch, ep());
}

#[test]
fn test_receipt_total_entries() {
    let mut ev = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
    ev.add_conformance(ConformanceAxis::Protocol, 100, 0);
    ev.add_replay_drop(ReplayDropCategory::TimeBudgetExceeded, 1, 1000);
    ev.add_claim_delta("c1", 500_000, 500_000);
    let receipt = ev.evaluate(ep());
    assert_eq!(receipt.total_entries(), 3);
}

#[test]
fn test_receipt_display_contains_component() {
    let mut ev = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
    ev.add_conformance(ConformanceAxis::Protocol, 100, 0);
    let receipt = ev.evaluate(ep());
    let s = format!("{receipt}");
    assert!(s.contains(COMPONENT));
}

// ============================================================================
// Content hash determinism
// ============================================================================

#[test]
fn test_content_hash_deterministic_across_evaluations() {
    let build = || {
        let mut ev = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
        for axis in ConformanceAxis::ALL {
            ev.add_conformance(*axis, 95, 5);
        }
        ev.evaluate(ep())
    };
    let r1 = build();
    let r2 = build();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn test_content_hash_changes_with_different_evidence() {
    let mut ev1 = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
    ev1.add_conformance(ConformanceAxis::Protocol, 100, 0);
    let r1 = ev1.evaluate(ep());

    let mut ev2 = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
    ev2.add_conformance(ConformanceAxis::Protocol, 50, 50);
    let r2 = ev2.evaluate(ep());

    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn test_content_hash_changes_with_different_epoch() {
    let mut ev1 = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
    ev1.add_conformance(ConformanceAxis::Protocol, 100, 0);
    let r1 = ev1.evaluate(SecurityEpoch::from_raw(1));

    let mut ev2 = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
    ev2.add_conformance(ConformanceAxis::Protocol, 100, 0);
    let r2 = ev2.evaluate(SecurityEpoch::from_raw(2));

    assert_ne!(r1.content_hash, r2.content_hash);
}

// ============================================================================
// E2E scenarios
// ============================================================================

#[test]
fn test_e2e_all_axes_passing_approved() {
    let mut ev = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 99, 1);
    }
    ev.add_replay_drop(ReplayDropCategory::TimeBudgetExceeded, 1, 1000);
    ev.add_degraded_mode(DegradedModeKind::ReducedBandwidth, 1_000, true);
    ev.add_claim_delta("latency", 500_000, 510_000);
    let receipt = ev.evaluate(ep());
    assert!(receipt.is_approved());
    assert!(!receipt.has_violations());
    assert_eq!(receipt.conformance_count, 6);
    assert_eq!(receipt.drop_entry_count, 1);
    assert_eq!(receipt.degraded_policy_count, 1);
    assert_eq!(receipt.claim_delta_count, 1);
}

#[test]
fn test_e2e_strict_config_rejects_low_conformance() {
    let mut ev = GovernanceEvaluator::with_config(GovernanceConfig::strict());
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 90, 10);
    }
    let receipt = ev.evaluate(ep());
    assert!(!receipt.is_approved());
}

#[test]
fn test_e2e_permissive_config_approves_low_conformance() {
    let mut ev = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
    ev.add_conformance(ConformanceAxis::Protocol, 50, 50);
    let receipt = ev.evaluate(ep());
    assert!(receipt.is_approved());
}

#[test]
fn test_e2e_degraded_mode_with_ack_passes() {
    let mut ev = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
    ev.add_degraded_mode(DegradedModeKind::PartialFunctionality, 1_000, true);
    let receipt = ev.evaluate(ep());
    assert!(receipt.is_approved());
}

#[test]
fn test_e2e_degraded_mode_without_ack_fails() {
    let mut ev = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
    ev.add_degraded_mode(DegradedModeKind::PartialFunctionality, 1_000, false);
    let receipt = ev.evaluate(ep());
    assert!(!receipt.is_approved());
}

#[test]
fn test_e2e_verdict_convenience_method() {
    let mut ev = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
    ev.add_conformance(ConformanceAxis::Protocol, 95, 5);
    let verdict = ev.verdict(ep());
    assert!(verdict.is_approved());
}

#[test]
fn test_e2e_serde_roundtrip_receipt() {
    let mut ev = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 95, 5);
    }
    let receipt = ev.evaluate(ep());
    let json = serde_json::to_string(&receipt).unwrap();
    let back: GovernanceReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt.verdict, back.verdict);
    assert_eq!(receipt.content_hash, back.content_hash);
}

#[test]
fn test_e2e_security_sensitive_drop_over_budget() {
    let mut ev = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 99, 1);
    }
    ev.add_replay_drop(ReplayDropCategory::AuthenticationFailure, 200, 1000);
    let receipt = ev.evaluate(ep());
    assert!(!receipt.is_approved());
    assert!(ReplayDropCategory::AuthenticationFailure.is_security_sensitive());
}
