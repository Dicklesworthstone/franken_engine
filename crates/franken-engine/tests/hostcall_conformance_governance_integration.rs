#![forbid(unsafe_code)]
#![allow(
    clippy::too_many_arguments,
    clippy::clone_on_copy,
    clippy::len_zero,
    clippy::identity_op
)]

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
    const { assert!(DEFAULT_MIN_CONFORMANCE > 0 && DEFAULT_MIN_CONFORMANCE <= 1_000_000) };
    assert_eq!(DEFAULT_MIN_CONFORMANCE, 900_000);
}

#[test]
fn test_default_max_drop_rate_in_range() {
    const { assert!(DEFAULT_MAX_DROP_RATE > 0 && DEFAULT_MAX_DROP_RATE <= 1_000_000) };
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
    const {
        assert!(DEFAULT_MIN_REQUIRED_AXES <= ConformanceAxis::ALL.len());
    }
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
fn test_replay_drop_entry_nonzero_drop_zero_total_fails_closed() {
    let e = ReplayDropEntry::new(ReplayDropCategory::EncodingError, 5, 0, 50_000);
    assert_eq!(e.drop_rate_millionths, 1_000_000);
    assert!(!e.within_budget);
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

// ============================================================================
// Enrichment tests
// ============================================================================

// ---------------------------------------------------------------------------
// ConformanceAxis — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_conformance_axis_debug_all_variants() {
    for axis in ConformanceAxis::ALL {
        let dbg = format!("{axis:?}");
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_conformance_axis_clone_eq() {
    for axis in ConformanceAxis::ALL {
        let cloned = axis.clone();
        assert_eq!(*axis, cloned);
    }
}

#[test]
fn enrichment_conformance_axis_ord_is_total() {
    for (i, a) in ConformanceAxis::ALL.iter().enumerate() {
        for (j, b) in ConformanceAxis::ALL.iter().enumerate() {
            if i < j {
                assert!(*a < *b);
            } else if i > j {
                assert!(*a > *b);
            } else {
                assert_eq!(*a, *b);
            }
        }
    }
}

#[test]
fn enrichment_conformance_axis_all_names_are_lowercase() {
    for axis in ConformanceAxis::ALL {
        let s = axis.as_str();
        assert_eq!(s, s.to_lowercase());
    }
}

#[test]
fn enrichment_conformance_axis_serde_json_field_is_snake_case() {
    for axis in ConformanceAxis::ALL {
        let json = serde_json::to_string(axis).unwrap();
        // JSON string should be surrounded by quotes
        assert!(json.starts_with('"'));
        assert!(json.ends_with('"'));
        let inner = &json[1..json.len() - 1];
        assert_eq!(inner, axis.as_str());
    }
}

#[test]
fn enrichment_conformance_axis_all_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for axis in ConformanceAxis::ALL {
        assert!(seen.insert(*axis));
    }
    assert_eq!(seen.len(), 6);
}

#[test]
fn enrichment_conformance_axis_protocol_is_first() {
    assert_eq!(ConformanceAxis::ALL[0], ConformanceAxis::Protocol);
}

#[test]
fn enrichment_conformance_axis_authorization_is_last() {
    assert_eq!(
        ConformanceAxis::ALL[ConformanceAxis::ALL.len() - 1],
        ConformanceAxis::Authorization
    );
}

// ---------------------------------------------------------------------------
// ConformanceResult — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_conformance_result_exact_threshold_passes() {
    let r = ConformanceResult::new(ConformanceAxis::Protocol, 90, 10, 900_000);
    assert_eq!(r.conformance_ratio_millionths, 900_000);
    assert!(r.passes);
}

#[test]
fn enrichment_conformance_result_one_below_threshold_fails() {
    // 89/100 = 890_000 ppm, threshold 900_000
    let r = ConformanceResult::new(ConformanceAxis::Protocol, 89, 11, 900_000);
    assert_eq!(r.conformance_ratio_millionths, 890_000);
    assert!(!r.passes);
}

#[test]
fn enrichment_conformance_result_all_fail_zero_ratio() {
    let r = ConformanceResult::new(ConformanceAxis::Encoding, 0, 100, 0);
    assert_eq!(r.conformance_ratio_millionths, 0);
    assert!(r.passes); // threshold 0 means 0 >= 0
}

#[test]
fn enrichment_conformance_result_total_count_large() {
    let r = ConformanceResult::new(ConformanceAxis::Timeout, u64::MAX / 2, 1, 0);
    assert_eq!(r.total_count(), u64::MAX / 2 + 1);
}

#[test]
fn enrichment_conformance_result_clone_eq() {
    let r = ConformanceResult::new(ConformanceAxis::Authentication, 50, 50, 500_000);
    let cloned = r.clone();
    assert_eq!(r, cloned);
}

#[test]
fn enrichment_conformance_result_debug_not_empty() {
    let r = ConformanceResult::new(ConformanceAxis::Protocol, 10, 0, 900_000);
    let dbg = format!("{r:?}");
    assert!(dbg.contains("ConformanceResult"));
}

#[test]
fn enrichment_conformance_result_display_fail_case() {
    let r = ConformanceResult::new(ConformanceAxis::Ordering, 10, 90, 900_000);
    let s = format!("{r}");
    assert!(s.contains("FAIL"));
    assert!(s.contains("ordering"));
}

#[test]
fn enrichment_conformance_result_serde_roundtrip_all_axes() {
    for axis in ConformanceAxis::ALL {
        let r = ConformanceResult::new(*axis, 77, 23, 750_000);
        let json = serde_json::to_string(&r).unwrap();
        let back: ConformanceResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

#[test]
fn enrichment_conformance_result_serde_field_names() {
    let r = ConformanceResult::new(ConformanceAxis::Protocol, 10, 5, 600_000);
    let val: serde_json::Value = serde_json::to_value(&r).unwrap();
    let obj = val.as_object().unwrap();
    assert!(obj.contains_key("axis"));
    assert!(obj.contains_key("pass_count"));
    assert!(obj.contains_key("fail_count"));
    assert!(obj.contains_key("conformance_ratio_millionths"));
    assert!(obj.contains_key("passes"));
}

#[test]
fn enrichment_conformance_result_display_contains_ppm() {
    let r = ConformanceResult::new(ConformanceAxis::Authorization, 99, 1, 900_000);
    let s = format!("{r}");
    assert!(s.contains("ppm"));
}

#[test]
fn enrichment_conformance_result_total_count_saturating() {
    let r = ConformanceResult::new(ConformanceAxis::Protocol, u64::MAX, 1, 0);
    // saturating_add means total_count is u64::MAX
    assert_eq!(r.total_count(), u64::MAX);
}

// ---------------------------------------------------------------------------
// ReplayDropCategory — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_replay_drop_category_debug_all() {
    for cat in ReplayDropCategory::ALL {
        let dbg = format!("{cat:?}");
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_replay_drop_category_clone_eq() {
    for cat in ReplayDropCategory::ALL {
        let cloned = cat.clone();
        assert_eq!(*cat, cloned);
    }
}

#[test]
fn enrichment_replay_drop_category_ord_consistent() {
    assert!(ReplayDropCategory::TimeBudgetExceeded < ReplayDropCategory::ProtocolMismatch);
    assert!(ReplayDropCategory::ProtocolMismatch < ReplayDropCategory::EncodingError);
    assert!(ReplayDropCategory::EncodingError < ReplayDropCategory::AuthenticationFailure);
    assert!(ReplayDropCategory::AuthenticationFailure < ReplayDropCategory::PolicyViolation);
}

#[test]
fn enrichment_replay_drop_category_all_names_snake_case() {
    for cat in ReplayDropCategory::ALL {
        let name = cat.as_str();
        assert_eq!(name, name.to_lowercase());
        assert!(!name.contains('-'));
    }
}

#[test]
fn enrichment_replay_drop_category_security_sensitive_count() {
    let sensitive_count = ReplayDropCategory::ALL
        .iter()
        .filter(|c| c.is_security_sensitive())
        .count();
    assert_eq!(sensitive_count, 2);
}

// ---------------------------------------------------------------------------
// ReplayDropEntry — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_replay_drop_entry_exact_budget_is_within() {
    // drop_rate = 50/1000 * 1_000_000 = 50_000 exactly
    let e = ReplayDropEntry::new(ReplayDropCategory::TimeBudgetExceeded, 50, 1000, 50_000);
    assert_eq!(e.drop_rate_millionths, 50_000);
    assert!(e.within_budget);
}

#[test]
fn enrichment_replay_drop_entry_one_over_budget() {
    // drop_rate = 51/1000 * 1_000_000 = 51_000 > 50_000
    let e = ReplayDropEntry::new(ReplayDropCategory::EncodingError, 51, 1000, 50_000);
    assert_eq!(e.drop_rate_millionths, 51_000);
    assert!(!e.within_budget);
}

#[test]
fn enrichment_replay_drop_entry_debug_not_empty() {
    let e = ReplayDropEntry::new(ReplayDropCategory::ProtocolMismatch, 1, 100, 50_000);
    let dbg = format!("{e:?}");
    assert!(dbg.contains("ReplayDropEntry"));
}

#[test]
fn enrichment_replay_drop_entry_clone_eq() {
    let e = ReplayDropEntry::new(ReplayDropCategory::AuthenticationFailure, 3, 200, 50_000);
    let cloned = e.clone();
    assert_eq!(e, cloned);
}

#[test]
fn enrichment_replay_drop_entry_display_within_budget_text() {
    let e = ReplayDropEntry::new(ReplayDropCategory::TimeBudgetExceeded, 1, 1000, 50_000);
    let s = format!("{e}");
    assert!(s.contains("WITHIN_BUDGET"));
}

#[test]
fn enrichment_replay_drop_entry_display_over_budget_text() {
    let e = ReplayDropEntry::new(ReplayDropCategory::PolicyViolation, 500, 1000, 50_000);
    let s = format!("{e}");
    assert!(s.contains("OVER_BUDGET"));
}

#[test]
fn enrichment_replay_drop_entry_serde_field_names() {
    let e = ReplayDropEntry::new(ReplayDropCategory::EncodingError, 2, 100, 50_000);
    let val: serde_json::Value = serde_json::to_value(&e).unwrap();
    let obj = val.as_object().unwrap();
    assert!(obj.contains_key("category"));
    assert!(obj.contains_key("drop_count"));
    assert!(obj.contains_key("total_replays"));
    assert!(obj.contains_key("drop_rate_millionths"));
    assert!(obj.contains_key("within_budget"));
}

#[test]
fn enrichment_replay_drop_entry_all_categories_roundtrip() {
    for cat in ReplayDropCategory::ALL {
        let e = ReplayDropEntry::new(*cat, 5, 200, 50_000);
        let json = serde_json::to_string(&e).unwrap();
        let back: ReplayDropEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}

#[test]
fn enrichment_replay_drop_entry_max_rate_zero_always_over() {
    let e = ReplayDropEntry::new(ReplayDropCategory::TimeBudgetExceeded, 1, 100, 0);
    assert!(!e.within_budget);
}

#[test]
fn enrichment_replay_drop_entry_max_rate_million_always_within() {
    let e = ReplayDropEntry::new(ReplayDropCategory::PolicyViolation, 999, 1000, 1_000_000);
    assert!(e.within_budget);
}

// ---------------------------------------------------------------------------
// DegradedModeKind — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_degraded_mode_kind_debug_all() {
    for kind in DegradedModeKind::ALL {
        let dbg = format!("{kind:?}");
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_degraded_mode_kind_clone_eq() {
    for kind in DegradedModeKind::ALL {
        let cloned = kind.clone();
        assert_eq!(*kind, cloned);
    }
}

#[test]
fn enrichment_degraded_mode_kind_severity_rank_unique() {
    let mut ranks = std::collections::BTreeSet::new();
    for kind in DegradedModeKind::ALL {
        assert!(ranks.insert(kind.severity_rank()));
    }
    assert_eq!(ranks.len(), 5);
}

#[test]
fn enrichment_degraded_mode_kind_severity_rank_starts_at_one() {
    assert_eq!(DegradedModeKind::ReducedBandwidth.severity_rank(), 1);
}

#[test]
fn enrichment_degraded_mode_kind_severity_rank_ends_at_five() {
    assert_eq!(DegradedModeKind::Disconnected.severity_rank(), 5);
}

#[test]
fn enrichment_degraded_mode_kind_only_disconnected_is_terminal() {
    let terminal_count = DegradedModeKind::ALL
        .iter()
        .filter(|k| k.is_terminal())
        .count();
    assert_eq!(terminal_count, 1);
}

#[test]
fn enrichment_degraded_mode_kind_serde_json_snake_case() {
    for kind in DegradedModeKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let inner = &json[1..json.len() - 1];
        assert_eq!(inner, kind.as_str());
    }
}

// ---------------------------------------------------------------------------
// DegradedModePolicy — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_degraded_mode_policy_for_all_kinds() {
    for kind in DegradedModeKind::ALL {
        let p = DegradedModePolicy::for_kind(*kind);
        assert_eq!(p.kind, *kind);
    }
}

#[test]
fn enrichment_degraded_mode_policy_increased_latency() {
    let p = DegradedModePolicy::for_kind(DegradedModeKind::IncreasedLatency);
    assert_eq!(p.max_duration_ns, DEFAULT_MAX_DEGRADED_DURATION_NS);
    assert!(!p.requires_operator_ack);
    assert!(p.auto_recovery);
    assert!(p.can_auto_recover());
}

#[test]
fn enrichment_degraded_mode_policy_partial_functionality() {
    let p = DegradedModePolicy::for_kind(DegradedModeKind::PartialFunctionality);
    assert_eq!(p.max_duration_ns, DEFAULT_MAX_DEGRADED_DURATION_NS * 2);
    assert!(p.requires_operator_ack);
    assert!(p.auto_recovery);
    assert!(p.can_auto_recover());
}

#[test]
fn enrichment_degraded_mode_policy_read_only() {
    let p = DegradedModePolicy::for_kind(DegradedModeKind::ReadOnly);
    assert_eq!(p.max_duration_ns, DEFAULT_MAX_DEGRADED_DURATION_NS * 5);
    assert!(p.requires_operator_ack);
    assert!(!p.auto_recovery);
    assert!(!p.can_auto_recover());
}

#[test]
fn enrichment_degraded_mode_policy_disconnected_always_exceeds() {
    let p = DegradedModePolicy::for_kind(DegradedModeKind::Disconnected);
    // max_duration_ns is 0, so any non-zero duration exceeds
    assert!(p.exceeds_duration(1));
    // zero does not exceed
    assert!(!p.exceeds_duration(0));
}

#[test]
fn enrichment_degraded_mode_policy_debug_not_empty() {
    let p = DegradedModePolicy::for_kind(DegradedModeKind::ReducedBandwidth);
    let dbg = format!("{p:?}");
    assert!(dbg.contains("DegradedModePolicy"));
}

#[test]
fn enrichment_degraded_mode_policy_display_contains_kind() {
    for kind in DegradedModeKind::ALL {
        let p = DegradedModePolicy::for_kind(*kind);
        let s = format!("{p}");
        assert!(s.contains(kind.as_str()));
        assert!(s.contains("degraded-policy"));
    }
}

#[test]
fn enrichment_degraded_mode_policy_serde_roundtrip_all() {
    for kind in DegradedModeKind::ALL {
        let p = DegradedModePolicy::for_kind(*kind);
        let json = serde_json::to_string(&p).unwrap();
        let back: DegradedModePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}

#[test]
fn enrichment_degraded_mode_policy_serde_field_names() {
    let p = DegradedModePolicy::for_kind(DegradedModeKind::ReadOnly);
    let val: serde_json::Value = serde_json::to_value(&p).unwrap();
    let obj = val.as_object().unwrap();
    assert!(obj.contains_key("kind"));
    assert!(obj.contains_key("max_duration_ns"));
    assert!(obj.contains_key("requires_operator_ack"));
    assert!(obj.contains_key("auto_recovery"));
}

// ---------------------------------------------------------------------------
// DegradedModeViolation — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_degraded_mode_violation_display() {
    let v = DegradedModeViolation {
        kind: DegradedModeKind::Disconnected,
        observed_duration_ns: 5000,
        max_duration_ns: 0,
        missing_operator_ack: true,
    };
    let s = format!("{v}");
    assert!(s.contains("disconnected"));
    assert!(s.contains("5000"));
    assert!(s.contains("ack_missing=true"));
}

#[test]
fn enrichment_degraded_mode_violation_debug() {
    let v = DegradedModeViolation {
        kind: DegradedModeKind::ReducedBandwidth,
        observed_duration_ns: 100,
        max_duration_ns: 50,
        missing_operator_ack: false,
    };
    let dbg = format!("{v:?}");
    assert!(dbg.contains("DegradedModeViolation"));
}

#[test]
fn enrichment_degraded_mode_violation_clone_eq() {
    let v = DegradedModeViolation {
        kind: DegradedModeKind::IncreasedLatency,
        observed_duration_ns: 1000,
        max_duration_ns: 500,
        missing_operator_ack: true,
    };
    let cloned = v.clone();
    assert_eq!(v, cloned);
}

#[test]
fn enrichment_degraded_mode_violation_serde_roundtrip() {
    let v = DegradedModeViolation {
        kind: DegradedModeKind::PartialFunctionality,
        observed_duration_ns: 999_999,
        max_duration_ns: 500_000,
        missing_operator_ack: false,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: DegradedModeViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_degraded_mode_violation_serde_field_names() {
    let v = DegradedModeViolation {
        kind: DegradedModeKind::ReadOnly,
        observed_duration_ns: 10,
        max_duration_ns: 5,
        missing_operator_ack: true,
    };
    let val: serde_json::Value = serde_json::to_value(&v).unwrap();
    let obj = val.as_object().unwrap();
    assert!(obj.contains_key("kind"));
    assert!(obj.contains_key("observed_duration_ns"));
    assert!(obj.contains_key("max_duration_ns"));
    assert!(obj.contains_key("missing_operator_ack"));
}

// ---------------------------------------------------------------------------
// ObservabilityClaimDelta — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_claim_delta_exact_tolerance_is_within() {
    let d = ObservabilityClaimDelta::new("exact", 500_000, 550_000, 50_000);
    assert_eq!(d.delta_millionths, 50_000);
    assert!(d.within_tolerance);
}

#[test]
fn enrichment_claim_delta_one_over_tolerance() {
    let d = ObservabilityClaimDelta::new("over", 500_000, 550_001, 50_000);
    assert_eq!(d.delta_millionths, 50_001);
    assert!(!d.within_tolerance);
}

#[test]
fn enrichment_claim_delta_zero_baseline_relative_drift_zero() {
    let d = ObservabilityClaimDelta::new("zero_base", 0, 100_000, 50_000);
    assert_eq!(d.relative_drift_millionths(), 1_000_000);
}

#[test]
fn enrichment_claim_delta_zero_baseline_zero_delta() {
    let d = ObservabilityClaimDelta::new("zero_base_same", 0, 0, 50_000);
    assert_eq!(d.relative_drift_millionths(), 0);
}

#[test]
fn enrichment_claim_delta_identical_values() {
    let d = ObservabilityClaimDelta::new("same", 777_000, 777_000, 0);
    assert_eq!(d.delta_millionths, 0);
    assert!(d.within_tolerance);
    assert_eq!(d.relative_drift_millionths(), 0);
}

#[test]
fn enrichment_claim_delta_debug_not_empty() {
    let d = ObservabilityClaimDelta::new("dbg", 100, 200, 50);
    let dbg = format!("{d:?}");
    assert!(dbg.contains("ObservabilityClaimDelta"));
}

#[test]
fn enrichment_claim_delta_display_drifted_case() {
    let d = ObservabilityClaimDelta::new("drifted", 100_000, 300_000, 50_000);
    let s = format!("{d}");
    assert!(s.contains("DRIFTED"));
    assert!(s.contains("drifted"));
}

#[test]
fn enrichment_claim_delta_display_within_case() {
    let d = ObservabilityClaimDelta::new("ok", 500_000, 510_000, 50_000);
    let s = format!("{d}");
    assert!(s.contains("WITHIN"));
}

#[test]
fn enrichment_claim_delta_serde_field_names() {
    let d = ObservabilityClaimDelta::new("fld", 100, 200, 50);
    let val: serde_json::Value = serde_json::to_value(&d).unwrap();
    let obj = val.as_object().unwrap();
    assert!(obj.contains_key("claim_id"));
    assert!(obj.contains_key("baseline_millionths"));
    assert!(obj.contains_key("observed_millionths"));
    assert!(obj.contains_key("delta_millionths"));
    assert!(obj.contains_key("within_tolerance"));
}

#[test]
fn enrichment_claim_delta_large_values() {
    let d = ObservabilityClaimDelta::new("big", u64::MAX, 0, u64::MAX);
    assert_eq!(d.delta_millionths, u64::MAX);
    assert!(d.within_tolerance);
}

#[test]
fn enrichment_claim_delta_claim_id_preserved() {
    let d = ObservabilityClaimDelta::new("my-special-claim-123", 100, 200, 500);
    assert_eq!(d.claim_id, "my-special-claim-123");
}

// ---------------------------------------------------------------------------
// GovernanceConfig — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_governance_config_debug_not_empty() {
    let c = GovernanceConfig::default();
    let dbg = format!("{c:?}");
    assert!(dbg.contains("GovernanceConfig"));
}

#[test]
fn enrichment_governance_config_clone_eq() {
    let c = GovernanceConfig::strict();
    let cloned = c.clone();
    assert_eq!(c, cloned);
}

#[test]
fn enrichment_governance_config_serde_roundtrip_strict() {
    let c = GovernanceConfig::strict();
    let json = serde_json::to_string(&c).unwrap();
    let back: GovernanceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn enrichment_governance_config_serde_roundtrip_permissive() {
    let c = GovernanceConfig::permissive();
    let json = serde_json::to_string(&c).unwrap();
    let back: GovernanceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn enrichment_governance_config_serde_field_names() {
    let c = GovernanceConfig::default();
    let val: serde_json::Value = serde_json::to_value(&c).unwrap();
    let obj = val.as_object().unwrap();
    assert!(obj.contains_key("min_conformance"));
    assert!(obj.contains_key("max_drop_rate"));
    assert!(obj.contains_key("max_degraded_duration"));
    assert!(obj.contains_key("min_observability_tolerance"));
    assert!(obj.contains_key("required_axes"));
}

#[test]
fn enrichment_governance_config_strict_values() {
    let c = GovernanceConfig::strict();
    assert_eq!(c.min_conformance, 950_000);
    assert_eq!(c.max_drop_rate, 10_000);
    assert_eq!(c.max_degraded_duration, 30_000_000_000);
    assert_eq!(c.min_observability_tolerance, 20_000);
    assert_eq!(c.required_axes, 6);
}

#[test]
fn enrichment_governance_config_permissive_values() {
    let c = GovernanceConfig::permissive();
    assert_eq!(c.min_conformance, 500_000);
    assert_eq!(c.max_drop_rate, 200_000);
    assert_eq!(c.max_degraded_duration, u64::MAX);
    assert_eq!(c.min_observability_tolerance, 500_000);
    assert_eq!(c.required_axes, 1);
}

#[test]
fn enrichment_governance_config_custom_partial_override() {
    let c = GovernanceConfig {
        min_conformance: 800_000,
        required_axes: 3,
        ..GovernanceConfig::default()
    };
    assert_eq!(c.min_conformance, 800_000);
    assert_eq!(c.required_axes, 3);
    assert_eq!(c.max_drop_rate, DEFAULT_MAX_DROP_RATE);
}

// ---------------------------------------------------------------------------
// GovernanceVerdict — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verdict_debug_all() {
    for v in GovernanceVerdict::ALL {
        let dbg = format!("{v:?}");
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_verdict_clone_eq() {
    for v in GovernanceVerdict::ALL {
        let cloned = v.clone();
        assert_eq!(*v, cloned);
    }
}

#[test]
fn enrichment_verdict_ord_consistent() {
    // Approved should be the smallest in enum order
    assert!(GovernanceVerdict::Approved < GovernanceVerdict::ConformanceViolation);
    assert!(GovernanceVerdict::ConformanceViolation < GovernanceVerdict::MultipleViolations);
}

#[test]
fn enrichment_verdict_unique_names() {
    let mut names = std::collections::BTreeSet::new();
    for v in GovernanceVerdict::ALL {
        assert!(names.insert(v.as_str()));
    }
    assert_eq!(names.len(), 7);
}

#[test]
fn enrichment_verdict_is_approved_xor_is_failure() {
    for v in GovernanceVerdict::ALL {
        assert_ne!(v.is_approved(), v.is_failure());
    }
}

#[test]
fn enrichment_verdict_serde_json_snake_case_all() {
    for v in GovernanceVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let inner = &json[1..json.len() - 1];
        assert_eq!(inner, v.as_str());
    }
}

// ---------------------------------------------------------------------------
// ViolationEntry — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_violation_entry_display() {
    let ve = ViolationEntry {
        category: GovernanceVerdict::ConformanceViolation,
        description: "axis protocol failed".to_string(),
    };
    let s = format!("{ve}");
    assert!(s.contains("conformance_violation"));
    assert!(s.contains("axis protocol failed"));
}

#[test]
fn enrichment_violation_entry_debug() {
    let ve = ViolationEntry {
        category: GovernanceVerdict::DropRateExceeded,
        description: "too many drops".to_string(),
    };
    let dbg = format!("{ve:?}");
    assert!(dbg.contains("ViolationEntry"));
}

#[test]
fn enrichment_violation_entry_clone_eq() {
    let ve = ViolationEntry {
        category: GovernanceVerdict::ObservabilityDrift,
        description: "drifted".to_string(),
    };
    let cloned = ve.clone();
    assert_eq!(ve, cloned);
}

#[test]
fn enrichment_violation_entry_serde_roundtrip() {
    let ve = ViolationEntry {
        category: GovernanceVerdict::DegradedModePolicyViolation,
        description: "missing ack".to_string(),
    };
    let json = serde_json::to_string(&ve).unwrap();
    let back: ViolationEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(ve, back);
}

#[test]
fn enrichment_violation_entry_serde_field_names() {
    let ve = ViolationEntry {
        category: GovernanceVerdict::InsufficientCoverage,
        description: "not enough axes".to_string(),
    };
    let val: serde_json::Value = serde_json::to_value(&ve).unwrap();
    let obj = val.as_object().unwrap();
    assert!(obj.contains_key("category"));
    assert!(obj.contains_key("description"));
}

// ---------------------------------------------------------------------------
// GovernanceEvaluator — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluator_with_defaults_config_is_default() {
    let ev = GovernanceEvaluator::with_defaults();
    assert_eq!(ev.config, GovernanceConfig::default());
}

#[test]
fn enrichment_evaluator_debug_not_empty() {
    let ev = GovernanceEvaluator::with_defaults();
    let dbg = format!("{ev:?}");
    assert!(dbg.contains("GovernanceEvaluator"));
}

#[test]
fn enrichment_evaluator_clone_eq() {
    let mut ev = GovernanceEvaluator::with_defaults();
    ev.add_conformance(ConformanceAxis::Protocol, 50, 50);
    let cloned = ev.clone();
    assert_eq!(ev, cloned);
}

#[test]
fn enrichment_evaluator_serde_roundtrip() {
    let mut ev = GovernanceEvaluator::with_defaults();
    ev.add_conformance(ConformanceAxis::Encoding, 80, 20);
    ev.add_replay_drop(ReplayDropCategory::TimeBudgetExceeded, 3, 100);
    let json = serde_json::to_string(&ev).unwrap();
    let back: GovernanceEvaluator = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn enrichment_evaluator_reset_preserves_config() {
    let cfg = GovernanceConfig::strict();
    let mut ev = GovernanceEvaluator::with_config(cfg.clone());
    ev.add_conformance(ConformanceAxis::Protocol, 100, 0);
    ev.reset();
    assert_eq!(ev.config, cfg);
    assert_eq!(ev.evidence_count(), 0);
}

#[test]
fn enrichment_evaluator_empty_with_zero_required_axes_approved() {
    let cfg = GovernanceConfig {
        required_axes: 0,
        ..GovernanceConfig::default()
    };
    let ev = GovernanceEvaluator::with_config(cfg);
    let receipt = ev.evaluate(ep());
    assert!(receipt.is_approved());
}

#[test]
fn enrichment_evaluator_duplicate_axes_counted_for_coverage() {
    let mut ev = GovernanceEvaluator::with_defaults();
    // Add same axis multiple times — BTreeSet deduplication means coverage = 1
    for _ in 0..10 {
        ev.add_conformance(ConformanceAxis::Protocol, 100, 0);
    }
    let receipt = ev.evaluate(ep());
    // Only 1 unique axis, need 4
    assert_eq!(receipt.verdict, GovernanceVerdict::InsufficientCoverage);
}

#[test]
fn enrichment_evaluator_evidence_count_increments_each_type() {
    let mut ev = GovernanceEvaluator::with_defaults();
    assert_eq!(ev.evidence_count(), 0);

    ev.add_conformance(ConformanceAxis::Protocol, 10, 0);
    assert_eq!(ev.evidence_count(), 1);

    ev.add_conformance(ConformanceAxis::Encoding, 10, 0);
    assert_eq!(ev.evidence_count(), 2);

    ev.add_replay_drop(ReplayDropCategory::EncodingError, 1, 100);
    assert_eq!(ev.evidence_count(), 3);

    ev.add_degraded_mode(DegradedModeKind::ReducedBandwidth, 100, false);
    assert_eq!(ev.evidence_count(), 4);

    ev.add_claim_delta("c", 100, 200);
    assert_eq!(ev.evidence_count(), 5);
}

#[test]
fn enrichment_evaluator_add_degraded_mode_with_policy_custom() {
    let mut ev = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 100, 0);
    }
    let policy = DegradedModePolicy {
        kind: DegradedModeKind::ReadOnly,
        max_duration_ns: 10_000,
        requires_operator_ack: false,
        auto_recovery: true,
    };
    ev.add_degraded_mode_with_policy(policy, 5_000, true);
    let receipt = ev.evaluate(ep());
    assert!(receipt.is_approved());
    assert_eq!(receipt.degraded_policy_count, 1);
}

#[test]
fn enrichment_evaluator_add_degraded_mode_with_policy_violation() {
    let mut ev = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 100, 0);
    }
    let policy = DegradedModePolicy {
        kind: DegradedModeKind::IncreasedLatency,
        max_duration_ns: 100,
        requires_operator_ack: true,
        auto_recovery: false,
    };
    // exceeds duration and missing ack
    ev.add_degraded_mode_with_policy(policy, 200, false);
    let receipt = ev.evaluate(ep());
    assert_eq!(
        receipt.verdict,
        GovernanceVerdict::DegradedModePolicyViolation
    );
}

#[test]
fn enrichment_evaluator_verdict_matches_receipt_verdict() {
    let mut ev = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 99, 1);
    }
    let receipt = ev.evaluate(ep());
    let verdict = ev.verdict(ep());
    assert_eq!(receipt.verdict, verdict);
}

// ---------------------------------------------------------------------------
// GovernanceReceipt — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_debug_not_empty() {
    let ev = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
    let receipt = ev.evaluate(ep());
    let dbg = format!("{receipt:?}");
    assert!(dbg.contains("GovernanceReceipt"));
}

#[test]
fn enrichment_receipt_clone_eq() {
    let mut ev = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 95, 5);
    }
    let receipt = ev.evaluate(ep());
    let cloned = receipt.clone();
    assert_eq!(receipt, cloned);
}

#[test]
fn enrichment_receipt_serde_field_names() {
    let mut ev = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 100, 0);
    }
    let receipt = ev.evaluate(ep());
    let val: serde_json::Value = serde_json::to_value(&receipt).unwrap();
    let obj = val.as_object().unwrap();
    assert!(obj.contains_key("schema_version"));
    assert!(obj.contains_key("verdict"));
    assert!(obj.contains_key("epoch"));
    assert!(obj.contains_key("conformance_count"));
    assert!(obj.contains_key("drop_entry_count"));
    assert!(obj.contains_key("degraded_policy_count"));
    assert!(obj.contains_key("claim_delta_count"));
    assert!(obj.contains_key("violations"));
    assert!(obj.contains_key("content_hash"));
}

#[test]
fn enrichment_receipt_violation_count_matches_vec_len() {
    let mut ev = GovernanceEvaluator::with_defaults();
    ev.add_conformance(ConformanceAxis::Protocol, 10, 90);
    let receipt = ev.evaluate(ep());
    assert_eq!(receipt.violation_count(), receipt.violations.len());
}

#[test]
fn enrichment_receipt_total_entries_zero_for_empty() {
    let cfg = GovernanceConfig {
        required_axes: 0,
        ..GovernanceConfig::default()
    };
    let ev = GovernanceEvaluator::with_config(cfg);
    let receipt = ev.evaluate(ep());
    assert_eq!(receipt.total_entries(), 0);
}

#[test]
fn enrichment_receipt_display_contains_verdict() {
    let mut ev = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 100, 0);
    }
    let receipt = ev.evaluate(ep());
    let s = format!("{receipt}");
    assert!(s.contains("approved"));
    assert!(s.contains("receipt"));
}

#[test]
fn enrichment_receipt_display_contains_violation_count_text() {
    let mut ev = GovernanceEvaluator::with_defaults();
    ev.add_conformance(ConformanceAxis::Protocol, 10, 90);
    let receipt = ev.evaluate(ep());
    let s = format!("{receipt}");
    assert!(s.contains("violations="));
}

#[test]
fn enrichment_receipt_approved_has_no_violations() {
    let mut ev = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 100, 0);
    }
    let receipt = ev.evaluate(ep());
    assert!(receipt.is_approved());
    assert!(!receipt.has_violations());
    assert_eq!(receipt.violation_count(), 0);
}

#[test]
fn enrichment_receipt_is_approved_iff_verdict_approved() {
    for _v in GovernanceVerdict::ALL {
        // Build scenario per verdict
        let cfg = GovernanceConfig {
            required_axes: 0,
            ..GovernanceConfig::permissive()
        };
        let ev = GovernanceEvaluator::with_config(cfg);
        let receipt = ev.evaluate(ep());
        assert_eq!(
            receipt.is_approved(),
            receipt.verdict == GovernanceVerdict::Approved
        );
    }
}

// ---------------------------------------------------------------------------
// Content hash determinism — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_content_hash_deterministic_with_drops() {
    let build = || {
        let mut ev = GovernanceEvaluator::with_defaults();
        for axis in ConformanceAxis::ALL {
            ev.add_conformance(*axis, 99, 1);
        }
        ev.add_replay_drop(ReplayDropCategory::TimeBudgetExceeded, 5, 1000);
        ev.add_replay_drop(ReplayDropCategory::EncodingError, 3, 1000);
        ev.evaluate(ep())
    };
    assert_eq!(build().content_hash, build().content_hash);
}

#[test]
fn enrichment_content_hash_deterministic_with_degraded() {
    let build = || {
        let mut ev = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
        ev.add_degraded_mode(DegradedModeKind::ReducedBandwidth, 1000, true);
        ev.evaluate(ep())
    };
    assert_eq!(build().content_hash, build().content_hash);
}

#[test]
fn enrichment_content_hash_deterministic_with_claims() {
    let build = || {
        let mut ev = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
        ev.add_claim_delta("c1", 500_000, 510_000);
        ev.add_claim_delta("c2", 700_000, 720_000);
        ev.evaluate(ep())
    };
    assert_eq!(build().content_hash, build().content_hash);
}

#[test]
fn enrichment_content_hash_changes_with_drop_count() {
    let mut ev1 = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev1.add_conformance(*axis, 100, 0);
    }
    ev1.add_replay_drop(ReplayDropCategory::TimeBudgetExceeded, 1, 1000);
    let r1 = ev1.evaluate(ep());

    let mut ev2 = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev2.add_conformance(*axis, 100, 0);
    }
    ev2.add_replay_drop(ReplayDropCategory::TimeBudgetExceeded, 2, 1000);
    let r2 = ev2.evaluate(ep());

    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_content_hash_changes_with_degraded_duration() {
    let mut ev1 = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
    ev1.add_degraded_mode(DegradedModeKind::ReducedBandwidth, 1000, true);
    let r1 = ev1.evaluate(ep());

    let mut ev2 = GovernanceEvaluator::with_config(GovernanceConfig::permissive());
    ev2.add_degraded_mode(DegradedModeKind::ReducedBandwidth, 2000, true);
    let r2 = ev2.evaluate(ep());

    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_content_hash_changes_with_claim_values() {
    let cfg = GovernanceConfig {
        required_axes: 0,
        ..GovernanceConfig::permissive()
    };

    let mut ev1 = GovernanceEvaluator::with_config(cfg.clone());
    ev1.add_claim_delta("c1", 100, 200);
    let r1 = ev1.evaluate(ep());

    let mut ev2 = GovernanceEvaluator::with_config(cfg);
    ev2.add_claim_delta("c1", 100, 300);
    let r2 = ev2.evaluate(ep());

    assert_ne!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// E2E scenario enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_e2e_all_violation_categories_in_receipt() {
    let mut ev = GovernanceEvaluator::with_defaults();
    // Insufficient coverage: only 1 axis
    ev.add_conformance(ConformanceAxis::Protocol, 10, 90); // conformance violation
    ev.add_replay_drop(ReplayDropCategory::EncodingError, 500, 1000); // drop rate exceeded
    ev.add_degraded_mode(DegradedModeKind::Disconnected, 100, false); // degraded violation
    ev.add_claim_delta("obs", 100_000, 500_000); // observability drift

    let receipt = ev.evaluate(ep());
    assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
    assert!(receipt.violation_count() >= 4);
}

#[test]
fn enrichment_e2e_strict_rejects_91_percent_conformance() {
    let mut ev = GovernanceEvaluator::with_config(GovernanceConfig::strict());
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 91, 9); // 910_000 ppm < strict 950_000
    }
    let receipt = ev.evaluate(ep());
    assert!(!receipt.is_approved());
}

#[test]
fn enrichment_e2e_strict_accepts_96_percent_conformance() {
    let mut ev = GovernanceEvaluator::with_config(GovernanceConfig::strict());
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 96, 4); // 960_000 ppm >= strict 950_000
    }
    let receipt = ev.evaluate(ep());
    assert!(receipt.is_approved());
}

#[test]
fn enrichment_e2e_receipt_serde_full_roundtrip() {
    let mut ev = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 95, 5);
    }
    ev.add_replay_drop(ReplayDropCategory::TimeBudgetExceeded, 1, 1000);
    ev.add_degraded_mode(DegradedModeKind::ReducedBandwidth, 500, false);
    ev.add_claim_delta("metric_a", 500_000, 510_000);
    let receipt = ev.evaluate(ep());
    let json = serde_json::to_string_pretty(&receipt).unwrap();
    let back: GovernanceReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn enrichment_e2e_multiple_drop_categories() {
    let mut ev = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 100, 0);
    }
    for cat in ReplayDropCategory::ALL {
        ev.add_replay_drop(*cat, 1, 1000);
    }
    let receipt = ev.evaluate(ep());
    assert!(receipt.is_approved());
    assert_eq!(receipt.drop_entry_count, 5);
}

#[test]
fn enrichment_e2e_multiple_degraded_kinds_mixed() {
    let cfg = GovernanceConfig {
        required_axes: 0,
        ..GovernanceConfig::permissive()
    };
    let mut ev = GovernanceEvaluator::with_config(cfg);
    ev.add_degraded_mode(DegradedModeKind::ReducedBandwidth, 100, false);
    ev.add_degraded_mode(DegradedModeKind::IncreasedLatency, 200, false);
    let receipt = ev.evaluate(ep());
    assert!(receipt.is_approved());
    assert_eq!(receipt.degraded_policy_count, 2);
}

#[test]
fn enrichment_e2e_multiple_claim_deltas() {
    let cfg = GovernanceConfig {
        required_axes: 0,
        ..GovernanceConfig::permissive()
    };
    let mut ev = GovernanceEvaluator::with_config(cfg);
    for i in 0..5 {
        ev.add_claim_delta(format!("claim_{i}"), 500_000, 510_000);
    }
    let receipt = ev.evaluate(ep());
    assert!(receipt.is_approved());
    assert_eq!(receipt.claim_delta_count, 5);
}

#[test]
fn enrichment_e2e_reset_then_reevaluate() {
    let mut ev = GovernanceEvaluator::with_defaults();
    // First evaluation: should fail (insufficient coverage)
    ev.add_conformance(ConformanceAxis::Protocol, 10, 90);
    let r1 = ev.evaluate(ep());
    assert!(!r1.is_approved());

    // Reset and add passing data
    ev.reset();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 100, 0);
    }
    let r2 = ev.evaluate(ep());
    assert!(r2.is_approved());
}

#[test]
fn enrichment_e2e_evaluator_serde_preserves_behavior() {
    let mut ev = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 95, 5);
    }
    ev.add_replay_drop(ReplayDropCategory::TimeBudgetExceeded, 2, 1000);

    let json = serde_json::to_string(&ev).unwrap();
    let restored: GovernanceEvaluator = serde_json::from_str(&json).unwrap();

    let r1 = ev.evaluate(ep());
    let r2 = restored.evaluate(ep());
    assert_eq!(r1.verdict, r2.verdict);
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_e2e_conformance_violation_description_contains_axis() {
    let mut ev = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 100, 0);
    }
    // Add a failing axis on top
    ev.add_conformance(ConformanceAxis::Protocol, 10, 90);
    let receipt = ev.evaluate(ep());
    // Find the conformance violation
    let violation = receipt
        .violations
        .iter()
        .find(|v| v.category == GovernanceVerdict::ConformanceViolation);
    assert!(violation.is_some());
    assert!(violation.unwrap().description.contains("protocol"));
}

#[test]
fn enrichment_e2e_insufficient_coverage_description() {
    let mut ev = GovernanceEvaluator::with_defaults();
    ev.add_conformance(ConformanceAxis::Protocol, 100, 0);
    ev.add_conformance(ConformanceAxis::Encoding, 100, 0);
    let receipt = ev.evaluate(ep());
    assert_eq!(receipt.verdict, GovernanceVerdict::InsufficientCoverage);
    let violation = receipt
        .violations
        .iter()
        .find(|v| v.category == GovernanceVerdict::InsufficientCoverage)
        .unwrap();
    assert!(violation.description.contains("2"));
    assert!(violation.description.contains("4"));
}

#[test]
fn enrichment_e2e_drop_rate_violation_description() {
    let mut ev = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 100, 0);
    }
    ev.add_replay_drop(ReplayDropCategory::PolicyViolation, 200, 1000);
    let receipt = ev.evaluate(ep());
    let violation = receipt
        .violations
        .iter()
        .find(|v| v.category == GovernanceVerdict::DropRateExceeded)
        .unwrap();
    assert!(violation.description.contains("policy_violation"));
}

#[test]
fn enrichment_e2e_observability_drift_violation_description() {
    let mut ev = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 100, 0);
    }
    ev.add_claim_delta("my_metric", 500_000, 700_000);
    let receipt = ev.evaluate(ep());
    assert_eq!(receipt.verdict, GovernanceVerdict::ObservabilityDrift);
    let violation = receipt
        .violations
        .iter()
        .find(|v| v.category == GovernanceVerdict::ObservabilityDrift)
        .unwrap();
    assert!(violation.description.contains("my_metric"));
}

#[test]
fn enrichment_e2e_degraded_violation_description_contains_kind() {
    let mut ev = GovernanceEvaluator::with_defaults();
    for axis in ConformanceAxis::ALL {
        ev.add_conformance(*axis, 100, 0);
    }
    ev.add_degraded_mode(DegradedModeKind::Disconnected, 100, false);
    let receipt = ev.evaluate(ep());
    let violation = receipt
        .violations
        .iter()
        .find(|v| v.category == GovernanceVerdict::DegradedModePolicyViolation)
        .unwrap();
    assert!(violation.description.contains("disconnected"));
}
