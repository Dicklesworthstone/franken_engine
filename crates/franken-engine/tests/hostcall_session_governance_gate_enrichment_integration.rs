//! Enrichment integration tests for `hostcall_session_governance_gate`.
//!
//! Covers Copy/Clone semantics, BTreeSet dedup, Debug/Display uniqueness,
//! serde JSON field stability, Clone independence, determinism, and
//! cross-cutting invariants NOT already tested in the base integration file.

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

use frankenengine_engine::hostcall_session_governance_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn passing_conformance() -> ConformanceVector {
    ConformanceVector::new("sess-enrich", "v1", 100, 100, vec![], epoch(1))
}

// ===========================================================================
// ConformanceLevel enrichment
// ===========================================================================

#[test]
fn enrichment_conformance_level_copy_semantics() {
    let a = ConformanceLevel::Full;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_conformance_level_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for &l in ConformanceLevel::ALL {
        set.insert(l);
        set.insert(l);
    }
    assert_eq!(set.len(), ConformanceLevel::ALL.len());
}

#[test]
fn enrichment_conformance_level_debug_all_unique() {
    let debugs: BTreeSet<String> = ConformanceLevel::ALL
        .iter()
        .map(|l| format!("{l:?}"))
        .collect();
    assert_eq!(debugs.len(), ConformanceLevel::ALL.len());
}

#[test]
fn enrichment_conformance_level_display_all_unique() {
    let displays: BTreeSet<String> = ConformanceLevel::ALL
        .iter()
        .map(|l| l.to_string())
        .collect();
    assert_eq!(displays.len(), ConformanceLevel::ALL.len());
}

#[test]
fn enrichment_conformance_level_as_str_matches_display() {
    for &l in ConformanceLevel::ALL {
        assert_eq!(l.as_str(), &l.to_string());
    }
}

#[test]
fn enrichment_conformance_level_acceptable_coverage() {
    assert!(ConformanceLevel::Full.is_acceptable());
    assert!(ConformanceLevel::Partial.is_acceptable());
    assert!(!ConformanceLevel::Degraded.is_acceptable());
    assert!(!ConformanceLevel::NonConformant.is_acceptable());
}

#[test]
fn enrichment_conformance_level_serde_all() {
    for &l in ConformanceLevel::ALL {
        let json = serde_json::to_string(&l).unwrap();
        let back: ConformanceLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, l);
    }
}

// ===========================================================================
// DegradedModeReason enrichment
// ===========================================================================

#[test]
fn enrichment_degraded_mode_reason_copy_semantics() {
    let a = DegradedModeReason::HighLatency;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_degraded_mode_reason_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for &r in DegradedModeReason::ALL {
        set.insert(r);
        set.insert(r);
    }
    assert_eq!(set.len(), DegradedModeReason::ALL.len());
}

#[test]
fn enrichment_degraded_mode_reason_debug_all_unique() {
    let debugs: BTreeSet<String> = DegradedModeReason::ALL
        .iter()
        .map(|r| format!("{r:?}"))
        .collect();
    assert_eq!(debugs.len(), DegradedModeReason::ALL.len());
}

#[test]
fn enrichment_degraded_mode_reason_display_all_unique() {
    let displays: BTreeSet<String> = DegradedModeReason::ALL
        .iter()
        .map(|r| r.to_string())
        .collect();
    assert_eq!(displays.len(), DegradedModeReason::ALL.len());
}

#[test]
fn enrichment_degraded_mode_reason_security_critical_only_one() {
    let critical_count = DegradedModeReason::ALL
        .iter()
        .filter(|r| r.is_security_critical())
        .count();
    assert_eq!(critical_count, 1);
    assert!(DegradedModeReason::SecurityViolation.is_security_critical());
}

#[test]
fn enrichment_degraded_mode_reason_serde_all() {
    for &r in DegradedModeReason::ALL {
        let json = serde_json::to_string(&r).unwrap();
        let back: DegradedModeReason = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}

// ===========================================================================
// GateVerdict enrichment
// ===========================================================================

#[test]
fn enrichment_gate_verdict_copy_semantics() {
    let a = GateVerdict::Pass;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_gate_verdict_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for &v in GateVerdict::ALL {
        set.insert(v);
        set.insert(v);
    }
    assert_eq!(set.len(), GateVerdict::ALL.len());
}

#[test]
fn enrichment_gate_verdict_debug_all_unique() {
    let debugs: BTreeSet<String> = GateVerdict::ALL.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), GateVerdict::ALL.len());
}

#[test]
fn enrichment_gate_verdict_display_all_unique() {
    let displays: BTreeSet<String> = GateVerdict::ALL.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), GateVerdict::ALL.len());
}

#[test]
fn enrichment_gate_verdict_allows_session_coverage() {
    assert!(GateVerdict::Pass.allows_session());
    assert!(GateVerdict::ConditionalPass.allows_session());
    assert!(!GateVerdict::Fail.allows_session());
    assert!(GateVerdict::DegradedMode.allows_session());
}

#[test]
fn enrichment_gate_verdict_is_clean_coverage() {
    assert!(GateVerdict::Pass.is_clean());
    assert!(!GateVerdict::ConditionalPass.is_clean());
    assert!(!GateVerdict::Fail.is_clean());
    assert!(!GateVerdict::DegradedMode.is_clean());
}

#[test]
fn enrichment_gate_verdict_serde_all() {
    for &v in GateVerdict::ALL {
        let json = serde_json::to_string(&v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }
}

// ===========================================================================
// ReplayDropKind enrichment
// ===========================================================================

#[test]
fn enrichment_replay_drop_kind_copy_semantics() {
    let a = ReplayDropKind::Timeout;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_replay_drop_kind_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for &k in ReplayDropKind::ALL {
        set.insert(k);
        set.insert(k);
    }
    assert_eq!(set.len(), ReplayDropKind::ALL.len());
}

#[test]
fn enrichment_replay_drop_kind_debug_all_unique() {
    let debugs: BTreeSet<String> = ReplayDropKind::ALL
        .iter()
        .map(|k| format!("{k:?}"))
        .collect();
    assert_eq!(debugs.len(), ReplayDropKind::ALL.len());
}

#[test]
fn enrichment_replay_drop_kind_display_all_unique() {
    let displays: BTreeSet<String> = ReplayDropKind::ALL.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), ReplayDropKind::ALL.len());
}

#[test]
fn enrichment_replay_drop_kind_serde_all() {
    for &k in ReplayDropKind::ALL {
        let json = serde_json::to_string(&k).unwrap();
        let back: ReplayDropKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }
}

// ===========================================================================
// ConformanceVector enrichment
// ===========================================================================

#[test]
fn enrichment_conformance_vector_clone_independence() {
    let original = passing_conformance();
    let mut cloned = original.clone();
    cloned.session_id = "mutated".to_string();
    assert_eq!(original.session_id, "sess-enrich");
    assert_eq!(cloned.session_id, "mutated");
}

#[test]
fn enrichment_conformance_vector_json_field_names() {
    let cv = passing_conformance();
    let json = serde_json::to_string(&cv).unwrap();
    assert!(json.contains("\"session_id\""));
    assert!(json.contains("\"protocol_version\""));
    assert!(json.contains("\"operations_tested\""));
    assert!(json.contains("\"operations_passed\""));
    assert!(json.contains("\"conformance_fraction\""));
    assert!(json.contains("\"failures\""));
    assert!(json.contains("\"epoch\""));
}

#[test]
fn enrichment_conformance_vector_serde_roundtrip() {
    let cv = passing_conformance();
    let json = serde_json::to_string(&cv).unwrap();
    let back: ConformanceVector = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cv);
}

#[test]
fn enrichment_conformance_vector_display_contains_session_id() {
    let cv = passing_conformance();
    let s = cv.to_string();
    assert!(s.contains("sess-enrich"));
}

// ===========================================================================
// ObservabilityDelta enrichment
// ===========================================================================

#[test]
fn enrichment_observability_delta_copy_semantics() {
    let a = ObservabilityDelta::new(900_000, 1_000_000);
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_observability_delta_json_field_names() {
    let d = ObservabilityDelta::new(900_000, 1_000_000);
    let json = serde_json::to_string(&d).unwrap();
    assert!(json.contains("\"instrumented_throughput\""));
    assert!(json.contains("\"uninstrumented_throughput\""));
    assert!(json.contains("\"overhead_fraction\""));
    assert!(json.contains("\"acceptable\""));
}

#[test]
fn enrichment_observability_delta_zero_zero() {
    let d = ObservabilityDelta::new(0, 0);
    assert_eq!(d.overhead_fraction, 0);
    assert!(d.acceptable);
}

#[test]
fn enrichment_observability_delta_equal_throughput() {
    let d = ObservabilityDelta::new(500_000, 500_000);
    assert_eq!(d.overhead_fraction, 0);
    assert!(d.acceptable);
}

// ===========================================================================
// GateConfig enrichment
// ===========================================================================

#[test]
fn enrichment_gate_config_clone_independence() {
    let original = GateConfig::default();
    let mut cloned = original.clone();
    cloned.min_operations_tested = 999;
    assert_eq!(
        original.min_operations_tested,
        DEFAULT_MIN_OPERATIONS_TESTED
    );
    assert_eq!(cloned.min_operations_tested, 999);
}

#[test]
fn enrichment_gate_config_json_field_names() {
    let config = GateConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    assert!(json.contains("\"min_conformance_fraction\""));
    assert!(json.contains("\"max_replay_drop_rate\""));
    assert!(json.contains("\"max_degraded_severity\""));
    assert!(json.contains("\"max_observability_overhead\""));
    assert!(json.contains("\"min_operations_tested\""));
}

#[test]
fn enrichment_gate_config_strict_stricter_than_default() {
    let strict = GateConfig::strict();
    let default = GateConfig::default();
    assert!(strict.min_conformance_fraction >= default.min_conformance_fraction);
    assert!(strict.max_replay_drop_rate <= default.max_replay_drop_rate);
    assert!(strict.min_operations_tested >= default.min_operations_tested);
}

#[test]
fn enrichment_gate_config_permissive_more_lenient_than_default() {
    let permissive = GateConfig::permissive();
    let default = GateConfig::default();
    assert!(permissive.min_conformance_fraction <= default.min_conformance_fraction);
    assert!(permissive.max_replay_drop_rate >= default.max_replay_drop_rate);
}

// ===========================================================================
// GateResult enrichment
// ===========================================================================

#[test]
fn enrichment_gate_result_clone_independence() {
    let original = evaluate(
        &passing_conformance(),
        &[],
        &[],
        None,
        &GateConfig::default(),
    );
    let mut cloned = original.clone();
    cloned.blocking_reasons.push("injected".to_string());
    assert!(original.blocking_reasons.is_empty());
    assert_eq!(cloned.blocking_reasons.len(), 1);
}

#[test]
fn enrichment_gate_result_json_field_names() {
    let result = evaluate(
        &passing_conformance(),
        &[],
        &[],
        None,
        &GateConfig::default(),
    );
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("\"verdict\""));
    assert!(json.contains("\"conformance_level\""));
    assert!(json.contains("\"blocking_reasons\""));
    assert!(json.contains("\"recommendations\""));
    assert!(json.contains("\"receipt_hash\""));
}

#[test]
fn enrichment_gate_result_display_contains_verdict() {
    let result = evaluate(
        &passing_conformance(),
        &[],
        &[],
        None,
        &GateConfig::default(),
    );
    let s = result.to_string();
    assert!(s.contains("gate["));
}

// ===========================================================================
// Cross-cutting: evaluate determinism
// ===========================================================================

#[test]
fn enrichment_evaluate_determinism_five_runs() {
    let cv = passing_conformance();
    let config = GateConfig::default();
    let first = evaluate(&cv, &[], &[], None, &config);
    for _ in 0..4 {
        let again = evaluate(&cv, &[], &[], None, &config);
        assert_eq!(first.verdict, again.verdict);
        assert_eq!(first.conformance_level, again.conformance_level);
        assert_eq!(first.receipt_hash, again.receipt_hash);
    }
}

// ===========================================================================
// Cross-cutting: constants stability
// ===========================================================================

#[test]
fn enrichment_constants_stable() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.hostcall-session-governance-gate.v1"
    );
    assert_eq!(COMPONENT, "hostcall_session_governance_gate");
    assert_eq!(BEAD_ID, "bd-1lsy.6.5.3");
    assert_eq!(POLICY_ID, "RGC-505C");
    assert_eq!(DEFAULT_MIN_CONFORMANCE, 900_000);
    assert_eq!(DEFAULT_MAX_REPLAY_DROP_RATE, 50_000);
    assert_eq!(DEFAULT_MAX_DEGRADED_SEVERITY, 700_000);
    assert_eq!(DEFAULT_MAX_OBSERVABILITY_OVERHEAD, 100_000);
    assert_eq!(DEFAULT_MIN_OPERATIONS_TESTED, 10);
}

// ===========================================================================
// Cross-cutting: GateSummary from results
// ===========================================================================

#[test]
fn enrichment_gate_summary_from_empty() {
    let summary = GateSummary::from_results(&[]);
    assert_eq!(summary.total, 0);
    assert_eq!(summary.pass_rate, 0);
    assert!(!summary.all_passing());
}

#[test]
fn enrichment_gate_summary_all_passing() {
    let config = GateConfig::default();
    let cv = passing_conformance();
    let results: Vec<GateResult> = (0..5)
        .map(|_| evaluate(&cv, &[], &[], None, &config))
        .collect();
    let summary = GateSummary::from_results(&results);
    assert_eq!(summary.total, 5);
    assert_eq!(summary.passed, 5);
    assert_eq!(summary.failed, 0);
    assert!(summary.all_passing());
    assert_eq!(summary.pass_rate, 1_000_000);
}

#[test]
fn enrichment_gate_summary_display_nonempty() {
    let summary = GateSummary::from_results(&[]);
    let s = summary.to_string();
    assert!(s.contains("summary:"));
}

#[test]
fn enrichment_gate_summary_serde_roundtrip() {
    let config = GateConfig::default();
    let cv = passing_conformance();
    let results: Vec<GateResult> = (0..3)
        .map(|_| evaluate(&cv, &[], &[], None, &config))
        .collect();
    let summary = GateSummary::from_results(&results);
    let json = serde_json::to_string(&summary).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, summary);
}

// ===========================================================================
// Cross-cutting: DecisionReceipt
// ===========================================================================

#[test]
fn enrichment_decision_receipt_determinism() {
    let eh = frankenengine_engine::hash_tiers::ContentHash::compute(b"evidence");
    let r1 = DecisionReceipt::new(epoch(1), GateVerdict::Pass, eh);
    let r2 = DecisionReceipt::new(epoch(1), GateVerdict::Pass, eh);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_decision_receipt_display() {
    let eh = frankenengine_engine::hash_tiers::ContentHash::compute(b"evidence");
    let r = DecisionReceipt::new(epoch(42), GateVerdict::Fail, eh);
    let s = r.to_string();
    assert!(s.contains("receipt["));
    assert!(s.contains("42"));
}

#[test]
fn enrichment_decision_receipt_serde_roundtrip() {
    let eh = frankenengine_engine::hash_tiers::ContentHash::compute(b"evidence");
    let r = DecisionReceipt::new(epoch(1), GateVerdict::ConditionalPass, eh);
    let json = serde_json::to_string(&r).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}
