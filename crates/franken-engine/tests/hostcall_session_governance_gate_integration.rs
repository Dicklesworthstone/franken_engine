#![forbid(unsafe_code)]

//! Integration tests for the hostcall_session_governance_gate module.

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::hostcall_session_governance_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(100)
}

fn good_conformance() -> ConformanceVector {
    ConformanceVector::new("sess-1", "v1.0", 100, 100, Vec::new(), epoch())
}

fn partial_conformance() -> ConformanceVector {
    ConformanceVector::new(
        "sess-2",
        "v1.0",
        100,
        95,
        vec!["minor failure".into()],
        epoch(),
    )
}

fn bad_conformance() -> ConformanceVector {
    ConformanceVector::new(
        "sess-3",
        "v1.0",
        100,
        30,
        vec!["critical failure".into()],
        epoch(),
    )
}

fn low_test_conformance() -> ConformanceVector {
    ConformanceVector::new("sess-4", "v1.0", 3, 3, Vec::new(), epoch())
}

fn good_drop() -> ReplayDropRecord {
    ReplayDropRecord::new("sess-1", ReplayDropKind::Timeout, 1, 1000, epoch())
}

fn bad_drop() -> ReplayDropRecord {
    ReplayDropRecord::new("sess-1", ReplayDropKind::BufferOverflow, 200, 1000, epoch())
}

fn mild_degraded() -> DegradedModeRecord {
    DegradedModeRecord::new(
        "sess-1",
        DegradedModeReason::HighLatency,
        300_000,
        2,
        vec!["throttle applied".into()],
        epoch(),
    )
}

fn severe_degraded() -> DegradedModeRecord {
    DegradedModeRecord::new(
        "sess-1",
        DegradedModeReason::ResourceExhaustion,
        900_000,
        5,
        Vec::new(),
        epoch(),
    )
}

fn security_degraded() -> DegradedModeRecord {
    DegradedModeRecord::new(
        "sess-1",
        DegradedModeReason::SecurityViolation,
        500_000,
        1,
        vec!["session quarantined".into()],
        epoch(),
    )
}

fn default_config() -> GateConfig {
    GateConfig::default()
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_value() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.hostcall-session-governance-gate.v1"
    );
}

#[test]
fn test_component_value() {
    assert_eq!(COMPONENT, "hostcall_session_governance_gate");
}

#[test]
fn test_bead_id_value() {
    assert_eq!(BEAD_ID, "bd-1lsy.6.5.3");
}

#[test]
fn test_policy_id_value() {
    assert_eq!(POLICY_ID, "RGC-505C");
}

#[test]
fn test_default_min_conformance() {
    assert_eq!(DEFAULT_MIN_CONFORMANCE, 900_000);
}

#[test]
fn test_default_max_replay_drop_rate() {
    assert_eq!(DEFAULT_MAX_REPLAY_DROP_RATE, 50_000);
}

#[test]
fn test_default_max_degraded_severity() {
    assert_eq!(DEFAULT_MAX_DEGRADED_SEVERITY, 700_000);
}

#[test]
fn test_default_max_observability_overhead() {
    assert_eq!(DEFAULT_MAX_OBSERVABILITY_OVERHEAD, 100_000);
}

#[test]
fn test_default_min_operations_tested() {
    assert_eq!(DEFAULT_MIN_OPERATIONS_TESTED, 10);
}

// ---------------------------------------------------------------------------
// ConformanceLevel
// ---------------------------------------------------------------------------

#[test]
fn test_conformance_level_all_variants() {
    assert_eq!(ConformanceLevel::ALL.len(), 4);
}

#[test]
fn test_conformance_level_serde_roundtrip() {
    for variant in ConformanceLevel::ALL {
        let json = serde_json::to_string(variant).unwrap();
        let back: ConformanceLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, back);
    }
}

#[test]
fn test_conformance_level_display() {
    assert_eq!(ConformanceLevel::Full.to_string(), "full");
    assert_eq!(ConformanceLevel::Partial.to_string(), "partial");
    assert_eq!(ConformanceLevel::Degraded.to_string(), "degraded");
    assert_eq!(
        ConformanceLevel::NonConformant.to_string(),
        "non_conformant"
    );
}

#[test]
fn test_conformance_level_is_acceptable() {
    assert!(ConformanceLevel::Full.is_acceptable());
    assert!(ConformanceLevel::Partial.is_acceptable());
    assert!(!ConformanceLevel::Degraded.is_acceptable());
    assert!(!ConformanceLevel::NonConformant.is_acceptable());
}

// ---------------------------------------------------------------------------
// DegradedModeReason
// ---------------------------------------------------------------------------

#[test]
fn test_degraded_mode_reason_all_variants() {
    assert_eq!(DegradedModeReason::ALL.len(), 5);
}

#[test]
fn test_degraded_mode_reason_serde_roundtrip() {
    for variant in DegradedModeReason::ALL {
        let json = serde_json::to_string(variant).unwrap();
        let back: DegradedModeReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, back);
    }
}

#[test]
fn test_degraded_mode_reason_display() {
    assert_eq!(DegradedModeReason::HighLatency.to_string(), "high_latency");
    assert_eq!(
        DegradedModeReason::SecurityViolation.to_string(),
        "security_violation"
    );
    assert_eq!(
        DegradedModeReason::ProtocolMismatch.to_string(),
        "protocol_mismatch"
    );
}

#[test]
fn test_degraded_mode_reason_is_security_critical() {
    assert!(DegradedModeReason::SecurityViolation.is_security_critical());
    assert!(!DegradedModeReason::HighLatency.is_security_critical());
    assert!(!DegradedModeReason::ResourceExhaustion.is_security_critical());
    assert!(!DegradedModeReason::ReplayDrop.is_security_critical());
    assert!(!DegradedModeReason::ProtocolMismatch.is_security_critical());
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

#[test]
fn test_gate_verdict_all_variants() {
    assert_eq!(GateVerdict::ALL.len(), 4);
}

#[test]
fn test_gate_verdict_serde_roundtrip() {
    for variant in GateVerdict::ALL {
        let json = serde_json::to_string(variant).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, back);
    }
}

#[test]
fn test_gate_verdict_display() {
    assert_eq!(GateVerdict::Pass.to_string(), "pass");
    assert_eq!(GateVerdict::ConditionalPass.to_string(), "conditional_pass");
    assert_eq!(GateVerdict::Fail.to_string(), "fail");
    assert_eq!(GateVerdict::DegradedMode.to_string(), "degraded_mode");
}

#[test]
fn test_gate_verdict_allows_session() {
    assert!(GateVerdict::Pass.allows_session());
    assert!(GateVerdict::ConditionalPass.allows_session());
    assert!(GateVerdict::DegradedMode.allows_session());
    assert!(!GateVerdict::Fail.allows_session());
}

#[test]
fn test_gate_verdict_is_clean() {
    assert!(GateVerdict::Pass.is_clean());
    assert!(!GateVerdict::ConditionalPass.is_clean());
    assert!(!GateVerdict::Fail.is_clean());
    assert!(!GateVerdict::DegradedMode.is_clean());
}

// ---------------------------------------------------------------------------
// ReplayDropKind
// ---------------------------------------------------------------------------

#[test]
fn test_replay_drop_kind_all_variants() {
    assert_eq!(ReplayDropKind::ALL.len(), 5);
}

#[test]
fn test_replay_drop_kind_serde_roundtrip() {
    for variant in ReplayDropKind::ALL {
        let json = serde_json::to_string(variant).unwrap();
        let back: ReplayDropKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, back);
    }
}

#[test]
fn test_replay_drop_kind_display() {
    assert_eq!(ReplayDropKind::Timeout.to_string(), "timeout");
    assert_eq!(
        ReplayDropKind::BufferOverflow.to_string(),
        "buffer_overflow"
    );
    assert_eq!(ReplayDropKind::SessionExpiry.to_string(), "session_expiry");
}

// ---------------------------------------------------------------------------
// ConformanceVector
// ---------------------------------------------------------------------------

#[test]
fn test_conformance_vector_new_full() {
    let cv = good_conformance();
    assert_eq!(cv.session_id, "sess-1");
    assert_eq!(cv.operations_tested, 100);
    assert_eq!(cv.operations_passed, 100);
    assert_eq!(cv.conformance_fraction, 1_000_000);
    assert!(cv.is_fully_conformant());
}

#[test]
fn test_conformance_vector_partial() {
    let cv = partial_conformance();
    assert_eq!(cv.conformance_fraction, 950_000);
    assert!(!cv.is_fully_conformant());
}

#[test]
fn test_conformance_vector_zero_operations() {
    let cv = ConformanceVector::new("s", "v1", 0, 0, Vec::new(), epoch());
    assert_eq!(cv.conformance_fraction, 0);
    assert!(!cv.is_fully_conformant());
}

#[test]
fn test_conformance_vector_display() {
    let cv = good_conformance();
    let s = cv.to_string();
    assert!(s.contains("sess-1"));
    assert!(s.contains("100/100"));
}

#[test]
fn test_conformance_vector_serde_roundtrip() {
    let cv = partial_conformance();
    let json = serde_json::to_string(&cv).unwrap();
    let back: ConformanceVector = serde_json::from_str(&json).unwrap();
    assert_eq!(cv, back);
}

// ---------------------------------------------------------------------------
// ReplayDropRecord
// ---------------------------------------------------------------------------

#[test]
fn test_replay_drop_record_new() {
    let r = good_drop();
    assert_eq!(r.session_id, "sess-1");
    assert_eq!(r.dropped_count, 1);
    assert_eq!(r.total_count, 1000);
    assert_eq!(r.drop_rate, 1_000);
}

#[test]
fn test_replay_drop_record_zero_total() {
    let r = ReplayDropRecord::new("s", ReplayDropKind::Timeout, 5, 0, epoch());
    assert_eq!(r.drop_rate, 1_000_000);
}

#[test]
fn test_replay_drop_record_zero_total_zero_drops() {
    let r = ReplayDropRecord::new("s", ReplayDropKind::Timeout, 0, 0, epoch());
    assert_eq!(r.drop_rate, 0);
}

#[test]
fn test_replay_drop_record_display() {
    let r = bad_drop();
    let s = r.to_string();
    assert!(s.contains("replay-drop"));
    assert!(s.contains("buffer_overflow"));
}

#[test]
fn test_replay_drop_record_serde_roundtrip() {
    let r = good_drop();
    let json = serde_json::to_string(&r).unwrap();
    let back: ReplayDropRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// DegradedModeRecord
// ---------------------------------------------------------------------------

#[test]
fn test_degraded_mode_record_new() {
    let d = mild_degraded();
    assert_eq!(d.session_id, "sess-1");
    assert_eq!(d.reason, DegradedModeReason::HighLatency);
    assert_eq!(d.severity, 300_000);
    assert_eq!(d.duration_epochs, 2);
    assert!(!d.is_security_critical());
}

#[test]
fn test_degraded_mode_record_security_critical() {
    let d = security_degraded();
    assert!(d.is_security_critical());
}

#[test]
fn test_degraded_mode_record_display() {
    let d = severe_degraded();
    let s = d.to_string();
    assert!(s.contains("degraded"));
    assert!(s.contains("resource_exhaustion"));
}

#[test]
fn test_degraded_mode_record_serde_roundtrip() {
    let d = mild_degraded();
    let json = serde_json::to_string(&d).unwrap();
    let back: DegradedModeRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

// ---------------------------------------------------------------------------
// ObservabilityDelta
// ---------------------------------------------------------------------------

#[test]
fn test_observability_delta_no_overhead() {
    let d = ObservabilityDelta::new(1000, 1000);
    assert_eq!(d.overhead_fraction, 0);
    assert!(d.acceptable);
}

#[test]
fn test_observability_delta_some_overhead() {
    let d = ObservabilityDelta::new(900, 1000);
    assert_eq!(d.overhead_fraction, 100_000);
    assert!(d.acceptable);
}

#[test]
fn test_observability_delta_high_overhead() {
    let d = ObservabilityDelta::new(500, 1000);
    assert_eq!(d.overhead_fraction, 500_000);
    assert!(!d.acceptable);
}

#[test]
fn test_observability_delta_zero_uninstrumented() {
    let d = ObservabilityDelta::new(100, 0);
    assert_eq!(d.overhead_fraction, 1_000_000);
    assert!(!d.acceptable);
}

#[test]
fn test_observability_delta_zero_uninstrumented_zero_instrumented() {
    let d = ObservabilityDelta::new(0, 0);
    assert_eq!(d.overhead_fraction, 0);
    assert!(d.acceptable);
}

#[test]
fn test_observability_delta_with_acceptable() {
    let d = ObservabilityDelta::with_acceptable(900, 1000, 200_000);
    assert_eq!(d.overhead_fraction, 100_000);
    assert!(d.acceptable);
}

#[test]
fn test_observability_delta_display() {
    let d = ObservabilityDelta::new(900, 1000);
    let s = d.to_string();
    assert!(s.contains("observability"));
    assert!(s.contains("acceptable="));
}

#[test]
fn test_observability_delta_serde_roundtrip() {
    let d = ObservabilityDelta::new(900, 1000);
    let json = serde_json::to_string(&d).unwrap();
    let back: ObservabilityDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

#[test]
fn test_gate_config_default() {
    let cfg = default_config();
    assert_eq!(cfg.min_conformance_fraction, DEFAULT_MIN_CONFORMANCE);
    assert_eq!(cfg.max_replay_drop_rate, DEFAULT_MAX_REPLAY_DROP_RATE);
    assert_eq!(cfg.max_degraded_severity, DEFAULT_MAX_DEGRADED_SEVERITY);
    assert_eq!(
        cfg.max_observability_overhead,
        DEFAULT_MAX_OBSERVABILITY_OVERHEAD
    );
    assert_eq!(cfg.min_operations_tested, DEFAULT_MIN_OPERATIONS_TESTED);
}

#[test]
fn test_gate_config_strict() {
    let cfg = GateConfig::strict();
    assert!(cfg.min_conformance_fraction > DEFAULT_MIN_CONFORMANCE);
    assert!(cfg.max_replay_drop_rate < DEFAULT_MAX_REPLAY_DROP_RATE);
}

#[test]
fn test_gate_config_permissive() {
    let cfg = GateConfig::permissive();
    assert!(cfg.min_conformance_fraction < DEFAULT_MIN_CONFORMANCE);
    assert!(cfg.max_replay_drop_rate > DEFAULT_MAX_REPLAY_DROP_RATE);
}

#[test]
fn test_gate_config_serde_roundtrip() {
    let cfg = default_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// evaluate_conformance
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_conformance_full() {
    let level = evaluate_conformance(&good_conformance(), &default_config());
    assert_eq!(level, ConformanceLevel::Full);
}

#[test]
fn test_evaluate_conformance_partial() {
    let level = evaluate_conformance(&partial_conformance(), &default_config());
    assert_eq!(level, ConformanceLevel::Partial);
}

#[test]
fn test_evaluate_conformance_non_conformant() {
    let level = evaluate_conformance(&bad_conformance(), &default_config());
    assert_eq!(level, ConformanceLevel::NonConformant);
}

#[test]
fn test_evaluate_conformance_too_few_operations() {
    let level = evaluate_conformance(&low_test_conformance(), &default_config());
    assert_eq!(level, ConformanceLevel::NonConformant);
}

#[test]
fn test_evaluate_conformance_degraded() {
    // conformance at 50% (500_000) which is above half of 900_000 (450_000)
    let cv = ConformanceVector::new("s", "v1", 100, 50, Vec::new(), epoch());
    let level = evaluate_conformance(&cv, &default_config());
    assert_eq!(level, ConformanceLevel::Degraded);
}

// ---------------------------------------------------------------------------
// evaluate_replay_drops
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_replay_drops_empty() {
    assert!(evaluate_replay_drops(&[], &default_config()));
}

#[test]
fn test_evaluate_replay_drops_acceptable() {
    assert!(evaluate_replay_drops(&[good_drop()], &default_config()));
}

#[test]
fn test_evaluate_replay_drops_excessive() {
    assert!(!evaluate_replay_drops(&[bad_drop()], &default_config()));
}

// ---------------------------------------------------------------------------
// evaluate_degraded_mode
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_degraded_mode_empty() {
    let reasons = evaluate_degraded_mode(&[], &default_config());
    assert!(reasons.is_empty());
}

#[test]
fn test_evaluate_degraded_mode_mild() {
    let reasons = evaluate_degraded_mode(&[mild_degraded()], &default_config());
    assert!(reasons.is_empty());
}

#[test]
fn test_evaluate_degraded_mode_severe() {
    let reasons = evaluate_degraded_mode(&[severe_degraded()], &default_config());
    assert!(!reasons.is_empty());
    assert!(reasons.contains(&DegradedModeReason::ResourceExhaustion));
}

#[test]
fn test_evaluate_degraded_mode_security() {
    let reasons = evaluate_degraded_mode(&[security_degraded()], &default_config());
    assert!(!reasons.is_empty());
    assert!(reasons.contains(&DegradedModeReason::SecurityViolation));
}

// ---------------------------------------------------------------------------
// evaluate (full gate)
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_all_clean() {
    let result = evaluate(&good_conformance(), &[], &[], None, &default_config());
    assert_eq!(result.verdict, GateVerdict::Pass);
    assert!(result.is_passing());
    assert!(result.blocking_reasons.is_empty());
}

#[test]
fn test_evaluate_partial_conformance_conditional() {
    let result = evaluate(&partial_conformance(), &[], &[], None, &default_config());
    assert_eq!(result.verdict, GateVerdict::ConditionalPass);
    assert!(result.is_passing());
    assert!(result.has_recommendations());
}

#[test]
fn test_evaluate_bad_conformance_fail() {
    let result = evaluate(&bad_conformance(), &[], &[], None, &default_config());
    assert_eq!(result.verdict, GateVerdict::Fail);
    assert!(!result.is_passing());
    assert!(!result.blocking_reasons.is_empty());
}

#[test]
fn test_evaluate_low_operations_fail() {
    let result = evaluate(&low_test_conformance(), &[], &[], None, &default_config());
    assert_eq!(result.verdict, GateVerdict::Fail);
}

#[test]
fn test_evaluate_excessive_replay_drops_fail() {
    let result = evaluate(
        &good_conformance(),
        &[bad_drop()],
        &[],
        None,
        &default_config(),
    );
    assert_eq!(result.verdict, GateVerdict::Fail);
}

#[test]
fn test_evaluate_security_degradation_fail() {
    let result = evaluate(
        &good_conformance(),
        &[],
        &[security_degraded()],
        None,
        &default_config(),
    );
    assert_eq!(result.verdict, GateVerdict::Fail);
}

#[test]
fn test_evaluate_severe_degradation_not_security() {
    // severe but not security-critical, severity exceeds threshold -> degraded_reasons populated
    let result = evaluate(
        &good_conformance(),
        &[],
        &[severe_degraded()],
        None,
        &default_config(),
    );
    // Non-security critical degradation with severity > threshold -> DegradedMode
    assert_eq!(result.verdict, GateVerdict::DegradedMode);
}

#[test]
fn test_evaluate_observability_overhead_recommendation() {
    let obs = ObservabilityDelta::new(700, 1000);
    let result = evaluate(&good_conformance(), &[], &[], Some(&obs), &default_config());
    assert!(result.has_recommendations());
}

#[test]
fn test_evaluate_receipt_hash_deterministic() {
    let a = evaluate(&good_conformance(), &[], &[], None, &default_config());
    let b = evaluate(&good_conformance(), &[], &[], None, &default_config());
    assert_eq!(a.receipt_hash, b.receipt_hash);
}

// ---------------------------------------------------------------------------
// GateResult
// ---------------------------------------------------------------------------

#[test]
fn test_gate_result_display() {
    let result = evaluate(&good_conformance(), &[], &[], None, &default_config());
    let s = result.to_string();
    assert!(s.contains("gate["));
    assert!(s.contains("pass"));
}

#[test]
fn test_gate_result_serde_roundtrip() {
    let result = evaluate(&good_conformance(), &[], &[], None, &default_config());
    let json = serde_json::to_string(&result).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn test_decision_receipt_new() {
    let ev_hash = ContentHash::compute(b"test-evidence");
    let receipt = DecisionReceipt::new(epoch(), GateVerdict::Pass, ev_hash);
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.epoch, epoch());
    assert_eq!(receipt.verdict, GateVerdict::Pass);
    assert_eq!(receipt.evidence_hash, ev_hash);
}

#[test]
fn test_decision_receipt_hash_deterministic() {
    let ev_hash = ContentHash::compute(b"test");
    let a = DecisionReceipt::new(epoch(), GateVerdict::Pass, ev_hash);
    let b = DecisionReceipt::new(epoch(), GateVerdict::Pass, ev_hash);
    assert_eq!(a.receipt_hash, b.receipt_hash);
}

#[test]
fn test_decision_receipt_different_verdicts_differ() {
    let ev_hash = ContentHash::compute(b"test");
    let a = DecisionReceipt::new(epoch(), GateVerdict::Pass, ev_hash);
    let b = DecisionReceipt::new(epoch(), GateVerdict::Fail, ev_hash);
    assert_ne!(a.receipt_hash, b.receipt_hash);
}

#[test]
fn test_decision_receipt_display() {
    let ev_hash = ContentHash::compute(b"test");
    let receipt = DecisionReceipt::new(epoch(), GateVerdict::Fail, ev_hash);
    let s = receipt.to_string();
    assert!(s.contains("receipt["));
    assert!(s.contains("fail"));
    assert!(s.contains("epoch 100"));
}

#[test]
fn test_decision_receipt_serde_roundtrip() {
    let ev_hash = ContentHash::compute(b"test");
    let receipt = DecisionReceipt::new(epoch(), GateVerdict::Pass, ev_hash);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// ---------------------------------------------------------------------------
// GateSummary
// ---------------------------------------------------------------------------

#[test]
fn test_gate_summary_from_results_empty() {
    let summary = GateSummary::from_results(&[]);
    assert_eq!(summary.total, 0);
    assert_eq!(summary.pass_rate, 0);
}

#[test]
fn test_gate_summary_from_results_all_pass() {
    let r = evaluate(&good_conformance(), &[], &[], None, &default_config());
    let summary = GateSummary::from_results(&[r.clone(), r]);
    assert_eq!(summary.total, 2);
    assert_eq!(summary.passed, 2);
    assert_eq!(summary.pass_rate, 1_000_000);
    assert!(summary.all_passing());
}

#[test]
fn test_gate_summary_from_results_mixed() {
    let pass = evaluate(&good_conformance(), &[], &[], None, &default_config());
    let fail = evaluate(&bad_conformance(), &[], &[], None, &default_config());
    let summary = GateSummary::from_results(&[pass, fail]);
    assert_eq!(summary.total, 2);
    assert!(!summary.all_passing());
    assert!(summary.pass_rate < 1_000_000);
}

#[test]
fn test_gate_summary_display() {
    let summary = GateSummary::from_results(&[]);
    let s = summary.to_string();
    assert!(s.contains("summary:"));
}

#[test]
fn test_gate_summary_serde_roundtrip() {
    let r = evaluate(&good_conformance(), &[], &[], None, &default_config());
    let summary = GateSummary::from_results(&[r]);
    let json = serde_json::to_string(&summary).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}
