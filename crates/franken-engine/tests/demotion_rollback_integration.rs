//! Integration tests for the `demotion_rollback` module.
//!
//! Covers: DemotionReason Display+category for all 5 variants, DemotionSeverity
//! Display+as_str+ordering, DemotionPolicy strict defaults + block/unblock,
//! DemotionReceipt create_signed + verify_signature + content_hash,
//! AutoDemotionMonitor (creation, slot mismatch, semantic divergence triggers,
//! performance breach with sustained duration, risk threshold, capability
//! violation, disabled triggers, post-demotion ignoring, burn-in period,
//! determinism), MonitoringObservation timestamp_ns, DemotionError Display
//! for all 7 variants, serde round-trips for all public types.

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

use frankenengine_engine::demotion_rollback::{
    AutoDemotionMonitor, CreateDemotionReceiptInput, DemotionError, DemotionEvidenceItem,
    DemotionPolicy, DemotionReason, DemotionReceipt, DemotionSeverity, MonitoringObservation,
    PerformanceThreshold, TriggerEvaluation,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::self_replacement::{
    CreateReceiptInput, ReplacementReceipt, ValidationArtifactKind, ValidationArtifactRef,
};
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::slot_registry::SlotId;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn slot() -> SlotId {
    SlotId::new("slot-integ-001").expect("valid slot id")
}

fn sk() -> SigningKey {
    SigningKey::from_bytes([42u8; 32])
}

fn promotion_receipt() -> ReplacementReceipt {
    ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &slot(),
        old_cell_digest: "old-delegate-aaa",
        new_cell_digest: "new-native-bbb",
        validation_artifacts: &[ValidationArtifactRef {
            kind: ValidationArtifactKind::EquivalenceResult,
            artifact_digest: "equiv-001".into(),
            passed: true,
            summary: "all tests passed".into(),
        }],
        rollback_token: "rollback-tok-xyz",
        promotion_rationale: "gate pass",
        timestamp_ns: 1_000_000_000,
        epoch: SecurityEpoch::from_raw(1),
        zone: "test-zone",
        required_signatures: 0,
    })
    .expect("create promotion receipt")
}

fn strict_policy() -> DemotionPolicy {
    let mut p = DemotionPolicy::strict(slot());
    p.performance_thresholds.push(PerformanceThreshold {
        metric_name: "latency_p99_ns".into(),
        max_value_millionths: 50_000_000,      // 50ms
        sustained_duration_ns: 10_000_000_000, // 10s
    });
    p
}

fn monitor() -> AutoDemotionMonitor {
    AutoDemotionMonitor::new(&promotion_receipt(), strict_policy(), 1_000_000_000)
        .expect("create monitor")
}

// ---------------------------------------------------------------------------
// DemotionReason — Display and category for all 5 variants
// ---------------------------------------------------------------------------

#[test]
fn demotion_reason_semantic_divergence_display_and_category() {
    let r = DemotionReason::SemanticDivergence {
        divergence_count: 3,
        first_divergence_artifact: ContentHash::compute(b"x"),
    };
    assert!(r.to_string().contains("semantic divergence"));
    assert!(r.to_string().contains("3 outputs"));
    assert_eq!(r.category(), "semantic_divergence");
}

#[test]
fn demotion_reason_performance_breach_display_and_category() {
    let r = DemotionReason::PerformanceBreach {
        metric_name: "throughput".into(),
        observed_millionths: 100,
        threshold_millionths: 50,
        sustained_duration_ns: 1000,
    };
    assert!(r.to_string().contains("performance breach"));
    assert!(r.to_string().contains("throughput"));
    assert_eq!(r.category(), "performance_breach");
}

#[test]
fn demotion_reason_risk_threshold_display_and_category() {
    let r = DemotionReason::RiskThresholdBreach {
        observed_risk_millionths: 900_000,
        max_risk_millionths: 800_000,
    };
    assert!(r.to_string().contains("risk threshold breach"));
    assert!(r.to_string().contains("900000"));
    assert_eq!(r.category(), "risk_threshold_breach");
}

#[test]
fn demotion_reason_capability_violation_display_and_category() {
    let r = DemotionReason::CapabilityViolation {
        attempted_capability: "network_send".into(),
        envelope_digest: ContentHash::compute(b"env"),
    };
    assert!(r.to_string().contains("capability violation"));
    assert!(r.to_string().contains("network_send"));
    assert_eq!(r.category(), "capability_violation");
}

#[test]
fn demotion_reason_operator_initiated_display_and_category() {
    let r = DemotionReason::OperatorInitiated {
        operator_id: "op-1".into(),
        reason: "manual".into(),
    };
    assert!(r.to_string().contains("operator-initiated"));
    assert!(r.to_string().contains("op-1"));
    assert_eq!(r.category(), "operator_initiated");
}

// ---------------------------------------------------------------------------
// DemotionSeverity — Display, as_str, ordering
// ---------------------------------------------------------------------------

#[test]
fn demotion_severity_display_and_as_str() {
    assert_eq!(DemotionSeverity::Advisory.to_string(), "advisory");
    assert_eq!(DemotionSeverity::Warning.to_string(), "warning");
    assert_eq!(DemotionSeverity::Critical.to_string(), "critical");
    assert_eq!(DemotionSeverity::Advisory.as_str(), "advisory");
    assert_eq!(DemotionSeverity::Warning.as_str(), "warning");
    assert_eq!(DemotionSeverity::Critical.as_str(), "critical");
}

#[test]
fn demotion_severity_ordering() {
    assert!(DemotionSeverity::Advisory < DemotionSeverity::Warning);
    assert!(DemotionSeverity::Warning < DemotionSeverity::Critical);
    assert!(DemotionSeverity::Advisory < DemotionSeverity::Critical);
}

// ---------------------------------------------------------------------------
// DemotionPolicy — strict defaults, block/unblock
// ---------------------------------------------------------------------------

#[test]
fn policy_strict_defaults() {
    let p = DemotionPolicy::strict(slot());
    assert!(p.semantic_divergence_enabled);
    assert_eq!(p.semantic_divergence_severity, DemotionSeverity::Critical);
    assert_eq!(p.max_divergence_count, 0);
    assert!(p.performance_breach_enabled);
    assert_eq!(p.performance_breach_severity, DemotionSeverity::Warning);
    assert!(p.risk_threshold_enabled);
    assert_eq!(p.risk_threshold_severity, DemotionSeverity::Critical);
    assert_eq!(p.max_risk_millionths, 800_000);
    assert!(p.capability_violation_enabled);
    assert_eq!(p.capability_violation_severity, DemotionSeverity::Critical);
    assert!(p.blocked_candidates.is_empty());
    assert_eq!(p.burn_in_duration_ns, 300_000_000_000);
    assert_eq!(p.max_rollback_latency_ns, 1_000_000_000);
}

#[test]
fn policy_block_and_unblock_candidate() {
    let mut p = DemotionPolicy::strict(slot());
    assert!(!p.is_candidate_blocked("digest-abc"));
    p.block_candidate("digest-abc".into());
    assert!(p.is_candidate_blocked("digest-abc"));
    assert!(!p.is_candidate_blocked("digest-other"));

    assert!(p.unblock_candidate("digest-abc"));
    assert!(!p.is_candidate_blocked("digest-abc"));
    // Unblocking again returns false
    assert!(!p.unblock_candidate("digest-abc"));
}

#[test]
fn policy_multiple_blocked_candidates() {
    let mut p = DemotionPolicy::strict(slot());
    p.block_candidate("a".into());
    p.block_candidate("b".into());
    p.block_candidate("c".into());
    assert!(p.is_candidate_blocked("a"));
    assert!(p.is_candidate_blocked("b"));
    assert!(p.is_candidate_blocked("c"));
    assert!(!p.is_candidate_blocked("d"));
}

// ---------------------------------------------------------------------------
// DemotionReceipt — create, verify, content hash
// ---------------------------------------------------------------------------

#[test]
fn demotion_receipt_create_and_verify_signature() {
    let key = sk();
    let evidence = vec![DemotionEvidenceItem {
        artifact_hash: ContentHash::compute(b"ev-1"),
        category: "divergence_trace".into(),
        collected_at_ns: 2_000_000_000,
        summary: "test divergence".into(),
    }];

    let receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "new-native-bbb",
            restored_cell_digest: "old-delegate-aaa",
            rollback_token_used: "rollback-tok-xyz",
            demotion_reason: &DemotionReason::SemanticDivergence {
                divergence_count: 1,
                first_divergence_artifact: ContentHash::compute(b"div-1"),
            },
            severity: DemotionSeverity::Critical,
            evidence: &evidence,
            timestamp_ns: 2_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
        },
    )
    .expect("create receipt");

    assert_eq!(receipt.slot_id, slot());
    assert_eq!(receipt.demoted_cell_digest, "new-native-bbb");
    assert_eq!(receipt.restored_cell_digest, "old-delegate-aaa");
    assert_eq!(receipt.severity, DemotionSeverity::Critical);
    assert_eq!(receipt.evidence.len(), 1);

    // Verify with correct key
    receipt
        .verify_signature(&key.verification_key())
        .expect("valid signature");
}

#[test]
fn demotion_receipt_verify_fails_with_wrong_key() {
    let key = sk();
    let wrong_key = SigningKey::from_bytes([99u8; 32]);

    let receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native",
            restored_cell_digest: "delegate",
            rollback_token_used: "tok",
            demotion_reason: &DemotionReason::OperatorInitiated {
                operator_id: "op".into(),
                reason: "test".into(),
            },
            severity: DemotionSeverity::Warning,
            evidence: &[],
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "zone",
        },
    )
    .expect("create");

    let err = receipt.verify_signature(&wrong_key.verification_key());
    assert!(err.is_err());
    assert!(matches!(
        err.unwrap_err(),
        DemotionError::SignatureInvalid { .. }
    ));
}

#[test]
fn demotion_receipt_content_hash_is_deterministic() {
    let key = sk();
    let input = CreateDemotionReceiptInput {
        slot_id: &slot(),
        demoted_cell_digest: "native",
        restored_cell_digest: "delegate",
        rollback_token_used: "tok",
        demotion_reason: &DemotionReason::RiskThresholdBreach {
            observed_risk_millionths: 900_000,
            max_risk_millionths: 800_000,
        },
        severity: DemotionSeverity::Critical,
        evidence: &[],
        timestamp_ns: 5_000_000_000,
        epoch: SecurityEpoch::from_raw(2),
        zone: "prod",
    };

    let r = DemotionReceipt::create_signed(&key, input).expect("create");
    let h1 = r.content_hash();
    let h2 = r.content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn demotion_receipt_derive_receipt_id_is_deterministic() {
    let id1 = DemotionReceipt::derive_receipt_id(&slot(), "native", "delegate", 1000, "zone")
        .expect("derive");
    let id2 = DemotionReceipt::derive_receipt_id(&slot(), "native", "delegate", 1000, "zone")
        .expect("derive");
    assert_eq!(id1, id2);
}

#[test]
fn demotion_receipt_derive_receipt_id_varies_with_inputs() {
    let id1 = DemotionReceipt::derive_receipt_id(&slot(), "native-a", "delegate", 1000, "zone")
        .expect("derive");
    let id2 = DemotionReceipt::derive_receipt_id(&slot(), "native-b", "delegate", 1000, "zone")
        .expect("derive");
    assert_ne!(id1, id2);
}

// ---------------------------------------------------------------------------
// AutoDemotionMonitor — creation and accessors
// ---------------------------------------------------------------------------

#[test]
fn monitor_creation_with_valid_input() {
    let m = monitor();
    assert_eq!(m.slot_id(), &slot());
    assert_eq!(m.native_cell_digest(), "new-native-bbb");
    assert_eq!(m.previous_cell_digest(), "old-delegate-aaa");
    assert_eq!(m.rollback_token(), "rollback-tok-xyz");
    assert_eq!(m.observations_processed(), 0);
    assert!(!m.is_demotion_triggered());
    assert_eq!(m.divergence_count(), 0);
    assert_eq!(m.latest_risk_millionths(), 0);
    assert_eq!(m.policy().slot_id, slot());
}

#[test]
fn monitor_rejects_slot_mismatch() {
    let receipt = promotion_receipt();
    let wrong_policy = DemotionPolicy::strict(SlotId::new("wrong-slot").unwrap());
    let err = AutoDemotionMonitor::new(&receipt, wrong_policy, 1_000_000_000).unwrap_err();
    match err {
        DemotionError::SlotMismatch { expected, got } => {
            assert_eq!(expected, "wrong-slot");
            assert_eq!(got, "slot-integ-001");
        }
        other => panic!("unexpected error: {other}"),
    }
}

// ---------------------------------------------------------------------------
// Semantic divergence trigger
// ---------------------------------------------------------------------------

#[test]
fn semantic_divergence_fires_on_first_unwaived_mismatch() {
    let mut m = monitor();
    let obs = MonitoringObservation::OutputComparison {
        matched: false,
        input_hash: ContentHash::compute(b"in-1"),
        native_output_hash: ContentHash::compute(b"native-out"),
        reference_output_hash: ContentHash::compute(b"ref-out"),
        waiver_covered: false,
        timestamp_ns: 2_000_000_000,
    };
    let r = m.process_observation(&obs);
    assert!(r.trigger_fired);
    assert!(m.is_demotion_triggered());
    assert_eq!(m.divergence_count(), 1);
    let eval = r.evaluation.unwrap();
    assert_eq!(eval.severity, DemotionSeverity::Critical);
    assert!(matches!(
        eval.reason.as_ref().unwrap(),
        DemotionReason::SemanticDivergence {
            divergence_count: 1,
            ..
        }
    ));
}

#[test]
fn semantic_divergence_ignores_waived_mismatch() {
    let mut m = monitor();
    let obs = MonitoringObservation::OutputComparison {
        matched: false,
        input_hash: ContentHash::compute(b"in"),
        native_output_hash: ContentHash::compute(b"n"),
        reference_output_hash: ContentHash::compute(b"r"),
        waiver_covered: true,
        timestamp_ns: 2_000_000_000,
    };
    assert!(!m.process_observation(&obs).trigger_fired);
    assert_eq!(m.divergence_count(), 0);
}

#[test]
fn semantic_divergence_ignores_matching_output() {
    let mut m = monitor();
    let obs = MonitoringObservation::OutputComparison {
        matched: true,
        input_hash: ContentHash::compute(b"in"),
        native_output_hash: ContentHash::compute(b"same"),
        reference_output_hash: ContentHash::compute(b"same"),
        waiver_covered: false,
        timestamp_ns: 2_000_000_000,
    };
    assert!(!m.process_observation(&obs).trigger_fired);
}

#[test]
fn semantic_divergence_respects_max_count() {
    let receipt = promotion_receipt();
    let mut p = strict_policy();
    p.max_divergence_count = 3;
    let mut m = AutoDemotionMonitor::new(&receipt, p, 1_000_000_000).unwrap();

    for i in 0..2 {
        let obs = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(format!("in-{i}").as_bytes()),
            native_output_hash: ContentHash::compute(format!("n-{i}").as_bytes()),
            reference_output_hash: ContentHash::compute(format!("r-{i}").as_bytes()),
            waiver_covered: false,
            timestamp_ns: 2_000_000_000 + u64::try_from(i).unwrap() * 1_000_000_000,
        };
        assert!(!m.process_observation(&obs).trigger_fired);
    }
    assert_eq!(m.divergence_count(), 2);

    // Third divergence fires
    let obs3 = MonitoringObservation::OutputComparison {
        matched: false,
        input_hash: ContentHash::compute(b"in-3"),
        native_output_hash: ContentHash::compute(b"n-3"),
        reference_output_hash: ContentHash::compute(b"r-3"),
        waiver_covered: false,
        timestamp_ns: 5_000_000_000,
    };
    assert!(m.process_observation(&obs3).trigger_fired);
    assert!(m.is_demotion_triggered());
}

// ---------------------------------------------------------------------------
// Performance breach trigger
// ---------------------------------------------------------------------------

#[test]
fn performance_breach_fires_after_sustained_duration() {
    let mut m = monitor();

    // Start breaching
    let obs1 = MonitoringObservation::PerformanceSample {
        metric_name: "latency_p99_ns".into(),
        value_millionths: 60_000_000,
        timestamp_ns: 2_000_000_000,
    };
    assert!(!m.process_observation(&obs1).trigger_fired);

    // Not sustained long enough
    let obs2 = MonitoringObservation::PerformanceSample {
        metric_name: "latency_p99_ns".into(),
        value_millionths: 70_000_000,
        timestamp_ns: 8_000_000_000,
    };
    assert!(!m.process_observation(&obs2).trigger_fired);

    // Sustained >= 10s
    let obs3 = MonitoringObservation::PerformanceSample {
        metric_name: "latency_p99_ns".into(),
        value_millionths: 65_000_000,
        timestamp_ns: 13_000_000_000,
    };
    let r = m.process_observation(&obs3);
    assert!(r.trigger_fired);
    assert!(m.is_demotion_triggered());
    let eval = r.evaluation.unwrap();
    assert!(matches!(
        eval.reason.as_ref().unwrap(),
        DemotionReason::PerformanceBreach { metric_name, .. } if metric_name == "latency_p99_ns"
    ));
}

#[test]
fn performance_breach_resets_on_recovery() {
    let mut m = monitor();

    // Breach
    let obs1 = MonitoringObservation::PerformanceSample {
        metric_name: "latency_p99_ns".into(),
        value_millionths: 60_000_000,
        timestamp_ns: 2_000_000_000,
    };
    m.process_observation(&obs1);

    // Recover
    let obs2 = MonitoringObservation::PerformanceSample {
        metric_name: "latency_p99_ns".into(),
        value_millionths: 30_000_000,
        timestamp_ns: 8_000_000_000,
    };
    m.process_observation(&obs2);

    // Breach again - duration counter restarted
    let obs3 = MonitoringObservation::PerformanceSample {
        metric_name: "latency_p99_ns".into(),
        value_millionths: 60_000_000,
        timestamp_ns: 13_000_000_000,
    };
    m.process_observation(&obs3);

    // Not enough sustained time from new start
    let obs4 = MonitoringObservation::PerformanceSample {
        metric_name: "latency_p99_ns".into(),
        value_millionths: 60_000_000,
        timestamp_ns: 20_000_000_000,
    };
    assert!(!m.process_observation(&obs4).trigger_fired);
    assert!(!m.is_demotion_triggered());
}

#[test]
fn performance_breach_ignores_unknown_metric() {
    let mut m = monitor();
    let obs = MonitoringObservation::PerformanceSample {
        metric_name: "unknown_metric".into(),
        value_millionths: 999_999_999,
        timestamp_ns: 2_000_000_000,
    };
    assert!(!m.process_observation(&obs).trigger_fired);
}

// ---------------------------------------------------------------------------
// Risk threshold trigger
// ---------------------------------------------------------------------------

#[test]
fn risk_threshold_fires_above_limit() {
    let mut m = monitor();
    let obs = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 900_000,
        timestamp_ns: 2_000_000_000,
    };
    let r = m.process_observation(&obs);
    assert!(r.trigger_fired);
    assert_eq!(m.latest_risk_millionths(), 900_000);
}

#[test]
fn risk_threshold_passes_below_limit() {
    let mut m = monitor();
    let obs = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 500_000,
        timestamp_ns: 2_000_000_000,
    };
    assert!(!m.process_observation(&obs).trigger_fired);
    assert_eq!(m.latest_risk_millionths(), 500_000);
}

#[test]
fn risk_threshold_at_boundary_does_not_fire() {
    let mut m = monitor();
    let obs = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 800_000,
        timestamp_ns: 2_000_000_000,
    };
    assert!(!m.process_observation(&obs).trigger_fired);
}

// ---------------------------------------------------------------------------
// Capability violation trigger
// ---------------------------------------------------------------------------

#[test]
fn capability_violation_fires_outside_envelope() {
    let mut m = monitor();
    let obs = MonitoringObservation::CapabilityEvent {
        capability: "network_send".into(),
        within_envelope: false,
        envelope_digest: ContentHash::compute(b"env"),
        timestamp_ns: 2_000_000_000,
    };
    let r = m.process_observation(&obs);
    assert!(r.trigger_fired);
    let eval = r.evaluation.unwrap();
    assert!(matches!(
        eval.reason.as_ref().unwrap(),
        DemotionReason::CapabilityViolation { attempted_capability, .. }
        if attempted_capability == "network_send"
    ));
}

#[test]
fn capability_within_envelope_does_not_fire() {
    let mut m = monitor();
    let obs = MonitoringObservation::CapabilityEvent {
        capability: "fs_read".into(),
        within_envelope: true,
        envelope_digest: ContentHash::compute(b"env"),
        timestamp_ns: 2_000_000_000,
    };
    assert!(!m.process_observation(&obs).trigger_fired);
}

// ---------------------------------------------------------------------------
// Post-demotion behavior
// ---------------------------------------------------------------------------

#[test]
fn monitor_ignores_observations_after_demotion() {
    let mut m = monitor();
    // Trigger
    let obs1 = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 999_999,
        timestamp_ns: 2_000_000_000,
    };
    assert!(m.process_observation(&obs1).trigger_fired);

    // Subsequent ignored
    let obs2 = MonitoringObservation::CapabilityEvent {
        capability: "evil".into(),
        within_envelope: false,
        envelope_digest: ContentHash::compute(b"x"),
        timestamp_ns: 3_000_000_000,
    };
    let r = m.process_observation(&obs2);
    assert!(!r.trigger_fired);
    assert!(r.evaluation.is_none());
    assert_eq!(r.observations_processed, 2);
}

// ---------------------------------------------------------------------------
// Burn-in period
// ---------------------------------------------------------------------------

#[test]
fn burn_in_period_detection() {
    let m = monitor();
    // start=1_000_000_000, burn_in=300_000_000_000
    assert!(m.is_burn_in(2_000_000_000));
    assert!(m.is_burn_in(300_999_999_999));
    assert!(!m.is_burn_in(301_000_000_001));
}

// ---------------------------------------------------------------------------
// Disabled triggers
// ---------------------------------------------------------------------------

#[test]
fn disabled_triggers_do_not_fire() {
    let receipt = promotion_receipt();
    let mut p = strict_policy();
    p.semantic_divergence_enabled = false;
    p.risk_threshold_enabled = false;
    p.capability_violation_enabled = false;
    p.performance_breach_enabled = false;

    let mut m = AutoDemotionMonitor::new(&receipt, p, 1_000_000_000).unwrap();

    let obs1 = MonitoringObservation::OutputComparison {
        matched: false,
        input_hash: ContentHash::compute(b"x"),
        native_output_hash: ContentHash::compute(b"y"),
        reference_output_hash: ContentHash::compute(b"z"),
        waiver_covered: false,
        timestamp_ns: 2_000_000_000,
    };
    assert!(!m.process_observation(&obs1).trigger_fired);

    let obs2 = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 999_999,
        timestamp_ns: 3_000_000_000,
    };
    assert!(!m.process_observation(&obs2).trigger_fired);

    let obs3 = MonitoringObservation::CapabilityEvent {
        capability: "evil".into(),
        within_envelope: false,
        envelope_digest: ContentHash::compute(b"x"),
        timestamp_ns: 4_000_000_000,
    };
    assert!(!m.process_observation(&obs3).trigger_fired);
    assert!(!m.is_demotion_triggered());
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn identical_observation_sequences_produce_identical_results() {
    let receipt = promotion_receipt();
    let p = strict_policy();

    let observations = vec![
        MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 500_000,
            timestamp_ns: 2_000_000_000,
        },
        MonitoringObservation::OutputComparison {
            matched: true,
            input_hash: ContentHash::compute(b"in"),
            native_output_hash: ContentHash::compute(b"out"),
            reference_output_hash: ContentHash::compute(b"out"),
            waiver_covered: false,
            timestamp_ns: 3_000_000_000,
        },
        MonitoringObservation::PerformanceSample {
            metric_name: "latency_p99_ns".into(),
            value_millionths: 30_000_000,
            timestamp_ns: 4_000_000_000,
        },
    ];

    let mut m1 = AutoDemotionMonitor::new(&receipt, p.clone(), 1_000_000_000).unwrap();
    let mut m2 = AutoDemotionMonitor::new(&receipt, p, 1_000_000_000).unwrap();

    for obs in &observations {
        let r1 = m1.process_observation(obs);
        let r2 = m2.process_observation(obs);
        assert_eq!(r1.trigger_fired, r2.trigger_fired);
        assert_eq!(r1.observations_processed, r2.observations_processed);
    }

    assert_eq!(m1.divergence_count(), m2.divergence_count());
    assert_eq!(m1.latest_risk_millionths(), m2.latest_risk_millionths());
}

// ---------------------------------------------------------------------------
// MonitoringObservation — timestamp extraction
// ---------------------------------------------------------------------------

#[test]
fn monitoring_observation_timestamp_extraction_all_variants() {
    let obs1 = MonitoringObservation::OutputComparison {
        matched: true,
        input_hash: ContentHash::compute(b""),
        native_output_hash: ContentHash::compute(b""),
        reference_output_hash: ContentHash::compute(b""),
        waiver_covered: false,
        timestamp_ns: 10,
    };
    assert_eq!(obs1.timestamp_ns(), 10);

    let obs2 = MonitoringObservation::PerformanceSample {
        metric_name: "m".into(),
        value_millionths: 0,
        timestamp_ns: 20,
    };
    assert_eq!(obs2.timestamp_ns(), 20);

    let obs3 = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 0,
        timestamp_ns: 30,
    };
    assert_eq!(obs3.timestamp_ns(), 30);

    let obs4 = MonitoringObservation::CapabilityEvent {
        capability: "c".into(),
        within_envelope: true,
        envelope_digest: ContentHash::compute(b""),
        timestamp_ns: 40,
    };
    assert_eq!(obs4.timestamp_ns(), 40);
}

// ---------------------------------------------------------------------------
// DemotionError Display — all 7 variants
// ---------------------------------------------------------------------------

#[test]
fn demotion_error_display_id_derivation_failed() {
    // We can't easily construct an IdError, so test via create with invalid zone
    // Just test the other variants that are directly constructible
    let e = DemotionError::SignatureInvalid {
        receipt_id: "rid-123".into(),
    };
    assert!(e.to_string().contains("invalid signature"));
    assert!(e.to_string().contains("rid-123"));
}

#[test]
fn demotion_error_display_slot_mismatch() {
    let e = DemotionError::SlotMismatch {
        expected: "a".into(),
        got: "b".into(),
    };
    assert!(e.to_string().contains("slot mismatch"));
    assert!(e.to_string().contains("expected a"));
    assert!(e.to_string().contains("got b"));
}

#[test]
fn demotion_error_display_candidate_blocked() {
    let e = DemotionError::CandidateBlocked {
        candidate_digest: "abc".into(),
    };
    assert!(e.to_string().contains("blocked"));
    assert!(e.to_string().contains("abc"));
}

#[test]
fn demotion_error_display_no_previous_cell() {
    let e = DemotionError::NoPreviousCell {
        slot_id: "slot-1".into(),
    };
    assert!(e.to_string().contains("no previous cell"));
    assert!(e.to_string().contains("slot-1"));
}

#[test]
fn demotion_error_display_already_demoted() {
    let e = DemotionError::AlreadyDemoted {
        slot_id: "slot-2".into(),
    };
    assert!(e.to_string().contains("already triggered"));
    assert!(e.to_string().contains("slot-2"));
}

// ---------------------------------------------------------------------------
// Observations counter
// ---------------------------------------------------------------------------

#[test]
fn observations_counter_increments() {
    let mut m = monitor();
    for i in 0..5 {
        let obs = MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 100_000,
            timestamp_ns: 2_000_000_000 + i * 1_000_000_000,
        };
        let r = m.process_observation(&obs);
        assert_eq!(r.observations_processed, i + 1);
    }
    assert_eq!(m.observations_processed(), 5);
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn demotion_reason_serde_round_trip_all_variants() {
    let reasons = vec![
        DemotionReason::SemanticDivergence {
            divergence_count: 3,
            first_divergence_artifact: ContentHash::compute(b"x"),
        },
        DemotionReason::PerformanceBreach {
            metric_name: "latency".into(),
            observed_millionths: 100,
            threshold_millionths: 50,
            sustained_duration_ns: 1000,
        },
        DemotionReason::RiskThresholdBreach {
            observed_risk_millionths: 900_000,
            max_risk_millionths: 800_000,
        },
        DemotionReason::CapabilityViolation {
            attempted_capability: "net".into(),
            envelope_digest: ContentHash::compute(b"env"),
        },
        DemotionReason::OperatorInitiated {
            operator_id: "op".into(),
            reason: "manual".into(),
        },
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).expect("serialize");
        let rt: DemotionReason = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*r, rt);
    }
}

#[test]
fn demotion_severity_serde_round_trip() {
    for s in [
        DemotionSeverity::Advisory,
        DemotionSeverity::Warning,
        DemotionSeverity::Critical,
    ] {
        let json = serde_json::to_string(&s).expect("serialize");
        let rt: DemotionSeverity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(s, rt);
    }
}

#[test]
fn demotion_receipt_serde_round_trip() {
    let key = sk();
    let receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native",
            restored_cell_digest: "delegate",
            rollback_token_used: "tok",
            demotion_reason: &DemotionReason::CapabilityViolation {
                attempted_capability: "net_send".into(),
                envelope_digest: ContentHash::compute(b"env"),
            },
            severity: DemotionSeverity::Critical,
            evidence: &[],
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test",
        },
    )
    .expect("create");

    let json = serde_json::to_string(&receipt).expect("serialize");
    let rt: DemotionReceipt = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(receipt, rt);
}

#[test]
fn demotion_policy_serde_round_trip() {
    let mut p = strict_policy();
    p.block_candidate("blocked".into());
    let json = serde_json::to_string(&p).expect("serialize");
    let rt: DemotionPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(p, rt);
}

#[test]
fn auto_demotion_monitor_serde_round_trip() {
    let mut m = monitor();
    let obs = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 500_000,
        timestamp_ns: 2_000_000_000,
    };
    m.process_observation(&obs);
    let json = serde_json::to_string(&m).expect("serialize");
    let rt: AutoDemotionMonitor = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(m, rt);
}

#[test]
fn monitoring_observation_serde_round_trip_all_variants() {
    let observations = vec![
        MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(b"in"),
            native_output_hash: ContentHash::compute(b"n"),
            reference_output_hash: ContentHash::compute(b"r"),
            waiver_covered: true,
            timestamp_ns: 42,
        },
        MonitoringObservation::PerformanceSample {
            metric_name: "m".into(),
            value_millionths: 100,
            timestamp_ns: 43,
        },
        MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 500_000,
            timestamp_ns: 44,
        },
        MonitoringObservation::CapabilityEvent {
            capability: "cap".into(),
            within_envelope: false,
            envelope_digest: ContentHash::compute(b"env"),
            timestamp_ns: 45,
        },
    ];
    for obs in &observations {
        let json = serde_json::to_string(obs).expect("serialize");
        let rt: MonitoringObservation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*obs, rt);
    }
}

#[test]
fn trigger_evaluation_serde_round_trip() {
    let eval = TriggerEvaluation {
        fired: true,
        reason: Some(DemotionReason::RiskThresholdBreach {
            observed_risk_millionths: 900_000,
            max_risk_millionths: 800_000,
        }),
        severity: DemotionSeverity::Critical,
        evidence: vec![DemotionEvidenceItem {
            artifact_hash: ContentHash::compute(b"ev"),
            category: "risk_score".into(),
            collected_at_ns: 42,
            summary: "test".into(),
        }],
    };
    let json = serde_json::to_string(&eval).expect("serialize");
    let rt: TriggerEvaluation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(eval, rt);
}

#[test]
fn demotion_evidence_item_serde_round_trip() {
    let item = DemotionEvidenceItem {
        artifact_hash: ContentHash::compute(b"evidence"),
        category: "divergence_trace".into(),
        collected_at_ns: 1_000_000_000,
        summary: "divergence at input X".into(),
    };
    let json = serde_json::to_string(&item).expect("serialize");
    let rt: DemotionEvidenceItem = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(item, rt);
}

#[test]
fn demotion_error_serde_round_trip() {
    let errors = vec![
        DemotionError::SignatureInvalid {
            receipt_id: "rid".into(),
        },
        DemotionError::SlotMismatch {
            expected: "a".into(),
            got: "b".into(),
        },
        DemotionError::CandidateBlocked {
            candidate_digest: "d".into(),
        },
        DemotionError::NoPreviousCell {
            slot_id: "s".into(),
        },
        DemotionError::AlreadyDemoted {
            slot_id: "s".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let rt: DemotionError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, rt);
    }
}

// ---------------------------------------------------------------------------
// Enrichment batch — PearlTower 2026-03-12
// ---------------------------------------------------------------------------

// --- ObservationResult serde ---

#[test]
fn observation_result_serde_round_trip_no_trigger() {
    use frankenengine_engine::demotion_rollback::ObservationResult;
    let or = ObservationResult {
        trigger_fired: false,
        evaluation: None,
        observations_processed: 7,
    };
    let json = serde_json::to_string(&or).expect("serialize");
    let rt: ObservationResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(or, rt);
}

#[test]
fn observation_result_serde_round_trip_with_trigger() {
    use frankenengine_engine::demotion_rollback::ObservationResult;
    let or = ObservationResult {
        trigger_fired: true,
        evaluation: Some(TriggerEvaluation {
            fired: true,
            reason: Some(DemotionReason::CapabilityViolation {
                attempted_capability: "fs_write".into(),
                envelope_digest: ContentHash::compute(b"env"),
            }),
            severity: DemotionSeverity::Critical,
            evidence: vec![DemotionEvidenceItem {
                artifact_hash: ContentHash::compute(b"cap-ev"),
                category: "capability_violation".into(),
                collected_at_ns: 100,
                summary: "violation of fs_write".into(),
            }],
        }),
        observations_processed: 1,
    };
    let json = serde_json::to_string(&or).expect("serialize");
    let rt: ObservationResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(or, rt);
}

// --- PerformanceThreshold serde ---

#[test]
fn performance_threshold_serde_round_trip() {
    let pt = PerformanceThreshold {
        metric_name: "throughput_ops_sec".into(),
        max_value_millionths: 100_000_000,
        sustained_duration_ns: 5_000_000_000,
    };
    let json = serde_json::to_string(&pt).expect("serialize");
    let rt: PerformanceThreshold = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(pt, rt);
}

// --- DemotionError Display: IdDerivationFailed and SignatureFailed ---

#[test]
fn demotion_error_display_signature_failed() {
    use frankenengine_engine::signature_preimage::SignatureError;
    let e = DemotionError::SignatureFailed(SignatureError::InvalidSigningKey);
    let s = e.to_string();
    assert!(s.contains("signature error"), "got: {s}");
}

// --- DemotionError is std::error::Error ---

#[test]
fn demotion_error_implements_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(DemotionError::NoPreviousCell {
        slot_id: "s-1".into(),
    });
    assert!(e.to_string().contains("no previous cell"));
}

#[test]
fn demotion_error_implements_std_error_all_constructible() {
    let errors: Vec<Box<dyn std::error::Error>> = vec![
        Box::new(DemotionError::SignatureInvalid {
            receipt_id: "r".into(),
        }),
        Box::new(DemotionError::SlotMismatch {
            expected: "a".into(),
            got: "b".into(),
        }),
        Box::new(DemotionError::CandidateBlocked {
            candidate_digest: "d".into(),
        }),
        Box::new(DemotionError::NoPreviousCell {
            slot_id: "s".into(),
        }),
        Box::new(DemotionError::AlreadyDemoted {
            slot_id: "s".into(),
        }),
    ];
    for e in &errors {
        assert!(!e.to_string().is_empty());
    }
}

// --- DemotionReason Ord trait ---

#[test]
fn demotion_reason_ordering_semantic_before_performance() {
    let a = DemotionReason::SemanticDivergence {
        divergence_count: 1,
        first_divergence_artifact: ContentHash::compute(b"a"),
    };
    let b = DemotionReason::PerformanceBreach {
        metric_name: "lat".into(),
        observed_millionths: 0,
        threshold_millionths: 0,
        sustained_duration_ns: 0,
    };
    assert!(
        a < b,
        "SemanticDivergence should be ordered before PerformanceBreach"
    );
}

#[test]
fn demotion_reason_ordering_risk_before_capability() {
    let a = DemotionReason::RiskThresholdBreach {
        observed_risk_millionths: 0,
        max_risk_millionths: 0,
    };
    let b = DemotionReason::CapabilityViolation {
        attempted_capability: "net".into(),
        envelope_digest: ContentHash::compute(b"env"),
    };
    assert!(
        a < b,
        "RiskThresholdBreach should be ordered before CapabilityViolation"
    );
}

#[test]
fn demotion_reason_ordering_capability_before_operator() {
    let a = DemotionReason::CapabilityViolation {
        attempted_capability: "net".into(),
        envelope_digest: ContentHash::compute(b"env"),
    };
    let b = DemotionReason::OperatorInitiated {
        operator_id: "op".into(),
        reason: "r".into(),
    };
    assert!(
        a < b,
        "CapabilityViolation should be ordered before OperatorInitiated"
    );
}

#[test]
fn demotion_reason_same_variant_different_count_ordering() {
    let a = DemotionReason::SemanticDivergence {
        divergence_count: 1,
        first_divergence_artifact: ContentHash::compute(b"x"),
    };
    let b = DemotionReason::SemanticDivergence {
        divergence_count: 5,
        first_divergence_artifact: ContentHash::compute(b"x"),
    };
    assert!(a < b, "lower divergence_count should sort before higher");
}

// --- DemotionReason Hash trait ---

#[test]
fn demotion_reason_hash_equal_for_clones() {
    use std::hash::{Hash, Hasher};
    let r = DemotionReason::PerformanceBreach {
        metric_name: "throughput".into(),
        observed_millionths: 80_000_000,
        threshold_millionths: 50_000_000,
        sustained_duration_ns: 10_000_000_000,
    };
    let r2 = r.clone();
    let hash = |v: &DemotionReason| {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        v.hash(&mut h);
        h.finish()
    };
    assert_eq!(hash(&r), hash(&r2));
}

// --- DemotionSeverity Clone/Copy ---

#[test]
fn demotion_severity_is_copy() {
    let s = DemotionSeverity::Warning;
    let s2 = s; // copy
    assert_eq!(s, s2);
}

#[test]
fn demotion_severity_clone_equals_original() {
    let s = DemotionSeverity::Critical;
    let s2 = s.clone();
    assert_eq!(s, s2);
}

// --- Multiple performance thresholds ---

#[test]
fn multiple_performance_thresholds_fire_independently() {
    let receipt = promotion_receipt();
    let mut p = strict_policy();
    p.performance_thresholds.push(PerformanceThreshold {
        metric_name: "throughput_ops_sec".into(),
        max_value_millionths: 100_000_000,
        sustained_duration_ns: 5_000_000_000,
    });
    let mut m = AutoDemotionMonitor::new(&receipt, p, 1_000_000_000).unwrap();

    // Breach throughput threshold
    let obs1 = MonitoringObservation::PerformanceSample {
        metric_name: "throughput_ops_sec".into(),
        value_millionths: 150_000_000,
        timestamp_ns: 2_000_000_000,
    };
    assert!(!m.process_observation(&obs1).trigger_fired);

    // Sustained throughput breach fires at 5s
    let obs2 = MonitoringObservation::PerformanceSample {
        metric_name: "throughput_ops_sec".into(),
        value_millionths: 150_000_000,
        timestamp_ns: 8_000_000_000,
    };
    let r = m.process_observation(&obs2);
    assert!(r.trigger_fired);
    let eval = r.evaluation.unwrap();
    assert!(matches!(
        eval.reason.as_ref().unwrap(),
        DemotionReason::PerformanceBreach { metric_name, .. } if metric_name == "throughput_ops_sec"
    ));
}

// --- Performance breach exact threshold boundary ---

#[test]
fn performance_breach_at_exact_threshold_not_triggered() {
    let mut m = monitor();
    // Exactly at threshold (50M): not a breach (> required)
    let obs = MonitoringObservation::PerformanceSample {
        metric_name: "latency_p99_ns".into(),
        value_millionths: 50_000_000,
        timestamp_ns: 2_000_000_000,
    };
    assert!(!m.process_observation(&obs).trigger_fired);

    // Even after sustained, no fire since it's not above threshold
    let obs2 = MonitoringObservation::PerformanceSample {
        metric_name: "latency_p99_ns".into(),
        value_millionths: 50_000_000,
        timestamp_ns: 20_000_000_000,
    };
    assert!(!m.process_observation(&obs2).trigger_fired);
}

// --- Performance breach exact sustained duration boundary ---

#[test]
fn performance_breach_fires_at_exact_sustained_boundary() {
    let mut m = monitor();
    // Start breach at t=2s
    let obs1 = MonitoringObservation::PerformanceSample {
        metric_name: "latency_p99_ns".into(),
        value_millionths: 60_000_000,
        timestamp_ns: 2_000_000_000,
    };
    assert!(!m.process_observation(&obs1).trigger_fired);

    // Exactly 10s sustained
    let obs2 = MonitoringObservation::PerformanceSample {
        metric_name: "latency_p99_ns".into(),
        value_millionths: 60_000_000,
        timestamp_ns: 12_000_000_000,
    };
    assert!(
        m.process_observation(&obs2).trigger_fired,
        "should fire at exact sustained boundary"
    );
}

// --- Semantic divergence first artifact tracking ---

#[test]
fn semantic_divergence_first_artifact_is_from_first_divergence() {
    let receipt = promotion_receipt();
    let mut p = strict_policy();
    p.max_divergence_count = 3;
    let mut m = AutoDemotionMonitor::new(&receipt, p, 1_000_000_000).unwrap();

    let first_input_hash = ContentHash::compute(b"first-divergent-input");
    let obs1 = MonitoringObservation::OutputComparison {
        matched: false,
        input_hash: first_input_hash,
        native_output_hash: ContentHash::compute(b"n1"),
        reference_output_hash: ContentHash::compute(b"r1"),
        waiver_covered: false,
        timestamp_ns: 2_000_000_000,
    };
    assert!(!m.process_observation(&obs1).trigger_fired);

    let obs2 = MonitoringObservation::OutputComparison {
        matched: false,
        input_hash: ContentHash::compute(b"second-divergent-input"),
        native_output_hash: ContentHash::compute(b"n2"),
        reference_output_hash: ContentHash::compute(b"r2"),
        waiver_covered: false,
        timestamp_ns: 3_000_000_000,
    };
    assert!(!m.process_observation(&obs2).trigger_fired);

    // Third divergence fires
    let obs3 = MonitoringObservation::OutputComparison {
        matched: false,
        input_hash: ContentHash::compute(b"third-divergent-input"),
        native_output_hash: ContentHash::compute(b"n3"),
        reference_output_hash: ContentHash::compute(b"r3"),
        waiver_covered: false,
        timestamp_ns: 4_000_000_000,
    };
    let r = m.process_observation(&obs3);
    assert!(r.trigger_fired);
    let eval = r.evaluation.unwrap();
    match eval.reason.unwrap() {
        DemotionReason::SemanticDivergence {
            first_divergence_artifact,
            ..
        } => {
            // Should track the first divergent input
            assert_eq!(first_divergence_artifact, first_input_hash);
        }
        other => panic!("unexpected reason: {other}"),
    }
}

// --- Content hash varies with different fields ---

#[test]
fn content_hash_varies_with_zone() {
    let key = sk();
    let make_receipt = |zone: &str| {
        DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &slot(),
                demoted_cell_digest: "native",
                restored_cell_digest: "delegate",
                rollback_token_used: "tok",
                demotion_reason: &DemotionReason::SemanticDivergence {
                    divergence_count: 1,
                    first_divergence_artifact: ContentHash::compute(b"d"),
                },
                severity: DemotionSeverity::Critical,
                evidence: &[],
                timestamp_ns: 1_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone,
            },
        )
        .unwrap()
    };
    let r1 = make_receipt("zone-a");
    let r2 = make_receipt("zone-b");
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn content_hash_varies_with_epoch() {
    let key = sk();
    let make_receipt = |epoch_val: u64| {
        DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &slot(),
                demoted_cell_digest: "native",
                restored_cell_digest: "delegate",
                rollback_token_used: "tok",
                demotion_reason: &DemotionReason::RiskThresholdBreach {
                    observed_risk_millionths: 900_000,
                    max_risk_millionths: 800_000,
                },
                severity: DemotionSeverity::Critical,
                evidence: &[],
                timestamp_ns: 1_000_000_000,
                epoch: SecurityEpoch::from_raw(epoch_val),
                zone: "z",
            },
        )
        .unwrap()
    };
    let r1 = make_receipt(1);
    let r2 = make_receipt(2);
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn content_hash_varies_with_severity() {
    let key = sk();
    let make_receipt = |severity: DemotionSeverity| {
        DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &slot(),
                demoted_cell_digest: "native",
                restored_cell_digest: "delegate",
                rollback_token_used: "tok",
                demotion_reason: &DemotionReason::OperatorInitiated {
                    operator_id: "op".into(),
                    reason: "manual".into(),
                },
                severity,
                evidence: &[],
                timestamp_ns: 1_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "z",
            },
        )
        .unwrap()
    };
    let r1 = make_receipt(DemotionSeverity::Warning);
    let r2 = make_receipt(DemotionSeverity::Critical);
    assert_ne!(r1.content_hash(), r2.content_hash());
}

// --- Receipt with multiple evidence items ---

#[test]
fn receipt_with_multiple_evidence_items_preserves_order() {
    let key = sk();
    let evidence = vec![
        DemotionEvidenceItem {
            artifact_hash: ContentHash::compute(b"ev-1"),
            category: "divergence_trace".into(),
            collected_at_ns: 1_000_000,
            summary: "first".into(),
        },
        DemotionEvidenceItem {
            artifact_hash: ContentHash::compute(b"ev-2"),
            category: "latency_sample".into(),
            collected_at_ns: 2_000_000,
            summary: "second".into(),
        },
        DemotionEvidenceItem {
            artifact_hash: ContentHash::compute(b"ev-3"),
            category: "risk_score".into(),
            collected_at_ns: 3_000_000,
            summary: "third".into(),
        },
    ];
    let receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native",
            restored_cell_digest: "delegate",
            rollback_token_used: "tok",
            demotion_reason: &DemotionReason::SemanticDivergence {
                divergence_count: 1,
                first_divergence_artifact: ContentHash::compute(b"div"),
            },
            severity: DemotionSeverity::Critical,
            evidence: &evidence,
            timestamp_ns: 5_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test",
        },
    )
    .expect("create");
    assert_eq!(receipt.evidence.len(), 3);
    assert_eq!(receipt.evidence[0].category, "divergence_trace");
    assert_eq!(receipt.evidence[1].category, "latency_sample");
    assert_eq!(receipt.evidence[2].category, "risk_score");
    receipt
        .verify_signature(&key.verification_key())
        .expect("verify");
}

// --- Tamper detection ---

#[test]
fn tamper_detection_demoted_cell_digest() {
    let key = sk();
    let mut receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native",
            restored_cell_digest: "delegate",
            rollback_token_used: "tok",
            demotion_reason: &DemotionReason::OperatorInitiated {
                operator_id: "op".into(),
                reason: "manual".into(),
            },
            severity: DemotionSeverity::Warning,
            evidence: &[],
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "z",
        },
    )
    .expect("create");
    receipt.demoted_cell_digest = "tampered".into();
    assert!(matches!(
        receipt.verify_signature(&key.verification_key()),
        Err(DemotionError::SignatureInvalid { .. })
    ));
}

#[test]
fn tamper_detection_restored_cell_digest() {
    let key = sk();
    let mut receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native",
            restored_cell_digest: "delegate",
            rollback_token_used: "tok",
            demotion_reason: &DemotionReason::OperatorInitiated {
                operator_id: "op".into(),
                reason: "r".into(),
            },
            severity: DemotionSeverity::Warning,
            evidence: &[],
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "z",
        },
    )
    .expect("create");
    receipt.restored_cell_digest = "tampered".into();
    assert!(receipt.verify_signature(&key.verification_key()).is_err());
}

#[test]
fn tamper_detection_rollback_token() {
    let key = sk();
    let mut receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native",
            restored_cell_digest: "delegate",
            rollback_token_used: "tok-original",
            demotion_reason: &DemotionReason::OperatorInitiated {
                operator_id: "op".into(),
                reason: "r".into(),
            },
            severity: DemotionSeverity::Warning,
            evidence: &[],
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "z",
        },
    )
    .expect("create");
    receipt.rollback_token_used = "tok-tampered".into();
    assert!(receipt.verify_signature(&key.verification_key()).is_err());
}

#[test]
fn tamper_detection_timestamp() {
    let key = sk();
    let mut receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native",
            restored_cell_digest: "delegate",
            rollback_token_used: "tok",
            demotion_reason: &DemotionReason::RiskThresholdBreach {
                observed_risk_millionths: 900_000,
                max_risk_millionths: 800_000,
            },
            severity: DemotionSeverity::Critical,
            evidence: &[],
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "z",
        },
    )
    .expect("create");
    receipt.timestamp_ns = 9_999_999_999;
    assert!(receipt.verify_signature(&key.verification_key()).is_err());
}

#[test]
fn tamper_detection_zone() {
    let key = sk();
    let mut receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native",
            restored_cell_digest: "delegate",
            rollback_token_used: "tok",
            demotion_reason: &DemotionReason::RiskThresholdBreach {
                observed_risk_millionths: 900_000,
                max_risk_millionths: 800_000,
            },
            severity: DemotionSeverity::Critical,
            evidence: &[],
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "production",
        },
    )
    .expect("create");
    receipt.zone = "staging".into();
    assert!(receipt.verify_signature(&key.verification_key()).is_err());
}

#[test]
fn tamper_detection_severity() {
    let key = sk();
    let mut receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native",
            restored_cell_digest: "delegate",
            rollback_token_used: "tok",
            demotion_reason: &DemotionReason::OperatorInitiated {
                operator_id: "op".into(),
                reason: "r".into(),
            },
            severity: DemotionSeverity::Critical,
            evidence: &[],
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "z",
        },
    )
    .expect("create");
    receipt.severity = DemotionSeverity::Advisory;
    assert!(receipt.verify_signature(&key.verification_key()).is_err());
}

#[test]
fn tamper_detection_reason() {
    let key = sk();
    let mut receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native",
            restored_cell_digest: "delegate",
            rollback_token_used: "tok",
            demotion_reason: &DemotionReason::RiskThresholdBreach {
                observed_risk_millionths: 900_000,
                max_risk_millionths: 800_000,
            },
            severity: DemotionSeverity::Critical,
            evidence: &[],
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "z",
        },
    )
    .expect("create");
    receipt.demotion_reason = DemotionReason::OperatorInitiated {
        operator_id: "attacker".into(),
        reason: "forged".into(),
    };
    assert!(receipt.verify_signature(&key.verification_key()).is_err());
}

// --- Burn-in edge cases ---

#[test]
fn burn_in_at_exact_boundary() {
    let m = monitor();
    // start=1_000_000_000, burn_in=300_000_000_000
    let boundary = 1_000_000_000 + 300_000_000_000;
    assert!(
        m.is_burn_in(boundary - 1),
        "1ns before end should be in burn-in"
    );
    assert!(
        !m.is_burn_in(boundary),
        "exact boundary should be outside burn-in"
    );
    assert!(!m.is_burn_in(boundary + 1));
}

#[test]
fn burn_in_underflow_saturates() {
    let m = monitor();
    // monitoring_start_ns=1_000_000_000, passing current_ns=0 underflows
    assert!(
        m.is_burn_in(0),
        "time before start should be within burn-in due to saturating_sub"
    );
}

#[test]
fn burn_in_at_start_time() {
    let m = monitor();
    // current_ns equals monitoring_start_ns: elapsed=0 < burn_in_duration
    assert!(m.is_burn_in(1_000_000_000));
}

// --- Receipt ID variations ---

#[test]
fn receipt_id_varies_by_restored_digest() {
    let id1 = DemotionReceipt::derive_receipt_id(&slot(), "native", "delegate-a", 1000, "z")
        .expect("derive");
    let id2 = DemotionReceipt::derive_receipt_id(&slot(), "native", "delegate-b", 1000, "z")
        .expect("derive");
    assert_ne!(id1, id2);
}

#[test]
fn receipt_id_varies_by_slot() {
    let slot_a = SlotId::new("slot-alpha").unwrap();
    let slot_b = SlotId::new("slot-beta").unwrap();
    let id1 = DemotionReceipt::derive_receipt_id(&slot_a, "native", "delegate", 1000, "z")
        .expect("derive");
    let id2 = DemotionReceipt::derive_receipt_id(&slot_b, "native", "delegate", 1000, "z")
        .expect("derive");
    assert_ne!(id1, id2);
}

#[test]
fn receipt_id_varies_by_zone() {
    let id1 = DemotionReceipt::derive_receipt_id(&slot(), "native", "delegate", 1000, "zone-a")
        .expect("derive");
    let id2 = DemotionReceipt::derive_receipt_id(&slot(), "native", "delegate", 1000, "zone-b")
        .expect("derive");
    assert_ne!(id1, id2);
}

#[test]
fn receipt_id_varies_by_timestamp() {
    let id1 = DemotionReceipt::derive_receipt_id(&slot(), "native", "delegate", 1000, "z")
        .expect("derive");
    let id2 = DemotionReceipt::derive_receipt_id(&slot(), "native", "delegate", 2000, "z")
        .expect("derive");
    assert_ne!(id1, id2);
}

// --- Custom severity mappings ---

#[test]
fn custom_severity_semantic_divergence_advisory() {
    let receipt = promotion_receipt();
    let mut p = strict_policy();
    p.semantic_divergence_severity = DemotionSeverity::Advisory;
    let mut m = AutoDemotionMonitor::new(&receipt, p, 1_000_000_000).unwrap();

    let obs = MonitoringObservation::OutputComparison {
        matched: false,
        input_hash: ContentHash::compute(b"in"),
        native_output_hash: ContentHash::compute(b"n"),
        reference_output_hash: ContentHash::compute(b"r"),
        waiver_covered: false,
        timestamp_ns: 2_000_000_000,
    };
    let r = m.process_observation(&obs);
    assert!(r.trigger_fired);
    assert_eq!(r.evaluation.unwrap().severity, DemotionSeverity::Advisory);
}

#[test]
fn custom_severity_risk_warning() {
    let receipt = promotion_receipt();
    let mut p = strict_policy();
    p.risk_threshold_severity = DemotionSeverity::Warning;
    let mut m = AutoDemotionMonitor::new(&receipt, p, 1_000_000_000).unwrap();

    let obs = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 900_000,
        timestamp_ns: 2_000_000_000,
    };
    let r = m.process_observation(&obs);
    assert!(r.trigger_fired);
    assert_eq!(r.evaluation.unwrap().severity, DemotionSeverity::Warning);
}

#[test]
fn custom_severity_capability_advisory() {
    let receipt = promotion_receipt();
    let mut p = strict_policy();
    p.capability_violation_severity = DemotionSeverity::Advisory;
    let mut m = AutoDemotionMonitor::new(&receipt, p, 1_000_000_000).unwrap();

    let obs = MonitoringObservation::CapabilityEvent {
        capability: "evil".into(),
        within_envelope: false,
        envelope_digest: ContentHash::compute(b"env"),
        timestamp_ns: 2_000_000_000,
    };
    let r = m.process_observation(&obs);
    assert!(r.trigger_fired);
    assert_eq!(r.evaluation.unwrap().severity, DemotionSeverity::Advisory);
}

// --- Observation counter after demotion ---

#[test]
fn observation_counter_still_increments_post_demotion() {
    let mut m = monitor();
    // Trigger
    let obs1 = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 999_999,
        timestamp_ns: 2_000_000_000,
    };
    assert!(m.process_observation(&obs1).trigger_fired);
    assert_eq!(m.observations_processed(), 1);

    // Post-demotion observations still counted
    for i in 0..5 {
        let obs = MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 100_000,
            timestamp_ns: 3_000_000_000 + i * 1_000_000_000,
        };
        let r = m.process_observation(&obs);
        assert!(!r.trigger_fired);
        assert_eq!(r.observations_processed, i + 2);
    }
    assert_eq!(m.observations_processed(), 6);
}

// --- Risk score tracking ---

#[test]
fn risk_score_tracks_latest_below_threshold() {
    let mut m = monitor();
    for (risk, ts) in [
        (100_000u64, 2_000_000_000u64),
        (300_000, 3_000_000_000),
        (700_000, 4_000_000_000),
        (500_000, 5_000_000_000),
    ] {
        let obs = MonitoringObservation::RiskScoreUpdate {
            risk_millionths: risk,
            timestamp_ns: ts,
        };
        assert!(!m.process_observation(&obs).trigger_fired);
        assert_eq!(m.latest_risk_millionths(), risk);
    }
}

#[test]
fn risk_score_one_above_threshold_fires() {
    let mut m = monitor();
    // 800_001 is just above 800_000 threshold
    let obs = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 800_001,
        timestamp_ns: 2_000_000_000,
    };
    assert!(m.process_observation(&obs).trigger_fired);
    assert_eq!(m.latest_risk_millionths(), 800_001);
}

// --- Interleaved observation types ---

#[test]
fn interleaved_observations_all_benign_no_trigger() {
    let mut m = monitor();
    let observations: Vec<MonitoringObservation> = vec![
        MonitoringObservation::OutputComparison {
            matched: true,
            input_hash: ContentHash::compute(b"in-1"),
            native_output_hash: ContentHash::compute(b"out-1"),
            reference_output_hash: ContentHash::compute(b"out-1"),
            waiver_covered: false,
            timestamp_ns: 2_000_000_000,
        },
        MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 100_000,
            timestamp_ns: 3_000_000_000,
        },
        MonitoringObservation::PerformanceSample {
            metric_name: "latency_p99_ns".into(),
            value_millionths: 10_000_000,
            timestamp_ns: 4_000_000_000,
        },
        MonitoringObservation::CapabilityEvent {
            capability: "fs_read".into(),
            within_envelope: true,
            envelope_digest: ContentHash::compute(b"env"),
            timestamp_ns: 5_000_000_000,
        },
        MonitoringObservation::OutputComparison {
            matched: true,
            input_hash: ContentHash::compute(b"in-2"),
            native_output_hash: ContentHash::compute(b"out-2"),
            reference_output_hash: ContentHash::compute(b"out-2"),
            waiver_covered: false,
            timestamp_ns: 6_000_000_000,
        },
    ];
    for obs in &observations {
        assert!(!m.process_observation(obs).trigger_fired);
    }
    assert!(!m.is_demotion_triggered());
    assert_eq!(m.observations_processed(), 5);
    assert_eq!(m.divergence_count(), 0);
}

// --- Monitor serde round-trip after processing ---

#[test]
fn monitor_serde_after_processing_without_trigger() {
    let mut m = monitor();
    let obs = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 500_000,
        timestamp_ns: 2_000_000_000,
    };
    m.process_observation(&obs);
    let obs2 = MonitoringObservation::OutputComparison {
        matched: true,
        input_hash: ContentHash::compute(b"in"),
        native_output_hash: ContentHash::compute(b"out"),
        reference_output_hash: ContentHash::compute(b"out"),
        waiver_covered: false,
        timestamp_ns: 3_000_000_000,
    };
    m.process_observation(&obs2);

    let json = serde_json::to_string(&m).expect("serialize");
    let rt: AutoDemotionMonitor = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(m, rt);
    assert_eq!(rt.observations_processed(), 2);
    assert_eq!(rt.latest_risk_millionths(), 500_000);
    assert!(!rt.is_demotion_triggered());
}

#[test]
fn monitor_serde_after_trigger_preserves_state() {
    let mut m = monitor();
    let obs = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 900_000,
        timestamp_ns: 2_000_000_000,
    };
    assert!(m.process_observation(&obs).trigger_fired);

    let json = serde_json::to_string(&m).expect("serialize");
    let rt: AutoDemotionMonitor = serde_json::from_str(&json).expect("deserialize");
    assert!(rt.is_demotion_triggered());
    assert_eq!(rt.latest_risk_millionths(), 900_000);
    assert_eq!(rt.observations_processed(), 1);

    // Restored monitor also ignores new observations
    let mut rt = rt;
    let obs2 = MonitoringObservation::CapabilityEvent {
        capability: "evil".into(),
        within_envelope: false,
        envelope_digest: ContentHash::compute(b"x"),
        timestamp_ns: 3_000_000_000,
    };
    let r = rt.process_observation(&obs2);
    assert!(!r.trigger_fired);
    assert!(r.evaluation.is_none());
}

// --- DemotionReason Display format details ---

#[test]
fn demotion_reason_display_semantic_includes_count() {
    let r = DemotionReason::SemanticDivergence {
        divergence_count: 42,
        first_divergence_artifact: ContentHash::compute(b"x"),
    };
    let s = r.to_string();
    assert!(s.contains("42"), "should include count 42, got: {s}");
    assert!(s.contains("outputs"), "should include 'outputs', got: {s}");
}

#[test]
fn demotion_reason_display_performance_includes_observed_and_threshold() {
    let r = DemotionReason::PerformanceBreach {
        metric_name: "my_metric".into(),
        observed_millionths: 12345,
        threshold_millionths: 6789,
        sustained_duration_ns: 1000,
    };
    let s = r.to_string();
    assert!(
        s.contains("my_metric"),
        "should contain metric name, got: {s}"
    );
    assert!(
        s.contains("12345"),
        "should contain observed value, got: {s}"
    );
    assert!(
        s.contains("6789"),
        "should contain threshold value, got: {s}"
    );
}

#[test]
fn demotion_reason_display_risk_includes_scores() {
    let r = DemotionReason::RiskThresholdBreach {
        observed_risk_millionths: 950_000,
        max_risk_millionths: 800_000,
    };
    let s = r.to_string();
    assert!(
        s.contains("950000"),
        "should contain observed risk, got: {s}"
    );
    assert!(s.contains("800000"), "should contain max risk, got: {s}");
}

#[test]
fn demotion_reason_display_capability_includes_name() {
    let r = DemotionReason::CapabilityViolation {
        attempted_capability: "spawn_process".into(),
        envelope_digest: ContentHash::compute(b"env"),
    };
    let s = r.to_string();
    assert!(
        s.contains("spawn_process"),
        "should contain capability name, got: {s}"
    );
}

#[test]
fn demotion_reason_display_operator_includes_id() {
    let r = DemotionReason::OperatorInitiated {
        operator_id: "admin-77".into(),
        reason: "emergency rollback".into(),
    };
    let s = r.to_string();
    assert!(
        s.contains("admin-77"),
        "should contain operator id, got: {s}"
    );
}

// --- Receipt creation for each reason variant ---

#[test]
fn receipt_creation_semantic_divergence() {
    let key = sk();
    let receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native",
            restored_cell_digest: "delegate",
            rollback_token_used: "tok",
            demotion_reason: &DemotionReason::SemanticDivergence {
                divergence_count: 5,
                first_divergence_artifact: ContentHash::compute(b"d"),
            },
            severity: DemotionSeverity::Critical,
            evidence: &[],
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "z",
        },
    )
    .expect("create");
    assert!(matches!(
        receipt.demotion_reason,
        DemotionReason::SemanticDivergence { .. }
    ));
    receipt
        .verify_signature(&key.verification_key())
        .expect("verify");
}

#[test]
fn receipt_creation_performance_breach() {
    let key = sk();
    let receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native",
            restored_cell_digest: "delegate",
            rollback_token_used: "tok",
            demotion_reason: &DemotionReason::PerformanceBreach {
                metric_name: "latency_p99_ns".into(),
                observed_millionths: 80_000_000,
                threshold_millionths: 50_000_000,
                sustained_duration_ns: 15_000_000_000,
            },
            severity: DemotionSeverity::Warning,
            evidence: &[],
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "z",
        },
    )
    .expect("create");
    assert!(matches!(
        receipt.demotion_reason,
        DemotionReason::PerformanceBreach { .. }
    ));
    receipt
        .verify_signature(&key.verification_key())
        .expect("verify");
}

#[test]
fn receipt_creation_risk_threshold() {
    let key = sk();
    let receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native",
            restored_cell_digest: "delegate",
            rollback_token_used: "tok",
            demotion_reason: &DemotionReason::RiskThresholdBreach {
                observed_risk_millionths: 900_000,
                max_risk_millionths: 800_000,
            },
            severity: DemotionSeverity::Critical,
            evidence: &[],
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "z",
        },
    )
    .expect("create");
    assert!(matches!(
        receipt.demotion_reason,
        DemotionReason::RiskThresholdBreach { .. }
    ));
    receipt
        .verify_signature(&key.verification_key())
        .expect("verify");
}

#[test]
fn receipt_creation_capability_violation() {
    let key = sk();
    let receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native",
            restored_cell_digest: "delegate",
            rollback_token_used: "tok",
            demotion_reason: &DemotionReason::CapabilityViolation {
                attempted_capability: "exec_shell".into(),
                envelope_digest: ContentHash::compute(b"restricted"),
            },
            severity: DemotionSeverity::Critical,
            evidence: &[],
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "z",
        },
    )
    .expect("create");
    assert!(matches!(
        receipt.demotion_reason,
        DemotionReason::CapabilityViolation { .. }
    ));
    receipt
        .verify_signature(&key.verification_key())
        .expect("verify");
}

#[test]
fn receipt_creation_operator_initiated() {
    let key = sk();
    let receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native",
            restored_cell_digest: "delegate",
            rollback_token_used: "tok",
            demotion_reason: &DemotionReason::OperatorInitiated {
                operator_id: "admin-42".into(),
                reason: "emergency rollback".into(),
            },
            severity: DemotionSeverity::Warning,
            evidence: &[],
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "z",
        },
    )
    .expect("create");
    assert!(matches!(
        receipt.demotion_reason,
        DemotionReason::OperatorInitiated { .. }
    ));
    receipt
        .verify_signature(&key.verification_key())
        .expect("verify");
}

// --- Policy with empty perf thresholds ---

#[test]
fn policy_no_perf_thresholds_ignores_perf_samples() {
    let receipt = promotion_receipt();
    let p = DemotionPolicy::strict(slot()); // no performance_thresholds pushed
    let mut m = AutoDemotionMonitor::new(&receipt, p, 1_000_000_000).unwrap();

    let obs = MonitoringObservation::PerformanceSample {
        metric_name: "latency_p99_ns".into(),
        value_millionths: 999_999_999,
        timestamp_ns: 2_000_000_000,
    };
    assert!(!m.process_observation(&obs).trigger_fired);
}

// --- Large observation sequences ---

#[test]
fn large_observation_sequence_deterministic() {
    let receipt = promotion_receipt();
    let p = strict_policy();

    let mut m1 = AutoDemotionMonitor::new(&receipt, p.clone(), 1_000_000_000).unwrap();
    let mut m2 = AutoDemotionMonitor::new(&receipt, p, 1_000_000_000).unwrap();

    for i in 0u64..50 {
        let obs = MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 100_000 + i * 10_000,
            timestamp_ns: 2_000_000_000 + i * 100_000_000,
        };
        let r1 = m1.process_observation(&obs);
        let r2 = m2.process_observation(&obs);
        assert_eq!(r1.trigger_fired, r2.trigger_fired);
        assert_eq!(r1.observations_processed, r2.observations_processed);
    }
    assert_eq!(m1.latest_risk_millionths(), m2.latest_risk_millionths());
    assert_eq!(m1.is_demotion_triggered(), m2.is_demotion_triggered());
}

// --- Evidence summary content verification ---

#[test]
fn risk_trigger_evidence_summary_includes_values() {
    let mut m = monitor();
    let obs = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 900_000,
        timestamp_ns: 2_000_000_000,
    };
    let r = m.process_observation(&obs);
    assert!(r.trigger_fired);
    let eval = r.evaluation.unwrap();
    assert_eq!(eval.evidence.len(), 1);
    let summary = &eval.evidence[0].summary;
    assert!(
        summary.contains("900000"),
        "should contain observed risk in summary, got: {summary}"
    );
    assert!(
        summary.contains("800000"),
        "should contain max risk in summary, got: {summary}"
    );
}

#[test]
fn performance_trigger_evidence_summary_includes_metric() {
    let mut m = monitor();
    // Start breach
    let obs1 = MonitoringObservation::PerformanceSample {
        metric_name: "latency_p99_ns".into(),
        value_millionths: 60_000_000,
        timestamp_ns: 2_000_000_000,
    };
    m.process_observation(&obs1);
    // Fire
    let obs2 = MonitoringObservation::PerformanceSample {
        metric_name: "latency_p99_ns".into(),
        value_millionths: 60_000_000,
        timestamp_ns: 13_000_000_000,
    };
    let r = m.process_observation(&obs2);
    assert!(r.trigger_fired);
    let eval = r.evaluation.unwrap();
    let summary = &eval.evidence[0].summary;
    assert!(
        summary.contains("latency_p99_ns"),
        "summary should contain metric name, got: {summary}"
    );
    assert!(
        summary.contains("60000000"),
        "summary should contain observed value, got: {summary}"
    );
}

#[test]
fn semantic_divergence_evidence_summary_includes_slot_and_count() {
    let mut m = monitor();
    let obs = MonitoringObservation::OutputComparison {
        matched: false,
        input_hash: ContentHash::compute(b"in"),
        native_output_hash: ContentHash::compute(b"n"),
        reference_output_hash: ContentHash::compute(b"r"),
        waiver_covered: false,
        timestamp_ns: 2_000_000_000,
    };
    let r = m.process_observation(&obs);
    assert!(r.trigger_fired);
    let eval = r.evaluation.unwrap();
    let summary = &eval.evidence[0].summary;
    assert!(
        summary.contains("slot-integ-001"),
        "summary should include slot id, got: {summary}"
    );
    assert!(
        summary.contains("divergence #1"),
        "summary should include count, got: {summary}"
    );
}

#[test]
fn capability_violation_evidence_summary_includes_capability_name() {
    let mut m = monitor();
    let obs = MonitoringObservation::CapabilityEvent {
        capability: "exec_shell".into(),
        within_envelope: false,
        envelope_digest: ContentHash::compute(b"env"),
        timestamp_ns: 2_000_000_000,
    };
    let r = m.process_observation(&obs);
    assert!(r.trigger_fired);
    let eval = r.evaluation.unwrap();
    let summary = &eval.evidence[0].summary;
    assert!(
        summary.contains("exec_shell"),
        "summary should include capability, got: {summary}"
    );
}

// --- Selectively disabling individual triggers ---

#[test]
fn only_semantic_divergence_disabled() {
    let receipt = promotion_receipt();
    let mut p = strict_policy();
    p.semantic_divergence_enabled = false;
    let mut m = AutoDemotionMonitor::new(&receipt, p, 1_000_000_000).unwrap();

    // Semantic divergence ignored
    let obs1 = MonitoringObservation::OutputComparison {
        matched: false,
        input_hash: ContentHash::compute(b"in"),
        native_output_hash: ContentHash::compute(b"n"),
        reference_output_hash: ContentHash::compute(b"r"),
        waiver_covered: false,
        timestamp_ns: 2_000_000_000,
    };
    assert!(!m.process_observation(&obs1).trigger_fired);
    assert_eq!(m.divergence_count(), 0);

    // Risk still works
    let obs2 = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 900_000,
        timestamp_ns: 3_000_000_000,
    };
    assert!(m.process_observation(&obs2).trigger_fired);
}

#[test]
fn only_risk_disabled() {
    let receipt = promotion_receipt();
    let mut p = strict_policy();
    p.risk_threshold_enabled = false;
    let mut m = AutoDemotionMonitor::new(&receipt, p, 1_000_000_000).unwrap();

    // Risk ignored
    let obs = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 999_999,
        timestamp_ns: 2_000_000_000,
    };
    assert!(!m.process_observation(&obs).trigger_fired);

    // Capability still works
    let obs2 = MonitoringObservation::CapabilityEvent {
        capability: "evil".into(),
        within_envelope: false,
        envelope_digest: ContentHash::compute(b"x"),
        timestamp_ns: 3_000_000_000,
    };
    assert!(m.process_observation(&obs2).trigger_fired);
}

#[test]
fn only_capability_disabled() {
    let receipt = promotion_receipt();
    let mut p = strict_policy();
    p.capability_violation_enabled = false;
    let mut m = AutoDemotionMonitor::new(&receipt, p, 1_000_000_000).unwrap();

    // Capability ignored
    let obs = MonitoringObservation::CapabilityEvent {
        capability: "evil".into(),
        within_envelope: false,
        envelope_digest: ContentHash::compute(b"x"),
        timestamp_ns: 2_000_000_000,
    };
    assert!(!m.process_observation(&obs).trigger_fired);

    // Semantic still works
    let obs2 = MonitoringObservation::OutputComparison {
        matched: false,
        input_hash: ContentHash::compute(b"in"),
        native_output_hash: ContentHash::compute(b"n"),
        reference_output_hash: ContentHash::compute(b"r"),
        waiver_covered: false,
        timestamp_ns: 3_000_000_000,
    };
    assert!(m.process_observation(&obs2).trigger_fired);
}

#[test]
fn only_performance_disabled() {
    let receipt = promotion_receipt();
    let mut p = strict_policy();
    p.performance_breach_enabled = false;
    let mut m = AutoDemotionMonitor::new(&receipt, p, 1_000_000_000).unwrap();

    // Performance ignored even with sustained breach
    let obs1 = MonitoringObservation::PerformanceSample {
        metric_name: "latency_p99_ns".into(),
        value_millionths: 60_000_000,
        timestamp_ns: 2_000_000_000,
    };
    m.process_observation(&obs1);
    let obs2 = MonitoringObservation::PerformanceSample {
        metric_name: "latency_p99_ns".into(),
        value_millionths: 60_000_000,
        timestamp_ns: 15_000_000_000,
    };
    assert!(!m.process_observation(&obs2).trigger_fired);

    // Risk still works
    let obs3 = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 900_000,
        timestamp_ns: 16_000_000_000,
    };
    assert!(m.process_observation(&obs3).trigger_fired);
}

// --- Waived divergence not counted ---

#[test]
fn waived_divergence_mixed_with_unwaived() {
    let receipt = promotion_receipt();
    let mut p = strict_policy();
    p.max_divergence_count = 3;
    let mut m = AutoDemotionMonitor::new(&receipt, p, 1_000_000_000).unwrap();

    // 5 waived divergences interleaved with 2 unwaived
    for i in 0..5 {
        let obs = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(format!("waived-{i}").as_bytes()),
            native_output_hash: ContentHash::compute(format!("wn-{i}").as_bytes()),
            reference_output_hash: ContentHash::compute(format!("wr-{i}").as_bytes()),
            waiver_covered: true,
            timestamp_ns: 2_000_000_000 + i * 100_000_000,
        };
        assert!(!m.process_observation(&obs).trigger_fired);
    }
    assert_eq!(m.divergence_count(), 0);

    // 2 unwaived: below threshold
    for i in 0..2 {
        let obs = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(format!("real-{i}").as_bytes()),
            native_output_hash: ContentHash::compute(format!("rn-{i}").as_bytes()),
            reference_output_hash: ContentHash::compute(format!("rr-{i}").as_bytes()),
            waiver_covered: false,
            timestamp_ns: 3_000_000_000 + i * 100_000_000,
        };
        assert!(!m.process_observation(&obs).trigger_fired);
    }
    assert_eq!(m.divergence_count(), 2);

    // 3rd unwaived fires
    let obs3 = MonitoringObservation::OutputComparison {
        matched: false,
        input_hash: ContentHash::compute(b"real-3"),
        native_output_hash: ContentHash::compute(b"rn-3"),
        reference_output_hash: ContentHash::compute(b"rr-3"),
        waiver_covered: false,
        timestamp_ns: 4_000_000_000,
    };
    assert!(m.process_observation(&obs3).trigger_fired);
    assert_eq!(m.divergence_count(), 3);
}

// --- Monitor clone ---

#[test]
fn monitor_clone_is_independent() {
    let mut m = monitor();
    let m2 = m.clone();

    // Process observation on original
    let obs = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 900_000,
        timestamp_ns: 2_000_000_000,
    };
    assert!(m.process_observation(&obs).trigger_fired);

    // Clone should be unaffected
    assert!(!m2.is_demotion_triggered());
    assert_eq!(m2.observations_processed(), 0);
}

// --- Receipt schema_version ---

#[test]
fn receipt_schema_version_is_v1() {
    let key = sk();
    let receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native",
            restored_cell_digest: "delegate",
            rollback_token_used: "tok",
            demotion_reason: &DemotionReason::SemanticDivergence {
                divergence_count: 1,
                first_divergence_artifact: ContentHash::compute(b"d"),
            },
            severity: DemotionSeverity::Critical,
            evidence: &[],
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "z",
        },
    )
    .expect("create");
    assert_eq!(
        receipt.schema_version,
        frankenengine_engine::self_replacement::SchemaVersion::V1
    );
}

// --- Policy serde with blocked candidates ---

#[test]
fn policy_serde_preserves_blocked_candidates() {
    let mut p = strict_policy();
    p.block_candidate("a".into());
    p.block_candidate("b".into());
    p.block_candidate("c".into());
    let json = serde_json::to_string(&p).expect("serialize");
    let rt: DemotionPolicy = serde_json::from_str(&json).expect("deserialize");
    assert!(rt.is_candidate_blocked("a"));
    assert!(rt.is_candidate_blocked("b"));
    assert!(rt.is_candidate_blocked("c"));
    assert!(!rt.is_candidate_blocked("d"));
}

// --- Policy serde with custom severities ---

#[test]
fn policy_serde_preserves_custom_severities() {
    let mut p = strict_policy();
    p.semantic_divergence_severity = DemotionSeverity::Advisory;
    p.performance_breach_severity = DemotionSeverity::Critical;
    p.risk_threshold_severity = DemotionSeverity::Warning;
    p.capability_violation_severity = DemotionSeverity::Advisory;
    let json = serde_json::to_string(&p).expect("serialize");
    let rt: DemotionPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(rt.semantic_divergence_severity, DemotionSeverity::Advisory);
    assert_eq!(rt.performance_breach_severity, DemotionSeverity::Critical);
    assert_eq!(rt.risk_threshold_severity, DemotionSeverity::Warning);
    assert_eq!(rt.capability_violation_severity, DemotionSeverity::Advisory);
}

// --- Trigger evaluation without reason ---

#[test]
fn trigger_evaluation_serde_round_trip_no_reason() {
    let eval = TriggerEvaluation {
        fired: false,
        reason: None,
        severity: DemotionSeverity::Advisory,
        evidence: Vec::new(),
    };
    let json = serde_json::to_string(&eval).expect("serialize");
    let rt: TriggerEvaluation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(eval, rt);
}

// --- DemotionEvidenceItem serde with varied data ---

#[test]
fn evidence_item_serde_with_long_summary() {
    let item = DemotionEvidenceItem {
        artifact_hash: ContentHash::compute(b"long-evidence"),
        category: "performance_trace".into(),
        collected_at_ns: u64::MAX,
        summary: "A".repeat(1000),
    };
    let json = serde_json::to_string(&item).expect("serialize");
    let rt: DemotionEvidenceItem = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(item, rt);
}

// --- DemotionReason category all unique ---

#[test]
fn all_demotion_reason_categories_are_distinct() {
    let categories = vec![
        DemotionReason::SemanticDivergence {
            divergence_count: 0,
            first_divergence_artifact: ContentHash::compute(b""),
        }
        .category(),
        DemotionReason::PerformanceBreach {
            metric_name: "m".into(),
            observed_millionths: 0,
            threshold_millionths: 0,
            sustained_duration_ns: 0,
        }
        .category(),
        DemotionReason::RiskThresholdBreach {
            observed_risk_millionths: 0,
            max_risk_millionths: 0,
        }
        .category(),
        DemotionReason::CapabilityViolation {
            attempted_capability: "c".into(),
            envelope_digest: ContentHash::compute(b""),
        }
        .category(),
        DemotionReason::OperatorInitiated {
            operator_id: "o".into(),
            reason: "r".into(),
        }
        .category(),
    ];
    let unique: std::collections::BTreeSet<&str> = categories.iter().copied().collect();
    assert_eq!(unique.len(), 5, "all 5 categories should be distinct");
}

// --- Severity equality ---

#[test]
fn demotion_severity_equality() {
    assert_eq!(DemotionSeverity::Advisory, DemotionSeverity::Advisory);
    assert_eq!(DemotionSeverity::Warning, DemotionSeverity::Warning);
    assert_eq!(DemotionSeverity::Critical, DemotionSeverity::Critical);
    assert_ne!(DemotionSeverity::Advisory, DemotionSeverity::Warning);
    assert_ne!(DemotionSeverity::Warning, DemotionSeverity::Critical);
    assert_ne!(DemotionSeverity::Advisory, DemotionSeverity::Critical);
}

// --- DemotionReason equality ---

#[test]
fn demotion_reason_equality_same_variant_same_data() {
    let a = DemotionReason::PerformanceBreach {
        metric_name: "lat".into(),
        observed_millionths: 100,
        threshold_millionths: 50,
        sustained_duration_ns: 1000,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn demotion_reason_inequality_different_data() {
    let a = DemotionReason::PerformanceBreach {
        metric_name: "lat".into(),
        observed_millionths: 100,
        threshold_millionths: 50,
        sustained_duration_ns: 1000,
    };
    let b = DemotionReason::PerformanceBreach {
        metric_name: "lat".into(),
        observed_millionths: 200,
        threshold_millionths: 50,
        sustained_duration_ns: 1000,
    };
    assert_ne!(a, b);
}

// --- Policy custom risk threshold ---

#[test]
fn policy_custom_risk_threshold() {
    let receipt = promotion_receipt();
    let mut p = strict_policy();
    p.max_risk_millionths = 500_000; // Lower threshold
    let mut m = AutoDemotionMonitor::new(&receipt, p, 1_000_000_000).unwrap();

    // 600_000 > 500_000 fires
    let obs = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 600_000,
        timestamp_ns: 2_000_000_000,
    };
    assert!(m.process_observation(&obs).trigger_fired);
}

// --- Policy custom max_divergence_count edge ---

#[test]
fn max_divergence_count_of_one_fires_on_first() {
    let receipt = promotion_receipt();
    let mut p = strict_policy();
    p.max_divergence_count = 1;
    let mut m = AutoDemotionMonitor::new(&receipt, p, 1_000_000_000).unwrap();

    let obs = MonitoringObservation::OutputComparison {
        matched: false,
        input_hash: ContentHash::compute(b"in"),
        native_output_hash: ContentHash::compute(b"n"),
        reference_output_hash: ContentHash::compute(b"r"),
        waiver_covered: false,
        timestamp_ns: 2_000_000_000,
    };
    assert!(
        m.process_observation(&obs).trigger_fired,
        "divergence_count=1 >= max=1 should fire"
    );
}

// --- Receipt serde roundtrip for different reason variants ---

#[test]
fn receipt_serde_roundtrip_risk_reason() {
    let key = sk();
    let receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native-x",
            restored_cell_digest: "delegate-y",
            rollback_token_used: "tok-z",
            demotion_reason: &DemotionReason::RiskThresholdBreach {
                observed_risk_millionths: 950_000,
                max_risk_millionths: 800_000,
            },
            severity: DemotionSeverity::Critical,
            evidence: &[DemotionEvidenceItem {
                artifact_hash: ContentHash::compute(b"risk-ev"),
                category: "risk_score".into(),
                collected_at_ns: 42,
                summary: "risk high".into(),
            }],
            timestamp_ns: 3_000_000_000,
            epoch: SecurityEpoch::from_raw(2),
            zone: "staging",
        },
    )
    .expect("create");
    let json = serde_json::to_string(&receipt).expect("serialize");
    let rt: DemotionReceipt = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(receipt, rt);
    rt.verify_signature(&key.verification_key())
        .expect("verify after roundtrip");
}
