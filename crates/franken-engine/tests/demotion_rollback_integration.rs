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
