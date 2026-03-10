#![forbid(unsafe_code)]
//! Enrichment integration tests for `demotion_rollback`.
//!
//! Adds exact Display messages, Debug distinctness, JSON field-name stability,
//! serde exact enum values, std::error::Error impl, and additional edge-case
//! coverage beyond the existing 49 integration tests.

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
    ObservationResult, PerformanceThreshold, TriggerEvaluation,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::self_replacement::{
    CreateReceiptInput, ReplacementReceipt, ValidationArtifactKind, ValidationArtifactRef,
};
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::slot_registry::SlotId;

// ===========================================================================
// Test helpers
// ===========================================================================

fn slot() -> SlotId {
    SlotId::new("enrich-slot-001").expect("valid slot id")
}

fn sk() -> SigningKey {
    SigningKey::from_bytes([55u8; 32])
}

fn promotion_receipt() -> ReplacementReceipt {
    let artifacts = vec![ValidationArtifactRef {
        kind: ValidationArtifactKind::EquivalenceResult,
        artifact_digest: "equiv-enrich".to_string(),
        passed: true,
        summary: "passed".to_string(),
    }];
    ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &slot(),
        old_cell_digest: "old-delegate-enrich",
        new_cell_digest: "new-native-enrich",
        validation_artifacts: &artifacts,
        rollback_token: "rollback-enrich-token",
        promotion_rationale: "enrichment test",
        timestamp_ns: 1_000_000_000,
        epoch: SecurityEpoch::from_raw(1),
        zone: "enrich-zone",
        required_signatures: 0,
    })
    .expect("create receipt")
}

fn strict_policy() -> DemotionPolicy {
    let mut p = DemotionPolicy::strict(slot());
    p.performance_thresholds.push(PerformanceThreshold {
        metric_name: "latency_p99_ns".to_string(),
        max_value_millionths: 50_000_000,
        sustained_duration_ns: 10_000_000_000,
    });
    p
}

fn monitor() -> AutoDemotionMonitor {
    AutoDemotionMonitor::new(&promotion_receipt(), strict_policy(), 1_000_000_000)
        .expect("create monitor")
}

// ===========================================================================
// 1) DemotionReason — exact Display messages
// ===========================================================================

#[test]
fn demotion_reason_display_exact_semantic_divergence() {
    let r = DemotionReason::SemanticDivergence {
        divergence_count: 7,
        first_divergence_artifact: ContentHash::compute(b"aaa"),
    };
    assert_eq!(r.to_string(), "semantic divergence (7 outputs)");
}

#[test]
fn demotion_reason_display_exact_performance_breach() {
    let r = DemotionReason::PerformanceBreach {
        metric_name: "latency_p99_ns".to_string(),
        observed_millionths: 60_000_000,
        threshold_millionths: 50_000_000,
        sustained_duration_ns: 10_000_000_000,
    };
    assert_eq!(
        r.to_string(),
        "performance breach: latency_p99_ns observed=60000000 threshold=50000000"
    );
}

#[test]
fn demotion_reason_display_exact_risk_threshold() {
    let r = DemotionReason::RiskThresholdBreach {
        observed_risk_millionths: 900_000,
        max_risk_millionths: 800_000,
    };
    assert_eq!(
        r.to_string(),
        "risk threshold breach: observed=900000 max=800000"
    );
}

#[test]
fn demotion_reason_display_exact_capability_violation() {
    let r = DemotionReason::CapabilityViolation {
        attempted_capability: "network_send".to_string(),
        envelope_digest: ContentHash::compute(b"env"),
    };
    assert_eq!(r.to_string(), "capability violation: network_send");
}

#[test]
fn demotion_reason_display_exact_operator_initiated() {
    let r = DemotionReason::OperatorInitiated {
        operator_id: "admin-007".to_string(),
        reason: "manual demotion".to_string(),
    };
    assert_eq!(r.to_string(), "operator-initiated: admin-007");
}

// ===========================================================================
// 2) DemotionSeverity — exact as_str/Display
// ===========================================================================

#[test]
fn demotion_severity_as_str_exact() {
    assert_eq!(DemotionSeverity::Advisory.as_str(), "advisory");
    assert_eq!(DemotionSeverity::Warning.as_str(), "warning");
    assert_eq!(DemotionSeverity::Critical.as_str(), "critical");
}

#[test]
fn demotion_severity_display_exact() {
    assert_eq!(DemotionSeverity::Advisory.to_string(), "advisory");
    assert_eq!(DemotionSeverity::Warning.to_string(), "warning");
    assert_eq!(DemotionSeverity::Critical.to_string(), "critical");
}

// ===========================================================================
// 3) DemotionReason — category exact
// ===========================================================================

#[test]
fn demotion_reason_category_exact_values() {
    let cases: Vec<(DemotionReason, &str)> = vec![
        (
            DemotionReason::SemanticDivergence {
                divergence_count: 0,
                first_divergence_artifact: ContentHash::compute(b""),
            },
            "semantic_divergence",
        ),
        (
            DemotionReason::PerformanceBreach {
                metric_name: String::new(),
                observed_millionths: 0,
                threshold_millionths: 0,
                sustained_duration_ns: 0,
            },
            "performance_breach",
        ),
        (
            DemotionReason::RiskThresholdBreach {
                observed_risk_millionths: 0,
                max_risk_millionths: 0,
            },
            "risk_threshold_breach",
        ),
        (
            DemotionReason::CapabilityViolation {
                attempted_capability: String::new(),
                envelope_digest: ContentHash::compute(b""),
            },
            "capability_violation",
        ),
        (
            DemotionReason::OperatorInitiated {
                operator_id: String::new(),
                reason: String::new(),
            },
            "operator_initiated",
        ),
    ];
    for (reason, expected) in cases {
        assert_eq!(reason.category(), expected);
    }
}

// ===========================================================================
// 4) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_demotion_reason() {
    let variants: Vec<DemotionReason> = vec![
        DemotionReason::SemanticDivergence {
            divergence_count: 1,
            first_divergence_artifact: ContentHash::compute(b"d1"),
        },
        DemotionReason::PerformanceBreach {
            metric_name: "m".to_string(),
            observed_millionths: 1,
            threshold_millionths: 1,
            sustained_duration_ns: 1,
        },
        DemotionReason::RiskThresholdBreach {
            observed_risk_millionths: 1,
            max_risk_millionths: 1,
        },
        DemotionReason::CapabilityViolation {
            attempted_capability: "c".to_string(),
            envelope_digest: ContentHash::compute(b"e"),
        },
        DemotionReason::OperatorInitiated {
            operator_id: "op".to_string(),
            reason: "r".to_string(),
        },
    ];
    let debugs: std::collections::BTreeSet<String> =
        variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), variants.len());
}

#[test]
fn debug_distinct_demotion_severity() {
    let variants = [
        DemotionSeverity::Advisory,
        DemotionSeverity::Warning,
        DemotionSeverity::Critical,
    ];
    let debugs: std::collections::BTreeSet<String> =
        variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), variants.len());
}

#[test]
fn debug_distinct_monitoring_observation() {
    let variants: Vec<MonitoringObservation> = vec![
        MonitoringObservation::OutputComparison {
            matched: true,
            input_hash: ContentHash::compute(b"i"),
            native_output_hash: ContentHash::compute(b"n"),
            reference_output_hash: ContentHash::compute(b"r"),
            waiver_covered: false,
            timestamp_ns: 1,
        },
        MonitoringObservation::PerformanceSample {
            metric_name: "m".to_string(),
            value_millionths: 1,
            timestamp_ns: 2,
        },
        MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 1,
            timestamp_ns: 3,
        },
        MonitoringObservation::CapabilityEvent {
            capability: "c".to_string(),
            within_envelope: true,
            envelope_digest: ContentHash::compute(b"e"),
            timestamp_ns: 4,
        },
    ];
    let debugs: std::collections::BTreeSet<String> =
        variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), variants.len());
}

// ===========================================================================
// 5) DemotionError — exact Display messages
// ===========================================================================

#[test]
fn error_display_exact_signature_invalid() {
    let e = DemotionError::SignatureInvalid {
        receipt_id: "r-001".to_string(),
    };
    assert_eq!(e.to_string(), "invalid signature on demotion receipt r-001");
}

#[test]
fn error_display_exact_slot_mismatch() {
    let e = DemotionError::SlotMismatch {
        expected: "slot-a".to_string(),
        got: "slot-b".to_string(),
    };
    assert_eq!(e.to_string(), "slot mismatch: expected slot-a, got slot-b");
}

#[test]
fn error_display_exact_candidate_blocked() {
    let e = DemotionError::CandidateBlocked {
        candidate_digest: "digest-xyz".to_string(),
    };
    assert_eq!(
        e.to_string(),
        "candidate digest-xyz is blocked from re-promotion"
    );
}

#[test]
fn error_display_exact_no_previous_cell() {
    let e = DemotionError::NoPreviousCell {
        slot_id: "slot-1".to_string(),
    };
    assert_eq!(e.to_string(), "no previous cell to restore for slot slot-1");
}

#[test]
fn error_display_exact_already_demoted() {
    let e = DemotionError::AlreadyDemoted {
        slot_id: "slot-2".to_string(),
    };
    assert_eq!(e.to_string(), "demotion already triggered for slot slot-2");
}

// ===========================================================================
// 6) std::error::Error impl
// ===========================================================================

#[test]
fn demotion_error_is_std_error() {
    let errors: Vec<Box<dyn std::error::Error>> = vec![
        Box::new(DemotionError::SignatureInvalid {
            receipt_id: "r".to_string(),
        }),
        Box::new(DemotionError::SlotMismatch {
            expected: "a".to_string(),
            got: "b".to_string(),
        }),
        Box::new(DemotionError::CandidateBlocked {
            candidate_digest: "d".to_string(),
        }),
        Box::new(DemotionError::NoPreviousCell {
            slot_id: "s".to_string(),
        }),
        Box::new(DemotionError::AlreadyDemoted {
            slot_id: "s".to_string(),
        }),
    ];
    for e in &errors {
        assert!(!e.to_string().is_empty());
        assert!(e.source().is_none());
    }
}

// ===========================================================================
// 7) serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_demotion_severity() {
    assert_eq!(
        serde_json::to_string(&DemotionSeverity::Advisory).unwrap(),
        "\"Advisory\""
    );
    assert_eq!(
        serde_json::to_string(&DemotionSeverity::Warning).unwrap(),
        "\"Warning\""
    );
    assert_eq!(
        serde_json::to_string(&DemotionSeverity::Critical).unwrap(),
        "\"Critical\""
    );
}

#[test]
fn serde_exact_demotion_reason_tags() {
    // Each variant serializes with its tag name
    let sem = DemotionReason::SemanticDivergence {
        divergence_count: 1,
        first_divergence_artifact: ContentHash::compute(b"x"),
    };
    let json = serde_json::to_string(&sem).unwrap();
    assert!(json.contains("\"SemanticDivergence\""));

    let perf = DemotionReason::PerformanceBreach {
        metric_name: "m".to_string(),
        observed_millionths: 1,
        threshold_millionths: 1,
        sustained_duration_ns: 1,
    };
    let json = serde_json::to_string(&perf).unwrap();
    assert!(json.contains("\"PerformanceBreach\""));

    let risk = DemotionReason::RiskThresholdBreach {
        observed_risk_millionths: 1,
        max_risk_millionths: 1,
    };
    let json = serde_json::to_string(&risk).unwrap();
    assert!(json.contains("\"RiskThresholdBreach\""));

    let cap = DemotionReason::CapabilityViolation {
        attempted_capability: "c".to_string(),
        envelope_digest: ContentHash::compute(b"e"),
    };
    let json = serde_json::to_string(&cap).unwrap();
    assert!(json.contains("\"CapabilityViolation\""));

    let op = DemotionReason::OperatorInitiated {
        operator_id: "o".to_string(),
        reason: "r".to_string(),
    };
    let json = serde_json::to_string(&op).unwrap();
    assert!(json.contains("\"OperatorInitiated\""));
}

#[test]
fn serde_exact_monitoring_observation_tags() {
    let oc = MonitoringObservation::OutputComparison {
        matched: true,
        input_hash: ContentHash::compute(b"i"),
        native_output_hash: ContentHash::compute(b"n"),
        reference_output_hash: ContentHash::compute(b"r"),
        waiver_covered: false,
        timestamp_ns: 1,
    };
    assert!(
        serde_json::to_string(&oc)
            .unwrap()
            .contains("\"OutputComparison\"")
    );

    let ps = MonitoringObservation::PerformanceSample {
        metric_name: "m".to_string(),
        value_millionths: 1,
        timestamp_ns: 2,
    };
    assert!(
        serde_json::to_string(&ps)
            .unwrap()
            .contains("\"PerformanceSample\"")
    );

    let rs = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 1,
        timestamp_ns: 3,
    };
    assert!(
        serde_json::to_string(&rs)
            .unwrap()
            .contains("\"RiskScoreUpdate\"")
    );

    let ce = MonitoringObservation::CapabilityEvent {
        capability: "c".to_string(),
        within_envelope: true,
        envelope_digest: ContentHash::compute(b"e"),
        timestamp_ns: 4,
    };
    assert!(
        serde_json::to_string(&ce)
            .unwrap()
            .contains("\"CapabilityEvent\"")
    );
}

// ===========================================================================
// 8) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_demotion_evidence_item() {
    let item = DemotionEvidenceItem {
        artifact_hash: ContentHash::compute(b"ev"),
        category: "divergence_trace".to_string(),
        collected_at_ns: 100,
        summary: "test".to_string(),
    };
    let json = serde_json::to_string(&item).unwrap();
    assert!(json.contains("\"artifact_hash\""));
    assert!(json.contains("\"category\""));
    assert!(json.contains("\"collected_at_ns\""));
    assert!(json.contains("\"summary\""));
}

#[test]
fn json_fields_performance_threshold() {
    let t = PerformanceThreshold {
        metric_name: "latency".to_string(),
        max_value_millionths: 50_000_000,
        sustained_duration_ns: 10_000_000_000,
    };
    let json = serde_json::to_string(&t).unwrap();
    assert!(json.contains("\"metric_name\""));
    assert!(json.contains("\"max_value_millionths\""));
    assert!(json.contains("\"sustained_duration_ns\""));
}

#[test]
fn json_fields_demotion_policy() {
    let p = DemotionPolicy::strict(slot());
    let json = serde_json::to_string(&p).unwrap();
    assert!(json.contains("\"slot_id\""));
    assert!(json.contains("\"semantic_divergence_enabled\""));
    assert!(json.contains("\"semantic_divergence_severity\""));
    assert!(json.contains("\"max_divergence_count\""));
    assert!(json.contains("\"performance_breach_enabled\""));
    assert!(json.contains("\"performance_breach_severity\""));
    assert!(json.contains("\"performance_thresholds\""));
    assert!(json.contains("\"risk_threshold_enabled\""));
    assert!(json.contains("\"risk_threshold_severity\""));
    assert!(json.contains("\"max_risk_millionths\""));
    assert!(json.contains("\"capability_violation_enabled\""));
    assert!(json.contains("\"capability_violation_severity\""));
    assert!(json.contains("\"burn_in_duration_ns\""));
    assert!(json.contains("\"max_rollback_latency_ns\""));
    assert!(json.contains("\"blocked_candidates\""));
}

#[test]
fn json_fields_trigger_evaluation() {
    let te = TriggerEvaluation {
        fired: true,
        reason: Some(DemotionReason::RiskThresholdBreach {
            observed_risk_millionths: 1,
            max_risk_millionths: 1,
        }),
        severity: DemotionSeverity::Critical,
        evidence: vec![],
    };
    let json = serde_json::to_string(&te).unwrap();
    assert!(json.contains("\"fired\""));
    assert!(json.contains("\"reason\""));
    assert!(json.contains("\"severity\""));
    assert!(json.contains("\"evidence\""));
}

#[test]
fn json_fields_observation_result() {
    let or = ObservationResult {
        trigger_fired: false,
        evaluation: None,
        observations_processed: 1,
    };
    let json = serde_json::to_string(&or).unwrap();
    assert!(json.contains("\"trigger_fired\""));
    assert!(json.contains("\"evaluation\""));
    assert!(json.contains("\"observations_processed\""));
}

#[test]
fn json_fields_demotion_receipt() {
    let key = sk();
    let receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native",
            restored_cell_digest: "delegate",
            rollback_token_used: "token",
            demotion_reason: &DemotionReason::OperatorInitiated {
                operator_id: "op".to_string(),
                reason: "test".to_string(),
            },
            severity: DemotionSeverity::Warning,
            evidence: &[],
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "z",
        },
    )
    .expect("create");
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(json.contains("\"receipt_id\""));
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"slot_id\""));
    assert!(json.contains("\"demoted_cell_digest\""));
    assert!(json.contains("\"restored_cell_digest\""));
    assert!(json.contains("\"rollback_token_used\""));
    assert!(json.contains("\"demotion_reason\""));
    assert!(json.contains("\"severity\""));
    assert!(json.contains("\"evidence\""));
    assert!(json.contains("\"timestamp_ns\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"zone\""));
    assert!(json.contains("\"signature\""));
}

// ===========================================================================
// 9) DemotionPolicy strict defaults — exact values
// ===========================================================================

#[test]
fn strict_policy_defaults_exact() {
    let p = DemotionPolicy::strict(slot());
    assert!(p.semantic_divergence_enabled);
    assert_eq!(p.semantic_divergence_severity, DemotionSeverity::Critical);
    assert_eq!(p.max_divergence_count, 0);
    assert!(p.performance_breach_enabled);
    assert_eq!(p.performance_breach_severity, DemotionSeverity::Warning);
    assert!(p.performance_thresholds.is_empty());
    assert!(p.risk_threshold_enabled);
    assert_eq!(p.risk_threshold_severity, DemotionSeverity::Critical);
    assert_eq!(p.max_risk_millionths, 800_000);
    assert!(p.capability_violation_enabled);
    assert_eq!(p.capability_violation_severity, DemotionSeverity::Critical);
    assert_eq!(p.burn_in_duration_ns, 300_000_000_000);
    assert_eq!(p.max_rollback_latency_ns, 1_000_000_000);
    assert!(p.blocked_candidates.is_empty());
}

// ===========================================================================
// 10) Edge cases — policy candidate blocking
// ===========================================================================

#[test]
fn policy_unblock_nonexistent_returns_false() {
    let mut p = DemotionPolicy::strict(slot());
    assert!(!p.unblock_candidate("no-such-digest"));
}

#[test]
fn policy_block_duplicate_candidate_is_idempotent() {
    let mut p = DemotionPolicy::strict(slot());
    p.block_candidate("digest-aaa".to_string());
    p.block_candidate("digest-aaa".to_string());
    assert!(p.is_candidate_blocked("digest-aaa"));
    assert_eq!(p.blocked_candidates.len(), 1);
}

// ===========================================================================
// 11) MonitoringObservation — timestamp extraction edge cases
// ===========================================================================

#[test]
fn observation_timestamp_zero() {
    let obs = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 0,
        timestamp_ns: 0,
    };
    assert_eq!(obs.timestamp_ns(), 0);
}

#[test]
fn observation_timestamp_u64_max() {
    let obs = MonitoringObservation::PerformanceSample {
        metric_name: "x".to_string(),
        value_millionths: 0,
        timestamp_ns: u64::MAX,
    };
    assert_eq!(obs.timestamp_ns(), u64::MAX);
}

// ===========================================================================
// 12) Monitor — burn-in edge cases
// ===========================================================================

#[test]
fn burn_in_at_start_is_active() {
    let m = monitor();
    // monitoring_start_ns = 1_000_000_000
    assert!(m.is_burn_in(1_000_000_000));
}

#[test]
fn burn_in_saturating_sub_with_zero() {
    let m = monitor();
    // current_ns < monitoring_start_ns → saturating_sub returns 0, which is < burn_in
    assert!(m.is_burn_in(0));
}

// ===========================================================================
// 13) Monitor — content hash determinism across separate receipts
// ===========================================================================

#[test]
fn demotion_receipt_content_hash_same_inputs_same_hash() {
    let key = sk();
    let mk_receipt = || {
        DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &slot(),
                demoted_cell_digest: "native-hash-test",
                restored_cell_digest: "delegate-hash-test",
                rollback_token_used: "token-hash",
                demotion_reason: &DemotionReason::RiskThresholdBreach {
                    observed_risk_millionths: 900_000,
                    max_risk_millionths: 800_000,
                },
                severity: DemotionSeverity::Critical,
                evidence: &[],
                timestamp_ns: 5_000_000_000,
                epoch: SecurityEpoch::from_raw(2),
                zone: "hash-zone",
            },
        )
        .expect("create receipt")
    };
    let r1 = mk_receipt();
    let r2 = mk_receipt();
    // Content hash doesn't depend on signature (which has randomness)
    assert_eq!(r1.content_hash(), r2.content_hash());
}

// ===========================================================================
// 14) Monitor — demotion receipt ID determinism
// ===========================================================================

#[test]
fn demotion_receipt_derive_id_deterministic() {
    let id1 = DemotionReceipt::derive_receipt_id(
        &slot(),
        "native-1",
        "delegate-1",
        1_000_000_000,
        "zone-1",
    )
    .unwrap();
    let id2 = DemotionReceipt::derive_receipt_id(
        &slot(),
        "native-1",
        "delegate-1",
        1_000_000_000,
        "zone-1",
    )
    .unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn demotion_receipt_derive_id_varies_with_timestamp() {
    let id1 =
        DemotionReceipt::derive_receipt_id(&slot(), "native", "delegate", 1_000_000_000, "zone")
            .unwrap();
    let id2 =
        DemotionReceipt::derive_receipt_id(&slot(), "native", "delegate", 2_000_000_000, "zone")
            .unwrap();
    assert_ne!(id1, id2);
}

// ===========================================================================
// 15) DemotionError serde all variants
// ===========================================================================

#[test]
fn demotion_error_serde_all_variants() {
    let errors = vec![
        DemotionError::SignatureInvalid {
            receipt_id: "r-1".to_string(),
        },
        DemotionError::SlotMismatch {
            expected: "a".to_string(),
            got: "b".to_string(),
        },
        DemotionError::CandidateBlocked {
            candidate_digest: "d".to_string(),
        },
        DemotionError::NoPreviousCell {
            slot_id: "s".to_string(),
        },
        DemotionError::AlreadyDemoted {
            slot_id: "s".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: DemotionError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ===========================================================================
// 16) DemotionError — Display messages are unique across variants
// ===========================================================================

#[test]
fn demotion_error_display_unique() {
    let msgs: Vec<String> = vec![
        DemotionError::SignatureInvalid {
            receipt_id: "r".to_string(),
        }
        .to_string(),
        DemotionError::SlotMismatch {
            expected: "a".to_string(),
            got: "b".to_string(),
        }
        .to_string(),
        DemotionError::CandidateBlocked {
            candidate_digest: "d".to_string(),
        }
        .to_string(),
        DemotionError::NoPreviousCell {
            slot_id: "s".to_string(),
        }
        .to_string(),
        DemotionError::AlreadyDemoted {
            slot_id: "s2".to_string(),
        }
        .to_string(),
    ];
    let set: std::collections::BTreeSet<&str> = msgs.iter().map(|s| s.as_str()).collect();
    assert_eq!(set.len(), msgs.len());
}

// ===========================================================================
// 17) Monitor — multiple sequential observations count
// ===========================================================================

#[test]
fn monitor_observations_count_increments() {
    let mut m = monitor();
    assert_eq!(m.observations_processed(), 0);

    for i in 1..=5u64 {
        let obs = MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 100_000,
            timestamp_ns: i * 1_000_000_000,
        };
        m.process_observation(&obs);
        assert_eq!(m.observations_processed(), i);
    }
}

// ===========================================================================
// 18) Monitor — observations after demotion still increment counter
// ===========================================================================

#[test]
fn monitor_observations_after_demotion_increment_counter() {
    let mut m = monitor();
    // Trigger demotion
    let obs1 = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 999_999,
        timestamp_ns: 2_000_000_000,
    };
    let r1 = m.process_observation(&obs1);
    assert!(r1.trigger_fired);
    assert_eq!(m.observations_processed(), 1);

    // Post-demotion observation: counter still increments
    let obs2 = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 999_999,
        timestamp_ns: 3_000_000_000,
    };
    let r2 = m.process_observation(&obs2);
    assert!(!r2.trigger_fired);
    assert_eq!(m.observations_processed(), 2);
}

// ===========================================================================
// 19) ObservationResult serde roundtrip
// ===========================================================================

#[test]
fn observation_result_serde_roundtrip_no_trigger() {
    let or = ObservationResult {
        trigger_fired: false,
        evaluation: None,
        observations_processed: 42,
    };
    let json = serde_json::to_string(&or).unwrap();
    let back: ObservationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(or, back);
}

#[test]
fn observation_result_serde_roundtrip_with_trigger() {
    let or = ObservationResult {
        trigger_fired: true,
        evaluation: Some(TriggerEvaluation {
            fired: true,
            reason: Some(DemotionReason::RiskThresholdBreach {
                observed_risk_millionths: 900_000,
                max_risk_millionths: 800_000,
            }),
            severity: DemotionSeverity::Critical,
            evidence: vec![DemotionEvidenceItem {
                artifact_hash: ContentHash::compute(b"risk-ev"),
                category: "risk_score".to_string(),
                collected_at_ns: 1_000,
                summary: "risk exceeded".to_string(),
            }],
        }),
        observations_processed: 1,
    };
    let json = serde_json::to_string(&or).unwrap();
    let back: ObservationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(or, back);
}

// ===========================================================================
// 20) DemotionSeverity ordering — Ord is consistent
// ===========================================================================

#[test]
fn demotion_severity_total_ordering() {
    let mut severities = vec![
        DemotionSeverity::Critical,
        DemotionSeverity::Advisory,
        DemotionSeverity::Warning,
    ];
    severities.sort();
    assert_eq!(
        severities,
        vec![
            DemotionSeverity::Advisory,
            DemotionSeverity::Warning,
            DemotionSeverity::Critical,
        ]
    );
}

// ===========================================================================
// 21) DemotionReason — Ord ordering
// ===========================================================================

#[test]
fn demotion_reason_ord_distinct() {
    let reasons: std::collections::BTreeSet<DemotionReason> = vec![
        DemotionReason::SemanticDivergence {
            divergence_count: 1,
            first_divergence_artifact: ContentHash::compute(b"a"),
        },
        DemotionReason::PerformanceBreach {
            metric_name: "m".to_string(),
            observed_millionths: 1,
            threshold_millionths: 1,
            sustained_duration_ns: 1,
        },
        DemotionReason::RiskThresholdBreach {
            observed_risk_millionths: 1,
            max_risk_millionths: 1,
        },
        DemotionReason::CapabilityViolation {
            attempted_capability: "c".to_string(),
            envelope_digest: ContentHash::compute(b"e"),
        },
        DemotionReason::OperatorInitiated {
            operator_id: "o".to_string(),
            reason: "r".to_string(),
        },
    ]
    .into_iter()
    .collect();
    assert_eq!(reasons.len(), 5);
}

// ===========================================================================
// 22) Monitor — semantic divergence accumulates across observations
// ===========================================================================

#[test]
fn semantic_divergence_accumulates_count() {
    let receipt = promotion_receipt();
    let mut policy = strict_policy();
    policy.max_divergence_count = 5; // Fire on 5th divergence

    let mut m = AutoDemotionMonitor::new(&receipt, policy, 1_000_000_000).expect("create monitor");

    for i in 1..=4u64 {
        let obs = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(format!("in-{i}").as_bytes()),
            native_output_hash: ContentHash::compute(format!("native-{i}").as_bytes()),
            reference_output_hash: ContentHash::compute(format!("ref-{i}").as_bytes()),
            waiver_covered: false,
            timestamp_ns: i * 1_000_000_000,
        };
        let result = m.process_observation(&obs);
        assert!(!result.trigger_fired, "should not fire on divergence #{i}");
        assert_eq!(m.divergence_count(), i);
    }

    // 5th divergence fires
    let obs5 = MonitoringObservation::OutputComparison {
        matched: false,
        input_hash: ContentHash::compute(b"in-5"),
        native_output_hash: ContentHash::compute(b"native-5"),
        reference_output_hash: ContentHash::compute(b"ref-5"),
        waiver_covered: false,
        timestamp_ns: 5_000_000_000,
    };
    let result = m.process_observation(&obs5);
    assert!(result.trigger_fired);
    assert_eq!(m.divergence_count(), 5);
}

// ===========================================================================
// 23) Monitor — risk score tracks latest value
// ===========================================================================

#[test]
fn risk_score_tracks_latest() {
    let mut m = monitor();
    assert_eq!(m.latest_risk_millionths(), 0);

    let obs = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 500_000,
        timestamp_ns: 2_000_000_000,
    };
    m.process_observation(&obs);
    assert_eq!(m.latest_risk_millionths(), 500_000);

    let obs2 = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 300_000,
        timestamp_ns: 3_000_000_000,
    };
    m.process_observation(&obs2);
    assert_eq!(m.latest_risk_millionths(), 300_000);
}

// ===========================================================================
// 24) DemotionReceipt — verify signature success path
// ===========================================================================

#[test]
fn demotion_receipt_verify_signature_with_evidence() {
    let key = sk();
    let evidence = vec![
        DemotionEvidenceItem {
            artifact_hash: ContentHash::compute(b"ev-1"),
            category: "divergence_trace".to_string(),
            collected_at_ns: 1_000,
            summary: "first".to_string(),
        },
        DemotionEvidenceItem {
            artifact_hash: ContentHash::compute(b"ev-2"),
            category: "latency_sample".to_string(),
            collected_at_ns: 2_000,
            summary: "second".to_string(),
        },
    ];
    let receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native-sig-test",
            restored_cell_digest: "delegate-sig-test",
            rollback_token_used: "tok-sig",
            demotion_reason: &DemotionReason::SemanticDivergence {
                divergence_count: 2,
                first_divergence_artifact: ContentHash::compute(b"div-1"),
            },
            severity: DemotionSeverity::Critical,
            evidence: &evidence,
            timestamp_ns: 3_000_000_000,
            epoch: SecurityEpoch::from_raw(3),
            zone: "sig-zone",
        },
    )
    .expect("create");
    assert_eq!(receipt.evidence.len(), 2);
    receipt
        .verify_signature(&key.verification_key())
        .expect("signature should verify");
}

// ===========================================================================
// 25) Serde roundtrips — additional types
// ===========================================================================

#[test]
fn serde_roundtrip_demotion_policy() {
    let p = strict_policy();
    let json = serde_json::to_string(&p).unwrap();
    let back: DemotionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn serde_roundtrip_performance_threshold() {
    let t = PerformanceThreshold {
        metric_name: "throughput_ops_sec".to_string(),
        max_value_millionths: 100_000_000,
        sustained_duration_ns: 5_000_000_000,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: PerformanceThreshold = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn serde_roundtrip_demotion_evidence_item() {
    let item = DemotionEvidenceItem {
        artifact_hash: ContentHash::compute(b"ev-roundtrip"),
        category: "capability_violation".to_string(),
        collected_at_ns: 42_000,
        summary: "capability exceeded".to_string(),
    };
    let json = serde_json::to_string(&item).unwrap();
    let back: DemotionEvidenceItem = serde_json::from_str(&json).unwrap();
    assert_eq!(item, back);
}

#[test]
fn serde_roundtrip_trigger_evaluation_fired() {
    let te = TriggerEvaluation {
        fired: true,
        reason: Some(DemotionReason::CapabilityViolation {
            attempted_capability: "net_send".to_string(),
            envelope_digest: ContentHash::compute(b"env"),
        }),
        severity: DemotionSeverity::Critical,
        evidence: vec![DemotionEvidenceItem {
            artifact_hash: ContentHash::compute(b"cap-ev"),
            category: "capability_violation".to_string(),
            collected_at_ns: 100,
            summary: "unauthorized".to_string(),
        }],
    };
    let json = serde_json::to_string(&te).unwrap();
    let back: TriggerEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(te, back);
}

#[test]
fn serde_roundtrip_trigger_evaluation_not_fired() {
    let te = TriggerEvaluation {
        fired: false,
        reason: None,
        severity: DemotionSeverity::Advisory,
        evidence: vec![],
    };
    let json = serde_json::to_string(&te).unwrap();
    let back: TriggerEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(te, back);
}

#[test]
fn serde_roundtrip_demotion_reason_all_variants() {
    let reasons: Vec<DemotionReason> = vec![
        DemotionReason::SemanticDivergence {
            divergence_count: 3,
            first_divergence_artifact: ContentHash::compute(b"div"),
        },
        DemotionReason::PerformanceBreach {
            metric_name: "lat".to_string(),
            observed_millionths: 60_000,
            threshold_millionths: 50_000,
            sustained_duration_ns: 1_000,
        },
        DemotionReason::RiskThresholdBreach {
            observed_risk_millionths: 900_000,
            max_risk_millionths: 800_000,
        },
        DemotionReason::CapabilityViolation {
            attempted_capability: "cap".to_string(),
            envelope_digest: ContentHash::compute(b"env"),
        },
        DemotionReason::OperatorInitiated {
            operator_id: "admin".to_string(),
            reason: "manual".to_string(),
        },
    ];
    for reason in &reasons {
        let json = serde_json::to_string(reason).unwrap();
        let back: DemotionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

#[test]
fn serde_roundtrip_monitoring_observation_all_variants() {
    let observations: Vec<MonitoringObservation> = vec![
        MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(b"in"),
            native_output_hash: ContentHash::compute(b"nat"),
            reference_output_hash: ContentHash::compute(b"ref"),
            waiver_covered: true,
            timestamp_ns: 100,
        },
        MonitoringObservation::PerformanceSample {
            metric_name: "latency".to_string(),
            value_millionths: 55_000_000,
            timestamp_ns: 200,
        },
        MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 750_000,
            timestamp_ns: 300,
        },
        MonitoringObservation::CapabilityEvent {
            capability: "fs_write".to_string(),
            within_envelope: false,
            envelope_digest: ContentHash::compute(b"env"),
            timestamp_ns: 400,
        },
    ];
    for obs in &observations {
        let json = serde_json::to_string(obs).unwrap();
        let back: MonitoringObservation = serde_json::from_str(&json).unwrap();
        assert_eq!(*obs, back);
    }
}

// ===========================================================================
// 26) Monitor accessor methods
// ===========================================================================

#[test]
fn monitor_accessor_slot_id() {
    let m = monitor();
    assert_eq!(m.slot_id(), &slot());
}

#[test]
fn monitor_accessor_native_cell_digest() {
    let m = monitor();
    assert_eq!(m.native_cell_digest(), "new-native-enrich");
}

#[test]
fn monitor_accessor_previous_cell_digest() {
    let m = monitor();
    assert_eq!(m.previous_cell_digest(), "old-delegate-enrich");
}

#[test]
fn monitor_accessor_rollback_token() {
    let m = monitor();
    assert_eq!(m.rollback_token(), "rollback-enrich-token");
}

#[test]
fn monitor_accessor_policy() {
    let m = monitor();
    let policy = m.policy();
    assert!(policy.semantic_divergence_enabled);
    assert_eq!(policy.max_risk_millionths, 800_000);
}

// ===========================================================================
// 27) Capability violation triggers demotion
// ===========================================================================

#[test]
fn capability_violation_triggers_demotion() {
    let mut m = monitor();
    let obs = MonitoringObservation::CapabilityEvent {
        capability: "forbidden_call".to_string(),
        within_envelope: false,
        envelope_digest: ContentHash::compute(b"envelope"),
        timestamp_ns: 2_000_000_000,
    };
    let result = m.process_observation(&obs);
    assert!(result.trigger_fired);
    assert!(m.is_demotion_triggered());
    let eval = result.evaluation.unwrap();
    assert!(eval.fired);
    assert_eq!(eval.severity, DemotionSeverity::Critical);
}

// ===========================================================================
// 28) Waiver-covered divergences don't count
// ===========================================================================

#[test]
fn waiver_covered_divergence_not_counted() {
    let mut m = monitor();
    let obs = MonitoringObservation::OutputComparison {
        matched: false,
        input_hash: ContentHash::compute(b"waiver-input"),
        native_output_hash: ContentHash::compute(b"nat-waiver"),
        reference_output_hash: ContentHash::compute(b"ref-waiver"),
        waiver_covered: true,
        timestamp_ns: 2_000_000_000,
    };
    let result = m.process_observation(&obs);
    assert!(!result.trigger_fired);
    assert_eq!(m.divergence_count(), 0); // waived divergence not counted
}

// ===========================================================================
// 29) Matched outputs don't trigger divergence
// ===========================================================================

#[test]
fn matched_output_no_divergence() {
    let mut m = monitor();
    let obs = MonitoringObservation::OutputComparison {
        matched: true,
        input_hash: ContentHash::compute(b"matched-in"),
        native_output_hash: ContentHash::compute(b"same"),
        reference_output_hash: ContentHash::compute(b"same"),
        waiver_covered: false,
        timestamp_ns: 2_000_000_000,
    };
    let result = m.process_observation(&obs);
    assert!(!result.trigger_fired);
    assert_eq!(m.divergence_count(), 0);
}

// ===========================================================================
// 30) Capability event within envelope doesn't trigger
// ===========================================================================

#[test]
fn capability_within_envelope_no_trigger() {
    let mut m = monitor();
    let obs = MonitoringObservation::CapabilityEvent {
        capability: "allowed_call".to_string(),
        within_envelope: true,
        envelope_digest: ContentHash::compute(b"envelope"),
        timestamp_ns: 2_000_000_000,
    };
    let result = m.process_observation(&obs);
    assert!(!result.trigger_fired);
    assert!(!m.is_demotion_triggered());
}

// ===========================================================================
// 31) Monitor with disabled triggers
// ===========================================================================

#[test]
fn monitor_disabled_semantic_divergence_no_trigger() {
    let receipt = promotion_receipt();
    let mut policy = strict_policy();
    policy.semantic_divergence_enabled = false;

    let mut m = AutoDemotionMonitor::new(&receipt, policy, 1_000_000_000).unwrap();

    // Divergence that would normally trigger
    let obs = MonitoringObservation::OutputComparison {
        matched: false,
        input_hash: ContentHash::compute(b"in"),
        native_output_hash: ContentHash::compute(b"nat"),
        reference_output_hash: ContentHash::compute(b"ref"),
        waiver_covered: false,
        timestamp_ns: 2_000_000_000,
    };
    let result = m.process_observation(&obs);
    assert!(!result.trigger_fired, "disabled trigger should not fire");
}

#[test]
fn monitor_disabled_risk_threshold_no_trigger() {
    let receipt = promotion_receipt();
    let mut policy = strict_policy();
    policy.risk_threshold_enabled = false;

    let mut m = AutoDemotionMonitor::new(&receipt, policy, 1_000_000_000).unwrap();

    // Risk score that would normally trigger
    let obs = MonitoringObservation::RiskScoreUpdate {
        risk_millionths: 999_999,
        timestamp_ns: 2_000_000_000,
    };
    let result = m.process_observation(&obs);
    assert!(
        !result.trigger_fired,
        "disabled risk trigger should not fire"
    );
}

#[test]
fn monitor_disabled_capability_violation_no_trigger() {
    let receipt = promotion_receipt();
    let mut policy = strict_policy();
    policy.capability_violation_enabled = false;

    let mut m = AutoDemotionMonitor::new(&receipt, policy, 1_000_000_000).unwrap();

    let obs = MonitoringObservation::CapabilityEvent {
        capability: "forbidden".to_string(),
        within_envelope: false,
        envelope_digest: ContentHash::compute(b"env"),
        timestamp_ns: 2_000_000_000,
    };
    let result = m.process_observation(&obs);
    assert!(
        !result.trigger_fired,
        "disabled capability trigger should not fire"
    );
}

// ===========================================================================
// 32) DemotionReceipt serde roundtrip
// ===========================================================================

#[test]
fn demotion_receipt_serde_roundtrip() {
    let key = sk();
    let receipt = DemotionReceipt::create_signed(
        &key,
        CreateDemotionReceiptInput {
            slot_id: &slot(),
            demoted_cell_digest: "native-serde",
            restored_cell_digest: "delegate-serde",
            rollback_token_used: "tok-serde",
            demotion_reason: &DemotionReason::OperatorInitiated {
                operator_id: "admin".to_string(),
                reason: "serde test".to_string(),
            },
            severity: DemotionSeverity::Advisory,
            evidence: &[DemotionEvidenceItem {
                artifact_hash: ContentHash::compute(b"ev-serde"),
                category: "manual".to_string(),
                collected_at_ns: 500,
                summary: "operator action".to_string(),
            }],
            timestamp_ns: 4_000_000_000,
            epoch: SecurityEpoch::from_raw(4),
            zone: "serde-zone",
        },
    )
    .unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DemotionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}
