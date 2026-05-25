//! Integration tests for quarantine de-escalation primitive.
//!
//! Tests the complete re-admission workflow including:
//! - Operator-signed re-admission decisions with TEE attestation
//! - Evidence chain continuity and integrity verification
//! - Deterministic replay of re-admission decisions
//! - Fallback path configuration and validation

use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::quarantine_deescalation::{
    AttestationStatus, FallbackPath, QuarantineReason, ReAdmissionDecision, ReAdmissionError,
    ReAdmissionReceipt,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{generate_keypair, SigningKey, VerificationKey};
use frankenengine_engine::tee_attestation_policy::{
    AttestationQuote, MeasurementAlgorithm, MeasurementDigest, RevocationProbeStatus, TeePlatform,
};

use std::collections::BTreeMap;

fn make_test_keys() -> (SigningKey, VerificationKey) {
    let signing_key = generate_keypair().0;
    let verification_key = signing_key.verification_key();
    (signing_key, verification_key)
}

fn make_mock_attestation_quote() -> AttestationQuote {
    let mut revocation_observations = BTreeMap::new();
    revocation_observations.insert("intel-pcs".to_string(), RevocationProbeStatus::Good);
    revocation_observations.insert("manufacturer-crl".to_string(), RevocationProbeStatus::Good);

    AttestationQuote {
        platform: TeePlatform::IntelSgx,
        measurement: MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: "abcd1234ef567890".repeat(4), // 32 bytes for SHA256
        },
        quote_age_secs: 30, // 30 seconds old
        trust_root_id: "intel-sgx-root-ca-001".to_string(),
        revocation_observations,
    }
}

#[test]
fn test_end_to_end_readmission_workflow() {
    let (operator_key, operator_verification_key) = make_test_keys();
    let (system_key, system_verification_key) = make_test_keys();
    let epoch = SecurityEpoch::from_raw(100);

    // Simulate original quarantine scenario.
    let original_quarantine_id = EngineObjectId::default();
    let quarantine_reason = QuarantineReason::PolicyViolation {
        policy_id: "memory-limit-v2".to_string(),
        violation_details: "Exceeded 2GB allocation limit for 30+ seconds".to_string(),
    };

    let fallback_path = FallbackPath::AutoReQuarantine {
        policy_id: "strict-memory-monitoring-v1".to_string(),
        escalation_threshold: 2,
    };

    // Operator makes re-admission decision after investigation.
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "investigation_ticket".to_string(),
        "TICKET-12345".to_string(),
    );
    metadata.insert("approved_by".to_string(), "security-team-lead".to_string());

    let decision = ReAdmissionDecision::new(
        epoch,
        original_quarantine_id,
        quarantine_reason,
        7200, // 2 hours in quarantine
        "operator-security-lead".to_string(),
        AttestationStatus::Available {
            quote: make_mock_attestation_quote(),
        },
        750_000, // 75% confidence
        fallback_path,
        metadata,
        &operator_key,
    )
    .expect("Decision creation should succeed");

    // Verify operator signature.
    assert!(
        decision
            .verify_signature(&operator_verification_key)
            .expect("Signature verification should not error")
    );

    // System generates receipt for evidence chain.
    let prev_evidence_hash = ReAdmissionReceipt::genesis_hash();
    let receipt =
        ReAdmissionReceipt::new(epoch, decision, prev_evidence_hash, 1234567890, &system_key)
            .expect("Receipt creation should succeed");

    // Verify receipt integrity.
    assert!(
        receipt
            .verify(&system_verification_key)
            .expect("Receipt verification should not error")
    );

    // Verify evidence chain linkage.
    assert_eq!(receipt.prev_evidence_hash, prev_evidence_hash);
    assert_eq!(receipt.decision.operator_id, "operator-security-lead");
    assert_eq!(receipt.decision.time_in_quarantine_secs, 7200);
}

#[test]
fn test_evidence_chain_continuity() {
    let (operator_key, _) = make_test_keys();
    let (system_key, system_verification_key) = make_test_keys();
    let epoch = SecurityEpoch::from_raw(200);

    // Create a chain of three re-admission receipts.
    let mut prev_hash = ReAdmissionReceipt::genesis_hash();
    let mut receipts = Vec::new();

    for i in 0..3 {
        let quarantine_reason = QuarantineReason::SuspiciousBehavior {
            pattern_id: format!("pattern-{:03}", i),
            confidence_score: 700_000 + (i as u64) * 10_000,
        };

        let decision = ReAdmissionDecision::new(
            epoch,
            EngineObjectId::default(),
            quarantine_reason,
            3600 * (i as u64 + 1), // Increasing quarantine time
            format!("operator-{}", i),
            AttestationStatus::NotAvailable,
            650_000 + (i as u64) * 50_000,
            FallbackPath::RequireManualIntervention {
                contact_info: "security@example.com".to_string(),
            },
            BTreeMap::new(),
            &operator_key,
        )
        .expect("Decision creation should succeed");

        let receipt = ReAdmissionReceipt::new(
            epoch,
            decision,
            prev_hash,
            1234567890 + (i as u64) * 100,
            &system_key,
        )
        .expect("Receipt creation should succeed");

        // Verify each receipt.
        assert!(
            receipt
                .verify(&system_verification_key)
                .expect("Receipt verification should not error")
        );

        // Update for next iteration.
        prev_hash = receipt.content_hash;
        receipts.push(receipt);
    }

    // Verify chain integrity: each receipt links to the previous one.
    assert_eq!(
        receipts[0].prev_evidence_hash,
        ReAdmissionReceipt::genesis_hash()
    );
    assert_eq!(receipts[1].prev_evidence_hash, receipts[0].content_hash);
    assert_eq!(receipts[2].prev_evidence_hash, receipts[1].content_hash);

    // Verify increasing quarantine times.
    assert_eq!(receipts[0].decision.time_in_quarantine_secs, 3600);
    assert_eq!(receipts[1].decision.time_in_quarantine_secs, 7200);
    assert_eq!(receipts[2].decision.time_in_quarantine_secs, 10800);
}

#[test]
fn test_deterministic_decision_replay() {
    let (operator_key, _) = make_test_keys();
    let epoch = SecurityEpoch::from_raw(300);
    let original_quarantine_id = EngineObjectId::default();

    let quarantine_reason = QuarantineReason::ResourceExhaustion {
        resource_type: "cpu-cycles".to_string(),
        threshold_exceeded: 950_000, // 95% CPU for extended period
    };

    let fallback_path = FallbackPath::StrictMonitoring {
        budget_reduction_millionths: 200_000, // 20% reduction
        monitoring_duration_secs: 86400,      // 24 hours
    };

    let mut metadata = BTreeMap::new();
    metadata.insert(
        "justification".to_string(),
        "Resource spike was due to legitimate batch processing".to_string(),
    );

    // Create the same decision twice with identical parameters.
    let decision1 = ReAdmissionDecision::new(
        epoch,
        original_quarantine_id.clone(),
        quarantine_reason.clone(),
        14400, // 4 hours
        "operator-resource-team".to_string(),
        AttestationStatus::Failed {
            reason: "TEE hardware temporarily unavailable".to_string(),
        },
        600_000, // 60% confidence
        fallback_path.clone(),
        metadata.clone(),
        &operator_key,
    )
    .expect("First decision creation should succeed");

    let decision2 = ReAdmissionDecision::new(
        epoch,
        original_quarantine_id,
        quarantine_reason,
        14400,
        "operator-resource-team".to_string(),
        AttestationStatus::Failed {
            reason: "TEE hardware temporarily unavailable".to_string(),
        },
        600_000,
        fallback_path,
        metadata,
        &operator_key,
    )
    .expect("Second decision creation should succeed");

    // Decisions should be identical (deterministic).
    assert_eq!(decision1.decision_id, decision2.decision_id);
    assert_eq!(decision1.operator_signature, decision2.operator_signature);

    // Create receipts with identical parameters.
    let (system_key, _) = make_test_keys();
    let prev_hash = ReAdmissionReceipt::genesis_hash();
    let timestamp = 1234567890;

    let receipt1 = ReAdmissionReceipt::new(epoch, decision1, prev_hash, timestamp, &system_key)
        .expect("First receipt creation should succeed");

    let receipt2 = ReAdmissionReceipt::new(epoch, decision2, prev_hash, timestamp, &system_key)
        .expect("Second receipt creation should succeed");

    // Receipts should be identical (deterministic).
    assert_eq!(receipt1.receipt_id, receipt2.receipt_id);
    assert_eq!(receipt1.content_hash, receipt2.content_hash);
    assert_eq!(receipt1.system_signature, receipt2.system_signature);
}

#[test]
fn test_tee_attestation_integration() {
    let (operator_key, operator_verification_key) = make_test_keys();
    let epoch = SecurityEpoch::from_raw(400);

    // Test with TEE attestation available.
    let attestation_available = AttestationStatus::Available {
        quote: make_mock_attestation_quote(),
    };

    let decision_with_tee = ReAdmissionDecision::new(
        epoch,
        EngineObjectId::default(),
        QuarantineReason::OperatorInitiated {
            operator_id: "incident-response-team".to_string(),
            reason: "Precautionary isolation during security audit".to_string(),
        },
        1800, // 30 minutes
        "operator-incident-response".to_string(),
        attestation_available,
        900_000, // 90% confidence with TEE
        FallbackPath::RequireManualIntervention {
            contact_info: "incident-response@example.com".to_string(),
        },
        BTreeMap::new(),
        &operator_key,
    )
    .expect("Decision with TEE should succeed");

    // Test with TEE attestation failed.
    let attestation_failed = AttestationStatus::Failed {
        reason: "Quote signature verification failed".to_string(),
    };

    let decision_without_tee = ReAdmissionDecision::new(
        epoch,
        EngineObjectId::default(),
        QuarantineReason::OperatorInitiated {
            operator_id: "incident-response-team".to_string(),
            reason: "Precautionary isolation during security audit".to_string(),
        },
        1800,
        "operator-incident-response".to_string(),
        attestation_failed,
        600_000, // Lower confidence without TEE
        FallbackPath::RequireManualIntervention {
            contact_info: "incident-response@example.com".to_string(),
        },
        BTreeMap::new(),
        &operator_key,
    )
    .expect("Decision without TEE should succeed");

    // Both decisions should be valid but have different confidence levels.
    assert!(
        decision_with_tee
            .verify_signature(&operator_verification_key)
            .expect("TEE decision verification should not error")
    );
    assert!(
        decision_without_tee
            .verify_signature(&operator_verification_key)
            .expect("Non-TEE decision verification should not error")
    );

    assert_eq!(decision_with_tee.posterior_confidence_millionths, 900_000);
    assert_eq!(
        decision_without_tee.posterior_confidence_millionths,
        600_000
    );

    // TEE status should be correctly preserved.
    match &decision_with_tee.tee_attestation {
        AttestationStatus::Available { quote } => {
            assert_eq!(quote.platform, TeePlatform::IntelSgx);
        }
        _ => panic!("Expected TEE attestation to be available"),
    }

    match &decision_without_tee.tee_attestation {
        AttestationStatus::Failed { reason } => {
            assert!(reason.contains("Quote signature verification failed"));
        }
        _ => panic!("Expected TEE attestation to be failed"),
    }
}

#[test]
fn test_fallback_path_scenarios() {
    let (operator_key, _) = make_test_keys();
    let epoch = SecurityEpoch::from_raw(500);

    let test_cases = vec![
        (
            FallbackPath::AutoReQuarantine {
                policy_id: "auto-quarantine-v2".to_string(),
                escalation_threshold: 3,
            },
            "Auto re-quarantine fallback",
        ),
        (
            FallbackPath::StrictMonitoring {
                budget_reduction_millionths: 500_000, // 50% reduction
                monitoring_duration_secs: 172800,     // 48 hours
            },
            "Strict monitoring fallback",
        ),
        (
            FallbackPath::RequireManualIntervention {
                contact_info: "security-escalation@example.com".to_string(),
            },
            "Manual intervention fallback",
        ),
        (
            FallbackPath::PermanentContainment {
                justification: "Repeated violations indicate persistent threat".to_string(),
            },
            "Permanent containment fallback",
        ),
    ];

    for (fallback_path, description) in test_cases {
        let decision = ReAdmissionDecision::new(
            epoch,
            EngineObjectId::default(),
            QuarantineReason::CascadeProtection {
                failed_component: "network-proxy".to_string(),
                dependency_chain: vec!["proxy".to_string(), "auth-service".to_string()],
            },
            5400, // 1.5 hours
            "operator-cascade-response".to_string(),
            AttestationStatus::NotAvailable,
            700_000, // 70% confidence
            fallback_path,
            BTreeMap::new(),
            &operator_key,
        )
        .expect(&format!("{} decision creation should succeed", description));

        // Verify the fallback path is correctly preserved.
        let fallback_display = format!("{}", decision.fallback_path);
        assert!(
            !fallback_display.is_empty(),
            "Fallback path should have a display representation"
        );
    }
}

#[test]
fn test_quarantine_reason_types() {
    let (operator_key, _) = make_test_keys();
    let epoch = SecurityEpoch::from_raw(600);

    let quarantine_reasons = vec![
        QuarantineReason::PolicyViolation {
            policy_id: "data-access-policy-v3".to_string(),
            violation_details: "Accessed sensitive data without proper authorization".to_string(),
        },
        QuarantineReason::SuspiciousBehavior {
            pattern_id: "exfiltration-pattern-001".to_string(),
            confidence_score: 850_000, // 85% confidence
        },
        QuarantineReason::ResourceExhaustion {
            resource_type: "memory".to_string(),
            threshold_exceeded: 4_000_000_000, // 4GB
        },
        QuarantineReason::OperatorInitiated {
            operator_id: "security-team-alpha".to_string(),
            reason: "Scheduled security maintenance".to_string(),
        },
        QuarantineReason::CascadeProtection {
            failed_component: "database-connection-pool".to_string(),
            dependency_chain: vec![
                "db-pool".to_string(),
                "cache-layer".to_string(),
                "api-gateway".to_string(),
            ],
        },
    ];

    for (i, quarantine_reason) in quarantine_reasons.into_iter().enumerate() {
        let decision = ReAdmissionDecision::new(
            epoch,
            EngineObjectId::default(),
            quarantine_reason,
            3600 * (i as u64 + 1), // Varying quarantine times
            format!("operator-test-{}", i),
            AttestationStatus::NotAvailable,
            650_000 + (i as u64) * 25_000, // Varying confidence
            FallbackPath::StrictMonitoring {
                budget_reduction_millionths: 100_000 * (i as u64 + 1),
                monitoring_duration_secs: 3600,
            },
            BTreeMap::new(),
            &operator_key,
        )
        .expect(&format!("Decision {} creation should succeed", i));

        // Verify each quarantine reason type is handled correctly.
        let reason_display = format!("{}", decision.original_quarantine_reason);
        assert!(
            !reason_display.is_empty(),
            "Quarantine reason should have a display representation"
        );
    }
}

#[test]
fn test_content_hash_stability() {
    let (operator_key, _) = make_test_keys();
    let (system_key, _) = make_test_keys();
    let epoch = SecurityEpoch::from_raw(700);

    let decision = ReAdmissionDecision::new(
        epoch,
        EngineObjectId::default(),
        QuarantineReason::PolicyViolation {
            policy_id: "test-policy".to_string(),
            violation_details: "test violation".to_string(),
        },
        3600,
        "test-operator".to_string(),
        AttestationStatus::NotAvailable,
        750_000,
        FallbackPath::AutoReQuarantine {
            policy_id: "test-fallback".to_string(),
            escalation_threshold: 1,
        },
        BTreeMap::new(),
        &operator_key,
    )
    .expect("Decision creation should succeed");

    let prev_hash = ContentHash::compute(b"test-prev-hash");
    let timestamp = 1000000000;

    // Create multiple receipts with same parameters.
    let mut receipt_hashes = Vec::new();

    for _ in 0..5 {
        let receipt =
            ReAdmissionReceipt::new(epoch, decision.clone(), prev_hash, timestamp, &system_key)
                .expect("Receipt creation should succeed");

        receipt_hashes.push(receipt.content_hash);
    }

    // All content hashes should be identical.
    for hash in &receipt_hashes[1..] {
        assert_eq!(
            *hash, receipt_hashes[0],
            "Content hashes should be deterministic"
        );
    }
}

#[test]
fn test_signature_tampering_detection() {
    let (operator_key, operator_verification_key) = make_test_keys();
    let (_, wrong_verification_key) = make_test_keys();

    let mut decision = ReAdmissionDecision::new(
        SecurityEpoch::from_raw(800),
        EngineObjectId::default(),
        QuarantineReason::PolicyViolation {
            policy_id: "tamper-test".to_string(),
            violation_details: "test".to_string(),
        },
        3600,
        "test-operator".to_string(),
        AttestationStatus::NotAvailable,
        750_000,
        FallbackPath::AutoReQuarantine {
            policy_id: "test".to_string(),
            escalation_threshold: 1,
        },
        BTreeMap::new(),
        &operator_key,
    )
    .expect("Decision creation should succeed");

    // Valid signature should verify.
    assert!(
        decision
            .verify_signature(&operator_verification_key)
            .expect("Verification should not error")
    );

    // Wrong key should fail verification.
    assert!(
        !decision
            .verify_signature(&wrong_verification_key)
            .expect("Verification should not error")
    );

    // Tamper with operator ID and verify it's detected.
    decision.operator_id = "tampered-operator".to_string();
    assert!(
        !decision
            .verify_signature(&operator_verification_key)
            .expect("Verification should not error")
    );
}

#[test]
fn test_error_handling() {
    let (operator_key, _) = make_test_keys();
    let epoch = SecurityEpoch::from_raw(900);

    // Test with extreme confidence values.
    let decision_high_confidence = ReAdmissionDecision::new(
        epoch,
        EngineObjectId::default(),
        QuarantineReason::PolicyViolation {
            policy_id: "test".to_string(),
            violation_details: "test".to_string(),
        },
        3600,
        "test-operator".to_string(),
        AttestationStatus::NotAvailable,
        1_000_000, // 100% confidence
        FallbackPath::AutoReQuarantine {
            policy_id: "test".to_string(),
            escalation_threshold: 1,
        },
        BTreeMap::new(),
        &operator_key,
    );

    // Should succeed even with 100% confidence.
    assert!(decision_high_confidence.is_ok());

    // Test error display formatting.
    let test_error = ReAdmissionError::InvalidInput("test input error".to_string());
    let error_display = format!("{}", test_error);
    assert!(error_display.contains("Invalid input"));
    assert!(error_display.contains("test input error"));
}
