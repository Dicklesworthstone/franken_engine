//! Integration tests for the `recovery_artifact` module.
//!
//! Covers: ArtifactType, RecoveryTrigger, ProofElement, OperatorAction,
//! RecoveryArtifact, RecoveryVerdict, VerificationError, RecoveryEvent,
//! ArtifactBuilder, and RecoveryArtifactStore.

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

use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::recovery_artifact::{
    ArtifactBuilder, ArtifactType, OperatorAction, ProofElement, RecoveryArtifact,
    RecoveryArtifactStore, RecoveryEvent, RecoveryTrigger, RecoveryVerdict, VerificationError,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn test_key() -> Vec<u8> {
    b"test-signing-key-epoch-1".to_vec()
}

fn sample_before_state() -> ContentHash {
    ContentHash::compute(b"before-state")
}

fn sample_after_state() -> ContentHash {
    ContentHash::compute(b"after-state")
}

fn build_valid_artifact() -> RecoveryArtifact {
    ArtifactBuilder::new(
        ArtifactType::ForcedReconciliation,
        RecoveryTrigger::AutomaticFallback {
            fallback_id: "fb-t1-1".to_string(),
        },
        sample_before_state(),
        "t1",
        1,
        1000,
        &test_key(),
    )
    .after_state(sample_after_state())
    .proof(ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"mmr-root"),
        leaf_count: 42,
        proof_hashes: vec![ContentHash::compute(b"h1"), ContentHash::compute(b"h2")],
    })
    .proof(ProofElement::HashChainVerification {
        start_marker_id: 0,
        end_marker_id: 10,
        chain_hash: ContentHash::compute(b"chain"),
        verified: true,
    })
    .proof(ProofElement::EvidenceEntryLink {
        evidence_hash: ContentHash::compute(b"evidence"),
        decision_id: "d-1".to_string(),
    })
    .proof(ProofElement::EpochValidityCheck {
        epoch: test_epoch(),
        is_valid: true,
        reason: "current epoch".to_string(),
    })
    .build()
}

fn test_store() -> RecoveryArtifactStore {
    RecoveryArtifactStore::new(test_epoch(), &test_key())
}

// ===========================================================================
// ArtifactType — serde + display + ord
// ===========================================================================

#[test]
fn artifact_type_serde_roundtrip_all_variants() {
    let types = [
        ArtifactType::GapFill,
        ArtifactType::StateRepair,
        ArtifactType::ForcedReconciliation,
        ArtifactType::TrustRestoration,
        ArtifactType::RejectedEpochPromotion,
        ArtifactType::RejectedRevocation,
        ArtifactType::FailedAttestation,
    ];
    for t in &types {
        let json = serde_json::to_string(t).unwrap();
        let restored: ArtifactType = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, restored);
    }
}

#[test]
fn artifact_type_display_all_variants() {
    assert_eq!(ArtifactType::GapFill.to_string(), "gap_fill");
    assert_eq!(ArtifactType::StateRepair.to_string(), "state_repair");
    assert_eq!(
        ArtifactType::ForcedReconciliation.to_string(),
        "forced_reconciliation"
    );
    assert_eq!(
        ArtifactType::TrustRestoration.to_string(),
        "trust_restoration"
    );
    assert_eq!(
        ArtifactType::RejectedEpochPromotion.to_string(),
        "rejected_epoch_promotion"
    );
    assert_eq!(
        ArtifactType::RejectedRevocation.to_string(),
        "rejected_revocation"
    );
    assert_eq!(
        ArtifactType::FailedAttestation.to_string(),
        "failed_attestation"
    );
}

#[test]
fn artifact_type_ordering() {
    assert!(ArtifactType::GapFill < ArtifactType::StateRepair);
    assert!(ArtifactType::StateRepair < ArtifactType::ForcedReconciliation);
    assert!(ArtifactType::ForcedReconciliation < ArtifactType::TrustRestoration);
}

// ===========================================================================
// RecoveryTrigger — serde + display
// ===========================================================================

#[test]
fn recovery_trigger_serde_roundtrip_all_variants() {
    let triggers = [
        RecoveryTrigger::ReconciliationFailure {
            reconciliation_id: "r1".to_string(),
        },
        RecoveryTrigger::IntegrityCheckFailure {
            check_id: "c1".to_string(),
            details: "corrupt".to_string(),
        },
        RecoveryTrigger::OperatorIntervention {
            operator: "admin".to_string(),
            reason: "restore".to_string(),
        },
        RecoveryTrigger::AutomaticFallback {
            fallback_id: "fb-1".to_string(),
        },
        RecoveryTrigger::EpochValidationFailure {
            from_epoch: 1,
            to_epoch: 2,
        },
        RecoveryTrigger::StaleAttestation {
            attestation_age_ticks: 10000,
        },
    ];
    for t in &triggers {
        let json = serde_json::to_string(t).unwrap();
        let restored: RecoveryTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, restored);
    }
}

#[test]
fn recovery_trigger_display_all_variants() {
    assert!(
        RecoveryTrigger::ReconciliationFailure {
            reconciliation_id: "r1".to_string()
        }
        .to_string()
        .contains("reconciliation_failure")
    );
    assert!(
        RecoveryTrigger::IntegrityCheckFailure {
            check_id: "c1".to_string(),
            details: "corrupt".to_string(),
        }
        .to_string()
        .contains("integrity_check_failure")
    );
    assert!(
        RecoveryTrigger::OperatorIntervention {
            operator: "admin".to_string(),
            reason: "fix".to_string(),
        }
        .to_string()
        .contains("operator_intervention")
    );
    assert!(
        RecoveryTrigger::AutomaticFallback {
            fallback_id: "fb-1".to_string()
        }
        .to_string()
        .contains("automatic_fallback")
    );
    assert!(
        RecoveryTrigger::EpochValidationFailure {
            from_epoch: 1,
            to_epoch: 2
        }
        .to_string()
        .contains("epoch_validation_failure")
    );
    assert!(
        RecoveryTrigger::StaleAttestation {
            attestation_age_ticks: 5000
        }
        .to_string()
        .contains("stale_attestation")
    );
}

// ===========================================================================
// ProofElement — serde + display
// ===========================================================================

#[test]
fn proof_element_serde_roundtrip_all_variants() {
    let elements = [
        ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(b"root"),
            leaf_count: 10,
            proof_hashes: vec![ContentHash::compute(b"a")],
        },
        ProofElement::HashChainVerification {
            start_marker_id: 0,
            end_marker_id: 5,
            chain_hash: ContentHash::compute(b"chain"),
            verified: true,
        },
        ProofElement::EvidenceEntryLink {
            evidence_hash: ContentHash::compute(b"ev"),
            decision_id: "d-1".to_string(),
        },
        ProofElement::EpochValidityCheck {
            epoch: test_epoch(),
            is_valid: true,
            reason: "ok".to_string(),
        },
    ];
    for e in &elements {
        let json = serde_json::to_string(e).unwrap();
        let restored: ProofElement = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, restored);
    }
}

#[test]
fn proof_element_display_all_variants() {
    let mmr = ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"r"),
        leaf_count: 42,
        proof_hashes: vec![],
    };
    assert!(mmr.to_string().contains("42"));

    let chain = ProofElement::HashChainVerification {
        start_marker_id: 0,
        end_marker_id: 10,
        chain_hash: ContentHash::compute(b"c"),
        verified: true,
    };
    assert!(chain.to_string().contains("ok=true"));

    let link = ProofElement::EvidenceEntryLink {
        evidence_hash: ContentHash::compute(b"ev"),
        decision_id: "d-99".to_string(),
    };
    assert!(link.to_string().contains("d-99"));

    let epoch = ProofElement::EpochValidityCheck {
        epoch: test_epoch(),
        is_valid: false,
        reason: "stale".to_string(),
    };
    assert!(epoch.to_string().contains("valid=false"));
}

// ===========================================================================
// OperatorAction — serde
// ===========================================================================

#[test]
fn operator_action_serde_roundtrip() {
    let action = OperatorAction {
        operator: "admin".to_string(),
        action: "force restore".to_string(),
        authorization_hash: AuthenticityHash::compute_keyed(b"key", b"payload"),
        timestamp_ticks: 5000,
    };
    let json = serde_json::to_string(&action).unwrap();
    let restored: OperatorAction = serde_json::from_str(&json).unwrap();
    assert_eq!(action, restored);
}

// ===========================================================================
// RecoveryVerdict — serde + display + is_valid
// ===========================================================================

#[test]
fn recovery_verdict_valid_is_valid() {
    assert!(RecoveryVerdict::Valid.is_valid());
}

#[test]
fn recovery_verdict_invalid_is_not_valid() {
    let v = RecoveryVerdict::Invalid {
        reasons: vec!["bad".to_string()],
    };
    assert!(!v.is_valid());
}

#[test]
fn recovery_verdict_display() {
    assert_eq!(RecoveryVerdict::Valid.to_string(), "valid");
    let inv = RecoveryVerdict::Invalid {
        reasons: vec!["r1".to_string(), "r2".to_string()],
    };
    let display = inv.to_string();
    assert!(display.contains("r1"));
    assert!(display.contains("r2"));
}

#[test]
fn recovery_verdict_serde_roundtrip() {
    let verdicts = [
        RecoveryVerdict::Valid,
        RecoveryVerdict::Invalid {
            reasons: vec!["bad".to_string()],
        },
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let restored: RecoveryVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

// ===========================================================================
// VerificationError — serde + display + std::error
// ===========================================================================

#[test]
fn verification_error_serde_roundtrip_all_variants() {
    let errors = [
        VerificationError::ArtifactIdMismatch {
            expected: ContentHash::compute(b"a"),
            computed: ContentHash::compute(b"b"),
        },
        VerificationError::SignatureInvalid {
            details: "bad sig".to_string(),
        },
        VerificationError::EmptyProofBundle,
        VerificationError::MissingProofElement {
            element_type: "mmr".to_string(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let restored: VerificationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, restored);
    }
}

#[test]
fn verification_error_display_all_variants() {
    assert!(
        VerificationError::ArtifactIdMismatch {
            expected: ContentHash::compute(b"a"),
            computed: ContentHash::compute(b"b"),
        }
        .to_string()
        .contains("mismatch")
    );
    assert!(
        VerificationError::SignatureInvalid {
            details: "bad".to_string(),
        }
        .to_string()
        .contains("bad")
    );
    assert!(
        VerificationError::EmptyProofBundle
            .to_string()
            .contains("empty")
    );
    assert!(
        VerificationError::MissingProofElement {
            element_type: "chain".to_string(),
        }
        .to_string()
        .contains("chain")
    );
}

#[test]
fn verification_error_implements_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(VerificationError::EmptyProofBundle);
    assert!(!e.to_string().is_empty());
}

// ===========================================================================
// RecoveryEvent — serde
// ===========================================================================

#[test]
fn recovery_event_serde_roundtrip() {
    let event = RecoveryEvent {
        artifact_id: "abc".to_string(),
        artifact_type: "gap_fill".to_string(),
        trigger: "reconciliation_failure:r1".to_string(),
        verification_verdict: "valid".to_string(),
        trace_id: "t1".to_string(),
        epoch_id: 1,
        event: "artifact_recorded".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: RecoveryEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// ===========================================================================
// ArtifactBuilder — construction
// ===========================================================================

#[test]
fn builder_produces_valid_artifact_with_all_proof_types() {
    let artifact = build_valid_artifact();
    assert_eq!(artifact.artifact_type, ArtifactType::ForcedReconciliation);
    assert_eq!(artifact.epoch_id, 1);
    assert_eq!(artifact.proof_bundle.len(), 4);
    assert_eq!(artifact.before_state, sample_before_state());
    assert_eq!(artifact.after_state, sample_after_state());
    assert_eq!(artifact.trace_id, "t1");
    assert_eq!(artifact.timestamp_ticks, 1000);
    assert!(artifact.operator_actions.is_empty());
}

#[test]
fn builder_uses_before_state_when_no_after_set() {
    let artifact = ArtifactBuilder::new(
        ArtifactType::GapFill,
        RecoveryTrigger::ReconciliationFailure {
            reconciliation_id: "r1".to_string(),
        },
        sample_before_state(),
        "t1",
        1,
        1000,
        &test_key(),
    )
    .proof(ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"root"),
        leaf_count: 1,
        proof_hashes: vec![],
    })
    .build();

    assert_eq!(artifact.before_state, artifact.after_state);
}

#[test]
fn builder_includes_operator_actions() {
    let artifact = ArtifactBuilder::new(
        ArtifactType::TrustRestoration,
        RecoveryTrigger::OperatorIntervention {
            operator: "admin".to_string(),
            reason: "manual restore".to_string(),
        },
        sample_before_state(),
        "t1",
        1,
        2000,
        &test_key(),
    )
    .after_state(sample_after_state())
    .proof(ProofElement::EpochValidityCheck {
        epoch: test_epoch(),
        is_valid: true,
        reason: "current".to_string(),
    })
    .operator_action(OperatorAction {
        operator: "admin".to_string(),
        action: "force restore trust".to_string(),
        authorization_hash: AuthenticityHash::compute_keyed(b"admin-key", b"force restore trust"),
        timestamp_ticks: 2000,
    })
    .build();

    assert_eq!(artifact.operator_actions.len(), 1);
    assert_eq!(artifact.operator_actions[0].operator, "admin");
}

#[test]
fn builder_computes_deterministic_artifact_id() {
    let a1 = build_valid_artifact();
    let a2 = build_valid_artifact();
    assert_eq!(a1.artifact_id, a2.artifact_id);
    assert_eq!(a1.signature, a2.signature);
}

#[test]
fn builder_different_inputs_produce_different_ids() {
    let a1 = ArtifactBuilder::new(
        ArtifactType::GapFill,
        RecoveryTrigger::ReconciliationFailure {
            reconciliation_id: "r1".to_string(),
        },
        sample_before_state(),
        "t1",
        1,
        1000,
        &test_key(),
    )
    .proof(ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"root"),
        leaf_count: 1,
        proof_hashes: vec![],
    })
    .build();

    let a2 = ArtifactBuilder::new(
        ArtifactType::StateRepair,
        RecoveryTrigger::IntegrityCheckFailure {
            check_id: "c1".to_string(),
            details: "corrupt".to_string(),
        },
        sample_before_state(),
        "t2",
        2,
        2000,
        &test_key(),
    )
    .proof(ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"root"),
        leaf_count: 1,
        proof_hashes: vec![],
    })
    .build();

    assert_ne!(a1.artifact_id, a2.artifact_id);
}

#[test]
fn builder_computes_signature() {
    let artifact = build_valid_artifact();
    let expected_sig =
        AuthenticityHash::compute_keyed(&test_key(), artifact.artifact_id.as_bytes());
    assert_eq!(artifact.signature, expected_sig);
}

#[test]
fn builder_multiple_operator_actions() {
    let artifact = ArtifactBuilder::new(
        ArtifactType::ForcedReconciliation,
        RecoveryTrigger::OperatorIntervention {
            operator: "admin".to_string(),
            reason: "multi-step repair".to_string(),
        },
        sample_before_state(),
        "t1",
        1,
        1000,
        &test_key(),
    )
    .after_state(sample_after_state())
    .proof(ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"root"),
        leaf_count: 5,
        proof_hashes: vec![],
    })
    .operator_action(OperatorAction {
        operator: "admin".to_string(),
        action: "step 1".to_string(),
        authorization_hash: AuthenticityHash::compute_keyed(b"k", b"step 1"),
        timestamp_ticks: 1000,
    })
    .operator_action(OperatorAction {
        operator: "admin".to_string(),
        action: "step 2".to_string(),
        authorization_hash: AuthenticityHash::compute_keyed(b"k", b"step 2"),
        timestamp_ticks: 1001,
    })
    .build();

    assert_eq!(artifact.operator_actions.len(), 2);
}

// ===========================================================================
// RecoveryArtifact — serde
// ===========================================================================

#[test]
fn recovery_artifact_serde_roundtrip() {
    let artifact = build_valid_artifact();
    let json = serde_json::to_string(&artifact).unwrap();
    let restored: RecoveryArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, restored);
}

// ===========================================================================
// RecoveryArtifactStore — construction
// ===========================================================================

#[test]
fn store_starts_empty() {
    let store = test_store();
    assert_eq!(store.len(), 0);
    assert!(store.is_empty());
    assert_eq!(store.epoch(), test_epoch());
    assert!(store.event_counts().is_empty());
}

// ===========================================================================
// Store — record + get
// ===========================================================================

#[test]
fn store_record_and_get() {
    let mut store = test_store();
    let artifact = build_valid_artifact();
    let hex_id = artifact.artifact_id.to_hex();
    store.record(artifact.clone(), "t1");

    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());

    let retrieved = store.get(&hex_id).unwrap();
    assert_eq!(retrieved.artifact_type, ArtifactType::ForcedReconciliation);
    assert_eq!(retrieved.epoch_id, 1);
}

#[test]
fn store_get_returns_none_for_missing() {
    let store = test_store();
    assert!(store.get("nonexistent").is_none());
}

#[test]
fn store_record_multiple() {
    let mut store = test_store();

    let a1 = ArtifactBuilder::new(
        ArtifactType::GapFill,
        RecoveryTrigger::ReconciliationFailure {
            reconciliation_id: "r1".to_string(),
        },
        sample_before_state(),
        "t1",
        1,
        1000,
        &test_key(),
    )
    .proof(ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"root"),
        leaf_count: 1,
        proof_hashes: vec![],
    })
    .build();

    let a2 = ArtifactBuilder::new(
        ArtifactType::StateRepair,
        RecoveryTrigger::IntegrityCheckFailure {
            check_id: "c1".to_string(),
            details: "corrupt".to_string(),
        },
        sample_before_state(),
        "t2",
        1,
        2000,
        &test_key(),
    )
    .proof(ProofElement::HashChainVerification {
        start_marker_id: 0,
        end_marker_id: 5,
        chain_hash: ContentHash::compute(b"chain"),
        verified: true,
    })
    .build();

    store.record(a1, "t1");
    store.record(a2, "t2");
    assert_eq!(store.len(), 2);
}

// ===========================================================================
// Store — export
// ===========================================================================

#[test]
fn store_export() {
    let mut store = test_store();
    store.record(build_valid_artifact(), "t1");

    let exported = store.export();
    assert_eq!(exported.len(), 1);

    let json = serde_json::to_string(exported[0]).unwrap();
    let restored: RecoveryArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.artifact_type, ArtifactType::ForcedReconciliation);
}

#[test]
fn store_export_empty() {
    let store = test_store();
    assert!(store.export().is_empty());
}

// ===========================================================================
// Store — verify valid artifacts
// ===========================================================================

#[test]
fn verify_valid_artifact_returns_valid() {
    let mut store = test_store();
    let artifact = build_valid_artifact();
    let verdict = store.verify(&artifact, "t1").unwrap();
    assert!(verdict.is_valid());
}

// ===========================================================================
// Store — verify detects tampered artifact_id
// ===========================================================================

#[test]
fn verify_detects_tampered_artifact_id() {
    let mut store = test_store();
    let mut artifact = build_valid_artifact();
    artifact.artifact_id = ContentHash::compute(b"tampered");

    let result = store.verify(&artifact, "t1");
    assert!(matches!(
        result,
        Err(VerificationError::ArtifactIdMismatch { .. })
    ));
}

// ===========================================================================
// Store — verify detects wrong signing key
// ===========================================================================

#[test]
fn verify_detects_wrong_signing_key() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), b"wrong-key");
    let artifact = build_valid_artifact();

    let result = store.verify(&artifact, "t1");
    assert!(matches!(
        result,
        Err(VerificationError::SignatureInvalid { .. })
    ));
}

// ===========================================================================
// Store — verify rejects empty proof bundle
// ===========================================================================

#[test]
fn verify_rejects_empty_proof_bundle() {
    let mut store = test_store();
    let artifact = ArtifactBuilder::new(
        ArtifactType::StateRepair,
        RecoveryTrigger::IntegrityCheckFailure {
            check_id: "c1".to_string(),
            details: "corrupt".to_string(),
        },
        sample_before_state(),
        "t1",
        1,
        1000,
        &test_key(),
    )
    .build();

    let result = store.verify(&artifact, "t1");
    assert!(matches!(result, Err(VerificationError::EmptyProofBundle)));
}

// ===========================================================================
// Store — verify detects failed proof elements
// ===========================================================================

#[test]
fn verify_detects_failed_chain_verification() {
    let mut store = test_store();
    let artifact = ArtifactBuilder::new(
        ArtifactType::StateRepair,
        RecoveryTrigger::IntegrityCheckFailure {
            check_id: "c1".to_string(),
            details: "corrupt".to_string(),
        },
        sample_before_state(),
        "t1",
        1,
        1000,
        &test_key(),
    )
    .proof(ProofElement::HashChainVerification {
        start_marker_id: 0,
        end_marker_id: 5,
        chain_hash: ContentHash::compute(b"chain"),
        verified: false,
    })
    .build();

    let verdict = store.verify(&artifact, "t1").unwrap();
    assert!(!verdict.is_valid());
    if let RecoveryVerdict::Invalid { reasons } = &verdict {
        assert!(reasons[0].contains("hash chain"));
    }
}

#[test]
fn verify_detects_failed_epoch_check() {
    let mut store = test_store();
    let artifact = ArtifactBuilder::new(
        ArtifactType::RejectedEpochPromotion,
        RecoveryTrigger::EpochValidationFailure {
            from_epoch: 1,
            to_epoch: 2,
        },
        sample_before_state(),
        "t1",
        1,
        1000,
        &test_key(),
    )
    .proof(ProofElement::EpochValidityCheck {
        epoch: SecurityEpoch::from_raw(2),
        is_valid: false,
        reason: "quorum not met".to_string(),
    })
    .build();

    let verdict = store.verify(&artifact, "t1").unwrap();
    assert!(!verdict.is_valid());
    if let RecoveryVerdict::Invalid { reasons } = &verdict {
        assert!(reasons[0].contains("quorum not met"));
    }
}

#[test]
fn verify_collects_multiple_failure_reasons() {
    let mut store = test_store();
    let artifact = ArtifactBuilder::new(
        ArtifactType::StateRepair,
        RecoveryTrigger::IntegrityCheckFailure {
            check_id: "c1".to_string(),
            details: "corrupt".to_string(),
        },
        sample_before_state(),
        "t1",
        1,
        1000,
        &test_key(),
    )
    .proof(ProofElement::HashChainVerification {
        start_marker_id: 0,
        end_marker_id: 5,
        chain_hash: ContentHash::compute(b"chain"),
        verified: false,
    })
    .proof(ProofElement::EpochValidityCheck {
        epoch: test_epoch(),
        is_valid: false,
        reason: "stale".to_string(),
    })
    .build();

    let verdict = store.verify(&artifact, "t1").unwrap();
    assert!(!verdict.is_valid());
    if let RecoveryVerdict::Invalid { reasons } = &verdict {
        assert_eq!(reasons.len(), 2);
    }
}

#[test]
fn verify_passes_mmr_and_evidence_as_informational() {
    let mut store = test_store();
    let artifact = ArtifactBuilder::new(
        ArtifactType::GapFill,
        RecoveryTrigger::ReconciliationFailure {
            reconciliation_id: "r1".to_string(),
        },
        sample_before_state(),
        "t1",
        1,
        1000,
        &test_key(),
    )
    .proof(ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"root"),
        leaf_count: 10,
        proof_hashes: vec![],
    })
    .proof(ProofElement::EvidenceEntryLink {
        evidence_hash: ContentHash::compute(b"ev"),
        decision_id: "d-1".to_string(),
    })
    .build();

    let verdict = store.verify(&artifact, "t1").unwrap();
    assert!(verdict.is_valid());
}

// ===========================================================================
// Store — events
// ===========================================================================

#[test]
fn store_emits_record_event() {
    let mut store = test_store();
    let artifact = build_valid_artifact();
    store.record(artifact, "t1");

    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "artifact_recorded");
    assert_eq!(events[0].trace_id, "t1");
}

#[test]
fn store_emits_verify_event() {
    let mut store = test_store();
    let artifact = build_valid_artifact();
    store.verify(&artifact, "t1").unwrap();

    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "artifact_verified");
    assert_eq!(events[0].verification_verdict, "valid");
}

#[test]
fn store_emits_both_record_and_verify_events() {
    let mut store = test_store();
    let artifact = build_valid_artifact();
    store.record(artifact.clone(), "t1");
    store.verify(&artifact, "t1").unwrap();

    let events = store.drain_events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event, "artifact_recorded");
    assert_eq!(events[1].event, "artifact_verified");
}

#[test]
fn drain_events_clears_events() {
    let mut store = test_store();
    store.record(build_valid_artifact(), "t1");
    let first = store.drain_events();
    assert_eq!(first.len(), 1);
    let second = store.drain_events();
    assert!(second.is_empty());
}

#[test]
fn event_counts_accumulate() {
    let mut store = test_store();
    let a1 = build_valid_artifact();
    store.record(a1.clone(), "t1");
    store.verify(&a1, "t1").unwrap();

    assert_eq!(store.event_counts().get("artifact_recorded"), Some(&1));
    assert_eq!(store.event_counts().get("artifact_verified"), Some(&1));
}

#[test]
fn event_counts_increase_with_multiple_operations() {
    let mut store = test_store();
    let a1 = build_valid_artifact();
    store.record(a1.clone(), "t1");
    store.record(a1.clone(), "t2");
    store.verify(&a1, "t3").unwrap();
    store.verify(&a1, "t4").unwrap();

    assert_eq!(store.event_counts().get("artifact_recorded"), Some(&2));
    assert_eq!(store.event_counts().get("artifact_verified"), Some(&2));
}

// ===========================================================================
// Store — record then verify roundtrip
// ===========================================================================

#[test]
fn record_then_verify_roundtrip() {
    let mut store = test_store();
    let artifact = build_valid_artifact();
    let hex_id = artifact.artifact_id.to_hex();

    store.record(artifact, "t1");
    let retrieved = store.get(&hex_id).unwrap().clone();
    let verdict = store.verify(&retrieved, "t1").unwrap();
    assert!(verdict.is_valid());
}

// ===========================================================================
// Builder — all 7 artifact types
// ===========================================================================

#[test]
fn build_all_artifact_types() {
    let types = [
        ArtifactType::GapFill,
        ArtifactType::StateRepair,
        ArtifactType::ForcedReconciliation,
        ArtifactType::TrustRestoration,
        ArtifactType::RejectedEpochPromotion,
        ArtifactType::RejectedRevocation,
        ArtifactType::FailedAttestation,
    ];

    let mut store = test_store();
    for (i, at) in types.iter().enumerate() {
        let trigger = RecoveryTrigger::AutomaticFallback {
            fallback_id: format!("fb-{i}"),
        };
        let artifact = ArtifactBuilder::new(
            at.clone(),
            trigger,
            sample_before_state(),
            &format!("t-{i}"),
            1,
            1000 + i as u64,
            &test_key(),
        )
        .after_state(sample_after_state())
        .proof(ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(format!("root-{i}").as_bytes()),
            leaf_count: i as u64,
            proof_hashes: vec![],
        })
        .build();

        assert_eq!(artifact.artifact_type, *at);
        let verdict = store.verify(&artifact, &format!("t-{i}")).unwrap();
        assert!(verdict.is_valid());
        store.record(artifact, &format!("t-{i}"));
    }
    assert_eq!(store.len(), 7);
}

// ===========================================================================
// Builder — all 6 trigger types
// ===========================================================================

#[test]
fn build_all_trigger_types() {
    let triggers = [
        RecoveryTrigger::ReconciliationFailure {
            reconciliation_id: "r1".to_string(),
        },
        RecoveryTrigger::IntegrityCheckFailure {
            check_id: "c1".to_string(),
            details: "corrupt".to_string(),
        },
        RecoveryTrigger::OperatorIntervention {
            operator: "admin".to_string(),
            reason: "manual fix".to_string(),
        },
        RecoveryTrigger::AutomaticFallback {
            fallback_id: "fb-1".to_string(),
        },
        RecoveryTrigger::EpochValidationFailure {
            from_epoch: 1,
            to_epoch: 2,
        },
        RecoveryTrigger::StaleAttestation {
            attestation_age_ticks: 50000,
        },
    ];

    let mut store = test_store();
    for (i, trigger) in triggers.into_iter().enumerate() {
        let artifact = ArtifactBuilder::new(
            ArtifactType::GapFill,
            trigger,
            sample_before_state(),
            &format!("trigger-{i}"),
            1,
            1000 + i as u64,
            &test_key(),
        )
        .proof(ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(format!("root-{i}").as_bytes()),
            leaf_count: 1,
            proof_hashes: vec![],
        })
        .build();

        let verdict = store.verify(&artifact, &format!("trigger-{i}")).unwrap();
        assert!(verdict.is_valid());
        store.record(artifact, &format!("trigger-{i}"));
    }
    assert_eq!(store.len(), 6);
}

// ===========================================================================
// Stress — 20 artifacts
// ===========================================================================

#[test]
fn stress_20_artifacts() {
    let mut store = test_store();
    let types = [
        ArtifactType::GapFill,
        ArtifactType::StateRepair,
        ArtifactType::ForcedReconciliation,
        ArtifactType::TrustRestoration,
    ];

    for i in 0u32..20 {
        let at = types[(i % 4) as usize].clone();
        let artifact = ArtifactBuilder::new(
            at,
            RecoveryTrigger::AutomaticFallback {
                fallback_id: format!("fb-{i}"),
            },
            ContentHash::compute(format!("before-{i}").as_bytes()),
            &format!("stress-{i}"),
            1,
            1000 + u64::from(i),
            &test_key(),
        )
        .after_state(ContentHash::compute(format!("after-{i}").as_bytes()))
        .proof(ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(format!("root-{i}").as_bytes()),
            leaf_count: u64::from(i),
            proof_hashes: vec![],
        })
        .proof(ProofElement::HashChainVerification {
            start_marker_id: 0,
            end_marker_id: u64::from(i),
            chain_hash: ContentHash::compute(format!("chain-{i}").as_bytes()),
            verified: true,
        })
        .build();

        let verdict = store.verify(&artifact, &format!("stress-{i}")).unwrap();
        assert!(verdict.is_valid());
        store.record(artifact, &format!("stress-{i}"));
    }

    assert_eq!(store.len(), 20);
    assert_eq!(store.event_counts().get("artifact_recorded"), Some(&20));
    assert_eq!(store.event_counts().get("artifact_verified"), Some(&20));
    assert_eq!(store.export().len(), 20);
}
