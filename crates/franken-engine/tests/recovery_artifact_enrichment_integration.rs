//! Enrichment integration tests for `frankenengine_engine::recovery_artifact`.
//!
//! Exercises public types, enums, structs, builder patterns, store operations,
//! verification, Display uniqueness, serde roundtrips, deterministic hashing,
//! and edge cases from the crate boundary.

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

use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::recovery_artifact::*;
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

fn build_artifact_with_type(at: ArtifactType) -> RecoveryArtifact {
    ArtifactBuilder::new(
        at,
        RecoveryTrigger::AutomaticFallback {
            fallback_id: "fb-typed".to_string(),
        },
        sample_before_state(),
        "t-typed",
        1,
        1000,
        &test_key(),
    )
    .proof(ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"r"),
        leaf_count: 1,
        proof_hashes: vec![],
    })
    .build()
}

fn all_artifact_types() -> Vec<ArtifactType> {
    vec![
        ArtifactType::GapFill,
        ArtifactType::StateRepair,
        ArtifactType::ForcedReconciliation,
        ArtifactType::TrustRestoration,
        ArtifactType::RejectedEpochPromotion,
        ArtifactType::RejectedRevocation,
        ArtifactType::FailedAttestation,
    ]
}

fn all_triggers() -> Vec<RecoveryTrigger> {
    vec![
        RecoveryTrigger::ReconciliationFailure {
            reconciliation_id: "r1".to_string(),
        },
        RecoveryTrigger::IntegrityCheckFailure {
            check_id: "c1".to_string(),
            details: "corrupt".to_string(),
        },
        RecoveryTrigger::OperatorIntervention {
            operator: "admin".to_string(),
            reason: "manual".to_string(),
        },
        RecoveryTrigger::AutomaticFallback {
            fallback_id: "fb-1".to_string(),
        },
        RecoveryTrigger::EpochValidationFailure {
            from_epoch: 1,
            to_epoch: 2,
        },
        RecoveryTrigger::StaleAttestation {
            attestation_age_ticks: 5000,
        },
    ]
}

// ---------------------------------------------------------------------------
// ArtifactType Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_type_display_uniqueness_all_seven() {
    let displays: BTreeSet<String> = all_artifact_types()
        .into_iter()
        .map(|t| t.to_string())
        .collect();
    assert_eq!(
        displays.len(),
        7,
        "all 7 ArtifactType variants must have unique Display"
    );
}

#[test]
fn enrichment_artifact_type_display_gap_fill() {
    assert_eq!(ArtifactType::GapFill.to_string(), "gap_fill");
}

#[test]
fn enrichment_artifact_type_display_state_repair() {
    assert_eq!(ArtifactType::StateRepair.to_string(), "state_repair");
}

#[test]
fn enrichment_artifact_type_display_forced_reconciliation() {
    assert_eq!(
        ArtifactType::ForcedReconciliation.to_string(),
        "forced_reconciliation"
    );
}

#[test]
fn enrichment_artifact_type_display_trust_restoration() {
    assert_eq!(
        ArtifactType::TrustRestoration.to_string(),
        "trust_restoration"
    );
}

#[test]
fn enrichment_artifact_type_display_rejected_epoch_promotion() {
    assert_eq!(
        ArtifactType::RejectedEpochPromotion.to_string(),
        "rejected_epoch_promotion"
    );
}

#[test]
fn enrichment_artifact_type_display_rejected_revocation() {
    assert_eq!(
        ArtifactType::RejectedRevocation.to_string(),
        "rejected_revocation"
    );
}

#[test]
fn enrichment_artifact_type_display_failed_attestation() {
    assert_eq!(
        ArtifactType::FailedAttestation.to_string(),
        "failed_attestation"
    );
}

// ---------------------------------------------------------------------------
// ArtifactType serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_type_serde_roundtrip_all_variants() {
    for at in &all_artifact_types() {
        let json = serde_json::to_string(at).unwrap();
        let restored: ArtifactType = serde_json::from_str(&json).unwrap();
        assert_eq!(*at, restored);
    }
}

// ---------------------------------------------------------------------------
// ArtifactType ordering
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_type_ordering_is_declaration_order() {
    let types = all_artifact_types();
    for i in 0..types.len() - 1 {
        assert!(
            types[i] < types[i + 1],
            "{} should be less than {}",
            types[i],
            types[i + 1]
        );
    }
}

// ---------------------------------------------------------------------------
// RecoveryTrigger Display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_recovery_trigger_display_uniqueness_all_six() {
    let displays: BTreeSet<String> = all_triggers().into_iter().map(|t| t.to_string()).collect();
    assert_eq!(
        displays.len(),
        6,
        "all 6 RecoveryTrigger variants must have unique Display"
    );
}

#[test]
fn enrichment_trigger_reconciliation_failure_display_contains_id() {
    let t = RecoveryTrigger::ReconciliationFailure {
        reconciliation_id: "recon-xyz-99".to_string(),
    };
    let display = t.to_string();
    assert!(display.contains("reconciliation_failure"));
    assert!(display.contains("recon-xyz-99"));
}

#[test]
fn enrichment_trigger_integrity_check_failure_display_contains_check_id() {
    let t = RecoveryTrigger::IntegrityCheckFailure {
        check_id: "chk-42".to_string(),
        details: "this is NOT in display".to_string(),
    };
    let display = t.to_string();
    assert!(display.contains("integrity_check_failure"));
    assert!(display.contains("chk-42"));
    // details field is NOT included in Display
    assert!(!display.contains("this is NOT in display"));
}

#[test]
fn enrichment_trigger_operator_intervention_display_contains_operator() {
    let t = RecoveryTrigger::OperatorIntervention {
        operator: "ops-lead".to_string(),
        reason: "not shown".to_string(),
    };
    let display = t.to_string();
    assert!(display.contains("operator_intervention"));
    assert!(display.contains("ops-lead"));
}

#[test]
fn enrichment_trigger_automatic_fallback_display_contains_fallback_id() {
    let t = RecoveryTrigger::AutomaticFallback {
        fallback_id: "fb-omega-7".to_string(),
    };
    let display = t.to_string();
    assert!(display.contains("automatic_fallback"));
    assert!(display.contains("fb-omega-7"));
}

#[test]
fn enrichment_trigger_epoch_validation_failure_display_contains_epochs() {
    let t = RecoveryTrigger::EpochValidationFailure {
        from_epoch: 10,
        to_epoch: 11,
    };
    let display = t.to_string();
    assert!(display.contains("epoch_validation_failure"));
    assert!(display.contains("10->11"));
}

#[test]
fn enrichment_trigger_stale_attestation_display_contains_age() {
    let t = RecoveryTrigger::StaleAttestation {
        attestation_age_ticks: 99999,
    };
    let display = t.to_string();
    assert!(display.contains("stale_attestation"));
    assert!(display.contains("99999"));
}

// ---------------------------------------------------------------------------
// RecoveryTrigger serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_recovery_trigger_serde_roundtrip_all_variants() {
    for trigger in &all_triggers() {
        let json = serde_json::to_string(trigger).unwrap();
        let restored: RecoveryTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(*trigger, restored);
    }
}

// ---------------------------------------------------------------------------
// ProofElement Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_proof_element_display_uniqueness_all_four() {
    let elements = vec![
        ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(b"r"),
            leaf_count: 1,
            proof_hashes: vec![],
        },
        ProofElement::HashChainVerification {
            start_marker_id: 0,
            end_marker_id: 1,
            chain_hash: ContentHash::compute(b"c"),
            verified: true,
        },
        ProofElement::EvidenceEntryLink {
            evidence_hash: ContentHash::compute(b"e"),
            decision_id: "d".to_string(),
        },
        ProofElement::EpochValidityCheck {
            epoch: test_epoch(),
            is_valid: true,
            reason: "ok".to_string(),
        },
    ];
    let displays: BTreeSet<String> = elements.into_iter().map(|p| p.to_string()).collect();
    assert_eq!(
        displays.len(),
        4,
        "all 4 ProofElement variants must have unique Display"
    );
}

#[test]
fn enrichment_proof_element_mmr_display_shows_leaf_count() {
    let pe = ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"root"),
        leaf_count: 1024,
        proof_hashes: vec![],
    };
    assert!(pe.to_string().contains("mmr_consistency"));
    assert!(pe.to_string().contains("leaves=1024"));
}

#[test]
fn enrichment_proof_element_chain_display_shows_range_and_verified() {
    let pe = ProofElement::HashChainVerification {
        start_marker_id: 5,
        end_marker_id: 15,
        chain_hash: ContentHash::compute(b"c"),
        verified: false,
    };
    let display = pe.to_string();
    assert!(display.contains("chain_verification"));
    assert!(display.contains("5..15"));
    assert!(display.contains("ok=false"));
}

#[test]
fn enrichment_proof_element_evidence_link_display_shows_decision_id() {
    let pe = ProofElement::EvidenceEntryLink {
        evidence_hash: ContentHash::compute(b"ev"),
        decision_id: "decision-777".to_string(),
    };
    assert!(pe.to_string().contains("evidence_link"));
    assert!(pe.to_string().contains("decision-777"));
}

#[test]
fn enrichment_proof_element_epoch_check_display_shows_valid_flag() {
    let pe = ProofElement::EpochValidityCheck {
        epoch: SecurityEpoch::from_raw(3),
        is_valid: true,
        reason: "good".to_string(),
    };
    let display = pe.to_string();
    assert!(display.contains("epoch_check"));
    assert!(display.contains("valid=true"));
}

// ---------------------------------------------------------------------------
// ProofElement serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_proof_element_serde_roundtrip_mmr_consistency() {
    let pe = ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"root"),
        leaf_count: 42,
        proof_hashes: vec![ContentHash::compute(b"a"), ContentHash::compute(b"b")],
    };
    let json = serde_json::to_string(&pe).unwrap();
    let restored: ProofElement = serde_json::from_str(&json).unwrap();
    assert_eq!(pe, restored);
}

#[test]
fn enrichment_proof_element_serde_roundtrip_hash_chain() {
    let pe = ProofElement::HashChainVerification {
        start_marker_id: 100,
        end_marker_id: 200,
        chain_hash: ContentHash::compute(b"chain"),
        verified: true,
    };
    let json = serde_json::to_string(&pe).unwrap();
    let restored: ProofElement = serde_json::from_str(&json).unwrap();
    assert_eq!(pe, restored);
}

#[test]
fn enrichment_proof_element_serde_roundtrip_evidence_link() {
    let pe = ProofElement::EvidenceEntryLink {
        evidence_hash: ContentHash::compute(b"ev-hash"),
        decision_id: "dec-999".to_string(),
    };
    let json = serde_json::to_string(&pe).unwrap();
    let restored: ProofElement = serde_json::from_str(&json).unwrap();
    assert_eq!(pe, restored);
}

#[test]
fn enrichment_proof_element_serde_roundtrip_epoch_validity() {
    let pe = ProofElement::EpochValidityCheck {
        epoch: SecurityEpoch::from_raw(55),
        is_valid: false,
        reason: "quorum not met".to_string(),
    };
    let json = serde_json::to_string(&pe).unwrap();
    let restored: ProofElement = serde_json::from_str(&json).unwrap();
    assert_eq!(pe, restored);
}

// ---------------------------------------------------------------------------
// OperatorAction serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_operator_action_serde_roundtrip() {
    let action = OperatorAction {
        operator: "admin-ops".to_string(),
        action: "force_restore".to_string(),
        authorization_hash: AuthenticityHash::compute_keyed(b"key", b"approve"),
        timestamp_ticks: 42_000,
    };
    let json = serde_json::to_string(&action).unwrap();
    let restored: OperatorAction = serde_json::from_str(&json).unwrap();
    assert_eq!(action, restored);
}

// ---------------------------------------------------------------------------
// RecoveryVerdict Display uniqueness and serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_recovery_verdict_display_uniqueness() {
    let verdicts = vec![
        RecoveryVerdict::Valid,
        RecoveryVerdict::Invalid {
            reasons: vec!["r".to_string()],
        },
    ];
    let displays: BTreeSet<String> = verdicts.into_iter().map(|v| v.to_string()).collect();
    assert_eq!(
        displays.len(),
        2,
        "both RecoveryVerdict variants must have unique Display"
    );
}

#[test]
fn enrichment_recovery_verdict_valid_display() {
    assert_eq!(RecoveryVerdict::Valid.to_string(), "valid");
}

#[test]
fn enrichment_recovery_verdict_invalid_display_joins_reasons() {
    let v = RecoveryVerdict::Invalid {
        reasons: vec!["reason-a".to_string(), "reason-b".to_string()],
    };
    let display = v.to_string();
    assert!(display.starts_with("invalid("));
    assert!(display.contains("reason-a; reason-b"));
}

#[test]
fn enrichment_recovery_verdict_invalid_empty_reasons_display() {
    let v = RecoveryVerdict::Invalid { reasons: vec![] };
    let display = v.to_string();
    assert!(display.contains("invalid"));
    assert!(!v.is_valid());
}

#[test]
fn enrichment_recovery_verdict_is_valid_true() {
    assert!(RecoveryVerdict::Valid.is_valid());
}

#[test]
fn enrichment_recovery_verdict_is_valid_false() {
    let v = RecoveryVerdict::Invalid {
        reasons: vec!["err".to_string()],
    };
    assert!(!v.is_valid());
}

#[test]
fn enrichment_recovery_verdict_serde_roundtrip_valid() {
    let v = RecoveryVerdict::Valid;
    let json = serde_json::to_string(&v).unwrap();
    let restored: RecoveryVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

#[test]
fn enrichment_recovery_verdict_serde_roundtrip_invalid() {
    let v = RecoveryVerdict::Invalid {
        reasons: vec!["a".to_string(), "b".to_string()],
    };
    let json = serde_json::to_string(&v).unwrap();
    let restored: RecoveryVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

// ---------------------------------------------------------------------------
// VerificationError Display uniqueness and serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verification_error_display_uniqueness_all_four() {
    let errors = vec![
        VerificationError::ArtifactIdMismatch {
            expected: ContentHash::compute(b"a"),
            computed: ContentHash::compute(b"b"),
        },
        VerificationError::SignatureInvalid {
            details: "bad".to_string(),
        },
        VerificationError::EmptyProofBundle,
        VerificationError::MissingProofElement {
            element_type: "mmr".to_string(),
        },
    ];
    let displays: BTreeSet<String> = errors.into_iter().map(|e| e.to_string()).collect();
    assert_eq!(
        displays.len(),
        4,
        "all 4 VerificationError variants must have unique Display"
    );
}

#[test]
fn enrichment_verification_error_artifact_id_mismatch_display() {
    let e = VerificationError::ArtifactIdMismatch {
        expected: ContentHash::compute(b"exp"),
        computed: ContentHash::compute(b"comp"),
    };
    let display = e.to_string();
    assert!(display.contains("artifact ID mismatch"));
    assert!(display.contains("expected"));
    assert!(display.contains("computed"));
}

#[test]
fn enrichment_verification_error_signature_invalid_display() {
    let e = VerificationError::SignatureInvalid {
        details: "key mismatch".to_string(),
    };
    assert!(e.to_string().contains("signature invalid"));
    assert!(e.to_string().contains("key mismatch"));
}

#[test]
fn enrichment_verification_error_empty_proof_bundle_display() {
    assert_eq!(
        VerificationError::EmptyProofBundle.to_string(),
        "proof bundle is empty"
    );
}

#[test]
fn enrichment_verification_error_missing_proof_element_display() {
    let e = VerificationError::MissingProofElement {
        element_type: "chain_verify".to_string(),
    };
    assert!(e.to_string().contains("missing proof element"));
    assert!(e.to_string().contains("chain_verify"));
}

#[test]
fn enrichment_verification_error_serde_roundtrip_all_variants() {
    let errors = vec![
        VerificationError::ArtifactIdMismatch {
            expected: ContentHash::compute(b"e"),
            computed: ContentHash::compute(b"c"),
        },
        VerificationError::SignatureInvalid {
            details: "sig fail".to_string(),
        },
        VerificationError::EmptyProofBundle,
        VerificationError::MissingProofElement {
            element_type: "mmr_consistency".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: VerificationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

#[test]
fn enrichment_verification_error_implements_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(VerificationError::EmptyProofBundle);
    assert!(!e.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// RecoveryEvent serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_recovery_event_serde_roundtrip() {
    let event = RecoveryEvent {
        artifact_id: "hex-id-abc".to_string(),
        artifact_type: "gap_fill".to_string(),
        trigger: "reconciliation_failure:r1".to_string(),
        verification_verdict: "valid".to_string(),
        trace_id: "trace-42".to_string(),
        epoch_id: 7,
        event: "artifact_verified".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: RecoveryEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// ---------------------------------------------------------------------------
// RecoveryArtifact serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_recovery_artifact_serde_roundtrip() {
    let artifact = build_valid_artifact();
    let json = serde_json::to_string(&artifact).unwrap();
    let restored: RecoveryArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, restored);
}

#[test]
fn enrichment_recovery_artifact_serde_roundtrip_with_operator_actions() {
    let artifact = ArtifactBuilder::new(
        ArtifactType::TrustRestoration,
        RecoveryTrigger::OperatorIntervention {
            operator: "admin".to_string(),
            reason: "manual fix".to_string(),
        },
        sample_before_state(),
        "t-ops",
        3,
        5000,
        &test_key(),
    )
    .after_state(sample_after_state())
    .proof(ProofElement::EpochValidityCheck {
        epoch: SecurityEpoch::from_raw(3),
        is_valid: true,
        reason: "current".to_string(),
    })
    .operator_action(OperatorAction {
        operator: "admin".to_string(),
        action: "approve_restore".to_string(),
        authorization_hash: AuthenticityHash::compute_keyed(b"admin-key", b"approve"),
        timestamp_ticks: 5000,
    })
    .build();

    let json = serde_json::to_string(&artifact).unwrap();
    let restored: RecoveryArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, restored);
    assert_eq!(restored.operator_actions.len(), 1);
}

// ---------------------------------------------------------------------------
// ArtifactBuilder tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_builder_after_state_defaults_to_before_state() {
    let artifact = ArtifactBuilder::new(
        ArtifactType::GapFill,
        RecoveryTrigger::ReconciliationFailure {
            reconciliation_id: "r-default".to_string(),
        },
        sample_before_state(),
        "t-default",
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
fn enrichment_builder_explicit_after_state_differs_from_before() {
    let artifact = ArtifactBuilder::new(
        ArtifactType::StateRepair,
        RecoveryTrigger::IntegrityCheckFailure {
            check_id: "c-diff".to_string(),
            details: "mismatch".to_string(),
        },
        ContentHash::compute(b"old-state"),
        "t-diff",
        1,
        1000,
        &test_key(),
    )
    .after_state(ContentHash::compute(b"new-state"))
    .proof(ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"r"),
        leaf_count: 1,
        proof_hashes: vec![],
    })
    .build();

    assert_ne!(artifact.before_state, artifact.after_state);
}

#[test]
fn enrichment_builder_multiple_proof_elements_preserved_in_order() {
    let artifact = ArtifactBuilder::new(
        ArtifactType::ForcedReconciliation,
        RecoveryTrigger::AutomaticFallback {
            fallback_id: "fb-order".to_string(),
        },
        sample_before_state(),
        "t-order",
        1,
        1000,
        &test_key(),
    )
    .proof(ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"r1"),
        leaf_count: 10,
        proof_hashes: vec![],
    })
    .proof(ProofElement::HashChainVerification {
        start_marker_id: 0,
        end_marker_id: 5,
        chain_hash: ContentHash::compute(b"chain"),
        verified: true,
    })
    .proof(ProofElement::EvidenceEntryLink {
        evidence_hash: ContentHash::compute(b"ev"),
        decision_id: "dec-1".to_string(),
    })
    .build();

    assert_eq!(artifact.proof_bundle.len(), 3);
    assert!(
        artifact.proof_bundle[0]
            .to_string()
            .contains("mmr_consistency")
    );
    assert!(
        artifact.proof_bundle[1]
            .to_string()
            .contains("chain_verification")
    );
    assert!(
        artifact.proof_bundle[2]
            .to_string()
            .contains("evidence_link")
    );
}

#[test]
fn enrichment_builder_multiple_operator_actions_preserved_in_order() {
    let artifact = ArtifactBuilder::new(
        ArtifactType::TrustRestoration,
        RecoveryTrigger::OperatorIntervention {
            operator: "team-lead".to_string(),
            reason: "escalation".to_string(),
        },
        sample_before_state(),
        "t-multi-ops",
        1,
        1000,
        &test_key(),
    )
    .proof(ProofElement::EpochValidityCheck {
        epoch: test_epoch(),
        is_valid: true,
        reason: "ok".to_string(),
    })
    .operator_action(OperatorAction {
        operator: "first-admin".to_string(),
        action: "initiate".to_string(),
        authorization_hash: AuthenticityHash::compute_keyed(b"k1", b"init"),
        timestamp_ticks: 100,
    })
    .operator_action(OperatorAction {
        operator: "second-admin".to_string(),
        action: "confirm".to_string(),
        authorization_hash: AuthenticityHash::compute_keyed(b"k2", b"confirm"),
        timestamp_ticks: 200,
    })
    .operator_action(OperatorAction {
        operator: "third-admin".to_string(),
        action: "finalize".to_string(),
        authorization_hash: AuthenticityHash::compute_keyed(b"k3", b"finalize"),
        timestamp_ticks: 300,
    })
    .build();

    assert_eq!(artifact.operator_actions.len(), 3);
    assert_eq!(artifact.operator_actions[0].operator, "first-admin");
    assert_eq!(artifact.operator_actions[1].operator, "second-admin");
    assert_eq!(artifact.operator_actions[2].operator, "third-admin");
}

#[test]
fn enrichment_builder_all_artifact_types_produce_valid_artifacts() {
    for (i, at) in all_artifact_types().into_iter().enumerate() {
        let artifact = ArtifactBuilder::new(
            at.clone(),
            RecoveryTrigger::AutomaticFallback {
                fallback_id: format!("fb-{i}"),
            },
            sample_before_state(),
            &format!("t-{i}"),
            i as u64,
            1000,
            &test_key(),
        )
        .proof(ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(b"r"),
            leaf_count: 1,
            proof_hashes: vec![],
        })
        .build();
        assert_eq!(artifact.artifact_type, at);
    }
}

#[test]
fn enrichment_builder_all_trigger_types_produce_valid_artifacts() {
    for (i, trigger) in all_triggers().into_iter().enumerate() {
        let artifact = ArtifactBuilder::new(
            ArtifactType::GapFill,
            trigger,
            sample_before_state(),
            &format!("t-trig-{i}"),
            1,
            1000,
            &test_key(),
        )
        .proof(ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(b"r"),
            leaf_count: 1,
            proof_hashes: vec![],
        })
        .build();
        assert!(!artifact.artifact_id.to_hex().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Deterministic hash behavior
// ---------------------------------------------------------------------------

#[test]
fn enrichment_deterministic_artifact_id_same_inputs() {
    let a1 = build_valid_artifact();
    let a2 = build_valid_artifact();
    assert_eq!(a1.artifact_id, a2.artifact_id);
    assert_eq!(a1.signature, a2.signature);
}

#[test]
fn enrichment_artifact_id_sensitive_to_artifact_type() {
    let a1 = build_artifact_with_type(ArtifactType::GapFill);
    let a2 = build_artifact_with_type(ArtifactType::StateRepair);
    assert_ne!(a1.artifact_id, a2.artifact_id);
}

#[test]
fn enrichment_artifact_id_sensitive_to_trigger() {
    let make = |fb: &str| {
        ArtifactBuilder::new(
            ArtifactType::GapFill,
            RecoveryTrigger::AutomaticFallback {
                fallback_id: fb.to_string(),
            },
            sample_before_state(),
            "t",
            1,
            1000,
            &test_key(),
        )
        .proof(ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(b"r"),
            leaf_count: 1,
            proof_hashes: vec![],
        })
        .build()
    };
    assert_ne!(make("fb-alpha").artifact_id, make("fb-beta").artifact_id);
}

#[test]
fn enrichment_artifact_id_sensitive_to_before_state() {
    let make = |data: &[u8]| {
        ArtifactBuilder::new(
            ArtifactType::GapFill,
            RecoveryTrigger::AutomaticFallback {
                fallback_id: "fb".to_string(),
            },
            ContentHash::compute(data),
            "t",
            1,
            1000,
            &test_key(),
        )
        .proof(ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(b"r"),
            leaf_count: 1,
            proof_hashes: vec![],
        })
        .build()
    };
    assert_ne!(make(b"state-A").artifact_id, make(b"state-B").artifact_id);
}

#[test]
fn enrichment_artifact_id_sensitive_to_epoch_id() {
    let make = |epoch: u64| {
        ArtifactBuilder::new(
            ArtifactType::GapFill,
            RecoveryTrigger::AutomaticFallback {
                fallback_id: "fb".to_string(),
            },
            sample_before_state(),
            "t",
            epoch,
            1000,
            &test_key(),
        )
        .proof(ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(b"r"),
            leaf_count: 1,
            proof_hashes: vec![],
        })
        .build()
    };
    assert_ne!(make(1).artifact_id, make(2).artifact_id);
}

#[test]
fn enrichment_artifact_id_sensitive_to_timestamp() {
    let make = |ts: u64| {
        ArtifactBuilder::new(
            ArtifactType::GapFill,
            RecoveryTrigger::AutomaticFallback {
                fallback_id: "fb".to_string(),
            },
            sample_before_state(),
            "t",
            1,
            ts,
            &test_key(),
        )
        .proof(ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(b"r"),
            leaf_count: 1,
            proof_hashes: vec![],
        })
        .build()
    };
    assert_ne!(make(1000).artifact_id, make(2000).artifact_id);
}

#[test]
fn enrichment_artifact_id_sensitive_to_trace_id() {
    let make = |trace: &str| {
        ArtifactBuilder::new(
            ArtifactType::GapFill,
            RecoveryTrigger::AutomaticFallback {
                fallback_id: "fb".to_string(),
            },
            sample_before_state(),
            trace,
            1,
            1000,
            &test_key(),
        )
        .proof(ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(b"r"),
            leaf_count: 1,
            proof_hashes: vec![],
        })
        .build()
    };
    assert_ne!(
        make("trace-alpha").artifact_id,
        make("trace-beta").artifact_id
    );
}

#[test]
fn enrichment_signature_sensitive_to_signing_key() {
    let make = |key: &[u8]| {
        ArtifactBuilder::new(
            ArtifactType::GapFill,
            RecoveryTrigger::AutomaticFallback {
                fallback_id: "fb".to_string(),
            },
            sample_before_state(),
            "t",
            1,
            1000,
            key,
        )
        .proof(ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(b"r"),
            leaf_count: 1,
            proof_hashes: vec![],
        })
        .build()
    };
    let a1 = make(b"key-A");
    let a2 = make(b"key-B");
    // Same artifact_id (content hash doesn't depend on signing key)
    assert_eq!(a1.artifact_id, a2.artifact_id);
    // Different signatures
    assert_ne!(a1.signature, a2.signature);
}

// ---------------------------------------------------------------------------
// RecoveryArtifactStore tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_store_fresh_is_empty() {
    let store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
    assert!(store.export().is_empty());
    assert!(store.event_counts().is_empty());
}

#[test]
fn enrichment_store_epoch_accessor() {
    let store = RecoveryArtifactStore::new(SecurityEpoch::from_raw(42), &test_key());
    assert_eq!(store.epoch(), SecurityEpoch::from_raw(42));
}

#[test]
fn enrichment_store_record_and_get() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
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
fn enrichment_store_get_missing_returns_none() {
    let store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    assert!(store.get("nonexistent-hex-id").is_none());
}

#[test]
fn enrichment_store_record_multiple_distinct_artifacts() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());

    for i in 0..5u64 {
        let artifact = ArtifactBuilder::new(
            ArtifactType::GapFill,
            RecoveryTrigger::ReconciliationFailure {
                reconciliation_id: format!("r-{i}"),
            },
            sample_before_state(),
            &format!("t-{i}"),
            i,
            1000 + i,
            &test_key(),
        )
        .proof(ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(format!("root-{i}").as_bytes()),
            leaf_count: i,
            proof_hashes: vec![],
        })
        .build();
        store.record(artifact, &format!("t-{i}"));
    }

    assert_eq!(store.len(), 5);
    assert_eq!(store.export().len(), 5);
}

#[test]
fn enrichment_store_record_duplicate_overwrites() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    let artifact = build_valid_artifact();
    store.record(artifact.clone(), "first");
    store.record(artifact, "second");
    assert_eq!(store.len(), 1);
}

#[test]
fn enrichment_store_export_returns_all() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    store.record(build_valid_artifact(), "t1");
    let exported = store.export();
    assert_eq!(exported.len(), 1);

    let json = serde_json::to_string(exported[0]).unwrap();
    let restored: RecoveryArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.artifact_type, ArtifactType::ForcedReconciliation);
}

// ---------------------------------------------------------------------------
// Store verification
// ---------------------------------------------------------------------------

#[test]
fn enrichment_store_verify_valid_artifact_returns_valid() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    let artifact = build_valid_artifact();
    let verdict = store.verify(&artifact, "t-valid").unwrap();
    assert!(verdict.is_valid());
}

#[test]
fn enrichment_store_verify_detects_tampered_artifact_id() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    let mut artifact = build_valid_artifact();
    artifact.artifact_id = ContentHash::compute(b"tampered");

    let result = store.verify(&artifact, "t-tampered");
    assert!(matches!(
        result,
        Err(VerificationError::ArtifactIdMismatch { .. })
    ));
}

#[test]
fn enrichment_store_verify_detects_wrong_signing_key() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), b"wrong-key");
    let artifact = build_valid_artifact();

    let result = store.verify(&artifact, "t-wrong-key");
    assert!(matches!(
        result,
        Err(VerificationError::SignatureInvalid { .. })
    ));
}

#[test]
fn enrichment_store_verify_rejects_empty_proof_bundle() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    let artifact = ArtifactBuilder::new(
        ArtifactType::StateRepair,
        RecoveryTrigger::IntegrityCheckFailure {
            check_id: "c-empty".to_string(),
            details: "no proofs".to_string(),
        },
        sample_before_state(),
        "t-empty-proof",
        1,
        1000,
        &test_key(),
    )
    .build();

    let result = store.verify(&artifact, "t-empty-proof");
    assert!(matches!(result, Err(VerificationError::EmptyProofBundle)));
}

#[test]
fn enrichment_store_verify_failed_chain_returns_invalid_verdict() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    let artifact = ArtifactBuilder::new(
        ArtifactType::StateRepair,
        RecoveryTrigger::IntegrityCheckFailure {
            check_id: "c-chain".to_string(),
            details: "chain fail".to_string(),
        },
        sample_before_state(),
        "t-chain-fail",
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

    let verdict = store.verify(&artifact, "t-chain-fail").unwrap();
    assert!(!verdict.is_valid());
    if let RecoveryVerdict::Invalid { reasons } = &verdict {
        assert!(reasons[0].contains("hash chain"));
    } else {
        panic!("expected Invalid verdict");
    }
}

#[test]
fn enrichment_store_verify_failed_epoch_check_returns_invalid_verdict() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    let artifact = ArtifactBuilder::new(
        ArtifactType::RejectedEpochPromotion,
        RecoveryTrigger::EpochValidationFailure {
            from_epoch: 1,
            to_epoch: 2,
        },
        sample_before_state(),
        "t-epoch-fail",
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

    let verdict = store.verify(&artifact, "t-epoch-fail").unwrap();
    assert!(!verdict.is_valid());
    if let RecoveryVerdict::Invalid { reasons } = &verdict {
        assert!(reasons[0].contains("quorum not met"));
    } else {
        panic!("expected Invalid verdict");
    }
}

#[test]
fn enrichment_store_verify_collects_multiple_failure_reasons() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    let artifact = ArtifactBuilder::new(
        ArtifactType::StateRepair,
        RecoveryTrigger::IntegrityCheckFailure {
            check_id: "c-multi".to_string(),
            details: "multi-fail".to_string(),
        },
        sample_before_state(),
        "t-multi",
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
        reason: "expired".to_string(),
    })
    .proof(ProofElement::HashChainVerification {
        start_marker_id: 5,
        end_marker_id: 10,
        chain_hash: ContentHash::compute(b"chain2"),
        verified: false,
    })
    .build();

    let verdict = store.verify(&artifact, "t-multi").unwrap();
    assert!(!verdict.is_valid());
    if let RecoveryVerdict::Invalid { reasons } = &verdict {
        assert_eq!(reasons.len(), 3);
    } else {
        panic!("expected Invalid verdict");
    }
}

#[test]
fn enrichment_store_verify_mmr_and_evidence_are_informational_only() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    let artifact = ArtifactBuilder::new(
        ArtifactType::GapFill,
        RecoveryTrigger::ReconciliationFailure {
            reconciliation_id: "r-info".to_string(),
        },
        sample_before_state(),
        "t-info",
        1,
        1000,
        &test_key(),
    )
    .proof(ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"root"),
        leaf_count: 100,
        proof_hashes: vec![ContentHash::compute(b"h1")],
    })
    .proof(ProofElement::EvidenceEntryLink {
        evidence_hash: ContentHash::compute(b"ev"),
        decision_id: "d-info".to_string(),
    })
    .build();

    let verdict = store.verify(&artifact, "t-info").unwrap();
    assert!(verdict.is_valid());
}

// ---------------------------------------------------------------------------
// Store events
// ---------------------------------------------------------------------------

#[test]
fn enrichment_store_record_emits_artifact_recorded_event() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    store.record(build_valid_artifact(), "trace-rec");
    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "artifact_recorded");
    assert_eq!(events[0].trace_id, "trace-rec");
    assert!(events[0].verification_verdict.is_empty());
}

#[test]
fn enrichment_store_verify_emits_artifact_verified_event_with_verdict() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    let artifact = build_valid_artifact();
    store.verify(&artifact, "trace-ver").unwrap();
    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "artifact_verified");
    assert_eq!(events[0].trace_id, "trace-ver");
    assert_eq!(events[0].verification_verdict, "valid");
}

#[test]
fn enrichment_store_drain_events_empties_buffer() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    store.record(build_valid_artifact(), "t1");
    let events1 = store.drain_events();
    assert_eq!(events1.len(), 1);
    let events2 = store.drain_events();
    assert!(events2.is_empty());
}

#[test]
fn enrichment_store_event_counts_track_record_and_verify() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    let a1 = build_valid_artifact();
    store.record(a1.clone(), "t1");
    store.record(build_valid_artifact(), "t2");
    store.verify(&a1, "t1").unwrap();

    let counts = store.event_counts();
    assert_eq!(counts.get("artifact_recorded"), Some(&2));
    assert_eq!(counts.get("artifact_verified"), Some(&1));
}

#[test]
fn enrichment_store_event_counts_empty_on_fresh() {
    let store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    assert!(store.event_counts().is_empty());
}

#[test]
fn enrichment_store_verify_event_has_all_fields_populated() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    let artifact = build_valid_artifact();
    store.verify(&artifact, "full-trace").unwrap();
    let events = store.drain_events();
    let ev = &events[0];
    assert!(!ev.artifact_id.is_empty());
    assert!(!ev.artifact_type.is_empty());
    assert!(!ev.trigger.is_empty());
    assert!(!ev.verification_verdict.is_empty());
    assert_eq!(ev.trace_id, "full-trace");
    assert_eq!(ev.epoch_id, 1);
    assert_eq!(ev.event, "artifact_verified");
}

// ---------------------------------------------------------------------------
// Clone and equality
// ---------------------------------------------------------------------------

#[test]
fn enrichment_recovery_artifact_clone_preserves_all_fields() {
    let artifact = build_valid_artifact();
    let cloned = artifact.clone();
    assert_eq!(artifact, cloned);
    assert_eq!(artifact.artifact_id, cloned.artifact_id);
    assert_eq!(artifact.signature, cloned.signature);
    assert_eq!(artifact.proof_bundle.len(), cloned.proof_bundle.len());
    assert_eq!(
        artifact.operator_actions.len(),
        cloned.operator_actions.len()
    );
    assert_eq!(artifact.trace_id, cloned.trace_id);
    assert_eq!(artifact.epoch_id, cloned.epoch_id);
    assert_eq!(artifact.timestamp_ticks, cloned.timestamp_ticks);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_proof_element_mmr_zero_leaves() {
    let pe = ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"empty"),
        leaf_count: 0,
        proof_hashes: vec![],
    };
    assert!(pe.to_string().contains("leaves=0"));
}

#[test]
fn enrichment_proof_element_mmr_max_leaves() {
    let pe = ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"max"),
        leaf_count: u64::MAX,
        proof_hashes: vec![],
    };
    assert!(pe.to_string().contains(&u64::MAX.to_string()));
}

#[test]
fn enrichment_proof_element_chain_max_marker_ids() {
    let pe = ProofElement::HashChainVerification {
        start_marker_id: u64::MAX - 1,
        end_marker_id: u64::MAX,
        chain_hash: ContentHash::compute(b"c"),
        verified: false,
    };
    let display = pe.to_string();
    assert!(display.contains("ok=false"));
    assert!(display.contains(&(u64::MAX - 1).to_string()));
    assert!(display.contains(&u64::MAX.to_string()));
}

#[test]
fn enrichment_trigger_epoch_validation_failure_zero_to_zero() {
    let t = RecoveryTrigger::EpochValidationFailure {
        from_epoch: 0,
        to_epoch: 0,
    };
    assert!(t.to_string().contains("0->0"));
}

#[test]
fn enrichment_trigger_stale_attestation_zero_age() {
    let t = RecoveryTrigger::StaleAttestation {
        attestation_age_ticks: 0,
    };
    assert!(t.to_string().contains("age=0"));
}

#[test]
fn enrichment_operator_action_empty_strings() {
    let action = OperatorAction {
        operator: String::new(),
        action: String::new(),
        authorization_hash: AuthenticityHash::compute_keyed(b"k", b"v"),
        timestamp_ticks: 0,
    };
    let json = serde_json::to_string(&action).unwrap();
    let restored: OperatorAction = serde_json::from_str(&json).unwrap();
    assert_eq!(action, restored);
    assert!(restored.operator.is_empty());
}

#[test]
fn enrichment_recovery_event_empty_strings() {
    let event = RecoveryEvent {
        artifact_id: String::new(),
        artifact_type: String::new(),
        trigger: String::new(),
        verification_verdict: String::new(),
        trace_id: String::new(),
        epoch_id: 0,
        event: String::new(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: RecoveryEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn enrichment_builder_empty_trace_id_and_zero_epoch() {
    let artifact = ArtifactBuilder::new(
        ArtifactType::GapFill,
        RecoveryTrigger::ReconciliationFailure {
            reconciliation_id: "r-zero".to_string(),
        },
        sample_before_state(),
        "",
        0,
        0,
        &test_key(),
    )
    .proof(ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"r"),
        leaf_count: 1,
        proof_hashes: vec![],
    })
    .build();

    assert!(artifact.trace_id.is_empty());
    assert_eq!(artifact.epoch_id, 0);
    assert_eq!(artifact.timestamp_ticks, 0);
}

#[test]
fn enrichment_builder_empty_signing_key() {
    let artifact = ArtifactBuilder::new(
        ArtifactType::GapFill,
        RecoveryTrigger::ReconciliationFailure {
            reconciliation_id: "r-empty-key".to_string(),
        },
        sample_before_state(),
        "t-ek",
        1,
        1000,
        b"",
    )
    .proof(ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"r"),
        leaf_count: 1,
        proof_hashes: vec![],
    })
    .build();

    // Empty key still produces a signature
    assert!(!artifact.signature.to_hex().is_empty());
}

#[test]
fn enrichment_mmr_consistency_many_proof_hashes() {
    let proof_hashes: Vec<ContentHash> = (0..100)
        .map(|i| ContentHash::compute(format!("hash-{i}").as_bytes()))
        .collect();
    let pe = ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"big-root"),
        leaf_count: 100,
        proof_hashes: proof_hashes.clone(),
    };
    let json = serde_json::to_string(&pe).unwrap();
    let restored: ProofElement = serde_json::from_str(&json).unwrap();
    assert_eq!(pe, restored);
    if let ProofElement::MmrConsistency {
        proof_hashes: restored_hashes,
        ..
    } = &restored
    {
        assert_eq!(restored_hashes.len(), 100);
    }
}

#[test]
fn enrichment_store_record_then_verify_round_trip() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    let artifact = build_valid_artifact();
    let hex_id = artifact.artifact_id.to_hex();

    store.record(artifact, "t-round");
    let retrieved = store.get(&hex_id).unwrap().clone();
    let verdict = store.verify(&retrieved, "t-round-verify").unwrap();
    assert!(verdict.is_valid());
}

#[test]
fn enrichment_store_verify_invalid_then_event_has_invalid_verdict() {
    let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
    let artifact = ArtifactBuilder::new(
        ArtifactType::RejectedRevocation,
        RecoveryTrigger::StaleAttestation {
            attestation_age_ticks: 100_000,
        },
        sample_before_state(),
        "t-inv-ev",
        1,
        1000,
        &test_key(),
    )
    .proof(ProofElement::HashChainVerification {
        start_marker_id: 0,
        end_marker_id: 10,
        chain_hash: ContentHash::compute(b"c"),
        verified: false,
    })
    .build();

    let verdict = store.verify(&artifact, "t-inv-ev").unwrap();
    assert!(!verdict.is_valid());

    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert!(events[0].verification_verdict.contains("invalid"));
}

#[test]
fn enrichment_artifact_type_clone_and_eq() {
    for at in &all_artifact_types() {
        let cloned = at.clone();
        assert_eq!(*at, cloned);
    }
}

#[test]
fn enrichment_recovery_trigger_clone_and_eq() {
    for trigger in &all_triggers() {
        let cloned = trigger.clone();
        assert_eq!(*trigger, cloned);
    }
}

#[test]
fn enrichment_proof_element_clone_and_eq() {
    let pe = ProofElement::MmrConsistency {
        root_hash: ContentHash::compute(b"root"),
        leaf_count: 42,
        proof_hashes: vec![ContentHash::compute(b"a")],
    };
    let cloned = pe.clone();
    assert_eq!(pe, cloned);
}

#[test]
fn enrichment_verification_error_clone_and_eq() {
    let err = VerificationError::SignatureInvalid {
        details: "mismatch".to_string(),
    };
    let cloned = err.clone();
    assert_eq!(err, cloned);
}
