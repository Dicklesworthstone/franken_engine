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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::capability_witness::{
    CapabilityEscrowReceiptRecord, CapabilityWitness, ConfidenceInterval, ConsistencyProofLink,
    CustomTheoremExtension, DenialRecord, LifecycleState, PromotionTheoremInput,
    PromotionTheoremKind, PromotionTheoremReport, ProofKind, ProofObligation, PublicationEntryKind,
    RollbackToken, SourceCapabilitySet, WitnessBuilder, WitnessError, WitnessIndexError,
    WitnessIndexQuery, WitnessIndexStore, WitnessPublicationConfig, WitnessPublicationError,
    WitnessPublicationPipeline, WitnessPublicationQuery, WitnessReplayJoinQuery,
    WitnessSchemaVersion, WitnessStore, WitnessTreeHead, WitnessValidator,
};
use frankenengine_engine::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::mmr_proof::{MmrProof, ProofType};
use frankenengine_engine::policy_theorem_compiler::Capability;
use frankenengine_engine::portfolio_governor::governance_audit_ledger::GovernanceLedgerConfig;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::storage_adapter::{
    EventContext, InMemoryStorageAdapter, StorageError, StoreKind,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn test_signing_key() -> SigningKey {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(13);
    }
    SigningKey::from_bytes(key)
}

fn test_extension_id() -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::Attestation,
        "test-ext",
        &SchemaId::from_definition(b"TestExtension.v1"),
        b"ext-001",
    )
    .unwrap()
}

fn test_extension_id_seeded(seed: u64) -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::Attestation,
        "test-ext-seeded",
        &SchemaId::from_definition(b"TestExtension.v1"),
        &seed.to_be_bytes(),
    )
    .unwrap()
}

fn test_policy_id() -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::PolicyObject,
        "test-policy",
        &SchemaId::from_definition(b"TestPolicy.v1"),
        b"policy-001",
    )
    .unwrap()
}

fn test_proof_artifact_id() -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::EvidenceRecord,
        "test-proof",
        &SchemaId::from_definition(b"TestProof.v1"),
        b"proof-001",
    )
    .unwrap()
}

fn make_proof(cap: &Capability) -> ProofObligation {
    ProofObligation {
        capability: cap.clone(),
        kind: ProofKind::DynamicAblation,
        proof_artifact_id: test_proof_artifact_id(),
        justification: format!("Ablation test: removing {} breaks behavior", cap),
        artifact_hash: ContentHash::compute(format!("proof-for-{}", cap).as_bytes()),
    }
}

fn promotion_theorem_input_for(witness: &CapabilityWitness) -> PromotionTheoremInput {
    PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "ablation-evidence".to_string(),
            capabilities: witness.required_capabilities.clone(),
        }],
        manifest_capabilities: witness.required_capabilities.clone(),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    }
}

fn apply_passing_promotion_theorems(witness: &mut CapabilityWitness) {
    let report = witness
        .evaluate_promotion_theorems(&promotion_theorem_input_for(witness))
        .expect("theorem check report");
    assert!(report.all_passed, "expected passing theorem report");
    witness.apply_promotion_theorem_report(&report);
    rebind_witness(witness, &test_signing_key());
}

fn rebind_witness(witness: &mut CapabilityWitness, signing_key: &SigningKey) {
    use frankenengine_engine::signature_preimage::sign_preimage;
    let unsigned = witness.synthesis_unsigned_bytes();
    witness.content_hash = ContentHash::compute(&unsigned);
    let mut canonical = Vec::new();
    canonical.extend_from_slice(witness.extension_id.as_bytes());
    canonical.extend_from_slice(witness.policy_id.as_bytes());
    canonical.extend_from_slice(&witness.epoch.as_u64().to_be_bytes());
    canonical.extend_from_slice(&witness.timestamp_ns.to_be_bytes());
    canonical.extend_from_slice(witness.content_hash.as_bytes());
    witness.witness_id = engine_object_id::derive_id(
        ObjectDomain::Attestation,
        "capability-witness",
        &SchemaId::from_definition(b"CapabilityWitness.v1"),
        &canonical,
    )
    .expect("derive witness id after mutation");
    let signature = sign_preimage(signing_key, &unsigned).expect("sign witness after mutation");
    witness.synthesizer_signature = signature.to_bytes().to_vec();
}

fn build_test_witness() -> CapabilityWitness {
    let cap_read = Capability::new("read-data");
    let cap_write = Capability::new("write-data");
    let cap_admin = Capability::new("admin-access");
    let mut witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(100),
        5000,
        test_signing_key(),
    )
    .require(cap_read.clone())
    .require(cap_write.clone())
    .deny(cap_admin, "Extension does not require admin access")
    .proof(make_proof(&cap_read))
    .proof(make_proof(&cap_write))
    .confidence(ConfidenceInterval::from_trials(200, 195))
    .replay_seed(42)
    .transcript_hash(ContentHash::compute(b"synthesis-transcript"))
    .meta("synthesizer", "plas-v1")
    .build()
    .unwrap();
    apply_passing_promotion_theorems(&mut witness);
    witness
}

fn build_promoted_witness(seed: u64) -> CapabilityWitness {
    let cap_name = format!("read-{seed}");
    let cap = Capability::new(&cap_name);
    let mut witness = WitnessBuilder::new(
        test_extension_id_seeded(seed),
        test_policy_id(),
        SecurityEpoch::from_raw(10 + seed),
        10_000 + seed,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .confidence(ConfidenceInterval::from_trials(120, 118))
    .replay_seed(seed)
    .transcript_hash(ContentHash::compute(
        format!("transcript-{seed}").as_bytes(),
    ))
    .build()
    .unwrap();
    apply_passing_promotion_theorems(&mut witness);
    witness.transition_to(LifecycleState::Validated).unwrap();
    witness.transition_to(LifecycleState::Promoted).unwrap();
    witness
}

fn test_event_context() -> EventContext {
    EventContext {
        trace_id: "trace-test".to_string(),
        decision_id: "decision-test".to_string(),
        policy_id: "policy-test".to_string(),
    }
}

// ===========================================================================
// Enum serde roundtrips
// ===========================================================================

#[test]
fn lifecycle_state_serde_roundtrip_all_variants() {
    let variants = [
        LifecycleState::Draft,
        LifecycleState::Validated,
        LifecycleState::Promoted,
        LifecycleState::Active,
        LifecycleState::Superseded,
        LifecycleState::Revoked,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: LifecycleState = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn proof_kind_serde_roundtrip_all_variants() {
    let variants = [
        ProofKind::StaticAnalysis,
        ProofKind::DynamicAblation,
        ProofKind::PolicyTheoremCheck,
        ProofKind::OperatorAttestation,
        ProofKind::InheritedFromPredecessor,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: ProofKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn promotion_theorem_kind_serde_roundtrip_all_variants() {
    let variants = vec![
        PromotionTheoremKind::MergeLegality,
        PromotionTheoremKind::AttenuationLegality,
        PromotionTheoremKind::NonInterference,
        PromotionTheoremKind::Custom("my-theorem".to_string()),
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: PromotionTheoremKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn publication_entry_kind_serde_roundtrip_all_variants() {
    let variants = [PublicationEntryKind::Publish, PublicationEntryKind::Revoke];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: PublicationEntryKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn witness_error_serde_roundtrip_all_variants() {
    let variants: Vec<WitnessError> = vec![
        WitnessError::EmptyRequiredSet,
        WitnessError::MissingProofObligation {
            capability: "cap".to_string(),
        },
        WitnessError::InvalidConfidence {
            reason: "low".to_string(),
        },
        WitnessError::InvalidTransition {
            from: LifecycleState::Draft,
            to: LifecycleState::Active,
        },
        WitnessError::IncompatibleSchema {
            witness: WitnessSchemaVersion { major: 2, minor: 0 },
            reader: WitnessSchemaVersion::CURRENT,
        },
        WitnessError::SignatureInvalid {
            detail: "bad".to_string(),
        },
        WitnessError::IntegrityFailure {
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        },
        WitnessError::IdDerivation("id-err".to_string()),
        WitnessError::InvalidRollbackToken {
            reason: "unknown".to_string(),
        },
        WitnessError::EpochMismatch {
            witness_epoch: 1,
            current_epoch: 2,
        },
        WitnessError::MissingPromotionTheoremProofs {
            missing_checks: vec!["merge".to_string()],
        },
        WitnessError::PromotionTheoremFailed {
            failed_checks: vec!["attenuation".to_string()],
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: WitnessError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn witness_publication_error_serde_roundtrip_selected() {
    let variants: Vec<WitnessPublicationError> = vec![
        WitnessPublicationError::InvalidConfig {
            reason: "bad".to_string(),
        },
        WitnessPublicationError::WitnessNotPromoted {
            state: LifecycleState::Draft,
        },
        WitnessPublicationError::EmptyRevocationReason,
        WitnessPublicationError::IdDerivation("err".to_string()),
        WitnessPublicationError::LogEntryHashMismatch,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: WitnessPublicationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn witness_index_error_serde_roundtrip_selected() {
    let variants: Vec<WitnessIndexError> = vec![
        WitnessIndexError::Serialization {
            operation: "write".to_string(),
            detail: "fail".to_string(),
        },
        WitnessIndexError::CorruptRecord {
            key: "k1".to_string(),
            detail: "bad".to_string(),
        },
        WitnessIndexError::InvalidInput {
            detail: "empty".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: WitnessIndexError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// Display uniqueness
// ===========================================================================

#[test]
fn lifecycle_state_display_values_all_unique() {
    let states = [
        LifecycleState::Draft,
        LifecycleState::Validated,
        LifecycleState::Promoted,
        LifecycleState::Active,
        LifecycleState::Superseded,
        LifecycleState::Revoked,
    ];
    let names: BTreeSet<String> = states.iter().map(|s| s.to_string()).collect();
    assert_eq!(names.len(), states.len());
}

#[test]
fn proof_kind_display_values_all_unique() {
    let kinds = [
        ProofKind::StaticAnalysis,
        ProofKind::DynamicAblation,
        ProofKind::PolicyTheoremCheck,
        ProofKind::OperatorAttestation,
        ProofKind::InheritedFromPredecessor,
    ];
    let names: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(names.len(), kinds.len());
}

#[test]
fn witness_error_display_values_all_unique() {
    let errors: Vec<WitnessError> = vec![
        WitnessError::EmptyRequiredSet,
        WitnessError::MissingProofObligation {
            capability: "x".to_string(),
        },
        WitnessError::InvalidConfidence {
            reason: "y".to_string(),
        },
        WitnessError::InvalidTransition {
            from: LifecycleState::Draft,
            to: LifecycleState::Active,
        },
        WitnessError::IncompatibleSchema {
            witness: WitnessSchemaVersion::CURRENT,
            reader: WitnessSchemaVersion { major: 2, minor: 0 },
        },
        WitnessError::SignatureInvalid {
            detail: "z".to_string(),
        },
        WitnessError::IntegrityFailure {
            expected: "a".to_string(),
            actual: "b".to_string(),
        },
        WitnessError::IdDerivation("c".to_string()),
        WitnessError::InvalidRollbackToken {
            reason: "d".to_string(),
        },
        WitnessError::EpochMismatch {
            witness_epoch: 1,
            current_epoch: 2,
        },
        WitnessError::MissingPromotionTheoremProofs {
            missing_checks: vec!["e".to_string()],
        },
        WitnessError::PromotionTheoremFailed {
            failed_checks: vec!["f".to_string()],
        },
    ];
    let names: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(names.len(), errors.len());
}

// ===========================================================================
// WitnessSchemaVersion
// ===========================================================================

#[test]
fn schema_version_current_is_1_0() {
    let v = WitnessSchemaVersion::CURRENT;
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 0);
    assert_eq!(v.to_string(), "1.0");
}

#[test]
fn schema_version_compatibility_same_major_higher_minor() {
    let reader = WitnessSchemaVersion { major: 1, minor: 2 };
    let witness = WitnessSchemaVersion { major: 1, minor: 1 };
    assert!(reader.is_compatible_with(&witness));
    assert!(!witness.is_compatible_with(&reader));
}

#[test]
fn schema_version_incompatible_across_major() {
    let reader = WitnessSchemaVersion { major: 2, minor: 0 };
    let witness = WitnessSchemaVersion { major: 1, minor: 0 };
    assert!(!reader.is_compatible_with(&witness));
}

#[test]
fn schema_version_serde_roundtrip() {
    let v = WitnessSchemaVersion { major: 3, minor: 7 };
    let json = serde_json::to_string(&v).unwrap();
    let back: WitnessSchemaVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ===========================================================================
// LifecycleState
// ===========================================================================

#[test]
fn lifecycle_terminal_and_active_flags() {
    assert!(!LifecycleState::Draft.is_terminal());
    assert!(!LifecycleState::Draft.is_active());
    assert!(LifecycleState::Active.is_active());
    assert!(!LifecycleState::Active.is_terminal());
    assert!(LifecycleState::Superseded.is_terminal());
    assert!(LifecycleState::Revoked.is_terminal());
}

#[test]
fn lifecycle_valid_transition_counts() {
    assert_eq!(LifecycleState::Draft.valid_transitions().len(), 1);
    assert_eq!(LifecycleState::Active.valid_transitions().len(), 2);
    assert_eq!(LifecycleState::Superseded.valid_transitions().len(), 0);
}

#[test]
fn lifecycle_ordering_matches_progression() {
    assert!(LifecycleState::Draft < LifecycleState::Validated);
    assert!(LifecycleState::Validated < LifecycleState::Promoted);
    assert!(LifecycleState::Promoted < LifecycleState::Active);
    assert!(LifecycleState::Active < LifecycleState::Superseded);
    assert!(LifecycleState::Superseded < LifecycleState::Revoked);
}

// ===========================================================================
// ConfidenceInterval
// ===========================================================================

#[test]
fn confidence_zero_trials_returns_all_zeros() {
    let ci = ConfidenceInterval::from_trials(0, 0);
    assert_eq!(ci.lower_millionths, 0);
    assert_eq!(ci.upper_millionths, 0);
    assert_eq!(ci.point_estimate_millionths(), 0);
}

#[test]
fn confidence_perfect_trials_high_lower_bound() {
    let ci = ConfidenceInterval::from_trials(100, 100);
    assert!(ci.lower_millionths > 950_000);
    assert!(ci.upper_millionths >= ci.lower_millionths);
    assert_eq!(ci.point_estimate_millionths(), 1_000_000);
}

#[test]
fn confidence_mixed_trials_reasonable_bounds() {
    let ci = ConfidenceInterval::from_trials(100, 95);
    assert!(ci.lower_millionths > 0);
    assert!(ci.upper_millionths <= 1_000_000);
    assert!(ci.lower_millionths < ci.upper_millionths);
    assert_eq!(ci.point_estimate_millionths(), 950_000);
}

#[test]
fn confidence_meets_threshold_boundary() {
    let ci = ConfidenceInterval {
        lower_millionths: 900_000,
        upper_millionths: 950_000,
        n_trials: 100,
        n_successes: 95,
    };
    assert!(ci.meets_threshold(900_000));
    assert!(!ci.meets_threshold(900_001));
}

#[test]
fn confidence_serde_roundtrip() {
    let ci = ConfidenceInterval::from_trials(50, 48);
    let json = serde_json::to_string(&ci).unwrap();
    let back: ConfidenceInterval = serde_json::from_str(&json).unwrap();
    assert_eq!(ci, back);
}

// ===========================================================================
// WitnessBuilder and CapabilityWitness construction
// ===========================================================================

#[test]
fn builder_minimal_witness_starts_as_draft() {
    let cap = Capability::new("read");
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .build()
    .unwrap();
    assert_eq!(witness.lifecycle_state, LifecycleState::Draft);
    assert_eq!(witness.required_capabilities.len(), 1);
    assert_eq!(witness.schema_version, WitnessSchemaVersion::CURRENT);
    assert!(!witness.synthesizer_signature.is_empty());
}

#[test]
fn builder_empty_required_set_fails() {
    let err = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .build()
    .unwrap_err();
    assert!(matches!(err, WitnessError::EmptyRequiredSet));
}

#[test]
fn builder_full_witness_with_denials_and_metadata() {
    let witness = build_test_witness();
    assert_eq!(witness.required_capabilities.len(), 2);
    assert_eq!(witness.denied_capabilities.len(), 1);
    assert!(witness.proof_obligations.len() >= 2);
    assert_eq!(witness.denial_records.len(), 1);
    assert!(witness.confidence.n_trials > 0);
    assert_eq!(witness.replay_seed, 42);
    assert_eq!(
        witness.metadata.get("synthesizer"),
        Some(&"plas-v1".to_string())
    );
}

#[test]
fn builder_deterministic_produces_same_id_and_hash() {
    let w1 = build_test_witness();
    let w2 = build_test_witness();
    assert_eq!(w1.witness_id, w2.witness_id);
    assert_eq!(w1.content_hash, w2.content_hash);
}

#[test]
fn builder_require_all_batch() {
    let caps = vec![
        Capability::new("a"),
        Capability::new("b"),
        Capability::new("c"),
    ];
    let proofs: Vec<_> = caps.iter().map(make_proof).collect();
    let mut builder = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require_all(caps.clone());
    for p in proofs {
        builder = builder.proof(p);
    }
    let witness = builder.build().unwrap();
    assert_eq!(witness.required_capabilities.len(), 3);
}

#[test]
fn builder_with_rollback_token() {
    let cap = Capability::new("read");
    let token = RollbackToken {
        previous_witness_hash: ContentHash::compute(b"prev"),
        previous_witness_id: None,
        created_epoch: SecurityEpoch::from_raw(99),
        sequence: 7,
    };
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(100),
        5000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .rollback(token)
    .build()
    .unwrap();
    assert_eq!(witness.rollback_token.as_ref().unwrap().sequence, 7);
}

// ===========================================================================
// Integrity and signature verification
// ===========================================================================

#[test]
fn verify_integrity_passes_for_valid_witness() {
    let witness = build_test_witness();
    assert!(witness.verify_integrity().is_ok());
}

#[test]
fn verify_integrity_detects_replay_seed_tampering() {
    let mut witness = build_test_witness();
    witness.replay_seed = 999;
    let err = witness.verify_integrity().unwrap_err();
    assert!(matches!(err, WitnessError::IntegrityFailure { .. }));
}

#[test]
fn verify_signature_passes_with_correct_key() {
    let witness = build_test_witness();
    let vk = test_signing_key().verification_key();
    assert!(witness.verify_synthesizer_signature(&vk).is_ok());
}

#[test]
fn verify_signature_fails_with_wrong_key() {
    let witness = build_test_witness();
    let wrong_key = SigningKey::from_bytes([99u8; 32]).verification_key();
    let err = witness
        .verify_synthesizer_signature(&wrong_key)
        .unwrap_err();
    assert!(matches!(err, WitnessError::SignatureInvalid { .. }));
}

#[test]
fn verify_proof_coverage_detects_missing_obligation() {
    let cap_a = Capability::new("a");
    let cap_b = Capability::new("b");
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap_a.clone())
    .require(cap_b)
    .proof(make_proof(&cap_a))
    .build()
    .unwrap();
    let err = witness.verify_proof_coverage().unwrap_err();
    assert!(matches!(err, WitnessError::MissingProofObligation { .. }));
}

// ===========================================================================
// Full lifecycle transitions
// ===========================================================================

#[test]
fn full_lifecycle_draft_to_superseded() {
    let mut witness = build_test_witness();
    assert_eq!(witness.lifecycle_state, LifecycleState::Draft);
    witness.transition_to(LifecycleState::Validated).unwrap();
    witness.transition_to(LifecycleState::Promoted).unwrap();
    witness.transition_to(LifecycleState::Active).unwrap();
    witness.transition_to(LifecycleState::Superseded).unwrap();
    assert!(witness.lifecycle_state.is_terminal());
}

#[test]
fn full_lifecycle_draft_to_revoked() {
    let mut witness = build_test_witness();
    witness.transition_to(LifecycleState::Validated).unwrap();
    witness.transition_to(LifecycleState::Promoted).unwrap();
    witness.transition_to(LifecycleState::Active).unwrap();
    witness.transition_to(LifecycleState::Revoked).unwrap();
    assert!(witness.lifecycle_state.is_terminal());
}

#[test]
fn invalid_transition_draft_to_active_fails() {
    let mut witness = build_test_witness();
    let err = witness.transition_to(LifecycleState::Active).unwrap_err();
    assert!(matches!(err, WitnessError::InvalidTransition { .. }));
}

#[test]
fn promotion_requires_theorem_proofs_first() {
    let cap = Capability::new("read");
    let mut witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .build()
    .unwrap();
    witness.transition_to(LifecycleState::Validated).unwrap();
    let err = witness.transition_to(LifecycleState::Promoted).unwrap_err();
    assert!(matches!(
        err,
        WitnessError::MissingPromotionTheoremProofs { .. }
    ));
}

// ===========================================================================
// Promotion theorem evaluation
// ===========================================================================

#[test]
fn theorem_all_pass_enables_promotion() {
    let cap = Capability::new("read");
    let mut witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .build()
    .unwrap();
    let report = witness
        .evaluate_promotion_theorems(&promotion_theorem_input_for(&witness))
        .unwrap();
    assert!(report.all_passed);
    assert_eq!(report.results.len(), 3);
    witness.apply_promotion_theorem_report(&report);
    witness.transition_to(LifecycleState::Validated).unwrap();
    witness.transition_to(LifecycleState::Promoted).unwrap();
    assert_eq!(witness.lifecycle_state, LifecycleState::Promoted);
}

#[test]
fn theorem_merge_legality_fails_for_unjustified_capability() {
    let cap_r = Capability::new("read");
    let cap_w = Capability::new("write");
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap_r.clone())
    .require(cap_w.clone())
    .proof(make_proof(&cap_r))
    .proof(make_proof(&cap_w))
    .build()
    .unwrap();
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "dynamic-ablation".to_string(),
            capabilities: BTreeSet::from([cap_r]),
        }],
        manifest_capabilities: BTreeSet::from([Capability::new("read"), cap_w]),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    };
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    assert!(!report.all_passed);
    let merge = report
        .results
        .iter()
        .find(|r| r.theorem == PromotionTheoremKind::MergeLegality)
        .unwrap();
    assert!(!merge.passed);
    assert!(merge.counterexample.is_some());
}

#[test]
fn theorem_non_interference_detects_transitive_denied_deps() {
    let cap_r = Capability::new("read");
    let cap_hop = Capability::new("internal-hop");
    let cap_denied = Capability::new("denied-net");
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap_r.clone())
    .deny(cap_denied.clone(), "forbidden")
    .proof(make_proof(&cap_r))
    .build()
    .unwrap();
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "static-analysis".to_string(),
            capabilities: BTreeSet::from([cap_r.clone()]),
        }],
        manifest_capabilities: BTreeSet::from([cap_r.clone()]),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::from([
            (cap_r, BTreeSet::from([cap_hop.clone()])),
            (cap_hop, BTreeSet::from([cap_denied])),
        ]),
        custom_extensions: Vec::new(),
    };
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    let ni = report
        .results
        .iter()
        .find(|r| r.theorem == PromotionTheoremKind::NonInterference)
        .unwrap();
    assert!(!ni.passed);
}

#[test]
fn theorem_custom_extension_pass_and_fail() {
    let cap_r = Capability::new("read");
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap_r.clone())
    .proof(make_proof(&cap_r))
    .build()
    .unwrap();
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "src".to_string(),
            capabilities: BTreeSet::from([cap_r.clone()]),
        }],
        manifest_capabilities: BTreeSet::from([cap_r]),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: vec![
            CustomTheoremExtension {
                name: "ok-check".to_string(),
                required_capabilities: BTreeSet::new(),
                forbidden_capabilities: BTreeSet::from([Capability::new("network")]),
            },
            CustomTheoremExtension {
                name: "fail-check".to_string(),
                required_capabilities: BTreeSet::from([Capability::new("missing-cap")]),
                forbidden_capabilities: BTreeSet::new(),
            },
        ],
    };
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    assert!(!report.all_passed);
    let ok = report
        .results
        .iter()
        .find(|r| r.theorem == PromotionTheoremKind::Custom("ok-check".to_string()))
        .unwrap();
    assert!(ok.passed);
    let fail = report
        .results
        .iter()
        .find(|r| r.theorem == PromotionTheoremKind::Custom("fail-check".to_string()))
        .unwrap();
    assert!(!fail.passed);
}

#[test]
fn theorem_structured_events_count_matches_results_plus_gate() {
    let cap = Capability::new("read");
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .build()
    .unwrap();
    let report = witness
        .evaluate_promotion_theorems(&promotion_theorem_input_for(&witness))
        .unwrap();
    let events = report.structured_events("trace", "decision", "policy");
    assert_eq!(events.len(), report.results.len() + 1);
    assert_eq!(events.last().unwrap().event, "promotion_theorem_gate");
}

#[test]
fn apply_failing_report_does_not_add_theorem_proofs() {
    let cap_r = Capability::new("read");
    let cap_w = Capability::new("write");
    let mut witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap_r.clone())
    .require(cap_w.clone())
    .proof(make_proof(&cap_r))
    .proof(make_proof(&cap_w))
    .build()
    .unwrap();
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "partial".to_string(),
            capabilities: BTreeSet::from([cap_r]),
        }],
        manifest_capabilities: BTreeSet::from([Capability::new("read"), cap_w]),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    };
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    assert!(!report.all_passed);
    let before = witness
        .proof_obligations
        .iter()
        .filter(|p| p.kind == ProofKind::PolicyTheoremCheck)
        .count();
    witness.apply_promotion_theorem_report(&report);
    let after = witness
        .proof_obligations
        .iter()
        .filter(|p| p.kind == ProofKind::PolicyTheoremCheck)
        .count();
    assert_eq!(before, after);
    assert_eq!(
        witness.metadata.get("promotion_theorem.all_passed"),
        Some(&"false".to_string())
    );
}

// ===========================================================================
// WitnessValidator
// ===========================================================================

#[test]
fn validator_default_values() {
    let v = WitnessValidator::default();
    assert_eq!(v.supported_version, WitnessSchemaVersion::CURRENT);
    assert_eq!(v.min_confidence_millionths, 900_000);
}

#[test]
fn validator_passes_valid_witness() {
    let witness = build_test_witness();
    let errors = WitnessValidator::new().validate(&witness);
    assert!(errors.is_empty(), "unexpected errors: {errors:?}");
}

#[test]
fn validator_detects_incompatible_schema() {
    let mut witness = build_test_witness();
    witness.schema_version = WitnessSchemaVersion {
        major: 99,
        minor: 0,
    };
    let errors = WitnessValidator::new().validate(&witness);
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, WitnessError::IncompatibleSchema { .. }))
    );
}

#[test]
fn validator_detects_low_confidence() {
    let cap = Capability::new("read");
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .confidence(ConfidenceInterval::from_trials(10, 5))
    .build()
    .unwrap();
    let errors = WitnessValidator::new().validate(&witness);
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, WitnessError::InvalidConfidence { .. }))
    );
}

#[test]
fn validator_returns_multiple_errors() {
    let mut witness = build_test_witness();
    witness.schema_version = WitnessSchemaVersion {
        major: 99,
        minor: 0,
    };
    witness.required_capabilities.clear();
    let errors = WitnessValidator::new().validate(&witness);
    assert!(errors.len() >= 2);
}

#[test]
fn validator_serde_roundtrip() {
    let v = WitnessValidator::new();
    let json = serde_json::to_string(&v).unwrap();
    let back: WitnessValidator = serde_json::from_str(&json).unwrap();
    assert_eq!(v.supported_version, back.supported_version);
    assert_eq!(v.min_confidence_millionths, back.min_confidence_millionths);
}

// ===========================================================================
// WitnessStore
// ===========================================================================

#[test]
fn store_starts_empty_and_insert_works() {
    let mut store = WitnessStore::new();
    assert!(store.is_empty());
    let witness = build_test_witness();
    let wid = witness.witness_id.clone();
    store.insert(witness);
    assert_eq!(store.len(), 1);
    assert!(store.get(&wid).is_some());
}

#[test]
fn store_lifecycle_transitions_through_active() {
    let mut store = WitnessStore::new();
    let witness = build_test_witness();
    let wid = witness.witness_id.clone();
    let ext_id = witness.extension_id.clone();
    store.insert(witness);
    store.transition(&wid, LifecycleState::Validated).unwrap();
    store.transition(&wid, LifecycleState::Promoted).unwrap();
    store.transition(&wid, LifecycleState::Active).unwrap();
    assert!(store.active_for_extension(&ext_id).is_some());
}

#[test]
fn store_supersedes_old_active_on_new_activation() {
    let mut store = WitnessStore::new();
    let w1 = build_test_witness();
    let w1_id = w1.witness_id.clone();
    let ext_id = w1.extension_id.clone();
    store.insert(w1);
    store.transition(&w1_id, LifecycleState::Validated).unwrap();
    store.transition(&w1_id, LifecycleState::Promoted).unwrap();
    store.transition(&w1_id, LifecycleState::Active).unwrap();

    let cap = Capability::new("read-data");
    let mut w2 = WitnessBuilder::new(
        ext_id.clone(),
        test_policy_id(),
        SecurityEpoch::from_raw(101),
        6000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .build()
    .unwrap();
    apply_passing_promotion_theorems(&mut w2);
    let w2_id = w2.witness_id.clone();
    store.insert(w2);
    store.transition(&w2_id, LifecycleState::Validated).unwrap();
    store.transition(&w2_id, LifecycleState::Promoted).unwrap();
    store.transition(&w2_id, LifecycleState::Active).unwrap();

    assert_eq!(
        store.get(&w1_id).unwrap().lifecycle_state,
        LifecycleState::Superseded
    );
    assert_eq!(
        store.active_for_extension(&ext_id).unwrap().witness_id,
        w2_id
    );
}

#[test]
fn store_revoke_removes_active() {
    let mut store = WitnessStore::new();
    let witness = build_test_witness();
    let wid = witness.witness_id.clone();
    let ext_id = witness.extension_id.clone();
    store.insert(witness);
    store.transition(&wid, LifecycleState::Validated).unwrap();
    store.transition(&wid, LifecycleState::Promoted).unwrap();
    store.transition(&wid, LifecycleState::Active).unwrap();
    store.transition(&wid, LifecycleState::Revoked).unwrap();
    assert!(store.active_for_extension(&ext_id).is_none());
}

#[test]
fn store_by_state_filters_correctly() {
    let mut store = WitnessStore::new();
    store.insert(build_test_witness());
    assert_eq!(store.by_state(LifecycleState::Draft).len(), 1);
    assert_eq!(store.by_state(LifecycleState::Active).len(), 0);
}

#[test]
fn store_serde_roundtrip_preserves_active_pairs() {
    let mut store = WitnessStore::new();
    let mut witness = build_test_witness();
    let ext_id = witness.extension_id.clone();
    witness.lifecycle_state = LifecycleState::Active;
    store.insert(witness);
    let json = serde_json::to_string(&store).unwrap();
    let back: WitnessStore = serde_json::from_str(&json).unwrap();
    assert!(back.active_for_extension(&ext_id).is_some());
}

#[test]
fn store_insert_replaces_existing_by_id() {
    let mut store = WitnessStore::new();
    let mut witness = build_test_witness();
    let wid = witness.witness_id.clone();
    store.insert(witness.clone());
    witness
        .metadata
        .insert("replaced".to_string(), "true".to_string());
    store.insert(witness);
    assert_eq!(store.len(), 1);
    assert_eq!(
        store.get(&wid).unwrap().metadata.get("replaced"),
        Some(&"true".to_string())
    );
}

// ===========================================================================
// WitnessIndexStore
// ===========================================================================

#[test]
fn index_store_index_and_lookup_by_id() {
    let adapter = InMemoryStorageAdapter::new();
    let mut store = WitnessIndexStore::new(adapter);
    let ctx = test_event_context();
    let witness = build_test_witness();
    let wid = witness.witness_id.clone();
    let record = store.index_witness(&witness, 5000, &ctx).unwrap();
    assert_eq!(record.witness_id, wid);
    let found = store.witness_by_id(&wid, &ctx).unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().witness_id, wid);
}

#[test]
fn index_store_lookup_missing_returns_none() {
    let adapter = InMemoryStorageAdapter::new();
    let mut store = WitnessIndexStore::new(adapter);
    let ctx = test_event_context();
    assert!(
        store
            .witness_by_id(&test_extension_id(), &ctx)
            .unwrap()
            .is_none()
    );
}

#[test]
fn index_store_query_by_extension() {
    let adapter = InMemoryStorageAdapter::new();
    let mut store = WitnessIndexStore::new(adapter);
    let ctx = test_event_context();
    let witness = build_test_witness();
    let ext_id = witness.extension_id.clone();
    store.index_witness(&witness, 1000, &ctx).unwrap();
    let page = store
        .query_witnesses(
            &WitnessIndexQuery {
                extension_id: Some(ext_id),
                limit: 10,
                ..WitnessIndexQuery::default()
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(page.records.len(), 1);
    assert!(page.next_cursor.is_none());
}

#[test]
fn index_store_query_zero_limit_rejected() {
    let adapter = InMemoryStorageAdapter::new();
    let mut store = WitnessIndexStore::new(adapter);
    let ctx = test_event_context();
    let err = store
        .query_witnesses(
            &WitnessIndexQuery {
                limit: 0,
                ..WitnessIndexQuery::default()
            },
            &ctx,
        )
        .unwrap_err();
    assert!(matches!(err, WitnessIndexError::InvalidInput { .. }));
}

#[test]
fn index_store_query_by_capability() {
    let adapter = InMemoryStorageAdapter::new();
    let mut store = WitnessIndexStore::new(adapter);
    let ctx = test_event_context();
    let witness = build_test_witness();
    store.index_witness(&witness, 1000, &ctx).unwrap();
    let found = store
        .query_witnesses(
            &WitnessIndexQuery {
                capability: Some(Capability::new("read-data")),
                limit: 10,
                ..WitnessIndexQuery::default()
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(found.records.len(), 1);
    let missing = store
        .query_witnesses(
            &WitnessIndexQuery {
                capability: Some(Capability::new("nonexistent")),
                limit: 10,
                ..WitnessIndexQuery::default()
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(missing.records.len(), 0);
}

#[test]
fn index_store_escrow_receipt_and_replay_join() {
    let adapter = InMemoryStorageAdapter::new();
    let mut store = WitnessIndexStore::new(adapter);
    let ctx = test_event_context();
    let witness = build_test_witness();
    let ext_id = witness.extension_id.clone();
    store.index_witness(&witness, 1000, &ctx).unwrap();
    let receipt = CapabilityEscrowReceiptRecord {
        receipt_id: "r-001".to_string(),
        extension_id: ext_id.clone(),
        capability: Some(Capability::new("read-data")),
        decision_kind: "grant".to_string(),
        outcome: "approved".to_string(),
        timestamp_ns: 1500,
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        error_code: None,
    };
    store.index_escrow_receipt(receipt, &ctx).unwrap();
    let rows = store
        .replay_join(
            &WitnessReplayJoinQuery {
                extension_id: ext_id,
                start_timestamp_ns: None,
                end_timestamp_ns: None,
                include_revoked: true,
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].receipts.len(), 1);
}

#[test]
fn index_store_escrow_receipt_validation() {
    let adapter = InMemoryStorageAdapter::new();
    let mut store = WitnessIndexStore::new(adapter);
    let ctx = test_event_context();
    let base = CapabilityEscrowReceiptRecord {
        receipt_id: "r-1".to_string(),
        extension_id: test_extension_id(),
        capability: None,
        decision_kind: "grant".to_string(),
        outcome: "approved".to_string(),
        timestamp_ns: 100,
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        error_code: None,
    };

    let mut empty_id = base.clone();
    empty_id.receipt_id = "  ".to_string();
    assert!(matches!(
        store.index_escrow_receipt(empty_id, &ctx).unwrap_err(),
        WitnessIndexError::InvalidInput { .. }
    ));

    let mut empty_kind = base.clone();
    empty_kind.decision_kind = "  ".to_string();
    assert!(matches!(
        store.index_escrow_receipt(empty_kind, &ctx).unwrap_err(),
        WitnessIndexError::InvalidInput { .. }
    ));

    let mut empty_outcome = base;
    empty_outcome.outcome = "".to_string();
    assert!(matches!(
        store.index_escrow_receipt(empty_outcome, &ctx).unwrap_err(),
        WitnessIndexError::InvalidInput { .. }
    ));
}

#[test]
fn index_store_replay_join_reversed_timestamps_rejected() {
    let adapter = InMemoryStorageAdapter::new();
    let mut store = WitnessIndexStore::new(adapter);
    let ctx = test_event_context();
    let err = store
        .replay_join(
            &WitnessReplayJoinQuery {
                extension_id: test_extension_id(),
                start_timestamp_ns: Some(999),
                end_timestamp_ns: Some(100),
                include_revoked: true,
            },
            &ctx,
        )
        .unwrap_err();
    assert!(matches!(err, WitnessIndexError::InvalidInput { .. }));
}

#[test]
fn index_store_deterministic_snapshot_hash() {
    let adapter = InMemoryStorageAdapter::new();
    let mut store = WitnessIndexStore::new(adapter);
    let ctx = test_event_context();
    let witness = build_test_witness();
    let ext_id = witness.extension_id.clone();
    store.index_witness(&witness, 1000, &ctx).unwrap();
    let h1 = store.deterministic_snapshot_hash(&ext_id, &ctx).unwrap();
    let h2 = store.deterministic_snapshot_hash(&ext_id, &ctx).unwrap();
    assert_eq!(h1, h2);
    assert!(!h1.is_empty());
}

#[test]
fn index_store_cursor_pagination() {
    let adapter = InMemoryStorageAdapter::new();
    let mut store = WitnessIndexStore::new(adapter);
    let ctx = test_event_context();
    for seed in [100u64, 200, 300] {
        let cap_name = format!("cap-{seed}");
        let cap = Capability::new(&cap_name);
        let mut witness = WitnessBuilder::new(
            test_extension_id_seeded(seed),
            test_policy_id(),
            SecurityEpoch::from_raw(seed),
            seed * 10,
            test_signing_key(),
        )
        .require(cap.clone())
        .proof(make_proof(&cap))
        .build()
        .unwrap();
        apply_passing_promotion_theorems(&mut witness);
        store.index_witness(&witness, seed * 100, &ctx).unwrap();
    }
    let page1 = store
        .query_witnesses(
            &WitnessIndexQuery {
                limit: 2,
                ..WitnessIndexQuery::default()
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(page1.records.len(), 2);
    assert!(page1.next_cursor.is_some());
    let page2 = store
        .query_witnesses(
            &WitnessIndexQuery {
                cursor: page1.next_cursor,
                limit: 2,
                ..WitnessIndexQuery::default()
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(page2.records.len(), 1);
    assert!(page2.next_cursor.is_none());
}

#[test]
fn index_store_events_emitted() {
    let adapter = InMemoryStorageAdapter::new();
    let mut store = WitnessIndexStore::new(adapter);
    let ctx = test_event_context();
    assert!(store.events().is_empty());
    let witness = build_test_witness();
    store.index_witness(&witness, 1000, &ctx).unwrap();
    assert!(!store.events().is_empty());
    assert_eq!(store.events()[0].event, "index_witness");
}

// ===========================================================================
// WitnessPublicationPipeline
// ===========================================================================

#[test]
fn pipeline_publish_produces_verifiable_artifact() {
    let head_key = SigningKey::from_bytes([17u8; 32]);
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(500),
        head_key.clone(),
        WitnessPublicationConfig {
            checkpoint_interval: 1,
            policy_id: "test-policy".to_string(),
            governance_ledger_config: Some(GovernanceLedgerConfig {
                checkpoint_interval: 2,
                signer_key: b"witness-governance-signing-key".to_vec(),
                policy_id: "witness-governance".to_string(),
            }),
        },
    )
    .unwrap();
    let witness = build_promoted_witness(1);
    let pub_id = pipeline.publish_witness(witness, 90_000).unwrap();
    assert_eq!(pipeline.publications().len(), 1);
    let artifact = &pipeline.publications()[0];
    assert_eq!(artifact.publication_id, pub_id);
    assert!(!artifact.is_revoked());
    assert_eq!(pipeline.evidence_entries().len(), 1);
    assert_eq!(pipeline.governance_ledger().unwrap().entries().len(), 1);
    WitnessPublicationPipeline::verify_artifact(
        artifact,
        &test_signing_key().verification_key(),
        &head_key.verification_key(),
    )
    .unwrap();
}

#[test]
fn pipeline_second_publish_has_consistency_chain() {
    let head_key = SigningKey::from_bytes([21u8; 32]);
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(600),
        head_key.clone(),
        WitnessPublicationConfig {
            checkpoint_interval: 1,
            policy_id: "test".to_string(),
            governance_ledger_config: None,
        },
    )
    .unwrap();
    pipeline
        .publish_witness(build_promoted_witness(10), 100)
        .unwrap();
    let pub2 = pipeline
        .publish_witness(build_promoted_witness(11), 200)
        .unwrap();
    let artifact = pipeline
        .publications()
        .iter()
        .find(|a| a.publication_id == pub2)
        .unwrap();
    assert!(!artifact.publication_proof.consistency_chain.is_empty());
    WitnessPublicationPipeline::verify_artifact(
        artifact,
        &test_signing_key().verification_key(),
        &head_key.verification_key(),
    )
    .unwrap();
}

#[test]
fn pipeline_revoke_appends_signed_entry() {
    let head_key = SigningKey::from_bytes([33u8; 32]);
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(700),
        head_key.clone(),
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    let witness = build_promoted_witness(20);
    let wid = witness.witness_id.clone();
    pipeline.publish_witness(witness, 1_000).unwrap();
    pipeline
        .revoke_witness(&wid, "compromise detected", 2_000)
        .unwrap();
    let artifact = &pipeline.publications()[0];
    assert!(artifact.is_revoked());
    let revocation = artifact.revocation_proof.as_ref().unwrap();
    assert_eq!(revocation.log_entry.kind, PublicationEntryKind::Revoke);
    WitnessPublicationPipeline::verify_artifact(
        artifact,
        &test_signing_key().verification_key(),
        &head_key.verification_key(),
    )
    .unwrap();
}

#[test]
fn pipeline_query_filters_by_extension_and_revoked() {
    let head_key = SigningKey::from_bytes([44u8; 32]);
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(800),
        head_key,
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    let w1 = build_promoted_witness(31);
    let w1_ext = w1.extension_id.clone();
    let w1_id = w1.witness_id.clone();
    pipeline.publish_witness(w1, 10).unwrap();
    pipeline
        .publish_witness(build_promoted_witness(32), 20)
        .unwrap();
    pipeline.revoke_witness(&w1_id, "reason", 30).unwrap();

    let by_ext = pipeline.query(&WitnessPublicationQuery {
        extension_id: Some(w1_ext),
        policy_id: None,
        epoch: None,
        content_hash: None,
        include_revoked: true,
    });
    assert_eq!(by_ext.len(), 1);

    let non_revoked = pipeline.query(&WitnessPublicationQuery {
        extension_id: None,
        policy_id: None,
        epoch: None,
        content_hash: None,
        include_revoked: false,
    });
    assert_eq!(non_revoked.len(), 1);
    assert!(!non_revoked[0].is_revoked());
}

#[test]
fn pipeline_error_publish_draft_rejected() {
    let head_key = SigningKey::from_bytes([60u8; 32]);
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        head_key,
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    let cap = Capability::new("read");
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .build()
    .unwrap();
    assert!(matches!(
        pipeline.publish_witness(witness, 1000).unwrap_err(),
        WitnessPublicationError::WitnessNotPromoted { .. }
    ));
}

#[test]
fn pipeline_error_duplicate_publish_rejected() {
    let head_key = SigningKey::from_bytes([61u8; 32]);
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        head_key,
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    let witness = build_promoted_witness(50);
    pipeline.publish_witness(witness.clone(), 100).unwrap();
    assert!(matches!(
        pipeline.publish_witness(witness, 200).unwrap_err(),
        WitnessPublicationError::DuplicatePublication { .. }
    ));
}

#[test]
fn pipeline_error_revoke_empty_reason_rejected() {
    let head_key = SigningKey::from_bytes([62u8; 32]);
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        head_key,
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    let witness = build_promoted_witness(51);
    let wid = witness.witness_id.clone();
    pipeline.publish_witness(witness, 100).unwrap();
    assert!(matches!(
        pipeline.revoke_witness(&wid, "  ", 200).unwrap_err(),
        WitnessPublicationError::EmptyRevocationReason
    ));
}

#[test]
fn pipeline_error_revoke_already_revoked_rejected() {
    let head_key = SigningKey::from_bytes([63u8; 32]);
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        head_key,
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    let witness = build_promoted_witness(52);
    let wid = witness.witness_id.clone();
    pipeline.publish_witness(witness, 100).unwrap();
    pipeline.revoke_witness(&wid, "compromise", 200).unwrap();
    assert!(matches!(
        pipeline.revoke_witness(&wid, "again", 300).unwrap_err(),
        WitnessPublicationError::AlreadyRevoked { .. }
    ));
}

#[test]
fn pipeline_error_zero_checkpoint_interval() {
    let head_key = SigningKey::from_bytes([65u8; 32]);
    assert!(matches!(
        WitnessPublicationPipeline::new(
            SecurityEpoch::from_raw(1),
            head_key,
            WitnessPublicationConfig {
                checkpoint_interval: 0,
                policy_id: "ok".to_string(),
                governance_ledger_config: None,
            },
        )
        .unwrap_err(),
        WitnessPublicationError::InvalidConfig { .. }
    ));
}

#[test]
fn pipeline_checkpoints_at_configured_interval() {
    let head_key = SigningKey::from_bytes([71u8; 32]);
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        head_key,
        WitnessPublicationConfig {
            checkpoint_interval: 2,
            policy_id: "test".to_string(),
            governance_ledger_config: None,
        },
    )
    .unwrap();
    pipeline
        .publish_witness(build_promoted_witness(90), 100)
        .unwrap();
    assert_eq!(pipeline.checkpoints().len(), 0);
    pipeline
        .publish_witness(build_promoted_witness(91), 200)
        .unwrap();
    assert_eq!(pipeline.checkpoints().len(), 1);
}

#[test]
fn pipeline_events_emitted_on_publish_and_revoke() {
    let head_key = SigningKey::from_bytes([70u8; 32]);
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        head_key,
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    let w = build_promoted_witness(80);
    let wid = w.witness_id.clone();
    pipeline.publish_witness(w, 100).unwrap();
    assert_eq!(pipeline.events()[0].event, "publish_witness");
    pipeline.revoke_witness(&wid, "compromised", 200).unwrap();
    assert_eq!(pipeline.events()[1].event, "revoke_witness");
}

// ===========================================================================
// Struct serde roundtrips
// ===========================================================================

#[test]
fn capability_witness_serde_roundtrip() {
    let witness = build_test_witness();
    let json = serde_json::to_string(&witness).unwrap();
    let back: CapabilityWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(witness.witness_id, back.witness_id);
    assert_eq!(witness.content_hash, back.content_hash);
    assert_eq!(witness.required_capabilities, back.required_capabilities);
}

#[test]
fn rollback_token_serde_roundtrip() {
    let token = RollbackToken {
        previous_witness_hash: ContentHash::compute(b"prev"),
        previous_witness_id: Some(test_extension_id()),
        created_epoch: SecurityEpoch::from_raw(99),
        sequence: 5,
    };
    let json = serde_json::to_string(&token).unwrap();
    let back: RollbackToken = serde_json::from_str(&json).unwrap();
    assert_eq!(token, back);
}

#[test]
fn denial_record_serde_roundtrip() {
    let dr = DenialRecord {
        capability: Capability::new("admin"),
        reason: "not needed".to_string(),
        evidence_id: None,
    };
    let json = serde_json::to_string(&dr).unwrap();
    let back: DenialRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(dr, back);
}

#[test]
fn witness_store_serde_roundtrip() {
    let mut store = WitnessStore::new();
    store.insert(build_test_witness());
    let json = serde_json::to_string(&store).unwrap();
    let back: WitnessStore = serde_json::from_str(&json).unwrap();
    assert_eq!(store.len(), back.len());
}

#[test]
fn witness_index_query_serde_roundtrip() {
    let q = WitnessIndexQuery {
        extension_id: Some(test_extension_id()),
        policy_id: None,
        epoch: Some(SecurityEpoch::from_raw(1)),
        lifecycle_state: Some(LifecycleState::Active),
        capability: None,
        start_timestamp_ns: Some(100),
        end_timestamp_ns: Some(200),
        include_revoked: false,
        cursor: None,
        limit: 10,
    };
    let json = serde_json::to_string(&q).unwrap();
    let back: WitnessIndexQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(q, back);
}

#[test]
fn witness_publication_config_serde_roundtrip() {
    let config = WitnessPublicationConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: WitnessPublicationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn witness_publication_query_all_serde_roundtrip() {
    let q = WitnessPublicationQuery::all();
    let json = serde_json::to_string(&q).unwrap();
    let back: WitnessPublicationQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(q, back);
    assert!(back.include_revoked);
}

#[test]
fn promotion_theorem_input_serde_roundtrip() {
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "s1".to_string(),
            capabilities: BTreeSet::from([Capability::new("read")]),
        }],
        manifest_capabilities: BTreeSet::from([Capability::new("read")]),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    };
    let json = serde_json::to_string(&input).unwrap();
    let back: PromotionTheoremInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

#[test]
fn promotion_theorem_report_serde_roundtrip() {
    let cap = Capability::new("read");
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .build()
    .unwrap();
    let report = witness
        .evaluate_promotion_theorems(&promotion_theorem_input_for(&witness))
        .unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: PromotionTheoremReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn witness_tree_head_serde_roundtrip() {
    let head = WitnessTreeHead {
        checkpoint_seq: 1,
        log_length: 10,
        mmr_root: ContentHash::compute(b"root"),
        timestamp_ns: 5000,
        epoch: SecurityEpoch::from_raw(7),
        head_hash: ContentHash::compute(b"head"),
        signature: vec![0xab; 64],
    };
    let json = serde_json::to_string(&head).unwrap();
    let back: WitnessTreeHead = serde_json::from_str(&json).unwrap();
    assert_eq!(head, back);
}

#[test]
fn consistency_proof_link_serde_roundtrip() {
    let head1 = WitnessTreeHead {
        checkpoint_seq: 1,
        log_length: 5,
        mmr_root: ContentHash::compute(b"root1"),
        timestamp_ns: 1000,
        epoch: SecurityEpoch::from_raw(1),
        head_hash: ContentHash::compute(b"head1"),
        signature: vec![0xab; 64],
    };
    let head2 = WitnessTreeHead {
        checkpoint_seq: 2,
        log_length: 10,
        mmr_root: ContentHash::compute(b"root2"),
        timestamp_ns: 2000,
        epoch: SecurityEpoch::from_raw(1),
        head_hash: ContentHash::compute(b"head2"),
        signature: vec![0xcd; 64],
    };
    let link = ConsistencyProofLink {
        from_head: head1,
        to_head: head2,
        proof: MmrProof {
            proof_type: ProofType::Inclusion,
            marker_index: 5,
            proof_hashes: Vec::new(),
            root_hash: ContentHash::compute(b"root2"),
            stream_length: 10,
            epoch_id: 1,
        },
    };
    let json = serde_json::to_string(&link).unwrap();
    let back: ConsistencyProofLink = serde_json::from_str(&json).unwrap();
    assert_eq!(link, back);
}

// ===========================================================================
// Default value assertions
// ===========================================================================

#[test]
fn witness_index_query_default_values() {
    let q = WitnessIndexQuery::default();
    assert!(q.extension_id.is_none());
    assert!(q.policy_id.is_none());
    assert!(q.epoch.is_none());
    assert!(q.lifecycle_state.is_none());
    assert!(q.capability.is_none());
    assert!(q.include_revoked);
    assert!(q.cursor.is_none());
    assert_eq!(q.limit, 128);
}

#[test]
fn witness_publication_config_default_values() {
    let c = WitnessPublicationConfig::default();
    assert_eq!(c.checkpoint_interval, 8);
    assert_eq!(c.policy_id, "capability-witness-policy");
    assert!(c.governance_ledger_config.is_none());
}

// ===========================================================================
// Error code and Display coverage
// ===========================================================================

#[test]
fn witness_index_error_codes_all_unique() {
    let errors: Vec<WitnessIndexError> = vec![
        WitnessIndexError::Storage(StorageError::NotFound {
            store: StoreKind::PlasWitness,
            key: "k".to_string(),
        }),
        WitnessIndexError::Serialization {
            operation: "w".to_string(),
            detail: "e".to_string(),
        },
        WitnessIndexError::CorruptRecord {
            key: "k".to_string(),
            detail: "d".to_string(),
        },
        WitnessIndexError::InvalidInput {
            detail: "d".to_string(),
        },
    ];
    let codes: BTreeSet<&str> = errors.iter().map(|e| e.code()).collect();
    assert_eq!(codes.len(), errors.len());
}

#[test]
fn witness_publication_error_display_all_nonempty() {
    let variants: Vec<WitnessPublicationError> = vec![
        WitnessPublicationError::InvalidConfig {
            reason: "bad".to_string(),
        },
        WitnessPublicationError::WitnessNotPromoted {
            state: LifecycleState::Draft,
        },
        WitnessPublicationError::EmptyRevocationReason,
        WitnessPublicationError::LogEntryHashMismatch,
        WitnessPublicationError::IdDerivation("id".to_string()),
        WitnessPublicationError::InclusionProofFailed {
            detail: "d".to_string(),
        },
        WitnessPublicationError::ConsistencyProofFailed {
            detail: "d".to_string(),
        },
        WitnessPublicationError::TreeHeadSignatureInvalid {
            detail: "d".to_string(),
        },
        WitnessPublicationError::TreeHeadHashMismatch {
            expected: "a".to_string(),
            actual: "b".to_string(),
        },
        WitnessPublicationError::WitnessVerificationFailed {
            detail: "d".to_string(),
        },
        WitnessPublicationError::GovernanceLedger {
            detail: "d".to_string(),
        },
        WitnessPublicationError::EvidenceLedger {
            detail: "d".to_string(),
        },
    ];
    for v in &variants {
        assert!(!v.to_string().is_empty());
    }
}

// ===========================================================================
// Determinism checks
// ===========================================================================

#[test]
fn unsigned_bytes_deterministic_across_builds() {
    let w1 = build_test_witness();
    let w2 = build_test_witness();
    assert_eq!(w1.unsigned_bytes(), w2.unsigned_bytes());
}

#[test]
fn synthesis_unsigned_bytes_strips_promotion_metadata() {
    let mut witness = build_test_witness();
    let base = witness.synthesis_unsigned_bytes();
    witness.metadata.insert(
        "promotion_theorem.merge_legality".to_string(),
        "pass".to_string(),
    );
    let after = witness.synthesis_unsigned_bytes();
    assert_eq!(base, after);
}

#[test]
fn synthesis_unsigned_bytes_strips_theorem_proof_obligations() {
    let cap = Capability::new("read");
    let mut witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .build()
    .unwrap();
    let base = witness.synthesis_unsigned_bytes();
    witness.proof_obligations.push(ProofObligation {
        capability: cap,
        kind: ProofKind::PolicyTheoremCheck,
        proof_artifact_id: test_proof_artifact_id(),
        justification: "theorem proof".to_string(),
        artifact_hash: ContentHash::compute(b"theorem"),
    });
    let after = witness.synthesis_unsigned_bytes();
    assert_eq!(base, after);
}

// ===========================================================================
// End-to-end: Builder → Validator → Store → IndexStore → Publication
// ===========================================================================

#[test]
fn end_to_end_witness_lifecycle_through_publication() {
    let head_key = SigningKey::from_bytes([80u8; 32]);

    // 1. Build a witness
    let cap_read = Capability::new("read-data");
    let cap_write = Capability::new("write-data");
    let mut witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(100),
        5000,
        test_signing_key(),
    )
    .require(cap_read.clone())
    .require(cap_write.clone())
    .proof(make_proof(&cap_read))
    .proof(make_proof(&cap_write))
    .confidence(ConfidenceInterval::from_trials(200, 195))
    .replay_seed(42)
    .build()
    .unwrap();

    // 2. Validate
    let validator = WitnessValidator::new();
    let errors = validator.validate(&witness);
    assert!(errors.is_empty(), "validation errors: {errors:?}");

    // 3. Run promotion theorems
    apply_passing_promotion_theorems(&mut witness);

    // 4. Transition through lifecycle
    witness.transition_to(LifecycleState::Validated).unwrap();
    witness.transition_to(LifecycleState::Promoted).unwrap();

    // 5. Store in WitnessStore
    let mut store = WitnessStore::new();
    store.insert(witness.clone());

    // 6. Index in WitnessIndexStore
    let adapter = InMemoryStorageAdapter::new();
    let mut index_store = WitnessIndexStore::new(adapter);
    let ctx = test_event_context();
    let record = index_store.index_witness(&witness, 5000, &ctx).unwrap();
    assert_eq!(record.lifecycle_state, LifecycleState::Promoted);

    // 7. Publish
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(100),
        head_key.clone(),
        WitnessPublicationConfig::default(),
    )
    .unwrap();
    let pub_id = pipeline.publish_witness(witness.clone(), 10_000).unwrap();

    // 8. Verify
    pipeline
        .verify_publication(
            &pub_id,
            &test_signing_key().verification_key(),
            &head_key.verification_key(),
        )
        .unwrap();

    // 9. Query
    let results = pipeline.query(&WitnessPublicationQuery::all());
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_revoked());

    // 10. Revoke
    pipeline
        .revoke_witness(&witness.witness_id, "emergency", 20_000)
        .unwrap();
    assert!(pipeline.publications()[0].is_revoked());
}

// ===========================================================================
// JSON field name stability
// ===========================================================================

#[test]
fn witness_json_field_names_stable() {
    let witness = build_test_witness();
    let json = serde_json::to_string(&witness).unwrap();
    for field in [
        "witness_id",
        "schema_version",
        "extension_id",
        "policy_id",
        "lifecycle_state",
        "required_capabilities",
        "denied_capabilities",
        "proof_obligations",
        "confidence",
        "replay_seed",
        "transcript_hash",
        "synthesizer_signature",
        "epoch",
        "timestamp_ns",
        "content_hash",
        "metadata",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing field: {field}"
        );
    }
}

#[test]
fn witness_index_query_json_field_names_stable() {
    let q = WitnessIndexQuery::default();
    let json = serde_json::to_string(&q).unwrap();
    for field in [
        "extension_id",
        "policy_id",
        "epoch",
        "lifecycle_state",
        "capability",
        "start_timestamp_ns",
        "end_timestamp_ns",
        "include_revoked",
        "cursor",
        "limit",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing field: {field}"
        );
    }
}

// ===========================================================================
// Clone independence
// ===========================================================================

#[test]
fn witness_clone_independence() {
    let w1 = build_test_witness();
    let mut w2 = w1.clone();
    w2.metadata.insert("cloned".to_string(), "true".to_string());
    assert!(!w1.metadata.contains_key("cloned"));
}

#[test]
fn witness_store_clone_independence() {
    let mut store = WitnessStore::new();
    store.insert(build_test_witness());
    let store2 = store.clone();
    assert_eq!(store.len(), store2.len());
}
