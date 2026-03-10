//! Integration tests for the `capability_witness` module.
//!
//! These tests exercise the public API from outside the crate, covering
//! lifecycle workflows, witness construction, validation, publication
//! pipeline, error conditions, and serde round-trips.

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
    CapabilityEscrowReceiptRecord, CapabilityWitness, ConfidenceInterval, CustomTheoremExtension,
    DenialRecord, LifecycleState, PromotionTheoremInput, PromotionTheoremKind, ProofKind,
    ProofObligation, PublicationEntryKind, RollbackToken, SourceCapabilitySet, WitnessBuilder,
    WitnessError, WitnessIndexQuery, WitnessIndexStore, WitnessPublicationConfig,
    WitnessPublicationError, WitnessPublicationPipeline, WitnessPublicationQuery,
    WitnessReplayJoinQuery, WitnessSchemaVersion, WitnessStore, WitnessValidator,
};
use frankenengine_engine::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_theorem_compiler::Capability;
use frankenengine_engine::portfolio_governor::governance_audit_ledger::GovernanceLedgerConfig;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::storage_adapter::{EventContext, InMemoryStorageAdapter};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_sk(seed: u8) -> SigningKey {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(seed);
    }
    SigningKey::from_bytes(key)
}

fn ext_id() -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::Attestation,
        "test-ext",
        &SchemaId::from_definition(b"TestExtension.v1"),
        b"ext-001",
    )
    .unwrap()
}

fn ext_id_seeded(seed: u64) -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::Attestation,
        "test-ext-seeded",
        &SchemaId::from_definition(b"TestExtension.v1"),
        &seed.to_be_bytes(),
    )
    .unwrap()
}

fn policy_id() -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::PolicyObject,
        "test-policy",
        &SchemaId::from_definition(b"TestPolicy.v1"),
        b"policy-001",
    )
    .unwrap()
}

fn proof_artifact_id() -> EngineObjectId {
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
        proof_artifact_id: proof_artifact_id(),
        justification: format!("Ablation: removing {} breaks behavior", cap),
        artifact_hash: ContentHash::compute(format!("proof-for-{}", cap).as_bytes()),
    }
}

fn passing_theorem_input(witness: &CapabilityWitness) -> PromotionTheoremInput {
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

fn apply_passing_theorems(witness: &mut CapabilityWitness, sk: &SigningKey) {
    let report = witness
        .evaluate_promotion_theorems(&passing_theorem_input(witness))
        .expect("theorem check report");
    assert!(report.all_passed);
    witness.apply_promotion_theorem_report(&report);
    rebind(witness, sk);
}

fn rebind(witness: &mut CapabilityWitness, sk: &SigningKey) {
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
    .expect("derive id");
    let sig = sign_preimage(sk, &unsigned).expect("sign");
    witness.synthesizer_signature = sig.to_bytes().to_vec();
}

fn build_draft_witness() -> CapabilityWitness {
    let cap_r = Capability::new("read-data");
    let cap_w = Capability::new("write-data");
    let cap_a = Capability::new("admin-access");
    let sk = make_sk(13);
    let mut w = WitnessBuilder::new(
        ext_id(),
        policy_id(),
        SecurityEpoch::from_raw(100),
        5000,
        sk,
    )
    .require(cap_r.clone())
    .require(cap_w.clone())
    .deny(cap_a, "not needed")
    .proof(make_proof(&cap_r))
    .proof(make_proof(&cap_w))
    .confidence(ConfidenceInterval::from_trials(200, 195))
    .replay_seed(42)
    .transcript_hash(ContentHash::compute(b"synthesis-transcript"))
    .meta("synthesizer", "plas-v1")
    .build()
    .unwrap();
    apply_passing_theorems(&mut w, &make_sk(13));
    w
}

fn build_promoted(seed: u64) -> CapabilityWitness {
    let cap = Capability::new(format!("cap-{seed}"));
    let sk = make_sk(13);
    let mut w = WitnessBuilder::new(
        ext_id_seeded(seed),
        policy_id(),
        SecurityEpoch::from_raw(10 + seed),
        10_000 + seed,
        sk,
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
    apply_passing_theorems(&mut w, &make_sk(13));
    w.transition_to(LifecycleState::Validated).unwrap();
    w.transition_to(LifecycleState::Promoted).unwrap();
    w
}

fn build_promoted_for_extension(
    extension_id: EngineObjectId,
    capability_name: &str,
    epoch: u64,
    timestamp_ns: u64,
) -> CapabilityWitness {
    let cap = Capability::new(capability_name.to_string());
    let sk = make_sk(13);
    let mut w = WitnessBuilder::new(
        extension_id,
        policy_id(),
        SecurityEpoch::from_raw(epoch),
        timestamp_ns,
        sk,
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .confidence(ConfidenceInterval::from_trials(120, 118))
    .replay_seed(epoch)
    .transcript_hash(ContentHash::compute(
        format!("transcript-{capability_name}-{epoch}").as_bytes(),
    ))
    .build()
    .unwrap();
    apply_passing_theorems(&mut w, &make_sk(13));
    w.transition_to(LifecycleState::Validated).unwrap();
    w.transition_to(LifecycleState::Promoted).unwrap();
    w
}

fn index_ctx() -> EventContext {
    EventContext::new(
        "trace-witness-index",
        "decision-witness-index",
        "policy-witness-index",
    )
    .expect("index context")
}

fn default_pipeline(sk: &SigningKey) -> WitnessPublicationPipeline {
    WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(500),
        SigningKey::from_bytes(*sk.as_bytes()),
        WitnessPublicationConfig::default(),
    )
    .unwrap()
}

fn governance_config() -> WitnessPublicationConfig {
    WitnessPublicationConfig {
        checkpoint_interval: 1,
        policy_id: "witness-pub-policy".to_string(),
        governance_ledger_config: Some(GovernanceLedgerConfig {
            checkpoint_interval: 2,
            signer_key: b"witness-governance-signing-key".to_vec(),
            policy_id: "witness-governance".to_string(),
        }),
    }
}

// ===========================================================================
// WitnessSchemaVersion
// ===========================================================================

#[test]
fn schema_version_current_is_1_0() {
    let v = WitnessSchemaVersion::CURRENT;
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 0);
}

#[test]
fn schema_version_display() {
    let v = WitnessSchemaVersion { major: 3, minor: 7 };
    assert_eq!(v.to_string(), "3.7");
}

#[test]
fn schema_version_compatible_same_version() {
    let v = WitnessSchemaVersion::CURRENT;
    assert!(v.is_compatible_with(&v));
}

#[test]
fn schema_version_compatible_reader_higher_minor() {
    let reader = WitnessSchemaVersion { major: 1, minor: 2 };
    let witness = WitnessSchemaVersion { major: 1, minor: 0 };
    assert!(reader.is_compatible_with(&witness));
}

#[test]
fn schema_version_incompatible_reader_lower_minor() {
    let reader = WitnessSchemaVersion { major: 1, minor: 0 };
    let witness = WitnessSchemaVersion { major: 1, minor: 1 };
    assert!(!reader.is_compatible_with(&witness));
}

#[test]
fn schema_version_incompatible_different_major() {
    let reader = WitnessSchemaVersion { major: 2, minor: 0 };
    let witness = WitnessSchemaVersion { major: 1, minor: 0 };
    assert!(!reader.is_compatible_with(&witness));
}

#[test]
fn schema_version_serde_round_trip() {
    let v = WitnessSchemaVersion { major: 5, minor: 3 };
    let json = serde_json::to_string(&v).unwrap();
    let restored: WitnessSchemaVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

#[test]
fn schema_version_ord() {
    let a = WitnessSchemaVersion { major: 1, minor: 0 };
    let b = WitnessSchemaVersion { major: 1, minor: 1 };
    let c = WitnessSchemaVersion { major: 2, minor: 0 };
    assert!(a < b);
    assert!(b < c);
}

// ===========================================================================
// LifecycleState
// ===========================================================================

#[test]
fn lifecycle_display_all_variants() {
    assert_eq!(LifecycleState::Draft.to_string(), "draft");
    assert_eq!(LifecycleState::Validated.to_string(), "validated");
    assert_eq!(LifecycleState::Promoted.to_string(), "promoted");
    assert_eq!(LifecycleState::Active.to_string(), "active");
    assert_eq!(LifecycleState::Superseded.to_string(), "superseded");
    assert_eq!(LifecycleState::Revoked.to_string(), "revoked");
}

#[test]
fn lifecycle_terminal_states() {
    assert!(!LifecycleState::Draft.is_terminal());
    assert!(!LifecycleState::Validated.is_terminal());
    assert!(!LifecycleState::Promoted.is_terminal());
    assert!(!LifecycleState::Active.is_terminal());
    assert!(LifecycleState::Superseded.is_terminal());
    assert!(LifecycleState::Revoked.is_terminal());
}

#[test]
fn lifecycle_is_active() {
    assert!(!LifecycleState::Draft.is_active());
    assert!(LifecycleState::Active.is_active());
    assert!(!LifecycleState::Superseded.is_active());
}

#[test]
fn lifecycle_valid_transitions_chain() {
    assert!(LifecycleState::Draft.can_transition_to(LifecycleState::Validated));
    assert!(LifecycleState::Validated.can_transition_to(LifecycleState::Promoted));
    assert!(LifecycleState::Promoted.can_transition_to(LifecycleState::Active));
    assert!(LifecycleState::Active.can_transition_to(LifecycleState::Superseded));
    assert!(LifecycleState::Active.can_transition_to(LifecycleState::Revoked));
}

#[test]
fn lifecycle_invalid_skip_transitions() {
    assert!(!LifecycleState::Draft.can_transition_to(LifecycleState::Active));
    assert!(!LifecycleState::Draft.can_transition_to(LifecycleState::Promoted));
    assert!(!LifecycleState::Validated.can_transition_to(LifecycleState::Active));
}

#[test]
fn lifecycle_terminal_no_transitions() {
    assert!(LifecycleState::Superseded.valid_transitions().is_empty());
    assert!(LifecycleState::Revoked.valid_transitions().is_empty());
}

#[test]
fn lifecycle_serde_round_trip() {
    for state in [
        LifecycleState::Draft,
        LifecycleState::Validated,
        LifecycleState::Promoted,
        LifecycleState::Active,
        LifecycleState::Superseded,
        LifecycleState::Revoked,
    ] {
        let json = serde_json::to_string(&state).unwrap();
        let restored: LifecycleState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, restored);
    }
}

// ===========================================================================
// WitnessError
// ===========================================================================

#[test]
fn witness_error_display_all_variants() {
    let variants: Vec<WitnessError> = vec![
        WitnessError::EmptyRequiredSet,
        WitnessError::MissingProofObligation {
            capability: "net".to_string(),
        },
        WitnessError::InvalidConfidence {
            reason: "too low".to_string(),
        },
        WitnessError::InvalidTransition {
            from: LifecycleState::Draft,
            to: LifecycleState::Active,
        },
        WitnessError::IncompatibleSchema {
            witness: WitnessSchemaVersion { major: 2, minor: 0 },
            reader: WitnessSchemaVersion { major: 1, minor: 0 },
        },
        WitnessError::SignatureInvalid {
            detail: "bad sig".to_string(),
        },
        WitnessError::IntegrityFailure {
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        },
        WitnessError::IdDerivation("id problem".to_string()),
        WitnessError::InvalidRollbackToken {
            reason: "no such witness".to_string(),
        },
        WitnessError::EpochMismatch {
            witness_epoch: 1,
            current_epoch: 5,
        },
        WitnessError::MissingPromotionTheoremProofs {
            missing_checks: vec!["merge-legality".to_string()],
        },
        WitnessError::PromotionTheoremFailed {
            failed_checks: vec!["non-interference".to_string()],
        },
    ];
    for v in &variants {
        let s = v.to_string();
        assert!(!s.is_empty(), "display for {:?} was empty", v);
    }
}

#[test]
fn witness_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(WitnessError::EmptyRequiredSet);
    assert!(!err.to_string().is_empty());
}

#[test]
fn witness_error_serde_round_trip() {
    let err = WitnessError::EpochMismatch {
        witness_epoch: 10,
        current_epoch: 20,
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: WitnessError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

// ===========================================================================
// ConfidenceInterval
// ===========================================================================

#[test]
fn confidence_zero_trials() {
    let ci = ConfidenceInterval::from_trials(0, 0);
    assert_eq!(ci.n_trials, 0);
    assert_eq!(ci.n_successes, 0);
    assert_eq!(ci.point_estimate_millionths(), 0);
    assert_eq!(ci.lower_millionths, 0);
    assert_eq!(ci.upper_millionths, 0);
}

#[test]
fn confidence_perfect_trials() {
    let ci = ConfidenceInterval::from_trials(200, 200);
    assert!(ci.lower_millionths > 950_000);
    assert!(ci.upper_millionths >= ci.lower_millionths);
    assert_eq!(ci.point_estimate_millionths(), 1_000_000);
}

#[test]
fn confidence_mixed_trials() {
    let ci = ConfidenceInterval::from_trials(100, 90);
    assert!(ci.lower_millionths > 0);
    assert!(ci.upper_millionths <= 1_000_000);
    assert!(ci.lower_millionths < ci.upper_millionths);
    assert_eq!(ci.point_estimate_millionths(), 900_000);
}

#[test]
fn confidence_meets_threshold_true() {
    let ci = ConfidenceInterval::from_trials(200, 200);
    assert!(ci.meets_threshold(900_000));
}

#[test]
fn confidence_meets_threshold_false() {
    let ci = ConfidenceInterval::from_trials(10, 5);
    assert!(!ci.meets_threshold(900_000));
}

#[test]
fn confidence_serde_round_trip() {
    let ci = ConfidenceInterval::from_trials(80, 75);
    let json = serde_json::to_string(&ci).unwrap();
    let restored: ConfidenceInterval = serde_json::from_str(&json).unwrap();
    assert_eq!(ci, restored);
}

// ===========================================================================
// ProofKind
// ===========================================================================

#[test]
fn proof_kind_display_all_variants() {
    assert_eq!(ProofKind::StaticAnalysis.to_string(), "static-analysis");
    assert_eq!(ProofKind::DynamicAblation.to_string(), "dynamic-ablation");
    assert_eq!(
        ProofKind::PolicyTheoremCheck.to_string(),
        "policy-theorem-check"
    );
    assert_eq!(
        ProofKind::OperatorAttestation.to_string(),
        "operator-attestation"
    );
    assert_eq!(ProofKind::InheritedFromPredecessor.to_string(), "inherited");
}

#[test]
fn proof_kind_ord() {
    assert!(ProofKind::StaticAnalysis < ProofKind::DynamicAblation);
    assert!(ProofKind::DynamicAblation < ProofKind::PolicyTheoremCheck);
}

// ===========================================================================
// PromotionTheoremKind
// ===========================================================================

#[test]
fn promotion_theorem_kind_display_builtins() {
    assert_eq!(
        PromotionTheoremKind::MergeLegality.to_string(),
        "merge-legality"
    );
    assert_eq!(
        PromotionTheoremKind::AttenuationLegality.to_string(),
        "attenuation-legality"
    );
    assert_eq!(
        PromotionTheoremKind::NonInterference.to_string(),
        "non-interference"
    );
}

#[test]
fn promotion_theorem_kind_display_custom() {
    let k = PromotionTheoremKind::Custom("my-check".to_string());
    assert_eq!(k.to_string(), "custom:my-check");
}

#[test]
fn promotion_theorem_kind_serde_round_trip() {
    let kinds = [
        PromotionTheoremKind::MergeLegality,
        PromotionTheoremKind::AttenuationLegality,
        PromotionTheoremKind::NonInterference,
        PromotionTheoremKind::Custom("foo".to_string()),
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let restored: PromotionTheoremKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, restored);
    }
}

// ===========================================================================
// PublicationEntryKind
// ===========================================================================

#[test]
fn publication_entry_kind_as_str() {
    assert_eq!(PublicationEntryKind::Publish.as_str(), "publish");
    assert_eq!(PublicationEntryKind::Revoke.as_str(), "revoke");
}

#[test]
fn publication_entry_kind_display() {
    assert_eq!(PublicationEntryKind::Publish.to_string(), "publish");
    assert_eq!(PublicationEntryKind::Revoke.to_string(), "revoke");
}

// ===========================================================================
// RollbackToken
// ===========================================================================

#[test]
fn rollback_token_serde_round_trip() {
    let token = RollbackToken {
        previous_witness_hash: ContentHash::compute(b"prev"),
        previous_witness_id: Some(ext_id()),
        created_epoch: SecurityEpoch::from_raw(42),
        sequence: 7,
    };
    let json = serde_json::to_string(&token).unwrap();
    let restored: RollbackToken = serde_json::from_str(&json).unwrap();
    assert_eq!(token, restored);
}

#[test]
fn rollback_token_none_previous_id() {
    let token = RollbackToken {
        previous_witness_hash: ContentHash::compute(b"prev2"),
        previous_witness_id: None,
        created_epoch: SecurityEpoch::GENESIS,
        sequence: 0,
    };
    let json = serde_json::to_string(&token).unwrap();
    let restored: RollbackToken = serde_json::from_str(&json).unwrap();
    assert_eq!(token, restored);
}

// ===========================================================================
// DenialRecord
// ===========================================================================

#[test]
fn denial_record_serde_round_trip() {
    let dr = DenialRecord {
        capability: Capability::new("admin"),
        reason: "not required".to_string(),
        evidence_id: None,
    };
    let json = serde_json::to_string(&dr).unwrap();
    let restored: DenialRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(dr, restored);
}

// ===========================================================================
// WitnessBuilder
// ===========================================================================

#[test]
fn builder_minimal_witness() {
    let cap = Capability::new("read");
    let sk = make_sk(13);
    let w = WitnessBuilder::new(ext_id(), policy_id(), SecurityEpoch::from_raw(1), 1000, sk)
        .require(cap.clone())
        .proof(make_proof(&cap))
        .build()
        .unwrap();
    assert_eq!(w.lifecycle_state, LifecycleState::Draft);
    assert_eq!(w.required_capabilities.len(), 1);
    assert_eq!(w.schema_version, WitnessSchemaVersion::CURRENT);
    assert!(!w.synthesizer_signature.is_empty());
}

#[test]
fn builder_empty_required_set_fails() {
    let sk = make_sk(13);
    let err = WitnessBuilder::new(ext_id(), policy_id(), SecurityEpoch::from_raw(1), 1000, sk)
        .build()
        .unwrap_err();
    assert!(matches!(err, WitnessError::EmptyRequiredSet));
}

#[test]
fn builder_require_all() {
    let caps = [
        Capability::new("a"),
        Capability::new("b"),
        Capability::new("c"),
    ];
    let sk = make_sk(13);
    let w = WitnessBuilder::new(ext_id(), policy_id(), SecurityEpoch::from_raw(1), 1000, sk)
        .require_all(caps.iter().cloned())
        .proof(make_proof(&caps[0]))
        .proof(make_proof(&caps[1]))
        .proof(make_proof(&caps[2]))
        .build()
        .unwrap();
    assert_eq!(w.required_capabilities.len(), 3);
}

#[test]
fn builder_with_deny() {
    let cap_r = Capability::new("read");
    let cap_a = Capability::new("admin");
    let sk = make_sk(13);
    let w = WitnessBuilder::new(ext_id(), policy_id(), SecurityEpoch::from_raw(1), 1000, sk)
        .require(cap_r.clone())
        .deny(cap_a.clone(), "not needed")
        .proof(make_proof(&cap_r))
        .build()
        .unwrap();
    assert!(w.denied_capabilities.contains(&cap_a));
    assert_eq!(w.denial_records.len(), 1);
}

#[test]
fn builder_with_rollback_token() {
    let cap = Capability::new("read");
    let sk = make_sk(13);
    let token = RollbackToken {
        previous_witness_hash: ContentHash::compute(b"old"),
        previous_witness_id: None,
        created_epoch: SecurityEpoch::from_raw(99),
        sequence: 1,
    };
    let w = WitnessBuilder::new(
        ext_id(),
        policy_id(),
        SecurityEpoch::from_raw(100),
        5000,
        sk,
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .rollback(token)
    .build()
    .unwrap();
    assert!(w.rollback_token.is_some());
    assert_eq!(w.rollback_token.as_ref().unwrap().sequence, 1);
}

#[test]
fn builder_with_metadata() {
    let cap = Capability::new("read");
    let sk = make_sk(13);
    let w = WitnessBuilder::new(ext_id(), policy_id(), SecurityEpoch::from_raw(1), 1000, sk)
        .require(cap.clone())
        .proof(make_proof(&cap))
        .meta("key1", "val1")
        .meta("key2", "val2")
        .build()
        .unwrap();
    assert_eq!(w.metadata.get("key1"), Some(&"val1".to_string()));
    assert_eq!(w.metadata.get("key2"), Some(&"val2".to_string()));
}

#[test]
fn builder_deterministic_id() {
    let w1 = build_draft_witness();
    let w2 = build_draft_witness();
    assert_eq!(w1.witness_id, w2.witness_id);
    assert_eq!(w1.content_hash, w2.content_hash);
}

// ===========================================================================
// CapabilityWitness — lifecycle transitions
// ===========================================================================

#[test]
fn full_lifecycle_draft_to_superseded() {
    let mut w = build_draft_witness();
    assert_eq!(w.lifecycle_state, LifecycleState::Draft);
    w.transition_to(LifecycleState::Validated).unwrap();
    w.transition_to(LifecycleState::Promoted).unwrap();
    w.transition_to(LifecycleState::Active).unwrap();
    w.transition_to(LifecycleState::Superseded).unwrap();
    assert!(w.lifecycle_state.is_terminal());
}

#[test]
fn full_lifecycle_draft_to_revoked() {
    let mut w = build_draft_witness();
    w.transition_to(LifecycleState::Validated).unwrap();
    w.transition_to(LifecycleState::Promoted).unwrap();
    w.transition_to(LifecycleState::Active).unwrap();
    w.transition_to(LifecycleState::Revoked).unwrap();
    assert!(w.lifecycle_state.is_terminal());
}

#[test]
fn invalid_transition_returns_error() {
    let mut w = build_draft_witness();
    let err = w.transition_to(LifecycleState::Active).unwrap_err();
    assert!(matches!(err, WitnessError::InvalidTransition { .. }));
}

#[test]
fn promotion_without_theorem_report_fails() {
    let cap = Capability::new("read");
    let sk = make_sk(13);
    let mut w = WitnessBuilder::new(ext_id(), policy_id(), SecurityEpoch::from_raw(1), 1000, sk)
        .require(cap.clone())
        .proof(make_proof(&cap))
        .build()
        .unwrap();
    w.transition_to(LifecycleState::Validated).unwrap();
    let err = w.transition_to(LifecycleState::Promoted).unwrap_err();
    assert!(matches!(
        err,
        WitnessError::MissingPromotionTheoremProofs { .. }
    ));
}

// ===========================================================================
// CapabilityWitness — integrity and signature
// ===========================================================================

#[test]
fn verify_integrity_passes_for_valid() {
    let w = build_draft_witness();
    assert!(w.verify_integrity().is_ok());
}

#[test]
fn verify_integrity_detects_tamper() {
    let mut w = build_draft_witness();
    w.replay_seed = 999;
    let err = w.verify_integrity().unwrap_err();
    assert!(matches!(err, WitnessError::IntegrityFailure { .. }));
}

#[test]
fn verify_signature_valid() {
    let w = build_draft_witness();
    let vk = make_sk(13).verification_key();
    assert!(w.verify_synthesizer_signature(&vk).is_ok());
}

#[test]
fn verify_signature_wrong_key_fails() {
    let w = build_draft_witness();
    let wrong_vk = make_sk(99).verification_key();
    let err = w.verify_synthesizer_signature(&wrong_vk).unwrap_err();
    assert!(matches!(err, WitnessError::SignatureInvalid { .. }));
}

#[test]
fn verify_signature_bad_length_fails() {
    let mut w = build_draft_witness();
    w.synthesizer_signature = vec![0u8; 10];
    let vk = make_sk(13).verification_key();
    let err = w.verify_synthesizer_signature(&vk).unwrap_err();
    assert!(matches!(err, WitnessError::SignatureInvalid { .. }));
}

// ===========================================================================
// CapabilityWitness — proof coverage
// ===========================================================================

#[test]
fn verify_proof_coverage_passes() {
    let w = build_draft_witness();
    assert!(w.verify_proof_coverage().is_ok());
}

#[test]
fn verify_proof_coverage_missing_proof() {
    let cap_a = Capability::new("a");
    let cap_b = Capability::new("b");
    let sk = make_sk(13);
    let w = WitnessBuilder::new(ext_id(), policy_id(), SecurityEpoch::from_raw(1), 1000, sk)
        .require(cap_a.clone())
        .require(cap_b)
        .proof(make_proof(&cap_a))
        .build()
        .unwrap();
    let err = w.verify_proof_coverage().unwrap_err();
    assert!(matches!(err, WitnessError::MissingProofObligation { .. }));
}

// ===========================================================================
// CapabilityWitness — promotion theorems
// ===========================================================================

#[test]
fn evaluate_promotion_theorems_all_pass() {
    let cap = Capability::new("read");
    let sk = make_sk(13);
    let w = WitnessBuilder::new(ext_id(), policy_id(), SecurityEpoch::from_raw(1), 1000, sk)
        .require(cap.clone())
        .proof(make_proof(&cap))
        .build()
        .unwrap();
    let report = w
        .evaluate_promotion_theorems(&passing_theorem_input(&w))
        .unwrap();
    assert!(report.all_passed);
    assert_eq!(report.results.len(), 3); // merge, attenuation, non-interference
}

#[test]
fn merge_legality_detects_unjustified_capability() {
    let cap_r = Capability::new("read");
    let cap_w = Capability::new("write");
    let sk = make_sk(13);
    let w = WitnessBuilder::new(ext_id(), policy_id(), SecurityEpoch::from_raw(1), 1000, sk)
        .require(cap_r.clone())
        .require(cap_w.clone())
        .proof(make_proof(&cap_r))
        .proof(make_proof(&cap_w))
        .build()
        .unwrap();
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "evidence".to_string(),
            capabilities: BTreeSet::from([cap_r.clone()]),
        }],
        manifest_capabilities: BTreeSet::from([cap_r, cap_w]),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    };
    let report = w.evaluate_promotion_theorems(&input).unwrap();
    assert!(!report.all_passed);
    let merge = report
        .results
        .iter()
        .find(|r| r.theorem == PromotionTheoremKind::MergeLegality)
        .unwrap();
    assert!(!merge.passed);
    assert!(merge.counterexample.as_deref().unwrap().contains("write"));
}

#[test]
fn merge_legality_lattice_implied() {
    let cap_r = Capability::new("read");
    let cap_w = Capability::new("write");
    let sk = make_sk(13);
    let w = WitnessBuilder::new(ext_id(), policy_id(), SecurityEpoch::from_raw(1), 1000, sk)
        .require(cap_r.clone())
        .proof(make_proof(&cap_r))
        .build()
        .unwrap();
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "evidence".to_string(),
            capabilities: BTreeSet::from([cap_w.clone()]),
        }],
        manifest_capabilities: BTreeSet::from([cap_w.clone()]),
        capability_lattice: BTreeMap::from([(cap_w, BTreeSet::from([cap_r]))]),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    };
    let report = w.evaluate_promotion_theorems(&input).unwrap();
    let merge = report
        .results
        .iter()
        .find(|r| r.theorem == PromotionTheoremKind::MergeLegality)
        .unwrap();
    assert!(merge.passed);
}

#[test]
fn non_interference_transitive_dependency() {
    let cap_r = Capability::new("read");
    let cap_hop = Capability::new("internal-hop");
    let cap_denied = Capability::new("denied-net");
    let sk = make_sk(13);
    let w = WitnessBuilder::new(ext_id(), policy_id(), SecurityEpoch::from_raw(1), 1000, sk)
        .require(cap_r.clone())
        .deny(cap_denied.clone(), "forbidden")
        .proof(make_proof(&cap_r))
        .build()
        .unwrap();
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "ev".to_string(),
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
    let report = w.evaluate_promotion_theorems(&input).unwrap();
    let ni = report
        .results
        .iter()
        .find(|r| r.theorem == PromotionTheoremKind::NonInterference)
        .unwrap();
    assert!(!ni.passed);
}

#[test]
fn custom_extension_theorem_pass() {
    let cap = Capability::new("read");
    let sk = make_sk(13);
    let w = WitnessBuilder::new(ext_id(), policy_id(), SecurityEpoch::from_raw(1), 1000, sk)
        .require(cap.clone())
        .proof(make_proof(&cap))
        .build()
        .unwrap();
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "ev".to_string(),
            capabilities: BTreeSet::from([cap.clone()]),
        }],
        manifest_capabilities: BTreeSet::from([cap]),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: vec![CustomTheoremExtension {
            name: "no-network".to_string(),
            required_capabilities: BTreeSet::new(),
            forbidden_capabilities: BTreeSet::from([Capability::new("network")]),
        }],
    };
    let report = w.evaluate_promotion_theorems(&input).unwrap();
    let custom = report
        .results
        .iter()
        .find(|r| matches!(&r.theorem, PromotionTheoremKind::Custom(n) if n == "no-network"))
        .unwrap();
    assert!(custom.passed);
}

#[test]
fn custom_extension_theorem_fail_forbidden() {
    let cap = Capability::new("network");
    let sk = make_sk(13);
    let w = WitnessBuilder::new(ext_id(), policy_id(), SecurityEpoch::from_raw(1), 1000, sk)
        .require(cap.clone())
        .proof(make_proof(&cap))
        .build()
        .unwrap();
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "ev".to_string(),
            capabilities: BTreeSet::from([cap.clone()]),
        }],
        manifest_capabilities: BTreeSet::from([cap]),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: vec![CustomTheoremExtension {
            name: "deny-net".to_string(),
            required_capabilities: BTreeSet::new(),
            forbidden_capabilities: BTreeSet::from([Capability::new("network")]),
        }],
    };
    let report = w.evaluate_promotion_theorems(&input).unwrap();
    let custom = report
        .results
        .iter()
        .find(|r| matches!(&r.theorem, PromotionTheoremKind::Custom(n) if n == "deny-net"))
        .unwrap();
    assert!(!custom.passed);
}

#[test]
fn apply_promotion_theorem_report_sets_metadata() {
    let cap = Capability::new("read");
    let sk = make_sk(13);
    let mut w = WitnessBuilder::new(ext_id(), policy_id(), SecurityEpoch::from_raw(1), 1000, sk)
        .require(cap.clone())
        .proof(make_proof(&cap))
        .build()
        .unwrap();
    let report = w
        .evaluate_promotion_theorems(&passing_theorem_input(&w))
        .unwrap();
    w.apply_promotion_theorem_report(&report);
    assert_eq!(
        w.metadata.get("promotion_theorem.all_passed"),
        Some(&"true".to_string())
    );
    assert_eq!(
        w.metadata.get("promotion_theorem.merge_legality"),
        Some(&"pass".to_string())
    );
}

#[test]
fn structured_events_from_report() {
    let cap = Capability::new("read");
    let sk = make_sk(13);
    let w = WitnessBuilder::new(ext_id(), policy_id(), SecurityEpoch::from_raw(1), 1000, sk)
        .require(cap.clone())
        .proof(make_proof(&cap))
        .build()
        .unwrap();
    let report = w
        .evaluate_promotion_theorems(&passing_theorem_input(&w))
        .unwrap();
    let events = report.structured_events("t1", "d1", "p1");
    // 3 theorem results + 1 gate summary
    assert_eq!(events.len(), 4);
    for e in &events {
        assert_eq!(e.trace_id, "t1");
        assert_eq!(e.decision_id, "d1");
        assert_eq!(e.policy_id, "p1");
        assert!(!e.component.is_empty());
        assert!(!e.event.is_empty());
    }
}

// ===========================================================================
// WitnessValidator
// ===========================================================================

#[test]
fn validator_default_config() {
    let v = WitnessValidator::default();
    assert_eq!(v.supported_version, WitnessSchemaVersion::CURRENT);
    assert_eq!(v.min_confidence_millionths, 900_000);
}

#[test]
fn validator_passes_valid_witness() {
    let w = build_draft_witness();
    let v = WitnessValidator::new();
    let errors = v.validate(&w);
    assert!(errors.is_empty(), "errors: {:?}", errors);
}

#[test]
fn validator_detects_incompatible_schema() {
    let mut w = build_draft_witness();
    w.schema_version = WitnessSchemaVersion {
        major: 99,
        minor: 0,
    };
    let v = WitnessValidator::new();
    let errors = v.validate(&w);
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, WitnessError::IncompatibleSchema { .. }))
    );
}

#[test]
fn validator_detects_low_confidence() {
    let cap = Capability::new("read");
    let sk = make_sk(13);
    let w = WitnessBuilder::new(ext_id(), policy_id(), SecurityEpoch::from_raw(1), 1000, sk)
        .require(cap.clone())
        .proof(make_proof(&cap))
        .confidence(ConfidenceInterval::from_trials(10, 5))
        .build()
        .unwrap();
    let v = WitnessValidator::new();
    let errors = v.validate(&w);
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, WitnessError::InvalidConfidence { .. }))
    );
}

#[test]
fn validator_serde_round_trip() {
    let v = WitnessValidator::new();
    let json = serde_json::to_string(&v).unwrap();
    let restored: WitnessValidator = serde_json::from_str(&json).unwrap();
    assert_eq!(v.supported_version, restored.supported_version);
    assert_eq!(
        v.min_confidence_millionths,
        restored.min_confidence_millionths
    );
}

// ===========================================================================
// WitnessStore
// ===========================================================================

#[test]
fn store_empty_on_creation() {
    let s = WitnessStore::new();
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
}

#[test]
fn store_insert_and_get() {
    let mut s = WitnessStore::new();
    let w = build_draft_witness();
    let wid = w.witness_id.clone();
    s.insert(w);
    assert_eq!(s.len(), 1);
    assert!(!s.is_empty());
    assert!(s.get(&wid).is_some());
}

#[test]
fn store_lifecycle_to_active() {
    let mut s = WitnessStore::new();
    let w = build_draft_witness();
    let wid = w.witness_id.clone();
    let eid = w.extension_id.clone();
    s.insert(w);
    s.transition(&wid, LifecycleState::Validated).unwrap();
    s.transition(&wid, LifecycleState::Promoted).unwrap();
    s.transition(&wid, LifecycleState::Active).unwrap();
    assert!(s.active_for_extension(&eid).is_some());
    assert_eq!(s.get(&wid).unwrap().lifecycle_state, LifecycleState::Active);
}

#[test]
fn store_supersedes_old_active() {
    let mut s = WitnessStore::new();
    let w1 = build_draft_witness();
    let w1_id = w1.witness_id.clone();
    let eid = w1.extension_id.clone();
    s.insert(w1);
    s.transition(&w1_id, LifecycleState::Validated).unwrap();
    s.transition(&w1_id, LifecycleState::Promoted).unwrap();
    s.transition(&w1_id, LifecycleState::Active).unwrap();

    // Second witness for same extension.
    let cap = Capability::new("read-data");
    let sk = make_sk(13);
    let mut w2 = WitnessBuilder::new(
        eid.clone(),
        policy_id(),
        SecurityEpoch::from_raw(101),
        6000,
        sk,
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .build()
    .unwrap();
    apply_passing_theorems(&mut w2, &make_sk(13));
    let w2_id = w2.witness_id.clone();
    s.insert(w2);
    s.transition(&w2_id, LifecycleState::Validated).unwrap();
    s.transition(&w2_id, LifecycleState::Promoted).unwrap();
    s.transition(&w2_id, LifecycleState::Active).unwrap();

    assert_eq!(
        s.get(&w1_id).unwrap().lifecycle_state,
        LifecycleState::Superseded
    );
    assert_eq!(s.active_for_extension(&eid).unwrap().witness_id, w2_id);
}

#[test]
fn store_revoke_removes_active() {
    let mut s = WitnessStore::new();
    let w = build_draft_witness();
    let wid = w.witness_id.clone();
    let eid = w.extension_id.clone();
    s.insert(w);
    s.transition(&wid, LifecycleState::Validated).unwrap();
    s.transition(&wid, LifecycleState::Promoted).unwrap();
    s.transition(&wid, LifecycleState::Active).unwrap();
    s.transition(&wid, LifecycleState::Revoked).unwrap();
    assert!(s.active_for_extension(&eid).is_none());
}

#[test]
fn store_by_state() {
    let mut s = WitnessStore::new();
    s.insert(build_draft_witness());
    assert_eq!(s.by_state(LifecycleState::Draft).len(), 1);
    assert_eq!(s.by_state(LifecycleState::Active).len(), 0);
}

#[test]
fn store_iter() {
    let mut s = WitnessStore::new();
    let w = build_draft_witness();
    let wid = w.witness_id.clone();
    s.insert(w);
    let items: Vec<_> = s.iter().collect();
    assert_eq!(items.len(), 1);
    assert_eq!(*items[0].0, wid);
}

#[test]
fn store_invalid_transition_error() {
    let mut s = WitnessStore::new();
    let w = build_draft_witness();
    let wid = w.witness_id.clone();
    s.insert(w);
    let err = s.transition(&wid, LifecycleState::Active).unwrap_err();
    assert!(matches!(err, WitnessError::InvalidTransition { .. }));
}

#[test]
fn store_serde_round_trip() {
    let mut s = WitnessStore::new();
    s.insert(build_draft_witness());
    let json = serde_json::to_string(&s).unwrap();
    let restored: WitnessStore = serde_json::from_str(&json).unwrap();
    assert_eq!(s.len(), restored.len());
}

// ===========================================================================
// WitnessPublicationConfig
// ===========================================================================

#[test]
fn publication_config_default() {
    let cfg = WitnessPublicationConfig::default();
    assert_eq!(cfg.checkpoint_interval, 8);
    assert!(!cfg.policy_id.is_empty());
    assert!(cfg.governance_ledger_config.is_none());
}

// ===========================================================================
// WitnessPublicationQuery
// ===========================================================================

#[test]
fn publication_query_all() {
    let q = WitnessPublicationQuery::all();
    assert!(q.extension_id.is_none());
    assert!(q.policy_id.is_none());
    assert!(q.epoch.is_none());
    assert!(q.content_hash.is_none());
    assert!(q.include_revoked);
}

// ===========================================================================
// WitnessPublicationError
// ===========================================================================

#[test]
fn publication_error_display_all_variants() {
    let variants: Vec<WitnessPublicationError> = vec![
        WitnessPublicationError::InvalidConfig {
            reason: "bad".to_string(),
        },
        WitnessPublicationError::WitnessNotPromoted {
            state: LifecycleState::Draft,
        },
        WitnessPublicationError::DuplicatePublication {
            witness_id: ext_id(),
        },
        WitnessPublicationError::PublicationNotFound {
            publication_id: ext_id(),
        },
        WitnessPublicationError::WitnessNotPublished {
            witness_id: ext_id(),
        },
        WitnessPublicationError::AlreadyRevoked {
            witness_id: ext_id(),
        },
        WitnessPublicationError::EmptyRevocationReason,
        WitnessPublicationError::IdDerivation("id fail".to_string()),
        WitnessPublicationError::InclusionProofFailed {
            detail: "bad proof".to_string(),
        },
        WitnessPublicationError::ConsistencyProofFailed {
            detail: "bad consistency".to_string(),
        },
        WitnessPublicationError::TreeHeadSignatureInvalid {
            detail: "bad sig".to_string(),
        },
        WitnessPublicationError::TreeHeadHashMismatch {
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        },
        WitnessPublicationError::LogEntryHashMismatch,
        WitnessPublicationError::WitnessVerificationFailed {
            detail: "verification".to_string(),
        },
        WitnessPublicationError::GovernanceLedger {
            detail: "gov fail".to_string(),
        },
        WitnessPublicationError::EvidenceLedger {
            detail: "ev fail".to_string(),
        },
    ];
    for v in &variants {
        let s = v.to_string();
        assert!(!s.is_empty(), "display for {:?} was empty", v);
    }
}

#[test]
fn publication_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(WitnessPublicationError::EmptyRevocationReason);
    assert!(!err.to_string().is_empty());
}

#[test]
fn publication_error_serde_round_trip() {
    let err = WitnessPublicationError::InvalidConfig {
        reason: "zero interval".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: WitnessPublicationError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

// ===========================================================================
// WitnessPublicationPipeline — construction
// ===========================================================================

#[test]
fn pipeline_new_default_config() {
    let sk = make_sk(17);
    let p = default_pipeline(&sk);
    assert!(p.publications().is_empty());
    assert!(p.checkpoints().is_empty());
    assert!(p.log_entries().is_empty());
    assert!(p.events().is_empty());
    assert!(p.evidence_entries().is_empty());
    assert!(p.governance_ledger().is_none());
}

#[test]
fn pipeline_new_with_governance() {
    let sk = make_sk(17);
    let p = WitnessPublicationPipeline::new(SecurityEpoch::from_raw(500), sk, governance_config())
        .unwrap();
    assert!(p.governance_ledger().is_some());
}

#[test]
fn pipeline_zero_checkpoint_interval_fails() {
    let sk = make_sk(17);
    let err = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(500),
        sk,
        WitnessPublicationConfig {
            checkpoint_interval: 0,
            policy_id: "test".to_string(),
            governance_ledger_config: None,
        },
    )
    .unwrap_err();
    assert!(matches!(err, WitnessPublicationError::InvalidConfig { .. }));
}

#[test]
fn pipeline_empty_policy_id_fails() {
    let sk = make_sk(17);
    let err = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(500),
        sk,
        WitnessPublicationConfig {
            checkpoint_interval: 1,
            policy_id: "  ".to_string(),
            governance_ledger_config: None,
        },
    )
    .unwrap_err();
    assert!(matches!(err, WitnessPublicationError::InvalidConfig { .. }));
}

// ===========================================================================
// WitnessPublicationPipeline — publish
// ===========================================================================

#[test]
fn pipeline_publish_promoted_witness() {
    let head_sk = make_sk(17);
    let mut p = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(500),
        SigningKey::from_bytes(*head_sk.as_bytes()),
        governance_config(),
    )
    .unwrap();
    let w = build_promoted(1);
    let pub_id = p.publish_witness(w, 90_000).unwrap();
    assert_eq!(p.publications().len(), 1);
    assert_eq!(p.publications()[0].publication_id, pub_id);
    assert_eq!(
        p.publications()[0].publication_proof.log_entry.kind,
        PublicationEntryKind::Publish
    );
    assert!(!p.publications()[0].is_revoked());
    assert_eq!(p.evidence_entries().len(), 1);
    assert_eq!(p.governance_ledger().unwrap().entries().len(), 1);
    assert_eq!(p.events().len(), 1);
    assert_eq!(p.events()[0].outcome, "success");
}

#[test]
fn pipeline_publish_draft_witness_fails() {
    let head_sk = make_sk(17);
    let mut p = default_pipeline(&head_sk);
    let w = build_draft_witness(); // still Draft
    let err = p.publish_witness(w, 1000).unwrap_err();
    assert!(matches!(
        err,
        WitnessPublicationError::WitnessNotPromoted { .. }
    ));
}

#[test]
fn pipeline_duplicate_publish_fails() {
    let head_sk = make_sk(17);
    let mut p = default_pipeline(&head_sk);
    let w = build_promoted(2);
    p.publish_witness(w.clone(), 1000).unwrap();
    let err = p.publish_witness(w, 2000).unwrap_err();
    assert!(matches!(
        err,
        WitnessPublicationError::DuplicatePublication { .. }
    ));
}

#[test]
fn pipeline_second_publish_has_consistency_chain() {
    let head_sk = make_sk(17);
    let mut p = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(500),
        SigningKey::from_bytes(*head_sk.as_bytes()),
        WitnessPublicationConfig {
            checkpoint_interval: 1,
            policy_id: "test".to_string(),
            governance_ledger_config: None,
        },
    )
    .unwrap();
    let w1 = build_promoted(10);
    let w2 = build_promoted(11);
    p.publish_witness(w1, 100).unwrap();
    let pub2 = p.publish_witness(w2, 200).unwrap();
    let art2 = p
        .publications()
        .iter()
        .find(|a| a.publication_id == pub2)
        .unwrap();
    assert!(!art2.publication_proof.consistency_chain.is_empty());
}

// ===========================================================================
// WitnessPublicationPipeline — revoke
// ===========================================================================

#[test]
fn pipeline_revoke_published_witness() {
    let head_sk = make_sk(17);
    let mut p = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(500),
        SigningKey::from_bytes(*head_sk.as_bytes()),
        governance_config(),
    )
    .unwrap();
    let w = build_promoted(20);
    let wid = w.witness_id.clone();
    p.publish_witness(w, 1_000).unwrap();
    p.revoke_witness(&wid, "compromise", 2_000).unwrap();
    let art = p
        .publications()
        .iter()
        .find(|a| a.witness.witness_id == wid)
        .unwrap();
    assert!(art.is_revoked());
    let rev = art.revocation_proof.as_ref().unwrap();
    assert_eq!(rev.log_entry.kind, PublicationEntryKind::Revoke);
    assert_eq!(
        rev.log_entry.revocation_reason.as_deref(),
        Some("compromise")
    );
    assert_eq!(p.evidence_entries().len(), 2);
    assert_eq!(p.governance_ledger().unwrap().entries().len(), 2);
}

#[test]
fn pipeline_revoke_unpublished_fails() {
    let head_sk = make_sk(17);
    let mut p = default_pipeline(&head_sk);
    let fake_id = ext_id();
    let err = p.revoke_witness(&fake_id, "reason", 1000).unwrap_err();
    assert!(matches!(
        err,
        WitnessPublicationError::WitnessNotPublished { .. }
    ));
}

#[test]
fn pipeline_double_revoke_fails() {
    let head_sk = make_sk(17);
    let mut p = default_pipeline(&head_sk);
    let w = build_promoted(30);
    let wid = w.witness_id.clone();
    p.publish_witness(w, 1000).unwrap();
    p.revoke_witness(&wid, "reason1", 2000).unwrap();
    let err = p.revoke_witness(&wid, "reason2", 3000).unwrap_err();
    assert!(matches!(
        err,
        WitnessPublicationError::AlreadyRevoked { .. }
    ));
}

#[test]
fn pipeline_empty_revocation_reason_fails() {
    let head_sk = make_sk(17);
    let mut p = default_pipeline(&head_sk);
    let w = build_promoted(31);
    let wid = w.witness_id.clone();
    p.publish_witness(w, 1000).unwrap();
    let err = p.revoke_witness(&wid, "  ", 2000).unwrap_err();
    assert!(matches!(
        err,
        WitnessPublicationError::EmptyRevocationReason
    ));
}

// ===========================================================================
// WitnessPublicationPipeline — query
// ===========================================================================

#[test]
fn pipeline_query_all() {
    let head_sk = make_sk(17);
    let mut p = default_pipeline(&head_sk);
    let w1 = build_promoted(40);
    let w2 = build_promoted(41);
    p.publish_witness(w1, 10).unwrap();
    p.publish_witness(w2, 20).unwrap();
    let all = p.query(&WitnessPublicationQuery::all());
    assert_eq!(all.len(), 2);
}

#[test]
fn pipeline_query_by_extension() {
    let head_sk = make_sk(17);
    let mut p = default_pipeline(&head_sk);
    let w1 = build_promoted(50);
    let w2 = build_promoted(51);
    let eid1 = w1.extension_id.clone();
    p.publish_witness(w1, 10).unwrap();
    p.publish_witness(w2, 20).unwrap();
    let by_ext = p.query(&WitnessPublicationQuery {
        extension_id: Some(eid1),
        policy_id: None,
        epoch: None,
        content_hash: None,
        include_revoked: true,
    });
    assert_eq!(by_ext.len(), 1);
}

#[test]
fn pipeline_query_exclude_revoked() {
    let head_sk = make_sk(17);
    let mut p = default_pipeline(&head_sk);
    let w = build_promoted(60);
    let wid = w.witness_id.clone();
    p.publish_witness(w, 10).unwrap();
    p.revoke_witness(&wid, "revoke", 20).unwrap();
    let excluding = p.query(&WitnessPublicationQuery {
        extension_id: None,
        policy_id: None,
        epoch: None,
        content_hash: None,
        include_revoked: false,
    });
    assert_eq!(excluding.len(), 0);
    let including = p.query(&WitnessPublicationQuery::all());
    assert_eq!(including.len(), 1);
}

// ===========================================================================
// WitnessPublicationPipeline — verify
// ===========================================================================

#[test]
fn pipeline_verify_published_artifact() {
    let head_sk = make_sk(17);
    let witness_sk = make_sk(13);
    let mut p = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(500),
        SigningKey::from_bytes(*head_sk.as_bytes()),
        WitnessPublicationConfig {
            checkpoint_interval: 1,
            policy_id: "test".to_string(),
            governance_ledger_config: None,
        },
    )
    .unwrap();
    let w = build_promoted(70);
    let pub_id = p.publish_witness(w, 1000).unwrap();
    p.verify_publication(
        &pub_id,
        &witness_sk.verification_key(),
        &head_sk.verification_key(),
    )
    .unwrap();
}

#[test]
fn pipeline_verify_static_artifact() {
    let head_sk = make_sk(17);
    let witness_sk = make_sk(13);
    let mut p = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(500),
        SigningKey::from_bytes(*head_sk.as_bytes()),
        WitnessPublicationConfig {
            checkpoint_interval: 1,
            policy_id: "test".to_string(),
            governance_ledger_config: None,
        },
    )
    .unwrap();
    let w = build_promoted(71);
    p.publish_witness(w, 1000).unwrap();
    let art = p.publications()[0].clone();
    WitnessPublicationPipeline::verify_artifact(
        &art,
        &witness_sk.verification_key(),
        &head_sk.verification_key(),
    )
    .unwrap();
}

#[test]
fn pipeline_verify_revoked_artifact() {
    let head_sk = make_sk(17);
    let witness_sk = make_sk(13);
    let mut p = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(500),
        SigningKey::from_bytes(*head_sk.as_bytes()),
        WitnessPublicationConfig {
            checkpoint_interval: 1,
            policy_id: "test".to_string(),
            governance_ledger_config: None,
        },
    )
    .unwrap();
    let w = build_promoted(72);
    let wid = w.witness_id.clone();
    p.publish_witness(w, 1000).unwrap();
    p.revoke_witness(&wid, "compromise", 2000).unwrap();
    let art = p.publications()[0].clone();
    assert!(art.is_revoked());
    WitnessPublicationPipeline::verify_artifact(
        &art,
        &witness_sk.verification_key(),
        &head_sk.verification_key(),
    )
    .unwrap();
}

#[test]
fn pipeline_verify_not_found() {
    let head_sk = make_sk(17);
    let witness_sk = make_sk(13);
    let p = default_pipeline(&head_sk);
    let fake = ext_id();
    let err = p
        .verify_publication(
            &fake,
            &witness_sk.verification_key(),
            &head_sk.verification_key(),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        WitnessPublicationError::PublicationNotFound { .. }
    ));
}

// ===========================================================================
// Serde round-trips for composite types
// ===========================================================================

#[test]
fn witness_serde_round_trip() {
    let w = build_draft_witness();
    let json = serde_json::to_string(&w).unwrap();
    let restored: CapabilityWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(w.witness_id, restored.witness_id);
    assert_eq!(w.content_hash, restored.content_hash);
    assert_eq!(w.required_capabilities, restored.required_capabilities);
}

#[test]
fn proof_obligation_serde_round_trip() {
    let po = make_proof(&Capability::new("test"));
    let json = serde_json::to_string(&po).unwrap();
    let restored: ProofObligation = serde_json::from_str(&json).unwrap();
    assert_eq!(po.capability, restored.capability);
    assert_eq!(po.kind, restored.kind);
}

#[test]
fn source_capability_set_serde_round_trip() {
    let scs = SourceCapabilitySet {
        source_id: "src1".to_string(),
        capabilities: BTreeSet::from([Capability::new("a"), Capability::new("b")]),
    };
    let json = serde_json::to_string(&scs).unwrap();
    let restored: SourceCapabilitySet = serde_json::from_str(&json).unwrap();
    assert_eq!(scs, restored);
}

#[test]
fn custom_theorem_extension_serde_round_trip() {
    let cte = CustomTheoremExtension {
        name: "deny-net".to_string(),
        required_capabilities: BTreeSet::from([Capability::new("read")]),
        forbidden_capabilities: BTreeSet::from([Capability::new("network")]),
    };
    let json = serde_json::to_string(&cte).unwrap();
    let restored: CustomTheoremExtension = serde_json::from_str(&json).unwrap();
    assert_eq!(cte, restored);
}

#[test]
fn publication_config_serde_round_trip() {
    let cfg = WitnessPublicationConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: WitnessPublicationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// ===========================================================================
// unsigned_bytes determinism
// ===========================================================================

#[test]
fn unsigned_bytes_deterministic() {
    let w1 = build_draft_witness();
    let w2 = build_draft_witness();
    assert_eq!(w1.unsigned_bytes(), w2.unsigned_bytes());
}

// ===========================================================================
// WitnessIndexStore conformance
// ===========================================================================

#[test]
fn witness_index_round_trip_and_index_queries_are_byte_identical() {
    let mut index = WitnessIndexStore::new(InMemoryStorageAdapter::new());
    let ctx = index_ctx();

    let extension = ext_id();
    let mut witness = build_promoted_for_extension(extension.clone(), "read-data", 101, 5_000);
    witness.transition_to(LifecycleState::Active).unwrap();
    let indexed = index.index_witness(&witness, 5_000, &ctx).unwrap();

    let by_id = index
        .witness_by_id(&witness.witness_id, &ctx)
        .unwrap()
        .unwrap();
    assert_eq!(indexed.witness_id, by_id.witness_id);
    assert_eq!(
        serde_json::to_vec(&witness).unwrap(),
        serde_json::to_vec(&by_id.witness).unwrap()
    );

    let by_extension = index
        .query_witnesses(
            &WitnessIndexQuery {
                extension_id: Some(extension.clone()),
                include_revoked: true,
                limit: 10,
                ..WitnessIndexQuery::default()
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(by_extension.records.len(), 1);
    assert_eq!(by_extension.records[0].witness_id, witness.witness_id);

    let by_capability = index
        .query_witnesses(
            &WitnessIndexQuery {
                capability: Some(Capability::new("read-data")),
                include_revoked: true,
                limit: 10,
                ..WitnessIndexQuery::default()
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(by_capability.records.len(), 1);
    assert_eq!(by_capability.records[0].witness_id, witness.witness_id);
}

#[test]
fn witness_index_cursor_pagination_is_deterministic() {
    let mut index = WitnessIndexStore::new(InMemoryStorageAdapter::new());
    let ctx = index_ctx();
    let extension = ext_id();

    let w1 = build_promoted_for_extension(extension.clone(), "cap-a", 11, 1_000);
    let w2 = build_promoted_for_extension(extension.clone(), "cap-b", 12, 2_000);
    let w3 = build_promoted_for_extension(extension.clone(), "cap-c", 13, 3_000);
    index.index_witness(&w1, 1_000, &ctx).unwrap();
    index.index_witness(&w2, 2_000, &ctx).unwrap();
    index.index_witness(&w3, 3_000, &ctx).unwrap();

    let page_1 = index
        .query_witnesses(
            &WitnessIndexQuery {
                extension_id: Some(extension.clone()),
                include_revoked: true,
                limit: 2,
                ..WitnessIndexQuery::default()
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(page_1.records.len(), 2);
    assert_eq!(page_1.records[0].promotion_timestamp_ns, 1_000);
    assert_eq!(page_1.records[1].promotion_timestamp_ns, 2_000);
    assert!(page_1.next_cursor.is_some());

    let page_2 = index
        .query_witnesses(
            &WitnessIndexQuery {
                extension_id: Some(extension.clone()),
                include_revoked: true,
                cursor: page_1.next_cursor.clone(),
                limit: 2,
                ..WitnessIndexQuery::default()
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(page_2.records.len(), 1);
    assert_eq!(page_2.records[0].promotion_timestamp_ns, 3_000);
    assert!(page_2.next_cursor.is_none());

    let page_1_repeat = index
        .query_witnesses(
            &WitnessIndexQuery {
                extension_id: Some(extension),
                include_revoked: true,
                limit: 2,
                ..WitnessIndexQuery::default()
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(page_1, page_1_repeat);
}

#[test]
fn witness_index_replay_join_links_receipts_to_witness_windows() {
    let mut index = WitnessIndexStore::new(InMemoryStorageAdapter::new());
    let ctx = index_ctx();
    let extension = ext_id();

    let w1 = build_promoted_for_extension(extension.clone(), "cap-x", 21, 1_000);
    let w2 = build_promoted_for_extension(extension.clone(), "cap-y", 22, 2_000);
    index.index_witness(&w1, 1_000, &ctx).unwrap();
    index.index_witness(&w2, 2_000, &ctx).unwrap();

    for (receipt_id, capability, decision_kind, outcome, timestamp_ns) in [
        (
            "receipt-1",
            Some(Capability::new("cap-x")),
            "grant",
            "allow",
            1_100_u64,
        ),
        (
            "receipt-2",
            Some(Capability::new("cap-x")),
            "deny",
            "deny",
            1_500_u64,
        ),
        (
            "receipt-3",
            Some(Capability::new("cap-y")),
            "grant",
            "allow",
            2_200_u64,
        ),
    ] {
        index
            .index_escrow_receipt(
                CapabilityEscrowReceiptRecord {
                    receipt_id: receipt_id.to_string(),
                    extension_id: extension.clone(),
                    capability,
                    decision_kind: decision_kind.to_string(),
                    outcome: outcome.to_string(),
                    timestamp_ns,
                    trace_id: format!("trace-{receipt_id}"),
                    decision_id: format!("decision-{receipt_id}"),
                    policy_id: "policy-witness-index".to_string(),
                    error_code: None,
                },
                &ctx,
            )
            .unwrap();
    }

    let joined = index
        .replay_join(
            &WitnessReplayJoinQuery {
                extension_id: extension,
                start_timestamp_ns: Some(1_000),
                end_timestamp_ns: Some(2_500),
                include_revoked: true,
            },
            &ctx,
        )
        .unwrap();
    assert_eq!(joined.len(), 2);
    assert_eq!(
        joined[0]
            .receipts
            .iter()
            .map(|r| r.receipt_id.as_str())
            .collect::<Vec<_>>(),
        vec!["receipt-1", "receipt-2"]
    );
    assert_eq!(
        joined[1]
            .receipts
            .iter()
            .map(|r| r.receipt_id.as_str())
            .collect::<Vec<_>>(),
        vec!["receipt-3"]
    );
}

#[test]
fn witness_index_determinism_holds_across_timing_and_insert_order() {
    let ctx = index_ctx();
    let extension = ext_id();
    let w1 = build_promoted_for_extension(extension.clone(), "cap-a", 31, 1_000);
    let w2 = build_promoted_for_extension(extension.clone(), "cap-b", 32, 2_000);
    let r1 = CapabilityEscrowReceiptRecord {
        receipt_id: "receipt-a".to_string(),
        extension_id: extension.clone(),
        capability: Some(Capability::new("cap-a")),
        decision_kind: "grant".to_string(),
        outcome: "allow".to_string(),
        timestamp_ns: 1_100,
        trace_id: "trace-a".to_string(),
        decision_id: "decision-a".to_string(),
        policy_id: "policy-a".to_string(),
        error_code: None,
    };
    let r2 = CapabilityEscrowReceiptRecord {
        receipt_id: "receipt-b".to_string(),
        extension_id: extension.clone(),
        capability: Some(Capability::new("cap-b")),
        decision_kind: "grant".to_string(),
        outcome: "allow".to_string(),
        timestamp_ns: 2_100,
        trace_id: "trace-b".to_string(),
        decision_id: "decision-b".to_string(),
        policy_id: "policy-b".to_string(),
        error_code: None,
    };

    let mut idx_a = WitnessIndexStore::new(InMemoryStorageAdapter::new());
    idx_a.index_witness(&w1, 1_000, &ctx).unwrap();
    idx_a.index_witness(&w2, 2_000, &ctx).unwrap();
    idx_a.index_escrow_receipt(r1.clone(), &ctx).unwrap();
    idx_a.index_escrow_receipt(r2.clone(), &ctx).unwrap();

    let mut idx_b = WitnessIndexStore::new(InMemoryStorageAdapter::new());
    idx_b.index_witness(&w2, 2_000, &ctx).unwrap();
    idx_b.index_witness(&w1, 1_000, &ctx).unwrap();
    idx_b.index_escrow_receipt(r2, &ctx).unwrap();
    idx_b.index_escrow_receipt(r1, &ctx).unwrap();

    let hash_a = idx_a.deterministic_snapshot_hash(&extension, &ctx).unwrap();
    let hash_b = idx_b.deterministic_snapshot_hash(&extension, &ctx).unwrap();
    assert_eq!(hash_a, hash_b);
}

#[test]
fn witness_index_schema_migration_keeps_data_queryable() {
    let mut index = WitnessIndexStore::new(InMemoryStorageAdapter::new());
    let ctx = index_ctx();
    let extension = ext_id();
    let witness = build_promoted_for_extension(extension, "cap-z", 41, 4_100);
    index.index_witness(&witness, 4_100, &ctx).unwrap();

    let receipt = index.migrate_schema(2, &ctx).unwrap();
    assert_eq!(receipt.from_version, 1);
    assert_eq!(receipt.to_version, 2);

    let restored = index.witness_by_id(&witness.witness_id, &ctx).unwrap();
    assert!(restored.is_some());
}
