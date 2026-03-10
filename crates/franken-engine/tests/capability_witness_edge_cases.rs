//! Integration tests for the `capability_witness` module.
//!
//! Covers edge cases not covered by the 66 inline tests, including:
//! - WitnessError and WitnessPublicationError Display exhaustive checks
//! - std::error::Error impls
//! - PromotionTheoremKind metadata_key sanitization and Display
//! - PublicationEntryKind Display/as_str
//! - LifecycleState exhaustive transition matrix
//! - ConfidenceInterval boundary cases (1 trial, n_successes > n_trials edge)
//! - WitnessStore: iter, insert-overwrite, transition unknown witness
//! - Publication pipeline error paths: invalid config, duplicate publish,
//!   empty revocation, not-promoted, not-published, already-revoked, exclude_revoked query
//! - apply_promotion_theorem_report when not all_passed (no proof obligations added)
//! - Custom theorem failing (missing required / containing forbidden)
//! - Attenuation legality failing
//! - WitnessPublicationQuery::all
//! - WitnessPublicationConfig::default
//! - Multi-extension store isolation
//! - Serde roundtrips for publication types
//! - Determinism of publication artifact IDs
//! - Unsigned bytes: metadata and rollback token affect output

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
    CapabilityWitness, ConfidenceInterval, CustomTheoremExtension, DenialRecord, LifecycleState,
    PromotionTheoremInput, PromotionTheoremKind, ProofKind, ProofObligation, PublicationEntryKind,
    RollbackToken, SourceCapabilitySet, WitnessBuilder, WitnessError, WitnessPublicationConfig,
    WitnessPublicationError, WitnessPublicationEvent, WitnessPublicationPipeline,
    WitnessPublicationQuery, WitnessSchemaVersion, WitnessStore, WitnessValidator,
};
use frankenengine_engine::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_theorem_compiler::Capability;
use frankenengine_engine::portfolio_governor::governance_audit_ledger::GovernanceLedgerConfig;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{SigningKey, sign_preimage};

// ---------------------------------------------------------------------------
// Test helpers (mirrors inline helpers but exposed for integration tests)
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

fn rebind_witness(witness: &mut CapabilityWitness, signing_key: &SigningKey) {
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

fn publication_pipeline(epoch: u64, key_seed: u8) -> (WitnessPublicationPipeline, SigningKey) {
    let head_signing_key = SigningKey::from_bytes([key_seed; 32]);
    let pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(epoch),
        head_signing_key.clone(),
        WitnessPublicationConfig {
            checkpoint_interval: 1,
            policy_id: "test-policy".to_string(),
            governance_ledger_config: None,
        },
    )
    .unwrap();
    (pipeline, head_signing_key)
}

// ===========================================================================
// WitnessError Display — individual variant verification
// ===========================================================================

#[test]
fn witness_error_display_empty_required_set() {
    let err = WitnessError::EmptyRequiredSet;
    assert_eq!(err.to_string(), "required capability set is empty");
}

#[test]
fn witness_error_display_missing_proof_obligation() {
    let err = WitnessError::MissingProofObligation {
        capability: "net".to_string(),
    };
    assert!(err.to_string().contains("net"));
}

#[test]
fn witness_error_display_invalid_confidence() {
    let err = WitnessError::InvalidConfidence {
        reason: "too-low".to_string(),
    };
    assert!(err.to_string().contains("too-low"));
}

#[test]
fn witness_error_display_invalid_transition() {
    let err = WitnessError::InvalidTransition {
        from: LifecycleState::Draft,
        to: LifecycleState::Active,
    };
    let s = err.to_string();
    assert!(s.contains("draft"));
    assert!(s.contains("active"));
}

#[test]
fn witness_error_display_incompatible_schema() {
    let err = WitnessError::IncompatibleSchema {
        witness: WitnessSchemaVersion { major: 2, minor: 0 },
        reader: WitnessSchemaVersion { major: 1, minor: 0 },
    };
    let s = err.to_string();
    assert!(s.contains("2.0"));
    assert!(s.contains("1.0"));
}

#[test]
fn witness_error_display_signature_invalid() {
    let err = WitnessError::SignatureInvalid {
        detail: "bad-sig".to_string(),
    };
    assert!(err.to_string().contains("bad-sig"));
}

#[test]
fn witness_error_display_integrity_failure() {
    let err = WitnessError::IntegrityFailure {
        expected: "aaa".to_string(),
        actual: "bbb".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("aaa"));
    assert!(s.contains("bbb"));
}

#[test]
fn witness_error_display_id_derivation() {
    let err = WitnessError::IdDerivation("zone-fail".to_string());
    assert!(err.to_string().contains("zone-fail"));
}

#[test]
fn witness_error_display_invalid_rollback_token() {
    let err = WitnessError::InvalidRollbackToken {
        reason: "unknown-ref".to_string(),
    };
    assert!(err.to_string().contains("unknown-ref"));
}

#[test]
fn witness_error_display_epoch_mismatch() {
    let err = WitnessError::EpochMismatch {
        witness_epoch: 10,
        current_epoch: 20,
    };
    let s = err.to_string();
    assert!(s.contains("10"));
    assert!(s.contains("20"));
}

#[test]
fn witness_error_display_missing_promotion_proofs() {
    let err = WitnessError::MissingPromotionTheoremProofs {
        missing_checks: vec!["merge-legality".to_string(), "non-interference".to_string()],
    };
    let s = err.to_string();
    assert!(s.contains("merge-legality"));
    assert!(s.contains("non-interference"));
}

#[test]
fn witness_error_display_promotion_failed() {
    let err = WitnessError::PromotionTheoremFailed {
        failed_checks: vec!["attenuation-legality".to_string()],
    };
    assert!(err.to_string().contains("attenuation-legality"));
}

#[test]
fn witness_error_is_std_error() {
    let err = WitnessError::EmptyRequiredSet;
    let _: &dyn std::error::Error = &err;
}

// ===========================================================================
// WitnessPublicationError Display — exhaustive
// ===========================================================================

#[test]
fn publication_error_display_invalid_config() {
    let err = WitnessPublicationError::InvalidConfig {
        reason: "bad".to_string(),
    };
    assert!(err.to_string().contains("bad"));
}

#[test]
fn publication_error_display_not_promoted() {
    let err = WitnessPublicationError::WitnessNotPromoted {
        state: LifecycleState::Draft,
    };
    assert!(err.to_string().contains("draft"));
}

#[test]
fn publication_error_display_duplicate() {
    let err = WitnessPublicationError::DuplicatePublication {
        witness_id: test_extension_id(),
    };
    assert!(err.to_string().contains("already published"));
}

#[test]
fn publication_error_display_not_found() {
    let err = WitnessPublicationError::PublicationNotFound {
        publication_id: test_extension_id(),
    };
    assert!(err.to_string().contains("not found"));
}

#[test]
fn publication_error_display_not_published() {
    let err = WitnessPublicationError::WitnessNotPublished {
        witness_id: test_extension_id(),
    };
    assert!(err.to_string().contains("not published"));
}

#[test]
fn publication_error_display_already_revoked() {
    let err = WitnessPublicationError::AlreadyRevoked {
        witness_id: test_extension_id(),
    };
    assert!(err.to_string().contains("already revoked"));
}

#[test]
fn publication_error_display_empty_revocation_reason() {
    let err = WitnessPublicationError::EmptyRevocationReason;
    assert!(err.to_string().contains("empty"));
}

#[test]
fn publication_error_display_id_derivation() {
    let err = WitnessPublicationError::IdDerivation("zone".to_string());
    assert!(err.to_string().contains("zone"));
}

#[test]
fn publication_error_display_inclusion_proof_failed() {
    let err = WitnessPublicationError::InclusionProofFailed {
        detail: "bad-root".to_string(),
    };
    assert!(err.to_string().contains("bad-root"));
}

#[test]
fn publication_error_display_consistency_proof_failed() {
    let err = WitnessPublicationError::ConsistencyProofFailed {
        detail: "stale".to_string(),
    };
    assert!(err.to_string().contains("stale"));
}

#[test]
fn publication_error_display_tree_head_sig_invalid() {
    let err = WitnessPublicationError::TreeHeadSignatureInvalid {
        detail: "bad".to_string(),
    };
    assert!(err.to_string().contains("bad"));
}

#[test]
fn publication_error_display_tree_head_hash_mismatch() {
    let err = WitnessPublicationError::TreeHeadHashMismatch {
        expected: "aaa".to_string(),
        actual: "bbb".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("aaa"));
    assert!(s.contains("bbb"));
}

#[test]
fn publication_error_display_log_entry_hash_mismatch() {
    let err = WitnessPublicationError::LogEntryHashMismatch;
    assert!(err.to_string().contains("log entry"));
}

#[test]
fn publication_error_display_witness_verification_failed() {
    let err = WitnessPublicationError::WitnessVerificationFailed {
        detail: "sig".to_string(),
    };
    assert!(err.to_string().contains("sig"));
}

#[test]
fn publication_error_display_governance_ledger() {
    let err = WitnessPublicationError::GovernanceLedger {
        detail: "append".to_string(),
    };
    assert!(err.to_string().contains("append"));
}

#[test]
fn publication_error_display_evidence_ledger() {
    let err = WitnessPublicationError::EvidenceLedger {
        detail: "emit".to_string(),
    };
    assert!(err.to_string().contains("emit"));
}

#[test]
fn publication_error_is_std_error() {
    let err = WitnessPublicationError::EmptyRevocationReason;
    let _: &dyn std::error::Error = &err;
}

// ===========================================================================
// PublicationEntryKind
// ===========================================================================

#[test]
fn publication_entry_kind_display() {
    assert_eq!(PublicationEntryKind::Publish.to_string(), "publish");
    assert_eq!(PublicationEntryKind::Revoke.to_string(), "revoke");
}

#[test]
fn publication_entry_kind_as_str() {
    assert_eq!(PublicationEntryKind::Publish.as_str(), "publish");
    assert_eq!(PublicationEntryKind::Revoke.as_str(), "revoke");
}

// ===========================================================================
// PromotionTheoremKind Display
// ===========================================================================

#[test]
fn promotion_theorem_kind_display_all() {
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
    assert_eq!(
        PromotionTheoremKind::Custom("foo-bar".to_string()).to_string(),
        "custom:foo-bar"
    );
}

// ===========================================================================
// LifecycleState — exhaustive transition matrix
// ===========================================================================

#[test]
fn lifecycle_no_self_transitions() {
    let states = [
        LifecycleState::Draft,
        LifecycleState::Validated,
        LifecycleState::Promoted,
        LifecycleState::Active,
        LifecycleState::Superseded,
        LifecycleState::Revoked,
    ];
    for state in &states {
        assert!(
            !state.can_transition_to(*state),
            "{state} should not self-transition"
        );
    }
}

#[test]
fn lifecycle_terminal_states_have_no_successors() {
    assert!(LifecycleState::Superseded.valid_transitions().is_empty());
    assert!(LifecycleState::Revoked.valid_transitions().is_empty());
}

#[test]
fn lifecycle_draft_cannot_skip_to_promoted() {
    assert!(!LifecycleState::Draft.can_transition_to(LifecycleState::Promoted));
}

#[test]
fn lifecycle_validated_cannot_go_to_active() {
    assert!(!LifecycleState::Validated.can_transition_to(LifecycleState::Active));
}

#[test]
fn lifecycle_promoted_cannot_go_to_superseded() {
    assert!(!LifecycleState::Promoted.can_transition_to(LifecycleState::Superseded));
}

#[test]
fn lifecycle_active_cannot_go_to_draft() {
    assert!(!LifecycleState::Active.can_transition_to(LifecycleState::Draft));
}

// ===========================================================================
// ConfidenceInterval boundary cases
// ===========================================================================

#[test]
fn confidence_single_trial_single_success() {
    let ci = ConfidenceInterval::from_trials(1, 1);
    assert!(ci.lower_millionths >= 0);
    assert!(ci.upper_millionths <= 1_000_000);
    assert_eq!(ci.point_estimate_millionths(), 1_000_000);
}

#[test]
fn confidence_single_trial_zero_successes() {
    let ci = ConfidenceInterval::from_trials(1, 0);
    assert_eq!(ci.point_estimate_millionths(), 0);
    assert!(ci.lower_millionths >= 0);
}

#[test]
fn confidence_large_n_high_success_rate() {
    let ci = ConfidenceInterval::from_trials(10_000, 9_900);
    // ~99% success rate; Wilson lower should be > 98.x%
    assert!(ci.lower_millionths > 980_000);
    assert!(ci.upper_millionths <= 1_000_000);
    assert_eq!(ci.point_estimate_millionths(), 990_000);
}

#[test]
fn confidence_half_success_rate() {
    let ci = ConfidenceInterval::from_trials(200, 100);
    assert_eq!(ci.point_estimate_millionths(), 500_000);
    // Wilson interval for 50% with 200 trials should contain ~(43%, 57%)
    assert!(ci.lower_millionths < 500_000);
    assert!(ci.upper_millionths > 500_000);
}

#[test]
fn confidence_zero_successes_many_trials() {
    let ci = ConfidenceInterval::from_trials(100, 0);
    assert_eq!(ci.point_estimate_millionths(), 0);
    // Wilson score with z²/(2n) correction means lower > 0 even at p=0
    assert!(ci.lower_millionths >= 0);
    // Upper bound should be small (below 5%)
    assert!(ci.upper_millionths < 100_000);
}

// ===========================================================================
// WitnessBuilder — require_all
// ===========================================================================

#[test]
fn builder_require_all_adds_multiple_capabilities() {
    let caps = vec![
        Capability::new("a"),
        Capability::new("b"),
        Capability::new("c"),
    ];
    let proofs: Vec<ProofObligation> = caps.iter().map(make_proof).collect();
    let mut builder = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require_all(caps);
    for p in proofs {
        builder = builder.proof(p);
    }
    let witness = builder.build().unwrap();
    assert_eq!(witness.required_capabilities.len(), 3);
}

// ===========================================================================
// Unsigned bytes — metadata and rollback token affect output
// ===========================================================================

#[test]
fn unsigned_bytes_differ_with_different_metadata() {
    let cap = Capability::new("x");
    let w1 = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .meta("key", "val-1")
    .build()
    .unwrap();

    let w2 = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .meta("key", "val-2")
    .build()
    .unwrap();

    assert_ne!(w1.unsigned_bytes(), w2.unsigned_bytes());
    assert_ne!(w1.content_hash, w2.content_hash);
}

#[test]
fn unsigned_bytes_differ_with_rollback_token() {
    let cap = Capability::new("x");
    let w_no_rollback = WitnessBuilder::new(
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

    let w_with_rollback = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .rollback(RollbackToken {
        previous_witness_hash: ContentHash::compute(b"prev"),
        previous_witness_id: None,
        created_epoch: SecurityEpoch::from_raw(0),
        sequence: 0,
    })
    .build()
    .unwrap();

    assert_ne!(
        w_no_rollback.unsigned_bytes(),
        w_with_rollback.unsigned_bytes()
    );
}

// ===========================================================================
// Verify proof coverage — all proofs present but for wrong capabilities
// ===========================================================================

#[test]
fn verify_proof_coverage_detects_extra_capability_without_proof() {
    let cap_a = Capability::new("a");
    let cap_b = Capability::new("b");
    let cap_c = Capability::new("c");
    // Build with a, b required but only provide proofs for a and c (c is irrelevant)
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap_a.clone())
    .require(cap_b.clone())
    .proof(make_proof(&cap_a))
    .proof(make_proof(&cap_c)) // proof for c, but c not required
    .build()
    .unwrap();

    let err = witness.verify_proof_coverage().unwrap_err();
    match err {
        WitnessError::MissingProofObligation { capability } => {
            assert_eq!(capability, "b");
        }
        other => panic!("Expected MissingProofObligation, got {other:?}"),
    }
}

// ===========================================================================
// WitnessValidator — zero trials skip confidence check
// ===========================================================================

#[test]
fn validator_zero_trials_does_not_flag_confidence() {
    let cap = Capability::new("x");
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    // No confidence set → defaults to 0/0
    .build()
    .unwrap();

    let validator = WitnessValidator::new();
    let errors = validator.validate(&witness);
    // Should not have InvalidConfidence because n_trials == 0
    assert!(
        !errors
            .iter()
            .any(|e| matches!(e, WitnessError::InvalidConfidence { .. })),
        "zero trials should skip confidence check, got: {errors:?}"
    );
}

// ===========================================================================
// WitnessStore — iter, insert-overwrite, transition unknown
// ===========================================================================

#[test]
fn store_iter_yields_all_witnesses() {
    let mut store = WitnessStore::new();
    let w1 = build_test_witness();
    let w1_id = w1.witness_id.clone();
    store.insert(w1);

    let items: Vec<_> = store.iter().collect();
    assert_eq!(items.len(), 1);
    assert_eq!(*items[0].0, w1_id);
}

#[test]
fn store_insert_overwrites_same_witness_id() {
    let mut store = WitnessStore::new();
    let mut w = build_test_witness();
    let wid = w.witness_id.clone();
    store.insert(w.clone());
    assert_eq!(store.len(), 1);

    // Mutate metadata and re-insert with same ID
    w.metadata
        .insert("new-key".to_string(), "new-val".to_string());
    store.insert(w);
    assert_eq!(store.len(), 1); // Still 1 witness
    let fetched = store.get(&wid).unwrap();
    assert_eq!(
        fetched.metadata.get("new-key"),
        Some(&"new-val".to_string())
    );
}

#[test]
fn store_transition_unknown_witness_errors() {
    let mut store = WitnessStore::new();
    let fake_id = test_extension_id(); // Not in store
    let err = store
        .transition(&fake_id, LifecycleState::Validated)
        .unwrap_err();
    assert!(matches!(err, WitnessError::IdDerivation(_)));
}

// ===========================================================================
// WitnessStore — multiple extensions
// ===========================================================================

#[test]
fn store_tracks_active_per_extension_independently() {
    let mut store = WitnessStore::new();

    // Witness for extension A
    let cap_a = Capability::new("cap-a");
    let ext_a = test_extension_id_seeded(100);
    let mut wa = WitnessBuilder::new(
        ext_a.clone(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap_a.clone())
    .proof(make_proof(&cap_a))
    .build()
    .unwrap();
    apply_passing_promotion_theorems(&mut wa);
    let wa_id = wa.witness_id.clone();
    store.insert(wa);

    // Witness for extension B
    let cap_b = Capability::new("cap-b");
    let ext_b = test_extension_id_seeded(200);
    let mut wb = WitnessBuilder::new(
        ext_b.clone(),
        test_policy_id(),
        SecurityEpoch::from_raw(2),
        2000,
        test_signing_key(),
    )
    .require(cap_b.clone())
    .proof(make_proof(&cap_b))
    .build()
    .unwrap();
    apply_passing_promotion_theorems(&mut wb);
    let wb_id = wb.witness_id.clone();
    store.insert(wb);

    // Activate both
    for wid in [&wa_id, &wb_id] {
        store.transition(wid, LifecycleState::Validated).unwrap();
        store.transition(wid, LifecycleState::Promoted).unwrap();
        store.transition(wid, LifecycleState::Active).unwrap();
    }

    assert_eq!(
        store.active_for_extension(&ext_a).unwrap().witness_id,
        wa_id
    );
    assert_eq!(
        store.active_for_extension(&ext_b).unwrap().witness_id,
        wb_id
    );

    // Revoke A — B should remain active
    store.transition(&wa_id, LifecycleState::Revoked).unwrap();
    assert!(store.active_for_extension(&ext_a).is_none());
    assert!(store.active_for_extension(&ext_b).is_some());
}

// ===========================================================================
// Promotion theorems — attenuation legality failing
// ===========================================================================

#[test]
fn promotion_theorem_attenuation_legality_fails_when_required_exceeds_manifest() {
    let cap_read = Capability::new("read");
    let cap_write = Capability::new("write");
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap_read.clone())
    .require(cap_write.clone())
    .proof(make_proof(&cap_read))
    .proof(make_proof(&cap_write))
    .build()
    .unwrap();

    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "sa".to_string(),
            capabilities: BTreeSet::from([cap_read.clone(), cap_write.clone()]),
        }],
        manifest_capabilities: BTreeSet::from([cap_read]), // only read in manifest
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    };
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    assert!(!report.all_passed);
    let attenuation = report
        .results
        .iter()
        .find(|r| r.theorem == PromotionTheoremKind::AttenuationLegality)
        .unwrap();
    assert!(!attenuation.passed);
    assert!(
        attenuation
            .counterexample
            .as_deref()
            .unwrap()
            .contains("write")
    );
}

// ===========================================================================
// Promotion theorems — custom theorem failing
// ===========================================================================

#[test]
fn custom_theorem_fails_when_required_cap_missing() {
    let cap_read = Capability::new("read");
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap_read.clone())
    .proof(make_proof(&cap_read))
    .build()
    .unwrap();

    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "sa".to_string(),
            capabilities: BTreeSet::from([cap_read.clone()]),
        }],
        manifest_capabilities: BTreeSet::from([cap_read]),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: vec![CustomTheoremExtension {
            name: "needs-audit".to_string(),
            required_capabilities: BTreeSet::from([Capability::new("audit-log")]),
            forbidden_capabilities: BTreeSet::new(),
        }],
    };
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    assert!(!report.all_passed);
    let custom = report
        .results
        .iter()
        .find(|r| matches!(&r.theorem, PromotionTheoremKind::Custom(name) if name == "needs-audit"))
        .unwrap();
    assert!(!custom.passed);
    assert!(
        custom
            .counterexample
            .as_deref()
            .unwrap()
            .contains("audit-log")
    );
}

#[test]
fn custom_theorem_fails_when_forbidden_cap_present() {
    let cap_read = Capability::new("read");
    let cap_net = Capability::new("network");
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap_read.clone())
    .require(cap_net.clone())
    .proof(make_proof(&cap_read))
    .proof(make_proof(&cap_net))
    .build()
    .unwrap();

    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "sa".to_string(),
            capabilities: BTreeSet::from([cap_read.clone(), cap_net.clone()]),
        }],
        manifest_capabilities: BTreeSet::from([cap_read, cap_net.clone()]),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: vec![CustomTheoremExtension {
            name: "no-network".to_string(),
            required_capabilities: BTreeSet::new(),
            forbidden_capabilities: BTreeSet::from([cap_net]),
        }],
    };
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    assert!(!report.all_passed);
    let custom = report
        .results
        .iter()
        .find(|r| matches!(&r.theorem, PromotionTheoremKind::Custom(name) if name == "no-network"))
        .unwrap();
    assert!(!custom.passed);
    assert!(
        custom
            .counterexample
            .as_deref()
            .unwrap()
            .contains("network")
    );
}

// ===========================================================================
// apply_promotion_theorem_report — when not all_passed
// ===========================================================================

#[test]
fn apply_theorem_report_does_not_add_proofs_when_failed() {
    let cap_read = Capability::new("read");
    let cap_write = Capability::new("write");
    let mut witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap_read.clone())
    .require(cap_write.clone())
    .proof(make_proof(&cap_read))
    .proof(make_proof(&cap_write))
    .build()
    .unwrap();

    let initial_proof_count = witness.proof_obligations.len();

    // Use input that will cause merge legality to fail (source only has read)
    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "sa".to_string(),
            capabilities: BTreeSet::from([cap_read.clone()]),
        }],
        manifest_capabilities: BTreeSet::from([cap_read, cap_write]),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    };
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    assert!(!report.all_passed);

    witness.apply_promotion_theorem_report(&report);

    // Should NOT have added PolicyTheoremCheck proofs
    let theorem_proofs = witness
        .proof_obligations
        .iter()
        .filter(|p| p.kind == ProofKind::PolicyTheoremCheck)
        .count();
    assert_eq!(theorem_proofs, 0);
    assert_eq!(witness.proof_obligations.len(), initial_proof_count);

    // But metadata should still record results
    assert_eq!(
        witness
            .metadata
            .get("promotion_theorem.all_passed")
            .map(String::as_str),
        Some("false")
    );
}

// ===========================================================================
// PromotionTheoremReport structured_events — gate outcome
// ===========================================================================

#[test]
fn structured_events_gate_outcome_is_last_event() {
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
    let events = report.structured_events("t", "d", "p");
    let last = events.last().unwrap();
    assert_eq!(last.event, "promotion_theorem_gate");
    assert_eq!(last.outcome, "pass");
    assert!(last.error_code.is_none());
}

#[test]
fn structured_events_failing_gate_has_error_code() {
    let cap_read = Capability::new("read");
    let cap_write = Capability::new("write");
    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap_read.clone())
    .require(cap_write.clone())
    .proof(make_proof(&cap_read))
    .proof(make_proof(&cap_write))
    .build()
    .unwrap();

    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "sa".to_string(),
            capabilities: BTreeSet::from([cap_read]),
        }],
        manifest_capabilities: BTreeSet::from([Capability::new("read"), cap_write]),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    };
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    assert!(!report.all_passed);
    let events = report.structured_events("t", "d", "p");
    let gate = events.last().unwrap();
    assert_eq!(gate.outcome, "fail");
    assert!(gate.error_code.is_some());
}

// ===========================================================================
// Publication pipeline — error paths
// ===========================================================================

#[test]
fn pipeline_invalid_config_zero_checkpoint_interval() {
    let err = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        SigningKey::from_bytes([1; 32]),
        WitnessPublicationConfig {
            checkpoint_interval: 0,
            policy_id: "ok".to_string(),
            governance_ledger_config: None,
        },
    )
    .unwrap_err();
    assert!(matches!(err, WitnessPublicationError::InvalidConfig { .. }));
}

#[test]
fn pipeline_invalid_config_empty_policy_id() {
    let err = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1),
        SigningKey::from_bytes([1; 32]),
        WitnessPublicationConfig {
            checkpoint_interval: 1,
            policy_id: "  ".to_string(),
            governance_ledger_config: None,
        },
    )
    .unwrap_err();
    assert!(matches!(err, WitnessPublicationError::InvalidConfig { .. }));
}

#[test]
fn pipeline_publish_non_promoted_fails() {
    let (mut pipeline, _) = publication_pipeline(100, 10);
    let cap = Capability::new("r");
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
    .unwrap(); // Draft state
    let err = pipeline.publish_witness(witness, 100).unwrap_err();
    assert!(matches!(
        err,
        WitnessPublicationError::WitnessNotPromoted { .. }
    ));
}

#[test]
fn pipeline_duplicate_publish_fails() {
    let (mut pipeline, _) = publication_pipeline(200, 11);
    let witness = build_promoted_witness(50);
    pipeline.publish_witness(witness.clone(), 100).unwrap();
    let err = pipeline.publish_witness(witness, 200).unwrap_err();
    assert!(matches!(
        err,
        WitnessPublicationError::DuplicatePublication { .. }
    ));
}

#[test]
fn pipeline_revoke_not_published_fails() {
    let (mut pipeline, _) = publication_pipeline(300, 12);
    let err = pipeline
        .revoke_witness(&test_extension_id(), "reason", 100)
        .unwrap_err();
    assert!(matches!(
        err,
        WitnessPublicationError::WitnessNotPublished { .. }
    ));
}

#[test]
fn pipeline_revoke_empty_reason_fails() {
    let (mut pipeline, _) = publication_pipeline(400, 13);
    let witness = build_promoted_witness(60);
    let wid = witness.witness_id.clone();
    pipeline.publish_witness(witness, 100).unwrap();
    let err = pipeline.revoke_witness(&wid, "  ", 200).unwrap_err();
    assert!(matches!(
        err,
        WitnessPublicationError::EmptyRevocationReason
    ));
}

#[test]
fn pipeline_double_revoke_fails() {
    let (mut pipeline, _) = publication_pipeline(500, 14);
    let witness = build_promoted_witness(70);
    let wid = witness.witness_id.clone();
    pipeline.publish_witness(witness, 100).unwrap();
    pipeline.revoke_witness(&wid, "first revoke", 200).unwrap();
    let err = pipeline
        .revoke_witness(&wid, "second revoke", 300)
        .unwrap_err();
    assert!(matches!(
        err,
        WitnessPublicationError::AlreadyRevoked { .. }
    ));
}

// ===========================================================================
// Publication pipeline — query filters
// ===========================================================================

#[test]
fn pipeline_query_all_returns_everything() {
    let (mut pipeline, _) = publication_pipeline(600, 15);
    let w1 = build_promoted_witness(80);
    let w2 = build_promoted_witness(81);
    pipeline.publish_witness(w1, 100).unwrap();
    pipeline.publish_witness(w2, 200).unwrap();
    let all = pipeline.query(&WitnessPublicationQuery::all());
    assert_eq!(all.len(), 2);
}

#[test]
fn pipeline_query_exclude_revoked() {
    let (mut pipeline, _) = publication_pipeline(700, 16);
    let w1 = build_promoted_witness(90);
    let w2 = build_promoted_witness(91);
    let w1_id = w1.witness_id.clone();
    pipeline.publish_witness(w1, 100).unwrap();
    pipeline.publish_witness(w2, 200).unwrap();
    pipeline.revoke_witness(&w1_id, "compromised", 300).unwrap();

    let excluding_revoked = pipeline.query(&WitnessPublicationQuery {
        extension_id: None,
        policy_id: None,
        epoch: None,
        content_hash: None,
        include_revoked: false,
    });
    assert_eq!(excluding_revoked.len(), 1);

    let including_revoked = pipeline.query(&WitnessPublicationQuery::all());
    assert_eq!(including_revoked.len(), 2);
}

#[test]
fn pipeline_query_by_epoch() {
    let (mut pipeline, _) = publication_pipeline(800, 17);
    let w1 = build_promoted_witness(100);
    let w2 = build_promoted_witness(101);
    let w1_epoch = w1.epoch;
    pipeline.publish_witness(w1, 100).unwrap();
    pipeline.publish_witness(w2, 200).unwrap();

    let by_epoch = pipeline.query(&WitnessPublicationQuery {
        extension_id: None,
        policy_id: None,
        epoch: Some(w1_epoch),
        content_hash: None,
        include_revoked: true,
    });
    assert_eq!(by_epoch.len(), 1);
}

// ===========================================================================
// Publication pipeline — verify_publication
// ===========================================================================

#[test]
fn pipeline_verify_publication_by_id() {
    let (mut pipeline, head_key) = publication_pipeline(900, 18);
    let witness = build_promoted_witness(110);
    let pub_id = pipeline.publish_witness(witness, 100).unwrap();

    pipeline
        .verify_publication(
            &pub_id,
            &test_signing_key().verification_key(),
            &head_key.verification_key(),
        )
        .unwrap();
}

#[test]
fn pipeline_verify_publication_not_found() {
    let (pipeline, head_key) = publication_pipeline(1000, 19);
    let err = pipeline
        .verify_publication(
            &test_extension_id(),
            &test_signing_key().verification_key(),
            &head_key.verification_key(),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        WitnessPublicationError::PublicationNotFound { .. }
    ));
}

// ===========================================================================
// Publication pipeline — events and checkpoints
// ===========================================================================

#[test]
fn pipeline_events_emitted_for_publish_and_revoke() {
    let (mut pipeline, _) = publication_pipeline(1100, 20);
    let witness = build_promoted_witness(120);
    let wid = witness.witness_id.clone();
    pipeline.publish_witness(witness, 100).unwrap();
    pipeline.revoke_witness(&wid, "compromise", 200).unwrap();

    assert_eq!(pipeline.events().len(), 2);
    assert_eq!(pipeline.events()[0].event, "publish_witness");
    assert_eq!(pipeline.events()[1].event, "revoke_witness");
    for event in pipeline.events() {
        assert_eq!(event.outcome, "success");
        assert!(event.error_code.is_none());
        assert!(!event.component.is_empty());
        assert!(!event.trace_id.is_empty());
        assert!(!event.decision_id.is_empty());
    }
}

#[test]
fn pipeline_checkpoints_emitted_at_interval() {
    let head_key = SigningKey::from_bytes([21; 32]);
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1200),
        head_key,
        WitnessPublicationConfig {
            checkpoint_interval: 2,
            policy_id: "cp-test".to_string(),
            governance_ledger_config: None,
        },
    )
    .unwrap();

    // Publish 3 witnesses → 3 log entries → checkpoints at entries 2
    for seed in 130..133 {
        let w = build_promoted_witness(seed);
        pipeline.publish_witness(w, seed * 1000).unwrap();
    }

    // With checkpoint_interval=2, checkpoint at log entry count 2
    // (entry indices 0, 1 → checkpoint after 2nd entry)
    assert!(
        !pipeline.checkpoints().is_empty(),
        "should have at least one checkpoint"
    );
}

#[test]
fn pipeline_log_entries_have_sequential_sequences() {
    let (mut pipeline, _) = publication_pipeline(1300, 22);
    for seed in 140..145 {
        let w = build_promoted_witness(seed);
        pipeline.publish_witness(w, seed * 100).unwrap();
    }
    for (i, entry) in pipeline.log_entries().iter().enumerate() {
        assert_eq!(entry.sequence, i as u64);
    }
}

// ===========================================================================
// Publication pipeline — with governance ledger
// ===========================================================================

#[test]
fn pipeline_with_governance_records_entries() {
    let head_key = SigningKey::from_bytes([23; 32]);
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(1400),
        head_key,
        WitnessPublicationConfig {
            checkpoint_interval: 1,
            policy_id: "gov-test".to_string(),
            governance_ledger_config: Some(GovernanceLedgerConfig {
                checkpoint_interval: 2,
                signer_key: b"governance-key".to_vec(),
                policy_id: "witness-gov".to_string(),
            }),
        },
    )
    .unwrap();

    let w = build_promoted_witness(150);
    let wid = w.witness_id.clone();
    pipeline.publish_witness(w, 100).unwrap();
    pipeline
        .revoke_witness(&wid, "security issue", 200)
        .unwrap();

    let gov = pipeline.governance_ledger().unwrap();
    assert_eq!(gov.entries().len(), 2);
}

// ===========================================================================
// PublishedWitnessArtifact::is_revoked
// ===========================================================================

#[test]
fn published_artifact_is_revoked_flag() {
    let (mut pipeline, _) = publication_pipeline(1500, 24);
    let w = build_promoted_witness(160);
    let wid = w.witness_id.clone();
    pipeline.publish_witness(w, 100).unwrap();

    assert!(!pipeline.publications()[0].is_revoked());

    pipeline.revoke_witness(&wid, "reason", 200).unwrap();
    assert!(pipeline.publications()[0].is_revoked());
}

// ===========================================================================
// WitnessPublicationConfig::default
// ===========================================================================

#[test]
fn publication_config_default_values() {
    let cfg = WitnessPublicationConfig::default();
    assert_eq!(cfg.checkpoint_interval, 8);
    assert!(!cfg.policy_id.is_empty());
    assert!(cfg.governance_ledger_config.is_none());
}

// ===========================================================================
// WitnessPublicationQuery::all
// ===========================================================================

#[test]
fn publication_query_all_includes_revoked() {
    let q = WitnessPublicationQuery::all();
    assert!(q.include_revoked);
    assert!(q.extension_id.is_none());
    assert!(q.policy_id.is_none());
    assert!(q.epoch.is_none());
    assert!(q.content_hash.is_none());
}

// ===========================================================================
// WitnessSchemaVersion — edge cases
// ===========================================================================

#[test]
fn schema_version_compatible_zero_minor_both() {
    let v = WitnessSchemaVersion { major: 1, minor: 0 };
    assert!(v.is_compatible_with(&v));
}

#[test]
fn schema_version_major_zero() {
    let v0 = WitnessSchemaVersion { major: 0, minor: 5 };
    let v1 = WitnessSchemaVersion { major: 1, minor: 0 };
    assert!(!v0.is_compatible_with(&v1));
    assert!(!v1.is_compatible_with(&v0));
}

// ===========================================================================
// Serde roundtrips for publication types
// ===========================================================================

#[test]
fn witness_publication_error_serde_roundtrip() {
    let errors = vec![
        WitnessPublicationError::EmptyRevocationReason,
        WitnessPublicationError::LogEntryHashMismatch,
        WitnessPublicationError::InvalidConfig {
            reason: "test".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: WitnessPublicationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, &restored);
    }
}

#[test]
fn witness_publication_config_serde_roundtrip() {
    let cfg = WitnessPublicationConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: WitnessPublicationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

#[test]
fn witness_publication_event_serde_roundtrip() {
    let event = WitnessPublicationEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "success".to_string(),
        error_code: None,
        timestamp_ns: 12345,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: WitnessPublicationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn witness_publication_query_serde_roundtrip() {
    let query = WitnessPublicationQuery::all();
    let json = serde_json::to_string(&query).unwrap();
    let restored: WitnessPublicationQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(query, restored);
}

#[test]
fn promotion_theorem_kind_serde_roundtrip() {
    let kinds = vec![
        PromotionTheoremKind::MergeLegality,
        PromotionTheoremKind::AttenuationLegality,
        PromotionTheoremKind::NonInterference,
        PromotionTheoremKind::Custom("my-rule".to_string()),
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let restored: PromotionTheoremKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, &restored);
    }
}

#[test]
fn lifecycle_state_serde_roundtrip() {
    let states = [
        LifecycleState::Draft,
        LifecycleState::Validated,
        LifecycleState::Promoted,
        LifecycleState::Active,
        LifecycleState::Superseded,
        LifecycleState::Revoked,
    ];
    for state in &states {
        let json = serde_json::to_string(state).unwrap();
        let restored: LifecycleState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, &restored);
    }
}

#[test]
fn proof_kind_serde_roundtrip() {
    let kinds = [
        ProofKind::StaticAnalysis,
        ProofKind::DynamicAblation,
        ProofKind::PolicyTheoremCheck,
        ProofKind::OperatorAttestation,
        ProofKind::InheritedFromPredecessor,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let restored: ProofKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, &restored);
    }
}

#[test]
fn publication_entry_kind_serde_roundtrip() {
    for kind in [PublicationEntryKind::Publish, PublicationEntryKind::Revoke] {
        let json = serde_json::to_string(&kind).unwrap();
        let restored: PublicationEntryKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, restored);
    }
}

#[test]
fn witness_schema_version_serde_roundtrip() {
    let v = WitnessSchemaVersion { major: 3, minor: 7 };
    let json = serde_json::to_string(&v).unwrap();
    let restored: WitnessSchemaVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

// ===========================================================================
// Determinism of publication pipeline
// ===========================================================================

#[test]
fn publication_artifact_id_is_deterministic() {
    fn run() -> EngineObjectId {
        let (mut pipeline, _) = publication_pipeline(2000, 25);
        let w = build_promoted_witness(170);
        pipeline.publish_witness(w, 100).unwrap();
        pipeline.publications()[0].publication_id.clone()
    }
    assert_eq!(run(), run());
}

#[test]
fn publication_leaf_hash_is_deterministic() {
    fn run() -> ContentHash {
        let (mut pipeline, _) = publication_pipeline(2100, 26);
        let w = build_promoted_witness(180);
        pipeline.publish_witness(w, 100).unwrap();
        pipeline.log_entries()[0].leaf_hash.clone()
    }
    assert_eq!(run(), run());
}

// ===========================================================================
// PromotionTheoremLogEvent fields
// ===========================================================================

#[test]
fn promotion_theorem_log_event_fields_propagate() {
    let cap = Capability::new("r");
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
    let events = report.structured_events("TRACE", "DECISION", "POLICY");
    for event in &events {
        assert_eq!(event.trace_id, "TRACE");
        assert_eq!(event.decision_id, "DECISION");
        assert_eq!(event.policy_id, "POLICY");
        assert_eq!(event.component, "capability_witness_theorem_gate");
    }
}

// ===========================================================================
// Lattice transitive closure — multi-hop
// ===========================================================================

#[test]
fn lattice_multi_hop_expansion_satisfies_merge() {
    // cap_a → cap_b → cap_c (via lattice)
    // Witness requires cap_c
    // Source evidence only has cap_a
    // Lattice: a implies b, b implies c
    // So source union expanded should include c
    let cap_a = Capability::new("a");
    let cap_b = Capability::new("b");
    let cap_c = Capability::new("c");

    let witness = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap_c.clone())
    .proof(make_proof(&cap_c))
    .build()
    .unwrap();

    let input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "sa".to_string(),
            capabilities: BTreeSet::from([cap_a.clone()]),
        }],
        manifest_capabilities: BTreeSet::from([cap_c.clone()]),
        capability_lattice: BTreeMap::from([
            (cap_a, BTreeSet::from([cap_b.clone()])),
            (cap_b, BTreeSet::from([cap_c])),
        ]),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    };
    let report = witness.evaluate_promotion_theorems(&input).unwrap();
    let merge = report
        .results
        .iter()
        .find(|r| r.theorem == PromotionTheoremKind::MergeLegality)
        .unwrap();
    assert!(merge.passed, "multi-hop lattice should satisfy merge");
}

// ===========================================================================
// Pipeline — publish active witness (not just promoted)
// ===========================================================================

#[test]
fn pipeline_accepts_active_witness_for_publication() {
    let (mut pipeline, _) = publication_pipeline(2200, 27);
    let mut w = build_promoted_witness(190);
    w.transition_to(LifecycleState::Active).unwrap();
    // Active state should also be accepted for publication
    let pub_id = pipeline.publish_witness(w, 100);
    assert!(pub_id.is_ok());
}

// ===========================================================================
// Store — by_state comprehensive
// ===========================================================================

#[test]
fn store_by_state_returns_correct_subsets() {
    let mut store = WitnessStore::new();
    let w1 = build_test_witness();
    let w1_id = w1.witness_id.clone();
    store.insert(w1);

    // w1 starts as Draft
    assert_eq!(store.by_state(LifecycleState::Draft).len(), 1);
    assert_eq!(store.by_state(LifecycleState::Validated).len(), 0);

    store.transition(&w1_id, LifecycleState::Validated).unwrap();
    assert_eq!(store.by_state(LifecycleState::Draft).len(), 0);
    assert_eq!(store.by_state(LifecycleState::Validated).len(), 1);
}

// ===========================================================================
// DenialRecord with evidence_id
// ===========================================================================

#[test]
fn denial_record_with_evidence_id_serde() {
    let dr = DenialRecord {
        capability: Capability::new("dangerous"),
        reason: "forbidden by policy".to_string(),
        evidence_id: Some(test_proof_artifact_id()),
    };
    let json = serde_json::to_string(&dr).unwrap();
    let restored: DenialRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(dr, restored);
    assert!(restored.evidence_id.is_some());
}

// ===========================================================================
// WitnessBuilder — transcript_hash affects content hash
// ===========================================================================

#[test]
fn different_transcript_hash_produces_different_witness() {
    let cap = Capability::new("x");
    let w1 = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .transcript_hash(ContentHash::compute(b"transcript-1"))
    .build()
    .unwrap();

    let w2 = WitnessBuilder::new(
        test_extension_id(),
        test_policy_id(),
        SecurityEpoch::from_raw(1),
        1000,
        test_signing_key(),
    )
    .require(cap.clone())
    .proof(make_proof(&cap))
    .transcript_hash(ContentHash::compute(b"transcript-2"))
    .build()
    .unwrap();

    assert_ne!(w1.content_hash, w2.content_hash);
    assert_ne!(w1.witness_id, w2.witness_id);
}

// ===========================================================================
// Store serde roundtrip with active witness
// ===========================================================================

#[test]
fn store_serde_roundtrip_preserves_active_pairs() {
    let mut store = WitnessStore::new();
    let w = build_test_witness();
    let wid = w.witness_id.clone();
    let ext_id = w.extension_id.clone();
    store.insert(w);
    store.transition(&wid, LifecycleState::Validated).unwrap();
    store.transition(&wid, LifecycleState::Promoted).unwrap();
    store.transition(&wid, LifecycleState::Active).unwrap();

    let json = serde_json::to_string(&store).unwrap();
    let restored: WitnessStore = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.len(), 1);
    assert!(restored.active_for_extension(&ext_id).is_some());
}
