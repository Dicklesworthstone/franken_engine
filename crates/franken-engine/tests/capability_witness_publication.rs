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
    CapabilityWitness, ConfidenceInterval, LifecycleState, PromotionTheoremInput, ProofKind,
    ProofObligation, PublicationEntryKind, SourceCapabilitySet, WitnessBuilder,
    WitnessPublicationConfig, WitnessPublicationError, WitnessPublicationEvent,
    WitnessPublicationPipeline, WitnessPublicationQuery,
};
use frankenengine_engine::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_theorem_compiler::Capability;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{SigningKey, sign_preimage};

fn synthesizer_signing_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        *byte = (idx as u8).wrapping_mul(13).wrapping_add(7);
    }
    SigningKey::from_bytes(bytes)
}

fn tree_head_signing_key() -> SigningKey {
    SigningKey::from_bytes([0x44; 32])
}

fn extension_id(seed: u64) -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::Attestation,
        "witness-publication-test-extension",
        &SchemaId::from_definition(b"WitnessPublicationTestExtension.v1"),
        &seed.to_be_bytes(),
    )
    .expect("derive extension id")
}

fn policy_id() -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::PolicyObject,
        "witness-publication-test-policy",
        &SchemaId::from_definition(b"WitnessPublicationTestPolicy.v1"),
        b"policy-main",
    )
    .expect("derive policy id")
}

fn proof_artifact_id(seed: u64) -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::EvidenceRecord,
        "witness-publication-test-proof",
        &SchemaId::from_definition(b"WitnessPublicationTestProof.v1"),
        &seed.to_be_bytes(),
    )
    .expect("derive proof id")
}

fn make_proof(seed: u64, capability: &Capability) -> ProofObligation {
    ProofObligation {
        capability: capability.clone(),
        kind: ProofKind::DynamicAblation,
        proof_artifact_id: proof_artifact_id(seed),
        justification: format!("proof for {}", capability),
        artifact_hash: ContentHash::compute(format!("proof-{seed}-{capability}").as_bytes()),
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
    .expect("derive witness id");

    let signature = sign_preimage(signing_key, &unsigned).expect("sign witness");
    witness.synthesizer_signature = signature.to_bytes().to_vec();
}

fn build_promoted_witness(seed: u64, signing_key: &SigningKey) -> CapabilityWitness {
    let capability = Capability::new(format!("read-slot-{seed}"));
    let mut witness = WitnessBuilder::new(
        extension_id(seed),
        policy_id(),
        SecurityEpoch::from_raw(1_000 + seed),
        100_000 + seed,
        signing_key.clone(),
    )
    .require(capability.clone())
    .proof(make_proof(seed, &capability))
    .confidence(ConfidenceInterval::from_trials(128, 123))
    .replay_seed(seed)
    .transcript_hash(ContentHash::compute(
        format!("transcript-{seed}").as_bytes(),
    ))
    .build()
    .expect("build witness");

    let theorem_input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: format!("source-{seed}"),
            capabilities: witness.required_capabilities.clone(),
        }],
        manifest_capabilities: witness.required_capabilities.clone(),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    };
    let report = witness
        .evaluate_promotion_theorems(&theorem_input)
        .expect("evaluate promotion theorems");
    assert!(report.all_passed, "promotion theorem report must pass");
    witness.apply_promotion_theorem_report(&report);
    rebind_witness(&mut witness, signing_key);

    witness
        .transition_to(LifecycleState::Validated)
        .expect("draft -> validated");
    witness
        .transition_to(LifecycleState::Promoted)
        .expect("validated -> promoted");
    witness
}

fn build_pipeline() -> WitnessPublicationPipeline {
    WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(2_000),
        tree_head_signing_key(),
        WitnessPublicationConfig {
            checkpoint_interval: 1,
            policy_id: "witness-publication-test-policy".to_string(),
            governance_ledger_config: None,
        },
    )
    .expect("build publication pipeline")
}

fn assert_structured_event(event: &WitnessPublicationEvent, expected_event: &str) {
    assert!(!event.trace_id.is_empty(), "trace_id must be present");
    assert!(!event.decision_id.is_empty(), "decision_id must be present");
    assert!(!event.policy_id.is_empty(), "policy_id must be present");
    assert!(!event.component.is_empty(), "component must be present");
    assert_eq!(event.event, expected_event);
    assert_eq!(event.outcome, "success");
    assert_eq!(event.error_code, None);
}

#[test]
fn e2e_publish_revoke_verify_and_query_keeps_stable_event_fields() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();

    let witness = build_promoted_witness(7, &synthesizer_key);
    let witness_id = witness.witness_id.clone();
    let extension_id = witness.extension_id.clone();
    let witness_epoch = witness.epoch;
    let witness_content_hash = witness.content_hash;

    let publication_id = pipeline
        .publish_witness(witness, 90_000)
        .expect("publish witness");
    pipeline
        .verify_publication(
            &publication_id,
            &synthesizer_key.verification_key(),
            &tree_head_signing_key().verification_key(),
        )
        .expect("verify published witness");

    pipeline
        .revoke_witness(&witness_id, "incident drill", 91_000)
        .expect("revoke witness");
    pipeline
        .verify_publication(
            &publication_id,
            &synthesizer_key.verification_key(),
            &tree_head_signing_key().verification_key(),
        )
        .expect("verify revoked witness");

    assert_eq!(pipeline.publications().len(), 1);
    assert!(pipeline.publications()[0].is_revoked());
    assert_eq!(
        pipeline.publications()[0].publication_proof.log_entry.kind,
        PublicationEntryKind::Publish
    );
    assert_eq!(pipeline.evidence_entries().len(), 2);

    let filtered = pipeline.query(&WitnessPublicationQuery {
        extension_id: Some(extension_id),
        policy_id: Some(policy_id()),
        epoch: Some(witness_epoch),
        content_hash: Some(witness_content_hash),
        include_revoked: true,
    });
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].publication_id, publication_id);

    assert_eq!(pipeline.events().len(), 2);
    assert_structured_event(&pipeline.events()[0], "publish_witness");
    assert_structured_event(&pipeline.events()[1], "revoke_witness");
}

#[test]
fn publication_artifact_is_deterministic_for_identical_inputs() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline_a = build_pipeline();
    let mut pipeline_b = build_pipeline();

    let witness_a = build_promoted_witness(99, &synthesizer_key);
    let witness_b = build_promoted_witness(99, &synthesizer_key);

    let publication_id_a = pipeline_a
        .publish_witness(witness_a, 123_456)
        .expect("publish in pipeline A");
    let publication_id_b = pipeline_b
        .publish_witness(witness_b, 123_456)
        .expect("publish in pipeline B");

    let artifact_a = &pipeline_a.publications()[0];
    let artifact_b = &pipeline_b.publications()[0];
    assert_eq!(publication_id_a, publication_id_b);
    assert_eq!(artifact_a.publication_id, artifact_b.publication_id);
    assert_eq!(artifact_a.published_hash, artifact_b.published_hash);
    assert_eq!(
        artifact_a.publication_proof.log_entry.leaf_hash,
        artifact_b.publication_proof.log_entry.leaf_hash
    );
}

#[test]
fn tampered_log_entry_hash_is_rejected_deterministically() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();
    let witness = build_promoted_witness(123, &synthesizer_key);
    pipeline
        .publish_witness(witness, 222_222)
        .expect("publish witness");

    let mut tampered = pipeline.publications()[0].clone();
    tampered.publication_proof.log_entry.leaf_hash = ContentHash([0xAB; 32]);

    let err = WitnessPublicationPipeline::verify_artifact(
        &tampered,
        &synthesizer_key.verification_key(),
        &tree_head_signing_key().verification_key(),
    )
    .expect_err("tampered log entry hash must fail verification");
    assert!(matches!(err, WitnessPublicationError::LogEntryHashMismatch));
}

#[test]
fn capability_divergence_inputs_do_not_leak_into_query_filtering() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();

    let witness_a = build_promoted_witness(10, &synthesizer_key);
    let witness_b = build_promoted_witness(11, &synthesizer_key);
    let w_a_id = witness_a.witness_id.clone();

    pipeline
        .publish_witness(witness_a, 1_000)
        .expect("publish witness A");
    pipeline
        .publish_witness(witness_b, 2_000)
        .expect("publish witness B");
    pipeline
        .revoke_witness(&w_a_id, "test revocation", 3_000)
        .expect("revoke witness A");

    let live_only = pipeline.query(&WitnessPublicationQuery {
        extension_id: None,
        policy_id: None,
        epoch: None,
        content_hash: None,
        include_revoked: false,
    });
    assert_eq!(live_only.len(), 1);

    let all = pipeline.query(&WitnessPublicationQuery::all());
    assert_eq!(all.len(), 2);

    let seen_policy_ids: BTreeSet<_> = all
        .iter()
        .map(|entry| entry.witness.policy_id.clone())
        .collect();
    assert_eq!(seen_policy_ids.len(), 1);
}

// ---------- PublicationEntryKind ----------

#[test]
fn publication_entry_kind_as_str_values() {
    assert_eq!(PublicationEntryKind::Publish.as_str(), "publish");
    assert_eq!(PublicationEntryKind::Revoke.as_str(), "revoke");
}

// ---------- WitnessPublicationQuery ----------

#[test]
fn witness_publication_query_all_includes_revoked() {
    let query = WitnessPublicationQuery::all();
    assert!(query.include_revoked);
    assert!(query.extension_id.is_none());
    assert!(query.policy_id.is_none());
    assert!(query.epoch.is_none());
    assert!(query.content_hash.is_none());
}

// ---------- PublishedWitnessArtifact ----------

#[test]
fn published_witness_artifact_is_not_revoked_before_revocation() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();
    let witness = build_promoted_witness(200, &synthesizer_key);
    pipeline
        .publish_witness(witness, 500_000)
        .expect("publish witness");

    assert!(!pipeline.publications()[0].is_revoked());
}

#[test]
fn published_witness_artifact_is_revoked_after_revocation() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();
    let witness = build_promoted_witness(201, &synthesizer_key);
    let witness_id = witness.witness_id.clone();
    pipeline
        .publish_witness(witness, 500_000)
        .expect("publish witness");
    pipeline
        .revoke_witness(&witness_id, "test revocation", 600_000)
        .expect("revoke witness");

    assert!(pipeline.publications()[0].is_revoked());
}

// ---------- Pipeline error cases ----------

#[test]
fn pipeline_rejects_non_promoted_witness() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();

    let capability = Capability::new("read-slot-unpromoted".to_string());
    let witness = WitnessBuilder::new(
        extension_id(300),
        policy_id(),
        SecurityEpoch::from_raw(1_300),
        100_300,
        synthesizer_key.clone(),
    )
    .require(capability.clone())
    .proof(make_proof(300, &capability))
    .confidence(ConfidenceInterval::from_trials(128, 123))
    .replay_seed(300)
    .transcript_hash(ContentHash::compute(b"transcript-300"))
    .build()
    .expect("build witness");

    let result = pipeline.publish_witness(witness, 700_000);
    assert!(matches!(
        result,
        Err(WitnessPublicationError::WitnessNotPromoted { .. })
    ));
}

#[test]
fn pipeline_rejects_empty_revocation_reason() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();
    let witness = build_promoted_witness(301, &synthesizer_key);
    let witness_id = witness.witness_id.clone();
    pipeline.publish_witness(witness, 800_000).expect("publish");

    let result = pipeline.revoke_witness(&witness_id, "", 900_000);
    assert!(matches!(
        result,
        Err(WitnessPublicationError::EmptyRevocationReason)
    ));
}

#[test]
fn pipeline_rejects_revocation_of_non_existent_witness() {
    let mut pipeline = build_pipeline();
    let fake_id = engine_object_id::derive_id(
        ObjectDomain::Attestation,
        "fake-zone",
        &SchemaId::from_definition(b"Fake.v1"),
        b"fake-data",
    )
    .expect("derive fake id");

    let result = pipeline.revoke_witness(&fake_id, "no such witness", 1_000_000);
    assert!(matches!(
        result,
        Err(WitnessPublicationError::WitnessNotPublished { .. })
    ));
}

#[test]
fn pipeline_rejects_double_revocation() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();
    let witness = build_promoted_witness(302, &synthesizer_key);
    let witness_id = witness.witness_id.clone();
    pipeline
        .publish_witness(witness, 1_100_000)
        .expect("publish");
    pipeline
        .revoke_witness(&witness_id, "first revocation", 1_200_000)
        .expect("first revoke");

    let result = pipeline.revoke_witness(&witness_id, "second revocation", 1_300_000);
    assert!(matches!(
        result,
        Err(WitnessPublicationError::AlreadyRevoked { .. })
    ));
}

// ---------- Pipeline queries ----------

#[test]
fn query_by_epoch_filters_correctly() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();
    let witness_a = build_promoted_witness(400, &synthesizer_key);
    let witness_b = build_promoted_witness(401, &synthesizer_key);
    let epoch_a = witness_a.epoch;

    pipeline
        .publish_witness(witness_a, 2_000_000)
        .expect("publish A");
    pipeline
        .publish_witness(witness_b, 2_100_000)
        .expect("publish B");

    let filtered = pipeline.query(&WitnessPublicationQuery {
        extension_id: None,
        policy_id: None,
        epoch: Some(epoch_a),
        content_hash: None,
        include_revoked: true,
    });
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].witness.epoch, epoch_a);
}

#[test]
fn query_exclude_revoked_filters_revoked_entries() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();
    let witness_a = build_promoted_witness(500, &synthesizer_key);
    let witness_b = build_promoted_witness(501, &synthesizer_key);
    let witness_a_id = witness_a.witness_id.clone();

    pipeline
        .publish_witness(witness_a, 3_000_000)
        .expect("publish A");
    pipeline
        .publish_witness(witness_b, 3_100_000)
        .expect("publish B");
    pipeline
        .revoke_witness(&witness_a_id, "test", 3_200_000)
        .expect("revoke A");

    let live = pipeline.query(&WitnessPublicationQuery {
        extension_id: None,
        policy_id: None,
        epoch: None,
        content_hash: None,
        include_revoked: false,
    });
    assert_eq!(live.len(), 1);

    let all = pipeline.query(&WitnessPublicationQuery::all());
    assert_eq!(all.len(), 2);
}

// ---------- Pipeline accessors ----------

#[test]
fn pipeline_log_entries_accumulate() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();
    let witness = build_promoted_witness(600, &synthesizer_key);
    let witness_id = witness.witness_id.clone();

    assert!(pipeline.log_entries().is_empty());
    pipeline
        .publish_witness(witness, 4_000_000)
        .expect("publish");
    assert_eq!(pipeline.log_entries().len(), 1);

    pipeline
        .revoke_witness(&witness_id, "test log", 4_100_000)
        .expect("revoke");
    assert_eq!(pipeline.log_entries().len(), 2);
}

#[test]
fn pipeline_checkpoints_created_with_interval_1() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();
    let witness = build_promoted_witness(700, &synthesizer_key);
    pipeline
        .publish_witness(witness, 5_000_000)
        .expect("publish");

    assert!(
        !pipeline.checkpoints().is_empty(),
        "checkpoint_interval=1 should create checkpoints"
    );
}

// ---------- Evidence entries ----------

#[test]
fn evidence_entries_grow_with_each_operation() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();
    let witness = build_promoted_witness(800, &synthesizer_key);
    let witness_id = witness.witness_id.clone();

    let before = pipeline.evidence_entries().len();
    pipeline
        .publish_witness(witness, 6_000_000)
        .expect("publish");
    let after_publish = pipeline.evidence_entries().len();
    assert!(after_publish > before);

    pipeline
        .revoke_witness(&witness_id, "evidence test", 6_100_000)
        .expect("revoke");
    let after_revoke = pipeline.evidence_entries().len();
    assert!(after_revoke > after_publish);
}

// ---------- Serde roundtrip ----------

#[test]
fn witness_publication_event_serde_roundtrip() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();
    let witness = build_promoted_witness(900, &synthesizer_key);
    pipeline
        .publish_witness(witness, 7_000_000)
        .expect("publish");

    let event = &pipeline.events()[0];
    let json = serde_json::to_string(event).expect("serialize");
    let recovered: WitnessPublicationEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.event, event.event);
    assert_eq!(recovered.outcome, event.outcome);
}

#[test]
fn witness_publication_query_serde_roundtrip() {
    let query = WitnessPublicationQuery {
        extension_id: Some(extension_id(999)),
        policy_id: Some(policy_id()),
        epoch: Some(SecurityEpoch::from_raw(2_000)),
        content_hash: Some(ContentHash::compute(b"test-hash")),
        include_revoked: false,
    };
    let json = serde_json::to_string(&query).expect("serialize");
    let recovered: WitnessPublicationQuery = serde_json::from_str(&json).expect("deserialize");
    assert!(!recovered.include_revoked);
    assert!(recovered.extension_id.is_some());
    assert!(recovered.epoch.is_some());
}

#[test]
fn publication_entry_kind_all_variants_serde_roundtrip() {
    for kind in [PublicationEntryKind::Publish, PublicationEntryKind::Revoke] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: PublicationEntryKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, kind);
    }
}

#[test]
fn witness_publication_error_display_is_nonempty() {
    let err = WitnessPublicationError::WitnessNotPromoted {
        state: LifecycleState::Draft,
    };
    let msg = format!("{err}");
    assert!(!msg.trim().is_empty());
}

#[test]
fn witness_publication_config_default_is_constructible() {
    let config = WitnessPublicationConfig::default();
    let json = serde_json::to_string(&config).expect("serialize");
    assert!(!json.is_empty());
}

#[test]
fn witness_publication_query_all_has_none_fields() {
    let query = WitnessPublicationQuery::all();
    assert!(query.extension_id.is_none());
    assert!(query.policy_id.is_none());
    assert!(query.epoch.is_none());
    assert!(query.content_hash.is_none());
    assert!(query.include_revoked);
}

#[test]
fn publication_entry_kind_debug_is_nonempty() {
    for kind in [PublicationEntryKind::Publish, PublicationEntryKind::Revoke] {
        assert!(!format!("{kind:?}").is_empty());
    }
}

#[test]
fn witness_publication_config_serde_roundtrip() {
    let config = WitnessPublicationConfig::default();
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: WitnessPublicationConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(serde_json::to_string(&recovered).unwrap(), json);
}

// ---------- Multi-witness query and pipeline boundary tests ----------

#[test]
fn query_by_content_hash_filters_correctly() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();
    let witness_a = build_promoted_witness(1_100, &synthesizer_key);
    let witness_b = build_promoted_witness(1_101, &synthesizer_key);
    let target_hash = witness_a.content_hash;

    pipeline
        .publish_witness(witness_a, 10_000_000)
        .expect("publish A");
    pipeline
        .publish_witness(witness_b, 10_100_000)
        .expect("publish B");

    let filtered = pipeline.query(&WitnessPublicationQuery {
        extension_id: None,
        policy_id: None,
        epoch: None,
        content_hash: Some(target_hash),
        include_revoked: true,
    });
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].witness.content_hash, target_hash);
}

#[test]
fn pipeline_events_accumulate_across_multiple_publishes() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();

    for seed in 1_200..1_205 {
        let witness = build_promoted_witness(seed, &synthesizer_key);
        pipeline
            .publish_witness(witness, seed * 1_000)
            .expect("publish");
    }

    assert_eq!(
        pipeline.events().len(),
        5,
        "each publish should emit one event"
    );
    for event in pipeline.events() {
        assert_eq!(event.event, "publish_witness");
        assert_eq!(event.outcome, "success");
    }
}

#[test]
fn verify_artifact_rejects_wrong_synthesizer_key() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();
    let witness = build_promoted_witness(1_300, &synthesizer_key);
    pipeline
        .publish_witness(witness, 11_000_000)
        .expect("publish");

    let artifact = &pipeline.publications()[0];
    let wrong_key = SigningKey::from_bytes([0xFF; 32]);
    let err = WitnessPublicationPipeline::verify_artifact(
        artifact,
        &wrong_key.verification_key(),
        &tree_head_signing_key().verification_key(),
    )
    .expect_err("wrong synthesizer key must fail verification");

    // Should be some kind of verification error (signature mismatch or hash mismatch)
    let msg = format!("{err}");
    assert!(!msg.is_empty(), "error must have a display message");
}

#[test]
fn pipeline_publications_are_ordered_by_insertion() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();
    let mut ids = Vec::new();
    for seed in 1_400..1_403 {
        let witness = build_promoted_witness(seed, &synthesizer_key);
        let pub_id = pipeline
            .publish_witness(witness, seed * 1_000)
            .expect("publish");
        ids.push(pub_id);
    }

    let publications = pipeline.publications();
    assert_eq!(publications.len(), 3);
    for (i, pub_artifact) in publications.iter().enumerate() {
        assert_eq!(
            pub_artifact.publication_id, ids[i],
            "publications must preserve insertion order"
        );
    }
}

#[test]
fn witness_publication_error_variants_display_distinctly() {
    let err_a = WitnessPublicationError::WitnessNotPromoted {
        state: LifecycleState::Draft,
    };
    let err_b = WitnessPublicationError::EmptyRevocationReason;
    let err_c = WitnessPublicationError::LogEntryHashMismatch;

    let msgs: BTreeSet<String> = [err_a, err_b, err_c]
        .iter()
        .map(|e| format!("{e}"))
        .collect();
    assert_eq!(
        msgs.len(),
        3,
        "distinct error variants must produce distinct messages"
    );
}

#[test]
fn witness_publication_pipeline_debug_is_nonempty() {
    let pipeline = build_pipeline();
    assert!(!format!("{pipeline:?}").is_empty());
}

#[test]
fn witness_publication_query_debug_is_nonempty() {
    let query = WitnessPublicationQuery::all();
    assert!(!format!("{query:?}").is_empty());
}

#[test]
fn witness_publication_config_serde_is_deterministic() {
    let config = WitnessPublicationConfig::default();
    let a = serde_json::to_string(&config).expect("first");
    let b = serde_json::to_string(&config).expect("second");
    assert_eq!(a, b);
}
