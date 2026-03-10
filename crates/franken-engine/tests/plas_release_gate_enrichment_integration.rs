//! Enrichment integration tests for `plas_release_gate` — PearlTower 2026-02-27.
//!
//! Covers: JSON field-name stability, serde roundtrip from evaluate, multi-extension
//! mixed outcomes, grant/revocation receipt validation error paths, non-deterministic
//! replay detection, duplicate receipt detection, revocation without corresponding grant,
//! activation mode rejection variants, log contract key stability, finding sort
//! determinism, decision hash sensitivity, trust anchor mismatch, ambient authority
//! traceability, input validation through evaluate, and whitespace normalization.

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
    CapabilityEscrowReceiptRecord, CapabilityWitness, ConfidenceInterval, LifecycleState,
    PromotionTheoremInput, ProofKind, ProofObligation, SourceCapabilitySet, WitnessBuilder,
    WitnessPublicationConfig, WitnessPublicationPipeline, WitnessPublicationQuery,
};
use frankenengine_engine::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::plas_release_gate::{
    PlasActivationMode, PlasCohortExtension, PlasEscrowReplayEvidence, PlasGrantCheckRecord,
    PlasReleaseGateDecisionArtifact, PlasReleaseGateError, PlasReleaseGateFailureCode,
    PlasReleaseGateInput, PlasReleaseGateTrustAnchors, PlasRevocationCheckRecord,
    evaluate_plas_release_gate,
};
use frankenengine_engine::policy_theorem_compiler::Capability;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{SigningKey, sign_preimage};

// ─── helpers ────────────────────────────────────────────────────────────

fn signing_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add((idx as u8).wrapping_mul(11));
    }
    SigningKey::from_bytes(bytes)
}

fn extension_id(label: &str) -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::Attestation,
        "plas-release-gate-extension",
        &SchemaId::from_definition(b"PlasReleaseGateExtension.v1"),
        label.as_bytes(),
    )
    .expect("extension id")
}

fn policy_object_id(label: &str) -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::PolicyObject,
        "plas-release-gate-policy",
        &SchemaId::from_definition(b"PlasReleaseGatePolicy.v1"),
        label.as_bytes(),
    )
    .expect("policy id")
}

fn proof_artifact_id(label: &str) -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::EvidenceRecord,
        "plas-release-gate-proof",
        &SchemaId::from_definition(b"PlasReleaseGateProof.v1"),
        label.as_bytes(),
    )
    .expect("proof artifact id")
}

fn theorem_proof(capability: &Capability, label: &str) -> ProofObligation {
    ProofObligation {
        capability: capability.clone(),
        kind: ProofKind::PolicyTheoremCheck,
        proof_artifact_id: proof_artifact_id(label),
        justification: format!("policy theorem check satisfied for {capability}"),
        artifact_hash: ContentHash::compute(format!("proof-hash:{label}").as_bytes()),
    }
}

fn passing_theorem_input(witness: &CapabilityWitness) -> PromotionTheoremInput {
    PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "release-gate-fixture".to_string(),
            capabilities: witness.required_capabilities.clone(),
        }],
        manifest_capabilities: witness.required_capabilities.clone(),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    }
}

fn rebind_witness(witness: &mut CapabilityWitness, synthesizer_key: &SigningKey) {
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
    let signature = sign_preimage(synthesizer_key, &unsigned).expect("sign witness");
    witness.synthesizer_signature = signature.to_bytes().to_vec();
}

fn promote_witness(
    ext_id: EngineObjectId,
    policy_id: EngineObjectId,
    capability: Capability,
    synthesizer_key: &SigningKey,
    epoch: u64,
    timestamp_ns: u64,
) -> CapabilityWitness {
    let mut witness = WitnessBuilder::new(
        ext_id,
        policy_id,
        SecurityEpoch::from_raw(epoch),
        timestamp_ns,
        SigningKey::from_bytes(*synthesizer_key.as_bytes()),
    )
    .require(capability.clone())
    .proof(theorem_proof(&capability, capability.as_str()))
    .confidence(ConfidenceInterval::from_trials(128, 127))
    .replay_seed(epoch)
    .transcript_hash(ContentHash::compute(
        format!("transcript:{capability}:{epoch}").as_bytes(),
    ))
    .build()
    .expect("build witness");

    let theorem_report = witness
        .evaluate_promotion_theorems(&passing_theorem_input(&witness))
        .expect("theorem report");
    assert!(theorem_report.all_passed);
    witness.apply_promotion_theorem_report(&theorem_report);
    rebind_witness(&mut witness, synthesizer_key);
    witness
        .transition_to(LifecycleState::Validated)
        .expect("validated transition");
    witness
        .transition_to(LifecycleState::Promoted)
        .expect("promoted transition");
    witness
}

fn publish_artifact(
    witness: CapabilityWitness,
    tree_head_signing_key: &SigningKey,
    publish_timestamp_ns: u64,
    revoke_timestamp_ns: Option<u64>,
) -> frankenengine_engine::capability_witness::PublishedWitnessArtifact {
    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(900),
        SigningKey::from_bytes(*tree_head_signing_key.as_bytes()),
        WitnessPublicationConfig::default(),
    )
    .expect("pipeline");

    let witness_id = witness.witness_id.clone();
    let publication_id = pipeline
        .publish_witness(witness, publish_timestamp_ns)
        .expect("publish witness");
    if let Some(revocation_ts) = revoke_timestamp_ns {
        pipeline
            .revoke_witness(&witness_id, "capability retired", revocation_ts)
            .expect("revoke witness");
    }

    pipeline
        .query(&WitnessPublicationQuery::all())
        .into_iter()
        .find(|artifact| artifact.publication_id == publication_id)
        .expect("published artifact")
        .clone()
}

fn make_grant_receipt(
    receipt_id: &str,
    ext_id: &EngineObjectId,
    capability: &Capability,
    timestamp_ns: u64,
    policy_id: &str,
) -> CapabilityEscrowReceiptRecord {
    CapabilityEscrowReceiptRecord {
        receipt_id: receipt_id.to_string(),
        extension_id: ext_id.clone(),
        capability: Some(capability.clone()),
        decision_kind: "grant".to_string(),
        outcome: "allow".to_string(),
        timestamp_ns,
        trace_id: format!("trace-{receipt_id}"),
        decision_id: format!("decision-{receipt_id}"),
        policy_id: policy_id.to_string(),
        error_code: None,
    }
}

fn make_replay_evidence(receipt: &CapabilityEscrowReceiptRecord) -> PlasEscrowReplayEvidence {
    PlasEscrowReplayEvidence {
        receipt_id: receipt.receipt_id.clone(),
        replay_decision_kind: receipt.decision_kind.clone(),
        replay_outcome: receipt.outcome.clone(),
        replay_policy_id: receipt.policy_id.clone(),
        deterministic_replay: true,
        replay_trace_id: format!("replay-{}", receipt.receipt_id),
    }
}

fn make_revocation_receipt(
    receipt_id: &str,
    ext_id: &EngineObjectId,
    capability: &Capability,
    timestamp_ns: u64,
    policy_id: &str,
) -> CapabilityEscrowReceiptRecord {
    CapabilityEscrowReceiptRecord {
        receipt_id: receipt_id.to_string(),
        extension_id: ext_id.clone(),
        capability: Some(capability.clone()),
        decision_kind: "revoke".to_string(),
        outcome: "revoked".to_string(),
        timestamp_ns,
        trace_id: format!("trace-{receipt_id}"),
        decision_id: format!("decision-{receipt_id}"),
        policy_id: policy_id.to_string(),
        error_code: None,
    }
}

/// Builds a full passing gate fixture with one extension, two grants (fs.read + fs.write),
/// and one revocation (fs.write).
fn base_gate_fixture() -> (PlasReleaseGateInput, PlasReleaseGateTrustAnchors) {
    let synthesizer_key = signing_key(7);
    let tree_head_key = signing_key(53);
    let extension = extension_id("alpha-extension");
    let gate_policy_id = "policy-plas-release-v1".to_string();

    let read_cap = Capability::new("fs.read");
    let write_cap = Capability::new("fs.write");

    let read_witness = promote_witness(
        extension.clone(),
        policy_object_id("alpha-policy-read"),
        read_cap.clone(),
        &synthesizer_key,
        100,
        10_000,
    );
    let read_artifact = publish_artifact(read_witness, &tree_head_key, 10_500, None);
    let read_receipt = make_grant_receipt(
        "grant-alpha-read",
        &extension,
        &read_cap,
        10_700,
        &gate_policy_id,
    );

    let write_witness = promote_witness(
        extension.clone(),
        policy_object_id("alpha-policy-write"),
        write_cap.clone(),
        &synthesizer_key,
        101,
        11_000,
    );
    let write_artifact = publish_artifact(write_witness, &tree_head_key, 11_200, Some(11_900));
    let write_receipt = make_grant_receipt(
        "grant-alpha-write",
        &extension,
        &write_cap,
        11_300,
        &gate_policy_id,
    );
    let revoke_receipt = make_revocation_receipt(
        "revoke-alpha-write",
        &extension,
        &write_cap,
        11_950,
        &gate_policy_id,
    );

    let input = PlasReleaseGateInput {
        trace_id: "trace-plas-release-gate".to_string(),
        decision_id: "decision-plas-release-gate".to_string(),
        policy_id: gate_policy_id,
        cohort_id: "cohort-prioritized-alpha".to_string(),
        extensions: vec![PlasCohortExtension {
            extension_id: extension,
            activation_mode: PlasActivationMode::Active,
            manifest_capabilities: BTreeSet::from([read_cap.clone(), write_cap.clone()]),
            active_capabilities: BTreeSet::from([read_cap.clone()]),
            grants: vec![
                PlasGrantCheckRecord {
                    capability: read_cap,
                    receipt: read_receipt.clone(),
                    witness_artifact: read_artifact,
                    replay_evidence: Some(make_replay_evidence(&read_receipt)),
                },
                PlasGrantCheckRecord {
                    capability: write_cap.clone(),
                    receipt: write_receipt.clone(),
                    witness_artifact: write_artifact.clone(),
                    replay_evidence: Some(make_replay_evidence(&write_receipt)),
                },
            ],
            revocations: vec![PlasRevocationCheckRecord {
                capability: write_cap,
                receipt: revoke_receipt,
                witness_artifact: write_artifact,
            }],
        }],
    };

    let trust_anchors = PlasReleaseGateTrustAnchors {
        witness_verification_key: synthesizer_key.verification_key(),
        transparency_log_verification_key: tree_head_key.verification_key(),
    };

    (input, trust_anchors)
}

/// Builds a minimal single-grant extension with one capability and no revocations.
fn single_grant_fixture(
    ext_label: &str,
    cap_name: &str,
    gate_policy_id: &str,
    synthesizer_key: &SigningKey,
    tree_head_key: &SigningKey,
    epoch: u64,
) -> PlasCohortExtension {
    let ext = extension_id(ext_label);
    let cap = Capability::new(cap_name);

    let witness = promote_witness(
        ext.clone(),
        policy_object_id(&format!("{ext_label}-policy-{cap_name}")),
        cap.clone(),
        synthesizer_key,
        epoch,
        epoch * 100,
    );
    let artifact = publish_artifact(witness, tree_head_key, epoch * 100 + 50, None);
    let receipt = make_grant_receipt(
        &format!("grant-{ext_label}-{cap_name}"),
        &ext,
        &cap,
        epoch * 100 + 70,
        gate_policy_id,
    );

    PlasCohortExtension {
        extension_id: ext,
        activation_mode: PlasActivationMode::Active,
        manifest_capabilities: BTreeSet::from([cap.clone()]),
        active_capabilities: BTreeSet::from([cap]),
        grants: vec![PlasGrantCheckRecord {
            capability: Capability::new(cap_name),
            receipt: receipt.clone(),
            witness_artifact: artifact,
            replay_evidence: Some(make_replay_evidence(&receipt)),
        }],
        revocations: Vec::new(),
    }
}

// ─── 1. JSON field-name stability: decision artifact ────────────────────

#[test]
fn json_field_names_decision_artifact() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    let json = serde_json::to_string(&artifact).unwrap();
    for field in [
        "\"decision_id\"",
        "\"cohort_id\"",
        "\"pass\"",
        "\"checked_extensions\"",
        "\"checked_grants\"",
        "\"checked_revocations\"",
        "\"findings\"",
        "\"logs\"",
        "\"decision_hash\"",
    ] {
        assert!(
            json.contains(field),
            "missing field {field} in artifact JSON"
        );
    }
}

// ─── 2. JSON field-name stability: finding from evaluate ────────────────

#[test]
fn json_field_names_finding_from_evaluate() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].activation_mode = PlasActivationMode::Shadow;
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.findings.is_empty());
    let json = serde_json::to_string(&artifact.findings[0]).unwrap();
    for field in [
        "\"code\"",
        "\"extension_id\"",
        "\"receipt_id\"",
        "\"detail\"",
    ] {
        assert!(
            json.contains(field),
            "missing field {field} in finding JSON"
        );
    }
}

// ─── 3. JSON field-name stability: log event from evaluate ──────────────

#[test]
fn json_field_names_log_event_from_evaluate() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.logs.is_empty());
    let json = serde_json::to_string(&artifact.logs[0]).unwrap();
    for field in [
        "\"trace_id\"",
        "\"decision_id\"",
        "\"policy_id\"",
        "\"component\"",
        "\"event\"",
        "\"outcome\"",
    ] {
        assert!(json.contains(field), "missing field {field} in log JSON");
    }
}

// ─── 4. Decision artifact serde roundtrip from full evaluate ────────────

#[test]
fn decision_artifact_serde_roundtrip_from_evaluate() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    let json = serde_json::to_string_pretty(&artifact).unwrap();
    let restored: PlasReleaseGateDecisionArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, restored);
}

#[test]
fn decision_artifact_serde_roundtrip_from_failing_evaluate() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].activation_mode = PlasActivationMode::Disabled;
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    let json = serde_json::to_string(&artifact).unwrap();
    let restored: PlasReleaseGateDecisionArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, restored);
}

// ─── 5. Multi-extension mixed outcomes ──────────────────────────────────

#[test]
fn multi_extension_one_active_one_shadow() {
    let synthesizer_key = signing_key(7);
    let tree_head_key = signing_key(53);
    let policy_id = "policy-multi-ext";

    let ext_a = single_grant_fixture(
        "ext-a-multi",
        "cap.alpha",
        policy_id,
        &synthesizer_key,
        &tree_head_key,
        200,
    );
    let mut ext_b = single_grant_fixture(
        "ext-b-multi",
        "cap.beta",
        policy_id,
        &synthesizer_key,
        &tree_head_key,
        201,
    );
    ext_b.activation_mode = PlasActivationMode::Shadow;

    let input = PlasReleaseGateInput {
        trace_id: "t-multi".into(),
        decision_id: "d-multi".into(),
        policy_id: policy_id.into(),
        cohort_id: "c-multi".into(),
        extensions: vec![ext_a, ext_b],
    };
    let trust = PlasReleaseGateTrustAnchors {
        witness_verification_key: synthesizer_key.verification_key(),
        transparency_log_verification_key: tree_head_key.verification_key(),
    };
    let artifact = evaluate_plas_release_gate(&input, &trust).unwrap();
    assert!(!artifact.pass);
    assert_eq!(artifact.checked_extensions, 2);
    assert!(
        artifact
            .findings
            .iter()
            .any(|f| f.code == PlasReleaseGateFailureCode::CohortPlasNotActive)
    );
}

#[test]
fn multi_extension_all_active_all_pass() {
    let synthesizer_key = signing_key(7);
    let tree_head_key = signing_key(53);
    let policy_id = "policy-multi-pass";

    let ext_a = single_grant_fixture(
        "ext-a-pass",
        "cap.alpha",
        policy_id,
        &synthesizer_key,
        &tree_head_key,
        300,
    );
    let ext_b = single_grant_fixture(
        "ext-b-pass",
        "cap.beta",
        policy_id,
        &synthesizer_key,
        &tree_head_key,
        301,
    );

    let input = PlasReleaseGateInput {
        trace_id: "t-all-pass".into(),
        decision_id: "d-all-pass".into(),
        policy_id: policy_id.into(),
        cohort_id: "c-all-pass".into(),
        extensions: vec![ext_a, ext_b],
    };
    let trust = PlasReleaseGateTrustAnchors {
        witness_verification_key: synthesizer_key.verification_key(),
        transparency_log_verification_key: tree_head_key.verification_key(),
    };
    let artifact = evaluate_plas_release_gate(&input, &trust).unwrap();
    assert!(artifact.pass);
    assert!(artifact.findings.is_empty());
    assert_eq!(artifact.checked_extensions, 2);
    assert_eq!(artifact.checked_grants, 2);
}

// ─── 6. Grant receipt validation error paths ────────────────────────────

#[test]
fn grant_receipt_empty_receipt_id_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0].receipt.receipt_id = "".to_string();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::MissingCapabilityWitness
        && f.detail.contains("receipt_id")));
}

#[test]
fn grant_receipt_wrong_extension_id_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0].receipt.extension_id = extension_id("wrong-ext");
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::MissingCapabilityWitness
        && f.detail.contains("extension_id")));
}

#[test]
fn grant_receipt_zero_timestamp_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0].receipt.timestamp_ns = 0;
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::MissingCapabilityWitness
        && f.detail.contains("timestamp_ns")));
}

#[test]
fn grant_receipt_wrong_decision_kind_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0].receipt.decision_kind = "revoke".to_string();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::MissingCapabilityWitness
        && f.detail.contains("decision_kind")));
}

#[test]
fn grant_receipt_empty_outcome_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0].receipt.outcome = "".to_string();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::MissingCapabilityWitness
        && f.detail.contains("outcome")));
}

#[test]
fn grant_receipt_wrong_policy_id_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0].receipt.policy_id = "wrong-policy".to_string();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::MissingCapabilityWitness
        && f.detail.contains("policy_id")));
}

#[test]
fn grant_receipt_wrong_capability_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0].receipt.capability = Some(Capability::new("wrong.cap"));
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::MissingCapabilityWitness
        && f.detail.contains("capability")));
}

// ─── 7. Revocation receipt validation error paths ───────────────────────

#[test]
fn revocation_receipt_empty_receipt_id_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].revocations[0].receipt.receipt_id = "".to_string();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::RevocationEscrowEventMissing
        && f.detail.contains("receipt_id")));
}

#[test]
fn revocation_receipt_wrong_extension_id_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].revocations[0].receipt.extension_id = extension_id("bad-ext");
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::RevocationEscrowEventMissing
        && f.detail.contains("extension_id")));
}

#[test]
fn revocation_receipt_zero_timestamp_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].revocations[0].receipt.timestamp_ns = 0;
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::RevocationEscrowEventMissing
        && f.detail.contains("timestamp_ns")));
}

#[test]
fn revocation_receipt_wrong_decision_kind_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].revocations[0].receipt.decision_kind = "grant".to_string();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::RevocationEscrowEventMissing
        && f.detail.contains("decision_kind")));
}

#[test]
fn revocation_receipt_empty_outcome_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].revocations[0].receipt.outcome = "".to_string();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::RevocationEscrowEventMissing
        && f.detail.contains("outcome")));
}

#[test]
fn revocation_receipt_wrong_policy_id_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].revocations[0].receipt.policy_id = "wrong-policy".to_string();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::RevocationEscrowEventMissing
        && f.detail.contains("policy_id")));
}

#[test]
fn revocation_receipt_wrong_capability_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].revocations[0].receipt.capability = Some(Capability::new("wrong.cap"));
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::RevocationEscrowEventMissing
        && f.detail.contains("capability")));
}

// ─── 8. Non-deterministic replay detection ──────────────────────────────

#[test]
fn non_deterministic_replay_produces_mismatch_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0]
        .replay_evidence
        .as_mut()
        .unwrap()
        .deterministic_replay = false;
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(
        artifact
            .findings
            .iter()
            .any(|f| f.code == PlasReleaseGateFailureCode::EscrowReplayMismatch)
    );
}

#[test]
fn replay_decision_kind_mismatch_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0]
        .replay_evidence
        .as_mut()
        .unwrap()
        .replay_decision_kind = "revoke".to_string();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(
        artifact
            .findings
            .iter()
            .any(|f| f.code == PlasReleaseGateFailureCode::EscrowReplayMismatch)
    );
}

#[test]
fn replay_policy_id_mismatch_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0]
        .replay_evidence
        .as_mut()
        .unwrap()
        .replay_policy_id = "wrong-policy".to_string();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(
        artifact
            .findings
            .iter()
            .any(|f| f.code == PlasReleaseGateFailureCode::EscrowReplayMismatch)
    );
}

#[test]
fn replay_receipt_id_mismatch_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0]
        .replay_evidence
        .as_mut()
        .unwrap()
        .receipt_id = "wrong-receipt".to_string();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(
        artifact
            .findings
            .iter()
            .any(|f| f.code == PlasReleaseGateFailureCode::EscrowReplayMismatch)
    );
}

// ─── 9. Duplicate receipt detection ─────────────────────────────────────

#[test]
fn duplicate_grant_receipt_id_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    // Make both grants have the same receipt_id
    let shared_id = input.extensions[0].grants[0].receipt.receipt_id.clone();
    input.extensions[0].grants[1].receipt.receipt_id = shared_id.clone();
    input.extensions[0].grants[1]
        .replay_evidence
        .as_mut()
        .unwrap()
        .receipt_id = shared_id;

    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(
        artifact
            .findings
            .iter()
            .any(|f| f.detail.contains("duplicate grant receipt_id"))
    );
}

// ─── 10. Revocation without corresponding grant ─────────────────────────

#[test]
fn revocation_for_ungranted_capability_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    // Change the revocation's capability to something that wasn't granted
    input.extensions[0].revocations[0].capability = Capability::new("net.listen");
    input.extensions[0].revocations[0].receipt.capability = Some(Capability::new("net.listen"));

    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::RevocationEscrowEventMissing
        && f.detail.contains("no corresponding grant")));
}

// ─── 11. All activation mode rejection variants ─────────────────────────

#[test]
fn activation_mode_shadow_produces_not_active_finding() {
    let synthesizer_key = signing_key(7);
    let tree_head_key = signing_key(53);
    let policy_id = "policy-mode-test";
    let mut ext = single_grant_fixture(
        "ext-shadow",
        "cap.test",
        policy_id,
        &synthesizer_key,
        &tree_head_key,
        400,
    );
    ext.activation_mode = PlasActivationMode::Shadow;

    let input = PlasReleaseGateInput {
        trace_id: "t-shadow".into(),
        decision_id: "d-shadow".into(),
        policy_id: policy_id.into(),
        cohort_id: "c-shadow".into(),
        extensions: vec![ext],
    };
    let trust = PlasReleaseGateTrustAnchors {
        witness_verification_key: synthesizer_key.verification_key(),
        transparency_log_verification_key: tree_head_key.verification_key(),
    };
    let artifact = evaluate_plas_release_gate(&input, &trust).unwrap();
    assert!(!artifact.pass);
    let finding = artifact
        .findings
        .iter()
        .find(|f| f.code == PlasReleaseGateFailureCode::CohortPlasNotActive)
        .unwrap();
    assert!(finding.detail.contains("shadow"));
}

#[test]
fn activation_mode_audit_only_produces_not_active_finding() {
    let synthesizer_key = signing_key(7);
    let tree_head_key = signing_key(53);
    let policy_id = "policy-mode-audit";
    let mut ext = single_grant_fixture(
        "ext-audit",
        "cap.audit",
        policy_id,
        &synthesizer_key,
        &tree_head_key,
        401,
    );
    ext.activation_mode = PlasActivationMode::AuditOnly;

    let input = PlasReleaseGateInput {
        trace_id: "t-audit".into(),
        decision_id: "d-audit".into(),
        policy_id: policy_id.into(),
        cohort_id: "c-audit".into(),
        extensions: vec![ext],
    };
    let trust = PlasReleaseGateTrustAnchors {
        witness_verification_key: synthesizer_key.verification_key(),
        transparency_log_verification_key: tree_head_key.verification_key(),
    };
    let artifact = evaluate_plas_release_gate(&input, &trust).unwrap();
    assert!(!artifact.pass);
    let finding = artifact
        .findings
        .iter()
        .find(|f| f.code == PlasReleaseGateFailureCode::CohortPlasNotActive)
        .unwrap();
    assert!(finding.detail.contains("audit_only"));
}

#[test]
fn activation_mode_disabled_produces_not_active_finding() {
    let synthesizer_key = signing_key(7);
    let tree_head_key = signing_key(53);
    let policy_id = "policy-mode-disabled";
    let mut ext = single_grant_fixture(
        "ext-disabled",
        "cap.disabled",
        policy_id,
        &synthesizer_key,
        &tree_head_key,
        402,
    );
    ext.activation_mode = PlasActivationMode::Disabled;

    let input = PlasReleaseGateInput {
        trace_id: "t-disabled".into(),
        decision_id: "d-disabled".into(),
        policy_id: policy_id.into(),
        cohort_id: "c-disabled".into(),
        extensions: vec![ext],
    };
    let trust = PlasReleaseGateTrustAnchors {
        witness_verification_key: synthesizer_key.verification_key(),
        transparency_log_verification_key: tree_head_key.verification_key(),
    };
    let artifact = evaluate_plas_release_gate(&input, &trust).unwrap();
    assert!(!artifact.pass);
    let finding = artifact
        .findings
        .iter()
        .find(|f| f.code == PlasReleaseGateFailureCode::CohortPlasNotActive)
        .unwrap();
    assert!(finding.detail.contains("disabled"));
}

// ─── 12. Log contract key stability ─────────────────────────────────────

#[test]
fn all_logs_have_correct_trace_id_and_component() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    for log in &artifact.logs {
        assert_eq!(log.trace_id, "trace-plas-release-gate");
        assert_eq!(log.decision_id, "decision-plas-release-gate");
        assert_eq!(log.policy_id, "policy-plas-release-v1");
        assert_eq!(log.component, "plas_release_gate");
    }
}

#[test]
fn passing_gate_last_log_is_release_gate_decision_pass() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(artifact.pass);
    let last = artifact.logs.last().unwrap();
    assert_eq!(last.event, "release_gate_decision");
    assert_eq!(last.outcome, "pass");
    assert!(last.error_code.is_none());
}

#[test]
fn failing_gate_last_log_is_release_gate_decision_fail() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].activation_mode = PlasActivationMode::Shadow;
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    let last = artifact.logs.last().unwrap();
    assert_eq!(last.event, "release_gate_decision");
    assert_eq!(last.outcome, "fail");
    assert_eq!(last.error_code.as_deref(), Some("plas_release_gate_failed"));
}

#[test]
fn log_events_include_cohort_activation_pass() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(
        artifact
            .logs
            .iter()
            .any(|l| l.event == "cohort_activation" && l.outcome == "pass")
    );
}

#[test]
fn log_events_include_grant_witness_validation_pass() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(
        artifact
            .logs
            .iter()
            .any(|l| l.event == "grant_witness_validation" && l.outcome == "pass")
    );
}

#[test]
fn log_events_include_escrow_replay_validation_pass() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(
        artifact
            .logs
            .iter()
            .any(|l| l.event == "escrow_replay_validation" && l.outcome == "pass")
    );
}

#[test]
fn log_events_include_revocation_round_trip_validation_pass() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(
        artifact
            .logs
            .iter()
            .any(|l| l.event == "revocation_round_trip_validation" && l.outcome == "pass")
    );
}

#[test]
fn log_events_include_ambient_authority_scan_pass() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(
        artifact
            .logs
            .iter()
            .any(|l| l.event == "ambient_authority_scan" && l.outcome == "pass")
    );
}

// ─── 13. Finding sort determinism ───────────────────────────────────────

#[test]
fn findings_sorted_by_code_then_extension_then_detail() {
    let (mut input, trust_anchors) = base_gate_fixture();
    // Add an ambient authority to produce an extra finding type
    input.extensions[0]
        .active_capabilities
        .insert(Capability::new("net.admin"));
    input.extensions[0].activation_mode = PlasActivationMode::Shadow;

    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(artifact.findings.len() >= 2);
    for window in artifact.findings.windows(2) {
        let cmp = window[0]
            .code
            .cmp(&window[1].code)
            .then(window[0].extension_id.cmp(&window[1].extension_id))
            .then(window[0].receipt_id.cmp(&window[1].receipt_id))
            .then(window[0].detail.cmp(&window[1].detail));
        assert!(
            cmp.is_le(),
            "findings not sorted: {:?} > {:?}",
            window[0],
            window[1]
        );
    }
}

// ─── 14. Decision hash sensitivity ──────────────────────────────────────

#[test]
fn decision_hash_changes_with_different_trace_id() {
    let (input1, trust_anchors) = base_gate_fixture();
    let mut input2 = input1.clone();
    input2.trace_id = "trace-different".to_string();
    let r1 = evaluate_plas_release_gate(&input1, &trust_anchors).unwrap();
    let r2 = evaluate_plas_release_gate(&input2, &trust_anchors).unwrap();
    assert_ne!(r1.decision_hash, r2.decision_hash);
}

#[test]
fn decision_hash_changes_with_different_decision_id() {
    let (input1, trust_anchors) = base_gate_fixture();
    let mut input2 = input1.clone();
    input2.decision_id = "decision-different".to_string();
    let r1 = evaluate_plas_release_gate(&input1, &trust_anchors).unwrap();
    let r2 = evaluate_plas_release_gate(&input2, &trust_anchors).unwrap();
    assert_ne!(r1.decision_hash, r2.decision_hash);
}

#[test]
fn decision_hash_changes_with_different_cohort_id() {
    let (input1, trust_anchors) = base_gate_fixture();
    let mut input2 = input1.clone();
    input2.cohort_id = "cohort-different".to_string();
    let r1 = evaluate_plas_release_gate(&input1, &trust_anchors).unwrap();
    let r2 = evaluate_plas_release_gate(&input2, &trust_anchors).unwrap();
    assert_ne!(r1.decision_hash, r2.decision_hash);
}

#[test]
fn decision_hash_deterministic_across_runs() {
    let (input, trust_anchors) = base_gate_fixture();
    let r1 = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    let r2 = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    let r3 = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert_eq!(r1.decision_hash, r2.decision_hash);
    assert_eq!(r2.decision_hash, r3.decision_hash);
}

// ─── 15. Trust anchor mismatch ──────────────────────────────────────────

#[test]
fn wrong_witness_verification_key_causes_signature_failure() {
    let (input, mut trust_anchors) = base_gate_fixture();
    // Use a different key for verification
    trust_anchors.witness_verification_key = signing_key(99).verification_key();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(
        artifact
            .findings
            .iter()
            .any(|f| { f.code == PlasReleaseGateFailureCode::WitnessSignatureVerificationFailed })
    );
}

#[test]
fn wrong_transparency_log_key_causes_signature_failure() {
    let (input, mut trust_anchors) = base_gate_fixture();
    trust_anchors.transparency_log_verification_key = signing_key(99).verification_key();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    // Wrong transparency key should cause witness verification to fail
    assert!(artifact.findings.iter().any(|f| {
        f.code == PlasReleaseGateFailureCode::WitnessSignatureVerificationFailed
            || f.code == PlasReleaseGateFailureCode::RevocationWitnessMissing
    }));
}

// ─── 16. Ambient authority traceability ─────────────────────────────────

#[test]
fn traceable_active_capability_does_not_produce_ambient_finding() {
    let (input, trust_anchors) = base_gate_fixture();
    // Base fixture has active_capabilities = {fs.read}, which IS traceable
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(artifact.pass);
    assert!(
        !artifact
            .findings
            .iter()
            .any(|f| f.code == PlasReleaseGateFailureCode::AmbientAuthorityDetected)
    );
}

#[test]
fn untraceable_active_capability_detail_mentions_capability_name() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0]
        .active_capabilities
        .insert(Capability::new("net.socket.connect"));
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    let ambient_finding = artifact
        .findings
        .iter()
        .find(|f| f.code == PlasReleaseGateFailureCode::AmbientAuthorityDetected)
        .unwrap();
    assert!(ambient_finding.detail.contains("net.socket.connect"));
}

#[test]
fn multiple_untraceable_capabilities_produce_multiple_findings() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0]
        .active_capabilities
        .insert(Capability::new("net.admin"));
    input.extensions[0]
        .active_capabilities
        .insert(Capability::new("proc.exec"));
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    let ambient_count = artifact
        .findings
        .iter()
        .filter(|f| f.code == PlasReleaseGateFailureCode::AmbientAuthorityDetected)
        .count();
    assert_eq!(ambient_count, 2);
}

// ─── 17. Input validation through evaluate ──────────────────────────────

#[test]
fn evaluate_rejects_empty_trace_id() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.trace_id = "".to_string();
    let err = evaluate_plas_release_gate(&input, &trust_anchors).unwrap_err();
    assert!(matches!(err, PlasReleaseGateError::InvalidInput { .. }));
    assert!(err.to_string().contains("trace_id"));
}

#[test]
fn evaluate_rejects_empty_decision_id() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.decision_id = "".to_string();
    let err = evaluate_plas_release_gate(&input, &trust_anchors).unwrap_err();
    assert!(matches!(err, PlasReleaseGateError::InvalidInput { .. }));
    assert!(err.to_string().contains("decision_id"));
}

#[test]
fn evaluate_rejects_empty_policy_id() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.policy_id = "".to_string();
    let err = evaluate_plas_release_gate(&input, &trust_anchors).unwrap_err();
    assert!(matches!(err, PlasReleaseGateError::InvalidInput { .. }));
    assert!(err.to_string().contains("policy_id"));
}

#[test]
fn evaluate_rejects_empty_cohort_id() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.cohort_id = "".to_string();
    let err = evaluate_plas_release_gate(&input, &trust_anchors).unwrap_err();
    assert!(matches!(err, PlasReleaseGateError::InvalidInput { .. }));
    assert!(err.to_string().contains("cohort_id"));
}

#[test]
fn evaluate_rejects_no_extensions() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions.clear();
    let err = evaluate_plas_release_gate(&input, &trust_anchors).unwrap_err();
    assert!(matches!(err, PlasReleaseGateError::InvalidInput { .. }));
    assert!(err.to_string().contains("at least one"));
}

#[test]
fn evaluate_rejects_duplicate_extensions() {
    let (mut input, trust_anchors) = base_gate_fixture();
    let ext_copy = input.extensions[0].clone();
    input.extensions.push(ext_copy);
    let err = evaluate_plas_release_gate(&input, &trust_anchors).unwrap_err();
    assert!(matches!(err, PlasReleaseGateError::InvalidInput { .. }));
    assert!(err.to_string().contains("duplicate"));
}

#[test]
fn evaluate_accepts_whitespace_padded_ids_after_normalization() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.trace_id = "  trace-plas-release-gate  ".to_string();
    input.decision_id = "  decision-plas-release-gate  ".to_string();
    input.policy_id = "  policy-plas-release-v1  ".to_string();
    input.cohort_id = "  cohort-prioritized-alpha  ".to_string();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert_eq!(artifact.decision_id, "decision-plas-release-gate");
    assert_eq!(artifact.cohort_id, "cohort-prioritized-alpha");
}

#[test]
fn evaluate_rejects_whitespace_only_ids() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.trace_id = "   ".to_string();
    let err = evaluate_plas_release_gate(&input, &trust_anchors).unwrap_err();
    assert!(err.to_string().contains("trace_id"));
}

// ─── 18. Witness with missing fields ────────────────────────────────────

#[test]
fn witness_missing_synthesizer_signature_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0]
        .witness_artifact
        .witness
        .synthesizer_signature = Vec::new();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::MissingCapabilityWitness
        && f.detail.contains("missing required grant fields")));
}

#[test]
fn witness_empty_signature_bundle_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0]
        .witness_artifact
        .signature_bundle = Vec::new();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::MissingCapabilityWitness
        && f.detail.contains("missing required grant fields")));
}

#[test]
fn witness_wrong_extension_id_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0]
        .witness_artifact
        .witness
        .extension_id = extension_id("different-ext");
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::MissingCapabilityWitness
        && f.detail.contains("missing required grant fields")));
}

#[test]
fn witness_zero_timestamp_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0]
        .witness_artifact
        .witness
        .timestamp_ns = 0;
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::MissingCapabilityWitness
        && f.detail.contains("missing required grant fields")));
}

#[test]
fn witness_empty_required_capabilities_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0]
        .witness_artifact
        .witness
        .required_capabilities
        .clear();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|f| f.code
        == PlasReleaseGateFailureCode::MissingCapabilityWitness
        && f.detail.contains("missing required grant fields")));
}

// ─── 19. Revocation witness missing checks ──────────────────────────────

#[test]
fn revocation_witness_not_revoked_produces_finding() {
    let (mut input, trust_anchors) = base_gate_fixture();
    // Remove the revocation proof to make is_revoked() return false
    input.extensions[0].revocations[0]
        .witness_artifact
        .revocation_proof = None;
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);
    assert!(
        artifact
            .findings
            .iter()
            .any(|f| f.code == PlasReleaseGateFailureCode::RevocationWitnessMissing)
    );
}

// ─── 20. Checked counts accuracy ────────────────────────────────────────

#[test]
fn checked_grants_count_matches_grants_in_input() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    let total_grants: usize = input.extensions.iter().map(|e| e.grants.len()).sum();
    assert_eq!(artifact.checked_grants, total_grants as u64);
}

#[test]
fn checked_revocations_count_matches_revocations_in_input() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    let total_revocations: usize = input.extensions.iter().map(|e| e.revocations.len()).sum();
    assert_eq!(artifact.checked_revocations, total_revocations as u64);
}

#[test]
fn checked_extensions_count_matches_extensions_in_input() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert_eq!(artifact.checked_extensions, input.extensions.len() as u64);
}

// ─── 21. Serde roundtrip on type constructors ───────────────────────────

#[test]
fn plas_activation_mode_serde_exact_values() {
    assert_eq!(
        serde_json::to_string(&PlasActivationMode::Active).unwrap(),
        "\"active\""
    );
    assert_eq!(
        serde_json::to_string(&PlasActivationMode::Shadow).unwrap(),
        "\"shadow\""
    );
    assert_eq!(
        serde_json::to_string(&PlasActivationMode::AuditOnly).unwrap(),
        "\"audit_only\""
    );
    assert_eq!(
        serde_json::to_string(&PlasActivationMode::Disabled).unwrap(),
        "\"disabled\""
    );
}

#[test]
fn failure_code_serde_exact_values() {
    let expected = [
        (
            PlasReleaseGateFailureCode::CohortPlasNotActive,
            "\"cohort_plas_not_active\"",
        ),
        (
            PlasReleaseGateFailureCode::CohortCoverageMissingGrantExercise,
            "\"cohort_coverage_missing_grant_exercise\"",
        ),
        (
            PlasReleaseGateFailureCode::MissingCapabilityWitness,
            "\"missing_capability_witness\"",
        ),
        (
            PlasReleaseGateFailureCode::WitnessSignatureVerificationFailed,
            "\"witness_signature_verification_failed\"",
        ),
        (
            PlasReleaseGateFailureCode::EscrowReplayEvidenceMissing,
            "\"escrow_replay_evidence_missing\"",
        ),
        (
            PlasReleaseGateFailureCode::EscrowReplayMismatch,
            "\"escrow_replay_mismatch\"",
        ),
        (
            PlasReleaseGateFailureCode::RevocationWitnessMissing,
            "\"revocation_witness_missing\"",
        ),
        (
            PlasReleaseGateFailureCode::RevocationEscrowEventMissing,
            "\"revocation_escrow_event_missing\"",
        ),
        (
            PlasReleaseGateFailureCode::AmbientAuthorityDetected,
            "\"ambient_authority_detected\"",
        ),
    ];
    for (code, expected_json) in &expected {
        let json = serde_json::to_string(code).unwrap();
        assert_eq!(&json, expected_json, "wrong serde for {code:?}");
        let back: PlasReleaseGateFailureCode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *code);
    }
}

#[test]
fn error_display_exact_messages() {
    let err1 = PlasReleaseGateError::InvalidInput {
        detail: "bad data".into(),
    };
    assert_eq!(
        err1.to_string(),
        "invalid PLAS release gate input: bad data"
    );

    let err2 = PlasReleaseGateError::Serialization {
        detail: "json error".into(),
    };
    assert_eq!(err2.to_string(), "serialization failure: json error");
}

#[test]
fn error_serde_roundtrip_all_variants() {
    let variants = [
        PlasReleaseGateError::InvalidInput {
            detail: "test detail".into(),
        },
        PlasReleaseGateError::Serialization {
            detail: "ser detail".into(),
        },
    ];
    for err in &variants {
        let json = serde_json::to_string(err).unwrap();
        let back: PlasReleaseGateError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn error_is_std_error_trait() {
    let errs: Vec<Box<dyn std::error::Error>> = vec![
        Box::new(PlasReleaseGateError::InvalidInput { detail: "a".into() }),
        Box::new(PlasReleaseGateError::Serialization { detail: "b".into() }),
    ];
    for e in &errs {
        assert!(!e.to_string().is_empty());
        assert!(e.source().is_none());
    }
}

// ─── 22. Debug distinctness ─────────────────────────────────────────────

#[test]
fn activation_mode_debug_all_distinct() {
    let variants = [
        PlasActivationMode::Active,
        PlasActivationMode::Shadow,
        PlasActivationMode::AuditOnly,
        PlasActivationMode::Disabled,
    ];
    let mut debugs = BTreeSet::new();
    for v in &variants {
        assert!(debugs.insert(format!("{v:?}")));
    }
    assert_eq!(debugs.len(), 4);
}

#[test]
fn failure_code_debug_all_distinct() {
    let codes = [
        PlasReleaseGateFailureCode::CohortPlasNotActive,
        PlasReleaseGateFailureCode::CohortCoverageMissingGrantExercise,
        PlasReleaseGateFailureCode::MissingCapabilityWitness,
        PlasReleaseGateFailureCode::WitnessSignatureVerificationFailed,
        PlasReleaseGateFailureCode::EscrowReplayEvidenceMissing,
        PlasReleaseGateFailureCode::EscrowReplayMismatch,
        PlasReleaseGateFailureCode::RevocationWitnessMissing,
        PlasReleaseGateFailureCode::RevocationEscrowEventMissing,
        PlasReleaseGateFailureCode::AmbientAuthorityDetected,
    ];
    let mut debugs = BTreeSet::new();
    for c in &codes {
        assert!(debugs.insert(format!("{c:?}")));
    }
    assert_eq!(debugs.len(), 9);
}

#[test]
fn error_debug_variants_distinct() {
    let v1 = PlasReleaseGateError::InvalidInput { detail: "x".into() };
    let v2 = PlasReleaseGateError::Serialization { detail: "x".into() };
    assert_ne!(format!("{v1:?}"), format!("{v2:?}"));
}

// ─── 23. JSON field stability: input struct ─────────────────────────────

#[test]
fn json_field_names_input() {
    let (input, _) = base_gate_fixture();
    let json = serde_json::to_string(&input).unwrap();
    for field in [
        "\"trace_id\"",
        "\"decision_id\"",
        "\"policy_id\"",
        "\"cohort_id\"",
        "\"extensions\"",
    ] {
        assert!(json.contains(field), "missing field {field} in input JSON");
    }
}

#[test]
fn json_field_names_cohort_extension() {
    let (input, _) = base_gate_fixture();
    let json = serde_json::to_string(&input.extensions[0]).unwrap();
    for field in [
        "\"extension_id\"",
        "\"activation_mode\"",
        "\"manifest_capabilities\"",
        "\"active_capabilities\"",
        "\"grants\"",
        "\"revocations\"",
    ] {
        assert!(
            json.contains(field),
            "missing field {field} in extension JSON"
        );
    }
}

#[test]
fn json_field_names_grant_check_record() {
    let (input, _) = base_gate_fixture();
    let json = serde_json::to_string(&input.extensions[0].grants[0]).unwrap();
    for field in [
        "\"capability\"",
        "\"receipt\"",
        "\"witness_artifact\"",
        "\"replay_evidence\"",
    ] {
        assert!(json.contains(field), "missing field {field} in grant JSON");
    }
}

#[test]
fn json_field_names_revocation_check_record() {
    let (input, _) = base_gate_fixture();
    let json = serde_json::to_string(&input.extensions[0].revocations[0]).unwrap();
    for field in ["\"capability\"", "\"receipt\"", "\"witness_artifact\""] {
        assert!(
            json.contains(field),
            "missing field {field} in revocation JSON"
        );
    }
}

#[test]
fn json_field_names_trust_anchors() {
    let (_, trust_anchors) = base_gate_fixture();
    let json = serde_json::to_string(&trust_anchors).unwrap();
    for field in [
        "\"witness_verification_key\"",
        "\"transparency_log_verification_key\"",
    ] {
        assert!(json.contains(field), "missing field {field} in trust JSON");
    }
}

#[test]
fn json_field_names_escrow_replay_evidence() {
    let (input, _) = base_gate_fixture();
    let evidence = input.extensions[0].grants[0]
        .replay_evidence
        .as_ref()
        .unwrap();
    let json = serde_json::to_string(evidence).unwrap();
    for field in [
        "\"receipt_id\"",
        "\"replay_decision_kind\"",
        "\"replay_outcome\"",
        "\"replay_policy_id\"",
        "\"deterministic_replay\"",
        "\"replay_trace_id\"",
    ] {
        assert!(
            json.contains(field),
            "missing field {field} in replay evidence JSON"
        );
    }
}

// ─── 24. Input serde roundtrip ──────────────────────────────────────────

#[test]
fn input_serde_roundtrip_through_evaluate() {
    let (input, _) = base_gate_fixture();
    let json = serde_json::to_string(&input).unwrap();
    let restored: PlasReleaseGateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, restored);
}

#[test]
fn trust_anchors_serde_roundtrip() {
    let (_, trust_anchors) = base_gate_fixture();
    let json = serde_json::to_string(&trust_anchors).unwrap();
    let restored: PlasReleaseGateTrustAnchors = serde_json::from_str(&json).unwrap();
    assert_eq!(trust_anchors, restored);
}

// ─── 25. Failure code Display matches error_code ────────────────────────

#[test]
fn failure_code_display_equals_error_code_all_variants() {
    let codes = [
        PlasReleaseGateFailureCode::CohortPlasNotActive,
        PlasReleaseGateFailureCode::CohortCoverageMissingGrantExercise,
        PlasReleaseGateFailureCode::MissingCapabilityWitness,
        PlasReleaseGateFailureCode::WitnessSignatureVerificationFailed,
        PlasReleaseGateFailureCode::EscrowReplayEvidenceMissing,
        PlasReleaseGateFailureCode::EscrowReplayMismatch,
        PlasReleaseGateFailureCode::RevocationWitnessMissing,
        PlasReleaseGateFailureCode::RevocationEscrowEventMissing,
        PlasReleaseGateFailureCode::AmbientAuthorityDetected,
    ];
    for code in &codes {
        assert_eq!(code.to_string(), code.error_code());
    }
}

// ─── 26. E2E: full lifecycle pass then tamper then fail ─────────────────

#[test]
fn e2e_pass_then_tamper_then_fail() {
    let (input, trust_anchors) = base_gate_fixture();
    let pass_artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(pass_artifact.pass);
    assert!(pass_artifact.findings.is_empty());

    let mut tampered = input.clone();
    tampered.extensions[0].grants[0]
        .replay_evidence
        .as_mut()
        .unwrap()
        .replay_outcome = "deny".to_string();
    let fail_artifact = evaluate_plas_release_gate(&tampered, &trust_anchors).unwrap();
    assert!(!fail_artifact.pass);
    assert!(!fail_artifact.findings.is_empty());
    assert_ne!(pass_artifact.decision_hash, fail_artifact.decision_hash);
}

// ─── 27. Log event coverage: fail events have error_code ────────────────

#[test]
fn fail_log_events_always_have_error_code() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].activation_mode = PlasActivationMode::Shadow;
    input.extensions[0]
        .active_capabilities
        .insert(Capability::new("net.admin"));
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    for log in &artifact.logs {
        if log.outcome == "fail" {
            assert!(
                log.error_code.is_some(),
                "fail log event '{}' missing error_code",
                log.event
            );
        }
    }
}

#[test]
fn pass_log_events_never_have_error_code() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    for log in &artifact.logs {
        if log.outcome == "pass" {
            assert!(
                log.error_code.is_none(),
                "pass log event '{}' has unexpected error_code: {:?}",
                log.event,
                log.error_code
            );
        }
    }
}

// ─── 28. Extension with no grants produces coverage finding ─────────────

#[test]
fn active_extension_with_no_grants_produces_coverage_finding() {
    let synthesizer_key = signing_key(7);
    let tree_head_key = signing_key(53);
    let ext = extension_id("no-grants-ext");

    let input = PlasReleaseGateInput {
        trace_id: "t-no-grants".into(),
        decision_id: "d-no-grants".into(),
        policy_id: "p-no-grants".into(),
        cohort_id: "c-no-grants".into(),
        extensions: vec![PlasCohortExtension {
            extension_id: ext,
            activation_mode: PlasActivationMode::Active,
            manifest_capabilities: BTreeSet::new(),
            active_capabilities: BTreeSet::new(),
            grants: Vec::new(),
            revocations: Vec::new(),
        }],
    };
    let trust = PlasReleaseGateTrustAnchors {
        witness_verification_key: synthesizer_key.verification_key(),
        transparency_log_verification_key: tree_head_key.verification_key(),
    };
    let artifact = evaluate_plas_release_gate(&input, &trust).unwrap();
    assert!(!artifact.pass);
    assert!(
        artifact
            .findings
            .iter()
            .any(|f| f.code == PlasReleaseGateFailureCode::CohortCoverageMissingGrantExercise)
    );
}

// ─── 29. Multiple failure codes in single run ───────────────────────────

#[test]
fn multiple_failure_codes_accumulated_in_single_run() {
    let (mut input, trust_anchors) = base_gate_fixture();
    // Not active + add untraceable capability
    input.extensions[0].activation_mode = PlasActivationMode::Disabled;
    input.extensions[0]
        .active_capabilities
        .insert(Capability::new("crypto.sign"));

    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(!artifact.pass);

    let codes: BTreeSet<_> = artifact.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&PlasReleaseGateFailureCode::CohortPlasNotActive));
    assert!(codes.contains(&PlasReleaseGateFailureCode::AmbientAuthorityDetected));
}

// ─── 30. Normalization: receipt whitespace trimmed ──────────────────────

#[test]
fn whitespace_padded_receipts_still_pass() {
    let (mut input, trust_anchors) = base_gate_fixture();
    // Pad receipt fields with whitespace — normalization should trim them
    let receipt = &mut input.extensions[0].grants[0].receipt;
    receipt.receipt_id = format!("  {}  ", receipt.receipt_id);
    receipt.decision_kind = format!("  {}  ", receipt.decision_kind);
    receipt.outcome = format!("  {}  ", receipt.outcome);
    receipt.policy_id = format!("  {}  ", receipt.policy_id);
    receipt.trace_id = format!("  {}  ", receipt.trace_id);
    receipt.decision_id = format!("  {}  ", receipt.decision_id);

    // Update replay evidence to match trimmed receipt
    let replay = input.extensions[0].grants[0]
        .replay_evidence
        .as_mut()
        .unwrap();
    replay.receipt_id = format!("  {}  ", replay.receipt_id);
    replay.replay_decision_kind = format!("  {}  ", replay.replay_decision_kind);
    replay.replay_outcome = format!("  {}  ", replay.replay_outcome);
    replay.replay_policy_id = format!("  {}  ", replay.replay_policy_id);

    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).unwrap();
    assert!(artifact.pass, "findings: {:?}", artifact.findings);
}
