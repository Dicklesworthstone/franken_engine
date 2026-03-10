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
    PlasReleaseGateFinding, PlasReleaseGateInput, PlasReleaseGateLogEvent,
    PlasReleaseGateTrustAnchors, PlasRevocationCheckRecord, evaluate_plas_release_gate,
};
use frankenengine_engine::policy_theorem_compiler::Capability;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{SigningKey, sign_preimage};

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

fn promote_witness_with_passing_theorems(
    extension_id: EngineObjectId,
    policy_id: EngineObjectId,
    capability: Capability,
    synthesizer_key: &SigningKey,
    epoch: u64,
    timestamp_ns: u64,
) -> CapabilityWitness {
    let mut witness = WitnessBuilder::new(
        extension_id,
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

fn grant_receipt(
    receipt_id: &str,
    extension_id: &EngineObjectId,
    capability: &Capability,
    timestamp_ns: u64,
    policy_id: &str,
) -> CapabilityEscrowReceiptRecord {
    CapabilityEscrowReceiptRecord {
        receipt_id: receipt_id.to_string(),
        extension_id: extension_id.clone(),
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

fn replay_evidence(receipt: &CapabilityEscrowReceiptRecord) -> PlasEscrowReplayEvidence {
    PlasEscrowReplayEvidence {
        receipt_id: receipt.receipt_id.clone(),
        replay_decision_kind: receipt.decision_kind.clone(),
        replay_outcome: receipt.outcome.clone(),
        replay_policy_id: receipt.policy_id.clone(),
        deterministic_replay: true,
        replay_trace_id: format!("replay-{}", receipt.receipt_id),
    }
}

fn revocation_receipt(
    receipt_id: &str,
    extension_id: &EngineObjectId,
    capability: &Capability,
    timestamp_ns: u64,
    policy_id: &str,
) -> CapabilityEscrowReceiptRecord {
    CapabilityEscrowReceiptRecord {
        receipt_id: receipt_id.to_string(),
        extension_id: extension_id.clone(),
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

fn base_gate_fixture() -> (PlasReleaseGateInput, PlasReleaseGateTrustAnchors) {
    let synthesizer_key = signing_key(7);
    let tree_head_key = signing_key(53);

    let extension = extension_id("alpha-extension");
    let gate_policy_id = "policy-plas-release-v1".to_string();

    let read_capability = Capability::new("fs.read");
    let write_capability = Capability::new("fs.write");

    let read_witness = promote_witness_with_passing_theorems(
        extension.clone(),
        policy_object_id("alpha-policy-read"),
        read_capability.clone(),
        &synthesizer_key,
        100,
        10_000,
    );
    let read_artifact = publish_artifact(read_witness, &tree_head_key, 10_500, None);
    let read_receipt = grant_receipt(
        "grant-alpha-read",
        &extension,
        &read_capability,
        10_700,
        &gate_policy_id,
    );

    let write_witness = promote_witness_with_passing_theorems(
        extension.clone(),
        policy_object_id("alpha-policy-write"),
        write_capability.clone(),
        &synthesizer_key,
        101,
        11_000,
    );
    let write_artifact = publish_artifact(write_witness, &tree_head_key, 11_200, Some(11_900));
    let write_receipt = grant_receipt(
        "grant-alpha-write",
        &extension,
        &write_capability,
        11_300,
        &gate_policy_id,
    );
    let revoke_receipt = revocation_receipt(
        "revoke-alpha-write",
        &extension,
        &write_capability,
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
            manifest_capabilities: BTreeSet::from([
                read_capability.clone(),
                write_capability.clone(),
            ]),
            active_capabilities: BTreeSet::from([read_capability.clone()]),
            grants: vec![
                PlasGrantCheckRecord {
                    capability: read_capability,
                    receipt: read_receipt.clone(),
                    witness_artifact: read_artifact,
                    replay_evidence: Some(replay_evidence(&read_receipt)),
                },
                PlasGrantCheckRecord {
                    capability: write_capability.clone(),
                    receipt: write_receipt.clone(),
                    witness_artifact: write_artifact.clone(),
                    replay_evidence: Some(replay_evidence(&write_receipt)),
                },
            ],
            revocations: vec![PlasRevocationCheckRecord {
                capability: write_capability,
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

#[test]
fn gate_passes_when_all_plas_release_criteria_are_satisfied() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation");

    assert!(artifact.pass);
    assert!(artifact.findings.is_empty());
    assert_eq!(artifact.checked_extensions, 1);
    assert_eq!(artifact.checked_grants, 2);
    assert_eq!(artifact.checked_revocations, 1);
    assert!(!artifact.logs.is_empty());
}

#[test]
fn gate_rejects_when_cohort_extension_is_not_active() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].activation_mode = PlasActivationMode::Shadow;

    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation");
    assert!(!artifact.pass);
    assert!(
        artifact
            .findings
            .iter()
            .any(|finding| finding.code == PlasReleaseGateFailureCode::CohortPlasNotActive)
    );
}

#[test]
fn gate_rejects_when_witness_signature_verification_fails() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0]
        .witness_artifact
        .witness
        .synthesizer_signature = vec![0x5A; 64];

    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation");
    assert!(!artifact.pass);
    assert!(artifact.findings.iter().any(|finding| {
        finding.code == PlasReleaseGateFailureCode::WitnessSignatureVerificationFailed
    }));
}

#[test]
fn gate_rejects_when_replay_evidence_is_missing_for_a_grant() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0].replay_evidence = None;

    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation");
    assert!(!artifact.pass);
    assert!(
        artifact
            .findings
            .iter()
            .any(|finding| finding.code == PlasReleaseGateFailureCode::EscrowReplayEvidenceMissing)
    );
}

#[test]
fn gate_rejects_when_replay_output_does_not_match_grant_receipt() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0]
        .replay_evidence
        .as_mut()
        .expect("replay evidence")
        .replay_outcome = "deny".to_string();

    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation");
    assert!(!artifact.pass);
    assert!(
        artifact
            .findings
            .iter()
            .any(|finding| finding.code == PlasReleaseGateFailureCode::EscrowReplayMismatch)
    );
}

#[test]
fn gate_rejects_when_revocation_receipt_lacks_signed_revocation_witness() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].revocations[0]
        .witness_artifact
        .revocation_proof = None;

    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation");
    assert!(!artifact.pass);
    assert!(
        artifact
            .findings
            .iter()
            .any(|finding| finding.code == PlasReleaseGateFailureCode::RevocationWitnessMissing)
    );
}

#[test]
fn gate_rejects_when_active_capability_has_no_witness_traceability() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0]
        .active_capabilities
        .insert(Capability::new("network.admin"));

    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation");
    assert!(!artifact.pass);
    assert!(
        artifact
            .findings
            .iter()
            .any(|finding| finding.code == PlasReleaseGateFailureCode::AmbientAuthorityDetected)
    );
}

#[test]
fn decision_artifact_is_deterministic_and_logs_use_stable_contract_keys() {
    let (input, trust_anchors) = base_gate_fixture();

    let first = evaluate_plas_release_gate(&input, &trust_anchors).expect("first evaluation");
    let second = evaluate_plas_release_gate(&input, &trust_anchors).expect("second evaluation");

    assert_eq!(first.pass, second.pass);
    assert_eq!(first.findings, second.findings);
    assert_eq!(first.decision_hash, second.decision_hash);

    let last_log = first.logs.last().expect("decision log");
    assert_eq!(last_log.trace_id, input.trace_id);
    assert_eq!(last_log.decision_id, input.decision_id);
    assert_eq!(last_log.policy_id, input.policy_id);
    assert_eq!(last_log.component, "plas_release_gate");
    assert_eq!(last_log.event, "release_gate_decision");
    assert_eq!(last_log.outcome, "pass");
    assert!(last_log.error_code.is_none());
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde, display, defaults, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn plas_activation_mode_serde_round_trip_all_variants() {
    for mode in [
        PlasActivationMode::Active,
        PlasActivationMode::Shadow,
        PlasActivationMode::AuditOnly,
        PlasActivationMode::Disabled,
    ] {
        let json = serde_json::to_string(&mode).expect("serialize");
        let recovered: PlasActivationMode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(mode, recovered);
        assert!(!mode.as_str().is_empty());
    }
}

#[test]
fn plas_release_gate_failure_code_serde_round_trip_all_variants() {
    for code in [
        PlasReleaseGateFailureCode::CohortPlasNotActive,
        PlasReleaseGateFailureCode::CohortCoverageMissingGrantExercise,
        PlasReleaseGateFailureCode::MissingCapabilityWitness,
        PlasReleaseGateFailureCode::WitnessSignatureVerificationFailed,
        PlasReleaseGateFailureCode::EscrowReplayEvidenceMissing,
        PlasReleaseGateFailureCode::EscrowReplayMismatch,
        PlasReleaseGateFailureCode::RevocationWitnessMissing,
        PlasReleaseGateFailureCode::RevocationEscrowEventMissing,
        PlasReleaseGateFailureCode::AmbientAuthorityDetected,
    ] {
        let json = serde_json::to_string(&code).expect("serialize");
        let recovered: PlasReleaseGateFailureCode =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(code, recovered);
        assert!(!code.error_code().is_empty());
    }
}

#[test]
fn plas_escrow_replay_evidence_serde_round_trip() {
    let evidence = PlasEscrowReplayEvidence {
        receipt_id: "receipt-serde".to_string(),
        replay_decision_kind: "grant".to_string(),
        replay_outcome: "allow".to_string(),
        replay_policy_id: "policy-serde".to_string(),
        deterministic_replay: true,
        replay_trace_id: "replay-trace-serde".to_string(),
    };
    let json = serde_json::to_string(&evidence).expect("serialize");
    let recovered: PlasEscrowReplayEvidence = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(evidence, recovered);
}

// ────────────────────────────────────────────────────────────
// Input validation
// ────────────────────────────────────────────────────────────

#[test]
fn gate_rejects_empty_trace_id() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.trace_id = String::new();
    let err = evaluate_plas_release_gate(&input, &trust_anchors).expect_err("should fail");
    assert!(matches!(err, PlasReleaseGateError::InvalidInput { .. }));
}

#[test]
fn gate_rejects_whitespace_only_decision_id() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.decision_id = "   ".to_string();
    let err = evaluate_plas_release_gate(&input, &trust_anchors).expect_err("should fail");
    assert!(matches!(err, PlasReleaseGateError::InvalidInput { .. }));
}

#[test]
fn gate_rejects_empty_policy_id() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.policy_id = String::new();
    let err = evaluate_plas_release_gate(&input, &trust_anchors).expect_err("should fail");
    assert!(matches!(err, PlasReleaseGateError::InvalidInput { .. }));
}

#[test]
fn gate_rejects_empty_cohort_id() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.cohort_id = "  ".to_string();
    let err = evaluate_plas_release_gate(&input, &trust_anchors).expect_err("should fail");
    assert!(matches!(err, PlasReleaseGateError::InvalidInput { .. }));
}

#[test]
fn gate_rejects_no_extensions() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions.clear();
    let err = evaluate_plas_release_gate(&input, &trust_anchors).expect_err("should fail");
    assert!(
        matches!(err, PlasReleaseGateError::InvalidInput { ref detail } if detail.contains("extension"))
    );
}

// ────────────────────────────────────────────────────────────
// Decision artifact fields
// ────────────────────────────────────────────────────────────

#[test]
fn decision_artifact_has_correct_ids() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation");
    assert_eq!(artifact.decision_id, input.decision_id);
    assert_eq!(artifact.cohort_id, input.cohort_id);
}

#[test]
fn decision_artifact_hash_is_non_empty() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation");
    assert!(!artifact.decision_hash.as_bytes().is_empty());
}

#[test]
fn decision_artifact_serde_round_trip() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation");
    let json = serde_json::to_string_pretty(&artifact).expect("serialize");
    let recovered: PlasReleaseGateDecisionArtifact =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact.pass, recovered.pass);
    assert_eq!(artifact.decision_id, recovered.decision_id);
    assert_eq!(artifact.findings, recovered.findings);
    assert_eq!(artifact.decision_hash, recovered.decision_hash);
}

#[test]
fn decision_artifact_logs_contain_component_and_event() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation");
    for log in &artifact.logs {
        assert!(!log.component.is_empty());
        assert!(!log.event.is_empty());
        assert!(!log.trace_id.is_empty());
    }
}

// ────────────────────────────────────────────────────────────
// Error display and types
// ────────────────────────────────────────────────────────────

#[test]
fn plas_release_gate_error_invalid_input_display() {
    let err = PlasReleaseGateError::InvalidInput {
        detail: "test detail".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("test detail"));
    assert!(msg.contains("invalid") || msg.contains("PLAS"));
}

#[test]
fn plas_release_gate_error_serialization_display() {
    let err = PlasReleaseGateError::Serialization {
        detail: "json error".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("json error"));
}

#[test]
fn plas_release_gate_error_serde_round_trip() {
    for err in [
        PlasReleaseGateError::InvalidInput {
            detail: "bad input".to_string(),
        },
        PlasReleaseGateError::Serialization {
            detail: "bad serial".to_string(),
        },
    ] {
        let json = serde_json::to_string(&err).expect("serialize");
        let recovered: PlasReleaseGateError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, recovered);
    }
}

#[test]
fn plas_release_gate_error_is_std_error() {
    let err = PlasReleaseGateError::InvalidInput {
        detail: "test".to_string(),
    };
    let std_err: &dyn std::error::Error = &err;
    assert!(!std_err.to_string().is_empty());
}

// ────────────────────────────────────────────────────────────
// Failure code coverage
// ────────────────────────────────────────────────────────────

#[test]
fn failure_code_error_code_strings_are_unique() {
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
    let unique: BTreeSet<&str> = codes.iter().map(|c| c.error_code()).collect();
    assert_eq!(
        unique.len(),
        codes.len(),
        "all error codes should be unique"
    );
}

#[test]
fn failure_code_display_matches_error_code() {
    for code in [
        PlasReleaseGateFailureCode::CohortPlasNotActive,
        PlasReleaseGateFailureCode::EscrowReplayMismatch,
        PlasReleaseGateFailureCode::AmbientAuthorityDetected,
    ] {
        assert_eq!(code.to_string(), code.error_code());
    }
}

// ────────────────────────────────────────────────────────────
// Activation mode coverage
// ────────────────────────────────────────────────────────────

#[test]
fn activation_mode_as_str_is_non_empty() {
    for mode in [
        PlasActivationMode::Active,
        PlasActivationMode::Shadow,
        PlasActivationMode::AuditOnly,
        PlasActivationMode::Disabled,
    ] {
        assert!(!mode.as_str().is_empty());
    }
}

#[test]
fn activation_mode_disabled_also_rejects() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].activation_mode = PlasActivationMode::Disabled;
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation");
    assert!(!artifact.pass);
}

#[test]
fn activation_mode_audit_only_also_rejects() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].activation_mode = PlasActivationMode::AuditOnly;
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation");
    assert!(!artifact.pass);
}

// ────────────────────────────────────────────────────────────
// Replay evidence edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn gate_rejects_when_replay_decision_kind_mismatches() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0]
        .replay_evidence
        .as_mut()
        .expect("replay evidence")
        .replay_decision_kind = "revoke".to_string();

    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation");
    assert!(!artifact.pass);
}

#[test]
fn gate_rejects_when_replay_nondeterministic() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].grants[0]
        .replay_evidence
        .as_mut()
        .expect("replay evidence")
        .deterministic_replay = false;

    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation");
    assert!(!artifact.pass);
}

// ────────────────────────────────────────────────────────────
// Coverage gap: missing capability witness for manifest capability
// ────────────────────────────────────────────────────────────

#[test]
fn gate_passes_when_manifest_has_extra_inactive_capability() {
    let (mut input, trust_anchors) = base_gate_fixture();
    // Add a manifest capability that is NOT active — gate should still pass
    input.extensions[0]
        .manifest_capabilities
        .insert(Capability::new("net.outbound"));

    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation");
    assert!(
        artifact.pass,
        "extra inactive manifest capability should not cause failure"
    );
}

// ────────────────────────────────────────────────────────────
// Log structure
// ────────────────────────────────────────────────────────────

#[test]
fn failing_gate_logs_contain_error_code() {
    let (mut input, trust_anchors) = base_gate_fixture();
    input.extensions[0].activation_mode = PlasActivationMode::Shadow;

    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation");
    assert!(!artifact.pass);
    let decision_log = artifact.logs.last().expect("last log is decision");
    assert_eq!(decision_log.outcome, "fail");
    assert!(decision_log.error_code.is_some());
}

#[test]
fn passing_gate_last_log_has_pass_outcome() {
    let (input, trust_anchors) = base_gate_fixture();
    let artifact = evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation");
    let decision_log = artifact.logs.last().expect("last log");
    assert_eq!(decision_log.outcome, "pass");
    assert!(decision_log.error_code.is_none());
}

// ────────────────────────────────────────────────────────────
// Determinism
// ────────────────────────────────────────────────────────────

#[test]
fn gate_is_deterministic_across_multiple_evaluations() {
    let (input, trust_anchors) = base_gate_fixture();
    let results: Vec<_> = (0..3)
        .map(|_| evaluate_plas_release_gate(&input, &trust_anchors).expect("gate evaluation"))
        .collect();
    for r in &results[1..] {
        assert_eq!(results[0].pass, r.pass);
        assert_eq!(results[0].decision_hash, r.decision_hash);
        assert_eq!(results[0].findings, r.findings);
    }
}

// ────────────────────────────────────────────────────────────
// Serde of finding
// ────────────────────────────────────────────────────────────

#[test]
fn plas_finding_serde_round_trip() {
    let finding = PlasReleaseGateFinding {
        code: PlasReleaseGateFailureCode::AmbientAuthorityDetected,
        extension_id: "ext-1".to_string(),
        receipt_id: Some("receipt-1".to_string()),
        detail: "ambient authority found".to_string(),
    };
    let json = serde_json::to_string(&finding).expect("serialize");
    let recovered: PlasReleaseGateFinding = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(finding, recovered);
}

#[test]
fn plas_log_event_serde_round_trip() {
    let log = PlasReleaseGateLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "plas_release_gate".to_string(),
        event: "release_gate_decision".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        extension_id: Some("ext-1".to_string()),
        receipt_id: None,
        capability: Some("fs.read".to_string()),
    };
    let json = serde_json::to_string(&log).expect("serialize");
    let recovered: PlasReleaseGateLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(log, recovered);
}

// ────────────────────────────────────────────────────────────
// Trust anchor structs
// ────────────────────────────────────────────────────────────

#[test]
fn trust_anchors_serde_round_trip() {
    let (_, trust_anchors) = base_gate_fixture();
    let json = serde_json::to_string(&trust_anchors).expect("serialize");
    let recovered: PlasReleaseGateTrustAnchors = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(trust_anchors, recovered);
}

// ────────────────────────────────────────────────────────────
// Grant check record and cohort extension serde
// ────────────────────────────────────────────────────────────

#[test]
fn plas_cohort_extension_serde_round_trip() {
    let (input, _) = base_gate_fixture();
    let ext = &input.extensions[0];
    let json = serde_json::to_string(ext).expect("serialize");
    let recovered: PlasCohortExtension = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ext.extension_id, recovered.extension_id);
    assert_eq!(ext.activation_mode, recovered.activation_mode);
    assert_eq!(ext.manifest_capabilities, recovered.manifest_capabilities);
}

#[test]
fn plas_release_gate_input_serde_round_trip() {
    let (input, _) = base_gate_fixture();
    let json = serde_json::to_string(&input).expect("serialize");
    let recovered: PlasReleaseGateInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(input.trace_id, recovered.trace_id);
    assert_eq!(input.decision_id, recovered.decision_id);
    assert_eq!(input.extensions.len(), recovered.extensions.len());
}
