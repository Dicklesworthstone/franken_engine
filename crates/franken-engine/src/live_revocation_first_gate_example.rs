use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::capability_witness::{
    CapabilityWitness, ConfidenceInterval, LifecycleState, PromotionTheoremInput, ProofKind,
    ProofObligation, PublicationEntryKind, PublishedWitnessArtifact, SourceCapabilitySet,
    TransparencyProofBundle, WitnessPublicationConfig, WitnessPublicationPipeline,
    WitnessPublicationQuery,
};
use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::policy_theorem_compiler::Capability;
use crate::proof_artifact::{PROOF_EVENT_SCHEMA_VERSION, ProofEventSeverity, sha256_file};
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::SigningKey;

pub const LIVE_REVOCATION_FIRST_GATE_SCHEMA_VERSION: &str =
    "franken-engine.live-revocation-first-gate-example.v1";
pub const LIVE_REVOCATION_RECEIPT_SCHEMA_VERSION: &str =
    "franken-engine.live-revocation-first-gate-receipt.v1";
pub const COMPONENT: &str = "live_revocation_first_gate_example";
pub const BEAD_ID: &str = "bd-3mp80";
pub const SCENARIO_ID: &str = "synthetic_capability_revocation_v1";
pub const DECISION_ID: &str = "decision:post-revocation-capability-use";
pub const GRANTED_CAPABILITY: &str = "net.connect:partner-api";
pub const REVOKED_REASON: &str = "synthetic compromise receipt: revoked before decision";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationDecisionRequest {
    pub request_id: String,
    pub extension_id: String,
    pub requested_capability: String,
    pub timestamp_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptArtifactRef {
    pub receipt_kind: String,
    pub path: String,
    pub sha256: String,
    pub log_sequence: u64,
    pub tree_head_signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveRevocationFirstGateReport {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub scenario_id: String,
    pub extension_id: String,
    pub policy_id: String,
    pub witness_id: String,
    pub publication_id: String,
    pub granted_capability: String,
    pub revocation_reason: String,
    pub decision_request: RevocationDecisionRequest,
    pub decision: String,
    pub denial_reason: String,
    pub active_query_count_after_revocation: usize,
    pub revoked_query_count_after_revocation: usize,
    pub signed_receipts_verified: bool,
    pub receipt_artifacts: Vec<ReceiptArtifactRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveRevocationFirstGateEvent {
    pub schema_version: String,
    pub event_name: String,
    pub severity: ProofEventSeverity,
    pub step_id: String,
    pub command_id: Option<String>,
    pub artifact_path: Option<String>,
    pub artifact_sha256: Option<String>,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u64>,
    pub decision: String,
    pub remediation: Option<String>,
    pub scenario_id: String,
    pub decision_id: String,
    pub witness_id: String,
    pub publication_id: String,
    pub requested_capability: String,
    pub reason: String,
    pub log_sequence: Option<u64>,
    pub tree_head_signature_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTransparencyReceipt {
    pub schema_version: String,
    pub receipt_kind: String,
    pub publication_id: String,
    pub witness_id: String,
    pub extension_id: String,
    pub policy_id: String,
    pub published_hash: String,
    pub log_entry_kind: PublicationEntryKind,
    pub log_sequence: u64,
    pub leaf_hash: String,
    pub predecessor_leaf_hash: String,
    pub mmr_root: String,
    pub tree_head_hash: String,
    pub tree_head_signature_hex: String,
    pub consistency_link_count: usize,
    pub signature_bundle_count: usize,
    pub signature_bundle_hash: String,
    pub timestamp_ns: u64,
    pub revocation_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveRevocationFirstGateExecution {
    pub report: LiveRevocationFirstGateReport,
    pub events: Vec<LiveRevocationFirstGateEvent>,
    pub publication_receipt: SignedTransparencyReceipt,
    pub revocation_receipt: SignedTransparencyReceipt,
}

pub fn run_live_revocation_first_gate_example() -> Result<LiveRevocationFirstGateExecution, String>
{
    let witness_key = signing_key(17)?;
    let head_key = signing_key(29)?;
    let extension_id = derive_id(
        ObjectDomain::Attestation,
        "live-revocation-first-extension",
        b"LiveRevocationFirstExtension.v1",
        b"extension:revocation-first",
    )?;
    let policy_id = derive_id(
        ObjectDomain::PolicyObject,
        "live-revocation-first-policy",
        b"LiveRevocationFirstPolicy.v1",
        b"policy:revocation-first",
    )?;
    let requested_capability = Capability::new(GRANTED_CAPABILITY);
    let witness = build_promoted_witness(
        extension_id.clone(),
        policy_id.clone(),
        requested_capability.clone(),
        witness_key.clone(),
    )?;
    let witness_id = witness.witness_id.clone();

    let mut pipeline = WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(4_200),
        head_key.clone(),
        WitnessPublicationConfig {
            checkpoint_interval: 1,
            policy_id: "live-revocation-first-gate".to_string(),
            governance_ledger_config: None,
        },
    )
    .map_err(|error| format!("create publication pipeline: {error}"))?;

    let publication_id = pipeline
        .publish_witness(witness.clone(), 1_000_000)
        .map_err(|error| format!("publish synthetic capability witness: {error}"))?;
    pipeline
        .revoke_witness(&witness_id, REVOKED_REASON, 2_000_000)
        .map_err(|error| format!("revoke synthetic capability witness: {error}"))?;

    let active_query_count_after_revocation = pipeline
        .query(&WitnessPublicationQuery {
            extension_id: Some(extension_id.clone()),
            policy_id: Some(policy_id.clone()),
            epoch: None,
            content_hash: None,
            include_revoked: false,
        })
        .len();
    let revoked_query_count_after_revocation = pipeline
        .query(&WitnessPublicationQuery {
            extension_id: Some(extension_id.clone()),
            policy_id: Some(policy_id.clone()),
            epoch: None,
            content_hash: None,
            include_revoked: true,
        })
        .len();

    let artifact = pipeline
        .publications()
        .iter()
        .find(|candidate| candidate.publication_id == publication_id)
        .ok_or_else(|| "published witness artifact disappeared".to_string())?;
    let revocation_proof = artifact
        .revocation_proof
        .as_ref()
        .ok_or_else(|| "revocation proof missing after revoke_witness".to_string())?;
    WitnessPublicationPipeline::verify_artifact(
        artifact,
        &witness_key.verification_key(),
        &head_key.verification_key(),
    )
    .map_err(|error| format!("verify generated receipts: {error}"))?;

    let publication_receipt =
        receipt_from_bundle("publication", artifact, &artifact.publication_proof);
    let revocation_receipt = receipt_from_bundle("revocation", artifact, revocation_proof);
    let decision = if artifact.is_revoked() && active_query_count_after_revocation == 0 {
        "deny"
    } else {
        "allow"
    };
    let denial_reason = if decision == "deny" {
        "revoked_capability_witness"
    } else {
        "revocation_not_observed"
    };

    let report = LiveRevocationFirstGateReport {
        schema_version: LIVE_REVOCATION_FIRST_GATE_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        scenario_id: SCENARIO_ID.to_string(),
        extension_id: extension_id.to_string(),
        policy_id: policy_id.to_string(),
        witness_id: witness_id.to_string(),
        publication_id: publication_id.to_string(),
        granted_capability: GRANTED_CAPABILITY.to_string(),
        revocation_reason: REVOKED_REASON.to_string(),
        decision_request: RevocationDecisionRequest {
            request_id: DECISION_ID.to_string(),
            extension_id: extension_id.to_string(),
            requested_capability: GRANTED_CAPABILITY.to_string(),
            timestamp_ns: 2_500_000,
        },
        decision: decision.to_string(),
        denial_reason: denial_reason.to_string(),
        active_query_count_after_revocation,
        revoked_query_count_after_revocation,
        signed_receipts_verified: decision == "deny",
        receipt_artifacts: Vec::new(),
    };

    let events = vec![
        LiveRevocationFirstGateEvent {
            schema_version: PROOF_EVENT_SCHEMA_VERSION.to_string(),
            event_name: "live_revocation_first_gate.capability_granted".to_string(),
            severity: ProofEventSeverity::Info,
            step_id: "grant".to_string(),
            command_id: Some("publish_witness".to_string()),
            artifact_path: None,
            artifact_sha256: None,
            exit_code: Some(0),
            duration_ms: Some(1),
            decision: "granted".to_string(),
            remediation: None,
            scenario_id: SCENARIO_ID.to_string(),
            decision_id: DECISION_ID.to_string(),
            witness_id: witness_id.to_string(),
            publication_id: publication_id.to_string(),
            requested_capability: GRANTED_CAPABILITY.to_string(),
            reason: "synthetic witness published before revocation".to_string(),
            log_sequence: Some(publication_receipt.log_sequence),
            tree_head_signature_hex: Some(publication_receipt.tree_head_signature_hex.clone()),
        },
        LiveRevocationFirstGateEvent {
            schema_version: PROOF_EVENT_SCHEMA_VERSION.to_string(),
            event_name: "live_revocation_first_gate.capability_revoked".to_string(),
            severity: ProofEventSeverity::Info,
            step_id: "revoke".to_string(),
            command_id: Some("revoke_witness".to_string()),
            artifact_path: None,
            artifact_sha256: None,
            exit_code: Some(0),
            duration_ms: Some(1),
            decision: "revoked".to_string(),
            remediation: None,
            scenario_id: SCENARIO_ID.to_string(),
            decision_id: DECISION_ID.to_string(),
            witness_id: witness_id.to_string(),
            publication_id: publication_id.to_string(),
            requested_capability: GRANTED_CAPABILITY.to_string(),
            reason: REVOKED_REASON.to_string(),
            log_sequence: Some(revocation_receipt.log_sequence),
            tree_head_signature_hex: Some(revocation_receipt.tree_head_signature_hex.clone()),
        },
        LiveRevocationFirstGateEvent {
            schema_version: PROOF_EVENT_SCHEMA_VERSION.to_string(),
            event_name: "live_revocation_first_gate.post_revocation_decision".to_string(),
            severity: if decision == "deny" {
                ProofEventSeverity::Info
            } else {
                ProofEventSeverity::Error
            },
            step_id: "decision".to_string(),
            command_id: Some("query_publication_index".to_string()),
            artifact_path: None,
            artifact_sha256: None,
            exit_code: Some(0),
            duration_ms: Some(1),
            decision: decision.to_string(),
            remediation: (decision != "deny")
                .then(|| "decision must deny revoked capability witnesses".to_string()),
            scenario_id: SCENARIO_ID.to_string(),
            decision_id: DECISION_ID.to_string(),
            witness_id: witness_id.to_string(),
            publication_id: publication_id.to_string(),
            requested_capability: GRANTED_CAPABILITY.to_string(),
            reason: denial_reason.to_string(),
            log_sequence: Some(revocation_receipt.log_sequence),
            tree_head_signature_hex: Some(revocation_receipt.tree_head_signature_hex.clone()),
        },
    ];

    Ok(LiveRevocationFirstGateExecution {
        report,
        events,
        publication_receipt,
        revocation_receipt,
    })
}

pub fn write_live_revocation_first_gate_artifacts(
    run_dir: impl AsRef<Path>,
) -> Result<LiveRevocationFirstGateReport, String> {
    let run_dir = run_dir.as_ref();
    let receipts_dir = run_dir.join("receipts");
    fs::create_dir_all(&receipts_dir)
        .map_err(|error| format!("create {}: {error}", path_display(&receipts_dir)))?;

    let mut execution = run_live_revocation_first_gate_example()?;
    let publication_receipt_path = receipts_dir.join("publication_receipt.json");
    let revocation_receipt_path = receipts_dir.join("revocation_receipt.json");
    write_json_pretty(&publication_receipt_path, &execution.publication_receipt)?;
    write_json_pretty(&revocation_receipt_path, &execution.revocation_receipt)?;

    let publication_receipt_hash = prefixed_file_hash(&publication_receipt_path)?;
    let revocation_receipt_hash = prefixed_file_hash(&revocation_receipt_path)?;
    let publication_receipt_path_string = path_display(&publication_receipt_path);
    let revocation_receipt_path_string = path_display(&revocation_receipt_path);

    execution.report.receipt_artifacts = vec![
        ReceiptArtifactRef {
            receipt_kind: "publication".to_string(),
            path: publication_receipt_path_string.clone(),
            sha256: publication_receipt_hash.clone(),
            log_sequence: execution.publication_receipt.log_sequence,
            tree_head_signature_hex: execution
                .publication_receipt
                .tree_head_signature_hex
                .clone(),
        },
        ReceiptArtifactRef {
            receipt_kind: "revocation".to_string(),
            path: revocation_receipt_path_string.clone(),
            sha256: revocation_receipt_hash.clone(),
            log_sequence: execution.revocation_receipt.log_sequence,
            tree_head_signature_hex: execution.revocation_receipt.tree_head_signature_hex.clone(),
        },
    ];

    if let Some(event) = execution.events.get_mut(0) {
        event.artifact_path = Some(publication_receipt_path_string);
        event.artifact_sha256 = Some(publication_receipt_hash);
    }
    for event in execution.events.iter_mut().skip(1) {
        event.artifact_path = Some(revocation_receipt_path_string.clone());
        event.artifact_sha256 = Some(revocation_receipt_hash.clone());
    }

    let source_report_path = run_dir.join("source_report.json");
    let events_path = run_dir.join("events.jsonl");
    write_json_pretty(&source_report_path, &execution.report)?;
    write_events_jsonl(&events_path, &execution.events)?;

    Ok(execution.report)
}

fn build_promoted_witness(
    extension_id: EngineObjectId,
    policy_id: EngineObjectId,
    requested_capability: Capability,
    witness_key: SigningKey,
) -> Result<CapabilityWitness, String> {
    let proof_artifact_id = derive_id(
        ObjectDomain::EvidenceRecord,
        "live-revocation-first-proof",
        b"LiveRevocationFirstProof.v1",
        GRANTED_CAPABILITY.as_bytes(),
    )?;
    let proof = ProofObligation {
        capability: requested_capability.clone(),
        kind: ProofKind::DynamicAblation,
        proof_artifact_id,
        justification: "synthetic ablation transcript: capability removal breaks request"
            .to_string(),
        artifact_hash: ContentHash::compute(b"live-revocation-first-proof:grant"),
    };

    let mut witness = crate::capability_witness::WitnessBuilder::new(
        extension_id,
        policy_id,
        SecurityEpoch::from_raw(4_200),
        500_000,
        witness_key.clone(),
    )
    .require(requested_capability.clone())
    .proof(proof)
    .confidence(ConfidenceInterval::from_trials(256, 255))
    .replay_seed(0x3_8000)
    .transcript_hash(ContentHash::compute(
        b"live-revocation-first:grant-then-revoke",
    ))
    .meta("example_component", COMPONENT)
    .meta("bead_id", BEAD_ID)
    .build()
    .map_err(|error| format!("build synthetic witness: {error}"))?;

    let mut manifest_capabilities = BTreeSet::new();
    manifest_capabilities.insert(requested_capability);
    let theorem_input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: "synthetic-ablation-transcript".to_string(),
            capabilities: manifest_capabilities.clone(),
        }],
        manifest_capabilities,
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    };
    witness.metadata.insert(
        "trusted_synthesizer_verification_key".to_string(),
        witness_key.verification_key().to_hex(),
    );
    let theorem_report = witness
        .evaluate_promotion_theorems_signed_by(&theorem_input, &witness_key)
        .map_err(|error| format!("evaluate promotion theorems: {error}"))?;
    if !theorem_report.all_passed {
        return Err("synthetic witness promotion theorem report failed".to_string());
    }
    witness
        .apply_promotion_theorem_report(&theorem_report)
        .map_err(|error| format!("apply promotion theorem report: {error}"))?;
    witness
        .transition_to(LifecycleState::Validated)
        .map_err(|error| format!("validate witness: {error}"))?;
    witness
        .transition_to(LifecycleState::Promoted)
        .map_err(|error| format!("promote witness: {error}"))?;
    Ok(witness)
}

fn receipt_from_bundle(
    receipt_kind: &str,
    artifact: &PublishedWitnessArtifact,
    bundle: &TransparencyProofBundle,
) -> SignedTransparencyReceipt {
    let mut signature_bundle_bytes = Vec::new();
    for signature in &artifact.signature_bundle {
        signature_bundle_bytes.extend_from_slice(signature);
    }

    SignedTransparencyReceipt {
        schema_version: LIVE_REVOCATION_RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_kind: receipt_kind.to_string(),
        publication_id: artifact.publication_id.to_string(),
        witness_id: artifact.witness.witness_id.to_string(),
        extension_id: artifact.witness.extension_id.to_string(),
        policy_id: artifact.witness.policy_id.to_string(),
        published_hash: artifact.published_hash.to_hex(),
        log_entry_kind: bundle.log_entry.kind,
        log_sequence: bundle.log_entry.sequence,
        leaf_hash: bundle.log_entry.leaf_hash.to_hex(),
        predecessor_leaf_hash: bundle.log_entry.predecessor_leaf_hash.to_hex(),
        mmr_root: bundle.tree_head.mmr_root.to_hex(),
        tree_head_hash: bundle.tree_head.head_hash.to_hex(),
        tree_head_signature_hex: hex::encode(&bundle.tree_head.signature),
        consistency_link_count: bundle.consistency_chain.len(),
        signature_bundle_count: artifact.signature_bundle.len(),
        signature_bundle_hash: ContentHash::compute(&signature_bundle_bytes).to_hex(),
        timestamp_ns: bundle.log_entry.timestamp_ns,
        revocation_reason: bundle.log_entry.revocation_reason.clone(),
    }
}

fn derive_id(
    domain: ObjectDomain,
    zone: &str,
    schema_definition: &[u8],
    payload: &[u8],
) -> Result<EngineObjectId, String> {
    engine_object_id::derive_id(
        domain,
        zone,
        &SchemaId::from_definition(schema_definition),
        payload,
    )
    .map_err(|error| format!("derive engine object id for {zone}: {error}"))
}

fn signing_key(byte: u8) -> Result<SigningKey, String> {
    SigningKey::from_bytes([byte; 32]).map_err(|error| format!("create signing key: {error}"))
}

fn write_json_pretty(path: &Path, value: &impl Serialize) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", path_display(parent)))?;
    }
    let file =
        File::create(path).map_err(|error| format!("create {}: {error}", path_display(path)))?;
    serde_json::to_writer_pretty(file, value)
        .map_err(|error| format!("write {}: {error}", path_display(path)))
}

fn write_events_jsonl(path: &Path, events: &[LiveRevocationFirstGateEvent]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", path_display(parent)))?;
    }
    let mut file =
        File::create(path).map_err(|error| format!("create {}: {error}", path_display(path)))?;
    for event in events {
        serde_json::to_writer(&mut file, event)
            .map_err(|error| format!("write event to {}: {error}", path_display(path)))?;
        file.write_all(b"\n")
            .map_err(|error| format!("write newline to {}: {error}", path_display(path)))?;
    }
    Ok(())
}

fn prefixed_file_hash(path: &Path) -> Result<String, String> {
    sha256_file(path)
        .map(|digest| format!("sha256:{digest}"))
        .map_err(|error| format!("hash {}: {error}", path_display(path)))
}

fn path_display(path: &Path) -> String {
    path_to_string(path.to_path_buf())
}

fn path_to_string(path: PathBuf) -> String {
    path.to_string_lossy().replace('\\', "/")
}
