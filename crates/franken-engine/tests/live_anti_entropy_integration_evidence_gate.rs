use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use frankenengine_engine::anti_entropy::{
    FallbackEvidence, FallbackProtocol, FallbackRequest, FallbackTrigger, ObjectId,
    ReconcileConfig, ReconcileEvent, ReconcileObjectType, ReconcileSession,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::recovery_artifact::{
    ArtifactBuilder, ArtifactType, ProofElement, RecoveryArtifact, RecoveryArtifactStore,
    RecoveryEvent, RecoveryTrigger,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const SCHEMA_VERSION: &str = "franken-engine.live-anti-entropy-integration-evidence.v1";
const EVENT_SCHEMA_VERSION: &str = "franken-engine.live-anti-entropy-integration-event.v1";
const COMPONENT: &str = "live_anti_entropy_integration_evidence_gate";
const BEAD_ID: &str = "bd-fmyrx";
const SCENARIO_ID: &str = "revocation_checkpoint_evidence_partition_repair";
const TRACE_ID: &str = "trace-bd-fmyrx-live-anti-entropy";
const POLICY_ID: &str = "policy:anti-entropy-integration-evidence-v1";
const LOCAL_REPLICA: &str = "replica-a";
const REMOTE_REPLICA: &str = "replica-b";
const SIGNING_KEY: &[u8] = b"bd-fmyrx-live-anti-entropy-recovery-key";

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveObject {
    object_id: ObjectId,
    payload: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IntegrationReport {
    schema_version: String,
    component: String,
    bead_id: String,
    scenario_id: String,
    trace_id: String,
    policy_id: String,
    epoch_id: u64,
    local_replica: String,
    remote_replica: String,
    object_scope: Vec<String>,
    strategy: String,
    evidence_classes: Vec<String>,
    compact_reconciliation_event: String,
    fallback_triggered: bool,
    fallback_id: String,
    local_only: Vec<String>,
    remote_only: Vec<String>,
    recovery_artifact_id: String,
    recovery_artifact_type: String,
    recovery_verdict: String,
    proof_element_count: usize,
    event_count: usize,
}

#[derive(Debug)]
struct GateExecution {
    report: IntegrationReport,
    recovery_artifact: RecoveryArtifact,
    reconcile_events: Vec<ReconcileEvent>,
    fallback_evidence: FallbackEvidence,
    recovery_events: Vec<RecoveryEvent>,
}

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(4_209)
}

fn live_object(object_type: ReconcileObjectType, epoch: SecurityEpoch, label: &str) -> LiveObject {
    let payload = format!("{object_type}:{label}");
    LiveObject {
        object_id: ObjectId {
            content_hash: ContentHash::compute(payload.as_bytes()),
            object_type,
            epoch,
        },
        payload,
    }
}

fn base_objects(epoch: SecurityEpoch) -> Vec<LiveObject> {
    vec![
        live_object(
            ReconcileObjectType::RevocationEvent,
            epoch,
            "capability-alpha-revoked",
        ),
        live_object(
            ReconcileObjectType::CheckpointMarker,
            epoch,
            "checkpoint-4209-root-a",
        ),
        live_object(
            ReconcileObjectType::EvidenceEntry,
            epoch,
            "decision-evidence-common",
        ),
    ]
}

fn local_only_objects(epoch: SecurityEpoch) -> Vec<LiveObject> {
    vec![
        live_object(
            ReconcileObjectType::RevocationEvent,
            epoch,
            "capability-beta-revoked-local",
        ),
        live_object(
            ReconcileObjectType::EvidenceEntry,
            epoch,
            "repair-evidence-local",
        ),
    ]
}

fn remote_only_objects(epoch: SecurityEpoch) -> Vec<LiveObject> {
    vec![
        live_object(
            ReconcileObjectType::CheckpointMarker,
            epoch,
            "checkpoint-4209-root-remote",
        ),
        live_object(
            ReconcileObjectType::EvidenceEntry,
            epoch,
            "repair-evidence-remote",
        ),
    ]
}

fn object_set(objects: &[LiveObject]) -> BTreeSet<[u8; 32]> {
    objects
        .iter()
        .map(|object| *object.object_id.content_hash.as_bytes())
        .collect()
}

fn object_scope(objects: &[LiveObject]) -> Vec<String> {
    let mut scope = objects
        .iter()
        .map(|object| object.object_id.object_type.to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    scope.sort();
    scope
}

fn hex_hashes(hashes: &[[u8; 32]]) -> Vec<String> {
    hashes.iter().map(hex::encode).collect()
}

fn state_hash(label: &str, objects: &[LiveObject]) -> ContentHash {
    let mut sorted = objects.to_vec();
    sorted.sort_by(|left, right| left.object_id.cmp(&right.object_id));

    let mut bytes = Vec::new();
    bytes.extend_from_slice(label.as_bytes());
    for object in sorted {
        bytes.extend_from_slice(object.object_id.object_type.to_string().as_bytes());
        bytes.extend_from_slice(object.object_id.content_hash.as_bytes());
        bytes.extend_from_slice(object.payload.as_bytes());
    }
    ContentHash::compute(&bytes)
}

fn run_live_anti_entropy_gate(reverse_input_order: bool) -> GateExecution {
    let epoch = epoch();
    let mut local_objects = base_objects(epoch);
    local_objects.extend(local_only_objects(epoch));
    let mut remote_objects = base_objects(epoch);
    remote_objects.extend(remote_only_objects(epoch));

    if reverse_input_order {
        local_objects.reverse();
        remote_objects.reverse();
    }

    let local_hashes = object_set(&local_objects);
    let remote_hashes = object_set(&remote_objects);
    let expected_difference = ReconcileSession::exact_difference(&local_hashes, &remote_hashes);

    let config = ReconcileConfig {
        iblt_cells: 1,
        iblt_hashes: 3,
        max_retries: 0,
        retry_scale_factor: 2,
    };
    let mut session = ReconcileSession::new(epoch, config);
    let remote_iblt = session.build_iblt(&remote_hashes);
    let compact_result = session
        .reconcile(&local_hashes, &remote_iblt, REMOTE_REPLICA, TRACE_ID)
        .expect("compact reconciliation should fail closed into fallback");
    assert!(compact_result.fallback_triggered);

    let reconcile_events = session.drain_events();
    let compact_event = reconcile_events
        .iter()
        .find(|event| event.event == "reconcile_fallback")
        .expect("compact reconciliation must emit fallback event");

    let mut fallback = FallbackProtocol::new(epoch);
    let fallback_result = fallback.execute(FallbackRequest {
        local_hashes: &local_hashes,
        remote_hashes: &remote_hashes,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 1 },
        reconciliation_id: TRACE_ID,
        peer: REMOTE_REPLICA,
        trace_id: TRACE_ID,
    });
    assert_eq!(fallback_result.objects_to_send, expected_difference.0);
    assert_eq!(fallback_result.objects_to_fetch, expected_difference.1);

    let fallback_evidence = fallback
        .drain_events()
        .into_iter()
        .next()
        .expect("fallback protocol must emit evidence");

    let mut all_objects = local_objects.clone();
    all_objects.extend(remote_objects.iter().cloned());
    let before_state = state_hash("before-partitioned-replica-state", &local_objects);
    let after_state = state_hash("after-forced-reconciliation-union-state", &all_objects);

    let recovery_artifact = ArtifactBuilder::new(
        ArtifactType::ForcedReconciliation,
        RecoveryTrigger::AutomaticFallback {
            fallback_id: fallback_evidence.fallback_id.clone(),
        },
        before_state,
        TRACE_ID,
        epoch.as_u64(),
        1_000,
        SIGNING_KEY,
    )
    .after_state(after_state)
    .proof(ProofElement::MmrConsistency {
        root_hash: after_state,
        leaf_count: all_objects.len() as u64,
        proof_hashes: vec![before_state],
    })
    .proof(ProofElement::HashChainVerification {
        start_marker_id: 4_209,
        end_marker_id: 4_210,
        chain_hash: ContentHash::compute(fallback_evidence.fallback_id.as_bytes()),
        verified: true,
    })
    .proof(ProofElement::EvidenceEntryLink {
        evidence_hash: ContentHash::compute(format!("{fallback_evidence:?}").as_bytes()),
        decision_id: format!("{BEAD_ID}:forced-reconciliation"),
    })
    .proof(ProofElement::EpochValidityCheck {
        epoch,
        is_valid: true,
        reason: "fixed epoch for deterministic live anti-entropy evidence".to_string(),
    })
    .build();

    let mut recovery_store = RecoveryArtifactStore::new(epoch, SIGNING_KEY);
    recovery_store.record(recovery_artifact.clone(), TRACE_ID);
    let verdict = recovery_store
        .verify(&recovery_artifact, TRACE_ID)
        .expect("recovery artifact verification should run");
    assert!(verdict.is_valid());
    let recovery_events = recovery_store.drain_events();

    let mut event_count = reconcile_events.len() + recovery_events.len();
    event_count += 1;

    GateExecution {
        report: IntegrationReport {
            schema_version: SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            bead_id: BEAD_ID.to_string(),
            scenario_id: SCENARIO_ID.to_string(),
            trace_id: TRACE_ID.to_string(),
            policy_id: POLICY_ID.to_string(),
            epoch_id: epoch.as_u64(),
            local_replica: LOCAL_REPLICA.to_string(),
            remote_replica: REMOTE_REPLICA.to_string(),
            object_scope: object_scope(&all_objects),
            strategy: "iblt_then_deterministic_fallback_then_verified_recovery_artifact"
                .to_string(),
            evidence_classes: vec![
                "deterministic_replay".to_string(),
                "interleaving_order_stability".to_string(),
                "conformance_scope_vector".to_string(),
                "adversarial_peel_failure".to_string(),
            ],
            compact_reconciliation_event: compact_event.event.clone(),
            fallback_triggered: true,
            fallback_id: fallback_evidence.fallback_id.clone(),
            local_only: hex_hashes(&fallback_result.objects_to_send),
            remote_only: hex_hashes(&fallback_result.objects_to_fetch),
            recovery_artifact_id: recovery_artifact.artifact_id.to_hex(),
            recovery_artifact_type: recovery_artifact.artifact_type.to_string(),
            recovery_verdict: verdict.to_string(),
            proof_element_count: recovery_artifact.proof_bundle.len(),
            event_count,
        },
        recovery_artifact,
        reconcile_events,
        fallback_evidence,
        recovery_events,
    }
}

fn write_live_anti_entropy_gate_bundle(run_dir: &Path) -> Result<IntegrationReport, String> {
    fs::create_dir_all(run_dir)
        .map_err(|error| format!("create {}: {error}", run_dir.display()))?;
    let execution = run_live_anti_entropy_gate(false);

    let report_path = run_dir.join("live_anti_entropy_report.json");
    let recovery_path = run_dir.join("recovery_artifact.json");
    let events_path = run_dir.join("events.jsonl");

    write_json(&report_path, &execution.report)?;
    write_json(&recovery_path, &execution.recovery_artifact)?;

    let mut events = Vec::new();
    for event in &execution.reconcile_events {
        events.push(json!({
            "schema_version": EVENT_SCHEMA_VERSION,
            "component": COMPONENT,
            "bead_id": BEAD_ID,
            "trace_id": event.trace_id,
            "event": event.event,
            "peer": event.peer,
            "fallback_triggered": event.fallback_triggered,
            "epoch_id": event.epoch_id,
        }));
    }
    events.push(json!({
        "schema_version": EVENT_SCHEMA_VERSION,
        "component": COMPONENT,
        "bead_id": BEAD_ID,
        "trace_id": execution.fallback_evidence.trace_id,
        "event": "fallback_executed",
        "fallback_id": execution.fallback_evidence.fallback_id,
        "differences_found": execution.fallback_evidence.differences_found,
        "objects_transferred": execution.fallback_evidence.objects_transferred,
        "epoch_id": execution.fallback_evidence.epoch_id,
    }));
    for event in &execution.recovery_events {
        events.push(json!({
            "schema_version": EVENT_SCHEMA_VERSION,
            "component": COMPONENT,
            "bead_id": BEAD_ID,
            "trace_id": event.trace_id,
            "event": event.event,
            "artifact_id": event.artifact_id,
            "artifact_type": event.artifact_type,
            "verification_verdict": event.verification_verdict,
            "epoch_id": event.epoch_id,
        }));
    }
    write_jsonl(&events_path, &events)?;

    Ok(execution.report)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("serialize {}: {error}", path.display()))?;
    fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.display()))
}

fn write_jsonl(path: &Path, values: &[Value]) -> Result<(), String> {
    let mut body = String::new();
    for value in values {
        body.push_str(
            &serde_json::to_string(value)
                .map_err(|error| format!("serialize event for {}: {error}", path.display()))?,
        );
        body.push('\n');
    }
    fs::write(path, body).map_err(|error| format!("write {}: {error}", path.display()))
}

#[test]
fn live_anti_entropy_gate_emits_verified_forced_reconciliation_artifact() {
    let execution = run_live_anti_entropy_gate(false);

    assert_eq!(execution.report.schema_version, SCHEMA_VERSION);
    assert_eq!(execution.report.component, COMPONENT);
    assert_eq!(execution.report.bead_id, BEAD_ID);
    assert_eq!(
        execution.report.object_scope,
        vec!["checkpoint_marker", "evidence_entry", "revocation_event"]
    );
    assert_eq!(
        execution.report.strategy,
        "iblt_then_deterministic_fallback_then_verified_recovery_artifact"
    );
    assert!(execution.report.fallback_triggered);
    assert_eq!(
        execution.report.compact_reconciliation_event,
        "reconcile_fallback"
    );
    assert_eq!(execution.report.local_only.len(), 2);
    assert_eq!(execution.report.remote_only.len(), 2);
    assert_eq!(
        execution.report.recovery_artifact_type,
        "forced_reconciliation"
    );
    assert_eq!(execution.report.recovery_verdict, "valid");
    assert_eq!(execution.report.proof_element_count, 4);
    assert_eq!(execution.fallback_evidence.differences_found, 4);
    assert_eq!(execution.fallback_evidence.objects_transferred, 4);
    assert!(matches!(
        execution.recovery_artifact.trigger,
        RecoveryTrigger::AutomaticFallback { .. }
    ));
}

#[test]
fn live_anti_entropy_gate_is_deterministic_under_reordered_inputs() {
    let canonical = run_live_anti_entropy_gate(false);
    let reversed = run_live_anti_entropy_gate(true);

    assert_eq!(canonical.report, reversed.report);
    assert_eq!(
        canonical.recovery_artifact.artifact_id,
        reversed.recovery_artifact.artifact_id
    );
    assert_eq!(
        canonical.recovery_artifact.signature,
        reversed.recovery_artifact.signature
    );
}

#[test]
fn live_anti_entropy_gate_writes_machine_verifiable_bundle() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let report =
        write_live_anti_entropy_gate_bundle(temp_dir.path()).expect("write evidence bundle");

    let report_path = temp_dir.path().join("live_anti_entropy_report.json");
    let recovery_path = temp_dir.path().join("recovery_artifact.json");
    let events_path = temp_dir.path().join("events.jsonl");

    assert!(report_path.is_file());
    assert!(recovery_path.is_file());
    assert!(events_path.is_file());
    assert_eq!(report.bead_id, BEAD_ID);

    let report_json: Value =
        serde_json::from_slice(&fs::read(report_path).expect("read report")).expect("report json");
    assert_eq!(report_json["bead_id"], BEAD_ID);
    assert_eq!(report_json["fallback_triggered"], true);
    assert_eq!(report_json["recovery_verdict"], "valid");

    let recovery_json: Value =
        serde_json::from_slice(&fs::read(recovery_path).expect("read recovery artifact"))
            .expect("recovery json");
    assert_eq!(recovery_json["artifact_type"], "ForcedReconciliation");
    assert_eq!(recovery_json["proof_bundle"].as_array().unwrap().len(), 4);

    let events = fs::read_to_string(events_path).expect("read events");
    let event_lines = events.lines().collect::<Vec<_>>();
    assert_eq!(event_lines.len(), report.event_count);
    assert!(
        event_lines
            .iter()
            .any(|line| line.contains("reconcile_fallback"))
    );
    assert!(
        event_lines
            .iter()
            .any(|line| line.contains("fallback_executed"))
    );
    assert!(
        event_lines
            .iter()
            .any(|line| line.contains("artifact_verified"))
    );
    for line in event_lines {
        let event: Value = serde_json::from_str(line).expect("event json");
        assert_eq!(event["schema_version"], EVENT_SCHEMA_VERSION);
        assert_eq!(event["bead_id"], BEAD_ID);
        assert_eq!(event["trace_id"], TRACE_ID);
    }
}

#[test]
fn gate_runner_links_bead_and_rch_target_dir_contract() {
    let script = include_str!("../../../scripts/check_live_anti_entropy_integration_evidence.sh");
    assert!(script.contains(BEAD_ID));
    assert!(script.contains("cargo check -p frankenengine-engine"));
    assert!(script.contains("cargo test -p frankenengine-engine"));
    assert!(script.contains("--target-dir"));
    assert!(script.contains("target_rch_reality_check"));
}
