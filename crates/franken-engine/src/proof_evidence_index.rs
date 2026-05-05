//! Typed proof-evidence index for artifacts, receipts, validation plans, and gates.
//!
//! The index deliberately imports only structured evidence with an explicit
//! source revision and content hash, then persists rows through the
//! sqlmodel_rust typed boundary over `StoreKind::EvidenceIndex`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::proof_artifact::{PROOF_COST_MANIFEST_SCHEMA_VERSION, PROOF_MANIFEST_SCHEMA_VERSION};
use crate::storage_adapter::{EventContext, StorageAdapter, StorageError, StoreKind, StoreQuery};
use crate::typed_persistence_models::{
    ProofEvidenceIndexEntry, TypedStorageAdapterExt, TypedStoreRecord, allocate_typed_record_id,
};

/// Stable schema for dashboard/report query envelopes emitted by this module.
pub const PROOF_EVIDENCE_QUERY_SCHEMA_VERSION: &str = "franken-engine.proof-evidence-query.v1";

/// Schema emitted by `scripts/swarm_validation_planner.sh`.
pub const SWARM_VALIDATION_PLAN_SCHEMA_VERSION: &str = "franken-engine.swarm-validation-plan.v1";

/// Schema emitted by `scripts/focused_proof_cost_gate.sh`.
pub const FOCUSED_PROOF_COST_GATE_REPORT_SCHEMA_VERSION: &str =
    "franken-engine.focused-proof-cost-gate-report.v1";

/// Schema emitted by `scripts/focused_proof_runner.sh`.
pub const FOCUSED_PROOF_RUNNER_REPORT_SCHEMA_VERSION: &str =
    "franken-engine.focused-proof-runner-report.v1";

const TYPED_EVIDENCE_KEY_PREFIX: &str = "typed/evidence_index/";

type StorageResult<T> = Result<T, StorageError>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct EvidenceSeed {
    natural_key: String,
    bead_id: String,
    source_revision: String,
    artifact_id: String,
    artifact_path: String,
    artifact_role: String,
    artifact_sha256: String,
    receipt_kind: String,
    gate_status: String,
    generated_timestamp_ms: i64,
    freshness_deadline_ms: i64,
    metadata_json: String,
}

impl EvidenceSeed {
    fn into_entry(self, evidence_id: i64) -> ProofEvidenceIndexEntry {
        ProofEvidenceIndexEntry {
            evidence_id,
            bead_id: self.bead_id,
            source_revision: self.source_revision,
            artifact_id: self.artifact_id,
            artifact_path: self.artifact_path,
            artifact_role: self.artifact_role,
            artifact_sha256: self.artifact_sha256,
            receipt_kind: self.receipt_kind,
            gate_status: self.gate_status,
            generated_timestamp_ms: self.generated_timestamp_ms,
            freshness_deadline_ms: self.freshness_deadline_ms,
            metadata_json: self.metadata_json,
        }
    }
}

/// Stable JSON envelope for proof-evidence dashboard queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofEvidenceQueryReport {
    pub schema_version: String,
    pub query_kind: String,
    pub rows: Vec<ProofEvidenceIndexEntry>,
}

/// Import metadata for a focused proof runner or proof-cost gate report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateReportImport<'a> {
    pub bead_id: &'a str,
    pub source_revision: &'a str,
    pub artifact_path: &'a str,
    pub expected_source_revision: &'a str,
    pub generated_timestamp_ms: i64,
    pub freshness_policy_ms: i64,
}

/// Import a proof artifact manifest JSON document into the typed index.
pub fn import_proof_manifest_json<S>(
    storage: &mut S,
    manifest_json: &str,
    expected_source_revision: &str,
    freshness_policy_ms: i64,
    context: &EventContext,
) -> StorageResult<Vec<ProofEvidenceIndexEntry>>
where
    S: StorageAdapter,
{
    let manifest = parse_json_document(manifest_json, "proof artifact manifest")?;
    import_proof_manifest_value(
        storage,
        &manifest,
        expected_source_revision,
        freshness_policy_ms,
        context,
    )
}

/// Import a proof artifact manifest value into the typed index.
pub fn import_proof_manifest_value<S>(
    storage: &mut S,
    manifest: &Value,
    expected_source_revision: &str,
    freshness_policy_ms: i64,
    context: &EventContext,
) -> StorageResult<Vec<ProofEvidenceIndexEntry>>
where
    S: StorageAdapter,
{
    require_schema(manifest, PROOF_MANIFEST_SCHEMA_VERSION)?;
    let source_revision = required_string(manifest, &["source_revision"])?;
    validate_source_revision(&source_revision, expected_source_revision)?;
    let generated_timestamp_ms = required_rfc3339_timestamp_ms(manifest, &["generated_utc"])?;
    let freshness_deadline_ms = freshness_deadline(generated_timestamp_ms, freshness_policy_ms)?;
    let status = normalize_gate_status(&required_string(manifest, &["status"])?);
    let bundle_id = required_string(manifest, &["bundle_id"])?;
    let gate_name = required_string(manifest, &["gate_name"])?;
    let bead_ids = required_string_array(manifest, &["bead_ids"])?;
    if bead_ids.is_empty() {
        return Err(integrity(
            "proof manifest must include at least one bead_id",
        ));
    }
    let artifacts = required_array(manifest, &["generated_artifacts"])?;
    if artifacts.is_empty() {
        return Err(integrity(
            "proof manifest must include at least one generated artifact",
        ));
    }

    let mut seeds = Vec::new();
    for artifact in artifacts {
        let artifact_path = required_string(artifact, &["path"])?;
        let artifact_role = required_string(artifact, &["role"])?;
        let artifact_sha256 = match optional_string(artifact, &["sha256"]) {
            Some(sha256) => sha256,
            None if artifact_role == "redaction_policy" => continue,
            None => return Err(integrity("`sha256` must be a string")),
        };
        let artifact_schema = optional_string(artifact, &["schema_version"]);
        let receipt_kind = receipt_kind_for_manifest_role(&artifact_role);
        let artifact_id = format!("{bundle_id}:{receipt_kind}:{artifact_sha256}");
        let metadata_json = metadata_json(json!({
            "bundle_id": bundle_id,
            "gate_name": gate_name,
            "manifest_schema_version": PROOF_MANIFEST_SCHEMA_VERSION,
            "artifact_schema_version": artifact_schema,
            "import_source": "proof_manifest"
        }))?;

        for bead_id in &bead_ids {
            let natural_key = natural_key(&[
                "proof_manifest",
                bead_id,
                &source_revision,
                &artifact_path,
                &artifact_role,
                &artifact_sha256,
            ]);
            seeds.push(EvidenceSeed {
                natural_key,
                bead_id: bead_id.clone(),
                source_revision: source_revision.clone(),
                artifact_id: artifact_id.clone(),
                artifact_path: artifact_path.clone(),
                artifact_role: artifact_role.clone(),
                artifact_sha256: artifact_sha256.clone(),
                receipt_kind: receipt_kind.clone(),
                gate_status: status.clone(),
                generated_timestamp_ms,
                freshness_deadline_ms,
                metadata_json: metadata_json.clone(),
            });
        }
    }

    persist_evidence_seeds(storage, seeds, context)
}

/// Import a focused proof-cost manifest into the typed index.
pub fn import_proof_cost_manifest_json<S>(
    storage: &mut S,
    manifest_json: &str,
    source_revision: &str,
    expected_source_revision: &str,
    generated_timestamp_ms: i64,
    freshness_policy_ms: i64,
    context: &EventContext,
) -> StorageResult<Vec<ProofEvidenceIndexEntry>>
where
    S: StorageAdapter,
{
    let manifest = parse_json_document(manifest_json, "proof cost manifest")?;
    require_schema(&manifest, PROOF_COST_MANIFEST_SCHEMA_VERSION)?;
    validate_source_revision(source_revision, expected_source_revision)?;
    let bead_id = required_string(&manifest, &["bead_id"])?;
    let manifest_id = required_string(&manifest, &["manifest_id"])?;
    let suite = required_string(&manifest, &["focused_suite"])?;
    let command_hash = required_string(&manifest, &["command_hash"])?;
    let gate_status = if required_array(&manifest, &["unexpected_targets"])?.is_empty() {
        "pass".to_string()
    } else {
        "fail".to_string()
    };
    let artifact_sha256 = document_sha256(&manifest)?;
    let artifact_path =
        format!("artifacts/focused_proof_runner/{manifest_id}/proof_cost_manifest.json");
    let generated_timestamp_ms = require_non_negative_timestamp(generated_timestamp_ms)?;
    let freshness_deadline_ms = freshness_deadline(generated_timestamp_ms, freshness_policy_ms)?;
    let metadata_json = metadata_json(json!({
        "manifest_id": manifest_id,
        "focused_suite": suite,
        "command_hash": command_hash,
        "import_source": "proof_cost_manifest"
    }))?;

    persist_evidence_seeds(
        storage,
        vec![EvidenceSeed {
            natural_key: natural_key(&[
                "proof_cost_manifest",
                &bead_id,
                source_revision,
                &artifact_path,
                &artifact_sha256,
            ]),
            bead_id,
            source_revision: source_revision.to_string(),
            artifact_id: format!("proof-cost:{artifact_sha256}"),
            artifact_path,
            artifact_role: "proof_cost_manifest".to_string(),
            artifact_sha256,
            receipt_kind: "proof_cost_manifest".to_string(),
            gate_status,
            generated_timestamp_ms,
            freshness_deadline_ms,
            metadata_json,
        }],
        context,
    )
}

/// Import a validation plan emitted by `scripts/swarm_validation_planner.sh`.
pub fn import_validation_plan_json<S>(
    storage: &mut S,
    plan_json: &str,
    expected_source_revision: &str,
    generated_timestamp_ms: i64,
    freshness_policy_ms: i64,
    context: &EventContext,
) -> StorageResult<Vec<ProofEvidenceIndexEntry>>
where
    S: StorageAdapter,
{
    let plan = parse_json_document(plan_json, "swarm validation plan")?;
    require_schema(&plan, SWARM_VALIDATION_PLAN_SCHEMA_VERSION)?;
    let bead_id = required_string(&plan, &["bead_id"])?;
    let source_revision = required_string(&plan, &["source_revision"])?;
    validate_source_revision(&source_revision, expected_source_revision)?;
    let decision = required_string(&plan, &["decision"])?;
    let gate_status = normalize_planner_decision(&decision);
    let generated_timestamp_ms = require_non_negative_timestamp(generated_timestamp_ms)?;
    let freshness_deadline_ms = freshness_deadline(generated_timestamp_ms, freshness_policy_ms)?;
    let plan_sha256 = document_sha256(&plan)?;
    let artifacts = required_array(&plan, &["expected_artifacts"])?;
    if artifacts.is_empty() {
        return Err(integrity(
            "swarm validation plan must include expected_artifacts",
        ));
    }

    let mut seeds = Vec::new();
    for artifact in artifacts {
        let artifact_path = required_string(artifact, &["path"])?;
        let artifact_role = required_string(artifact, &["role"])?;
        let receipt_kind = if artifact_role == "command_transcript" {
            "validation_command"
        } else {
            "validation_plan"
        };
        let artifact_sha256 = hash_with_salt(&plan_sha256, &[&artifact_path, &artifact_role]);
        let metadata_json = metadata_json(json!({
            "decision": decision,
            "plan_schema_version": SWARM_VALIDATION_PLAN_SCHEMA_VERSION,
            "commands": plan.get("commands").cloned().unwrap_or(Value::Array(Vec::new())),
            "reason_codes": plan.get("reason_codes").cloned().unwrap_or(Value::Array(Vec::new())),
            "import_source": "validation_plan"
        }))?;
        seeds.push(EvidenceSeed {
            natural_key: natural_key(&[
                "validation_plan",
                &bead_id,
                &source_revision,
                &artifact_path,
                &artifact_role,
                &artifact_sha256,
            ]),
            bead_id: bead_id.clone(),
            source_revision: source_revision.clone(),
            artifact_id: format!("validation-plan:{artifact_sha256}"),
            artifact_path,
            artifact_role,
            artifact_sha256,
            receipt_kind: receipt_kind.to_string(),
            gate_status: gate_status.clone(),
            generated_timestamp_ms,
            freshness_deadline_ms,
            metadata_json,
        });
    }

    persist_evidence_seeds(storage, seeds, context)
}

/// Import a focused proof runner or proof-cost gate report.
pub fn import_gate_report_json<S>(
    storage: &mut S,
    report_json: &str,
    request: GateReportImport<'_>,
    context: &EventContext,
) -> StorageResult<Vec<ProofEvidenceIndexEntry>>
where
    S: StorageAdapter,
{
    let report = parse_json_document(report_json, "gate report")?;
    let schema_version = required_string(&report, &["schema_version"])?;
    if schema_version != FOCUSED_PROOF_COST_GATE_REPORT_SCHEMA_VERSION
        && schema_version != FOCUSED_PROOF_RUNNER_REPORT_SCHEMA_VERSION
    {
        return Err(integrity(format!(
            "unsupported gate report schema_version `{schema_version}`"
        )));
    }
    validate_source_revision(request.source_revision, request.expected_source_revision)?;
    require_non_empty("bead_id", request.bead_id)?;
    let status = normalize_gate_status(&required_string(&report, &["status"])?);
    let generated_timestamp_ms = require_non_negative_timestamp(request.generated_timestamp_ms)?;
    let freshness_deadline_ms =
        freshness_deadline(generated_timestamp_ms, request.freshness_policy_ms)?;
    let artifact_sha256 = document_sha256(&report)?;
    let metadata_json = metadata_json(json!({
        "report_schema_version": schema_version,
        "focused_suite": optional_string(&report, &["focused_suite"]),
        "diagnostics_id": optional_string(&report, &["diagnostics_id"]),
        "import_source": "gate_report"
    }))?;

    persist_evidence_seeds(
        storage,
        vec![EvidenceSeed {
            natural_key: natural_key(&[
                "gate_report",
                request.bead_id,
                request.source_revision,
                request.artifact_path,
                &artifact_sha256,
            ]),
            bead_id: request.bead_id.to_string(),
            source_revision: request.source_revision.to_string(),
            artifact_id: format!("gate-report:{artifact_sha256}"),
            artifact_path: request.artifact_path.to_string(),
            artifact_role: "gate_report".to_string(),
            artifact_sha256,
            receipt_kind: "gate_report".to_string(),
            gate_status: status,
            generated_timestamp_ms,
            freshness_deadline_ms,
            metadata_json,
        }],
        context,
    )
}

/// Query all indexed proof evidence for one bead.
pub fn query_proof_by_bead<S>(
    storage: &mut S,
    bead_id: &str,
    context: &EventContext,
) -> StorageResult<Vec<ProofEvidenceIndexEntry>>
where
    S: StorageAdapter,
{
    require_non_empty("bead_id", bead_id)?;
    query_entries(
        storage,
        BTreeMap::from([("bead_id".to_string(), bead_id.to_string())]),
        context,
    )
}

/// Query all indexed proof evidence for one source revision.
pub fn query_proof_by_source_revision<S>(
    storage: &mut S,
    source_revision: &str,
    context: &EventContext,
) -> StorageResult<Vec<ProofEvidenceIndexEntry>>
where
    S: StorageAdapter,
{
    require_non_empty("source_revision", source_revision)?;
    query_entries(
        storage,
        BTreeMap::from([("source_revision".to_string(), source_revision.to_string())]),
        context,
    )
}

/// Query recent failed gate/artifact evidence in stable newest-first order.
pub fn query_recent_failed_gates<S>(
    storage: &mut S,
    limit: usize,
    context: &EventContext,
) -> StorageResult<Vec<ProofEvidenceIndexEntry>>
where
    S: StorageAdapter,
{
    if limit == 0 {
        return Err(StorageError::InvalidQuery {
            detail: "limit cannot be zero".to_string(),
        });
    }
    let mut rows = query_entries(
        storage,
        BTreeMap::from([("gate_status".to_string(), "fail".to_string())]),
        context,
    )?;
    rows.sort_by(|a, b| {
        b.generated_timestamp_ms
            .cmp(&a.generated_timestamp_ms)
            .then(a.evidence_id.cmp(&b.evidence_id))
    });
    rows.truncate(limit);
    Ok(rows)
}

/// Query evidence that has exceeded its freshness deadline.
pub fn query_artifacts_older_than_freshness_policy<S>(
    storage: &mut S,
    now_ms: i64,
    context: &EventContext,
) -> StorageResult<Vec<ProofEvidenceIndexEntry>>
where
    S: StorageAdapter,
{
    let now_ms = require_non_negative_timestamp(now_ms)?;
    let mut rows = query_entries(storage, BTreeMap::new(), context)?;
    rows.retain(|row| row.freshness_deadline_ms < now_ms);
    rows.sort_by(|a, b| {
        a.freshness_deadline_ms
            .cmp(&b.freshness_deadline_ms)
            .then(a.evidence_id.cmp(&b.evidence_id))
    });
    Ok(rows)
}

/// Wrap already queried rows in a stable JSON-ready report envelope.
pub fn proof_evidence_query_report(
    query_kind: impl Into<String>,
    mut rows: Vec<ProofEvidenceIndexEntry>,
) -> ProofEvidenceQueryReport {
    rows.sort_by(dashboard_entry_order);
    ProofEvidenceQueryReport {
        schema_version: PROOF_EVIDENCE_QUERY_SCHEMA_VERSION.to_string(),
        query_kind: query_kind.into(),
        rows,
    }
}

/// Serialize a stable dashboard report.
pub fn proof_evidence_query_report_json(
    query_kind: impl Into<String>,
    rows: Vec<ProofEvidenceIndexEntry>,
) -> StorageResult<String> {
    serde_json::to_string(&proof_evidence_query_report(query_kind, rows)).map_err(|err| {
        integrity(format!(
            "failed to serialize proof evidence query report: {err}"
        ))
    })
}

fn persist_evidence_seeds<S>(
    storage: &mut S,
    seeds: Vec<EvidenceSeed>,
    context: &EventContext,
) -> StorageResult<Vec<ProofEvidenceIndexEntry>>
where
    S: StorageAdapter,
{
    let mut deduped = BTreeMap::new();
    for seed in seeds {
        deduped.entry(seed.natural_key.clone()).or_insert(seed);
    }

    let mut entries = Vec::with_capacity(deduped.len());
    for (natural_key, seed) in deduped {
        seed.clone().into_entry(0).validate_typed_record()?;
        let evidence_id =
            allocate_typed_record_id::<ProofEvidenceIndexEntry, S>(storage, &natural_key, context)?;
        entries.push(seed.into_entry(evidence_id));
    }
    entries.sort_by(dashboard_entry_order);
    storage.put_typed_batch(&entries, context)?;
    Ok(entries)
}

fn query_entries<S>(
    storage: &mut S,
    metadata_filters: BTreeMap<String, String>,
    context: &EventContext,
) -> StorageResult<Vec<ProofEvidenceIndexEntry>>
where
    S: StorageAdapter,
{
    let query = StoreQuery {
        key_prefix: Some(TYPED_EVIDENCE_KEY_PREFIX.to_string()),
        metadata_filters,
        limit: None,
    };
    let mut rows = storage.query_typed::<ProofEvidenceIndexEntry>(&query, context)?;
    rows.sort_by(dashboard_entry_order);
    Ok(rows)
}

fn dashboard_entry_order(
    a: &ProofEvidenceIndexEntry,
    b: &ProofEvidenceIndexEntry,
) -> std::cmp::Ordering {
    a.bead_id
        .cmp(&b.bead_id)
        .then(a.source_revision.cmp(&b.source_revision))
        .then(a.artifact_path.cmp(&b.artifact_path))
        .then(a.receipt_kind.cmp(&b.receipt_kind))
        .then(a.evidence_id.cmp(&b.evidence_id))
}

fn parse_json_document(input: &str, document_kind: &str) -> StorageResult<Value> {
    serde_json::from_str(input).map_err(|err| {
        integrity(format!(
            "{document_kind} is not valid JSON and cannot be indexed: {err}"
        ))
    })
}

fn require_schema(document: &Value, expected: &str) -> StorageResult<()> {
    let actual = required_string(document, &["schema_version"])?;
    if actual == expected {
        return Ok(());
    }
    Err(integrity(format!(
        "unsupported schema_version `{actual}`; expected `{expected}`"
    )))
}

fn required_string(document: &Value, path: &[&str]) -> StorageResult<String> {
    let value = value_at(document, path)?;
    let Some(string) = value.as_str() else {
        return Err(integrity(format!("`{}` must be a string", path.join("."))));
    };
    require_non_empty(&path.join("."), string)?;
    Ok(string.to_string())
}

fn optional_string(document: &Value, path: &[&str]) -> Option<String> {
    value_at(document, path)
        .ok()
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string)
}

fn required_string_array(document: &Value, path: &[&str]) -> StorageResult<Vec<String>> {
    required_array(document, path)?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let Some(string) = value.as_str() else {
                return Err(integrity(format!(
                    "`{}[{index}]` must be a string",
                    path.join(".")
                )));
            };
            require_non_empty(&format!("{}[{index}]", path.join(".")), string)?;
            Ok(string.to_string())
        })
        .collect()
}

fn required_array<'a>(document: &'a Value, path: &[&str]) -> StorageResult<&'a Vec<Value>> {
    let value = value_at(document, path)?;
    value
        .as_array()
        .ok_or_else(|| integrity(format!("`{}` must be an array", path.join("."))))
}

fn value_at<'a>(document: &'a Value, path: &[&str]) -> StorageResult<&'a Value> {
    let mut value = document;
    for segment in path {
        value = value
            .get(segment)
            .ok_or_else(|| integrity(format!("missing required field `{}`", path.join("."))))?;
    }
    Ok(value)
}

fn required_rfc3339_timestamp_ms(document: &Value, path: &[&str]) -> StorageResult<i64> {
    let raw = required_string(document, path)?;
    DateTime::parse_from_rfc3339(&raw)
        .map(|timestamp| timestamp.timestamp_millis())
        .map_err(|err| {
            integrity(format!(
                "`{}` must be an RFC3339 timestamp: {err}",
                path.join(".")
            ))
        })
}

fn require_non_empty(field: &str, value: &str) -> StorageResult<()> {
    if value.trim().is_empty() {
        return Err(integrity(format!("`{field}` must not be empty")));
    }
    if value.contains('\0') {
        return Err(integrity(format!("`{field}` must not contain NUL bytes")));
    }
    Ok(())
}

fn require_non_negative_timestamp(value: i64) -> StorageResult<i64> {
    if value < 0 {
        return Err(integrity(format!(
            "timestamp must be non-negative, got {value}"
        )));
    }
    Ok(value)
}

fn freshness_deadline(generated_timestamp_ms: i64, freshness_policy_ms: i64) -> StorageResult<i64> {
    require_non_negative_timestamp(generated_timestamp_ms)?;
    if freshness_policy_ms < 0 {
        return Err(integrity(format!(
            "freshness policy must be non-negative, got {freshness_policy_ms}"
        )));
    }
    generated_timestamp_ms
        .checked_add(freshness_policy_ms)
        .ok_or_else(|| integrity("freshness deadline overflow"))
}

fn validate_source_revision(
    source_revision: &str,
    expected_source_revision: &str,
) -> StorageResult<()> {
    require_non_empty("source_revision", source_revision)?;
    require_non_empty("expected_source_revision", expected_source_revision)?;
    if source_revision == "unknown" {
        return Err(integrity(
            "source_revision must be explicit; refusing to index `unknown`",
        ));
    }
    if source_revision != expected_source_revision {
        return Err(integrity(format!(
            "stale source_revision `{source_revision}`; expected `{expected_source_revision}`"
        )));
    }
    Ok(())
}

fn normalize_gate_status(raw: &str) -> String {
    match raw {
        "pass" | "passed" | "ok" | "success" | "admit" | "admit_narrow" => "pass",
        "fail" | "failed" | "error" => "fail",
        "blocked" | "fail_closed" | "defer" | "deferred" => "blocked",
        "skipped" => "skipped",
        "stale" => "stale",
        _ => "unknown",
    }
    .to_string()
}

fn normalize_planner_decision(raw: &str) -> String {
    match raw {
        "admit" | "admit_narrow" => "pass",
        "fail_closed" | "defer" | "deferred" => "blocked",
        _ => "unknown",
    }
    .to_string()
}

fn receipt_kind_for_manifest_role(role: &str) -> String {
    match role {
        "command_transcript" => "command_receipt",
        "proof_cost_manifest" => "proof_cost_manifest",
        "source_machine_report" | "structured_events" | "redaction_policy" => "proof_artifact",
        _ => "proof_artifact",
    }
    .to_string()
}

fn metadata_json(value: Value) -> StorageResult<String> {
    if !value.is_object() {
        return Err(integrity("metadata_json source must be an object"));
    }
    serde_json::to_string(&value)
        .map_err(|err| integrity(format!("failed to serialize metadata_json: {err}")))
}

fn document_sha256(document: &Value) -> StorageResult<String> {
    let bytes = serde_json::to_vec(document)
        .map_err(|err| integrity(format!("failed to serialize document for hashing: {err}")))?;
    Ok(sha256_hex(&bytes))
}

fn hash_with_salt(base_hash: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(base_hash.as_bytes());
    for part in parts {
        hasher.update([0]);
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn natural_key(parts: &[&str]) -> String {
    parts.join("\u{1f}")
}

fn integrity(detail: impl Into<String>) -> StorageError {
    StorageError::IntegrityViolation {
        store: StoreKind::EvidenceIndex,
        detail: detail.into(),
    }
}
