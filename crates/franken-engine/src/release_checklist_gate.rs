//! Machine-readable release checklist gate for Section 10.8 (`bd-ag4`).
//!
//! This module defines a deterministic checklist artifact format and a fail-closed
//! release gate evaluator:
//! - required security/performance/reproducibility/operational checklist items
//! - explicit waiver metadata requirements
//! - structured events with stable keys
//! - benchmark-ledger storage tagged by release for later verification

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::storage_adapter::{
    BatchPutEntry, EventContext, StorageAdapter, StorageError, StoreKind, StoreQuery,
};

pub const RELEASE_CHECKLIST_COMPONENT: &str = "release_checklist_gate";
pub const RELEASE_CHECKLIST_SCHEMA_VERSION: &str = "franken-engine.release-checklist.v1";
pub const RELEASE_CHECKLIST_STORAGE_INTEGRATION_POINT: &str = "frankensqlite::benchmark::ledger";

const RELEASE_CHECKLIST_STORE_KEY_PREFIX: &str = "release_checklist";

const ERROR_INVALID_REQUEST: &str = "FE-RCHK-1001";
const ERROR_INVALID_TIMESTAMP: &str = "FE-RCHK-1002";
const ERROR_INVALID_ITEM: &str = "FE-RCHK-1003";
const ERROR_SERIALIZATION: &str = "FE-RCHK-1004";
pub const ERROR_RELEASE_BLOCKED: &str = "FE-RCHK-1005";
const ERROR_STORAGE: &str = "FE-RCHK-1006";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistCategory {
    Security,
    Performance,
    Reproducibility,
    Operational,
}

impl ChecklistCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Performance => "performance",
            Self::Reproducibility => "reproducibility",
            Self::Operational => "operational",
        }
    }
}

impl fmt::Display for ChecklistCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistItemStatus {
    Pass,
    Fail,
    NotRun,
    Waived,
}

impl ChecklistItemStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::NotRun => "not_run",
            Self::Waived => "waived",
        }
    }

    fn blocks_release(self) -> bool {
        matches!(self, Self::Fail | Self::NotRun)
    }
}

impl fmt::Display for ChecklistItemStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub artifact_id: String,
    pub path: String,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecklistWaiver {
    pub reason: String,
    pub approver: String,
    pub exception_artifact_link: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecklistItem {
    pub item_id: String,
    pub category: ChecklistCategory,
    pub required: bool,
    pub status: ChecklistItemStatus,
    pub artifact_refs: Vec<ArtifactRef>,
    pub waiver: Option<ChecklistWaiver>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseChecklist {
    pub schema_version: String,
    pub release_tag: String,
    pub generated_at_utc: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub items: Vec<ChecklistItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseChecklistGateEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub checklist_id: Option<String>,
    pub item_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseChecklistGateDecision {
    pub checklist_id: Option<String>,
    pub release_tag: String,
    pub outcome: String,
    pub blocked: bool,
    pub blockers: Vec<String>,
    pub error_code: Option<String>,
    pub rollback_required: bool,
    pub storage_backend: String,
    pub storage_integration_point: String,
    pub store_key: Option<String>,
    pub events: Vec<ReleaseChecklistGateEvent>,
}

impl ReleaseChecklistGateDecision {
    pub fn allows_release(&self) -> bool {
        self.outcome == "allow"
    }
}

#[derive(Debug, Error)]
pub enum ReleaseChecklistError {
    #[error("invalid request field `{field}`: {detail}")]
    InvalidRequest { field: String, detail: String },
    #[error("invalid timestamp `{value}`: expected RFC3339 UTC")]
    InvalidTimestamp { value: String },
    #[error("invalid checklist item `{item_id}`: {detail}")]
    InvalidItem { item_id: String, detail: String },
    #[error("serialization failure: {detail}")]
    SerializationFailure { detail: String },
    #[error("storage failure: {0}")]
    StorageFailure(#[from] StorageError),
}

impl ReleaseChecklistError {
    pub fn stable_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest { .. } => ERROR_INVALID_REQUEST,
            Self::InvalidTimestamp { .. } => ERROR_INVALID_TIMESTAMP,
            Self::InvalidItem { .. } => ERROR_INVALID_ITEM,
            Self::SerializationFailure { .. } => ERROR_SERIALIZATION,
            Self::StorageFailure(_) => ERROR_STORAGE,
        }
    }

    pub fn requires_rollback(&self) -> bool {
        matches!(self, Self::StorageFailure(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequiredChecklistItem {
    pub item_id: &'static str,
    pub category: ChecklistCategory,
}

const REQUIRED_CHECKLIST_ITEMS: &[RequiredChecklistItem] = &[
    RequiredChecklistItem {
        item_id: "security.conformance_suite",
        category: ChecklistCategory::Security,
    },
    RequiredChecklistItem {
        item_id: "security.test262_es2020_gate",
        category: ChecklistCategory::Security,
    },
    RequiredChecklistItem {
        item_id: "security.adversarial_corpus",
        category: ChecklistCategory::Security,
    },
    RequiredChecklistItem {
        item_id: "security.containment_latency",
        category: ChecklistCategory::Security,
    },
    RequiredChecklistItem {
        item_id: "security.ifc_coverage",
        category: ChecklistCategory::Security,
    },
    RequiredChecklistItem {
        item_id: "security.plas_witness_coverage",
        category: ChecklistCategory::Security,
    },
    RequiredChecklistItem {
        item_id: "performance.benchmark_suite",
        category: ChecklistCategory::Performance,
    },
    RequiredChecklistItem {
        item_id: "performance.speedup_gate_3x",
        category: ChecklistCategory::Performance,
    },
    RequiredChecklistItem {
        item_id: "performance.flamegraph_comparisons",
        category: ChecklistCategory::Performance,
    },
    RequiredChecklistItem {
        item_id: "performance.gc_pause_budget",
        category: ChecklistCategory::Performance,
    },
    RequiredChecklistItem {
        item_id: "reproducibility.env_json",
        category: ChecklistCategory::Reproducibility,
    },
    RequiredChecklistItem {
        item_id: "reproducibility.manifest_json",
        category: ChecklistCategory::Reproducibility,
    },
    RequiredChecklistItem {
        item_id: "reproducibility.repro_lock",
        category: ChecklistCategory::Reproducibility,
    },
    RequiredChecklistItem {
        item_id: "operational.safe_mode_test",
        category: ChecklistCategory::Operational,
    },
    RequiredChecklistItem {
        item_id: "operational.diagnostics_cli_test",
        category: ChecklistCategory::Operational,
    },
    RequiredChecklistItem {
        item_id: "operational.evidence_export_test",
        category: ChecklistCategory::Operational,
    },
];

pub fn required_checklist_items() -> &'static [RequiredChecklistItem] {
    REQUIRED_CHECKLIST_ITEMS
}

struct EvaluationResult {
    normalized: ReleaseChecklist,
    checklist_id: String,
    blocked: bool,
    blockers: Vec<String>,
}

/// Parse and validate a checklist artifact from JSON.
pub fn parse_release_checklist_json(
    payload: &str,
) -> Result<ReleaseChecklist, ReleaseChecklistError> {
    serde_json::from_str::<ReleaseChecklist>(payload).map_err(|error| {
        ReleaseChecklistError::SerializationFailure {
            detail: error.to_string(),
        }
    })
}

/// Validate checklist schema and required-item constraints.
pub fn validate_release_checklist(
    checklist: &ReleaseChecklist,
) -> Result<(), ReleaseChecklistError> {
    evaluate_checklist(checklist).map(|_| ())
}

/// Evaluate checklist and persist it to benchmark-ledger storage.
pub fn run_release_checklist_gate<A: StorageAdapter>(
    adapter: &mut A,
    checklist: &ReleaseChecklist,
) -> ReleaseChecklistGateDecision {
    let release_tag = checklist.release_tag.trim().to_string();
    let mut events = vec![make_event(
        checklist,
        "release_checklist_gate_started",
        "pass",
        None,
        None,
        None,
    )];

    match run_gate_impl(adapter, checklist, &mut events) {
        Ok((evaluation, store_key)) => {
            let (outcome, error_code) = if evaluation.blocked {
                ("deny".to_string(), Some(ERROR_RELEASE_BLOCKED.to_string()))
            } else {
                ("allow".to_string(), None)
            };
            events.push(make_event(
                &evaluation.normalized,
                "release_checklist_gate_completed",
                &outcome,
                error_code.clone(),
                Some(evaluation.checklist_id.clone()),
                None,
            ));
            ReleaseChecklistGateDecision {
                checklist_id: Some(evaluation.checklist_id),
                release_tag: evaluation.normalized.release_tag,
                outcome,
                blocked: evaluation.blocked,
                blockers: evaluation.blockers,
                error_code,
                rollback_required: false,
                storage_backend: adapter.backend_name().to_string(),
                storage_integration_point: RELEASE_CHECKLIST_STORAGE_INTEGRATION_POINT.to_string(),
                store_key: Some(store_key),
                events,
            }
        }
        Err(error) => {
            let error_code = error.stable_code().to_string();
            events.push(make_event(
                checklist,
                "release_checklist_gate_completed",
                "fail",
                Some(error_code.clone()),
                None,
                None,
            ));
            ReleaseChecklistGateDecision {
                checklist_id: None,
                release_tag,
                outcome: "fail".to_string(),
                blocked: true,
                blockers: vec![error.to_string()],
                error_code: Some(error_code),
                rollback_required: error.requires_rollback(),
                storage_backend: adapter.backend_name().to_string(),
                storage_integration_point: RELEASE_CHECKLIST_STORAGE_INTEGRATION_POINT.to_string(),
                store_key: None,
                events,
            }
        }
    }
}

/// Query stored release checklist artifacts by release tag.
pub fn query_release_checklists_by_tag<A: StorageAdapter>(
    adapter: &mut A,
    release_tag: &str,
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
) -> Result<Vec<ReleaseChecklist>, ReleaseChecklistError> {
    let release_tag = release_tag.trim();
    if release_tag.is_empty() {
        return Err(ReleaseChecklistError::InvalidRequest {
            field: "release_tag".to_string(),
            detail: "release_tag must not be empty".to_string(),
        });
    }

    let context = EventContext::new(trace_id, decision_id, policy_id).map_err(|_| {
        ReleaseChecklistError::InvalidRequest {
            field: "event_context".to_string(),
            detail: "trace_id/decision_id/policy_id must be non-empty".to_string(),
        }
    })?;

    let mut metadata_filters = BTreeMap::new();
    metadata_filters.insert("release_tag".to_string(), release_tag.to_string());
    let query = StoreQuery {
        key_prefix: Some(format!(
            "{RELEASE_CHECKLIST_STORE_KEY_PREFIX}/{release_tag}/"
        )),
        metadata_filters,
        limit: None,
    };

    let records = adapter.query(StoreKind::BenchmarkLedger, &query, &context)?;
    let mut checklists = Vec::new();
    for record in records {
        let checklist: ReleaseChecklist =
            serde_json::from_slice(&record.value).map_err(|error| {
                ReleaseChecklistError::SerializationFailure {
                    detail: error.to_string(),
                }
            })?;
        checklists.push(checklist);
    }
    checklists.sort_by(|left, right| left.generated_at_utc.cmp(&right.generated_at_utc));
    Ok(checklists)
}

fn run_gate_impl<A: StorageAdapter>(
    adapter: &mut A,
    checklist: &ReleaseChecklist,
    events: &mut Vec<ReleaseChecklistGateEvent>,
) -> Result<(EvaluationResult, String), ReleaseChecklistError> {
    let evaluation = evaluate_checklist(checklist)?;
    events.push(make_event(
        &evaluation.normalized,
        "release_checklist_evaluated",
        if evaluation.blocked { "deny" } else { "allow" },
        if evaluation.blocked {
            Some(ERROR_RELEASE_BLOCKED.to_string())
        } else {
            None
        },
        Some(evaluation.checklist_id.clone()),
        None,
    ));

    let context = EventContext::new(
        evaluation.normalized.trace_id.clone(),
        evaluation.normalized.decision_id.clone(),
        evaluation.normalized.policy_id.clone(),
    )?;

    let serialized = serde_json::to_vec(&evaluation.normalized).map_err(|error| {
        ReleaseChecklistError::SerializationFailure {
            detail: error.to_string(),
        }
    })?;

    let store_key = format!(
        "{}/{}/{}",
        RELEASE_CHECKLIST_STORE_KEY_PREFIX,
        evaluation.normalized.release_tag,
        evaluation.checklist_id
    );
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "component".to_string(),
        RELEASE_CHECKLIST_COMPONENT.to_string(),
    );
    metadata.insert(
        "release_tag".to_string(),
        evaluation.normalized.release_tag.clone(),
    );
    metadata.insert("checklist_id".to_string(), evaluation.checklist_id.clone());
    metadata.insert(
        "schema_version".to_string(),
        evaluation.normalized.schema_version.clone(),
    );
    metadata.insert(
        "gate_outcome".to_string(),
        if evaluation.blocked {
            "deny".to_string()
        } else {
            "allow".to_string()
        },
    );

    let entry = BatchPutEntry {
        key: store_key.clone(),
        value: serialized,
        metadata,
    };
    adapter.put_batch(StoreKind::BenchmarkLedger, vec![entry], &context)?;
    events.push(make_event(
        &evaluation.normalized,
        "release_checklist_stored",
        "pass",
        None,
        Some(evaluation.checklist_id.clone()),
        None,
    ));
    Ok((evaluation, store_key))
}

fn evaluate_checklist(
    checklist: &ReleaseChecklist,
) -> Result<EvaluationResult, ReleaseChecklistError> {
    let mut normalized = checklist.clone();
    normalize_checklist(&mut normalized)?;
    let checklist_id = build_checklist_id(&normalized);

    let mut blockers = Vec::new();
    let mut by_id = BTreeMap::new();
    let mut seen_ids = BTreeSet::new();
    for item in &normalized.items {
        if !seen_ids.insert(item.item_id.clone()) {
            return Err(ReleaseChecklistError::InvalidItem {
                item_id: item.item_id.clone(),
                detail: "duplicate item_id".to_string(),
            });
        }
        by_id.insert(item.item_id.clone(), item);
    }

    for required in REQUIRED_CHECKLIST_ITEMS {
        let Some(item) = by_id.get(required.item_id) else {
            blockers.push(format!(
                "missing required checklist item `{}`",
                required.item_id
            ));
            continue;
        };

        if item.category != required.category {
            blockers.push(format!(
                "required item `{}` has category `{}` but expected `{}`",
                required.item_id, item.category, required.category
            ));
        }

        if item.status.blocks_release() {
            blockers.push(format!(
                "required item `{}` is `{}`",
                required.item_id, item.status
            ));
        }

        if matches!(
            item.status,
            ChecklistItemStatus::Pass | ChecklistItemStatus::Waived
        ) && item.artifact_refs.is_empty()
        {
            blockers.push(format!(
                "required item `{}` is `{}` but has no artifact_refs",
                required.item_id, item.status
            ));
        }
    }

    Ok(EvaluationResult {
        normalized,
        checklist_id,
        blocked: !blockers.is_empty(),
        blockers,
    })
}

fn normalize_checklist(checklist: &mut ReleaseChecklist) -> Result<(), ReleaseChecklistError> {
    checklist.schema_version = checklist.schema_version.trim().to_string();
    checklist.release_tag = checklist.release_tag.trim().to_string();
    checklist.generated_at_utc = normalize_utc_timestamp(&checklist.generated_at_utc)?;
    checklist.trace_id = checklist.trace_id.trim().to_string();
    checklist.decision_id = checklist.decision_id.trim().to_string();
    checklist.policy_id = checklist.policy_id.trim().to_string();

    if checklist.schema_version != RELEASE_CHECKLIST_SCHEMA_VERSION {
        return Err(ReleaseChecklistError::InvalidRequest {
            field: "schema_version".to_string(),
            detail: format!(
                "expected `{RELEASE_CHECKLIST_SCHEMA_VERSION}`, got `{}`",
                checklist.schema_version
            ),
        });
    }
    if checklist.release_tag.is_empty() {
        return Err(ReleaseChecklistError::InvalidRequest {
            field: "release_tag".to_string(),
            detail: "release_tag must not be empty".to_string(),
        });
    }
    if checklist.trace_id.is_empty() {
        return Err(ReleaseChecklistError::InvalidRequest {
            field: "trace_id".to_string(),
            detail: "trace_id must not be empty".to_string(),
        });
    }
    if checklist.decision_id.is_empty() {
        return Err(ReleaseChecklistError::InvalidRequest {
            field: "decision_id".to_string(),
            detail: "decision_id must not be empty".to_string(),
        });
    }
    if checklist.policy_id.is_empty() {
        return Err(ReleaseChecklistError::InvalidRequest {
            field: "policy_id".to_string(),
            detail: "policy_id must not be empty".to_string(),
        });
    }
    if checklist.items.is_empty() {
        return Err(ReleaseChecklistError::InvalidRequest {
            field: "items".to_string(),
            detail: "at least one checklist item is required".to_string(),
        });
    }

    checklist
        .items
        .sort_by(|left, right| left.item_id.cmp(&right.item_id));
    for item in &mut checklist.items {
        item.item_id = item.item_id.trim().to_string();
        if item.item_id.is_empty() {
            return Err(ReleaseChecklistError::InvalidItem {
                item_id: "<empty>".to_string(),
                detail: "item_id must not be empty".to_string(),
            });
        }
        if item.required && !is_required_item_id(&item.item_id) {
            return Err(ReleaseChecklistError::InvalidItem {
                item_id: item.item_id.clone(),
                detail: "unknown required item_id".to_string(),
            });
        }
        if matches!(item.status, ChecklistItemStatus::Waived) {
            let Some(waiver) = item.waiver.as_mut() else {
                return Err(ReleaseChecklistError::InvalidItem {
                    item_id: item.item_id.clone(),
                    detail: "waived status requires waiver metadata".to_string(),
                });
            };
            waiver.reason = waiver.reason.trim().to_string();
            waiver.approver = waiver.approver.trim().to_string();
            waiver.exception_artifact_link = waiver.exception_artifact_link.trim().to_string();
            if waiver.reason.is_empty()
                || waiver.approver.is_empty()
                || waiver.exception_artifact_link.is_empty()
            {
                return Err(ReleaseChecklistError::InvalidItem {
                    item_id: item.item_id.clone(),
                    detail: "waiver reason/approver/exception_artifact_link must be non-empty"
                        .to_string(),
                });
            }
        } else if item.waiver.is_some() {
            return Err(ReleaseChecklistError::InvalidItem {
                item_id: item.item_id.clone(),
                detail: "waiver metadata is allowed only when status=waived".to_string(),
            });
        }

        item.artifact_refs.sort_by(|left, right| {
            left.artifact_id
                .cmp(&right.artifact_id)
                .then(left.path.cmp(&right.path))
        });
        for artifact in &mut item.artifact_refs {
            artifact.artifact_id = artifact.artifact_id.trim().to_string();
            artifact.path = artifact.path.trim().to_string();
            if artifact.artifact_id.is_empty() || artifact.path.is_empty() {
                return Err(ReleaseChecklistError::InvalidItem {
                    item_id: item.item_id.clone(),
                    detail: "artifact_id and path must be non-empty".to_string(),
                });
            }
            if let Some(sha256) = &mut artifact.sha256 {
                *sha256 = sha256.trim().to_string();
                if sha256.is_empty() {
                    artifact.sha256 = None;
                }
            }
        }
    }
    Ok(())
}

fn is_required_item_id(item_id: &str) -> bool {
    REQUIRED_CHECKLIST_ITEMS
        .iter()
        .any(|required| required.item_id == item_id)
}

fn normalize_utc_timestamp(value: &str) -> Result<String, ReleaseChecklistError> {
    let parsed = DateTime::parse_from_rfc3339(value).map_err(|_| {
        ReleaseChecklistError::InvalidTimestamp {
            value: value.to_string(),
        }
    })?;
    Ok(parsed
        .with_timezone(&Utc)
        .to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn build_checklist_id(checklist: &ReleaseChecklist) -> String {
    let mut hasher = Sha256::new();
    hash_update(&mut hasher, &checklist.schema_version);
    hash_update(&mut hasher, &checklist.release_tag);
    hash_update(&mut hasher, &checklist.generated_at_utc);
    hash_update(&mut hasher, &checklist.trace_id);
    hash_update(&mut hasher, &checklist.decision_id);
    hash_update(&mut hasher, &checklist.policy_id);
    for item in &checklist.items {
        hash_update(&mut hasher, &item.item_id);
        hash_update(&mut hasher, item.category.as_str());
        hash_update(&mut hasher, item.status.as_str());
        hash_update(&mut hasher, if item.required { "1" } else { "0" });
        for artifact in &item.artifact_refs {
            hash_update(&mut hasher, &artifact.artifact_id);
            hash_update(&mut hasher, &artifact.path);
            hash_update(&mut hasher, artifact.sha256.as_deref().unwrap_or(""));
        }
        if let Some(waiver) = &item.waiver {
            hash_update(&mut hasher, &waiver.reason);
            hash_update(&mut hasher, &waiver.approver);
            hash_update(&mut hasher, &waiver.exception_artifact_link);
        }
    }
    let digest = hex::encode(hasher.finalize());
    format!("rchk_{}", &digest[..20])
}

fn hash_update(hasher: &mut Sha256, value: &str) {
    hasher.update(value.as_bytes());
    hasher.update([0x1f]);
}

fn make_event(
    checklist: &ReleaseChecklist,
    event: &str,
    outcome: &str,
    error_code: Option<String>,
    checklist_id: Option<String>,
    item_id: Option<String>,
) -> ReleaseChecklistGateEvent {
    ReleaseChecklistGateEvent {
        trace_id: checklist.trace_id.clone(),
        decision_id: checklist.decision_id.clone(),
        policy_id: checklist.policy_id.clone(),
        component: RELEASE_CHECKLIST_COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code,
        checklist_id,
        item_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_artifact_ref(id: &str) -> ArtifactRef {
        ArtifactRef {
            artifact_id: id.to_string(),
            path: format!("artifacts/{id}.json"),
            sha256: Some("a".repeat(64)),
        }
    }

    fn make_passing_item(item_id: &str, category: ChecklistCategory) -> ChecklistItem {
        ChecklistItem {
            item_id: item_id.to_string(),
            category,
            required: true,
            status: ChecklistItemStatus::Pass,
            artifact_refs: vec![make_artifact_ref("art-1")],
            waiver: None,
        }
    }

    fn make_full_checklist() -> ReleaseChecklist {
        let items: Vec<ChecklistItem> = REQUIRED_CHECKLIST_ITEMS
            .iter()
            .map(|req| make_passing_item(req.item_id, req.category))
            .collect();

        ReleaseChecklist {
            schema_version: RELEASE_CHECKLIST_SCHEMA_VERSION.to_string(),
            release_tag: "v0.1.0".to_string(),
            generated_at_utc: "2025-01-15T12:00:00Z".to_string(),
            trace_id: "trace-001".to_string(),
            decision_id: "decision-001".to_string(),
            policy_id: "policy-001".to_string(),
            items,
        }
    }

    // ── ChecklistCategory ─────────────────────────────────────────────

    #[test]
    fn checklist_category_as_str() {
        assert_eq!(ChecklistCategory::Security.as_str(), "security");
        assert_eq!(ChecklistCategory::Performance.as_str(), "performance");
        assert_eq!(
            ChecklistCategory::Reproducibility.as_str(),
            "reproducibility"
        );
        assert_eq!(ChecklistCategory::Operational.as_str(), "operational");
    }

    #[test]
    fn checklist_category_display() {
        assert_eq!(ChecklistCategory::Security.to_string(), "security");
    }

    #[test]
    fn checklist_category_serde_round_trip() {
        for cat in [
            ChecklistCategory::Security,
            ChecklistCategory::Performance,
            ChecklistCategory::Reproducibility,
            ChecklistCategory::Operational,
        ] {
            let json = serde_json::to_string(&cat).unwrap();
            let back: ChecklistCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(back, cat);
        }
    }

    // ── ChecklistItemStatus ───────────────────────────────────────────

    #[test]
    fn item_status_as_str() {
        assert_eq!(ChecklistItemStatus::Pass.as_str(), "pass");
        assert_eq!(ChecklistItemStatus::Fail.as_str(), "fail");
        assert_eq!(ChecklistItemStatus::NotRun.as_str(), "not_run");
        assert_eq!(ChecklistItemStatus::Waived.as_str(), "waived");
    }

    #[test]
    fn item_status_blocks_release() {
        assert!(ChecklistItemStatus::Fail.blocks_release());
        assert!(ChecklistItemStatus::NotRun.blocks_release());
        assert!(!ChecklistItemStatus::Pass.blocks_release());
        assert!(!ChecklistItemStatus::Waived.blocks_release());
    }

    #[test]
    fn item_status_serde_round_trip() {
        for status in [
            ChecklistItemStatus::Pass,
            ChecklistItemStatus::Fail,
            ChecklistItemStatus::NotRun,
            ChecklistItemStatus::Waived,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: ChecklistItemStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    // ── ReleaseChecklistGateDecision ──────────────────────────────────

    #[test]
    fn decision_allows_release() {
        let d = ReleaseChecklistGateDecision {
            checklist_id: None,
            release_tag: "v1".to_string(),
            outcome: "allow".to_string(),
            blocked: false,
            blockers: vec![],
            error_code: None,
            rollback_required: false,
            storage_backend: "test".to_string(),
            storage_integration_point: "test".to_string(),
            store_key: None,
            events: vec![],
        };
        assert!(d.allows_release());
    }

    #[test]
    fn decision_blocks_release() {
        let d = ReleaseChecklistGateDecision {
            checklist_id: None,
            release_tag: "v1".to_string(),
            outcome: "deny".to_string(),
            blocked: true,
            blockers: vec!["blocker".to_string()],
            error_code: Some(ERROR_RELEASE_BLOCKED.to_string()),
            rollback_required: false,
            storage_backend: "test".to_string(),
            storage_integration_point: "test".to_string(),
            store_key: None,
            events: vec![],
        };
        assert!(!d.allows_release());
    }

    // ── ReleaseChecklistError ─────────────────────────────────────────

    #[test]
    fn error_stable_codes() {
        let err = ReleaseChecklistError::InvalidRequest {
            field: "f".to_string(),
            detail: "d".to_string(),
        };
        assert_eq!(err.stable_code(), ERROR_INVALID_REQUEST);

        let err = ReleaseChecklistError::InvalidTimestamp {
            value: "v".to_string(),
        };
        assert_eq!(err.stable_code(), ERROR_INVALID_TIMESTAMP);

        let err = ReleaseChecklistError::InvalidItem {
            item_id: "id".to_string(),
            detail: "d".to_string(),
        };
        assert_eq!(err.stable_code(), ERROR_INVALID_ITEM);

        let err = ReleaseChecklistError::SerializationFailure {
            detail: "d".to_string(),
        };
        assert_eq!(err.stable_code(), ERROR_SERIALIZATION);
    }

    #[test]
    fn error_requires_rollback() {
        let err = ReleaseChecklistError::InvalidRequest {
            field: "f".to_string(),
            detail: "d".to_string(),
        };
        assert!(!err.requires_rollback());
    }

    #[test]
    fn error_display() {
        let err = ReleaseChecklistError::InvalidRequest {
            field: "release_tag".to_string(),
            detail: "must not be empty".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("release_tag"));
        assert!(msg.contains("must not be empty"));
    }

    // ── required_checklist_items ──────────────────────────────────────

    #[test]
    fn required_items_not_empty() {
        let items = required_checklist_items();
        assert!(!items.is_empty());
        assert_eq!(items.len(), REQUIRED_CHECKLIST_ITEMS.len());
    }

    #[test]
    fn required_items_all_have_non_empty_ids() {
        for item in required_checklist_items() {
            assert!(!item.item_id.is_empty());
        }
    }

    #[test]
    fn required_items_cover_all_categories() {
        let categories: BTreeSet<ChecklistCategory> = required_checklist_items()
            .iter()
            .map(|item| item.category)
            .collect();
        assert!(categories.contains(&ChecklistCategory::Security));
        assert!(categories.contains(&ChecklistCategory::Performance));
        assert!(categories.contains(&ChecklistCategory::Reproducibility));
        assert!(categories.contains(&ChecklistCategory::Operational));
    }

    // ── is_required_item_id ──────────────────────────────────────────

    #[test]
    fn is_required_item_id_known() {
        assert!(is_required_item_id("security.conformance_suite"));
        assert!(is_required_item_id("security.test262_es2020_gate"));
        assert!(is_required_item_id("performance.benchmark_suite"));
    }

    #[test]
    fn is_required_item_id_unknown() {
        assert!(!is_required_item_id("unknown.item"));
    }

    // ── normalize_utc_timestamp ───────────────────────────────────────

    #[test]
    fn normalize_utc_timestamp_valid() {
        let result = normalize_utc_timestamp("2025-01-15T12:00:00Z").unwrap();
        assert!(result.contains("2025-01-15"));
    }

    #[test]
    fn normalize_utc_timestamp_with_offset() {
        let result = normalize_utc_timestamp("2025-01-15T14:00:00+02:00").unwrap();
        assert!(result.contains("12:00:00")); // Converted to UTC
    }

    #[test]
    fn normalize_utc_timestamp_invalid() {
        let result = normalize_utc_timestamp("not-a-timestamp");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReleaseChecklistError::InvalidTimestamp { .. }
        ));
    }

    // ── build_checklist_id ───────────────────────────────────────────

    #[test]
    fn build_checklist_id_deterministic() {
        let cl = make_full_checklist();
        let a = build_checklist_id(&cl);
        let b = build_checklist_id(&cl);
        assert_eq!(a, b);
        assert!(a.starts_with("rchk_"));
        assert_eq!(a.len(), 5 + 20); // "rchk_" + 20 hex chars
    }

    #[test]
    fn build_checklist_id_changes_with_tag() {
        let mut cl = make_full_checklist();
        let a = build_checklist_id(&cl);
        cl.release_tag = "v0.2.0".to_string();
        let b = build_checklist_id(&cl);
        assert_ne!(a, b);
    }

    // ── validate_release_checklist ────────────────────────────────────

    #[test]
    fn validate_full_checklist_passes() {
        let cl = make_full_checklist();
        assert!(validate_release_checklist(&cl).is_ok());
    }

    #[test]
    fn validate_wrong_schema_version() {
        let mut cl = make_full_checklist();
        cl.schema_version = "wrong-version".to_string();
        let err = validate_release_checklist(&cl).unwrap_err();
        assert!(matches!(err, ReleaseChecklistError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_empty_release_tag() {
        let mut cl = make_full_checklist();
        cl.release_tag = " ".to_string();
        assert!(validate_release_checklist(&cl).is_err());
    }

    #[test]
    fn validate_empty_trace_id() {
        let mut cl = make_full_checklist();
        cl.trace_id = "".to_string();
        assert!(validate_release_checklist(&cl).is_err());
    }

    #[test]
    fn validate_empty_items() {
        let mut cl = make_full_checklist();
        cl.items.clear();
        assert!(validate_release_checklist(&cl).is_err());
    }

    #[test]
    fn validate_invalid_timestamp() {
        let mut cl = make_full_checklist();
        cl.generated_at_utc = "bad-date".to_string();
        let err = validate_release_checklist(&cl).unwrap_err();
        assert!(matches!(
            err,
            ReleaseChecklistError::InvalidTimestamp { .. }
        ));
    }

    #[test]
    fn validate_duplicate_item_id() {
        let mut cl = make_full_checklist();
        let dup = cl.items[0].clone();
        cl.items.push(dup);
        let err = validate_release_checklist(&cl).unwrap_err();
        assert!(matches!(err, ReleaseChecklistError::InvalidItem { .. }));
    }

    #[test]
    fn validate_waived_without_waiver_metadata_errors() {
        let mut cl = make_full_checklist();
        cl.items[0].status = ChecklistItemStatus::Waived;
        cl.items[0].waiver = None;
        let err = validate_release_checklist(&cl).unwrap_err();
        assert!(matches!(err, ReleaseChecklistError::InvalidItem { .. }));
    }

    #[test]
    fn validate_waiver_on_non_waived_errors() {
        let mut cl = make_full_checklist();
        cl.items[0].status = ChecklistItemStatus::Pass;
        cl.items[0].waiver = Some(ChecklistWaiver {
            reason: "r".to_string(),
            approver: "a".to_string(),
            exception_artifact_link: "l".to_string(),
        });
        let err = validate_release_checklist(&cl).unwrap_err();
        assert!(matches!(err, ReleaseChecklistError::InvalidItem { .. }));
    }

    #[test]
    fn validate_empty_artifact_id_errors() {
        let mut cl = make_full_checklist();
        cl.items[0].artifact_refs[0].artifact_id = " ".to_string();
        assert!(validate_release_checklist(&cl).is_err());
    }

    // ── evaluate_checklist ────────────────────────────────────────────

    #[test]
    fn evaluate_full_passing_not_blocked() {
        let cl = make_full_checklist();
        let result = evaluate_checklist(&cl).unwrap();
        assert!(!result.blocked);
        assert!(result.blockers.is_empty());
    }

    #[test]
    fn evaluate_missing_required_item_is_blocked() {
        let mut cl = make_full_checklist();
        // Remove the first required item
        let first_id = REQUIRED_CHECKLIST_ITEMS[0].item_id;
        cl.items.retain(|item| item.item_id != first_id);
        let result = evaluate_checklist(&cl).unwrap();
        assert!(result.blocked);
        assert!(result.blockers.iter().any(|b| b.contains(first_id)));
    }

    #[test]
    fn evaluate_failed_required_item_is_blocked() {
        let mut cl = make_full_checklist();
        cl.items[0].status = ChecklistItemStatus::Fail;
        let result = evaluate_checklist(&cl).unwrap();
        assert!(result.blocked);
    }

    #[test]
    fn evaluate_pass_without_artifacts_is_blocked() {
        let mut cl = make_full_checklist();
        cl.items[0].artifact_refs.clear();
        let result = evaluate_checklist(&cl).unwrap();
        assert!(result.blocked);
    }

    // ── parse_release_checklist_json ──────────────────────────────────

    #[test]
    fn parse_valid_json() {
        let cl = make_full_checklist();
        let json = serde_json::to_string(&cl).unwrap();
        let parsed = parse_release_checklist_json(&json).unwrap();
        assert_eq!(parsed.release_tag, "v0.1.0");
    }

    #[test]
    fn parse_invalid_json() {
        let err = parse_release_checklist_json("not json").unwrap_err();
        assert!(matches!(
            err,
            ReleaseChecklistError::SerializationFailure { .. }
        ));
    }

    // ── serde round-trips ──────────────────────────────────────────────

    #[test]
    fn checklist_serde_round_trip() {
        let cl = make_full_checklist();
        let json = serde_json::to_string(&cl).unwrap();
        let back: ReleaseChecklist = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cl);
    }

    #[test]
    fn gate_event_serde_round_trip() {
        let event = ReleaseChecklistGateEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: RELEASE_CHECKLIST_COMPONENT.to_string(),
            event: "test".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            checklist_id: Some("rchk_abc".to_string()),
            item_id: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: ReleaseChecklistGateEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, event);
    }

    // ── ChecklistItemStatus::Display ──────────────────────────────────

    #[test]
    fn item_status_display() {
        assert_eq!(ChecklistItemStatus::Pass.to_string(), "pass");
        assert_eq!(ChecklistItemStatus::Fail.to_string(), "fail");
        assert_eq!(ChecklistItemStatus::NotRun.to_string(), "not_run");
        assert_eq!(ChecklistItemStatus::Waived.to_string(), "waived");
    }

    // ── ChecklistCategory ordering ────────────────────────────────────

    #[test]
    fn checklist_category_ordering() {
        assert!(ChecklistCategory::Security < ChecklistCategory::Performance);
        assert!(ChecklistCategory::Performance < ChecklistCategory::Reproducibility);
        assert!(ChecklistCategory::Reproducibility < ChecklistCategory::Operational);
    }

    #[test]
    fn checklist_category_display_all_variants() {
        assert_eq!(ChecklistCategory::Performance.to_string(), "performance");
        assert_eq!(
            ChecklistCategory::Reproducibility.to_string(),
            "reproducibility"
        );
        assert_eq!(ChecklistCategory::Operational.to_string(), "operational");
    }

    // ── ChecklistItemStatus ordering ──────────────────────────────────

    #[test]
    fn item_status_ordering() {
        assert!(ChecklistItemStatus::Pass < ChecklistItemStatus::Fail);
        assert!(ChecklistItemStatus::Fail < ChecklistItemStatus::NotRun);
        assert!(ChecklistItemStatus::NotRun < ChecklistItemStatus::Waived);
    }

    // ── ReleaseChecklistError stable codes (remaining variants) ──────

    #[test]
    fn error_stable_code_storage_failure() {
        let err = ReleaseChecklistError::StorageFailure(StorageError::WriteRejected {
            detail: "test".to_string(),
        });
        assert_eq!(err.stable_code(), ERROR_STORAGE);
    }

    #[test]
    fn error_requires_rollback_storage_failure() {
        let err = ReleaseChecklistError::StorageFailure(StorageError::WriteRejected {
            detail: "test".to_string(),
        });
        assert!(err.requires_rollback());
    }

    #[test]
    fn error_requires_rollback_non_storage_variants() {
        assert!(
            !ReleaseChecklistError::InvalidTimestamp {
                value: "bad".to_string()
            }
            .requires_rollback()
        );
        assert!(
            !ReleaseChecklistError::InvalidItem {
                item_id: "x".to_string(),
                detail: "d".to_string()
            }
            .requires_rollback()
        );
        assert!(
            !ReleaseChecklistError::SerializationFailure {
                detail: "d".to_string()
            }
            .requires_rollback()
        );
    }

    // ── ReleaseChecklistError Display (remaining variants) ────────────

    #[test]
    fn error_display_invalid_timestamp() {
        let err = ReleaseChecklistError::InvalidTimestamp {
            value: "not-a-time".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("not-a-time"));
        assert!(msg.contains("RFC3339"));
    }

    #[test]
    fn error_display_invalid_item() {
        let err = ReleaseChecklistError::InvalidItem {
            item_id: "security.test".to_string(),
            detail: "duplicate item_id".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("security.test"));
        assert!(msg.contains("duplicate"));
    }

    #[test]
    fn error_display_serialization_failure() {
        let err = ReleaseChecklistError::SerializationFailure {
            detail: "parse error".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("parse error"));
    }

    #[test]
    fn error_display_storage_failure() {
        let err = ReleaseChecklistError::StorageFailure(StorageError::WriteRejected {
            detail: "write rejected".to_string(),
        });
        let msg = err.to_string();
        assert!(msg.contains("storage failure"));
    }

    // ── ArtifactRef serde round-trip ──────────────────────────────────

    #[test]
    fn artifact_ref_serde_round_trip() {
        let art = ArtifactRef {
            artifact_id: "art-1".to_string(),
            path: "artifacts/art-1.json".to_string(),
            sha256: Some("a".repeat(64)),
        };
        let json = serde_json::to_string(&art).unwrap();
        let back: ArtifactRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back, art);
    }

    #[test]
    fn artifact_ref_serde_without_sha256() {
        let art = ArtifactRef {
            artifact_id: "art-2".to_string(),
            path: "artifacts/art-2.json".to_string(),
            sha256: None,
        };
        let json = serde_json::to_string(&art).unwrap();
        let back: ArtifactRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back, art);
    }

    // ── ChecklistWaiver serde round-trip ──────────────────────────────

    #[test]
    fn checklist_waiver_serde_round_trip() {
        let waiver = ChecklistWaiver {
            reason: "known issue".to_string(),
            approver: "admin".to_string(),
            exception_artifact_link: "bd-99".to_string(),
        };
        let json = serde_json::to_string(&waiver).unwrap();
        let back: ChecklistWaiver = serde_json::from_str(&json).unwrap();
        assert_eq!(back, waiver);
    }

    // ── ChecklistItem serde round-trip ────────────────────────────────

    #[test]
    fn checklist_item_serde_round_trip() {
        let item = make_passing_item("security.conformance_suite", ChecklistCategory::Security);
        let json = serde_json::to_string(&item).unwrap();
        let back: ChecklistItem = serde_json::from_str(&json).unwrap();
        assert_eq!(back, item);
    }

    #[test]
    fn checklist_item_waived_serde_round_trip() {
        let item = ChecklistItem {
            item_id: "security.conformance_suite".to_string(),
            category: ChecklistCategory::Security,
            required: true,
            status: ChecklistItemStatus::Waived,
            artifact_refs: vec![make_artifact_ref("art-1")],
            waiver: Some(ChecklistWaiver {
                reason: "known gap".to_string(),
                approver: "eng-lead".to_string(),
                exception_artifact_link: "bd-100".to_string(),
            }),
        };
        let json = serde_json::to_string(&item).unwrap();
        let back: ChecklistItem = serde_json::from_str(&json).unwrap();
        assert_eq!(back, item);
    }

    // ── ReleaseChecklistGateDecision serde round-trip ─────────────────

    #[test]
    fn gate_decision_serde_round_trip() {
        let decision = ReleaseChecklistGateDecision {
            checklist_id: Some("rchk_abc".to_string()),
            release_tag: "v1.0.0".to_string(),
            outcome: "allow".to_string(),
            blocked: false,
            blockers: vec![],
            error_code: None,
            rollback_required: false,
            storage_backend: "in_memory".to_string(),
            storage_integration_point: RELEASE_CHECKLIST_STORAGE_INTEGRATION_POINT.to_string(),
            store_key: Some("release_checklist/v1.0.0/rchk_abc".to_string()),
            events: vec![],
        };
        let json = serde_json::to_string(&decision).unwrap();
        let back: ReleaseChecklistGateDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, decision);
    }

    // ── evaluate_checklist edge cases ─────────────────────────────────

    #[test]
    fn evaluate_not_run_required_item_is_blocked() {
        let mut cl = make_full_checklist();
        cl.items[0].status = ChecklistItemStatus::NotRun;
        let result = evaluate_checklist(&cl).unwrap();
        assert!(result.blocked);
        assert!(result.blockers.iter().any(|b| b.contains("not_run")));
    }

    #[test]
    fn evaluate_wrong_category_is_blocked() {
        let mut cl = make_full_checklist();
        // Change a security item to performance category
        cl.items[0].category = ChecklistCategory::Performance;
        let result = evaluate_checklist(&cl).unwrap();
        assert!(result.blocked);
        assert!(result.blockers.iter().any(|b| b.contains("category")));
    }

    #[test]
    fn evaluate_waived_with_valid_waiver_passes() {
        let mut cl = make_full_checklist();
        cl.items[0].status = ChecklistItemStatus::Waived;
        cl.items[0].waiver = Some(ChecklistWaiver {
            reason: "known issue".to_string(),
            approver: "admin".to_string(),
            exception_artifact_link: "bd-99".to_string(),
        });
        let result = evaluate_checklist(&cl).unwrap();
        // Waived items don't block release
        assert!(!result.blocked);
    }

    #[test]
    fn evaluate_waived_without_artifacts_is_blocked() {
        let mut cl = make_full_checklist();
        cl.items[0].status = ChecklistItemStatus::Waived;
        cl.items[0].waiver = Some(ChecklistWaiver {
            reason: "known issue".to_string(),
            approver: "admin".to_string(),
            exception_artifact_link: "bd-99".to_string(),
        });
        cl.items[0].artifact_refs.clear();
        let result = evaluate_checklist(&cl).unwrap();
        assert!(result.blocked);
        assert!(
            result
                .blockers
                .iter()
                .any(|b| b.contains("no artifact_refs"))
        );
    }

    // ── normalize_checklist edge cases ────────────────────────────────

    #[test]
    fn validate_empty_decision_id() {
        let mut cl = make_full_checklist();
        cl.decision_id = "".to_string();
        assert!(validate_release_checklist(&cl).is_err());
    }

    #[test]
    fn validate_empty_policy_id() {
        let mut cl = make_full_checklist();
        cl.policy_id = " ".to_string();
        assert!(validate_release_checklist(&cl).is_err());
    }

    #[test]
    fn validate_empty_item_id_errors() {
        let mut cl = make_full_checklist();
        cl.items.push(ChecklistItem {
            item_id: " ".to_string(),
            category: ChecklistCategory::Security,
            required: false,
            status: ChecklistItemStatus::Pass,
            artifact_refs: vec![],
            waiver: None,
        });
        let err = validate_release_checklist(&cl).unwrap_err();
        assert!(matches!(err, ReleaseChecklistError::InvalidItem { .. }));
    }

    #[test]
    fn validate_unknown_required_item_id_errors() {
        let mut cl = make_full_checklist();
        cl.items.push(ChecklistItem {
            item_id: "unknown.item".to_string(),
            category: ChecklistCategory::Security,
            required: true,
            status: ChecklistItemStatus::Pass,
            artifact_refs: vec![make_artifact_ref("art-1")],
            waiver: None,
        });
        let err = validate_release_checklist(&cl).unwrap_err();
        assert!(matches!(err, ReleaseChecklistError::InvalidItem { .. }));
    }

    #[test]
    fn validate_waiver_empty_reason_errors() {
        let mut cl = make_full_checklist();
        cl.items[0].status = ChecklistItemStatus::Waived;
        cl.items[0].waiver = Some(ChecklistWaiver {
            reason: " ".to_string(),
            approver: "admin".to_string(),
            exception_artifact_link: "link".to_string(),
        });
        let err = validate_release_checklist(&cl).unwrap_err();
        assert!(matches!(err, ReleaseChecklistError::InvalidItem { .. }));
    }

    #[test]
    fn validate_waiver_empty_approver_errors() {
        let mut cl = make_full_checklist();
        cl.items[0].status = ChecklistItemStatus::Waived;
        cl.items[0].waiver = Some(ChecklistWaiver {
            reason: "reason".to_string(),
            approver: "".to_string(),
            exception_artifact_link: "link".to_string(),
        });
        let err = validate_release_checklist(&cl).unwrap_err();
        assert!(matches!(err, ReleaseChecklistError::InvalidItem { .. }));
    }

    #[test]
    fn validate_waiver_empty_exception_link_errors() {
        let mut cl = make_full_checklist();
        cl.items[0].status = ChecklistItemStatus::Waived;
        cl.items[0].waiver = Some(ChecklistWaiver {
            reason: "reason".to_string(),
            approver: "admin".to_string(),
            exception_artifact_link: " ".to_string(),
        });
        let err = validate_release_checklist(&cl).unwrap_err();
        assert!(matches!(err, ReleaseChecklistError::InvalidItem { .. }));
    }

    #[test]
    fn validate_empty_artifact_path_errors() {
        let mut cl = make_full_checklist();
        cl.items[0].artifact_refs[0].path = " ".to_string();
        assert!(validate_release_checklist(&cl).is_err());
    }

    #[test]
    fn validate_empty_sha256_trimmed_to_none() {
        let mut cl = make_full_checklist();
        cl.items[0].artifact_refs[0].sha256 = Some("  ".to_string());
        // Should succeed — empty sha256 is trimmed to None
        assert!(validate_release_checklist(&cl).is_ok());
    }

    // ── normalize_utc_timestamp additional cases ──────────────────────

    #[test]
    fn normalize_utc_timestamp_fractional_seconds() {
        let result = normalize_utc_timestamp("2025-01-15T12:00:00.123Z").unwrap();
        assert!(result.contains("12:00:00"));
    }

    // ── build_checklist_id edge cases ─────────────────────────────────

    #[test]
    fn build_checklist_id_includes_waiver_content() {
        let mut cl = make_full_checklist();
        let id_without_waiver = build_checklist_id(&cl);

        cl.items[0].status = ChecklistItemStatus::Waived;
        cl.items[0].waiver = Some(ChecklistWaiver {
            reason: "reason".to_string(),
            approver: "admin".to_string(),
            exception_artifact_link: "link".to_string(),
        });
        let id_with_waiver = build_checklist_id(&cl);
        assert_ne!(id_without_waiver, id_with_waiver);
    }

    #[test]
    fn build_checklist_id_changes_with_artifact_refs() {
        let mut cl = make_full_checklist();
        let id_before = build_checklist_id(&cl);
        cl.items[0]
            .artifact_refs
            .push(make_artifact_ref("extra-art"));
        let id_after = build_checklist_id(&cl);
        assert_ne!(id_before, id_after);
    }

    // ── make_event ───────────────────────────────────────────────────

    #[test]
    fn make_event_populates_fields() {
        let cl = make_full_checklist();
        let event = make_event(
            &cl,
            "test_event",
            "pass",
            Some("FE-ERR".to_string()),
            Some("rchk_123".to_string()),
            Some("item-1".to_string()),
        );
        assert_eq!(event.trace_id, "trace-001");
        assert_eq!(event.decision_id, "decision-001");
        assert_eq!(event.policy_id, "policy-001");
        assert_eq!(event.component, RELEASE_CHECKLIST_COMPONENT);
        assert_eq!(event.event, "test_event");
        assert_eq!(event.outcome, "pass");
        assert_eq!(event.error_code.as_deref(), Some("FE-ERR"));
        assert_eq!(event.checklist_id.as_deref(), Some("rchk_123"));
        assert_eq!(event.item_id.as_deref(), Some("item-1"));
    }

    #[test]
    fn make_event_none_optionals() {
        let cl = make_full_checklist();
        let event = make_event(&cl, "started", "pass", None, None, None);
        assert!(event.error_code.is_none());
        assert!(event.checklist_id.is_none());
        assert!(event.item_id.is_none());
    }

    // ── hash_update ──────────────────────────────────────────────────

    #[test]
    fn hash_update_affects_digest() {
        let mut h1 = Sha256::new();
        hash_update(&mut h1, "hello");
        let d1 = hex::encode(h1.finalize());

        let mut h2 = Sha256::new();
        hash_update(&mut h2, "world");
        let d2 = hex::encode(h2.finalize());

        assert_ne!(d1, d2);
    }

    #[test]
    fn hash_update_separator_prevents_collision() {
        // "ab" + "c" vs "a" + "bc" should produce different hashes
        let mut h1 = Sha256::new();
        hash_update(&mut h1, "ab");
        hash_update(&mut h1, "c");
        let d1 = hex::encode(h1.finalize());

        let mut h2 = Sha256::new();
        hash_update(&mut h2, "a");
        hash_update(&mut h2, "bc");
        let d2 = hex::encode(h2.finalize());

        assert_ne!(d1, d2);
    }

    // ── required_checklist_items: unique ids ──────────────────────────

    #[test]
    fn required_items_unique_ids() {
        let ids: BTreeSet<&str> = required_checklist_items()
            .iter()
            .map(|item| item.item_id)
            .collect();
        assert_eq!(ids.len(), required_checklist_items().len());
    }

    // ── run_release_checklist_gate with InMemoryStorageAdapter ──────

    #[test]
    fn run_gate_passing_checklist() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut adapter = InMemoryStorageAdapter::default();
        let cl = make_full_checklist();
        let decision = run_release_checklist_gate(&mut adapter, &cl);
        assert!(decision.allows_release());
        assert!(!decision.blocked);
        assert!(decision.blockers.is_empty());
        assert_eq!(decision.outcome, "allow");
        assert!(decision.checklist_id.is_some());
        assert!(decision.store_key.is_some());
        assert!(decision.error_code.is_none());
        assert!(!decision.rollback_required);
        // Should have events: started, evaluated, stored, completed
        assert!(decision.events.len() >= 3);
    }

    #[test]
    fn run_gate_failing_checklist() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut adapter = InMemoryStorageAdapter::default();
        let mut cl = make_full_checklist();
        cl.items[0].status = ChecklistItemStatus::Fail;
        let decision = run_release_checklist_gate(&mut adapter, &cl);
        assert!(!decision.allows_release());
        assert!(decision.blocked);
        assert!(!decision.blockers.is_empty());
        assert_eq!(decision.outcome, "deny");
        assert_eq!(decision.error_code.as_deref(), Some(ERROR_RELEASE_BLOCKED));
    }

    #[test]
    fn run_gate_invalid_schema_fails() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut adapter = InMemoryStorageAdapter::default();
        let mut cl = make_full_checklist();
        cl.schema_version = "wrong".to_string();
        let decision = run_release_checklist_gate(&mut adapter, &cl);
        assert!(!decision.allows_release());
        assert!(decision.blocked);
        assert_eq!(decision.outcome, "fail");
        assert!(decision.checklist_id.is_none());
    }

    #[test]
    fn run_gate_stores_checklist_and_queryable() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut adapter = InMemoryStorageAdapter::default();
        let cl = make_full_checklist();
        let decision = run_release_checklist_gate(&mut adapter, &cl);
        assert!(decision.allows_release());

        // Query back
        let results = query_release_checklists_by_tag(
            &mut adapter,
            "v0.1.0",
            "trace-q",
            "decision-q",
            "policy-q",
        )
        .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].release_tag, "v0.1.0");
    }

    // ── query_release_checklists_by_tag ──────────────────────────────

    #[test]
    fn query_empty_release_tag_errors() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut adapter = InMemoryStorageAdapter::default();
        let err = query_release_checklists_by_tag(&mut adapter, "", "t", "d", "p").unwrap_err();
        assert!(matches!(err, ReleaseChecklistError::InvalidRequest { .. }));
    }

    #[test]
    fn query_empty_trace_id_errors() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut adapter = InMemoryStorageAdapter::default();
        let err = query_release_checklists_by_tag(&mut adapter, "v1", "", "d", "p").unwrap_err();
        assert!(matches!(err, ReleaseChecklistError::InvalidRequest { .. }));
    }

    #[test]
    fn query_nonexistent_tag_returns_empty() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut adapter = InMemoryStorageAdapter::default();
        let results =
            query_release_checklists_by_tag(&mut adapter, "nonexistent", "t", "d", "p").unwrap();
        assert!(results.is_empty());
    }

    // ── normalize_checklist items are sorted ──────────────────────────

    #[test]
    fn normalize_sorts_items_by_id() {
        let mut cl = make_full_checklist();
        // Reverse the items
        cl.items.reverse();
        let first_id_before = cl.items[0].item_id.clone();
        assert!(validate_release_checklist(&cl).is_ok());
        // After normalization via evaluate, items should be sorted
        let result = evaluate_checklist(&cl).unwrap();
        let first_id_after = result.normalized.items[0].item_id.clone();
        // The items are sorted alphabetically
        assert!(first_id_after <= result.normalized.items[1].item_id);
        // Should be different from the reversed order (unless already sorted)
        let _ = first_id_before;
    }

    // ── normalize_checklist artifact_refs sorted ──────────────────────

    #[test]
    fn normalize_sorts_artifact_refs() {
        let mut cl = make_full_checklist();
        let target_id = cl.items[0].item_id.clone();
        cl.items[0].artifact_refs = vec![
            ArtifactRef {
                artifact_id: "z-art".to_string(),
                path: "z.json".to_string(),
                sha256: None,
            },
            ArtifactRef {
                artifact_id: "a-art".to_string(),
                path: "a.json".to_string(),
                sha256: None,
            },
        ];
        let result = evaluate_checklist(&cl).unwrap();
        let item = result
            .normalized
            .items
            .iter()
            .find(|i| i.item_id == target_id)
            .unwrap();
        assert_eq!(item.artifact_refs[0].artifact_id, "a-art");
        assert_eq!(item.artifact_refs[1].artifact_id, "z-art");
    }

    // ── constants ────────────────────────────────────────────────────

    #[test]
    fn release_checklist_constants_not_empty() {
        assert!(!RELEASE_CHECKLIST_COMPONENT.is_empty());
        assert!(!RELEASE_CHECKLIST_SCHEMA_VERSION.is_empty());
        assert!(!RELEASE_CHECKLIST_STORAGE_INTEGRATION_POINT.is_empty());
    }

    #[test]
    fn error_constants_not_empty() {
        assert!(!ERROR_INVALID_REQUEST.is_empty());
        assert!(!ERROR_INVALID_TIMESTAMP.is_empty());
        assert!(!ERROR_INVALID_ITEM.is_empty());
        assert!(!ERROR_SERIALIZATION.is_empty());
        assert!(!ERROR_RELEASE_BLOCKED.is_empty());
        assert!(!ERROR_STORAGE.is_empty());
    }

    // ── run_release_checklist_gate events structure ──────────────────

    #[test]
    fn run_gate_events_have_correct_structure() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut adapter = InMemoryStorageAdapter::default();
        let cl = make_full_checklist();
        let decision = run_release_checklist_gate(&mut adapter, &cl);
        // First event should be "started"
        assert_eq!(decision.events[0].event, "release_checklist_gate_started");
        // Last event should be "completed"
        let last = decision.events.last().unwrap();
        assert_eq!(last.event, "release_checklist_gate_completed");
        // All events should have matching trace/decision/policy
        for event in &decision.events {
            assert_eq!(event.component, RELEASE_CHECKLIST_COMPONENT);
        }
    }

    // ── ReleaseChecklistError From<StorageError> ─────────────────────

    #[test]
    fn error_from_storage_error() {
        let storage_err = StorageError::WriteRejected {
            detail: "disk full".to_string(),
        };
        let err: ReleaseChecklistError = storage_err.into();
        assert!(matches!(err, ReleaseChecklistError::StorageFailure(_)));
        assert!(err.requires_rollback());
    }

    // ── Multiple run_gate calls store separately ─────────────────────

    #[test]
    fn multiple_gate_runs_stored_separately() {
        use crate::storage_adapter::InMemoryStorageAdapter;
        let mut adapter = InMemoryStorageAdapter::default();

        let cl1 = make_full_checklist();
        let decision1 = run_release_checklist_gate(&mut adapter, &cl1);
        assert!(decision1.allows_release());

        let mut cl2 = make_full_checklist();
        cl2.generated_at_utc = "2025-02-20T15:00:00Z".to_string();
        cl2.trace_id = "trace-002".to_string();
        cl2.decision_id = "decision-002".to_string();
        let decision2 = run_release_checklist_gate(&mut adapter, &cl2);
        assert!(decision2.allows_release());

        // Both should be queryable
        let results = query_release_checklists_by_tag(
            &mut adapter,
            "v0.1.0",
            "trace-q",
            "decision-q",
            "policy-q",
        )
        .unwrap();
        assert_eq!(results.len(), 2);
    }
}
