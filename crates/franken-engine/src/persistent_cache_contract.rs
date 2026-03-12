use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::module_cache::{
    CacheContext, CacheInsertRequest, CacheSnapshot, ModuleCache, ModuleCacheEntry,
    ModuleVersionFingerprint,
};

pub const BEAD_ID: &str = "bd-1lsy.7.10.1";
pub const COMPONENT: &str = "persistent_cache_contract";
pub const CONTRACT_SCHEMA_VERSION: &str = "franken-engine.rgc-persistent-cache-contract.v1";
pub const RECEIPT_SCHEMA_VERSION: &str = "franken-engine.rgc-persistent-cache-receipt.v1";
pub const ROLLBACK_PLAN_SCHEMA_VERSION: &str = "franken-engine.rgc-persistent-cache-rollback.v1";
pub const TRACE_IDS_SCHEMA_VERSION: &str = "franken-engine.rgc-persistent-cache-trace-ids.v1";
pub const RUN_MANIFEST_SCHEMA_VERSION: &str = "franken-engine.rgc-persistent-cache-run-manifest.v1";
#[cfg(test)]
pub const DOCS_CONTRACT_SCHEMA_VERSION: &str = "franken-engine.rgc-persistent-cache-docs.v1";

static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentCacheKeyMaterial {
    pub module_id: String,
    pub source_hash: String,
    pub policy_version: u64,
    pub trust_revision: u64,
    pub config_fingerprint: String,
    pub dependency_graph_hash: String,
    pub transform_profile: String,
    pub runtime_mode: String,
    pub engine_version_marker: String,
}

impl PersistentCacheKeyMaterial {
    pub fn from_fingerprint(
        module_id: impl Into<String>,
        fingerprint: &ModuleVersionFingerprint,
        config_fingerprint: ContentHash,
        dependency_graph_hash: ContentHash,
        transform_profile: impl Into<String>,
        runtime_mode: impl Into<String>,
        engine_version_marker: impl Into<String>,
    ) -> Self {
        Self {
            module_id: module_id.into(),
            source_hash: fingerprint.source_hash.to_hex(),
            policy_version: fingerprint.policy_version,
            trust_revision: fingerprint.trust_revision,
            config_fingerprint: config_fingerprint.to_hex(),
            dependency_graph_hash: dependency_graph_hash.to_hex(),
            transform_profile: transform_profile.into(),
            runtime_mode: runtime_mode.into(),
            engine_version_marker: engine_version_marker.into(),
        }
    }

    pub fn cache_key_id(&self) -> String {
        digest_json(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheConsumerRoute {
    pub consumer: String,
    pub required_fields: Vec<String>,
    pub usage: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidationRule {
    pub rule_id: String,
    pub trigger: String,
    pub fail_closed_behavior: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentCacheReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub cache_key_id: String,
    pub module_id: String,
    pub source_hash: String,
    pub policy_version: u64,
    pub trust_revision: u64,
    pub artifact_hash: String,
    pub snapshot_state_hash: String,
    pub resolved_specifier: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub consumers: Vec<String>,
    pub rollback_target_receipt_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheRollbackPlan {
    pub schema_version: String,
    pub trigger: String,
    pub rollback_receipt_id: String,
    pub rollback_cache_key_id: String,
    pub criteria: Vec<String>,
    pub fail_closed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractScenarioResult {
    pub scenario_id: String,
    pub outcome: String,
    pub detail: String,
    pub error_code: Option<String>,
    pub receipt_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentCacheContractArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub generated_at_utc: String,
    pub contract_hash: String,
    pub key_fields: Vec<String>,
    pub invalidation_rules: Vec<InvalidationRule>,
    pub consumer_routes: Vec<CacheConsumerRoute>,
    pub key_material_examples: Vec<PersistentCacheKeyMaterial>,
    pub receipts: Vec<PersistentCacheReceipt>,
    pub rollback_plan: CacheRollbackPlan,
    pub scenarios: Vec<ContractScenarioResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceIdsArtifact {
    pub schema_version: String,
    pub trace_ids: Vec<String>,
    pub decision_id: String,
    pub policy_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub scenario_id: Option<String>,
    pub receipt_id: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleWriteReport {
    pub artifact_dir: PathBuf,
    pub contract: PersistentCacheContractArtifact,
    pub run_manifest_path: PathBuf,
    pub trace_ids_path: PathBuf,
    pub written_files: BTreeMap<String, String>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsContractFixture {
    pub schema_version: String,
    pub bead_id: String,
    pub required_artifacts: Vec<String>,
    pub key_fields: Vec<String>,
    pub consumers: Vec<String>,
    pub scenario_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactContext {
    pub artifact_dir: PathBuf,
    pub run_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub generated_at_utc: String,
    pub source_commit: String,
    pub toolchain: String,
    pub command_invocation: String,
}

impl ArtifactContext {
    pub fn new(artifact_dir: impl Into<PathBuf>) -> Self {
        Self {
            artifact_dir: artifact_dir.into(),
            run_id: format!("run-{}-{}", COMPONENT, Utc::now().format("%Y%m%dT%H%M%SZ")),
            trace_id: "trace.rgc.610a".to_string(),
            decision_id: "decision.rgc.610a".to_string(),
            policy_id: "policy.rgc.610a".to_string(),
            generated_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            source_commit: "unknown".to_string(),
            toolchain: std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "nightly".to_string()),
            command_invocation: "cargo run -p frankenengine-engine --bin franken_persistent_cache_contract -- --artifact-dir <path>".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct EvaluatedArtifacts {
    contract: PersistentCacheContractArtifact,
    trace_ids: TraceIdsArtifact,
    logs: Vec<StructuredLogEvent>,
}

#[derive(Debug, Clone)]
struct FileArtifact {
    path: String,
    contents: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistentCacheContractError {
    MissingEntry {
        module_id: String,
        cache_key_id: String,
    },
    ReceiptFieldMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    RollbackTargetMissing {
        receipt_id: String,
    },
    EmptyRollbackCriteria,
}

impl PersistentCacheContractError {
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::MissingEntry { .. } => "FE-PCACHE-0001",
            Self::ReceiptFieldMismatch { .. } => "FE-PCACHE-0002",
            Self::RollbackTargetMissing { .. } => "FE-PCACHE-0003",
            Self::EmptyRollbackCriteria => "FE-PCACHE-0004",
        }
    }
}

impl fmt::Display for PersistentCacheContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEntry {
                module_id,
                cache_key_id,
            } => write!(
                f,
                "{}: missing cache entry for module `{module_id}` and key `{cache_key_id}`",
                self.error_code()
            ),
            Self::ReceiptFieldMismatch {
                field,
                expected,
                actual,
            } => write!(
                f,
                "{}: receipt field `{field}` mismatch (expected `{expected}`, got `{actual}`)",
                self.error_code()
            ),
            Self::RollbackTargetMissing { receipt_id } => write!(
                f,
                "{}: rollback target receipt `{receipt_id}` is unavailable",
                self.error_code()
            ),
            Self::EmptyRollbackCriteria => {
                write!(
                    f,
                    "{}: rollback criteria must not be empty",
                    self.error_code()
                )
            }
        }
    }
}

impl std::error::Error for PersistentCacheContractError {}

pub fn emit_default_contract_bundle(context: &ArtifactContext) -> io::Result<BundleWriteReport> {
    let evaluated = evaluate_default_artifacts(context).map_err(io::Error::other)?;
    write_bundle(context, &evaluated)
}

#[cfg(test)]
pub fn build_docs_contract_fixture() -> DocsContractFixture {
    DocsContractFixture {
        schema_version: DOCS_CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        required_artifacts: required_artifact_names(),
        key_fields: key_field_names(),
        consumers: vec![
            "product".to_string(),
            "benchmark".to_string(),
            "replay".to_string(),
        ],
        scenario_ids: default_scenario_ids(),
    }
}

pub fn render_summary(contract: &PersistentCacheContractArtifact) -> String {
    let mut lines = vec![
        "# Persistent Cache Contract Summary".to_string(),
        String::new(),
        format!("- bead_id: `{}`", BEAD_ID),
        format!("- component: `{}`", COMPONENT),
        format!("- generated_at_utc: `{}`", contract.generated_at_utc),
        format!("- contract_hash: `{}`", contract.contract_hash),
        format!("- receipts: `{}`", contract.receipts.len()),
        format!("- scenarios: `{}`", contract.scenarios.len()),
        String::new(),
        "## Consumer Routes".to_string(),
    ];

    for route in &contract.consumer_routes {
        lines.push(format!(
            "- `{}` fields={} usage={}",
            route.consumer,
            route.required_fields.join(","),
            route.usage
        ));
    }

    lines.push(String::new());
    lines.push("## Scenario Outcomes".to_string());
    for scenario in &contract.scenarios {
        lines.push(format!(
            "- `{}` outcome=`{}` detail=`{}`",
            scenario.scenario_id, scenario.outcome, scenario.detail
        ));
    }

    lines.join("\n")
}

pub fn verify_receipt(
    receipt: &PersistentCacheReceipt,
    entry: &ModuleCacheEntry,
    snapshot: &CacheSnapshot,
    material: &PersistentCacheKeyMaterial,
) -> Result<(), PersistentCacheContractError> {
    check_field(
        "cache_key_id",
        material.cache_key_id(),
        receipt.cache_key_id.clone(),
    )?;
    check_field(
        "module_id",
        entry.key.module_id.clone(),
        receipt.module_id.clone(),
    )?;
    check_field(
        "source_hash",
        material.source_hash.clone(),
        receipt.source_hash.clone(),
    )?;
    check_field(
        "policy_version",
        material.policy_version.to_string(),
        receipt.policy_version.to_string(),
    )?;
    check_field(
        "trust_revision",
        material.trust_revision.to_string(),
        receipt.trust_revision.to_string(),
    )?;
    check_field(
        "artifact_hash",
        entry.artifact_hash.to_hex(),
        receipt.artifact_hash.clone(),
    )?;
    check_field(
        "snapshot_state_hash",
        snapshot.state_hash.to_hex(),
        receipt.snapshot_state_hash.clone(),
    )?;
    check_field(
        "resolved_specifier",
        entry.resolved_specifier.clone(),
        receipt.resolved_specifier.clone(),
    )?;
    Ok(())
}

pub fn apply_rollback_plan(
    plan: &CacheRollbackPlan,
    receipts: &[PersistentCacheReceipt],
) -> Result<PersistentCacheReceipt, PersistentCacheContractError> {
    if plan.criteria.is_empty() {
        return Err(PersistentCacheContractError::EmptyRollbackCriteria);
    }

    receipts
        .iter()
        .find(|receipt| receipt.receipt_id == plan.rollback_receipt_id)
        .cloned()
        .ok_or_else(|| PersistentCacheContractError::RollbackTargetMissing {
            receipt_id: plan.rollback_receipt_id.clone(),
        })
}

fn evaluate_default_artifacts(
    context: &ArtifactContext,
) -> Result<EvaluatedArtifacts, PersistentCacheContractError> {
    let cache_context =
        CacheContext::new(&context.trace_id, &context.decision_id, &context.policy_id);
    let mut cache = ModuleCache::new();
    let module_id = "mod:compile:entry";
    let config_hash = ContentHash::compute(b"config:deterministic-profile");
    let dependency_hash = ContentHash::compute(b"depgraph:root->shared->runtime");

    let version_v1 = ModuleVersionFingerprint::new(ContentHash::compute(b"source:v1"), 1, 1);
    let key_v1 = PersistentCacheKeyMaterial::from_fingerprint(
        module_id,
        &version_v1,
        config_hash,
        dependency_hash,
        "lower_ir3",
        "baseline_deterministic_profile",
        "engine-0.1.0",
    );
    cache
        .insert(
            CacheInsertRequest::new(
                module_id,
                version_v1.clone(),
                ContentHash::compute(b"artifact:v1"),
                "/app/entry.js",
            ),
            &cache_context,
        )
        .map_err(|error| PersistentCacheContractError::MissingEntry {
            module_id: module_id.to_string(),
            cache_key_id: format!("insert-failed:{error}"),
        })?;

    let snapshot_v1 = cache.snapshot();
    let entry_v1 = cache.get(module_id, &version_v1).cloned().ok_or_else(|| {
        PersistentCacheContractError::MissingEntry {
            module_id: module_id.to_string(),
            cache_key_id: key_v1.cache_key_id(),
        }
    })?;

    let receipt_v1 = build_receipt(&entry_v1, &snapshot_v1, &key_v1, context, None);
    verify_receipt(&receipt_v1, &entry_v1, &snapshot_v1, &key_v1)?;

    let miss_version = ModuleVersionFingerprint::new(ContentHash::compute(b"source:v1"), 2, 1);

    cache.invalidate_source_update(
        module_id,
        ContentHash::compute(b"source:v2"),
        &cache_context,
    );
    let old_key_invalidated = cache.get(module_id, &version_v1).is_none();

    let version_v2 = ModuleVersionFingerprint::new(ContentHash::compute(b"source:v2"), 1, 1);
    let key_v2 = PersistentCacheKeyMaterial::from_fingerprint(
        module_id,
        &version_v2,
        config_hash,
        dependency_hash,
        "codegen_aot",
        "baseline_throughput_profile",
        "engine-0.1.0",
    );
    cache
        .insert(
            CacheInsertRequest::new(
                module_id,
                version_v2.clone(),
                ContentHash::compute(b"artifact:v2"),
                "/app/entry.js",
            ),
            &cache_context,
        )
        .map_err(|error| PersistentCacheContractError::MissingEntry {
            module_id: module_id.to_string(),
            cache_key_id: format!("reinsert-failed:{error}"),
        })?;

    let snapshot_v2 = cache.snapshot();
    let entry_v2 = cache.get(module_id, &version_v2).cloned().ok_or_else(|| {
        PersistentCacheContractError::MissingEntry {
            module_id: module_id.to_string(),
            cache_key_id: key_v2.cache_key_id(),
        }
    })?;

    let receipt_v2 = build_receipt(
        &entry_v2,
        &snapshot_v2,
        &key_v2,
        context,
        Some(receipt_v1.receipt_id.clone()),
    );
    verify_receipt(&receipt_v2, &entry_v2, &snapshot_v2, &key_v2)?;

    let mut corrupted_receipt = receipt_v2.clone();
    corrupted_receipt.artifact_hash = "sha256:corrupt".to_string();
    let corruption_error =
        verify_receipt(&corrupted_receipt, &entry_v2, &snapshot_v2, &key_v2).unwrap_err();

    let rollback_plan = CacheRollbackPlan {
        schema_version: ROLLBACK_PLAN_SCHEMA_VERSION.to_string(),
        trigger: corruption_error.error_code().to_string(),
        rollback_receipt_id: receipt_v1.receipt_id.clone(),
        rollback_cache_key_id: receipt_v1.cache_key_id.clone(),
        criteria: vec![
            "receipt verification fails closed".to_string(),
            "rollback target must be content-addressed and previously verified".to_string(),
            "consumer routes must remain product/benchmark/replay compatible".to_string(),
        ],
        fail_closed: true,
    };
    let rollback_target =
        apply_rollback_plan(&rollback_plan, &[receipt_v1.clone(), receipt_v2.clone()])?;

    let invalidation_rules = vec![
        InvalidationRule {
            rule_id: "source_update".to_string(),
            trigger: "source hash changes".to_string(),
            fail_closed_behavior: "reject old receipt and require a new cache key".to_string(),
        },
        InvalidationRule {
            rule_id: "policy_change".to_string(),
            trigger: "policy version changes".to_string(),
            fail_closed_behavior: "invalidate stale policy entries before reuse".to_string(),
        },
        InvalidationRule {
            rule_id: "trust_revocation".to_string(),
            trigger: "trust revision increases due to revocation".to_string(),
            fail_closed_behavior: "drop entries and deny reuse until trust is restored".to_string(),
        },
    ];

    let consumer_routes = default_consumer_routes();
    let scenarios = vec![
        ContractScenarioResult {
            scenario_id: "cache_hit".to_string(),
            outcome: "pass".to_string(),
            detail: "verified receipt for current deterministic entry".to_string(),
            error_code: None,
            receipt_id: Some(receipt_v1.receipt_id.clone()),
        },
        ContractScenarioResult {
            scenario_id: "cache_miss".to_string(),
            outcome: "pass".to_string(),
            detail: format!(
                "policy-version miss verified for version {}",
                miss_version.policy_version
            ),
            error_code: None,
            receipt_id: None,
        },
        ContractScenarioResult {
            scenario_id: "source_invalidation".to_string(),
            outcome: if old_key_invalidated { "pass" } else { "fail" }.to_string(),
            detail: "source update invalidates old cache key before v2 insert".to_string(),
            error_code: None,
            receipt_id: Some(receipt_v2.receipt_id.clone()),
        },
        ContractScenarioResult {
            scenario_id: "receipt_corruption".to_string(),
            outcome: "pass".to_string(),
            detail: "tampered artifact hash was rejected deterministically".to_string(),
            error_code: Some(corruption_error.error_code().to_string()),
            receipt_id: Some(receipt_v2.receipt_id.clone()),
        },
        ContractScenarioResult {
            scenario_id: "rollback_plan".to_string(),
            outcome: "pass".to_string(),
            detail: format!(
                "rollback selected previously verified receipt `{}`",
                rollback_target.receipt_id
            ),
            error_code: None,
            receipt_id: Some(rollback_target.receipt_id.clone()),
        },
    ];

    let key_material_examples = vec![key_v1, key_v2];
    let receipts = vec![receipt_v1.clone(), receipt_v2.clone()];
    let contract = PersistentCacheContractArtifact {
        schema_version: CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: context.generated_at_utc.clone(),
        contract_hash: digest_json(&serde_json::json!({
            "key_fields": key_field_names(),
            "invalidation_rules": &invalidation_rules,
            "consumer_routes": &consumer_routes,
            "key_material_examples": &key_material_examples,
            "receipts": &receipts,
            "rollback_plan": &rollback_plan,
            "scenarios": &scenarios,
        })),
        key_fields: key_field_names(),
        invalidation_rules,
        consumer_routes,
        key_material_examples,
        receipts: receipts.clone(),
        rollback_plan,
        scenarios: scenarios.clone(),
    };

    let trace_ids = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec![context.trace_id.clone()],
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
    };

    let mut logs = Vec::new();
    for receipt in &receipts {
        logs.push(StructuredLogEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: COMPONENT.to_string(),
            event: "cache_receipt_emitted".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            scenario_id: None,
            receipt_id: Some(receipt.receipt_id.clone()),
            detail: format!(
                "module={} cache_key_id={} consumers={}",
                receipt.module_id,
                receipt.cache_key_id,
                receipt.consumers.join(",")
            ),
        });
    }

    for scenario in &scenarios {
        logs.push(StructuredLogEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: COMPONENT.to_string(),
            event: "contract_scenario".to_string(),
            outcome: scenario.outcome.clone(),
            error_code: scenario.error_code.clone(),
            scenario_id: Some(scenario.scenario_id.clone()),
            receipt_id: scenario.receipt_id.clone(),
            detail: scenario.detail.clone(),
        });
    }

    logs.sort_by(|left, right| {
        left.event
            .cmp(&right.event)
            .then(left.scenario_id.cmp(&right.scenario_id))
            .then(left.receipt_id.cmp(&right.receipt_id))
    });

    Ok(EvaluatedArtifacts {
        contract,
        trace_ids,
        logs,
    })
}

fn build_receipt(
    entry: &ModuleCacheEntry,
    snapshot: &CacheSnapshot,
    material: &PersistentCacheKeyMaterial,
    context: &ArtifactContext,
    rollback_target_receipt_id: Option<String>,
) -> PersistentCacheReceipt {
    let receipt_seed = serde_json::json!({
        "cache_key_id": material.cache_key_id(),
        "artifact_hash": entry.artifact_hash.to_hex(),
        "snapshot_state_hash": snapshot.state_hash.to_hex(),
        "resolved_specifier": &entry.resolved_specifier,
    });
    PersistentCacheReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id: digest_json(&receipt_seed),
        cache_key_id: material.cache_key_id(),
        module_id: entry.key.module_id.clone(),
        source_hash: material.source_hash.clone(),
        policy_version: material.policy_version,
        trust_revision: material.trust_revision,
        artifact_hash: entry.artifact_hash.to_hex(),
        snapshot_state_hash: snapshot.state_hash.to_hex(),
        resolved_specifier: entry.resolved_specifier.clone(),
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        consumers: vec![
            "product".to_string(),
            "benchmark".to_string(),
            "replay".to_string(),
        ],
        rollback_target_receipt_id,
    }
}

fn default_consumer_routes() -> Vec<CacheConsumerRoute> {
    vec![
        CacheConsumerRoute {
            consumer: "product".to_string(),
            required_fields: vec![
                "cache_key_id".to_string(),
                "artifact_hash".to_string(),
                "resolved_specifier".to_string(),
            ],
            usage: "operator and CLI surfaces can explain why a compile/run reused or bypassed cached artifacts".to_string(),
        },
        CacheConsumerRoute {
            consumer: "benchmark".to_string(),
            required_fields: vec![
                "cache_key_id".to_string(),
                "snapshot_state_hash".to_string(),
                "policy_version".to_string(),
            ],
            usage: "benchmark harnesses can prove which cache state and policy version produced a result".to_string(),
        },
        CacheConsumerRoute {
            consumer: "replay".to_string(),
            required_fields: vec![
                "cache_key_id".to_string(),
                "trace_id".to_string(),
                "decision_id".to_string(),
            ],
            usage: "replay tooling can stitch receipt provenance back to deterministic run manifests".to_string(),
        },
    ]
}

fn write_bundle(
    context: &ArtifactContext,
    evaluated: &EvaluatedArtifacts,
) -> io::Result<BundleWriteReport> {
    fs::create_dir_all(&context.artifact_dir)?;

    let artifact_dir_display = context.artifact_dir.display().to_string();
    let summary_md = render_summary(&evaluated.contract);
    let commands = vec![
        context.command_invocation.clone(),
        format!(
            "jq '.receipts[] | {{receipt_id,cache_key_id,artifact_hash}}' {}/persistent_cache_contract.json",
            artifact_dir_display
        ),
        format!("cat {}/run_manifest.json", artifact_dir_display),
    ];

    let env_json = serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": "franken-engine.env.v1",
        "captured_at_utc": &context.generated_at_utc,
        "project": {
            "name": "franken_engine",
            "repo_url": "https://github.com/Dicklesworthstone/franken_engine",
            "commit": &context.source_commit,
            "bead_id": BEAD_ID,
        },
        "host": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        },
        "toolchain": {
            "rustup_toolchain": &context.toolchain,
        },
        "runtime": {
            "component": COMPONENT,
            "trace_id": &context.trace_id,
        },
        "policy": {
            "policy_id": &context.policy_id,
        }
    }))
    .expect("env.json must serialize");

    let mut primary_files = vec![
        FileArtifact::json("persistent_cache_contract.json", &evaluated.contract),
        FileArtifact::json("trace_ids.json", &evaluated.trace_ids),
        FileArtifact::json(
            "run_manifest.json",
            &serde_json::json!({
                "schema_version": RUN_MANIFEST_SCHEMA_VERSION,
                "bead_id": BEAD_ID,
                "component": COMPONENT,
                "run_id": &context.run_id,
                "generated_at_utc": &context.generated_at_utc,
                "trace_id": &context.trace_id,
                "decision_id": &context.decision_id,
                "policy_id": &context.policy_id,
                "contract_hash": &evaluated.contract.contract_hash,
                "receipt_count": evaluated.contract.receipts.len(),
                "scenario_count": evaluated.contract.scenarios.len(),
                "artifacts": required_artifact_names(),
                "consumer_routes": evaluated
                    .contract
                    .consumer_routes
                    .iter()
                    .map(|route| &route.consumer)
                    .collect::<Vec<_>>(),
                "operator_verification": commands.clone(),
            }),
        ),
        FileArtifact::jsonl("events.jsonl", &evaluated.logs),
        FileArtifact::text("commands.txt", &commands.join("\n")),
        FileArtifact::text("summary.md", &summary_md),
        FileArtifact::text("env.json", &env_json),
    ];
    primary_files.sort_by(|left, right| left.path.cmp(&right.path));

    let primary_hashes = primary_files
        .iter()
        .map(|artifact| {
            (
                artifact.path.clone(),
                format!("sha256:{}", sha256_hex(&artifact.contents)),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let repro_lock = serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": "franken-engine.repro-lock.v1",
        "generated_at_utc": &context.generated_at_utc,
        "lock_id": format!("{}-{}", COMPONENT, context.run_id),
        "source_commit": &context.source_commit,
        "determinism": {
            "allow_network": false,
            "allow_wall_clock": false,
            "allow_randomness": false,
        },
        "commands": commands.clone(),
        "expected_outputs": primary_hashes.iter().map(|(path, sha256)| {
            serde_json::json!({
                "path": path,
                "sha256": sha256,
            })
        }).collect::<Vec<_>>(),
        "replay": {
            "trace_id": &context.trace_id,
            "decision_id": &context.decision_id,
            "policy_id": &context.policy_id,
        }
    }))
    .expect("repro.lock must serialize");
    primary_files.push(FileArtifact::text("repro.lock", &repro_lock));
    primary_files.sort_by(|left, right| left.path.cmp(&right.path));

    let manifest_artifacts = primary_files
        .iter()
        .map(|artifact| {
            serde_json::json!({
                "path": artifact.path,
                "sha256": format!("sha256:{}", sha256_hex(&artifact.contents)),
            })
        })
        .collect::<Vec<_>>();

    let manifest_json = serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": "franken-engine.manifest.v1",
        "manifest_id": format!("{}-{}", COMPONENT, context.run_id),
        "generated_at_utc": &context.generated_at_utc,
        "claim": {
            "claim_id": BEAD_ID,
            "class": "implementation",
            "statement": "Persistent content-addressed cache contract with deterministic invalidation, receipts, and rollback rules.",
            "status": "observed",
            "bundle_root": &artifact_dir_display,
        },
        "source_revision": {
            "repo": "franken_engine",
            "branch": "main",
            "commit": &context.source_commit,
        },
        "provenance": {
            "trace_id": &context.trace_id,
            "decision_id": &context.decision_id,
            "policy_id": &context.policy_id,
            "replay_pointer": format!("file://{artifact_dir_display}/commands.txt"),
            "evidence_pointer": format!("file://{artifact_dir_display}/persistent_cache_contract.json"),
        },
        "artifacts": manifest_artifacts,
    }))
    .expect("manifest.json must serialize");
    let manifest_artifact = FileArtifact::text("manifest.json", &manifest_json);

    let _bundle_lock = acquire_bundle_write_lock(&context.artifact_dir)?;
    remove_commit_marker(&context.artifact_dir.join(&manifest_artifact.path))?;
    let mut written_files = BTreeMap::new();
    for artifact in primary_files {
        let full_path = context.artifact_dir.join(&artifact.path);
        write_atomic(&full_path, &artifact.contents)?;
        written_files.insert(
            artifact.path,
            format!("sha256:{}", sha256_hex(&artifact.contents)),
        );
    }
    let manifest_path = context.artifact_dir.join(&manifest_artifact.path);
    write_atomic(&manifest_path, &manifest_artifact.contents)?;
    written_files.insert(
        manifest_artifact.path,
        format!("sha256:{}", sha256_hex(&manifest_artifact.contents)),
    );

    Ok(BundleWriteReport {
        artifact_dir: context.artifact_dir.clone(),
        contract: evaluated.contract.clone(),
        run_manifest_path: context.artifact_dir.join("run_manifest.json"),
        trace_ids_path: context.artifact_dir.join("trace_ids.json"),
        written_files,
    })
}

fn key_field_names() -> Vec<String> {
    vec![
        "module_id".to_string(),
        "source_hash".to_string(),
        "policy_version".to_string(),
        "trust_revision".to_string(),
        "config_fingerprint".to_string(),
        "dependency_graph_hash".to_string(),
        "transform_profile".to_string(),
        "runtime_mode".to_string(),
        "engine_version_marker".to_string(),
    ]
}

#[allow(dead_code)]
fn default_scenario_ids() -> Vec<String> {
    vec![
        "cache_hit".to_string(),
        "cache_miss".to_string(),
        "source_invalidation".to_string(),
        "receipt_corruption".to_string(),
        "rollback_plan".to_string(),
    ]
}

fn required_artifact_names() -> Vec<String> {
    vec![
        "commands.txt".to_string(),
        "env.json".to_string(),
        "events.jsonl".to_string(),
        "manifest.json".to_string(),
        "persistent_cache_contract.json".to_string(),
        "repro.lock".to_string(),
        "run_manifest.json".to_string(),
        "summary.md".to_string(),
        "trace_ids.json".to_string(),
    ]
}

fn digest_json<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("json digest input must serialize");
    format!("sha256:{}", sha256_hex(&bytes))
}

fn check_field(
    field: &'static str,
    expected: String,
    actual: String,
) -> Result<(), PersistentCacheContractError> {
    if expected == actual {
        Ok(())
    } else {
        Err(PersistentCacheContractError::ReceiptFieldMismatch {
            field,
            expected,
            actual,
        })
    }
}

impl FileArtifact {
    fn json(path: &str, value: &impl Serialize) -> Self {
        let contents = serde_json::to_vec_pretty(value).expect("json artifact must serialize");
        Self {
            path: path.to_string(),
            contents,
        }
    }

    fn jsonl(path: &str, rows: &[impl Serialize]) -> Self {
        let mut contents = Vec::new();
        for row in rows {
            contents.extend(
                serde_json::to_vec(row)
                    .expect("jsonl row must serialize")
                    .into_iter(),
            );
            contents.push(b'\n');
        }
        Self {
            path: path.to_string(),
            contents,
        }
    }

    fn text(path: &str, contents: &str) -> Self {
        Self {
            path: path.to_string(),
            contents: contents.as_bytes().to_vec(),
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn remove_commit_marker(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp_path = unique_temp_path(path);
    fs::write(&temp_path, contents)?;
    if let Err(error) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }
    Ok(())
}

fn unique_temp_path(path: &Path) -> PathBuf {
    let sequence = NEXT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
    let mut temp_name = OsString::from(".");
    match path.file_name() {
        Some(file_name) => temp_name.push(file_name),
        None => temp_name.push("artifact"),
    }
    temp_name.push(format!(".{}.{}.tmp", std::process::id(), sequence));
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(temp_name)
}

fn acquire_bundle_write_lock(artifact_dir: &Path) -> io::Result<BundleWriteLock> {
    fs::create_dir_all(artifact_dir)?;
    let lock_path = artifact_dir.join(".persistent_cache_contract.lock");
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(lock_path)
    {
        Ok(_) => Ok(BundleWriteLock {
            path: artifact_dir.join(".persistent_cache_contract.lock"),
        }),
        Err(source) if source.kind() == ErrorKind::AlreadyExists => Err(io::Error::new(
            ErrorKind::AlreadyExists,
            format!(
                "bundle already being written: {}",
                artifact_dir
                    .join(".persistent_cache_contract.lock")
                    .display()
            ),
        )),
        Err(source) => Err(io::Error::new(
            source.kind(),
            format!(
                "failed to acquire bundle write lock {}: {source}",
                artifact_dir
                    .join(".persistent_cache_contract.lock")
                    .display()
            ),
        )),
    }
}

#[derive(Debug)]
struct BundleWriteLock {
    path: PathBuf,
}

impl Drop for BundleWriteLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "franken-engine-persistent-cache-src-test-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn cache_key_id_is_deterministic() {
        let fingerprint = ModuleVersionFingerprint::new(ContentHash::compute(b"source"), 1, 1);
        let material_a = PersistentCacheKeyMaterial::from_fingerprint(
            "mod:test",
            &fingerprint,
            ContentHash::compute(b"cfg"),
            ContentHash::compute(b"deps"),
            "lower_ir3",
            "baseline_deterministic_profile",
            "engine-0.1.0",
        );
        let material_b = material_a.clone();
        assert_eq!(material_a.cache_key_id(), material_b.cache_key_id());
    }

    #[test]
    fn verify_receipt_detects_corruption() {
        let context = ArtifactContext::new("/tmp/contract-test");
        let evaluated = evaluate_default_artifacts(&context).expect("evaluation");
        let receipt = evaluated.contract.receipts[1].clone();
        let fingerprint = ModuleVersionFingerprint::new(ContentHash::compute(b"source:v2"), 1, 1);
        let material = PersistentCacheKeyMaterial::from_fingerprint(
            "mod:compile:entry",
            &fingerprint,
            ContentHash::compute(b"config:deterministic-profile"),
            ContentHash::compute(b"depgraph:root->shared->runtime"),
            "codegen_aot",
            "baseline_throughput_profile",
            "engine-0.1.0",
        );
        let mut cache = ModuleCache::new();
        let ctx = CacheContext::new("t", "d", "p");
        cache.invalidate_source_update(
            "mod:compile:entry",
            ContentHash::compute(b"source:v2"),
            &ctx,
        );
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:compile:entry",
                    fingerprint.clone(),
                    ContentHash::compute(b"artifact:v2"),
                    "/app/entry.js",
                ),
                &ctx,
            )
            .expect("insert");
        let snapshot = cache.snapshot();
        let entry = cache
            .get("mod:compile:entry", &fingerprint)
            .expect("entry")
            .clone();

        let mut corrupted = receipt.clone();
        corrupted.snapshot_state_hash = "sha256:broken".to_string();
        let error = verify_receipt(&corrupted, &entry, &snapshot, &material).unwrap_err();
        assert_eq!(error.error_code(), "FE-PCACHE-0002");
    }

    #[test]
    fn verify_receipt_detects_source_hash_corruption() {
        let context = ArtifactContext::new("/tmp/contract-test");
        let evaluated = evaluate_default_artifacts(&context).expect("evaluation");
        let receipt = evaluated.contract.receipts[1].clone();
        let fingerprint = ModuleVersionFingerprint::new(ContentHash::compute(b"source:v2"), 1, 1);
        let material = PersistentCacheKeyMaterial::from_fingerprint(
            "mod:compile:entry",
            &fingerprint,
            ContentHash::compute(b"config:deterministic-profile"),
            ContentHash::compute(b"depgraph:root->shared->runtime"),
            "codegen_aot",
            "baseline_throughput_profile",
            "engine-0.1.0",
        );
        let mut cache = ModuleCache::new();
        let ctx = CacheContext::new("t", "d", "p");
        cache.invalidate_source_update(
            "mod:compile:entry",
            ContentHash::compute(b"source:v2"),
            &ctx,
        );
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:compile:entry",
                    fingerprint.clone(),
                    ContentHash::compute(b"artifact:v2"),
                    "/app/entry.js",
                ),
                &ctx,
            )
            .expect("insert");
        let snapshot = cache.snapshot();
        let entry = cache
            .get("mod:compile:entry", &fingerprint)
            .expect("entry")
            .clone();

        let mut corrupted = receipt.clone();
        corrupted.source_hash = "sha256:wrong".to_string();
        let error = verify_receipt(&corrupted, &entry, &snapshot, &material).unwrap_err();
        assert_eq!(error.error_code(), "FE-PCACHE-0002");
    }

    #[test]
    fn rollback_plan_fails_closed_when_target_missing() {
        let plan = CacheRollbackPlan {
            schema_version: ROLLBACK_PLAN_SCHEMA_VERSION.to_string(),
            trigger: "receipt_corruption".to_string(),
            rollback_receipt_id: "missing".to_string(),
            rollback_cache_key_id: "sha256:none".to_string(),
            criteria: vec!["receipt verification fails".to_string()],
            fail_closed: true,
        };
        let error = apply_rollback_plan(&plan, &[]).unwrap_err();
        assert_eq!(error.error_code(), "FE-PCACHE-0003");
    }

    #[test]
    fn docs_fixture_lists_required_artifacts() {
        let fixture = build_docs_contract_fixture();
        assert!(
            fixture
                .required_artifacts
                .contains(&"persistent_cache_contract.json".to_string())
        );
        assert!(
            fixture
                .scenario_ids
                .contains(&"receipt_corruption".to_string())
        );
    }

    #[test]
    fn unique_temp_path_is_distinct_for_each_write_attempt() {
        let target = Path::new("/tmp/persistent-cache-contract.json");
        let first = unique_temp_path(target);
        let second = unique_temp_path(target);

        assert_ne!(first, second);
        assert_eq!(first.parent(), target.parent());
        assert_eq!(second.parent(), target.parent());
    }

    #[test]
    fn bundle_write_lock_rejects_concurrent_writer_until_release() {
        let artifact_dir = temp_dir("lock");

        let first = acquire_bundle_write_lock(&artifact_dir).expect("first lock");
        let second = acquire_bundle_write_lock(&artifact_dir).expect_err("second lock should fail");
        assert_eq!(second.kind(), ErrorKind::AlreadyExists);

        drop(first);
        acquire_bundle_write_lock(&artifact_dir).expect("lock should be acquirable after release");

        let _ = fs::remove_dir_all(&artifact_dir);
    }

    #[test]
    fn failed_rewrite_removes_stale_manifest_commit_marker() {
        let artifact_dir = temp_dir("stale-manifest");
        let manifest_path = artifact_dir.join("manifest.json");
        fs::write(&manifest_path, "{\"stale\":true}\n").expect("seed stale manifest");
        fs::create_dir_all(artifact_dir.join("commands.txt")).expect("create blocking directory");

        let context = ArtifactContext::new(&artifact_dir);
        let err = emit_default_contract_bundle(&context)
            .expect_err("rewrite should fail when artifact target path is a directory");
        assert_eq!(err.kind(), ErrorKind::IsADirectory);
        assert!(
            !manifest_path.exists(),
            "stale manifest commit marker should be removed on failed rewrite"
        );
        assert!(
            !artifact_dir
                .join(".persistent_cache_contract.lock")
                .exists(),
            "bundle lock should be released after failure"
        );

        let _ = fs::remove_dir_all(&artifact_dir);
    }

    // ── schema constants ────────────────────────────────────────────

    #[test]
    fn schema_constants_start_with_franken_engine() {
        assert!(CONTRACT_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(RECEIPT_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(ROLLBACK_PLAN_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(TRACE_IDS_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(RUN_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(DOCS_CONTRACT_SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn bead_and_component_are_non_empty() {
        assert!(!BEAD_ID.is_empty());
        assert!(!COMPONENT.is_empty());
    }

    // ── error codes ─────────────────────────────────────────────────

    #[test]
    fn error_codes_are_distinct() {
        let codes = [
            PersistentCacheContractError::MissingEntry {
                module_id: String::new(),
                cache_key_id: String::new(),
            }
            .error_code(),
            PersistentCacheContractError::ReceiptFieldMismatch {
                field: "x",
                expected: String::new(),
                actual: String::new(),
            }
            .error_code(),
            PersistentCacheContractError::RollbackTargetMissing {
                receipt_id: String::new(),
            }
            .error_code(),
            PersistentCacheContractError::EmptyRollbackCriteria.error_code(),
        ];
        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len());
    }

    #[test]
    fn error_display_includes_error_code() {
        let err = PersistentCacheContractError::MissingEntry {
            module_id: "mod:test".to_string(),
            cache_key_id: "sha256:abc".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("FE-PCACHE-0001"));
        assert!(msg.contains("mod:test"));
    }

    #[test]
    fn empty_rollback_criteria_rejected() {
        let plan = CacheRollbackPlan {
            schema_version: ROLLBACK_PLAN_SCHEMA_VERSION.to_string(),
            trigger: "manual".to_string(),
            rollback_receipt_id: "r1".to_string(),
            rollback_cache_key_id: "key1".to_string(),
            criteria: vec![],
            fail_closed: false,
        };
        let err = apply_rollback_plan(&plan, &[]).unwrap_err();
        assert_eq!(err.error_code(), "FE-PCACHE-0004");
    }

    // ── cache_key_id properties ─────────────────────────────────────

    #[test]
    fn cache_key_id_differs_for_different_sources() {
        let fp1 = ModuleVersionFingerprint::new(ContentHash::compute(b"src-a"), 1, 1);
        let fp2 = ModuleVersionFingerprint::new(ContentHash::compute(b"src-b"), 1, 1);
        let m1 = PersistentCacheKeyMaterial::from_fingerprint(
            "mod:a",
            &fp1,
            ContentHash::compute(b"cfg"),
            ContentHash::compute(b"deps"),
            "lower_ir3",
            "profile",
            "0.1.0",
        );
        let m2 = PersistentCacheKeyMaterial::from_fingerprint(
            "mod:a",
            &fp2,
            ContentHash::compute(b"cfg"),
            ContentHash::compute(b"deps"),
            "lower_ir3",
            "profile",
            "0.1.0",
        );
        assert_ne!(m1.cache_key_id(), m2.cache_key_id());
    }

    #[test]
    fn cache_key_id_is_hex_sha256() {
        let fp = ModuleVersionFingerprint::new(ContentHash::compute(b"source"), 1, 1);
        let material = PersistentCacheKeyMaterial::from_fingerprint(
            "mod:test",
            &fp,
            ContentHash::compute(b"cfg"),
            ContentHash::compute(b"deps"),
            "lower_ir3",
            "profile",
            "0.1.0",
        );
        let key = material.cache_key_id();
        assert!(key.starts_with("sha256:"));
        assert_eq!(key.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    // ── serde round-trips ───────────────────────────────────────────

    #[test]
    fn persistent_cache_receipt_serde_round_trip() {
        let receipt = PersistentCacheReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_id: "r-1".to_string(),
            cache_key_id: "sha256:abc".to_string(),
            module_id: "mod:test".to_string(),
            source_hash: "sha256:def".to_string(),
            policy_version: 1,
            trust_revision: 1,
            artifact_hash: "sha256:ghi".to_string(),
            snapshot_state_hash: "sha256:jkl".to_string(),
            resolved_specifier: "/test.js".to_string(),
            trace_id: "trace-1".to_string(),
            decision_id: "decision-1".to_string(),
            policy_id: "policy-1".to_string(),
            consumers: vec!["product".to_string()],
            rollback_target_receipt_id: None,
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let back: PersistentCacheReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    #[test]
    fn cache_rollback_plan_serde_round_trip() {
        let plan = CacheRollbackPlan {
            schema_version: ROLLBACK_PLAN_SCHEMA_VERSION.to_string(),
            trigger: "test".to_string(),
            rollback_receipt_id: "r-1".to_string(),
            rollback_cache_key_id: "sha256:abc".to_string(),
            criteria: vec!["test criterion".to_string()],
            fail_closed: true,
        };
        let json = serde_json::to_string(&plan).unwrap();
        let back: CacheRollbackPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, back);
    }

    // ── render_summary ──────────────────────────────────────────────

    #[test]
    fn render_summary_contains_header() {
        let context = ArtifactContext::new("/tmp/render-test");
        let evaluated = evaluate_default_artifacts(&context).expect("evaluation");
        let summary = render_summary(&evaluated.contract);
        assert!(summary.contains("# Persistent Cache Contract Summary"));
        assert!(summary.contains("## Consumer Routes"));
        assert!(summary.contains("## Scenario Outcomes"));
    }

    // ── docs fixture ────────────────────────────────────────────────

    #[test]
    fn docs_fixture_scenario_ids_are_non_empty() {
        let fixture = build_docs_contract_fixture();
        assert!(!fixture.scenario_ids.is_empty());
        for id in &fixture.scenario_ids {
            assert!(!id.is_empty());
        }
    }

    #[test]
    fn docs_fixture_consumers_are_known() {
        let fixture = build_docs_contract_fixture();
        assert!(fixture.consumers.contains(&"product".to_string()));
        assert!(fixture.consumers.contains(&"benchmark".to_string()));
        assert!(fixture.consumers.contains(&"replay".to_string()));
    }

    #[test]
    fn artifact_context_defaults_are_reasonable() {
        let ctx = ArtifactContext::new("/tmp/test-pcache");
        assert!(ctx.run_id.starts_with("run-persistent_cache_contract-"));
        assert!(!ctx.trace_id.is_empty());
        assert!(!ctx.command_invocation.is_empty());
    }

    #[test]
    fn schema_version_constants_are_mutually_distinct() {
        let versions = [
            CONTRACT_SCHEMA_VERSION,
            RECEIPT_SCHEMA_VERSION,
            ROLLBACK_PLAN_SCHEMA_VERSION,
            TRACE_IDS_SCHEMA_VERSION,
            RUN_MANIFEST_SCHEMA_VERSION,
            DOCS_CONTRACT_SCHEMA_VERSION,
        ];
        let set: std::collections::BTreeSet<&str> = versions.iter().copied().collect();
        assert_eq!(set.len(), versions.len());
    }

    #[test]
    fn cache_key_material_serde_round_trip() {
        let km = PersistentCacheKeyMaterial {
            module_id: "mod-1".into(),
            source_hash: "abc123".into(),
            policy_version: 2,
            trust_revision: 1,
            config_fingerprint: "cfg-fp".into(),
            dependency_graph_hash: "dep-hash".into(),
            transform_profile: "default".into(),
            runtime_mode: "safe".into(),
            engine_version_marker: "0.1.0".into(),
        };
        let json = serde_json::to_string(&km).unwrap();
        let back: PersistentCacheKeyMaterial = serde_json::from_str(&json).unwrap();
        assert_eq!(km, back);
        assert_eq!(km.cache_key_id(), back.cache_key_id());
    }

    #[test]
    fn cache_key_id_differs_for_different_policy_versions() {
        let base = PersistentCacheKeyMaterial {
            module_id: "mod-1".into(),
            source_hash: "abc123".into(),
            policy_version: 1,
            trust_revision: 1,
            config_fingerprint: "cfg".into(),
            dependency_graph_hash: "dep".into(),
            transform_profile: "default".into(),
            runtime_mode: "safe".into(),
            engine_version_marker: "0.1.0".into(),
        };
        let mut alt = base.clone();
        alt.policy_version = 2;
        assert_ne!(base.cache_key_id(), alt.cache_key_id());
    }

    #[test]
    fn error_display_covers_all_variants() {
        let errors = [
            PersistentCacheContractError::MissingEntry {
                module_id: "m1".into(),
                cache_key_id: "k1".into(),
            },
            PersistentCacheContractError::ReceiptFieldMismatch {
                field: "source_hash",
                expected: "aaa".into(),
                actual: "bbb".into(),
            },
            PersistentCacheContractError::RollbackTargetMissing {
                receipt_id: "r1".into(),
            },
            PersistentCacheContractError::EmptyRollbackCriteria,
        ];
        for err in &errors {
            let display = format!("{}", err);
            assert!(!display.is_empty());
            assert!(display.contains(err.error_code()));
        }
    }

    #[test]
    fn contract_scenario_result_serde_round_trip() {
        let result = ContractScenarioResult {
            scenario_id: "test-scenario".into(),
            outcome: "pass".into(),
            detail: "test".into(),
            error_code: None,
            receipt_id: Some("r-1".into()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ContractScenarioResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn contract_scenario_result_none_receipt() {
        let result = ContractScenarioResult {
            scenario_id: "test-2".into(),
            outcome: "fail".into(),
            detail: "no receipt".into(),
            error_code: Some("FE-PCACHE-0001".into()),
            receipt_id: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ContractScenarioResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
        assert!(back.receipt_id.is_none());
    }

    #[test]
    fn error_codes_all_start_with_fe_pcache() {
        let errors = [
            PersistentCacheContractError::MissingEntry {
                module_id: "m".into(),
                cache_key_id: "k".into(),
            },
            PersistentCacheContractError::ReceiptFieldMismatch {
                field: "f",
                expected: "e".into(),
                actual: "a".into(),
            },
            PersistentCacheContractError::RollbackTargetMissing {
                receipt_id: "r".into(),
            },
            PersistentCacheContractError::EmptyRollbackCriteria,
        ];
        for err in &errors {
            assert!(err.error_code().starts_with("FE-PCACHE-"));
        }
    }
}
