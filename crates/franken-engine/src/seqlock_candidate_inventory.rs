use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const BEAD_ID: &str = "bd-1lsy.7.21.2";
pub const PREDECESSOR_BEAD_ID: &str = "bd-1lsy.7.21.1";
pub const COMPONENT: &str = "seqlock_candidate_inventory";
pub const INVENTORY_SCHEMA_VERSION: &str = "franken-engine.rgc-seqlock-candidate-inventory.v1";
pub const RETRY_SAFETY_SCHEMA_VERSION: &str = "franken-engine.rgc-seqlock-retry-safety-matrix.v1";
pub const BASELINE_COMPARATOR_SCHEMA_VERSION: &str =
    "franken-engine.rgc-seqlock-baseline-comparator.v1";
pub const READER_WRITER_CONTRACT_SCHEMA_VERSION: &str =
    "franken-engine.rgc-seqlock-reader-writer-contract.v1";
pub const RETRY_BUDGET_POLICY_SCHEMA_VERSION: &str =
    "franken-engine.rgc-seqlock-retry-budget-policy.v1";
pub const INCUMBENT_FALLBACK_MATRIX_SCHEMA_VERSION: &str =
    "franken-engine.rgc-seqlock-incumbent-fallback-matrix.v1";
pub const TRACE_IDS_SCHEMA_VERSION: &str = "franken-engine.rgc-seqlock-trace-ids.v1";
pub const RUN_MANIFEST_SCHEMA_VERSION: &str = "franken-engine.rgc-seqlock-run-manifest.v1";
#[cfg(test)]
pub const CONTRACT_SCHEMA_VERSION: &str = "franken-engine.rgc-seqlock-reader-writer-bundle.v1";

static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateDisposition {
    Accept,
    Conditional,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceArea {
    GovernanceState,
    OfflineArtifact,
    OperatorProjection,
    PolicyState,
    RuntimeMetadata,
    Telemetry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineStrategy {
    CloneSnapshot,
    ExternalJoinProjection,
    ImmutableValueObject,
    MutableSnapshotSideEffect,
    OfflineSummary,
    QueryAppendOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TearingRisk {
    None,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteProfile {
    Rare,
    Moderate,
    Bursty,
    HotPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CandidateSpec {
    candidate_id: &'static str,
    surface_name: &'static str,
    module_path: &'static str,
    api_path: &'static str,
    surface_area: SurfaceArea,
    baseline_path: &'static str,
    incumbent_baseline: &'static str,
    baseline_strategy: BaselineStrategy,
    shared_mutable_state: bool,
    read_side_effect_free: bool,
    retry_safe_read: bool,
    requires_atomic_multi_structure_view: bool,
    requires_external_input_join: bool,
    immutable_value_object: bool,
    write_profile: WriteProfile,
    tearing_risk: TearingRisk,
    exact_fallback_conditions: &'static [&'static str],
    notes: &'static [&'static str],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateInventoryEntry {
    pub candidate_id: String,
    pub surface_name: String,
    pub module_path: String,
    pub api_path: String,
    pub surface_area: SurfaceArea,
    pub baseline_path: String,
    pub incumbent_baseline: String,
    pub baseline_strategy: BaselineStrategy,
    pub disposition: CandidateDisposition,
    pub shared_mutable_state: bool,
    pub read_side_effect_free: bool,
    pub retry_safe_read: bool,
    pub requires_atomic_multi_structure_view: bool,
    pub requires_external_input_join: bool,
    pub immutable_value_object: bool,
    pub write_profile: WriteProfile,
    pub tearing_risk: TearingRisk,
    pub classification_rationale: Vec<String>,
    pub exact_fallback_conditions: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrySafetyMatrixRow {
    pub candidate_id: String,
    pub disposition: CandidateDisposition,
    pub read_side_effect_free: bool,
    pub retry_safe_read: bool,
    pub requires_atomic_multi_structure_view: bool,
    pub requires_external_input_join: bool,
    pub write_profile: WriteProfile,
    pub tearing_risk: TearingRisk,
    pub exact_fallback_conditions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotBaselineComparatorRow {
    pub candidate_id: String,
    pub disposition: CandidateDisposition,
    pub baseline_path: String,
    pub baseline_strategy: BaselineStrategy,
    pub incumbent_baseline: String,
    pub proposed_strategy: String,
    pub expected_read_side_benefit: String,
    pub migration_risk: TearingRisk,
    pub exact_fallback_conditions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CandidateCounts {
    pub accept: usize,
    pub conditional: usize,
    pub reject: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeqlockCandidateInventoryArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub generated_at_utc: String,
    pub inventory_hash: String,
    pub counts: CandidateCounts,
    pub candidates: Vec<CandidateInventoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrySafetyMatrixArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub generated_at_utc: String,
    pub matrix_hash: String,
    pub rows: Vec<RetrySafetyMatrixRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotBaselineComparatorArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub generated_at_utc: String,
    pub comparator_hash: String,
    pub rows: Vec<SnapshotBaselineComparatorRow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackReason {
    UnsupportedCandidate,
    WriterActive,
    RetryBudgetExhausted,
    ExternalJoinBoundary,
    ImmutableValueObject,
    HotPathWritePressure,
    NonRetrySafeRead,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadResolution {
    Optimistic,
    IncumbentFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeqlockReaderWriterContractRow {
    pub candidate_id: String,
    pub disposition: CandidateDisposition,
    pub optimistic_reads_enabled: bool,
    pub writer_exclusive: bool,
    pub reader_retry_safe: bool,
    pub publication_boundary: String,
    pub fallback_target: String,
    pub telemetry_fields: Vec<String>,
    pub contract_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeqlockReaderWriterContractArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub predecessor_bead_id: String,
    pub component: String,
    pub generated_at_utc: String,
    pub contract_hash: String,
    pub rows: Vec<SeqlockReaderWriterContractRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryBudgetPolicyRow {
    pub candidate_id: String,
    pub disposition: CandidateDisposition,
    pub max_retries: u32,
    pub fallback_target: String,
    pub fallback_reason: FallbackReason,
    pub write_pressure_limit: WriteProfile,
    pub policy_rationale: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryBudgetPolicyArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub predecessor_bead_id: String,
    pub component: String,
    pub generated_at_utc: String,
    pub policy_hash: String,
    pub rows: Vec<RetryBudgetPolicyRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncumbentFallbackMatrixRow {
    pub candidate_id: String,
    pub disposition: CandidateDisposition,
    pub baseline_path: String,
    pub incumbent_baseline: String,
    pub immediate_fallback: bool,
    pub fallback_target: String,
    pub fallback_reason: FallbackReason,
    pub fallback_conditions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncumbentFallbackMatrixArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub predecessor_bead_id: String,
    pub component: String,
    pub generated_at_utc: String,
    pub matrix_hash: String,
    pub rows: Vec<IncumbentFallbackMatrixRow>,
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
    pub candidate_id: Option<String>,
    pub detail: String,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulatedSeqlock<T> {
    current_value: T,
    sequence: u64,
    writer_active: bool,
    fallback_reads: u64,
    write_pressure_violations: u64,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadInterference<T> {
    Stable,
    WriterActive,
    Publish(T),
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOutcome<T> {
    pub value: T,
    pub resolution: ReadResolution,
    pub retries: u32,
    pub fallback_reason: Option<FallbackReason>,
    pub write_pressure_violations: u64,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeqlockContractError {
    WriterAlreadyActive,
    WriterNotActive,
}

#[cfg(test)]
impl std::fmt::Display for SeqlockContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WriterAlreadyActive => f.write_str("writer already active"),
            Self::WriterNotActive => f.write_str("writer not active"),
        }
    }
}

#[cfg(test)]
impl std::error::Error for SeqlockContractError {}

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
            trace_id: "trace.rgc.621b".to_string(),
            decision_id: "decision.rgc.621b".to_string(),
            policy_id: "policy.rgc.621b".to_string(),
            generated_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            source_commit: "unknown".to_string(),
            toolchain: std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "nightly".to_string()),
            command_invocation: "cargo run -p frankenengine-engine --bin franken_seqlock_candidate_inventory -- --artifact-dir <path>".to_string(),
        }
    }
}

#[cfg(test)]
impl<T: Clone + Eq> SimulatedSeqlock<T> {
    pub fn new(value: T) -> Self {
        Self {
            current_value: value,
            sequence: 0,
            writer_active: false,
            fallback_reads: 0,
            write_pressure_violations: 0,
        }
    }

    pub fn begin_write(&mut self) -> Result<(), SeqlockContractError> {
        if self.writer_active {
            return Err(SeqlockContractError::WriterAlreadyActive);
        }
        self.writer_active = true;
        self.sequence = self.sequence.saturating_add(1);
        Ok(())
    }

    pub fn commit_write(&mut self, value: T) -> Result<(), SeqlockContractError> {
        if !self.writer_active {
            return Err(SeqlockContractError::WriterNotActive);
        }
        self.current_value = value;
        self.writer_active = false;
        self.sequence = self.sequence.saturating_add(1);
        Ok(())
    }

    pub fn read_with_interference(
        &mut self,
        policy: &RetryBudgetPolicyRow,
        plan: &[ReadInterference<T>],
    ) -> ReadOutcome<T> {
        if policy.max_retries == 0 || !matches!(policy.disposition, CandidateDisposition::Accept) {
            return self.fallback_outcome(policy.fallback_reason, 0);
        }

        let mut retries = 0u32;
        let mut violations = 0u64;
        for step in plan {
            let start_sequence = self.sequence;
            let observed = self.current_value.clone();
            match step {
                ReadInterference::Stable => {}
                ReadInterference::WriterActive => {
                    violations = violations.saturating_add(1);
                    if retries >= policy.max_retries {
                        self.write_pressure_violations =
                            self.write_pressure_violations.saturating_add(violations);
                        return self
                            .fallback_outcome(FallbackReason::RetryBudgetExhausted, retries);
                    }
                    retries = retries.saturating_add(1);
                    continue;
                }
                ReadInterference::Publish(next_value) => {
                    let _ = self.begin_write();
                    let _ = self.commit_write(next_value.clone());
                }
            }

            if start_sequence == self.sequence {
                self.write_pressure_violations =
                    self.write_pressure_violations.saturating_add(violations);
                return ReadOutcome {
                    value: observed,
                    resolution: ReadResolution::Optimistic,
                    retries,
                    fallback_reason: None,
                    write_pressure_violations: violations,
                };
            }

            if retries >= policy.max_retries {
                self.write_pressure_violations =
                    self.write_pressure_violations.saturating_add(violations);
                return self.fallback_outcome(FallbackReason::RetryBudgetExhausted, retries);
            }
            retries = retries.saturating_add(1);
        }

        self.write_pressure_violations = self.write_pressure_violations.saturating_add(violations);
        ReadOutcome {
            value: self.current_value.clone(),
            resolution: ReadResolution::Optimistic,
            retries,
            fallback_reason: None,
            write_pressure_violations: violations,
        }
    }

    pub fn fallback_reads(&self) -> u64 {
        self.fallback_reads
    }

    pub fn write_pressure_violations(&self) -> u64 {
        self.write_pressure_violations
    }

    fn fallback_outcome(&mut self, reason: FallbackReason, retries: u32) -> ReadOutcome<T> {
        self.fallback_reads = self.fallback_reads.saturating_add(1);
        ReadOutcome {
            value: self.current_value.clone(),
            resolution: ReadResolution::IncumbentFallback,
            retries,
            fallback_reason: Some(reason),
            write_pressure_violations: self.write_pressure_violations,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestArtifactReference {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleWriteReport {
    pub artifact_dir: PathBuf,
    pub inventory: SeqlockCandidateInventoryArtifact,
    pub retry_safety: RetrySafetyMatrixArtifact,
    pub baseline_comparator: SnapshotBaselineComparatorArtifact,
    pub reader_writer_contract: SeqlockReaderWriterContractArtifact,
    pub retry_budget_policy: RetryBudgetPolicyArtifact,
    pub incumbent_fallback_matrix: IncumbentFallbackMatrixArtifact,
    pub trace_ids_path: PathBuf,
    pub written_files: BTreeMap<String, String>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractFixture {
    pub schema_version: String,
    pub bead_id: String,
    pub required_artifacts: Vec<String>,
    pub candidate_expectations: Vec<ContractCandidateExpectation>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractCandidateExpectation {
    pub candidate_id: String,
    pub disposition: CandidateDisposition,
}

#[derive(Debug, Clone)]
struct EvaluatedArtifacts {
    inventory: SeqlockCandidateInventoryArtifact,
    retry_safety: RetrySafetyMatrixArtifact,
    baseline_comparator: SnapshotBaselineComparatorArtifact,
    reader_writer_contract: SeqlockReaderWriterContractArtifact,
    retry_budget_policy: RetryBudgetPolicyArtifact,
    incumbent_fallback_matrix: IncumbentFallbackMatrixArtifact,
    trace_ids: TraceIdsArtifact,
    logs: Vec<StructuredLogEvent>,
}

#[derive(Debug, Clone)]
struct FileArtifact {
    path: String,
    contents: Vec<u8>,
}

pub fn default_candidate_inventory(
    generated_at_utc: impl Into<String>,
) -> SeqlockCandidateInventoryArtifact {
    let generated_at_utc = generated_at_utc.into();
    let mut candidates = candidate_specs()
        .iter()
        .map(evaluate_candidate)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
    let counts = count_dispositions(&candidates);
    let inventory_hash = digest_json(&serde_json::json!({
        "counts": &counts,
        "candidates": &candidates,
    }));

    SeqlockCandidateInventoryArtifact {
        schema_version: INVENTORY_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc,
        inventory_hash,
        counts,
        candidates,
    }
}

#[cfg(test)]
pub fn build_contract_fixture() -> ContractFixture {
    let inventory = default_candidate_inventory("2026-03-06T00:00:00Z");
    let mut candidate_expectations = inventory
        .candidates
        .iter()
        .map(|candidate| ContractCandidateExpectation {
            candidate_id: candidate.candidate_id.clone(),
            disposition: candidate.disposition,
        })
        .collect::<Vec<_>>();
    candidate_expectations.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));

    ContractFixture {
        schema_version: CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        required_artifacts: required_artifact_names(),
        candidate_expectations,
    }
}

pub fn render_summary(inventory: &SeqlockCandidateInventoryArtifact) -> String {
    let accepted = inventory
        .candidates
        .iter()
        .filter(|candidate| candidate.disposition == CandidateDisposition::Accept)
        .map(|candidate| candidate.candidate_id.as_str())
        .collect::<Vec<_>>();
    let conditional = inventory
        .candidates
        .iter()
        .filter(|candidate| candidate.disposition == CandidateDisposition::Conditional)
        .map(|candidate| candidate.candidate_id.as_str())
        .collect::<Vec<_>>();
    let rejected = inventory
        .candidates
        .iter()
        .filter(|candidate| candidate.disposition == CandidateDisposition::Reject)
        .map(|candidate| candidate.candidate_id.as_str())
        .collect::<Vec<_>>();

    [
        "# Seqlock Candidate Inventory Summary".to_string(),
        String::new(),
        format!("- bead_id: `{}`", BEAD_ID),
        format!("- component: `{}`", COMPONENT),
        format!("- predecessor_bead_id: `{}`", PREDECESSOR_BEAD_ID),
        format!("- generated_at_utc: `{}`", inventory.generated_at_utc),
        format!("- accepted: `{}`", inventory.counts.accept),
        format!("- conditional: `{}`", inventory.counts.conditional),
        format!("- rejected: `{}`", inventory.counts.reject),
        format!("- inventory_hash: `{}`", inventory.inventory_hash),
        String::new(),
        "## Accepted".to_string(),
        accepted
            .iter()
            .map(|candidate| format!("- `{candidate}`"))
            .collect::<Vec<_>>()
            .join("\n"),
        String::new(),
        "## Conditional".to_string(),
        conditional
            .iter()
            .map(|candidate| format!("- `{candidate}`"))
            .collect::<Vec<_>>()
            .join("\n"),
        String::new(),
        "## Rejected".to_string(),
        rejected
            .iter()
            .map(|candidate| format!("- `{candidate}`"))
            .collect::<Vec<_>>()
            .join("\n"),
    ]
    .join("\n")
}

pub fn emit_default_inventory_bundle(context: &ArtifactContext) -> io::Result<BundleWriteReport> {
    let evaluated = evaluate_default_artifacts(context);
    write_bundle(context, &evaluated)
}

fn evaluate_default_artifacts(context: &ArtifactContext) -> EvaluatedArtifacts {
    let inventory = default_candidate_inventory(context.generated_at_utc.clone());
    let retry_rows = inventory
        .candidates
        .iter()
        .map(|candidate| RetrySafetyMatrixRow {
            candidate_id: candidate.candidate_id.clone(),
            disposition: candidate.disposition,
            read_side_effect_free: candidate.read_side_effect_free,
            retry_safe_read: candidate.retry_safe_read,
            requires_atomic_multi_structure_view: candidate.requires_atomic_multi_structure_view,
            requires_external_input_join: candidate.requires_external_input_join,
            write_profile: candidate.write_profile,
            tearing_risk: candidate.tearing_risk,
            exact_fallback_conditions: candidate.exact_fallback_conditions.clone(),
        })
        .collect::<Vec<_>>();
    let matrix_hash = digest_json(&serde_json::json!({ "rows": &retry_rows }));
    let retry_safety = RetrySafetyMatrixArtifact {
        schema_version: RETRY_SAFETY_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: context.generated_at_utc.clone(),
        matrix_hash,
        rows: retry_rows,
    };

    let comparator_rows = inventory
        .candidates
        .iter()
        .map(|candidate| SnapshotBaselineComparatorRow {
            candidate_id: candidate.candidate_id.clone(),
            disposition: candidate.disposition,
            baseline_path: candidate.baseline_path.clone(),
            baseline_strategy: candidate.baseline_strategy,
            incumbent_baseline: candidate.incumbent_baseline.clone(),
            proposed_strategy: "seqlock_optimistic_read".to_string(),
            expected_read_side_benefit: expected_benefit(candidate),
            migration_risk: candidate.tearing_risk,
            exact_fallback_conditions: candidate.exact_fallback_conditions.clone(),
        })
        .collect::<Vec<_>>();
    let comparator_hash = digest_json(&serde_json::json!({ "rows": &comparator_rows }));
    let baseline_comparator = SnapshotBaselineComparatorArtifact {
        schema_version: BASELINE_COMPARATOR_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: context.generated_at_utc.clone(),
        comparator_hash,
        rows: comparator_rows,
    };
    let reader_writer_contract = build_reader_writer_contract_artifact(context, &inventory);
    let retry_budget_policy = build_retry_budget_policy_artifact(context, &inventory);
    let incumbent_fallback_matrix =
        build_incumbent_fallback_matrix_artifact(context, &inventory, &retry_budget_policy);

    let trace_ids = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec![context.trace_id.clone()],
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
    };

    let mut logs = inventory
        .candidates
        .iter()
        .map(|candidate| StructuredLogEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: COMPONENT.to_string(),
            event: "candidate_evaluated".to_string(),
            outcome: match candidate.disposition {
                CandidateDisposition::Accept => "accept".to_string(),
                CandidateDisposition::Conditional => "conditional".to_string(),
                CandidateDisposition::Reject => "reject".to_string(),
            },
            error_code: None,
            candidate_id: Some(candidate.candidate_id.clone()),
            detail: candidate.classification_rationale.join("; "),
        })
        .collect::<Vec<_>>();
    logs.extend(
        reader_writer_contract
            .rows
            .iter()
            .map(|row| StructuredLogEvent {
                trace_id: context.trace_id.clone(),
                decision_id: context.decision_id.clone(),
                policy_id: context.policy_id.clone(),
                component: COMPONENT.to_string(),
                event: "reader_writer_contract_derived".to_string(),
                outcome: if row.optimistic_reads_enabled {
                    "optimistic_enabled".to_string()
                } else {
                    "fallback_only".to_string()
                },
                error_code: None,
                candidate_id: Some(row.candidate_id.clone()),
                detail: format!(
                    "writer_exclusive={} reader_retry_safe={} telemetry_fields={}",
                    row.writer_exclusive,
                    row.reader_retry_safe,
                    row.telemetry_fields.join(","),
                ),
            }),
    );
    logs.extend(
        retry_budget_policy
            .rows
            .iter()
            .map(|row| StructuredLogEvent {
                trace_id: context.trace_id.clone(),
                decision_id: context.decision_id.clone(),
                policy_id: context.policy_id.clone(),
                component: COMPONENT.to_string(),
                event: "retry_budget_policy_derived".to_string(),
                outcome: if row.max_retries > 0 {
                    "bounded_retry".to_string()
                } else {
                    "immediate_fallback".to_string()
                },
                error_code: None,
                candidate_id: Some(row.candidate_id.clone()),
                detail: format!(
                    "max_retries={} fallback_reason={} write_pressure_limit={}",
                    row.max_retries,
                    fallback_reason_label(row.fallback_reason),
                    write_profile_label(row.write_pressure_limit),
                ),
            }),
    );
    logs.extend(
        incumbent_fallback_matrix
            .rows
            .iter()
            .map(|row| StructuredLogEvent {
                trace_id: context.trace_id.clone(),
                decision_id: context.decision_id.clone(),
                policy_id: context.policy_id.clone(),
                component: COMPONENT.to_string(),
                event: "incumbent_fallback_matrix_derived".to_string(),
                outcome: if row.immediate_fallback {
                    "fallback_immediate".to_string()
                } else {
                    "fallback_after_retry_budget".to_string()
                },
                error_code: None,
                candidate_id: Some(row.candidate_id.clone()),
                detail: format!(
                    "fallback_target={} fallback_reason={} conditions={}",
                    row.fallback_target,
                    fallback_reason_label(row.fallback_reason),
                    row.fallback_conditions.join("; "),
                ),
            }),
    );
    logs.push(StructuredLogEvent {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: "inventory_summary".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        candidate_id: None,
        detail: format!(
            "accept={} conditional={} reject={}",
            inventory.counts.accept, inventory.counts.conditional, inventory.counts.reject
        ),
    });
    logs.push(StructuredLogEvent {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: "operator_telemetry_summary".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        candidate_id: None,
        detail: format!(
            "optimistic_candidates={} immediate_fallback_candidates={} max_retry_budget={} telemetry_fields=retry_count,fallback_count,write_pressure_violations,read_resolution,trace_id,run_id",
            reader_writer_contract
                .rows
                .iter()
                .filter(|row| row.optimistic_reads_enabled)
                .count(),
            incumbent_fallback_matrix
                .rows
                .iter()
                .filter(|row| row.immediate_fallback)
                .count(),
            retry_budget_policy
                .rows
                .iter()
                .map(|row| row.max_retries)
                .max()
                .unwrap_or(0),
        ),
    });
    logs.sort_by(|left, right| {
        left.event
            .cmp(&right.event)
            .then(left.candidate_id.cmp(&right.candidate_id))
            .then(left.trace_id.cmp(&right.trace_id))
    });

    EvaluatedArtifacts {
        inventory,
        retry_safety,
        baseline_comparator,
        reader_writer_contract,
        retry_budget_policy,
        incumbent_fallback_matrix,
        trace_ids,
        logs,
    }
}

fn build_reader_writer_contract_artifact(
    context: &ArtifactContext,
    inventory: &SeqlockCandidateInventoryArtifact,
) -> SeqlockReaderWriterContractArtifact {
    let mut rows = inventory
        .candidates
        .iter()
        .map(build_reader_writer_contract_row)
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
    let contract_hash = digest_json(&serde_json::json!({ "rows": &rows }));

    SeqlockReaderWriterContractArtifact {
        schema_version: READER_WRITER_CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: context.generated_at_utc.clone(),
        contract_hash,
        rows,
    }
}

fn build_retry_budget_policy_artifact(
    context: &ArtifactContext,
    inventory: &SeqlockCandidateInventoryArtifact,
) -> RetryBudgetPolicyArtifact {
    let mut rows = inventory
        .candidates
        .iter()
        .map(build_retry_budget_policy_row)
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
    let policy_hash = digest_json(&serde_json::json!({ "rows": &rows }));

    RetryBudgetPolicyArtifact {
        schema_version: RETRY_BUDGET_POLICY_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: context.generated_at_utc.clone(),
        policy_hash,
        rows,
    }
}

fn build_incumbent_fallback_matrix_artifact(
    context: &ArtifactContext,
    inventory: &SeqlockCandidateInventoryArtifact,
    retry_budget_policy: &RetryBudgetPolicyArtifact,
) -> IncumbentFallbackMatrixArtifact {
    let policy_by_candidate = retry_budget_policy
        .rows
        .iter()
        .map(|row| (row.candidate_id.as_str(), row))
        .collect::<BTreeMap<_, _>>();
    let mut rows = inventory
        .candidates
        .iter()
        .map(|candidate| {
            let policy = policy_by_candidate
                .get(candidate.candidate_id.as_str())
                .expect("retry budget policy row must exist for every inventory candidate");
            build_incumbent_fallback_matrix_row(candidate, policy)
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
    let matrix_hash = digest_json(&serde_json::json!({ "rows": &rows }));

    IncumbentFallbackMatrixArtifact {
        schema_version: INCUMBENT_FALLBACK_MATRIX_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: context.generated_at_utc.clone(),
        matrix_hash,
        rows,
    }
}

fn build_reader_writer_contract_row(
    candidate: &CandidateInventoryEntry,
) -> SeqlockReaderWriterContractRow {
    let optimistic_reads_enabled = candidate.disposition == CandidateDisposition::Accept;
    let mut contract_notes = candidate.classification_rationale.clone();
    contract_notes.extend(candidate.notes.clone());
    if optimistic_reads_enabled {
        contract_notes.push(
            "require a single exclusive writer to publish the full snapshot boundary".to_string(),
        );
        contract_notes.push(format!(
            "fallback remains `{}` if retries exceed the budget or write pressure becomes hostile",
            candidate.incumbent_baseline
        ));
    } else {
        contract_notes.push(format!(
            "optimistic readers stay disabled and `{}` remains authoritative",
            candidate.incumbent_baseline
        ));
    }

    SeqlockReaderWriterContractRow {
        candidate_id: candidate.candidate_id.clone(),
        disposition: candidate.disposition,
        optimistic_reads_enabled,
        writer_exclusive: optimistic_reads_enabled,
        reader_retry_safe: candidate.read_side_effect_free && candidate.retry_safe_read,
        publication_boundary: publication_boundary(candidate),
        fallback_target: candidate.incumbent_baseline.clone(),
        telemetry_fields: vec![
            "retry_count".to_string(),
            "fallback_count".to_string(),
            "write_pressure_violations".to_string(),
            "read_resolution".to_string(),
            "trace_id".to_string(),
            "run_id".to_string(),
        ],
        contract_notes,
    }
}

fn build_retry_budget_policy_row(candidate: &CandidateInventoryEntry) -> RetryBudgetPolicyRow {
    let max_retries = retry_budget_for(candidate);
    let fallback_reason = fallback_reason_for(candidate);
    let mut policy_rationale = candidate.classification_rationale.clone();
    match candidate.disposition {
        CandidateDisposition::Accept => policy_rationale.push(format!(
            "allow up to {max_retries} optimistic retries before falling back to `{}`",
            candidate.incumbent_baseline
        )),
        CandidateDisposition::Conditional => policy_rationale.push(format!(
            "set retry budget to zero until `{}` is promoted behind one versioned publication boundary",
            candidate.surface_name
        )),
        CandidateDisposition::Reject => policy_rationale.push(format!(
            "set retry budget to zero because `{}` should keep the incumbent path",
            candidate.surface_name
        )),
    }
    policy_rationale.push(format!(
        "treat `{}` write pressure as the retry ceiling for this surface",
        write_profile_label(candidate.write_profile)
    ));

    RetryBudgetPolicyRow {
        candidate_id: candidate.candidate_id.clone(),
        disposition: candidate.disposition,
        max_retries,
        fallback_target: candidate.incumbent_baseline.clone(),
        fallback_reason,
        write_pressure_limit: candidate.write_profile,
        policy_rationale,
    }
}

fn build_incumbent_fallback_matrix_row(
    candidate: &CandidateInventoryEntry,
    policy: &RetryBudgetPolicyRow,
) -> IncumbentFallbackMatrixRow {
    let mut fallback_conditions = candidate.exact_fallback_conditions.clone();
    if policy.max_retries > 0 {
        fallback_conditions.push(format!(
            "fallback after {} retries if the single writer keeps the publication boundary unstable",
            policy.max_retries
        ));
    } else {
        fallback_conditions.push(format!(
            "fallback immediately because the retry budget is zero and `{}` stays authoritative",
            candidate.incumbent_baseline
        ));
    }

    IncumbentFallbackMatrixRow {
        candidate_id: candidate.candidate_id.clone(),
        disposition: candidate.disposition,
        baseline_path: candidate.baseline_path.clone(),
        incumbent_baseline: candidate.incumbent_baseline.clone(),
        immediate_fallback: policy.max_retries == 0,
        fallback_target: candidate.incumbent_baseline.clone(),
        fallback_reason: policy.fallback_reason,
        fallback_conditions,
    }
}

fn retry_budget_for(candidate: &CandidateInventoryEntry) -> u32 {
    if candidate.disposition != CandidateDisposition::Accept {
        return 0;
    }

    match candidate.write_profile {
        WriteProfile::Rare => 3,
        WriteProfile::Moderate => 2,
        WriteProfile::Bursty => 1,
        WriteProfile::HotPath => 0,
    }
}

fn fallback_reason_for(candidate: &CandidateInventoryEntry) -> FallbackReason {
    if candidate.disposition == CandidateDisposition::Accept {
        return FallbackReason::RetryBudgetExhausted;
    }

    if candidate.requires_external_input_join {
        return FallbackReason::ExternalJoinBoundary;
    }

    if candidate.immutable_value_object {
        return FallbackReason::ImmutableValueObject;
    }

    if !candidate.read_side_effect_free || !candidate.retry_safe_read {
        return FallbackReason::NonRetrySafeRead;
    }

    if candidate.write_profile == WriteProfile::HotPath {
        return FallbackReason::HotPathWritePressure;
    }

    FallbackReason::UnsupportedCandidate
}

fn publication_boundary(candidate: &CandidateInventoryEntry) -> String {
    if candidate.immutable_value_object {
        return "immutable value publication via pointer or ownership handoff".to_string();
    }

    if candidate.requires_external_input_join {
        return "versioned publication must span the local snapshot and its external signal join"
            .to_string();
    }

    if candidate.requires_atomic_multi_structure_view {
        return "single writer sequence gate over the full multi-structure snapshot".to_string();
    }

    "single writer sequence gate over one snapshot publication boundary".to_string()
}

fn fallback_reason_label(reason: FallbackReason) -> &'static str {
    match reason {
        FallbackReason::UnsupportedCandidate => "unsupported_candidate",
        FallbackReason::WriterActive => "writer_active",
        FallbackReason::RetryBudgetExhausted => "retry_budget_exhausted",
        FallbackReason::ExternalJoinBoundary => "external_join_boundary",
        FallbackReason::ImmutableValueObject => "immutable_value_object",
        FallbackReason::HotPathWritePressure => "hot_path_write_pressure",
        FallbackReason::NonRetrySafeRead => "non_retry_safe_read",
    }
}

fn write_profile_label(profile: WriteProfile) -> &'static str {
    match profile {
        WriteProfile::Rare => "rare",
        WriteProfile::Moderate => "moderate",
        WriteProfile::Bursty => "bursty",
        WriteProfile::HotPath => "hot_path",
    }
}

fn write_bundle(
    context: &ArtifactContext,
    evaluated: &EvaluatedArtifacts,
) -> io::Result<BundleWriteReport> {
    fs::create_dir_all(&context.artifact_dir)?;

    let summary_md = render_summary(&evaluated.inventory);
    let artifact_dir_display = context.artifact_dir.display().to_string();
    let commands = vec![
        context.command_invocation.clone(),
        format!(
            "jq '.counts' {}/seqlock_candidate_inventory.json",
            artifact_dir_display
        ),
        format!(
            "jq '.rows[] | {{candidate_id,max_retries,fallback_reason}}' {}/retry_budget_policy.json",
            artifact_dir_display
        ),
        format!(
            "jq '.rows[] | {{candidate_id,optimistic_reads_enabled,writer_exclusive}}' {}/seqlock_reader_writer_contract.json",
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
        FileArtifact::json("seqlock_candidate_inventory.json", &evaluated.inventory),
        FileArtifact::json("retry_safety_matrix.json", &evaluated.retry_safety),
        FileArtifact::json(
            "snapshot_baseline_comparator.json",
            &evaluated.baseline_comparator,
        ),
        FileArtifact::json(
            "seqlock_reader_writer_contract.json",
            &evaluated.reader_writer_contract,
        ),
        FileArtifact::json("retry_budget_policy.json", &evaluated.retry_budget_policy),
        FileArtifact::json(
            "incumbent_fallback_matrix.json",
            &evaluated.incumbent_fallback_matrix,
        ),
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
                "candidate_count": evaluated.inventory.candidates.len(),
                "counts": &evaluated.inventory.counts,
                "inventory_hash": &evaluated.inventory.inventory_hash,
                "retry_safety_hash": &evaluated.retry_safety.matrix_hash,
                "baseline_comparator_hash": &evaluated.baseline_comparator.comparator_hash,
                "reader_writer_contract_hash": &evaluated.reader_writer_contract.contract_hash,
                "retry_budget_policy_hash": &evaluated.retry_budget_policy.policy_hash,
                "incumbent_fallback_matrix_hash": &evaluated.incumbent_fallback_matrix.matrix_hash,
                "artifacts": required_artifact_names(),
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
        .map(|artifact| ManifestArtifactReference {
            path: artifact.path.clone(),
            sha256: format!("sha256:{}", sha256_hex(&artifact.contents)),
        })
        .collect::<Vec<_>>();

    let manifest_json = serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": "franken-engine.manifest.v1",
        "manifest_id": format!("{}-{}", COMPONENT, context.run_id),
        "generated_at_utc": &context.generated_at_utc,
        "claim": {
            "claim_id": BEAD_ID,
            "class": "reader_writer_contract",
            "statement": "Deterministic seqlock reader/writer contracts, retry budgets, and incumbent fallback rules for candidate snapshot surfaces.",
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
            "evidence_pointer": format!("file://{artifact_dir_display}/seqlock_reader_writer_contract.json"),
        },
        "artifacts": &manifest_artifacts,
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
        inventory: evaluated.inventory.clone(),
        retry_safety: evaluated.retry_safety.clone(),
        baseline_comparator: evaluated.baseline_comparator.clone(),
        reader_writer_contract: evaluated.reader_writer_contract.clone(),
        retry_budget_policy: evaluated.retry_budget_policy.clone(),
        incumbent_fallback_matrix: evaluated.incumbent_fallback_matrix.clone(),
        trace_ids_path: context.artifact_dir.join("trace_ids.json"),
        written_files,
    })
}

fn evaluate_candidate(spec: &CandidateSpec) -> CandidateInventoryEntry {
    let (disposition, mut rationale) = classify_candidate(spec);
    if disposition == CandidateDisposition::Conditional && spec.requires_external_input_join {
        rationale.push(
            "conditional until the external signal join is versioned under the same retry boundary"
                .to_string(),
        );
    }
    if disposition == CandidateDisposition::Conditional
        && spec.requires_atomic_multi_structure_view
        && !spec.retry_safe_read
    {
        rationale.push(
            "conditional until all participating structures publish behind a single sequence gate"
                .to_string(),
        );
    }

    CandidateInventoryEntry {
        candidate_id: spec.candidate_id.to_string(),
        surface_name: spec.surface_name.to_string(),
        module_path: spec.module_path.to_string(),
        api_path: spec.api_path.to_string(),
        surface_area: spec.surface_area,
        baseline_path: spec.baseline_path.to_string(),
        incumbent_baseline: spec.incumbent_baseline.to_string(),
        baseline_strategy: spec.baseline_strategy,
        disposition,
        shared_mutable_state: spec.shared_mutable_state,
        read_side_effect_free: spec.read_side_effect_free,
        retry_safe_read: spec.retry_safe_read,
        requires_atomic_multi_structure_view: spec.requires_atomic_multi_structure_view,
        requires_external_input_join: spec.requires_external_input_join,
        immutable_value_object: spec.immutable_value_object,
        write_profile: spec.write_profile,
        tearing_risk: spec.tearing_risk,
        classification_rationale: rationale,
        exact_fallback_conditions: spec
            .exact_fallback_conditions
            .iter()
            .map(|condition| condition.to_string())
            .collect(),
        notes: spec.notes.iter().map(|note| note.to_string()).collect(),
    }
}

fn classify_candidate(spec: &CandidateSpec) -> (CandidateDisposition, Vec<String>) {
    let mut rationale = Vec::new();

    if spec.immutable_value_object {
        rationale.push(
            "reject because the current surface is already an immutable value object; use pointer swap or Arc promotion instead of a seqlock".to_string(),
        );
        return (CandidateDisposition::Reject, rationale);
    }

    if !spec.shared_mutable_state {
        rationale.push(
            "reject because there is no shared mutable state boundary for optimistic readers to protect".to_string(),
        );
        return (CandidateDisposition::Reject, rationale);
    }

    if !spec.read_side_effect_free {
        rationale.push(
            "reject because the read API mutates internal state, so retries would change semantics"
                .to_string(),
        );
        return (CandidateDisposition::Reject, rationale);
    }

    if spec.write_profile == WriteProfile::HotPath {
        rationale.push(
            "reject because writes happen on the hot path and optimistic readers would spin under steady contention".to_string(),
        );
        return (CandidateDisposition::Reject, rationale);
    }

    if spec.requires_external_input_join {
        rationale.push(
            "conditional because the snapshot depends on an external join that is not yet published under one versioned boundary".to_string(),
        );
        return (CandidateDisposition::Conditional, rationale);
    }

    if !spec.retry_safe_read {
        rationale.push(
            "conditional because the current read path cannot retry without additional version fencing".to_string(),
        );
        return (CandidateDisposition::Conditional, rationale);
    }

    rationale.push(
        "accept because reads are side-effect free, retry-safe, and the incumbent baseline is a snapshot clone/query path that can benefit from optimistic reads".to_string(),
    );

    if spec.requires_atomic_multi_structure_view {
        rationale.push(
            "accept only while the seqlock protects the whole multi-structure publication boundary rather than one field at a time".to_string(),
        );
    }

    (CandidateDisposition::Accept, rationale)
}

fn count_dispositions(candidates: &[CandidateInventoryEntry]) -> CandidateCounts {
    let mut counts = CandidateCounts::default();
    for candidate in candidates {
        match candidate.disposition {
            CandidateDisposition::Accept => counts.accept += 1,
            CandidateDisposition::Conditional => counts.conditional += 1,
            CandidateDisposition::Reject => counts.reject += 1,
        }
    }
    counts
}

fn expected_benefit(candidate: &CandidateInventoryEntry) -> String {
    match candidate.disposition {
        CandidateDisposition::Accept if candidate.write_profile == WriteProfile::Rare => {
            "high".to_string()
        }
        CandidateDisposition::Accept => "medium".to_string(),
        CandidateDisposition::Conditional => "bounded-after-fencing".to_string(),
        CandidateDisposition::Reject => "negative".to_string(),
    }
}

fn required_artifact_names() -> Vec<String> {
    vec![
        "commands.txt".to_string(),
        "env.json".to_string(),
        "events.jsonl".to_string(),
        "incumbent_fallback_matrix.json".to_string(),
        "manifest.json".to_string(),
        "repro.lock".to_string(),
        "retry_budget_policy.json".to_string(),
        "retry_safety_matrix.json".to_string(),
        "run_manifest.json".to_string(),
        "seqlock_candidate_inventory.json".to_string(),
        "seqlock_reader_writer_contract.json".to_string(),
        "snapshot_baseline_comparator.json".to_string(),
        "summary.md".to_string(),
        "trace_ids.json".to_string(),
    ]
}

fn acquire_bundle_write_lock(artifact_dir: &Path) -> io::Result<BundleWriteLock> {
    let lock_path = artifact_dir.join(".seqlock_candidate_inventory.lock");
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(_) => Ok(BundleWriteLock { path: lock_path }),
        Err(source) if source.kind() == ErrorKind::AlreadyExists => Err(io::Error::new(
            ErrorKind::AlreadyExists,
            format!("bundle already being written: {}", lock_path.display()),
        )),
        Err(source) => Err(io::Error::new(
            source.kind(),
            format!(
                "failed to acquire bundle write lock {}: {source}",
                lock_path.display()
            ),
        )),
    }
}

fn remove_commit_marker(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(source),
    }
}

fn write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp_path = unique_temp_path(path);
    fs::write(&temp_path, contents)?;
    if let Err(source) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(source);
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

#[derive(Debug)]
struct BundleWriteLock {
    path: PathBuf,
}

impl Drop for BundleWriteLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn digest_json(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).expect("digest input must serialize");
    sha256_hex(&bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

impl FileArtifact {
    fn json<T: Serialize>(path: &str, value: &T) -> Self {
        Self {
            path: path.to_string(),
            contents: serde_json::to_vec_pretty(value).expect("json artifact must serialize"),
        }
    }

    fn jsonl<T: Serialize>(path: &str, records: &[T]) -> Self {
        let mut contents = Vec::new();
        for record in records {
            let mut line = serde_json::to_vec(record).expect("jsonl record must serialize");
            line.push(b'\n');
            contents.extend_from_slice(&line);
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

fn candidate_specs() -> &'static [CandidateSpec] {
    &[
        CandidateSpec {
            candidate_id: "bulkhead-registry-snapshot",
            surface_name: "Bulkhead pressure snapshot",
            module_path: "crates/franken-engine/src/bulkhead.rs",
            api_path: "frankenengine_engine::bulkhead::BulkheadRegistry::snapshot",
            surface_area: SurfaceArea::RuntimeMetadata,
            baseline_path: "clone BTreeMap<String, BulkheadSnapshot> from BulkheadRegistry",
            incumbent_baseline: "stable BTree snapshot under the registry owner",
            baseline_strategy: BaselineStrategy::CloneSnapshot,
            shared_mutable_state: true,
            read_side_effect_free: true,
            retry_safe_read: true,
            requires_atomic_multi_structure_view: true,
            requires_external_input_join: false,
            immutable_value_object: false,
            write_profile: WriteProfile::HotPath,
            tearing_risk: TearingRisk::High,
            exact_fallback_conditions: &[
                "fallback if permit acquisition and queue transitions continue to mutate the state on every hot-path request",
                "fallback if optimistic readers can starve the pressure-control feedback loop under sustained contention",
            ],
            notes: &["High write pressure makes seqlock retries the wrong tradeoff here."],
        },
        CandidateSpec {
            candidate_id: "governance-ledger-head-view",
            surface_name: "Governance ledger head and checkpoint view",
            module_path: "crates/franken-engine/src/portfolio_governor/governance_audit_ledger.rs",
            api_path: "frankenengine_engine::portfolio_governor::governance_audit_ledger::GovernanceLedger::{query,latest_checkpoint}",
            surface_area: SurfaceArea::GovernanceState,
            baseline_path: "query append-only governance entries and checkpoint vector under the ledger owner",
            incumbent_baseline: "append-only Vec query plus latest checkpoint read",
            baseline_strategy: BaselineStrategy::QueryAppendOnly,
            shared_mutable_state: true,
            read_side_effect_free: true,
            retry_safe_read: true,
            requires_atomic_multi_structure_view: true,
            requires_external_input_join: false,
            immutable_value_object: false,
            write_profile: WriteProfile::Rare,
            tearing_risk: TearingRisk::Low,
            exact_fallback_conditions: &[
                "fallback if entry append and checkpoint publication become independently visible to readers",
                "fallback if query semantics grow cursor side effects or mutable pagination state",
            ],
            notes: &[
                "Append-only governance paths are classic read-mostly candidates when the publication boundary is explicit.",
            ],
        },
        CandidateSpec {
            candidate_id: "guardplane-calibration-snapshot",
            surface_name: "Guardplane calibration snapshot",
            module_path: "crates/franken-engine/src/adversarial_campaign.rs",
            api_path: "frankenengine_engine::adversarial_campaign::GuardplaneCalibrationState::snapshot",
            surface_area: SurfaceArea::PolicyState,
            baseline_path: "clone threshold/weight/loss maps from GuardplaneCalibrationState",
            incumbent_baseline: "deterministic clone of calibration maps",
            baseline_strategy: BaselineStrategy::CloneSnapshot,
            shared_mutable_state: true,
            read_side_effect_free: true,
            retry_safe_read: true,
            requires_atomic_multi_structure_view: true,
            requires_external_input_join: false,
            immutable_value_object: false,
            write_profile: WriteProfile::Rare,
            tearing_risk: TearingRisk::Medium,
            exact_fallback_conditions: &[
                "fallback if threshold and map updates stop publishing behind one calibration epoch",
                "fallback if readers require signed promotion metadata not covered by the optimistic read boundary",
            ],
            notes: &[
                "Low write frequency and explicit epoch semantics make this a strong candidate.",
            ],
        },
        CandidateSpec {
            candidate_id: "hostcall-telemetry-snapshot",
            surface_name: "Hostcall telemetry snapshot",
            module_path: "crates/franken-engine/src/hostcall_telemetry.rs",
            api_path: "frankenengine_engine::hostcall_telemetry::HostcallTelemetryRecorder::snapshot",
            surface_area: SurfaceArea::Telemetry,
            baseline_path: "mutating snapshot() call that also appends to the recorder snapshot history",
            incumbent_baseline: "stateful mutable snapshot API",
            baseline_strategy: BaselineStrategy::MutableSnapshotSideEffect,
            shared_mutable_state: true,
            read_side_effect_free: false,
            retry_safe_read: false,
            requires_atomic_multi_structure_view: true,
            requires_external_input_join: false,
            immutable_value_object: false,
            write_profile: WriteProfile::Bursty,
            tearing_risk: TearingRisk::High,
            exact_fallback_conditions: &[
                "fallback until taking a snapshot stops mutating the recorder and stops appending to internal snapshot history",
                "fallback while telemetry capture remains both the observation surface and the mutation log",
            ],
            notes: &["A mutating read API is a hard reject for seqlock adoption."],
        },
        CandidateSpec {
            candidate_id: "module-cache-snapshot",
            surface_name: "Module cache version and revocation snapshot",
            module_path: "crates/franken-engine/src/module_cache.rs",
            api_path: "frankenengine_engine::module_cache::ModuleCache::snapshot",
            surface_area: SurfaceArea::RuntimeMetadata,
            baseline_path: "clone CacheSnapshot from entries/latest_versions/revoked_modules",
            incumbent_baseline: "full snapshot clone from owner-thread cache state",
            baseline_strategy: BaselineStrategy::CloneSnapshot,
            shared_mutable_state: true,
            read_side_effect_free: true,
            retry_safe_read: true,
            requires_atomic_multi_structure_view: true,
            requires_external_input_join: false,
            immutable_value_object: false,
            write_profile: WriteProfile::Moderate,
            tearing_risk: TearingRisk::Medium,
            exact_fallback_conditions: &[
                "fallback if entries, latest_versions, and revoked_modules stop publishing behind one generation boundary",
                "fallback if merge_snapshot or revocation repair introduces read-path side effects",
            ],
            notes: &["This is the clearest runtime metadata candidate in the current tree."],
        },
        CandidateSpec {
            candidate_id: "policy-checkpoint-value",
            surface_name: "Policy checkpoint value object",
            module_path: "crates/franken-engine/src/policy_checkpoint.rs",
            api_path: "frankenengine_engine::policy_checkpoint::PolicyCheckpoint",
            surface_area: SurfaceArea::PolicyState,
            baseline_path: "publish immutable PolicyCheckpoint values by ID or Arc pointer",
            incumbent_baseline: "immutable checkpoint objects",
            baseline_strategy: BaselineStrategy::ImmutableValueObject,
            shared_mutable_state: false,
            read_side_effect_free: true,
            retry_safe_read: true,
            requires_atomic_multi_structure_view: false,
            requires_external_input_join: false,
            immutable_value_object: true,
            write_profile: WriteProfile::Rare,
            tearing_risk: TearingRisk::None,
            exact_fallback_conditions: &[
                "fallback permanently unless the surface stops being an immutable value object",
            ],
            notes: &[
                "This is included to make the rejection boundary explicit rather than implicit.",
            ],
        },
        CandidateSpec {
            candidate_id: "privacy-randomness-snapshot-chain",
            surface_name: "Privacy/randomness snapshot summary chain",
            module_path: "crates/franken-engine/src/privacy_learning_contract.rs",
            api_path: "frankenengine_engine::privacy_learning_contract::RandomnessSnapshotSummary chain",
            surface_area: SurfaceArea::PolicyState,
            baseline_path: "append-only snapshot summary chain plus signature verification pass",
            incumbent_baseline: "chain verification over immutable summaries",
            baseline_strategy: BaselineStrategy::QueryAppendOnly,
            shared_mutable_state: true,
            read_side_effect_free: true,
            retry_safe_read: false,
            requires_atomic_multi_structure_view: true,
            requires_external_input_join: false,
            immutable_value_object: false,
            write_profile: WriteProfile::Rare,
            tearing_risk: TearingRisk::High,
            exact_fallback_conditions: &[
                "fallback until the summary chain, previous root, and signature material publish behind one versioned head",
                "fallback while chain verification requires a whole-ledger fixed point rather than a retryable point read",
            ],
            notes: &[
                "Potentially attractive, but only after the chain head becomes a first-class versioned publication boundary.",
            ],
        },
        CandidateSpec {
            candidate_id: "slot-registry-replacement-progress",
            surface_name: "Slot replacement progress snapshot",
            module_path: "crates/franken-engine/src/slot_registry.rs",
            api_path: "frankenengine_engine::slot_registry::SlotRegistry::snapshot_replacement_progress",
            surface_area: SurfaceArea::OperatorProjection,
            baseline_path: "recompute ReplacementProgressSnapshot from SlotRegistry plus external signals map",
            incumbent_baseline: "deterministic projection joined with caller-owned signals",
            baseline_strategy: BaselineStrategy::ExternalJoinProjection,
            shared_mutable_state: true,
            read_side_effect_free: true,
            retry_safe_read: true,
            requires_atomic_multi_structure_view: true,
            requires_external_input_join: true,
            immutable_value_object: false,
            write_profile: WriteProfile::Moderate,
            tearing_risk: TearingRisk::Medium,
            exact_fallback_conditions: &[
                "fallback until slot state and replacement signals share one versioned publication boundary",
                "fallback if the ranking depends on external signal stores that can change independently mid-retry",
            ],
            notes: &["A good conditional candidate once the external signal join is fenced."],
        },
        CandidateSpec {
            candidate_id: "static-analysis-summary",
            surface_name: "Static analysis summary snapshot",
            module_path: "crates/franken-engine/src/static_analysis_graph.rs",
            api_path: "frankenengine_engine::static_analysis_graph::StaticAnalysisGraph::summary",
            surface_area: SurfaceArea::OfflineArtifact,
            baseline_path: "recompute AnalysisSummary from batch analysis graph",
            incumbent_baseline: "offline deterministic analysis pass",
            baseline_strategy: BaselineStrategy::OfflineSummary,
            shared_mutable_state: false,
            read_side_effect_free: true,
            retry_safe_read: true,
            requires_atomic_multi_structure_view: false,
            requires_external_input_join: false,
            immutable_value_object: false,
            write_profile: WriteProfile::Rare,
            tearing_risk: TearingRisk::Low,
            exact_fallback_conditions: &[
                "fallback because this is not a live shared-state surface; keep the batch summary path",
            ],
            notes: &["The right answer is explicitly 'do nothing'."],
        },
    ]
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
            "franken-engine-seqlock-src-test-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn default_inventory_counts_are_stable() {
        let inventory = default_candidate_inventory("2026-03-06T00:00:00Z");
        assert_eq!(inventory.counts.accept, 3);
        assert_eq!(inventory.counts.conditional, 2);
        assert_eq!(inventory.counts.reject, 4);
        assert_eq!(inventory.candidates.len(), 9);
    }

    #[test]
    fn mutating_snapshot_api_is_rejected() {
        let inventory = default_candidate_inventory("2026-03-06T00:00:00Z");
        let candidate = inventory
            .candidates
            .iter()
            .find(|candidate| candidate.candidate_id == "hostcall-telemetry-snapshot")
            .expect("candidate present");
        assert_eq!(candidate.disposition, CandidateDisposition::Reject);
        assert!(
            candidate
                .classification_rationale
                .iter()
                .any(|line| line.contains("mutates internal state")),
            "expected mutating-read rationale",
        );
    }

    #[test]
    fn external_join_candidate_is_conditional() {
        let inventory = default_candidate_inventory("2026-03-06T00:00:00Z");
        let candidate = inventory
            .candidates
            .iter()
            .find(|candidate| candidate.candidate_id == "slot-registry-replacement-progress")
            .expect("candidate present");
        assert_eq!(candidate.disposition, CandidateDisposition::Conditional);
        assert!(candidate.requires_external_input_join);
    }

    #[test]
    fn immutable_value_object_is_rejected() {
        let inventory = default_candidate_inventory("2026-03-06T00:00:00Z");
        let candidate = inventory
            .candidates
            .iter()
            .find(|candidate| candidate.candidate_id == "policy-checkpoint-value")
            .expect("candidate present");
        assert_eq!(candidate.disposition, CandidateDisposition::Reject);
        assert!(candidate.immutable_value_object);
    }

    #[test]
    fn contract_fixture_tracks_default_inventory() {
        let fixture = build_contract_fixture();
        assert_eq!(fixture.schema_version, CONTRACT_SCHEMA_VERSION);
        assert_eq!(fixture.bead_id, BEAD_ID);
        assert!(
            fixture
                .required_artifacts
                .iter()
                .any(|artifact| artifact == "manifest.json")
        );
        assert_eq!(fixture.candidate_expectations.len(), 9);
    }

    #[test]
    fn evaluated_artifacts_include_reader_writer_bundle_rows() {
        let artifact_dir = temp_dir("evaluated");
        let mut context = ArtifactContext::new(&artifact_dir);
        context.generated_at_utc = "2026-03-06T00:00:00Z".to_string();
        let evaluated = evaluate_default_artifacts(&context);

        assert_eq!(evaluated.reader_writer_contract.rows.len(), 9);
        assert_eq!(evaluated.retry_budget_policy.rows.len(), 9);
        assert_eq!(evaluated.incumbent_fallback_matrix.rows.len(), 9);

        let module_cache_contract = evaluated
            .reader_writer_contract
            .rows
            .iter()
            .find(|row| row.candidate_id == "module-cache-snapshot")
            .expect("module-cache contract row");
        assert!(module_cache_contract.optimistic_reads_enabled);
        assert!(module_cache_contract.writer_exclusive);
        assert!(module_cache_contract.reader_retry_safe);
        assert!(
            module_cache_contract
                .telemetry_fields
                .iter()
                .any(|field| field == "write_pressure_violations")
        );

        let slot_registry_policy = evaluated
            .retry_budget_policy
            .rows
            .iter()
            .find(|row| row.candidate_id == "slot-registry-replacement-progress")
            .expect("slot-registry policy row");
        assert_eq!(slot_registry_policy.max_retries, 0);
        assert_eq!(
            slot_registry_policy.fallback_reason,
            FallbackReason::ExternalJoinBoundary
        );

        let slot_registry_fallback = evaluated
            .incumbent_fallback_matrix
            .rows
            .iter()
            .find(|row| row.candidate_id == "slot-registry-replacement-progress")
            .expect("slot-registry fallback row");
        assert!(slot_registry_fallback.immediate_fallback);
        assert_eq!(
            slot_registry_fallback.fallback_reason,
            FallbackReason::ExternalJoinBoundary
        );

        let _ = fs::remove_dir_all(&artifact_dir);
    }

    fn accepted_policy(max_retries: u32) -> RetryBudgetPolicyRow {
        RetryBudgetPolicyRow {
            candidate_id: "module-cache-snapshot".to_string(),
            disposition: CandidateDisposition::Accept,
            max_retries,
            fallback_target: "full snapshot clone from owner-thread cache state".to_string(),
            fallback_reason: FallbackReason::RetryBudgetExhausted,
            write_pressure_limit: WriteProfile::Moderate,
            policy_rationale: vec!["test policy".to_string()],
        }
    }

    #[test]
    fn simulated_seqlock_enforces_writer_exclusivity() {
        let mut seqlock = SimulatedSeqlock::new("v1");
        seqlock.begin_write().expect("first writer should acquire");
        assert_eq!(
            seqlock.begin_write(),
            Err(SeqlockContractError::WriterAlreadyActive)
        );
        seqlock
            .commit_write("v2")
            .expect("active writer should be able to publish");
        assert_eq!(
            seqlock.commit_write("v3"),
            Err(SeqlockContractError::WriterNotActive)
        );
    }

    #[test]
    fn simulated_seqlock_read_plan_is_deterministic() {
        let policy = accepted_policy(3);
        let plan = [
            ReadInterference::WriterActive,
            ReadInterference::Publish("v2"),
            ReadInterference::Stable,
        ];

        let mut left = SimulatedSeqlock::new("v1");
        let mut right = SimulatedSeqlock::new("v1");
        let left_outcome = left.read_with_interference(&policy, &plan);
        let right_outcome = right.read_with_interference(&policy, &plan);

        assert_eq!(left_outcome, right_outcome);
        assert_eq!(left_outcome.value, "v2");
        assert_eq!(left_outcome.resolution, ReadResolution::Optimistic);
        assert_eq!(left_outcome.retries, 2);
    }

    #[test]
    fn simulated_seqlock_falls_back_after_retry_budget_is_exhausted() {
        let policy = accepted_policy(1);
        let plan = [
            ReadInterference::WriterActive,
            ReadInterference::WriterActive,
        ];
        let mut seqlock = SimulatedSeqlock::new("v1");

        let outcome = seqlock.read_with_interference(&policy, &plan);

        assert_eq!(outcome.resolution, ReadResolution::IncumbentFallback);
        assert_eq!(
            outcome.fallback_reason,
            Some(FallbackReason::RetryBudgetExhausted)
        );
        assert_eq!(outcome.retries, 1);
        assert_eq!(seqlock.fallback_reads(), 1);
        assert_eq!(seqlock.write_pressure_violations(), 2);
    }

    #[test]
    fn simulated_seqlock_successful_retry_returns_latest_committed_value() {
        let policy = accepted_policy(3);
        let plan = [ReadInterference::Publish("v2"), ReadInterference::Stable];
        let mut seqlock = SimulatedSeqlock::new("v1");

        let outcome = seqlock.read_with_interference(&policy, &plan);

        assert_eq!(outcome.resolution, ReadResolution::Optimistic);
        assert_eq!(outcome.fallback_reason, None);
        assert_eq!(outcome.value, "v2");
        assert_eq!(outcome.retries, 1);
        assert_eq!(seqlock.fallback_reads(), 0);
    }

    #[test]
    fn unique_temp_path_is_distinct_for_each_write_attempt() {
        let target = Path::new("/tmp/seqlock-candidate-inventory.json");
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
        let err = emit_default_inventory_bundle(&context)
            .expect_err("rewrite should fail when artifact target path is a directory");
        assert_eq!(err.kind(), ErrorKind::IsADirectory);
        assert!(
            !manifest_path.exists(),
            "stale manifest commit marker should be removed on failed rewrite"
        );
        assert!(
            !artifact_dir
                .join(".seqlock_candidate_inventory.lock")
                .exists(),
            "bundle lock should be released after failure",
        );

        let _ = fs::remove_dir_all(&artifact_dir);
    }
}
