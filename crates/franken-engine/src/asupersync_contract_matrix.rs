//! Asupersync cross-repo contract matrix and artifact emitter.
//!
//! Bead: bd-3nr.1.5.1 [10.13X.E1]
//!
//! This module turns the existing 10.13X control-plane substrate into a
//! replayable cross-repo verification surface for the sibling `/dp/asupersync`
//! repository. It validates four upstream surfaces that FrankenEngine depends
//! on directly or bridges indirectly:
//!
//! - `franken-kernel` context / budget / trace semantics,
//! - `franken-decision` decision evaluation linkage,
//! - `franken-evidence` evidence-ledger validity,
//! - `frankenlab` operator-facing scenario harness surface.
//!
//! The output is intentionally operator-readable and machine-readable:
//! `asupersync_contract_compat_matrix.json`,
//! `version_drift_failure_codes.json`,
//! `run_manifest.json`,
//! `events.jsonl`,
//! `commands.txt`,
//! `summary.md`,
//! `env.json`,
//! `repro.lock`,
//! `trace_ids`,
//! and per-surface logs under `step_logs/`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use toml::Value as TomlValue;

use crate::conformance_catalog::{FailureSeverity, RequiredResponse};
use crate::control_plane::{
    Budget, ContractDecisionAdapter, Cx, DecisionAdapter, DecisionContract, DecisionId,
    DecisionRequest, DecisionVerdict, EvidenceLedgerBuilder, FallbackPolicy, LossMatrix, NoCaps,
    PolicyId, Posterior, TraceId,
};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

pub const SCHEMA_VERSION: &str = "franken-engine.asupersync-contract-matrix.v1";
pub const FAILURE_CODE_SCHEMA_VERSION: &str = "franken-engine.asupersync-contract-failure-codes.v1";
pub const BEAD_ID: &str = "bd-3nr.1.5.1";
pub const COMPONENT: &str = "asupersync_contract_matrix";
pub const DEFAULT_ASUPERSYNC_ROOT: &str = "/dp/asupersync";

const DEFAULT_SEED: &str = "bd-3nr.1.5.1-seed-v1";
const KERNEL_TRACE_TS_MS: u64 = 1_700_000_000_000;
const DECISION_TRACE_TS_MS: u64 = 1_700_000_000_500;
const EVIDENCE_TRACE_TS_MS: u64 = 1_700_000_001_000;
const FRANKENLAB_TRACE_TS_MS: u64 = 1_700_000_001_500;

static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum AsupersyncContractMatrixError {
    Io { path: PathBuf, source: io::Error },
    ManifestParse { path: PathBuf, reason: String },
    MissingField { path: PathBuf, field: &'static str },
}

impl fmt::Display for AsupersyncContractMatrixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "I/O error at {}: {source}", path.display())
            }
            Self::ManifestParse { path, reason } => {
                write!(f, "failed to parse {}: {reason}", path.display())
            }
            Self::MissingField { path, field } => {
                write!(f, "missing `{field}` in {}", path.display())
            }
        }
    }
}

impl std::error::Error for AsupersyncContractMatrixError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AsupersyncSurface {
    KernelContext,
    DecisionContract,
    EvidenceLedger,
    FrankenlabCli,
}

impl AsupersyncSurface {
    pub const fn all() -> &'static [Self] {
        &[
            Self::KernelContext,
            Self::DecisionContract,
            Self::EvidenceLedger,
            Self::FrankenlabCli,
        ]
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KernelContext => "kernel_context",
            Self::DecisionContract => "decision_contract",
            Self::EvidenceLedger => "evidence_ledger",
            Self::FrankenlabCli => "frankenlab_cli",
        }
    }

    const fn crate_name(self) -> &'static str {
        match self {
            Self::KernelContext => "franken_kernel",
            Self::DecisionContract => "franken_decision",
            Self::EvidenceLedger => "franken_evidence",
            Self::FrankenlabCli => "frankenlab",
        }
    }

    const fn manifest_rel_path(self) -> &'static str {
        match self {
            Self::KernelContext => "franken_kernel/Cargo.toml",
            Self::DecisionContract => "franken_decision/Cargo.toml",
            Self::EvidenceLedger => "franken_evidence/Cargo.toml",
            Self::FrankenlabCli => "frankenlab/Cargo.toml",
        }
    }

    const fn trace_timestamp_ms(self) -> u64 {
        match self {
            Self::KernelContext => KERNEL_TRACE_TS_MS,
            Self::DecisionContract => DECISION_TRACE_TS_MS,
            Self::EvidenceLedger => EVIDENCE_TRACE_TS_MS,
            Self::FrankenlabCli => FRANKENLAB_TRACE_TS_MS,
        }
    }
}

impl fmt::Display for AsupersyncSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityDisposition {
    Compatible,
    VersionDrift,
    MissingCapability,
    BridgeIncompatible,
}

impl CompatibilityDisposition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compatible => "compatible",
            Self::VersionDrift => "version_drift",
            Self::MissingCapability => "missing_capability",
            Self::BridgeIncompatible => "bridge_incompatible",
        }
    }

    fn from_codes(codes: &[ContractFailureCode]) -> Self {
        if codes.is_empty() {
            return Self::Compatible;
        }
        if codes.iter().all(|code| code.is_version_drift()) {
            return Self::VersionDrift;
        }
        if codes.iter().any(|code| code.is_missing_capability()) {
            return Self::MissingCapability;
        }
        Self::BridgeIncompatible
    }
}

impl fmt::Display for CompatibilityDisposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractFailureCode {
    AsupersyncReleaseCellDrift,
    DecisionKernelVersionDrift,
    DecisionEvidenceVersionDrift,
    FrankenlabAsupersyncVersionDrift,
    KernelContextBudgetDrift,
    DecisionContractEvalFailed,
    EvidenceLedgerValidationFailed,
    FrankenlabCliMissing,
    FrankenlabExampleScenariosMissing,
}

impl ContractFailureCode {
    pub const fn all() -> &'static [Self] {
        &[
            Self::AsupersyncReleaseCellDrift,
            Self::DecisionKernelVersionDrift,
            Self::DecisionEvidenceVersionDrift,
            Self::FrankenlabAsupersyncVersionDrift,
            Self::KernelContextBudgetDrift,
            Self::DecisionContractEvalFailed,
            Self::EvidenceLedgerValidationFailed,
            Self::FrankenlabCliMissing,
            Self::FrankenlabExampleScenariosMissing,
        ]
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AsupersyncReleaseCellDrift => "asupersync_release_cell_drift",
            Self::DecisionKernelVersionDrift => "decision_kernel_version_drift",
            Self::DecisionEvidenceVersionDrift => "decision_evidence_version_drift",
            Self::FrankenlabAsupersyncVersionDrift => "frankenlab_asupersync_version_drift",
            Self::KernelContextBudgetDrift => "kernel_context_budget_drift",
            Self::DecisionContractEvalFailed => "decision_contract_eval_failed",
            Self::EvidenceLedgerValidationFailed => "evidence_ledger_validation_failed",
            Self::FrankenlabCliMissing => "frankenlab_cli_missing",
            Self::FrankenlabExampleScenariosMissing => "frankenlab_example_scenarios_missing",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::AsupersyncReleaseCellDrift => {
                "upstream package versions are not in a single pinned release cell"
            }
            Self::DecisionKernelVersionDrift => {
                "franken-decision does not depend on the live franken-kernel release"
            }
            Self::DecisionEvidenceVersionDrift => {
                "franken-decision does not depend on the live franken-evidence release"
            }
            Self::FrankenlabAsupersyncVersionDrift => {
                "frankenlab does not depend on the live asupersync release cell"
            }
            Self::KernelContextBudgetDrift => {
                "context child derivation or budget monotonicity no longer matches the canonical kernel surface"
            }
            Self::DecisionContractEvalFailed => {
                "the adapter-backed decision evaluation path no longer produces the expected verdict"
            }
            Self::EvidenceLedgerValidationFailed => {
                "evidence-ledger builder or validation invariants no longer hold"
            }
            Self::FrankenlabCliMissing => {
                "the frankenlab CLI entrypoint is missing from the upstream sibling repo"
            }
            Self::FrankenlabExampleScenariosMissing => {
                "the canonical frankenlab example scenarios required by the bridge are missing"
            }
        }
    }

    pub const fn remediation(self) -> &'static str {
        match self {
            Self::AsupersyncReleaseCellDrift => {
                "Re-pin the sibling crates to a single reviewed release cell before promotion."
            }
            Self::DecisionKernelVersionDrift => {
                "Update franken-decision's kernel dependency or roll back the kernel bump."
            }
            Self::DecisionEvidenceVersionDrift => {
                "Update franken-decision's evidence dependency or roll back the evidence bump."
            }
            Self::FrankenlabAsupersyncVersionDrift => {
                "Re-align frankenlab with the reviewed Asupersync release cell."
            }
            Self::KernelContextBudgetDrift => {
                "Investigate kernel context semantics before trusting the control-plane adapter."
            }
            Self::DecisionContractEvalFailed => {
                "Investigate the adapter-backed decision path before shipping 10.13X control-plane changes."
            }
            Self::EvidenceLedgerValidationFailed => {
                "Restore evidence-ledger validity before relying on decision/evidence linkage."
            }
            Self::FrankenlabCliMissing => {
                "Restore the frankenlab CLI entrypoint or mark the bridge intentionally unavailable."
            }
            Self::FrankenlabExampleScenariosMissing => {
                "Restore the canonical frankenlab scenarios or update the bridge contract explicitly."
            }
        }
    }

    pub const fn severity(self) -> FailureSeverity {
        match self {
            Self::AsupersyncReleaseCellDrift
            | Self::DecisionKernelVersionDrift
            | Self::DecisionEvidenceVersionDrift
            | Self::FrankenlabAsupersyncVersionDrift
            | Self::KernelContextBudgetDrift
            | Self::DecisionContractEvalFailed
            | Self::EvidenceLedgerValidationFailed
            | Self::FrankenlabCliMissing
            | Self::FrankenlabExampleScenariosMissing => FailureSeverity::Critical,
        }
    }

    pub const fn required_response(self) -> RequiredResponse {
        match self {
            Self::AsupersyncReleaseCellDrift
            | Self::DecisionKernelVersionDrift
            | Self::DecisionEvidenceVersionDrift
            | Self::FrankenlabAsupersyncVersionDrift
            | Self::KernelContextBudgetDrift
            | Self::DecisionContractEvalFailed
            | Self::EvidenceLedgerValidationFailed
            | Self::FrankenlabCliMissing
            | Self::FrankenlabExampleScenariosMissing => RequiredResponse::Block,
        }
    }

    const fn is_version_drift(self) -> bool {
        matches!(
            self,
            Self::AsupersyncReleaseCellDrift
                | Self::DecisionKernelVersionDrift
                | Self::DecisionEvidenceVersionDrift
                | Self::FrankenlabAsupersyncVersionDrift
        )
    }

    const fn is_missing_capability(self) -> bool {
        matches!(
            self,
            Self::FrankenlabCliMissing | Self::FrankenlabExampleScenariosMissing
        )
    }
}

impl fmt::Display for ContractFailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamReleaseIdentifier {
    pub surface: AsupersyncSurface,
    pub package_name: String,
    pub crate_name: String,
    pub manifest_path: String,
    pub release_id: String,
    pub manifest_hash: String,
    pub dependency_versions: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityCell {
    pub surface: AsupersyncSurface,
    pub package_name: String,
    pub crate_name: String,
    pub manifest_path: String,
    pub release_id: String,
    pub supported_version_range: String,
    pub disposition: CompatibilityDisposition,
    pub diagnostic_codes: Vec<ContractFailureCode>,
    pub detail: String,
    pub checks: Vec<String>,
    pub trace_id: String,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
    pub budget_state: Option<String>,
    pub capability_profile: Option<String>,
    pub version_cell: String,
    pub dependency_versions: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsupersyncContractCompatMatrix {
    pub schema_version: String,
    pub bead_id: String,
    pub generated_at_unix_ms: u64,
    pub epoch: u64,
    pub asupersync_root: String,
    pub expected_release_cell: String,
    pub compatible_surface_count: usize,
    pub incompatible_surface_count: usize,
    pub releases: Vec<UpstreamReleaseIdentifier>,
    pub compatibility_cells: Vec<CompatibilityCell>,
    pub report_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureCodeDescriptor {
    pub code: ContractFailureCode,
    pub severity: FailureSeverity,
    pub required_response: RequiredResponse,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionDriftFailureCatalog {
    pub schema_version: String,
    pub bead_id: String,
    pub failure_codes: Vec<FailureCodeDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractEvent {
    pub trace_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub seed: String,
    pub scenario_id: String,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
    pub budget_state: Option<String>,
    pub capability_profile: Option<String>,
    pub compatibility_disposition: String,
    pub version_cell: String,
    pub upstream_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BundleManifest {
    schema_version: String,
    bead_id: String,
    generated_at_unix_ms: u64,
    epoch: u64,
    asupersync_root: String,
    expected_release_cell: String,
    compatible_surface_count: usize,
    incompatible_surface_count: usize,
    asupersync_contract_compat_matrix: String,
    version_drift_failure_codes: String,
    run_manifest: String,
    events_jsonl: String,
    commands_txt: String,
    summary_md: String,
    env_json: String,
    repro_lock: String,
    trace_ids: String,
    step_logs: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BundleEnvironment {
    schema_version: String,
    repo_root: String,
    asupersync_root: String,
    manifest_dir: String,
    cwd: String,
    argv: Vec<String>,
    release_cell: String,
    package_versions: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsupersyncContractBundleArtifacts {
    pub out_dir: PathBuf,
    pub compat_matrix_path: PathBuf,
    pub failure_codes_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub summary_path: PathBuf,
    pub env_path: PathBuf,
    pub repro_lock_path: PathBuf,
    pub trace_ids_path: PathBuf,
    pub step_logs_dir: PathBuf,
    pub report_hash: String,
    pub compatible_surface_count: usize,
}

pub fn default_asupersync_root() -> PathBuf {
    PathBuf::from(DEFAULT_ASUPERSYNC_ROOT)
}

pub fn canonical_failure_code_catalog() -> VersionDriftFailureCatalog {
    VersionDriftFailureCatalog {
        schema_version: FAILURE_CODE_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        failure_codes: ContractFailureCode::all()
            .iter()
            .map(|code| FailureCodeDescriptor {
                code: *code,
                severity: code.severity(),
                required_response: code.required_response(),
                description: code.description().to_string(),
                remediation: code.remediation().to_string(),
            })
            .collect(),
    }
}

pub fn build_asupersync_contract_matrix(
    asupersync_root: &Path,
) -> Result<AsupersyncContractCompatMatrix, AsupersyncContractMatrixError> {
    build_asupersync_contract_matrix_with_generated_at(
        asupersync_root,
        current_unix_ms(),
        SecurityEpoch::GENESIS,
    )
}

pub fn build_asupersync_contract_matrix_with_generated_at(
    asupersync_root: &Path,
    generated_at_unix_ms: u64,
    epoch: SecurityEpoch,
) -> Result<AsupersyncContractCompatMatrix, AsupersyncContractMatrixError> {
    let releases = load_upstream_release_identifiers(asupersync_root)?;
    let expected_release_cell = releases
        .iter()
        .find(|release| release.surface == AsupersyncSurface::KernelContext)
        .map(|release| release.release_id.clone())
        .or_else(|| releases.first().map(|release| release.release_id.clone()))
        .unwrap_or_default();
    let release_index = release_index(&releases);

    let compatibility_cells = vec![
        probe_kernel_surface(
            release_index
                .get(&AsupersyncSurface::KernelContext)
                .expect("kernel release present"),
            &expected_release_cell,
        ),
        probe_decision_surface(
            release_index
                .get(&AsupersyncSurface::DecisionContract)
                .expect("decision release present"),
            release_index
                .get(&AsupersyncSurface::KernelContext)
                .expect("kernel release present"),
            release_index
                .get(&AsupersyncSurface::EvidenceLedger)
                .expect("evidence release present"),
            &expected_release_cell,
        ),
        probe_evidence_surface(
            release_index
                .get(&AsupersyncSurface::EvidenceLedger)
                .expect("evidence release present"),
            &expected_release_cell,
        ),
        probe_frankenlab_surface(
            release_index
                .get(&AsupersyncSurface::FrankenlabCli)
                .expect("frankenlab release present"),
            &expected_release_cell,
            asupersync_root,
        ),
    ];

    let compatible_surface_count = compatibility_cells
        .iter()
        .filter(|cell| matches!(cell.disposition, CompatibilityDisposition::Compatible))
        .count();
    let incompatible_surface_count = compatibility_cells.len() - compatible_surface_count;

    let mut matrix = AsupersyncContractCompatMatrix {
        schema_version: SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        generated_at_unix_ms,
        epoch: epoch.as_u64(),
        asupersync_root: asupersync_root.display().to_string(),
        expected_release_cell,
        compatible_surface_count,
        incompatible_surface_count,
        releases,
        compatibility_cells,
        report_hash: String::new(),
    };
    matrix.report_hash = compute_matrix_hash(&matrix);
    Ok(matrix)
}

pub fn write_asupersync_contract_bundle(
    out_dir: &Path,
    asupersync_root: &Path,
    argv: &[String],
) -> Result<AsupersyncContractBundleArtifacts, AsupersyncContractMatrixError> {
    let generated_at_unix_ms = current_unix_ms();
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        asupersync_root,
        generated_at_unix_ms,
        SecurityEpoch::GENESIS,
    )?;
    let failure_catalog = canonical_failure_code_catalog();
    let events = build_events(&matrix.compatibility_cells);

    let compat_matrix_path = out_dir.join("asupersync_contract_compat_matrix.json");
    let failure_codes_path = out_dir.join("version_drift_failure_codes.json");
    let run_manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");
    let summary_path = out_dir.join("summary.md");
    let env_path = out_dir.join("env.json");
    let repro_lock_path = out_dir.join("repro.lock");
    let trace_ids_path = out_dir.join("trace_ids");
    let step_logs_dir = out_dir.join("step_logs");

    fs::create_dir_all(&step_logs_dir).map_err(|source| AsupersyncContractMatrixError::Io {
        path: step_logs_dir.clone(),
        source,
    })?;

    let compat_matrix_bytes = json_pretty_bytes(&matrix, &compat_matrix_path)?;
    let failure_codes_bytes = json_pretty_bytes(&failure_catalog, &failure_codes_path)?;
    let env_json = build_environment(out_dir, asupersync_root, argv, &matrix);
    let env_bytes = json_pretty_bytes(&env_json, &env_path)?;

    let manifest = BundleManifest {
        schema_version: SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        generated_at_unix_ms,
        epoch: SecurityEpoch::GENESIS.as_u64(),
        asupersync_root: asupersync_root.display().to_string(),
        expected_release_cell: matrix.expected_release_cell.clone(),
        compatible_surface_count: matrix.compatible_surface_count,
        incompatible_surface_count: matrix.incompatible_surface_count,
        asupersync_contract_compat_matrix: file_name_string(&compat_matrix_path),
        version_drift_failure_codes: file_name_string(&failure_codes_path),
        run_manifest: file_name_string(&run_manifest_path),
        events_jsonl: file_name_string(&events_path),
        commands_txt: file_name_string(&commands_path),
        summary_md: file_name_string(&summary_path),
        env_json: file_name_string(&env_path),
        repro_lock: file_name_string(&repro_lock_path),
        trace_ids: file_name_string(&trace_ids_path),
        step_logs: file_name_string(&step_logs_dir),
    };
    let manifest_bytes = json_pretty_bytes(&manifest, &run_manifest_path)?;

    let commands = render_commands(out_dir, asupersync_root, argv);
    let summary = render_summary(&matrix);
    let repro_lock = render_repro_lock(&matrix, asupersync_root);
    let trace_ids = render_trace_ids(&matrix.compatibility_cells);
    let events_jsonl = render_events_jsonl(&events)?;

    write_atomic(&compat_matrix_path, &compat_matrix_bytes)?;
    write_atomic(&failure_codes_path, &failure_codes_bytes)?;
    write_atomic(&run_manifest_path, &manifest_bytes)?;
    write_atomic(&events_path, events_jsonl.as_bytes())?;
    write_atomic(&commands_path, commands.as_bytes())?;
    write_atomic(&summary_path, summary.as_bytes())?;
    write_atomic(&env_path, &env_bytes)?;
    write_atomic(&repro_lock_path, repro_lock.as_bytes())?;
    write_atomic(&trace_ids_path, trace_ids.as_bytes())?;

    for cell in &matrix.compatibility_cells {
        let step_log_path = step_logs_dir.join(format!("{}.json", cell.surface.as_str()));
        let step_log_bytes = json_pretty_bytes(cell, &step_log_path)?;
        write_atomic(&step_log_path, &step_log_bytes)?;
    }

    Ok(AsupersyncContractBundleArtifacts {
        out_dir: out_dir.to_path_buf(),
        compat_matrix_path,
        failure_codes_path,
        run_manifest_path,
        events_path,
        commands_path,
        summary_path,
        env_path,
        repro_lock_path,
        trace_ids_path,
        step_logs_dir,
        report_hash: matrix.report_hash,
        compatible_surface_count: matrix.compatible_surface_count,
    })
}

fn probe_kernel_surface(
    release: &UpstreamReleaseIdentifier,
    expected_release_cell: &str,
) -> CompatibilityCell {
    let trace = TraceId::from_parts(AsupersyncSurface::KernelContext.trace_timestamp_ms(), 11);
    let root = Cx::new(trace, Budget::new(5_000), NoCaps);
    let child = root.child(NoCaps, Budget::new(3_000));
    let mut codes = drift_codes_for_surface(release, expected_release_cell);
    let mut detail = Vec::new();
    let checks = vec![
        "trace_id propagation".to_string(),
        "child derivation depth".to_string(),
        "budget monotonicity".to_string(),
    ];

    let trace_ok = child.trace_id() == trace;
    let depth_ok = child.depth() == 1;
    let budget_ok = child.budget().remaining_ms() == 3_000 && root.budget().remaining_ms() == 5_000;
    if trace_ok && depth_ok && budget_ok {
        detail.push(
            "kernel context derivation matches the canonical adapter expectations".to_string(),
        );
    } else {
        codes.push(ContractFailureCode::KernelContextBudgetDrift);
        detail.push(format!(
            "trace_ok={trace_ok}, depth_ok={depth_ok}, budget_ok={budget_ok}"
        ));
    }

    finalize_cell(
        release,
        expected_release_cell,
        FinalizeCellInput {
            diagnostic_codes: codes,
            detail_parts: detail,
            checks,
            trace_id: trace.to_string(),
            decision_id: None,
            policy_id: None,
            budget_state: Some(format!(
                "root_remaining_ms={},child_remaining_ms={}",
                root.budget().remaining_ms(),
                child.budget().remaining_ms()
            )),
            capability_profile: Some("no_caps".to_string()),
        },
    )
}

fn probe_decision_surface(
    release: &UpstreamReleaseIdentifier,
    kernel_release: &UpstreamReleaseIdentifier,
    evidence_release: &UpstreamReleaseIdentifier,
    expected_release_cell: &str,
) -> CompatibilityCell {
    let mut codes = drift_codes_for_surface(release, expected_release_cell);
    let mut detail = Vec::new();
    let checks = vec![
        "decision adapter evaluation".to_string(),
        "stable deny verdict".to_string(),
        "decision and policy identifiers preserved".to_string(),
    ];
    if release.dependency_versions.get("franken-kernel") != Some(&kernel_release.release_id) {
        codes.push(ContractFailureCode::DecisionKernelVersionDrift);
        detail.push(format!(
            "franken-decision expects franken-kernel {:?}, live release is {}",
            release.dependency_versions.get("franken-kernel"),
            kernel_release.release_id
        ));
    }
    if release.dependency_versions.get("franken-evidence") != Some(&evidence_release.release_id) {
        codes.push(ContractFailureCode::DecisionEvidenceVersionDrift);
        detail.push(format!(
            "franken-decision expects franken-evidence {:?}, live release is {}",
            release.dependency_versions.get("franken-evidence"),
            evidence_release.release_id
        ));
    }

    let trace_id =
        TraceId::from_parts(AsupersyncSurface::DecisionContract.trace_timestamp_ms(), 19);
    let decision_id =
        DecisionId::from_parts(AsupersyncSurface::DecisionContract.trace_timestamp_ms(), 23);
    let policy_id = PolicyId::new("control-plane.contract", 1);
    match MiniContract::new() {
        Ok(contract) => {
            let mut adapter = ContractDecisionAdapter::new(contract, Posterior::uniform(2));
            let request = DecisionRequest {
                decision_id,
                policy_id: policy_id.clone(),
                trace_id,
                ts_unix_ms: AsupersyncSurface::DecisionContract.trace_timestamp_ms(),
                calibration_score_bps: 9_500,
                e_process_milli: 100,
                ci_width_milli: 50,
            };
            match adapter.evaluate(&request) {
                Ok(DecisionVerdict::Deny) if adapter.events().len() == 1 => {
                    detail.push("decision adapter produced the expected deny verdict".to_string());
                }
                Ok(other) => {
                    codes.push(ContractFailureCode::DecisionContractEvalFailed);
                    detail.push(format!("unexpected verdict from adapter: {other:?}"));
                }
                Err(error) => {
                    codes.push(ContractFailureCode::DecisionContractEvalFailed);
                    detail.push(format!("adapter returned error: {error}"));
                }
            }
        }
        Err(error) => {
            codes.push(ContractFailureCode::DecisionContractEvalFailed);
            detail.push(error);
        }
    }

    finalize_cell(
        release,
        expected_release_cell,
        FinalizeCellInput {
            diagnostic_codes: codes,
            detail_parts: detail,
            checks,
            trace_id: trace_id.to_string(),
            decision_id: Some(decision_id.to_string()),
            policy_id: Some(policy_id.to_string()),
            budget_state: None,
            capability_profile: Some("adapter_control_plane".to_string()),
        },
    )
}

fn probe_evidence_surface(
    release: &UpstreamReleaseIdentifier,
    expected_release_cell: &str,
) -> CompatibilityCell {
    let mut codes = drift_codes_for_surface(release, expected_release_cell);
    let mut detail = Vec::new();
    let checks = vec![
        "evidence-ledger builder".to_string(),
        "schema validation".to_string(),
        "expected-loss serialization".to_string(),
    ];
    let trace_id = TraceId::from_parts(AsupersyncSurface::EvidenceLedger.trace_timestamp_ms(), 29);
    let entry_result = EvidenceLedgerBuilder::new()
        .ts_unix_ms(AsupersyncSurface::EvidenceLedger.trace_timestamp_ms())
        .component(COMPONENT)
        .action("allow")
        .posterior(vec![0.7, 0.3])
        .expected_loss("allow", 0.1)
        .expected_loss("deny", 0.3)
        .chosen_expected_loss(0.1)
        .calibration_score(0.93)
        .fallback_active(false)
        .top_feature("version_cell_match", 0.8)
        .build();

    match entry_result {
        Ok(entry) if entry.is_valid() => {
            detail.push("evidence-ledger builder emitted a valid canonical entry".to_string());
        }
        Ok(entry) => {
            codes.push(ContractFailureCode::EvidenceLedgerValidationFailed);
            detail.push(format!("entry validation errors: {:?}", entry.validate()));
        }
        Err(error) => {
            codes.push(ContractFailureCode::EvidenceLedgerValidationFailed);
            detail.push(format!("builder failure: {error}"));
        }
    }

    finalize_cell(
        release,
        expected_release_cell,
        FinalizeCellInput {
            diagnostic_codes: codes,
            detail_parts: detail,
            checks,
            trace_id: trace_id.to_string(),
            decision_id: None,
            policy_id: Some(PolicyId::new("control-plane.evidence", 1).to_string()),
            budget_state: None,
            capability_profile: Some("canonical_evidence_builder".to_string()),
        },
    )
}

fn probe_frankenlab_surface(
    release: &UpstreamReleaseIdentifier,
    expected_release_cell: &str,
    asupersync_root: &Path,
) -> CompatibilityCell {
    let mut codes = drift_codes_for_surface(release, expected_release_cell);
    let mut detail = Vec::new();
    let checks = vec![
        "frankenlab CLI entrypoint exists".to_string(),
        "canonical example scenarios exist".to_string(),
        "frankenlab stays in the reviewed release cell".to_string(),
    ];
    if release
        .dependency_versions
        .get("asupersync")
        .map(String::as_str)
        != Some(expected_release_cell)
    {
        codes.push(ContractFailureCode::FrankenlabAsupersyncVersionDrift);
        detail.push(format!(
            "frankenlab depends on asupersync {:?}, reviewed release cell is {}",
            release.dependency_versions.get("asupersync"),
            expected_release_cell
        ));
    }

    let cli_paths = frankenlab_cli_candidates(release);
    if let Some(cli_path) = cli_paths.iter().find(|path| path.is_file()) {
        detail.push(format!(
            "frankenlab CLI entrypoint present at {}",
            cli_path.display()
        ));
    } else {
        codes.push(ContractFailureCode::FrankenlabCliMissing);
        detail.push(format!(
            "missing CLI entrypoint; tried {}",
            cli_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let required_scenarios = [
        "01_race_condition.yaml",
        "02_obligation_leak.yaml",
        "03_saga_partition.yaml",
    ];
    let missing_scenarios: Vec<_> = required_scenarios
        .iter()
        .filter(|scenario| {
            !asupersync_root
                .join("frankenlab/examples/scenarios")
                .join(scenario)
                .exists()
        })
        .copied()
        .collect();
    if missing_scenarios.is_empty() {
        detail.push("all canonical frankenlab example scenarios are present".to_string());
    } else {
        codes.push(ContractFailureCode::FrankenlabExampleScenariosMissing);
        detail.push(format!(
            "missing frankenlab scenarios: {}",
            missing_scenarios.join(", ")
        ));
    }

    finalize_cell(
        release,
        expected_release_cell,
        FinalizeCellInput {
            diagnostic_codes: codes,
            detail_parts: detail,
            checks,
            trace_id: TraceId::from_parts(
                AsupersyncSurface::FrankenlabCli.trace_timestamp_ms(),
                37,
            )
            .to_string(),
            decision_id: None,
            policy_id: Some(PolicyId::new("frankenlab.bridge", 1).to_string()),
            budget_state: None,
            capability_profile: Some("frankenlab_cli".to_string()),
        },
    )
}

struct FinalizeCellInput {
    diagnostic_codes: Vec<ContractFailureCode>,
    detail_parts: Vec<String>,
    checks: Vec<String>,
    trace_id: String,
    decision_id: Option<String>,
    policy_id: Option<String>,
    budget_state: Option<String>,
    capability_profile: Option<String>,
}

fn finalize_cell(
    release: &UpstreamReleaseIdentifier,
    expected_release_cell: &str,
    input: FinalizeCellInput,
) -> CompatibilityCell {
    let FinalizeCellInput {
        diagnostic_codes,
        detail_parts,
        checks,
        trace_id,
        decision_id,
        policy_id,
        budget_state,
        capability_profile,
    } = input;
    CompatibilityCell {
        surface: release.surface,
        package_name: release.package_name.clone(),
        crate_name: release.crate_name.clone(),
        manifest_path: release.manifest_path.clone(),
        release_id: release.release_id.clone(),
        supported_version_range: format!("exact release cell `{expected_release_cell}`"),
        disposition: CompatibilityDisposition::from_codes(&diagnostic_codes),
        diagnostic_codes,
        detail: detail_parts.join(" | "),
        checks,
        trace_id,
        decision_id,
        policy_id,
        budget_state,
        capability_profile,
        version_cell: format!("{}@{}", release.package_name, release.release_id),
        dependency_versions: release.dependency_versions.clone(),
    }
}

fn drift_codes_for_surface(
    release: &UpstreamReleaseIdentifier,
    expected_release_cell: &str,
) -> Vec<ContractFailureCode> {
    if release.release_id == expected_release_cell {
        Vec::new()
    } else {
        vec![ContractFailureCode::AsupersyncReleaseCellDrift]
    }
}

fn build_events(cells: &[CompatibilityCell]) -> Vec<ContractEvent> {
    cells
        .iter()
        .map(|cell| ContractEvent {
            trace_id: cell.trace_id.clone(),
            component: COMPONENT.to_string(),
            event: "surface_verification".to_string(),
            outcome: cell.disposition.as_str().to_string(),
            error_code: cell.diagnostic_codes.first().map(ToString::to_string),
            seed: DEFAULT_SEED.to_string(),
            scenario_id: cell.surface.as_str().to_string(),
            decision_id: cell.decision_id.clone(),
            policy_id: cell.policy_id.clone(),
            budget_state: cell.budget_state.clone(),
            capability_profile: cell.capability_profile.clone(),
            compatibility_disposition: cell.disposition.as_str().to_string(),
            version_cell: cell.version_cell.clone(),
            upstream_revision: format!("{}@{}", cell.package_name, cell.release_id),
        })
        .collect()
}

fn render_events_jsonl(events: &[ContractEvent]) -> Result<String, AsupersyncContractMatrixError> {
    let mut rendered = String::new();
    for event in events {
        let line = serde_json::to_string(event).map_err(|error| {
            AsupersyncContractMatrixError::ManifestParse {
                path: PathBuf::from("events.jsonl"),
                reason: error.to_string(),
            }
        })?;
        rendered.push_str(&line);
        rendered.push('\n');
    }
    Ok(rendered)
}

fn render_summary(matrix: &AsupersyncContractCompatMatrix) -> String {
    let mut summary = String::new();
    summary.push_str("# Asupersync Contract Matrix\n\n");
    summary.push_str(&format!(
        "- Release cell: `{}`\n- Compatible surfaces: `{}`\n- Incompatible surfaces: `{}`\n\n",
        matrix.expected_release_cell,
        matrix.compatible_surface_count,
        matrix.incompatible_surface_count
    ));
    summary.push_str("## Surface Status\n");
    for cell in &matrix.compatibility_cells {
        let codes = if cell.diagnostic_codes.is_empty() {
            "none".to_string()
        } else {
            cell.diagnostic_codes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        summary.push_str(&format!(
            "- `{}`: `{}` on `{}`; codes=`{}`\n",
            cell.surface, cell.disposition, cell.version_cell, codes
        ));
    }
    summary
}

fn render_repro_lock(matrix: &AsupersyncContractCompatMatrix, asupersync_root: &Path) -> String {
    let mut rendered = String::new();
    rendered.push_str(&format!("bead_id={BEAD_ID}\n"));
    rendered.push_str(&format!("schema_version={SCHEMA_VERSION}\n"));
    rendered.push_str(&format!("asupersync_root={}\n", asupersync_root.display()));
    rendered.push_str(&format!("release_cell={}\n", matrix.expected_release_cell));
    for release in &matrix.releases {
        rendered.push_str(&format!(
            "{}={}\n",
            release.package_name, release.release_id
        ));
        rendered.push_str(&format!(
            "{}_manifest_hash={}\n",
            release.package_name.replace('-', "_"),
            release.manifest_hash
        ));
    }
    rendered
}

fn render_trace_ids(cells: &[CompatibilityCell]) -> String {
    let mut rendered = String::new();
    for cell in cells {
        rendered.push_str(&cell.trace_id);
        rendered.push('\n');
    }
    rendered
}

fn render_commands(out_dir: &Path, asupersync_root: &Path, argv: &[String]) -> String {
    let argv_line = render_shell_command(argv);
    let script_path =
        repo_root_from_manifest_dir().join("scripts/e2e/run_asupersync_contract_matrix.sh");
    let quoted_out_dir = shell_quote(&out_dir.display().to_string());
    let quoted_asupersync_root = shell_quote(&asupersync_root.display().to_string());
    let quoted_script = shell_quote(&script_path.display().to_string());
    format!(
        "# Original invocation\n{argv_line}\n\n# Preferred operator wrapper (rch-backed)\n{quoted_script} {quoted_out_dir} {quoted_asupersync_root}\n\n# Direct replayable heavy verification via rch\nrch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_asupersync_contract_matrix cargo run -p frankenengine-engine --bin franken_asupersync_contract_matrix -- --out-dir {quoted_out_dir} --asupersync-root {quoted_asupersync_root}\nrch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_asupersync_contract_matrix cargo check -p frankenengine-engine --test asupersync_contract_matrix_integration --test asupersync_contract_matrix_enrichment_integration\n",
    )
}

fn frankenlab_cli_candidates(release: &UpstreamReleaseIdentifier) -> Vec<PathBuf> {
    let manifest_path = PathBuf::from(&release.manifest_path);
    let manifest_dir = manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let mut candidates = vec![manifest_dir.join("src/main.rs")];

    if let Ok(manifest_text) = fs::read_to_string(&manifest_path)
        && let Ok(manifest) = toml::from_str::<TomlValue>(&manifest_text)
        && let Some(bins) = manifest.get("bin").and_then(TomlValue::as_array)
    {
        for bin in bins {
            if let Some(path) = bin.get("path").and_then(TomlValue::as_str) {
                candidates.push(manifest_dir.join(path));
            } else if let Some(name) = bin.get("name").and_then(TomlValue::as_str) {
                candidates.push(manifest_dir.join("src/bin").join(format!("{name}.rs")));
            }
        }
    }

    let package_bin_candidate = manifest_dir
        .join("src/bin")
        .join(format!("{}.rs", release.package_name.replace('-', "_")));
    if !candidates.contains(&package_bin_candidate) {
        candidates.push(package_bin_candidate);
    }

    candidates.sort();
    candidates.dedup();
    candidates
}

fn render_shell_command(argv: &[String]) -> String {
    if argv.is_empty() {
        return String::from("franken_asupersync_contract_matrix");
    }
    argv.iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }
    if arg.bytes().all(|byte| {
        matches!(
            byte,
            b'a'..=b'z'
                | b'A'..=b'Z'
                | b'0'..=b'9'
                | b'/'
                | b'.'
                | b'_'
                | b'-'
                | b':'
                | b'='
                | b'+'
        )
    }) {
        return arg.to_string();
    }
    format!("'{}'", arg.replace('\'', "'\"'\"'"))
}

fn build_environment(
    out_dir: &Path,
    asupersync_root: &Path,
    argv: &[String],
    matrix: &AsupersyncContractCompatMatrix,
) -> BundleEnvironment {
    let repo_root = repo_root_from_manifest_dir();
    let package_versions = matrix
        .releases
        .iter()
        .map(|release| (release.package_name.clone(), release.release_id.clone()))
        .collect();
    BundleEnvironment {
        schema_version: SCHEMA_VERSION.to_string(),
        repo_root: repo_root.display().to_string(),
        asupersync_root: asupersync_root.display().to_string(),
        manifest_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .display()
            .to_string(),
        cwd: std::env::current_dir()
            .unwrap_or_else(|_| out_dir.to_path_buf())
            .display()
            .to_string(),
        argv: argv.to_vec(),
        release_cell: matrix.expected_release_cell.clone(),
        package_versions,
    }
}

fn load_upstream_release_identifiers(
    asupersync_root: &Path,
) -> Result<Vec<UpstreamReleaseIdentifier>, AsupersyncContractMatrixError> {
    let mut releases = Vec::new();
    for surface in AsupersyncSurface::all() {
        let manifest_path = asupersync_root.join(surface.manifest_rel_path());
        let manifest_bytes =
            fs::read(&manifest_path).map_err(|source| AsupersyncContractMatrixError::Io {
                path: manifest_path.clone(),
                source,
            })?;
        let manifest_text = String::from_utf8(manifest_bytes.clone()).map_err(|error| {
            AsupersyncContractMatrixError::ManifestParse {
                path: manifest_path.clone(),
                reason: error.to_string(),
            }
        })?;
        let manifest: TomlValue = toml::from_str(&manifest_text).map_err(|error| {
            AsupersyncContractMatrixError::ManifestParse {
                path: manifest_path.clone(),
                reason: error.to_string(),
            }
        })?;
        let package_name = manifest_package_name(&manifest, &manifest_path)?;
        let release_id = manifest_package_version(&manifest, &manifest_path)?;
        let dependency_versions = dependency_versions_for_surface(*surface, &manifest);
        releases.push(UpstreamReleaseIdentifier {
            surface: *surface,
            package_name,
            crate_name: surface.crate_name().to_string(),
            manifest_path: manifest_path.display().to_string(),
            release_id,
            manifest_hash: ContentHash::compute(&manifest_bytes).to_hex(),
            dependency_versions,
        });
    }
    Ok(releases)
}

fn dependency_versions_for_surface(
    surface: AsupersyncSurface,
    manifest: &TomlValue,
) -> BTreeMap<String, String> {
    let dependency_names: &[&str] = match surface {
        AsupersyncSurface::KernelContext | AsupersyncSurface::EvidenceLedger => &[],
        AsupersyncSurface::DecisionContract => &["franken-kernel", "franken-evidence"],
        AsupersyncSurface::FrankenlabCli => &["asupersync"],
    };
    dependency_names
        .iter()
        .filter_map(|name| {
            manifest_dependency_version(manifest, name)
                .map(|version| ((*name).to_string(), version))
        })
        .collect()
}

fn manifest_package_name(
    manifest: &TomlValue,
    path: &Path,
) -> Result<String, AsupersyncContractMatrixError> {
    manifest
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(TomlValue::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| AsupersyncContractMatrixError::MissingField {
            path: path.to_path_buf(),
            field: "package.name",
        })
}

fn manifest_package_version(
    manifest: &TomlValue,
    path: &Path,
) -> Result<String, AsupersyncContractMatrixError> {
    manifest
        .get("package")
        .and_then(|package| package.get("version"))
        .and_then(TomlValue::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| AsupersyncContractMatrixError::MissingField {
            path: path.to_path_buf(),
            field: "package.version",
        })
}

fn manifest_dependency_version(manifest: &TomlValue, dependency: &str) -> Option<String> {
    let dependency_value = manifest.get("dependencies")?.get(dependency)?;
    match dependency_value {
        TomlValue::String(version) => Some(version.clone()),
        TomlValue::Table(table) => table
            .get("version")
            .and_then(TomlValue::as_str)
            .map(ToString::to_string),
        _ => None,
    }
}

fn release_index(
    releases: &[UpstreamReleaseIdentifier],
) -> BTreeMap<AsupersyncSurface, UpstreamReleaseIdentifier> {
    releases
        .iter()
        .cloned()
        .map(|release| (release.surface, release))
        .collect()
}

fn repo_root_from_manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

fn compute_matrix_hash(matrix: &AsupersyncContractCompatMatrix) -> String {
    let mut clone = matrix.clone();
    clone.report_hash.clear();
    match serde_json::to_vec(&clone) {
        Ok(bytes) => ContentHash::compute(&bytes).to_hex(),
        Err(_) => ContentHash::compute(SCHEMA_VERSION.as_bytes()).to_hex(),
    }
}

fn json_pretty_bytes<T: Serialize>(
    value: &T,
    path: &Path,
) -> Result<Vec<u8>, AsupersyncContractMatrixError> {
    serde_json::to_vec_pretty(value).map_err(|error| AsupersyncContractMatrixError::ManifestParse {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })
}

fn file_name_string(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string())
}

fn current_unix_ms() -> u64 {
    u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), AsupersyncContractMatrixError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| AsupersyncContractMatrixError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let temp_path = unique_temp_path(path);
    fs::write(&temp_path, bytes).map_err(|source| AsupersyncContractMatrixError::Io {
        path: temp_path.clone(),
        source,
    })?;
    fs::rename(&temp_path, path).map_err(|source| AsupersyncContractMatrixError::Io {
        path: path.to_path_buf(),
        source,
    })
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

struct MiniContract {
    loss_matrix: LossMatrix,
    fallback: FallbackPolicy,
}

impl MiniContract {
    fn new() -> Result<Self, String> {
        let loss_matrix = LossMatrix::new(
            vec!["good".to_string(), "bad".to_string()],
            vec![
                "allow".to_string(),
                "deny".to_string(),
                "timeout".to_string(),
            ],
            vec![
                0.01, 0.4, 0.6, // good
                0.8, 0.1, 0.3, // bad
            ],
        )
        .map_err(|error| error.to_string())?;
        Ok(Self {
            loss_matrix,
            fallback: FallbackPolicy::default(),
        })
    }
}

impl DecisionContract for MiniContract {
    fn name(&self) -> &str {
        "asupersync_contract_matrix"
    }

    fn state_space(&self) -> &[String] {
        self.loss_matrix.state_names()
    }

    fn action_set(&self) -> &[String] {
        self.loss_matrix.action_names()
    }

    fn loss_matrix(&self) -> &LossMatrix {
        &self.loss_matrix
    }

    fn update_posterior(&self, posterior: &mut Posterior, _state_index: usize) {
        posterior.bayesian_update(&[0.8, 0.2]);
    }

    fn choose_action(&self, posterior: &Posterior) -> usize {
        self.loss_matrix.bayes_action(posterior)
    }

    fn fallback_action(&self) -> usize {
        2
    }

    fn fallback_policy(&self) -> &FallbackPolicy {
        &self.fallback
    }
}

#[cfg(test)]
mod tests {
    use super::{CompatibilityDisposition, ContractFailureCode};

    #[test]
    fn compatibility_disposition_prefers_version_drift_for_release_codes() {
        let codes = [ContractFailureCode::DecisionKernelVersionDrift];
        assert_eq!(
            CompatibilityDisposition::from_codes(&codes),
            CompatibilityDisposition::VersionDrift
        );
    }

    #[test]
    fn canonical_failure_catalog_includes_frankenlab_missing_cli() {
        let codes = ContractFailureCode::all();
        assert!(codes.contains(&ContractFailureCode::FrankenlabCliMissing));
    }
}
