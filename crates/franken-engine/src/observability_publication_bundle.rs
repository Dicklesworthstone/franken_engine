//! Deterministic RGC-066C observability publication bundle writer.
//!
//! This module composes existing observability-quality, calibration-sentinel,
//! hot-path telemetry, and probabilistic-telemetry surfaces into the
//! publication-oriented artifact set promised by `bd-1lsy.11.20.3`.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::calibration_sentinel::{
    ObservabilityCell, PromotionDecision, PromotionRule, SentinelKind, build_cell, build_report,
    create_sentinel, update_sentinel,
};
use crate::deterministic_probabilistic_telemetry::{
    CaptureMode as TelemetryCaptureMode, TelemetryBudget, TelemetryEvent, TelemetryPlane,
    TelemetryReport, ThinningConfig as PlaneThinningConfig, ThinningPolicy as PlaneThinningPolicy,
};
use crate::hot_path_telemetry_kernel::{
    ExactShadowCounter, HotPathEvidenceEntry, KernelRegistry, SketchWriterKind,
    TelemetryError as HotPathTelemetryError, TelemetryManifest, ThinningPolicy, ThinningStrategy,
    apply_thinning, build_manifest, build_registry, calibrate_kernel, create_kernel,
    register_kernel, submit_observation,
};
use crate::observability_quality_sentinel::{
    DegradationArtifact, DemotionReceipt, DemotionTarget, ObservabilityQualitySentinel,
    QualityDimension, QualityObservation, SentinelReport as QualitySentinelReport,
    canonical_demotion_policy, generate_report as generate_quality_report,
};
use crate::security_epoch::SecurityEpoch;

pub const COMPONENT: &str = "observability_publication_bundle";
pub const BEAD_ID: &str = "bd-1lsy.11.20.3";
pub const POLICY_ID: &str = "policy-rgc-observability-publication-v1";
pub const BUDGET_SENTINEL_SCHEMA_VERSION: &str =
    "franken-engine.observability-budget-sentinel-report.v1";
pub const DEMOTION_RECEIPTS_SCHEMA_VERSION: &str = "franken-engine.telemetry-demotion-receipts.v1";
pub const SUPREMACY_MATRIX_SCHEMA_VERSION: &str =
    "franken-engine.observability-on-supremacy-matrix.v1";
pub const CLAIM_DELTA_SCHEMA_VERSION: &str = "franken-engine.observability-claim-delta-report.v1";
pub const PUBLICATION_POLICY_SCHEMA_VERSION: &str =
    "franken-engine.observability-publication-policy.v1";
pub const SUPPORT_BUNDLE_ATTESTATION_SCHEMA_VERSION: &str =
    "franken-engine.support-bundle-observability-attestation.v1";

const OBSERVABILITY_BUDGET_SENTINEL_REPORT_FILE: &str = "observability_budget_sentinel_report.json";
const OBSERVABILITY_ON_SUPREMACY_MATRIX_FILE: &str = "observability_on_supremacy_matrix.json";
const OBSERVABILITY_CLAIM_DELTA_REPORT_FILE: &str = "observability_claim_delta_report.json";
const TELEMETRY_DEMOTION_RECEIPTS_FILE: &str = "telemetry_demotion_receipts.json";
const OBSERVABILITY_PUBLICATION_POLICY_FILE: &str = "observability_publication_policy.json";
const SUPPORT_BUNDLE_OBSERVABILITY_ATTESTATION_FILE: &str =
    "support_bundle_observability_attestation.json";
const MILLION: u64 = 1_000_000;
const SAMPLE_EPOCH: u64 = 66;

static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum ObservabilityWorkloadClass {
    #[default]
    DispatchSensitive,
    HostcallSensitive,
    StartupSensitive,
}

impl ObservabilityWorkloadClass {
    pub const ALL: [Self; 3] = [
        Self::DispatchSensitive,
        Self::HostcallSensitive,
        Self::StartupSensitive,
    ];

    pub const fn workload_id(self) -> &'static str {
        match self {
            Self::DispatchSensitive => "dispatch_sensitive",
            Self::HostcallSensitive => "hostcall_sensitive",
            Self::StartupSensitive => "startup_sensitive",
        }
    }

    pub const fn telemetry_domain(self) -> &'static str {
        match self {
            Self::DispatchSensitive => "dispatch_hot_path",
            Self::HostcallSensitive => "hostcall_boundary",
            Self::StartupSensitive => "startup_latency",
        }
    }
}

impl fmt::Display for ObservabilityWorkloadClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.workload_id())
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum ObservabilityMode {
    #[default]
    Off,
    Budgeted,
    ExactShadow,
}

impl ObservabilityMode {
    pub const ALL: [Self; 3] = [Self::Off, Self::Budgeted, Self::ExactShadow];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Budgeted => "budgeted",
            Self::ExactShadow => "exact_shadow",
        }
    }
}

impl fmt::Display for ObservabilityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservabilityPublicationArtifacts {
    pub out_dir: PathBuf,
    pub observability_budget_sentinel_report_path: PathBuf,
    pub observability_on_supremacy_matrix_path: PathBuf,
    pub observability_claim_delta_report_path: PathBuf,
    pub telemetry_demotion_receipts_path: PathBuf,
    pub observability_publication_policy_path: PathBuf,
    pub support_bundle_observability_attestation_path: PathBuf,
    pub bundle_hash: String,
    pub attested: bool,
    pub suppressed_claim_count: usize,
    pub artifact_hashes: BTreeMap<String, String>,
}

#[derive(Debug)]
pub enum ObservabilityPublicationBundleError {
    Io {
        path: String,
        source: io::Error,
    },
    Json {
        path: String,
        source: serde_json::Error,
    },
    Busy {
        path: String,
    },
    HotPathTelemetry(HotPathTelemetryError),
}

impl fmt::Display for ObservabilityPublicationBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "I/O error at {path}: {source}"),
            Self::Json { path, source } => write!(f, "failed to render JSON for {path}: {source}"),
            Self::Busy { path } => write!(f, "bundle directory is already locked: {path}"),
            Self::HotPathTelemetry(source) => write!(f, "hot-path telemetry error: {source}"),
        }
    }
}

impl std::error::Error for ObservabilityPublicationBundleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::Busy { .. } => None,
            Self::HotPathTelemetry(_) => None,
        }
    }
}

impl From<HotPathTelemetryError> for ObservabilityPublicationBundleError {
    fn from(source: HotPathTelemetryError) -> Self {
        Self::HotPathTelemetry(source)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityBudgetSentinelReportArtifact {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub policy_id: String,
    pub sentinel_report: QualitySentinelReport,
    pub degradation_artifacts: Vec<DegradationArtifact>,
    pub highest_active_demotion: Option<DemotionTarget>,
    pub gate_pass: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryDemotionReceiptsArtifact {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub policy_id: String,
    pub receipt_count: u64,
    pub trigger_count: u64,
    pub highest_target: Option<DemotionTarget>,
    pub receipts: Vec<DemotionReceipt>,
    pub trigger_artifacts: Vec<DegradationArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotPathPublicationSummary {
    pub manifest_id: String,
    pub manifest_hash: String,
    pub overall_mode: String,
    pub publishable: bool,
    pub calibration_pass_count: u64,
    pub calibration_total: u64,
    pub thinning_retention_millionths: Option<u64>,
    pub rejection_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilitySupremacyCellSnapshot {
    pub workload_id: String,
    pub workload_class: ObservabilityWorkloadClass,
    pub mode: ObservabilityMode,
    pub cell: ObservabilityCell,
    pub decision: PromotionDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityOnSupremacyMatrixArtifact {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub report_id: String,
    pub report_hash: String,
    pub green_fraction_millionths: u64,
    pub allowed_fraction_millionths: u64,
    pub blocked_cell_count: u64,
    pub cells: Vec<ObservabilitySupremacyCellSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityClaimSurface {
    pub workload_id: String,
    pub workload_class: ObservabilityWorkloadClass,
    pub mode: ObservabilityMode,
    pub total_events_captured: u64,
    pub total_events_thinned: u64,
    pub total_events_rejected: u64,
    pub budget_utilization_millionths: u64,
    pub survival_rate_millionths: u64,
    pub exact_capture: bool,
    pub claim_allowed: bool,
    pub suppression_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityClaimDelta {
    pub workload_id: String,
    pub workload_class: ObservabilityWorkloadClass,
    pub baseline_mode: ObservabilityMode,
    pub comparison_mode: ObservabilityMode,
    pub captured_delta: i64,
    pub thinned_delta: i64,
    pub utilization_delta_millionths: i64,
    pub exact_capture_improved: bool,
    pub claim_state_transition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityClaimDeltaReportArtifact {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub hot_path_summary: HotPathPublicationSummary,
    pub claim_surfaces: Vec<ObservabilityClaimSurface>,
    pub deltas: Vec<ObservabilityClaimDelta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressedClaim {
    pub workload_id: String,
    pub workload_class: ObservabilityWorkloadClass,
    pub mode: ObservabilityMode,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityPublicationPolicyArtifact {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub default_shipped_mode: ObservabilityMode,
    pub quality_gate_pass: bool,
    pub hot_path_summary: HotPathPublicationSummary,
    pub allowed_cells: Vec<String>,
    pub suppressed_claims: Vec<SuppressedClaim>,
    pub required_artifacts: Vec<String>,
    pub fail_closed_conditions: Vec<String>,
    pub publication_gate_pass: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportBundleObservabilityAttestationArtifact {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub attested: bool,
    pub shipped_capture_mode: ObservabilityMode,
    pub quality_report_hash: String,
    pub supremacy_matrix_hash: String,
    pub claim_delta_hash: String,
    pub demotion_receipts_hash: String,
    pub publication_policy_hash: String,
    pub quality_overall_regime: String,
    pub hot_path_overall_mode: String,
    pub suppressed_claim_count: u64,
    pub active_demotion_targets: Vec<DemotionTarget>,
    pub operator_summary: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct WorkloadModeKey {
    workload: ObservabilityWorkloadClass,
    mode: ObservabilityMode,
}

#[derive(Debug, Clone)]
struct QualityBundle {
    sentinel_report: QualitySentinelReport,
    degradation_artifacts: Vec<DegradationArtifact>,
    demotion_receipts: Vec<DemotionReceipt>,
    active_demotion_targets: Vec<DemotionTarget>,
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

#[derive(Debug, Clone)]
struct SupremacyCellDescriptor {
    workload: ObservabilityWorkloadClass,
    mode: ObservabilityMode,
    cell: ObservabilityCell,
}

pub fn write_observability_publication_bundle(
    out_dir: impl AsRef<Path>,
) -> Result<ObservabilityPublicationArtifacts, ObservabilityPublicationBundleError> {
    let out_dir = out_dir.as_ref().to_path_buf();
    fs::create_dir_all(&out_dir).map_err(|source| ObservabilityPublicationBundleError::Io {
        path: out_dir.display().to_string(),
        source,
    })?;

    let epoch = SecurityEpoch::from_raw(SAMPLE_EPOCH);
    let quality_bundle = build_quality_bundle(epoch);
    let hot_path_summary = build_hot_path_summary(epoch)?;
    let supremacy_matrix = build_supremacy_matrix(epoch);
    let telemetry_reports = build_telemetry_reports(epoch);
    let claim_delta_report =
        build_claim_delta_report(&telemetry_reports, &supremacy_matrix, &hot_path_summary);
    let publication_policy =
        build_publication_policy(&quality_bundle, &supremacy_matrix, &hot_path_summary);

    let budget_report = ObservabilityBudgetSentinelReportArtifact {
        schema_version: BUDGET_SENTINEL_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        sentinel_report: quality_bundle.sentinel_report.clone(),
        degradation_artifacts: quality_bundle.degradation_artifacts.clone(),
        highest_active_demotion: quality_bundle
            .active_demotion_targets
            .iter()
            .copied()
            .max_by_key(|target| target.severity_rank()),
        gate_pass: quality_bundle.sentinel_report.gate_pass,
    };
    let demotion_receipts = TelemetryDemotionReceiptsArtifact {
        schema_version: DEMOTION_RECEIPTS_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        receipt_count: quality_bundle.demotion_receipts.len() as u64,
        trigger_count: quality_bundle.degradation_artifacts.len() as u64,
        highest_target: quality_bundle
            .demotion_receipts
            .iter()
            .map(|receipt| receipt.new_mode)
            .max_by_key(|target| target.severity_rank()),
        receipts: quality_bundle.demotion_receipts.clone(),
        trigger_artifacts: quality_bundle.degradation_artifacts.clone(),
    };

    let budget_path = out_dir.join(OBSERVABILITY_BUDGET_SENTINEL_REPORT_FILE);
    let matrix_path = out_dir.join(OBSERVABILITY_ON_SUPREMACY_MATRIX_FILE);
    let claim_delta_path = out_dir.join(OBSERVABILITY_CLAIM_DELTA_REPORT_FILE);
    let demotion_path = out_dir.join(TELEMETRY_DEMOTION_RECEIPTS_FILE);
    let policy_path = out_dir.join(OBSERVABILITY_PUBLICATION_POLICY_FILE);
    let support_path = out_dir.join(SUPPORT_BUNDLE_OBSERVABILITY_ATTESTATION_FILE);

    let budget_bytes = canonical_json_bytes(&budget_report, &budget_path)?;
    let matrix_bytes = canonical_json_bytes(&supremacy_matrix, &matrix_path)?;
    let claim_delta_bytes = canonical_json_bytes(&claim_delta_report, &claim_delta_path)?;
    let demotion_bytes = canonical_json_bytes(&demotion_receipts, &demotion_path)?;
    let policy_bytes = canonical_json_bytes(&publication_policy, &policy_path)?;

    let mut artifact_hashes = BTreeMap::new();
    artifact_hashes.insert(
        OBSERVABILITY_BUDGET_SENTINEL_REPORT_FILE.to_string(),
        sha256_hex(&budget_bytes),
    );
    artifact_hashes.insert(
        OBSERVABILITY_ON_SUPREMACY_MATRIX_FILE.to_string(),
        sha256_hex(&matrix_bytes),
    );
    artifact_hashes.insert(
        OBSERVABILITY_CLAIM_DELTA_REPORT_FILE.to_string(),
        sha256_hex(&claim_delta_bytes),
    );
    artifact_hashes.insert(
        TELEMETRY_DEMOTION_RECEIPTS_FILE.to_string(),
        sha256_hex(&demotion_bytes),
    );
    artifact_hashes.insert(
        OBSERVABILITY_PUBLICATION_POLICY_FILE.to_string(),
        sha256_hex(&policy_bytes),
    );

    let support_attestation = build_support_bundle_attestation(
        &quality_bundle,
        &supremacy_matrix,
        &publication_policy,
        &hot_path_summary,
        &artifact_hashes,
    );
    let support_bytes = canonical_json_bytes(&support_attestation, &support_path)?;
    artifact_hashes.insert(
        SUPPORT_BUNDLE_OBSERVABILITY_ATTESTATION_FILE.to_string(),
        sha256_hex(&support_bytes),
    );

    let bundle_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&budget_bytes);
        hasher.update(&matrix_bytes);
        hasher.update(&claim_delta_bytes);
        hasher.update(&demotion_bytes);
        hasher.update(&policy_bytes);
        hasher.update(&support_bytes);
        hex::encode(hasher.finalize())
    };

    let _bundle_lock = acquire_bundle_write_lock(&out_dir)?;
    write_atomic(&budget_path, &budget_bytes)?;
    write_atomic(&matrix_path, &matrix_bytes)?;
    write_atomic(&claim_delta_path, &claim_delta_bytes)?;
    write_atomic(&demotion_path, &demotion_bytes)?;
    write_atomic(&policy_path, &policy_bytes)?;
    write_atomic(&support_path, &support_bytes)?;

    Ok(ObservabilityPublicationArtifacts {
        out_dir,
        observability_budget_sentinel_report_path: budget_path,
        observability_on_supremacy_matrix_path: matrix_path,
        observability_claim_delta_report_path: claim_delta_path,
        telemetry_demotion_receipts_path: demotion_path,
        observability_publication_policy_path: policy_path,
        support_bundle_observability_attestation_path: support_path,
        bundle_hash,
        attested: support_attestation.attested,
        suppressed_claim_count: publication_policy.suppressed_claims.len(),
        artifact_hashes,
    })
}

fn build_quality_bundle(epoch: SecurityEpoch) -> QualityBundle {
    let mut sentinel = ObservabilityQualitySentinel::new(canonical_demotion_policy(epoch));
    let mut degradation_artifacts = Vec::new();
    let mut demotion_receipts = Vec::new();

    for observation in [
        QualityObservation {
            dimension: QualityDimension::SignalFidelity,
            value_millionths: 920_000,
            timestamp_ns: 1,
            channel_id: "dispatch_sensitive.budgeted".to_string(),
        },
        QualityObservation {
            dimension: QualityDimension::SignalFidelity,
            value_millionths: 760_000,
            timestamp_ns: 2,
            channel_id: "dispatch_sensitive.budgeted".to_string(),
        },
        QualityObservation {
            dimension: QualityDimension::BlindSpotRatio,
            value_millionths: 60_000,
            timestamp_ns: 3,
            channel_id: "hostcall_sensitive.budgeted".to_string(),
        },
        QualityObservation {
            dimension: QualityDimension::ReconstructionAmbiguity,
            value_millionths: 120_000,
            timestamp_ns: 4,
            channel_id: "hostcall_sensitive.budgeted".to_string(),
        },
        QualityObservation {
            dimension: QualityDimension::TailUndercoverage,
            value_millionths: 170_000,
            timestamp_ns: 5,
            channel_id: "startup_sensitive.budgeted".to_string(),
        },
        QualityObservation {
            dimension: QualityDimension::EvidenceStaleness,
            value_millionths: 250_000,
            timestamp_ns: 6,
            channel_id: "startup_sensitive.incident".to_string(),
        },
    ] {
        let (new_artifacts, new_receipts) = sentinel.observe(&observation);
        degradation_artifacts.extend(new_artifacts);
        demotion_receipts.extend(new_receipts);
    }

    let sentinel_report = generate_quality_report(&sentinel);
    let active_demotion_targets = sentinel_report
        .dimensions
        .iter()
        .filter_map(|dimension| dimension.active_demotion)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    QualityBundle {
        sentinel_report,
        degradation_artifacts,
        demotion_receipts,
        active_demotion_targets,
    }
}

fn build_hot_path_summary(
    epoch: SecurityEpoch,
) -> Result<HotPathPublicationSummary, ObservabilityPublicationBundleError> {
    let mut registry = build_registry("observability-publication-registry".to_string(), epoch);
    register_kernel(
        &mut registry,
        create_kernel(
            "dispatch_hot_path".to_string(),
            SketchWriterKind::CountMin,
            MILLION,
            64,
            epoch,
        ),
    )?;
    register_kernel(
        &mut registry,
        create_kernel(
            "hostcall_hot_path".to_string(),
            SketchWriterKind::HeavyHitter,
            MILLION,
            64,
            epoch,
        ),
    )?;
    register_kernel(
        &mut registry,
        create_kernel(
            "startup_hot_path".to_string(),
            SketchWriterKind::Histogram,
            MILLION,
            64,
            epoch,
        ),
    )?;

    let mut evidence_entries = Vec::new();
    let mut dispatch_shadow = ExactShadowCounter::new("dispatch_hot_path".to_string());
    let mut hostcall_shadow = ExactShadowCounter::new("hostcall_hot_path".to_string());
    let mut startup_shadow = ExactShadowCounter::new("startup_hot_path".to_string());

    record_kernel_observations(
        &mut registry,
        "dispatch_hot_path",
        &[("ic_hit", 4), ("ic_miss", 2), ("shape_transition", 3)],
        &mut dispatch_shadow,
        &mut evidence_entries,
    )?;
    record_kernel_observations(
        &mut registry,
        "hostcall_hot_path",
        &[("ffi_call", 4), ("callback_resume", 2)],
        &mut hostcall_shadow,
        &mut evidence_entries,
    )?;
    record_kernel_observations(
        &mut registry,
        "startup_hot_path",
        &[
            ("module_probe", 3),
            ("cache_prime", 2),
            ("metadata_touch", 2),
        ],
        &mut startup_shadow,
        &mut evidence_entries,
    )?;

    // Force one calibration failure so the publication policy has a concrete,
    // deterministic suppression reason to carry forward.
    for _ in 0..3 {
        hostcall_shadow.observe("ffi_call", MILLION);
    }

    let dispatch_calibration = calibrate_kernel(
        find_kernel(&registry, "dispatch_hot_path")?,
        &dispatch_shadow,
        epoch,
    )?;
    let hostcall_calibration = calibrate_kernel(
        find_kernel(&registry, "hostcall_hot_path")?,
        &hostcall_shadow,
        epoch,
    )?;
    let startup_calibration = calibrate_kernel(
        find_kernel(&registry, "startup_hot_path")?,
        &startup_shadow,
        epoch,
    )?;
    let thinning_policy = ThinningPolicy::new(
        "observability-publication-thinning".to_string(),
        ThinningStrategy::HashDeterministic,
        500_000,
        0,
        0,
    );
    let thinning_report = apply_thinning(&evidence_entries, &thinning_policy, epoch)?;
    let manifest = build_manifest(
        "observability-publication-hotpath".to_string(),
        &registry,
        vec![
            dispatch_calibration,
            hostcall_calibration,
            startup_calibration,
        ],
        vec![thinning_report],
        epoch,
    );
    Ok(summarize_hot_path_manifest(&manifest))
}

fn record_kernel_observations(
    registry: &mut KernelRegistry,
    kernel_id: &str,
    observations: &[(&str, u64)],
    shadow: &mut ExactShadowCounter,
    entries: &mut Vec<HotPathEvidenceEntry>,
) -> Result<(), ObservabilityPublicationBundleError> {
    for (key, count) in observations {
        for _ in 0..*count {
            let kernel = registry
                .find_kernel_mut(kernel_id)
                .ok_or_else(|| HotPathTelemetryError::KernelNotFound(kernel_id.to_string()))?;
            if let Some(entry) = submit_observation(kernel, key, MILLION)? {
                entries.push(entry);
            }
            shadow.observe(key, MILLION);
        }
    }
    registry.recompute_hash();
    Ok(())
}

fn find_kernel<'a>(
    registry: &'a KernelRegistry,
    kernel_id: &str,
) -> Result<&'a crate::hot_path_telemetry_kernel::KernelState, ObservabilityPublicationBundleError>
{
    registry
        .find_kernel(kernel_id)
        .ok_or_else(|| HotPathTelemetryError::KernelNotFound(kernel_id.to_string()).into())
}

fn summarize_hot_path_manifest(manifest: &TelemetryManifest) -> HotPathPublicationSummary {
    let calibration_pass_count = manifest
        .calibration_evidence
        .iter()
        .filter(|evidence| evidence.passed)
        .count() as u64;
    let thinning_retention_millionths = manifest
        .thinning_reports
        .first()
        .map(|report| report.actual_retention_millionths);

    HotPathPublicationSummary {
        manifest_id: manifest.manifest_id.clone(),
        manifest_hash: manifest.content_hash.to_hex(),
        overall_mode: manifest.overall_mode.as_str().to_string(),
        publishable: manifest.publishable,
        calibration_pass_count,
        calibration_total: manifest.calibration_evidence.len() as u64,
        thinning_retention_millionths,
        rejection_reasons: manifest.rejection_reasons.clone(),
    }
}

fn build_supremacy_matrix(epoch: SecurityEpoch) -> ObservabilityOnSupremacyMatrixArtifact {
    let descriptors = vec![
        build_supremacy_descriptor(
            ObservabilityWorkloadClass::DispatchSensitive,
            ObservabilityMode::Off,
            1_000_000,
            0,
            0,
            400_000,
            PromotionRule::SuppressClaim,
        ),
        build_supremacy_descriptor(
            ObservabilityWorkloadClass::DispatchSensitive,
            ObservabilityMode::Budgeted,
            40_000,
            910_000,
            920_000,
            50_000,
            PromotionRule::RequireCalibration,
        ),
        build_supremacy_descriptor(
            ObservabilityWorkloadClass::DispatchSensitive,
            ObservabilityMode::ExactShadow,
            0,
            1_000_000,
            1_000_000,
            10_000,
            PromotionRule::FailClosed,
        ),
        build_supremacy_descriptor(
            ObservabilityWorkloadClass::HostcallSensitive,
            ObservabilityMode::Off,
            1_000_000,
            0,
            0,
            400_000,
            PromotionRule::SuppressClaim,
        ),
        build_supremacy_descriptor(
            ObservabilityWorkloadClass::HostcallSensitive,
            ObservabilityMode::Budgeted,
            140_000,
            760_000,
            820_000,
            70_000,
            PromotionRule::RequireCalibration,
        ),
        build_supremacy_descriptor(
            ObservabilityWorkloadClass::HostcallSensitive,
            ObservabilityMode::ExactShadow,
            0,
            1_000_000,
            1_000_000,
            10_000,
            PromotionRule::FailClosed,
        ),
        build_supremacy_descriptor(
            ObservabilityWorkloadClass::StartupSensitive,
            ObservabilityMode::Off,
            1_000_000,
            0,
            0,
            400_000,
            PromotionRule::SuppressClaim,
        ),
        build_supremacy_descriptor(
            ObservabilityWorkloadClass::StartupSensitive,
            ObservabilityMode::Budgeted,
            90_000,
            830_000,
            870_000,
            120_000,
            PromotionRule::RequireCalibration,
        ),
        build_supremacy_descriptor(
            ObservabilityWorkloadClass::StartupSensitive,
            ObservabilityMode::ExactShadow,
            0,
            1_000_000,
            1_000_000,
            10_000,
            PromotionRule::FailClosed,
        ),
    ];
    let report = build_report(
        epoch,
        descriptors
            .iter()
            .map(|descriptor| descriptor.cell.clone())
            .collect(),
    );
    let cells = descriptors
        .into_iter()
        .zip(report.decisions.iter().cloned())
        .map(
            |(descriptor, decision)| ObservabilitySupremacyCellSnapshot {
                workload_id: descriptor.workload.workload_id().to_string(),
                workload_class: descriptor.workload,
                mode: descriptor.mode,
                cell: descriptor.cell,
                decision,
            },
        )
        .collect::<Vec<_>>();
    let blocked_cell_count = cells.iter().filter(|cell| !cell.decision.allowed).count() as u64;

    ObservabilityOnSupremacyMatrixArtifact {
        schema_version: SUPREMACY_MATRIX_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        report_id: report.report_id.clone(),
        report_hash: report.content_hash.to_hex(),
        green_fraction_millionths: report.green_fraction_millionths(),
        allowed_fraction_millionths: report.allowed_fraction_millionths(),
        blocked_cell_count,
        cells,
    }
}

fn build_supremacy_descriptor(
    workload: ObservabilityWorkloadClass,
    mode: ObservabilityMode,
    error_bound_millionths: u64,
    coverage_millionths: u64,
    completeness_millionths: u64,
    freshness_millionths: u64,
    rule: PromotionRule,
) -> SupremacyCellDescriptor {
    let cell_id = format!("{}::{}", workload.workload_id(), mode.as_str());
    let mut error = create_sentinel(
        &format!("{cell_id}::error_bound"),
        SentinelKind::ErrorBound,
        100_000,
    );
    let mut coverage = create_sentinel(
        &format!("{cell_id}::coverage"),
        SentinelKind::Coverage,
        800_000,
    );
    let mut completeness = create_sentinel(
        &format!("{cell_id}::completeness"),
        SentinelKind::Completeness,
        850_000,
    );
    let mut freshness = create_sentinel(
        &format!("{cell_id}::freshness"),
        SentinelKind::Freshness,
        200_000,
    );
    update_sentinel(&mut error, error_bound_millionths);
    update_sentinel(&mut coverage, coverage_millionths);
    update_sentinel(&mut completeness, completeness_millionths);
    update_sentinel(&mut freshness, freshness_millionths);
    let cell = build_cell(
        &cell_id,
        workload.workload_id(),
        vec![error, coverage, completeness, freshness],
        rule,
    );

    SupremacyCellDescriptor {
        workload,
        mode,
        cell,
    }
}

fn build_telemetry_reports(epoch: SecurityEpoch) -> BTreeMap<WorkloadModeKey, TelemetryReport> {
    let mut reports = BTreeMap::new();
    for workload in ObservabilityWorkloadClass::ALL {
        for mode in ObservabilityMode::ALL {
            reports.insert(
                WorkloadModeKey { workload, mode },
                simulate_telemetry_report(epoch, workload, mode),
            );
        }
    }
    reports
}

fn simulate_telemetry_report(
    epoch: SecurityEpoch,
    workload: ObservabilityWorkloadClass,
    mode: ObservabilityMode,
) -> TelemetryReport {
    match mode {
        ObservabilityMode::Off => TelemetryPlane::new(epoch).generate_report(),
        ObservabilityMode::Budgeted => {
            let mut plane = TelemetryPlane::with_default_budget(
                epoch,
                TelemetryBudget::new(
                    12,
                    1_000_000_000,
                    400_000,
                    TelemetryCaptureMode::BudgetedSampling,
                ),
            );
            plane.set_default_thinning(PlaneThinningConfig::new(
                PlaneThinningPolicy::Uniform,
                5,
                1,
            ));
            let event_count = match workload {
                ObservabilityWorkloadClass::DispatchSensitive => 10,
                ObservabilityWorkloadClass::HostcallSensitive => 8,
                ObservabilityWorkloadClass::StartupSensitive => 7,
            };
            for index in 0..event_count {
                let event = TelemetryEvent::new(
                    &format!("{}-budgeted-{index}", workload.workload_id()),
                    workload.telemetry_domain(),
                    index as u64,
                    TelemetryCaptureMode::BudgetedSampling,
                    2_500_000,
                    workload.workload_id().as_bytes(),
                );
                let _ = plane.record_event(event);
            }
            let _ = plane.thin_all();
            plane.generate_report()
        }
        ObservabilityMode::ExactShadow => {
            let mut plane = TelemetryPlane::with_default_budget(
                epoch,
                TelemetryBudget::new(
                    16,
                    1_000_000_000,
                    MILLION,
                    TelemetryCaptureMode::ExactShadow,
                ),
            );
            let event_count = match workload {
                ObservabilityWorkloadClass::DispatchSensitive => 12,
                ObservabilityWorkloadClass::HostcallSensitive => 11,
                ObservabilityWorkloadClass::StartupSensitive => 9,
            };
            for index in 0..event_count {
                let event = TelemetryEvent::new(
                    &format!("{}-exact-shadow-{index}", workload.workload_id()),
                    workload.telemetry_domain(),
                    index as u64,
                    TelemetryCaptureMode::ExactShadow,
                    MILLION,
                    workload.workload_id().as_bytes(),
                );
                let _ = plane.record_event(event);
            }
            plane.generate_report()
        }
    }
}

fn build_claim_delta_report(
    telemetry_reports: &BTreeMap<WorkloadModeKey, TelemetryReport>,
    supremacy_matrix: &ObservabilityOnSupremacyMatrixArtifact,
    hot_path_summary: &HotPathPublicationSummary,
) -> ObservabilityClaimDeltaReportArtifact {
    let surfaces = ObservabilityWorkloadClass::ALL
        .into_iter()
        .flat_map(|workload| {
            ObservabilityMode::ALL.into_iter().map(move |mode| {
                let report = telemetry_reports
                    .get(&WorkloadModeKey { workload, mode })
                    .expect("telemetry report exists");
                let cell = supremacy_matrix
                    .cells
                    .iter()
                    .find(|cell| cell.workload_class == workload && cell.mode == mode)
                    .expect("supremacy cell exists");
                ObservabilityClaimSurface {
                    workload_id: workload.workload_id().to_string(),
                    workload_class: workload,
                    mode,
                    total_events_captured: report.total_events_captured,
                    total_events_thinned: report.total_events_thinned,
                    total_events_rejected: report.total_events_rejected,
                    budget_utilization_millionths: report.budget_utilization_millionths,
                    survival_rate_millionths: report.survival_rate_millionths(),
                    exact_capture: mode != ObservabilityMode::Off && report.is_all_exact(),
                    claim_allowed: cell.decision.allowed,
                    suppression_reasons: cell.decision.suppression_reasons.clone(),
                }
            })
        })
        .collect::<Vec<_>>();
    let deltas = ObservabilityWorkloadClass::ALL
        .into_iter()
        .flat_map(|workload| {
            let off = surfaces
                .iter()
                .find(|surface| {
                    surface.workload_class == workload && surface.mode == ObservabilityMode::Off
                })
                .expect("off surface");
            let budgeted = surfaces
                .iter()
                .find(|surface| {
                    surface.workload_class == workload
                        && surface.mode == ObservabilityMode::Budgeted
                })
                .expect("budgeted surface");
            let exact_shadow = surfaces
                .iter()
                .find(|surface| {
                    surface.workload_class == workload
                        && surface.mode == ObservabilityMode::ExactShadow
                })
                .expect("exact-shadow surface");

            [
                build_claim_delta(off, budgeted),
                build_claim_delta(budgeted, exact_shadow),
            ]
        })
        .collect::<Vec<_>>();

    ObservabilityClaimDeltaReportArtifact {
        schema_version: CLAIM_DELTA_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        hot_path_summary: hot_path_summary.clone(),
        claim_surfaces: surfaces,
        deltas,
    }
}

fn build_claim_delta(
    baseline: &ObservabilityClaimSurface,
    comparison: &ObservabilityClaimSurface,
) -> ObservabilityClaimDelta {
    ObservabilityClaimDelta {
        workload_id: baseline.workload_id.clone(),
        workload_class: baseline.workload_class,
        baseline_mode: baseline.mode,
        comparison_mode: comparison.mode,
        captured_delta: comparison.total_events_captured as i64
            - baseline.total_events_captured as i64,
        thinned_delta: comparison.total_events_thinned as i64
            - baseline.total_events_thinned as i64,
        utilization_delta_millionths: comparison.budget_utilization_millionths as i64
            - baseline.budget_utilization_millionths as i64,
        exact_capture_improved: !baseline.exact_capture && comparison.exact_capture,
        claim_state_transition: claim_state_transition(baseline, comparison),
    }
}

fn claim_state_transition(
    baseline: &ObservabilityClaimSurface,
    comparison: &ObservabilityClaimSurface,
) -> String {
    match (
        baseline.claim_allowed,
        comparison.claim_allowed,
        baseline.exact_capture,
        comparison.exact_capture,
    ) {
        (false, false, _, _) => "suppressed_to_suppressed".to_string(),
        (false, true, _, true) => "suppressed_to_exact_attested".to_string(),
        (false, true, _, false) => "suppressed_to_allowed".to_string(),
        (true, false, _, _) => "allowed_to_suppressed".to_string(),
        (true, true, false, true) => "allowed_to_exact_attested".to_string(),
        (true, true, _, _) => "allowed_to_allowed".to_string(),
    }
}

fn build_publication_policy(
    quality_bundle: &QualityBundle,
    supremacy_matrix: &ObservabilityOnSupremacyMatrixArtifact,
    hot_path_summary: &HotPathPublicationSummary,
) -> ObservabilityPublicationPolicyArtifact {
    let allowed_cells = supremacy_matrix
        .cells
        .iter()
        .filter(|cell| cell.decision.allowed)
        .map(|cell| cell.cell.cell_id.clone())
        .collect::<Vec<_>>();
    let suppressed_claims = supremacy_matrix
        .cells
        .iter()
        .filter(|cell| !cell.decision.allowed)
        .map(|cell| SuppressedClaim {
            workload_id: cell.workload_id.clone(),
            workload_class: cell.workload_class,
            mode: cell.mode,
            reasons: cell.decision.suppression_reasons.clone(),
        })
        .collect::<Vec<_>>();

    let mut fail_closed_conditions = vec![
        "observability_off cells are never publishable claim surfaces".to_string(),
        "budgeted cells require calibration-sentinel evidence before publication".to_string(),
        "exact-shadow cells are the deterministic fallback when budgeted evidence is degraded"
            .to_string(),
    ];
    if !quality_bundle.sentinel_report.gate_pass {
        fail_closed_conditions.push(
            "observability quality sentinel is degraded; keep publication in attestation-only mode"
                .to_string(),
        );
    }
    if !hot_path_summary.publishable {
        fail_closed_conditions.push(
            "hot-path telemetry manifest lacks current publishable calibration evidence"
                .to_string(),
        );
    }
    if !suppressed_claims.is_empty() {
        fail_closed_conditions.push(
            "one or more workload cells remain suppressed pending exact-shadow or incident capture"
                .to_string(),
        );
    }

    let publication_gate_pass = quality_bundle.sentinel_report.gate_pass
        && hot_path_summary.publishable
        && suppressed_claims.is_empty();

    ObservabilityPublicationPolicyArtifact {
        schema_version: PUBLICATION_POLICY_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        default_shipped_mode: ObservabilityMode::Budgeted,
        quality_gate_pass: quality_bundle.sentinel_report.gate_pass,
        hot_path_summary: hot_path_summary.clone(),
        allowed_cells,
        suppressed_claims,
        required_artifacts: vec![
            OBSERVABILITY_BUDGET_SENTINEL_REPORT_FILE.to_string(),
            OBSERVABILITY_ON_SUPREMACY_MATRIX_FILE.to_string(),
            OBSERVABILITY_CLAIM_DELTA_REPORT_FILE.to_string(),
            TELEMETRY_DEMOTION_RECEIPTS_FILE.to_string(),
            OBSERVABILITY_PUBLICATION_POLICY_FILE.to_string(),
            SUPPORT_BUNDLE_OBSERVABILITY_ATTESTATION_FILE.to_string(),
        ],
        fail_closed_conditions,
        publication_gate_pass,
    }
}

fn build_support_bundle_attestation(
    quality_bundle: &QualityBundle,
    supremacy_matrix: &ObservabilityOnSupremacyMatrixArtifact,
    publication_policy: &ObservabilityPublicationPolicyArtifact,
    hot_path_summary: &HotPathPublicationSummary,
    artifact_hashes: &BTreeMap<String, String>,
) -> SupportBundleObservabilityAttestationArtifact {
    let suppressed_claim_count = publication_policy.suppressed_claims.len() as u64;
    let mut operator_summary = vec![
        format!(
            "default shipped capture mode: {}",
            ObservabilityMode::Budgeted.as_str()
        ),
        format!(
            "quality sentinel regime: {}",
            quality_bundle.sentinel_report.overall_regime
        ),
        format!(
            "hot-path manifest publishable: {} ({} / {} calibrations passed)",
            hot_path_summary.publishable,
            hot_path_summary.calibration_pass_count,
            hot_path_summary.calibration_total
        ),
        format!(
            "suppressed workload cells: {} of {}",
            suppressed_claim_count,
            supremacy_matrix.cells.len()
        ),
    ];
    operator_summary.extend(
        publication_policy
            .suppressed_claims
            .iter()
            .map(|claim| {
                format!(
                    "{} {} suppressed: {}",
                    claim.workload_id,
                    claim.mode,
                    claim.reasons.join("; ")
                )
            })
            .collect::<Vec<_>>(),
    );

    SupportBundleObservabilityAttestationArtifact {
        schema_version: SUPPORT_BUNDLE_ATTESTATION_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        attested: publication_policy.publication_gate_pass,
        shipped_capture_mode: ObservabilityMode::Budgeted,
        quality_report_hash: artifact_hashes
            .get(OBSERVABILITY_BUDGET_SENTINEL_REPORT_FILE)
            .cloned()
            .unwrap_or_default(),
        supremacy_matrix_hash: artifact_hashes
            .get(OBSERVABILITY_ON_SUPREMACY_MATRIX_FILE)
            .cloned()
            .unwrap_or_default(),
        claim_delta_hash: artifact_hashes
            .get(OBSERVABILITY_CLAIM_DELTA_REPORT_FILE)
            .cloned()
            .unwrap_or_default(),
        demotion_receipts_hash: artifact_hashes
            .get(TELEMETRY_DEMOTION_RECEIPTS_FILE)
            .cloned()
            .unwrap_or_default(),
        publication_policy_hash: artifact_hashes
            .get(OBSERVABILITY_PUBLICATION_POLICY_FILE)
            .cloned()
            .unwrap_or_default(),
        quality_overall_regime: quality_bundle.sentinel_report.overall_regime.to_string(),
        hot_path_overall_mode: hot_path_summary.overall_mode.clone(),
        suppressed_claim_count,
        active_demotion_targets: quality_bundle.active_demotion_targets.clone(),
        operator_summary,
    }
}

fn canonical_json_bytes<T: Serialize>(
    value: &T,
    path: &Path,
) -> Result<Vec<u8>, ObservabilityPublicationBundleError> {
    serde_json::to_vec(value).map_err(|source| ObservabilityPublicationBundleError::Json {
        path: path.display().to_string(),
        source,
    })
}

fn acquire_bundle_write_lock(
    out_dir: &Path,
) -> Result<BundleWriteLock, ObservabilityPublicationBundleError> {
    let lock_path = out_dir.join(".observability_publication_bundle.lock");
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(_) => Ok(BundleWriteLock { path: lock_path }),
        Err(source) if source.kind() == ErrorKind::AlreadyExists => {
            Err(ObservabilityPublicationBundleError::Busy {
                path: lock_path.display().to_string(),
            })
        }
        Err(source) => Err(ObservabilityPublicationBundleError::Io {
            path: lock_path.display().to_string(),
            source,
        }),
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ObservabilityPublicationBundleError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| ObservabilityPublicationBundleError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }

    let temp_path = unique_temp_path(path);
    fs::write(&temp_path, bytes).map_err(|source| ObservabilityPublicationBundleError::Io {
        path: temp_path.display().to_string(),
        source,
    })?;
    if let Err(source) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(ObservabilityPublicationBundleError::Io {
            path: path.display().to_string(),
            source,
        });
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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
